"""Composition root: builds every component once per process from Settings."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx
from agentic_core.audit import AuditLog
from agentic_core.policy import PolicyEngine, PolicySet
from sqlalchemy.ext.asyncio import AsyncEngine

from agent_control_plane.application.bundles import BundleService
from agent_control_plane.application.deployments import DeploymentService
from agent_control_plane.application.governance import Governance, Recorder
from agent_control_plane.application.killswitch import KillSwitchService
from agent_control_plane.application.operations import Operations
from agent_control_plane.application.registry import RegistryService
from agent_control_plane.config import Settings
from agent_control_plane.domain.ports import Clock, ClusterGateway, IdentityRegistrar
from agent_control_plane.infrastructure.database import (
    SqlAgentRepository,
    SqlAgentVersionRepository,
    SqlAuditSink,
    SqlBundleRepository,
    SqlDeploymentRepository,
    SqlKillSwitchRepository,
    SqlLeaseStore,
    SqlStatusRepository,
    SqlToolRepository,
    SystemClock,
    create_schema,
    make_engine,
)
from agent_control_plane.infrastructure.kubernetes import KubernetesCluster, load_api_client
from agent_control_plane.integrations.identity_fabric import (
    ClientCredentialsTokenProvider,
    FabricAuthorizer,
    FabricClient,
    FabricIdentityRegistrar,
)
from agent_control_plane.observability.metrics import ControlPlaneMetrics
from agent_control_plane.orchestration.manifests import RenderContext
from agent_control_plane.orchestration.reconciler import ReconcileLoop, Reconciler
from agent_control_plane.security.authorization import Authorizer, LocalAuthorizer, PolicyGate
from agent_control_plane.security.content import TextScreen
from agent_control_plane.security.oidc import KeyResolver, OperatorAuthenticator, RemoteJwks
from agent_control_plane.security.signing import SigningKey


@dataclass
class Container:
    settings: Settings
    engine: AsyncEngine
    http: httpx.AsyncClient
    metrics: ControlPlaneMetrics
    audit_key: SigningKey
    authenticator: OperatorAuthenticator
    gate: PolicyGate
    agent_authorizer: Authorizer
    recorder: Recorder
    governance: Governance
    registry: RegistryService
    bundles: BundleService
    deployments: DeploymentService
    kill_switches: KillSwitchService
    reconciler: Reconciler
    loop: ReconcileLoop
    operations: Operations
    cluster: ClusterGateway
    close_cluster: Callable[[], None]

    async def aclose(self) -> None:
        self.close_cluster()
        await self.http.aclose()
        await self.engine.dispose()


def _no_cluster_to_close() -> None:
    """An injected ClusterGateway is owned (and closed) by whoever injected it."""


def _keys(settings: Settings) -> tuple[SigningKey, SigningKey]:
    if settings.dev_ephemeral_keys:
        return SigningKey.ephemeral("audit"), SigningKey.ephemeral("bundle")
    if settings.audit_key_file is None or settings.bundle_key_file is None:
        raise ValueError("signing keys are not configured")  # pragma: no cover - validated
    return SigningKey.from_file(settings.audit_key_file), SigningKey.from_file(
        settings.bundle_key_file
    )


def _fabric(
    settings: Settings, http: httpx.AsyncClient
) -> tuple[FabricClient | None, IdentityRegistrar | None]:
    url = settings.fabric_url_str
    if url is None:
        return None, None
    if (
        settings.fabric_admin_token_url is None
        or settings.fabric_admin_client_id is None
        or settings.fabric_admin_client_secret is None
        or settings.fabric_trust_domain is None
        or settings.cluster_oidc_issuer is None
    ):
        raise ValueError("identity fabric integration incomplete")  # pragma: no cover - validated
    client = FabricClient(
        http=http,
        base_url=url,
        admin_tokens=ClientCredentialsTokenProvider(
            http=http,
            token_url=settings.fabric_admin_token_url,
            client_id=settings.fabric_admin_client_id,
            client_secret=settings.fabric_admin_client_secret,
            scope=settings.fabric_admin_scope,
        ),
    )
    registrar = FabricIdentityRegistrar(
        client,
        trust_domain=settings.fabric_trust_domain,
        workload_issuer=settings.cluster_oidc_issuer,
        workload_audience=settings.fabric_workload_audience,
    )
    return client, registrar


async def build_container(
    settings: Settings,
    *,
    cluster: ClusterGateway | None = None,
    operator_resolver: KeyResolver | None = None,
    clock: Clock | None = None,
    wall_clock: Callable[[], float] = time.time,
    http: httpx.AsyncClient | None = None,
) -> Container:
    clock = clock or SystemClock()
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    engine = make_engine(settings.database_url)
    await create_schema(engine)
    metrics = ControlPlaneMetrics()

    close_cluster: Callable[[], None] = _no_cluster_to_close
    if cluster is None:
        kube = KubernetesCluster(load_api_client(settings.kube_mode, settings.kubeconfig_path))
        cluster, close_cluster = kube, kube.close

    audit_key, bundle_key = _keys(settings)
    recorder = Recorder(
        AuditLog(SqlAuditSink(engine, settings.instance_id), audit_key, key_id=audit_key.key_id)
    )
    governance = Governance(recorder)
    gate = PolicyGate(PolicyEngine(PolicySet.from_file(settings.policy_file)))
    authenticator = OperatorAuthenticator(
        operator_resolver or RemoteJwks(settings.operator_jwks_url, client=http),
        issuer=settings.operator_issuer,
        audience=settings.operator_audience,
        roles_claim=settings.operator_roles_claim,
        clock=wall_clock,
    )
    fabric_client, registrar = _fabric(settings, http)
    agent_authorizer: Authorizer = (
        FabricAuthorizer(fabric_client)
        if fabric_client is not None
        else LocalAuthorizer(authenticator, gate)
    )
    screen = TextScreen()

    agents = SqlAgentRepository(engine)
    versions = SqlAgentVersionRepository(engine)
    tools = SqlToolRepository(engine)
    bundles = SqlBundleRepository(engine)
    deployments = SqlDeploymentRepository(engine)
    statuses = SqlStatusRepository(engine)
    switches = SqlKillSwitchRepository(engine)

    reconciler = Reconciler(
        deployments=deployments,
        statuses=statuses,
        agents=agents,
        versions=versions,
        tools=tools,
        bundles=bundles,
        kill_switches=switches,
        cluster=cluster,
        context=RenderContext(
            control_plane_url=settings.public_url_str,
            fabric_url=settings.fabric_url_str,
            workload_audience=settings.fabric_workload_audience,
            platform_namespace=settings.platform_namespace,
        ),
        registrar=registrar,
        recorder=recorder,
        metrics=metrics,
        clock=clock,
    )
    registry = RegistryService(
        agents=agents,
        versions=versions,
        tools=tools,
        deployments=deployments,
        governance=governance,
        screen=screen,
        clock=clock,
    )
    bundle_service = BundleService(
        bundles=bundles, key=bundle_key, governance=governance, screen=screen, clock=clock
    )
    deployment_service = DeploymentService(
        deployments=deployments,
        statuses=statuses,
        agents=agents,
        versions=versions,
        tools=tools,
        bundles=bundles,
        registrar=registrar,
        reconciler=reconciler,
        governance=governance,
        screen=screen,
        clock=clock,
        allowed_namespaces=settings.managed_namespaces,
    )
    kill_switches = KillSwitchService(
        switches=switches,
        deployments=deployments,
        agents=agents,
        registrar=registrar,
        reconciler=reconciler,
        governance=governance,
        screen=screen,
        metrics=metrics,
        clock=clock,
    )
    loop = ReconcileLoop(
        reconciler,
        SqlLeaseStore(engine),
        holder=settings.instance_id,
        interval_s=settings.reconcile_interval_s,
        lease_ttl_s=settings.lease_ttl_s,
        clock=clock,
        metrics=metrics,
        cluster=cluster,
    )
    operations = Operations(
        registry=registry,
        deployments=deployment_service,
        kill_switches=kill_switches,
        reconciler=reconciler,
        governance=governance,
    )
    return Container(
        settings=settings,
        engine=engine,
        http=http,
        metrics=metrics,
        audit_key=audit_key,
        authenticator=authenticator,
        gate=gate,
        agent_authorizer=agent_authorizer,
        recorder=recorder,
        governance=governance,
        registry=registry,
        bundles=bundle_service,
        deployments=deployment_service,
        kill_switches=kill_switches,
        reconciler=reconciler,
        loop=loop,
        operations=operations,
        cluster=cluster,
        close_cluster=close_cluster,
    )
