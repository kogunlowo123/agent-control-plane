"""Shared fixtures: an in-process IdP, fake Kubernetes API server and identity fabric,
a control plane wired to SQLite, and an ASGI app built inside its own event loop."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from agentic_core.domain.classification import DataClassification, RiskLevel
from fastapi.testclient import TestClient
from pydantic import SecretStr

from agent_control_plane.api.app import create_app
from agent_control_plane.application.commands import (
    ApplyDeployment,
    CreateAgent,
    CreateAgentVersion,
    CreateTool,
    DeploymentResult,
    PublishBundle,
    Transition,
)
from agent_control_plane.application.governance import OperatorCaller
from agent_control_plane.config import Settings
from agent_control_plane.domain.models import (
    AgentVersion,
    BundleRef,
    EgressRule,
    Environment,
    Framework,
    ImageRef,
    LifecycleAction,
    Owners,
    ToolRef,
)
from agent_control_plane.runtime.container import Container, build_container
from agent_control_plane.security.oidc import Principal, StaticJwks
from tests.fakes import (
    ADMIN_CLIENT,
    FABRIC,
    IDP_TOKEN_URL,
    TRUST_DOMAIN,
    FakeFabric,
    FakeIdp,
    FakeKubeApiServer,
    make_cluster,
)

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_ISSUER = "https://login.corp.test/tenant"
OPERATOR_AUDIENCE = "agent-control-plane"
CLUSTER_ISSUER = "https://oidc.eks.us-east-1.amazonaws.com/id/TESTCLUSTER"
DIGEST = "sha256:" + "b" * 64
DIGEST_V2 = "sha256:" + "c" * 64
PROD_NS = "agents-prod"
DEV_NS = "agents-dev"

BUNDLE_POLICY: dict[str, Any] = {
    "name": "claims-agent",
    "version": "2026.10.0",
    "rules": [
        {"id": "allow-claim-reads", "effect": "allow", "actions": ["claims:read:*"]},
        {
            "id": "approve-claim-payments",
            "effect": "require_approval",
            "actions": ["claims:pay:*"],
            "conditions": [{"attribute": "resource.amount", "operator": "gt", "value": 10000}],
        },
    ],
}

ROLES = {
    "dev@corp.test": ("acp-agent-developer",),
    "approver@corp.test": ("acp-approver",),
    "approver2@corp.test": ("acp-approver",),
    "deployer@corp.test": ("acp-deployer",),
    "policy@corp.test": ("acp-policy-author",),
    "secops@corp.test": ("acp-security-officer",),
    "secops2@corp.test": ("acp-security-officer",),
    "auditor@corp.test": ("acp-auditor",),
    "admin@corp.test": ("acp-platform-admin",),
}


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture
def operator_idp() -> FakeIdp:
    return FakeIdp(OPERATOR_ISSUER, kid="operator-1")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def kube() -> FakeKubeApiServer:
    return FakeKubeApiServer()


@pytest.fixture
def fabric() -> FakeFabric:
    return FakeFabric()


def database_url(tmp_path: Path) -> str:
    return os.environ.get("ACP_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'acp.db'}")


def base_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "public_url": "https://acp.corp.test",
        "instance_id": f"acp-test-{tmp_path.name[-12:]}",
        "database_url": database_url(tmp_path),
        "operator_issuer": OPERATOR_ISSUER,
        "operator_audience": OPERATOR_AUDIENCE,
        "operator_jwks_url": "https://unused.invalid/jwks",
        "dev_ephemeral_keys": True,
        "kube_mode": "kubeconfig",
        "kubeconfig_path": str(tmp_path / "unused-kubeconfig"),
        "managed_namespaces": frozenset({PROD_NS, DEV_NS}),
        "policy_file": ROOT / "policies" / "control-plane.yaml",
    }
    values.update(overrides)
    return Settings(**values)


def fabric_overrides() -> dict[str, Any]:
    return {
        "fabric_url": FABRIC,
        "fabric_trust_domain": TRUST_DOMAIN,
        "cluster_oidc_issuer": CLUSTER_ISSUER,
        "fabric_admin_token_url": IDP_TOKEN_URL,
        "fabric_admin_client_id": ADMIN_CLIENT[0],
        "fabric_admin_client_secret": SecretStr(ADMIN_CLIENT[1]),
    }


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return base_settings(tmp_path)


@pytest.fixture
def fabric_settings(tmp_path: Path) -> Settings:
    return base_settings(tmp_path, **fabric_overrides())


async def build(
    settings: Settings,
    kube: FakeKubeApiServer,
    idp: FakeIdp,
    clock: FakeClock,
    fabric: FakeFabric | None = None,
) -> Container:
    http = httpx.AsyncClient(transport=fabric.transport()) if fabric is not None else None
    return await build_container(
        settings,
        cluster=make_cluster(kube),
        operator_resolver=StaticJwks(idp.jwks()),
        clock=clock,
        http=http,
    )


@pytest.fixture
async def container(
    settings: Settings, kube: FakeKubeApiServer, operator_idp: FakeIdp, clock: FakeClock
) -> AsyncIterator[Container]:
    built = await build(settings, kube, operator_idp, clock)
    yield built
    await built.aclose()


@pytest.fixture
async def fabric_container(
    fabric_settings: Settings,
    kube: FakeKubeApiServer,
    operator_idp: FakeIdp,
    clock: FakeClock,
    fabric: FakeFabric,
) -> AsyncIterator[Container]:
    built = await build(fabric_settings, kube, operator_idp, clock, fabric)
    yield built
    await built.aclose()


def app_client(
    settings: Settings,
    kube: FakeKubeApiServer,
    idp: FakeIdp,
    clock: FakeClock,
    fabric: FakeFabric | None = None,
) -> TestClient:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await build(settings, kube, idp, clock, fabric)

    return TestClient(create_app(factory, run_reconcile_loop=False))


@pytest.fixture
def client(
    settings: Settings, kube: FakeKubeApiServer, operator_idp: FakeIdp, clock: FakeClock
) -> Iterator[TestClient]:
    with app_client(settings, kube, operator_idp, clock) as test_client:
        yield test_client


@pytest.fixture
def fabric_client(
    fabric_settings: Settings,
    kube: FakeKubeApiServer,
    operator_idp: FakeIdp,
    clock: FakeClock,
    fabric: FakeFabric,
) -> Iterator[TestClient]:
    with app_client(fabric_settings, kube, operator_idp, clock, fabric) as test_client:
        yield test_client


# ------------------------------------------------------------------ callers


def op(c: Container, subject: str, *roles: str) -> OperatorCaller:
    granted = roles or ROLES[subject]
    return OperatorCaller(Principal(subject=subject, roles=frozenset(granted)), c.gate)


def headers(idp: FakeIdp, subject: str, *roles: str) -> dict[str, str]:
    granted = list(roles or ROLES[subject])
    token = idp.mint(sub=subject, aud=OPERATOR_AUDIENCE, roles=granted)
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ commands


def agent_command(
    name: str = "claims-triage", *, risk: RiskLevel = RiskLevel.MODERATE, namespace: str = "claims"
) -> CreateAgent:
    return CreateAgent(
        namespace=namespace,
        name=name,
        display_name=f"{name} agent",
        mission="Triage incoming insurance claims and route them to the right adjuster queue.",
        owners=Owners(
            business="claims-operations",
            technical="claims-platform",
            escalation_contact="claims-oncall",
        ),
        risk=risk,
        max_classification=DataClassification.CONFIDENTIAL,
        disallowed_actions=("claims:pay:*",),
    )


TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"claim_id": {"type": "string"}, "limit": {"type": "integer"}},
    "required": ["claim_id"],
}


def tool_command(name: str = "claims.search", version: str = "1.0.0") -> CreateTool:
    return CreateTool(
        name=name,
        version=version,
        description="Search claims by identifier and return their status history.",
        owner="claims-platform",
        risk=RiskLevel.LOW,
        endpoint="https://mcp.claims.corp.test/mcp/",
        input_schema=TOOL_SCHEMA,
    )


def version_command(
    version: str = "1.0.0",
    *,
    digest: str = DIGEST,
    egress: tuple[EgressRule, ...] = (EgressRule(cidr="10.40.0.0/16", ports=(443,)),),
    tools: tuple[ToolRef, ...] = (ToolRef(name="claims.search", version="1.0.0"),),
    health_path: str | None = "/healthz",
) -> CreateAgentVersion:
    return CreateAgentVersion(
        version=version,
        framework=Framework.LANGGRAPH,
        entrypoint="claims_triage.graph:app",
        image=ImageRef(repository="ghcr.io/corp/claims-triage", digest=digest),
        tools=tools,
        scopes=frozenset({"claims:read:*", "controlplane:runtime:status"}),
        egress=egress,
        health_path=health_path,
        release_notes="Initial release.",
    )


def bundle_command(version: str = "1.0.0") -> PublishBundle:
    return PublishBundle(
        name="claims-policy",
        version=version,
        description="Runtime policy for claims agents.",
        policies=(BUNDLE_POLICY,),
    )


def deploy_command(
    name: str = "claims-triage-prod",
    *,
    environment: Environment = Environment.PRODUCTION,
    namespace: str = PROD_NS,
    version: str = "1.0.0",
    replicas: int = 2,
    agent: tuple[str, str] = ("claims", "claims-triage"),
    env: dict[str, str] | None = None,
) -> ApplyDeployment:
    return ApplyDeployment(
        name=name,
        agent_namespace=agent[0],
        agent_name=agent[1],
        environment=environment,
        namespace=namespace,
        version=version,
        replicas=replicas,
        policy_bundle=BundleRef(name="claims-policy", version="1.0.0"),
        ingress_namespaces=("agent-gateway",),
        env=env if env is not None else {"CLAIMS_REGION": "us-east-1"},
        service_account_annotations={
            "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/claims-triage"
        },
    )


async def approve_version(
    c: Container, namespace: str, name: str, version: str, risk: RiskLevel
) -> None:
    dev = op(c, "dev@corp.test")
    await c.registry.transition_version(
        namespace, name, version, Transition(action=LifecycleAction.SUBMIT), dev
    )
    approvers = (
        ["approver@corp.test", "approver2@corp.test"]
        if risk >= RiskLevel.HIGH
        else ["approver@corp.test"]
    )
    for subject in approvers:
        await c.registry.transition_version(
            namespace,
            name,
            version,
            Transition(action=LifecycleAction.APPROVE, comment="reviewed"),
            op(c, subject),
        )


async def seed(
    c: Container,
    *,
    risk: RiskLevel = RiskLevel.MODERATE,
    version: str = "1.0.0",
    digest: str = DIGEST,
    with_tool: bool = True,
) -> AgentVersion:
    """Register an approved agent version, an approved tool and a published bundle."""
    dev = op(c, "dev@corp.test")
    if await c.registry._agents.get("claims", "claims-triage") is None:
        await c.registry.create_agent(agent_command(risk=risk), dev)
    if with_tool and await c.registry._tools.get("claims.search", "1.0.0") is None:
        await c.registry.create_tool(tool_command(), dev)
        await c.registry.transition_tool(
            "claims.search", "1.0.0", Transition(action=LifecycleAction.SUBMIT), dev
        )
        await c.registry.transition_tool(
            "claims.search",
            "1.0.0",
            Transition(action=LifecycleAction.APPROVE),
            op(c, "approver@corp.test"),
        )
    await c.registry.create_version(
        "claims",
        "claims-triage",
        version_command(
            version, digest=digest, tools=() if not with_tool else version_command().tools
        ),
        dev,
    )
    await approve_version(c, "claims", "claims-triage", version, risk)
    if await c.bundles._bundles.get("claims-policy", "1.0.0") is None:
        await c.bundles.publish(bundle_command(), op(c, "policy@corp.test"))
    return await c.registry.get_version("claims", "claims-triage", version)


async def deploy(c: Container, **kwargs: Any) -> DeploymentResult:
    return await c.deployments.apply(deploy_command(**kwargs), op(c, "deployer@corp.test"))
