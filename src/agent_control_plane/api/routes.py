"""Operator REST API.

Every ``/v1`` route except the runtime status endpoint requires an
enterprise IdP bearer token; the caller's roles are evaluated against the
local control-plane policy set (policies/control-plane.yaml). The runtime
status endpoint is called by agent workloads and is decided by the agent
authorizer (identity fabric when configured).
"""

from __future__ import annotations

from typing import Annotated

from agentic_core.audit import AuditEvent, verify_chain
from agentic_core.domain.errors import AuditIntegrityError
from agentic_core.policy import Resource
from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from agent_control_plane.api.schemas import (
    AgentList,
    AuditChains,
    AuditEvents,
    AuditVerification,
    BundleList,
    BundleView,
    DeploymentDetail,
    DeploymentList,
    KillSwitchList,
    ManifestList,
    ToolList,
    VersionList,
)
from agent_control_plane.application.commands import (
    AgentResult,
    AgentVersionResult,
    ApplyDeployment,
    Approve,
    CreateAgent,
    CreateAgentVersion,
    CreateTool,
    DeploymentResult,
    EngageKillSwitch,
    KillSwitchResult,
    PublishBundle,
    Reason,
    ToolResult,
    Transition,
)
from agent_control_plane.application.governance import AgentCaller, OperatorCaller
from agent_control_plane.application.operations import RuntimeStatus
from agent_control_plane.domain.models import (
    AgentRecord,
    AgentStatus,
    AgentVersion,
    DeploymentState,
    DeploymentStatus,
    KillSwitch,
    Lifecycle,
    PolicyBundle,
    ToolVersion,
)
from agent_control_plane.infrastructure.database import list_chains, read_chain
from agent_control_plane.orchestration.reconciler import DriftReport
from agent_control_plane.runtime.container import Container

router = APIRouter()

SEGMENT = r"^[a-z0-9]([a-z0-9\-_.]{0,62}[a-z0-9])?$"
LABEL = r"^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$"
VERSION = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9a-z][0-9a-z.\-]*)?$"
TOOL = r"^[a-z][a-z0-9_.\-]{1,63}$"

Namespace = Annotated[str, Path(pattern=SEGMENT, max_length=64)]
Name = Annotated[str, Path(pattern=SEGMENT, max_length=64)]
Version = Annotated[str, Path(pattern=VERSION, max_length=23)]
DeploymentName = Annotated[str, Path(pattern=LABEL, max_length=40)]
ToolName = Annotated[str, Path(pattern=TOOL, max_length=64)]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=100_000)]


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


Deps = Annotated[Container, Depends(container)]


async def operator(
    c: Deps, authorization: Annotated[str | None, Header()] = None
) -> OperatorCaller:
    principal = await c.authenticator.authenticate(authorization)
    return OperatorCaller(principal, c.gate)


Operator = Annotated[OperatorCaller, Depends(operator)]


async def _read(c: Container, who: OperatorCaller, action: str, kind: str, ident: str) -> None:
    await c.governance.check(who, action=action, resource=Resource(type=kind, id=ident))


# --------------------------------------------------------------------- agents


@router.post("/v1/agents", status_code=201, tags=["registry"])
async def create_agent(body: CreateAgent, c: Deps, who: Operator) -> AgentRecord:
    agent = await c.registry.create_agent(body, who)
    c.metrics.registry_events.labels("agent", "create").inc()
    return agent


@router.get("/v1/agents", tags=["registry"])
async def list_agents(
    c: Deps,
    who: Operator,
    status: AgentStatus | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> AgentList:
    await _read(c, who, "controlplane:registry:read", "agent", "*")
    items = await c.registry.list_agents(status=status, limit=limit, offset=offset)
    return AgentList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/agents/{namespace}/{name}", tags=["registry"])
async def get_agent(namespace: Namespace, name: Name, c: Deps, who: Operator) -> AgentRecord:
    await _read(c, who, "controlplane:registry:read", "agent", f"{namespace}/{name}")
    return await c.registry.get_agent(namespace, name)


@router.post("/v1/agents/{namespace}/{name}/retire", tags=["registry"])
async def retire_agent(
    namespace: Namespace, name: Name, body: Reason, c: Deps, who: Operator
) -> AgentResult:
    result = await c.registry.retire_agent(namespace, name, body, who)
    c.metrics.registry_events.labels("agent", "retire").inc()
    return result


@router.post("/v1/agents/{namespace}/{name}/versions", status_code=201, tags=["registry"])
async def create_version(
    namespace: Namespace, name: Name, body: CreateAgentVersion, c: Deps, who: Operator
) -> AgentVersion:
    version = await c.registry.create_version(namespace, name, body, who)
    c.metrics.registry_events.labels("agent_version", "create").inc()
    return version


@router.get("/v1/agents/{namespace}/{name}/versions", tags=["registry"])
async def list_versions(namespace: Namespace, name: Name, c: Deps, who: Operator) -> VersionList:
    await _read(c, who, "controlplane:registry:read", "agent", f"{namespace}/{name}")
    return VersionList(items=list(await c.registry.list_versions(namespace, name)))


@router.get("/v1/agents/{namespace}/{name}/versions/{version}", tags=["registry"])
async def get_version(
    namespace: Namespace, name: Name, version: Version, c: Deps, who: Operator
) -> AgentVersion:
    await _read(c, who, "controlplane:registry:read", "agent_version", f"{namespace}/{name}")
    return await c.registry.get_version(namespace, name, version)


@router.post("/v1/agents/{namespace}/{name}/versions/{version}/transitions", tags=["registry"])
async def transition_version(
    *,
    namespace: Namespace,
    name: Name,
    version: Version,
    body: Transition,
    c: Deps,
    who: Operator,
) -> AgentVersionResult:
    result = await c.registry.transition_version(namespace, name, version, body, who)
    c.metrics.registry_events.labels("agent_version", body.action.value).inc()
    return result


# ---------------------------------------------------------------------- tools


@router.post("/v1/tools", status_code=201, tags=["registry"])
async def create_tool(body: CreateTool, c: Deps, who: Operator) -> ToolVersion:
    tool = await c.registry.create_tool(body, who)
    c.metrics.registry_events.labels("tool", "create").inc()
    return tool


@router.get("/v1/tools", tags=["registry"])
async def list_tools(
    c: Deps,
    who: Operator,
    state: Lifecycle | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> ToolList:
    await _read(c, who, "controlplane:registry:read", "tool", "*")
    items = await c.registry.list_tools(state=state, limit=limit, offset=offset)
    return ToolList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/tools/{name}/{version}", tags=["registry"])
async def get_tool(name: ToolName, version: Version, c: Deps, who: Operator) -> ToolVersion:
    await _read(c, who, "controlplane:registry:read", "tool", f"{name}@{version}")
    return await c.registry.get_tool(name, version)


@router.post("/v1/tools/{name}/{version}/transitions", tags=["registry"])
async def transition_tool(
    name: ToolName, version: Version, body: Transition, c: Deps, who: Operator
) -> ToolResult:
    result = await c.registry.transition_tool(name, version, body, who)
    c.metrics.registry_events.labels("tool", body.action.value).inc()
    return result


# ------------------------------------------------------------- policy bundles


@router.post("/v1/policy-bundles", status_code=201, tags=["policy"])
async def publish_bundle(body: PublishBundle, c: Deps, who: Operator) -> PolicyBundle:
    return await c.bundles.publish(body, who)


@router.get("/v1/policy-bundles", tags=["policy"])
async def list_bundles(
    c: Deps, who: Operator, limit: Limit = 100, offset: Offset = 0
) -> BundleList:
    await _read(c, who, "controlplane:bundle:read", "policy_bundle", "*")
    items = await c.bundles.list(limit=limit, offset=offset)
    return BundleList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/policy-bundles/signing-key", tags=["policy"])
async def bundle_signing_key(c: Deps) -> dict[str, object]:
    """Public JWK set agents use to verify bundle signatures."""
    return c.bundles.signing_key()


@router.get("/v1/policy-bundles/{name}/{version}", tags=["policy"])
async def get_bundle(name: DeploymentName, version: Version, c: Deps, who: Operator) -> BundleView:
    await _read(c, who, "controlplane:bundle:read", "policy_bundle", f"{name}@{version}")
    bundle = await c.bundles.get(name, version)
    return BundleView(bundle=bundle, verified=c.bundles.verify(bundle))


# ---------------------------------------------------------------- deployments


@router.post(
    "/v1/deployments",
    tags=["deployments"],
    responses={202: {"model": DeploymentResult, "description": "Recorded; awaits approval"}},
)
async def apply_deployment(
    body: ApplyDeployment, c: Deps, who: Operator, response: Response
) -> DeploymentResult:
    """Create or update a deployment's desired state (idempotent per name)."""
    result = await c.deployments.apply(body, who)
    if result.outcome == "approval_required":
        response.status_code = 202
    return result


@router.get("/v1/deployments", tags=["deployments"])
async def list_deployments(
    *,
    c: Deps,
    who: Operator,
    state: DeploymentState | None = None,
    agent: Annotated[str | None, Query(max_length=130)] = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> DeploymentList:
    await _read(c, who, "controlplane:deployments:read", "deployment", "*")
    items = await c.deployments.list(state=state, agent_key=agent, limit=limit, offset=offset)
    return DeploymentList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/deployments/{name}", tags=["deployments"])
async def get_deployment(name: DeploymentName, c: Deps, who: Operator) -> DeploymentDetail:
    await _read(c, who, "controlplane:deployments:read", "deployment", name)
    return DeploymentDetail(
        deployment=await c.deployments.get(name), status=await c.deployments.status(name)
    )


@router.post("/v1/deployments/{name}/approve", tags=["deployments"])
async def approve_deployment(
    name: DeploymentName, body: Approve, c: Deps, who: Operator
) -> DeploymentResult:
    return await c.deployments.approve(name, body, who)


@router.post("/v1/deployments/{name}/delete", status_code=202, tags=["deployments"])
async def delete_deployment(
    name: DeploymentName, body: Reason, c: Deps, who: Operator
) -> DeploymentResult:
    return await c.deployments.delete(name, body, who)


@router.post("/v1/deployments/{name}/reconcile", tags=["deployments"])
async def reconcile_deployment(name: DeploymentName, c: Deps, who: Operator) -> DeploymentStatus:
    await c.deployments.get(name)
    await _read(c, who, "controlplane:deployment:reconcile", "deployment", name)
    return await c.reconciler.reconcile(name)


@router.get("/v1/deployments/{name}/drift", tags=["deployments"])
async def deployment_drift(name: DeploymentName, c: Deps, who: Operator) -> DriftReport:
    await _read(c, who, "controlplane:deployments:read", "deployment", name)
    await c.deployments.get(name)
    return await c.reconciler.detect_drift(name)


@router.get("/v1/deployments/{name}/manifests", tags=["deployments"])
async def deployment_manifests(name: DeploymentName, c: Deps, who: Operator) -> ManifestList:
    await _read(c, who, "controlplane:deployments:read", "deployment", name)
    spec = await c.deployments.get(name)
    objects, killed = await c.reconciler.desired(spec)
    return ManifestList(deployment=name, killed_by=list(killed), items=objects)


# --------------------------------------------------------------- kill switch


@router.post("/v1/kill-switches", status_code=201, tags=["kill-switch"])
async def engage_kill_switch(body: EngageKillSwitch, c: Deps, who: Operator) -> KillSwitchResult:
    return await c.kill_switches.engage(body, who)


@router.get("/v1/kill-switches", tags=["kill-switch"])
async def list_kill_switches(c: Deps, who: Operator, active: bool | None = None) -> KillSwitchList:
    await _read(c, who, "controlplane:killswitch:read", "kill_switch", "*")
    return KillSwitchList(items=list(await c.kill_switches.list(active=active)))


@router.get("/v1/kill-switches/{switch_id}", tags=["kill-switch"])
async def get_kill_switch(
    switch_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")], c: Deps, who: Operator
) -> KillSwitch:
    await _read(c, who, "controlplane:killswitch:read", "kill_switch", switch_id)
    return await c.kill_switches.get(switch_id)


@router.post("/v1/kill-switches/{switch_id}/release", tags=["kill-switch"])
async def release_kill_switch(
    switch_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    body: Reason,
    c: Deps,
    who: Operator,
) -> KillSwitchResult:
    return await c.kill_switches.release(switch_id, body, who)


# ------------------------------------------------------------------- runtime


@router.get("/v1/runtime/{name}", tags=["runtime"])
async def runtime_status(
    name: DeploymentName, c: Deps, authorization: Annotated[str | None, Header()] = None
) -> RuntimeStatus:
    """Checked by agent runtimes before each run; agents authenticate with their credential."""
    caller = AgentCaller(authorization, c.agent_authorizer)
    status = await c.operations.runtime_status(caller, name)
    c.metrics.authz_decisions.labels("runtime", "allow").inc()
    return status


# --------------------------------------------------------------------- audit


@router.get("/v1/audit/chains", tags=["audit"])
async def audit_chains(c: Deps, who: Operator) -> AuditChains:
    await _read(c, who, "controlplane:audit:read", "audit", "*")
    return AuditChains(chains=await list_chains(c.engine))


@router.get("/v1/audit/events", tags=["audit"])
async def audit_events(
    c: Deps,
    who: Operator,
    chain: Annotated[str, Query(min_length=1, max_length=128)],
    limit: Limit = 100,
    offset: Offset = 0,
) -> AuditEvents:
    await _read(c, who, "controlplane:audit:read", "audit", chain)
    items: list[AuditEvent] = [
        e async for e in read_chain(c.engine, chain, limit=limit, offset=offset)
    ]
    return AuditEvents(chain=chain, items=items, limit=limit, offset=offset)


@router.get("/v1/audit/verify", tags=["audit"])
async def audit_verify(
    c: Deps, who: Operator, chain: Annotated[str, Query(min_length=1, max_length=128)]
) -> AuditVerification:
    """Verify hash linkage and signatures of a chain written with this replica's audit key."""
    await _read(c, who, "controlplane:audit:read", "audit", chain)
    events = [e async for e in read_chain(c.engine, chain)]
    key_id = c.audit_key.key_id
    try:
        count = verify_chain(events, {key_id: c.audit_key.public})
    except AuditIntegrityError as exc:
        return AuditVerification(
            chain=chain,
            verified=False,
            events=len(events),
            key_id=key_id,
            error=str(exc),
            failed_sequence=exc.sequence,
        )
    return AuditVerification(chain=chain, verified=True, events=count, key_id=key_id)


# ---------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
