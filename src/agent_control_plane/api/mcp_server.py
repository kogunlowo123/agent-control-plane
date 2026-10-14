"""MCP tools of the control plane, served over streamable HTTP at ``/mcp/``.

Built on the official ``mcp`` SDK (``MCPServer``, the 2.x name of FastMCP).
Every tool has typed input and output schemas, authorizes the calling agent
(identity fabric or local policy) before doing anything, and writes an audit
event for every invocation, successful or not.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from agent_control_plane import __version__
from agent_control_plane.application.commands import EngageKillSwitch
from agent_control_plane.application.governance import AgentCaller
from agent_control_plane.application.operations import (
    AgentListing,
    DeploymentView,
    RuntimeStatus,
)
from agent_control_plane.domain.errors import ControlPlaneError
from agent_control_plane.domain.models import KillScope
from agent_control_plane.orchestration.reconciler import DriftReport
from agent_control_plane.runtime.container import Container

DeploymentName = Annotated[
    str, Field(pattern=r"^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$", description="Deployment name")
]


class KillSwitchOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    kill_switch_id: str
    scope: str
    target: str
    affected: list[str]
    phases: dict[str, str]
    identity_actions: dict[str, str]


ContainerSource = Callable[[], Container]


def build_mcp_server(get_container: ContainerSource) -> MCPServer[Any]:
    server: MCPServer[Any] = MCPServer(
        "agent-control-plane",
        title="Agent Control Plane",
        description="Registry, deployment status, drift and kill switch for enterprise agents",
        version=__version__,
        log_level="WARNING",
    )

    async def invoke[T](
        tool: str, resource: str, ctx: Context, call: Callable[[AgentCaller], Awaitable[T]]
    ) -> T:
        c = get_container()
        headers = ctx.headers or {}
        caller = AgentCaller(headers.get("authorization"), c.agent_authorizer)
        try:
            result = await call(caller)
        except ControlPlaneError as exc:
            decision = caller.last.decision.value if caller.last else "unauthenticated"
            c.metrics.mcp_tool_calls.labels(tool, exc.code).inc()
            c.metrics.authz_decisions.labels("mcp", decision).inc()
            await c.recorder.record(
                caller.subject or "unauthenticated",
                f"mcp.{tool}",
                resource,
                "failure",
                {"error": exc.code},
            )
            raise ToolError(f"{exc.code}: {exc.message}") from exc
        c.metrics.mcp_tool_calls.labels(tool, "ok").inc()
        c.metrics.authz_decisions.labels("mcp", "allow").inc()
        await c.recorder.record(caller.subject or "unknown", f"mcp.{tool}", resource, "success")
        return result

    @server.tool(
        description="List registered agents with owners, risk tier and classification ceiling.",
        annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    )
    async def list_agents(
        ctx: Context,
        include_retired: bool = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
    ) -> AgentListing:
        return await invoke(
            "list_agents",
            "agent:*",
            ctx,
            lambda caller: get_container().operations.list_agents(
                caller, include_retired=include_retired, limit=limit
            ),
        )

    @server.tool(
        description="Desired state and last reconciled status of one agent deployment.",
        annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    )
    async def get_deployment(deployment: DeploymentName, ctx: Context) -> DeploymentView:
        return await invoke(
            "get_deployment",
            f"deployment:{deployment}",
            ctx,
            lambda caller: get_container().operations.deployment(caller, deployment),
        )

    @server.tool(
        description=(
            "Compare a deployment's desired Kubernetes objects with the live cluster without "
            "changing anything. Reports out-of-band drift and pending rollouts."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    )
    async def detect_drift(deployment: DeploymentName, ctx: Context) -> DriftReport:
        return await invoke(
            "detect_drift",
            f"deployment:{deployment}",
            ctx,
            lambda caller: get_container().operations.drift(caller, deployment),
        )

    @server.tool(
        description="Whether a deployment may run now (false while a kill switch covers it).",
        annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    )
    async def runtime_status(deployment: DeploymentName, ctx: Context) -> RuntimeStatus:
        return await invoke(
            "runtime_status",
            f"deployment:{deployment}",
            ctx,
            lambda caller: get_container().operations.runtime_status(caller, deployment),
        )

    @server.tool(
        description=(
            "Emergency stop: scale the target to zero, deny all its network traffic and suspend "
            "its identities. Scope global (target '*'), agent (namespace/name) or deployment."
        ),
        annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False),
    )
    async def engage_kill_switch(
        scope: KillScope,
        target: Annotated[str, Field(min_length=1, max_length=200)],
        reason: Annotated[str, Field(min_length=5, max_length=500)],
        ctx: Context,
    ) -> KillSwitchOutcome:
        command = EngageKillSwitch(scope=scope, target=target, reason=reason)

        async def run(caller: AgentCaller) -> KillSwitchOutcome:
            result = await get_container().operations.engage_kill_switch(caller, command)
            return KillSwitchOutcome(
                kill_switch_id=result.kill_switch.id,
                scope=result.kill_switch.scope.value,
                target=result.kill_switch.target,
                affected=list(result.affected),
                phases={s.name: s.phase.value for s in result.statuses},
                identity_actions=dict(result.identity_actions),
            )

        return await invoke("engage_kill_switch", f"kill_switch:{target}", ctx, run)

    return server
