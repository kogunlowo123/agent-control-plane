"""Agent and tool registry: versions, owners, risk and lifecycle.

Approvals follow the policy set: separation of duties (the submitter cannot
approve), and a two-person rule for high and critical risk (the first
approval is recorded and the version stays in review until a second,
different approver signs off).
"""

from __future__ import annotations

from collections.abc import Sequence

from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.policy import Resource

from agent_control_plane.application.commands import (
    AgentResult,
    AgentVersionResult,
    CreateAgent,
    CreateAgentVersion,
    CreateTool,
    Reason,
    ToolResult,
    Transition,
)
from agent_control_plane.application.governance import Caller, Governance
from agent_control_plane.domain.errors import ConflictError, InvalidStateError, NotFoundError
from agent_control_plane.domain.models import (
    AgentRecord,
    AgentStatus,
    AgentVersion,
    Approval,
    DeploymentState,
    Lifecycle,
    LifecycleAction,
    ToolVersion,
)
from agent_control_plane.domain.ports import (
    AgentRepository,
    AgentVersionRepository,
    Clock,
    DeploymentRepository,
    ToolRepository,
)
from agent_control_plane.security.content import TextScreen

USABLE_TOOL_STATES = frozenset({Lifecycle.APPROVED, Lifecycle.DEPRECATED})
ACTION = {
    LifecycleAction.SUBMIT: "controlplane:registry:submit",
    LifecycleAction.APPROVE: "controlplane:registry:approve",
    LifecycleAction.REJECT: "controlplane:registry:reject",
    LifecycleAction.DEPRECATE: "controlplane:registry:deprecate",
    LifecycleAction.RETIRE: "controlplane:registry:retire",
}
WRITE = "controlplane:registry:write"


class RegistryService:
    def __init__(
        self,
        *,
        agents: AgentRepository,
        versions: AgentVersionRepository,
        tools: ToolRepository,
        deployments: DeploymentRepository,
        governance: Governance,
        screen: TextScreen,
        clock: Clock,
    ) -> None:
        self._agents = agents
        self._versions = versions
        self._tools = tools
        self._deployments = deployments
        self._gov = governance
        self._screen = screen
        self._clock = clock

    # ---------------------------------------------------------------- agents

    async def create_agent(self, command: CreateAgent, caller: Caller) -> AgentRecord:
        key = f"{command.namespace}/{command.name}"
        decided = await self._gov.check(
            caller,
            action=WRITE,
            resource=Resource(type="agent", id=key, classification=command.max_classification),
            risk=command.risk,
        )
        now = self._clock.now()
        agent = AgentRecord(
            namespace=command.namespace,
            name=command.name,
            display_name=self._screen.free_text("display_name", command.display_name),
            mission=self._screen.free_text("mission", command.mission),
            owners=command.owners,
            risk=command.risk,
            max_classification=command.max_classification,
            disallowed_actions=command.disallowed_actions,
            created_by=decided.subject,
            created_at=now,
            updated_at=now,
        )
        await self._agents.add(agent)
        await self._gov.recorder.record(
            decided.subject, "agent.create", f"agent:{key}", "success", {"risk": int(agent.risk)}
        )
        return agent

    async def get_agent(self, namespace: str, name: str) -> AgentRecord:
        agent = await self._agents.get(namespace, name)
        if agent is None:
            raise NotFoundError(f"agent {namespace}/{name} not found")
        return agent

    async def list_agents(
        self, *, status: AgentStatus | None, limit: int, offset: int
    ) -> Sequence[AgentRecord]:
        return await self._agents.list(status=status, limit=limit, offset=offset)

    async def retire_agent(
        self, namespace: str, name: str, command: Reason, caller: Caller
    ) -> AgentResult:
        agent = await self.get_agent(namespace, name)
        decided = await self._gov.check(
            caller,
            action=ACTION[LifecycleAction.RETIRE],
            resource=Resource(type="agent", id=agent.key, classification=agent.max_classification),
            risk=agent.risk,
        )
        if agent.status is AgentStatus.RETIRED:
            raise InvalidStateError(f"agent {agent.key} is already retired")
        live = await self._deployments.list(
            agent_key=agent.key,
            states=[
                DeploymentState.ACTIVE,
                DeploymentState.PENDING_APPROVAL,
                DeploymentState.DELETING,
            ],
        )
        if live:
            raise InvalidStateError(
                f"agent {agent.key} still has deployments: {sorted(d.name for d in live)}"
            )
        reason = self._screen.free_text("reason", command.reason)
        now = self._clock.now()
        retired: list[str] = []
        for version in await self._versions.list_for(namespace, name):
            if version.state is not Lifecycle.RETIRED:
                await self._versions.update(
                    version.transition(LifecycleAction.RETIRE, actor=decided.subject, at=now)
                )
                retired.append(version.version)
        updated = agent.model_copy(update={"status": AgentStatus.RETIRED, "updated_at": now})
        await self._agents.update(updated)
        await self._gov.recorder.record(
            decided.subject,
            "agent.retire",
            f"agent:{agent.key}",
            "success",
            {"reason": reason, "retired_versions": retired},
        )
        return AgentResult(agent=updated, retired_versions=tuple(retired))

    # -------------------------------------------------------------- versions

    async def create_version(
        self, namespace: str, name: str, command: CreateAgentVersion, caller: Caller
    ) -> AgentVersion:
        agent = await self.get_agent(namespace, name)
        decided = await self._gov.check(
            caller,
            action=WRITE,
            resource=Resource(
                type="agent_version",
                id=f"{agent.key}@{command.version}",
                classification=agent.max_classification,
            ),
            risk=agent.risk,
        )
        if agent.status is AgentStatus.RETIRED:
            raise InvalidStateError(f"agent {agent.key} is retired")
        for ref in command.tools:
            if await self._tools.get(ref.name, ref.version) is None:
                raise NotFoundError(f"tool {ref.key} is not registered")
        now = self._clock.now()
        version = AgentVersion(
            namespace=namespace,
            name=name,
            version=command.version,
            framework=command.framework,
            entrypoint=command.entrypoint,
            image=command.image,
            tools=command.tools,
            scopes=command.scopes,
            egress=command.egress,
            resources=command.resources,
            health_path=command.health_path,
            release_notes=self._screen.free_text("release_notes", command.release_notes),
            created_by=decided.subject,
            created_at=now,
            updated_at=now,
        )
        await self._versions.add(version)
        await self._gov.recorder.record(
            decided.subject,
            "agent_version.create",
            f"agent_version:{version.key}",
            "success",
            {"framework": version.framework.value, "image": version.image.reference},
        )
        return version

    async def get_version(self, namespace: str, name: str, version: str) -> AgentVersion:
        found = await self._versions.get(namespace, name, version)
        if found is None:
            raise NotFoundError(f"agent version {namespace}/{name}@{version} not found")
        return found

    async def list_versions(self, namespace: str, name: str) -> Sequence[AgentVersion]:
        await self.get_agent(namespace, name)
        return await self._versions.list_for(namespace, name)

    async def transition_version(
        self, namespace: str, name: str, version: str, command: Transition, caller: Caller
    ) -> AgentVersionResult:
        agent = await self.get_agent(namespace, name)
        current = await self.get_version(namespace, name, version)
        action = command.action
        decided = await self._gov.check(
            caller,
            action=ACTION[action],
            resource=Resource(
                type="agent_version",
                id=current.key,
                classification=agent.max_classification,
                attributes={
                    "risk": int(agent.risk),
                    "submitted_by": current.submitted_by or "",
                    "approvals": len(current.approvals),
                    "unrestricted_egress": current.unrestricted_egress,
                },
            ),
            risk=agent.risk,
            approval_workflow=action is LifecycleAction.APPROVE,
        )
        comment = self._screen.free_text("comment", command.comment)
        now = self._clock.now()
        outcome = "applied"
        if action is LifecycleAction.APPROVE:
            self._ensure_new_approver(current.approvals, decided.subject, current.key)
            await self._ensure_tools_usable(current)
            approval = Approval(
                actor=decided.subject, at=now, comment=comment, policy_digest=decided.policy_digest
            )
            if decided.decision is Decision.REQUIRE_APPROVAL:
                updated = current.with_approval(approval, at=now)
                outcome = "approval_recorded"
            else:
                updated = current.transition(
                    action, actor=decided.subject, at=now, approval=approval
                )
        else:
            if action is LifecycleAction.RETIRE:
                await self._ensure_not_deployed(current)
            updated = current.transition(action, actor=decided.subject, at=now)
        await self._versions.update(updated)
        await self._gov.recorder.record(
            decided.subject,
            f"agent_version.{action.value}",
            f"agent_version:{current.key}",
            outcome,
            {
                "from": current.state.value,
                "to": updated.state.value,
                "approvals": len(updated.approvals),
                "comment": comment,
                "policy_digest": decided.policy_digest,
            },
        )
        return AgentVersionResult(outcome=outcome, version=updated)

    async def _ensure_tools_usable(self, version: AgentVersion) -> None:
        for ref in version.tools:
            tool = await self._tools.get(ref.name, ref.version)
            if tool is None or tool.state not in USABLE_TOOL_STATES:
                state = tool.state.value if tool else "missing"
                raise InvalidStateError(f"tool {ref.key} is {state}; approve it first")

    async def _ensure_not_deployed(self, version: AgentVersion) -> None:
        for spec in await self._deployments.list(
            agent_key=version.agent_key,
            states=[DeploymentState.ACTIVE, DeploymentState.PENDING_APPROVAL],
        ):
            revisions = [r for r in (spec.current, spec.pending) if r is not None]
            if any(r.version == version.version for r in revisions):
                raise InvalidStateError(
                    f"version {version.key} is used by deployment {spec.name}; deprecate instead"
                )

    @staticmethod
    def _ensure_new_approver(approvals: Sequence[Approval], subject: str, key: str) -> None:
        if any(a.actor == subject for a in approvals):
            raise ConflictError(f"{subject} has already approved {key}")

    # ------------------------------------------------------------------ tools

    async def create_tool(self, command: CreateTool, caller: Caller) -> ToolVersion:
        key = f"{command.name}@{command.version}"
        decided = await self._gov.check(
            caller,
            action=WRITE,
            resource=Resource(type="tool", id=key),
            risk=command.risk,
        )
        if command.input_schema.get("type") != "object":
            raise InvalidStateError("tool input_schema must describe an object")
        now = self._clock.now()
        tool = ToolVersion(
            name=command.name,
            version=command.version,
            description=self._screen.free_text("description", command.description),
            owner=command.owner,
            risk=command.risk,
            endpoint=command.endpoint,
            input_schema=command.input_schema,
            schema_digest=ToolVersion.digest_of(command.input_schema),
            created_by=decided.subject,
            created_at=now,
            updated_at=now,
        )
        await self._tools.add(tool)
        await self._gov.recorder.record(
            decided.subject,
            "tool.create",
            f"tool:{key}",
            "success",
            {"schema_digest": tool.schema_digest, "risk": int(tool.risk)},
        )
        return tool

    async def get_tool(self, name: str, version: str) -> ToolVersion:
        tool = await self._tools.get(name, version)
        if tool is None:
            raise NotFoundError(f"tool {name}@{version} not found")
        return tool

    async def list_tools(
        self, *, state: Lifecycle | None, limit: int, offset: int
    ) -> Sequence[ToolVersion]:
        return await self._tools.list(state=state, limit=limit, offset=offset)

    async def transition_tool(
        self, name: str, version: str, command: Transition, caller: Caller
    ) -> ToolResult:
        current = await self.get_tool(name, version)
        action = command.action
        decided = await self._gov.check(
            caller,
            action=ACTION[action],
            resource=Resource(
                type="tool",
                id=current.key,
                attributes={
                    "risk": int(current.risk),
                    "submitted_by": current.submitted_by or "",
                    "approvals": len(current.approvals),
                    "unrestricted_egress": False,
                },
            ),
            risk=RiskLevel(current.risk),
            approval_workflow=action is LifecycleAction.APPROVE,
        )
        comment = self._screen.free_text("comment", command.comment)
        now = self._clock.now()
        outcome = "applied"
        if action is LifecycleAction.APPROVE:
            self._ensure_new_approver(current.approvals, decided.subject, current.key)
            approval = Approval(
                actor=decided.subject, at=now, comment=comment, policy_digest=decided.policy_digest
            )
            if decided.decision is Decision.REQUIRE_APPROVAL:
                updated = current.with_approval(approval, at=now)
                outcome = "approval_recorded"
            else:
                updated = current.transition(
                    action, actor=decided.subject, at=now, approval=approval
                )
        else:
            updated = current.transition(action, actor=decided.subject, at=now)
        await self._tools.update(updated)
        await self._gov.recorder.record(
            decided.subject,
            f"tool.{action.value}",
            f"tool:{current.key}",
            outcome,
            {
                "from": current.state.value,
                "to": updated.state.value,
                "approvals": len(updated.approvals),
                "schema_digest": current.schema_digest,
                "comment": comment,
            },
        )
        return ToolResult(outcome=outcome, tool=updated)
