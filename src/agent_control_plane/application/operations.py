"""Operations exposed to agents over MCP and A2A, and to agent runtimes.

Both protocol surfaces call these methods so that authorization, audit and
behaviour are identical whichever protocol an agent speaks.
"""

from __future__ import annotations

from agentic_core.domain.classification import RiskLevel
from agentic_core.policy import Resource
from pydantic import BaseModel, ConfigDict, Field

from agent_control_plane.application.commands import EngageKillSwitch, KillSwitchResult
from agent_control_plane.application.deployments import DeploymentService
from agent_control_plane.application.governance import Caller, Governance
from agent_control_plane.application.killswitch import KillSwitchService
from agent_control_plane.application.registry import RegistryService
from agent_control_plane.domain.models import AgentStatus, DeploymentState, DeploymentStatus
from agent_control_plane.orchestration.reconciler import DriftReport, Reconciler

READ_REGISTRY = "controlplane:registry:read"
READ_DEPLOYMENTS = "controlplane:deployments:read"
RUNTIME_STATUS = "controlplane:runtime:status"


class AgentSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent: str
    display_name: str
    risk: int
    max_classification: int
    status: str
    business_owner: str
    escalation_contact: str


class AgentListing(BaseModel):
    model_config = ConfigDict(frozen=True)

    agents: list[AgentSummary]
    count: int


class DeploymentView(BaseModel):
    model_config = ConfigDict(frozen=True)

    deployment: str
    agent: str
    environment: str
    namespace: str
    state: str
    version: str | None
    generation: int
    pending_approval: bool
    identity: str | None
    status: DeploymentStatus | None


class RuntimeStatus(BaseModel):
    """What an agent runtime checks before each run."""

    model_config = ConfigDict(frozen=True)

    deployment: str
    run_permitted: bool = Field(description="False while a kill switch covers the deployment")
    killed_by: tuple[str, ...]
    version: str | None
    policy_bundle: str | None
    identity: str | None


class Operations:
    def __init__(
        self,
        *,
        registry: RegistryService,
        deployments: DeploymentService,
        kill_switches: KillSwitchService,
        reconciler: Reconciler,
        governance: Governance,
    ) -> None:
        self._registry = registry
        self._deployments = deployments
        self._kill_switches = kill_switches
        self._reconciler = reconciler
        self._gov = governance

    async def list_agents(
        self, caller: Caller, *, include_retired: bool = False, limit: int = 100
    ) -> AgentListing:
        await self._gov.check(caller, action=READ_REGISTRY, resource=Resource(type="agent", id="*"))
        records = await self._registry.list_agents(
            status=None if include_retired else AgentStatus.ACTIVE, limit=limit, offset=0
        )
        summaries = [
            AgentSummary(
                agent=r.key,
                display_name=r.display_name,
                risk=int(r.risk),
                max_classification=int(r.max_classification),
                status=r.status.value,
                business_owner=r.owners.business,
                escalation_contact=r.owners.escalation_contact,
            )
            for r in records
        ]
        return AgentListing(agents=summaries, count=len(summaries))

    async def deployment(self, caller: Caller, name: str) -> DeploymentView:
        await self._gov.check(
            caller, action=READ_DEPLOYMENTS, resource=Resource(type="deployment", id=name)
        )
        spec = await self._deployments.get(name)
        status = await self._deployments.status(name)
        return DeploymentView(
            deployment=spec.name,
            agent=spec.agent_key,
            environment=spec.environment.value,
            namespace=spec.namespace,
            state=spec.state.value,
            version=spec.current.version if spec.current else None,
            generation=spec.current.generation if spec.current else 0,
            pending_approval=spec.pending is not None,
            identity=spec.identity_uri,
            status=status,
        )

    async def drift(self, caller: Caller, name: str) -> DriftReport:
        await self._gov.check(
            caller, action=READ_DEPLOYMENTS, resource=Resource(type="deployment", id=name)
        )
        await self._deployments.get(name)
        return await self._reconciler.detect_drift(name)

    async def engage_kill_switch(
        self, caller: Caller, command: EngageKillSwitch
    ) -> KillSwitchResult:
        return await self._kill_switches.engage(command, caller)

    async def runtime_status(self, caller: Caller, deployment: str) -> RuntimeStatus:
        await self._gov.check(
            caller,
            action=RUNTIME_STATUS,
            resource=Resource(type="deployment", id=deployment),
            risk=RiskLevel.LOW,
        )
        spec = await self._deployments.get(deployment)
        killed = await self._kill_switches.is_killed(deployment)
        current = spec.current
        live = current is not None and spec.state is DeploymentState.ACTIVE
        return RuntimeStatus(
            deployment=deployment,
            run_permitted=live and not killed,
            killed_by=killed,
            version=current.version if current else None,
            policy_bundle=current.policy_bundle.key if current else None,
            identity=spec.identity_uri,
        )
