"""Kill switch: stop an agent everywhere, immediately, and keep it stopped.

Engaging a kill switch (global, per agent, or per deployment):

1. records it durably, so every later reconcile keeps the agent stopped;
2. suspends each affected deployment's identity in the identity fabric,
   which invalidates every credential it holds (credential epoch);
3. reconciles each affected deployment now: zero replicas and a deny-all
   NetworkPolicy.

Failure of step 2 for one identity never blocks steps 1 and 3. Releasing
requires a second person (policy) and reverses the steps for deployments
no other active kill switch still covers.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentic_core.domain.classification import RiskLevel
from agentic_core.domain.identifiers import new_id
from agentic_core.policy import Resource

from agent_control_plane.application.commands import (
    EngageKillSwitch,
    KillSwitchResult,
    Reason,
)
from agent_control_plane.application.governance import Caller, Governance
from agent_control_plane.domain.errors import (
    ControlPlaneError,
    InvalidStateError,
    NotFoundError,
)
from agent_control_plane.domain.models import (
    DeploymentSpec,
    DeploymentState,
    DeploymentStatus,
    KillScope,
    KillSwitch,
)
from agent_control_plane.domain.ports import (
    AgentRepository,
    Clock,
    DeploymentRepository,
    IdentityRegistrar,
    KillSwitchRepository,
)
from agent_control_plane.observability.metrics import ControlPlaneMetrics
from agent_control_plane.orchestration.reconciler import Reconciler
from agent_control_plane.security.content import TextScreen

LIVE_STATES = [DeploymentState.ACTIVE, DeploymentState.PENDING_APPROVAL]


class KillSwitchService:
    def __init__(
        self,
        *,
        switches: KillSwitchRepository,
        deployments: DeploymentRepository,
        agents: AgentRepository,
        registrar: IdentityRegistrar | None,
        reconciler: Reconciler,
        governance: Governance,
        screen: TextScreen,
        metrics: ControlPlaneMetrics,
        clock: Clock,
    ) -> None:
        self._switches = switches
        self._deployments = deployments
        self._agents = agents
        self._registrar = registrar
        self._reconciler = reconciler
        self._gov = governance
        self._screen = screen
        self._metrics = metrics
        self._clock = clock

    async def _risk_of(self, scope: KillScope, target: str) -> RiskLevel:
        if scope is KillScope.GLOBAL:
            if target != "*":
                raise ControlPlaneError("a global kill switch targets '*'")
            return RiskLevel.CRITICAL
        if scope is KillScope.AGENT:
            namespace, _, name = target.partition("/")
            agent = await self._agents.get(namespace, name) if name else None
            if agent is None:
                raise NotFoundError(f"agent {target} not found")
            return agent.risk
        spec = await self._deployments.get(target)
        if spec is None:
            raise NotFoundError(f"deployment {target} not found")
        agent = await self._agents.get(spec.agent_namespace, spec.agent_name)
        return agent.risk if agent else RiskLevel.HIGH

    async def _covered(self, switch: KillSwitch) -> list[DeploymentSpec]:
        specs = await self._deployments.list(states=LIVE_STATES)
        return [s for s in specs if switch.covers(s)]

    async def _refresh_gauge(self) -> int:
        active = len(await self._switches.list(active=True))
        self._metrics.kill_switches_active.set(active)
        return active

    async def _identity(self, op: str, spec: DeploymentSpec, reason: str) -> str:
        if self._registrar is None or spec.identity_uri is None:
            return "no_identity"
        action = self._registrar.suspend if op == "suspend" else self._registrar.reinstate
        try:
            await action(spec.identity_uri, reason)
            outcome = "success"
        except InvalidStateError:
            outcome = "not_applicable"  # e.g. identity still pending attestation
        except ControlPlaneError as exc:
            outcome = f"failed: {exc.code}"
        await self._gov.recorder.record(
            "system:kill-switch",
            f"identity.{op}",
            spec.identity_uri,
            outcome,
            {"deployment": spec.name},
        )
        return outcome

    async def list(self, *, active: bool | None) -> Sequence[KillSwitch]:
        return await self._switches.list(active=active)

    async def get(self, switch_id: str) -> KillSwitch:
        switch = await self._switches.get(switch_id)
        if switch is None:
            raise NotFoundError(f"kill switch {switch_id} not found")
        return switch

    async def engage(self, command: EngageKillSwitch, caller: Caller) -> KillSwitchResult:
        risk = await self._risk_of(command.scope, command.target)
        decided = await self._gov.check(
            caller,
            action="controlplane:killswitch:engage",
            resource=Resource(
                type="kill_switch",
                id=command.target,
                attributes={"scope": command.scope.value, "risk": int(risk)},
            ),
            risk=risk,
        )
        reason = self._screen.free_text("reason", command.reason)
        switch = KillSwitch(
            id=new_id(),
            scope=command.scope,
            target=command.target,
            reason=reason,
            engaged_by=decided.subject,
            engaged_at=self._clock.now(),
        )
        await self._switches.add(switch)
        self._metrics.kill_switch_events.labels("engage", switch.scope.value).inc()
        await self._refresh_gauge()
        affected = await self._covered(switch)
        await self._gov.recorder.record(
            decided.subject,
            "killswitch.engage",
            f"kill_switch:{switch.id}",
            "success",
            {
                "scope": switch.scope.value,
                "target": switch.target,
                "reason": reason,
                "affected": [s.name for s in affected],
            },
        )
        identity_actions = {
            s.name: await self._identity("suspend", s, f"kill switch {switch.id}: {reason}")
            for s in affected
        }
        statuses = [await self._reconciler.reconcile(s.name) for s in affected]
        return KillSwitchResult(
            kill_switch=switch,
            affected=tuple(s.name for s in affected),
            statuses=tuple(statuses),
            identity_actions=identity_actions,
        )

    async def release(self, switch_id: str, command: Reason, caller: Caller) -> KillSwitchResult:
        switch = await self.get(switch_id)
        if not switch.active:
            raise InvalidStateError(f"kill switch {switch_id} is already released")
        risk = (
            RiskLevel.CRITICAL
            if switch.scope is KillScope.GLOBAL
            else await self._risk_of(switch.scope, switch.target)
        )
        decided = await self._gov.check(
            caller,
            action="controlplane:killswitch:release",
            resource=Resource(
                type="kill_switch",
                id=switch.id,
                attributes={
                    "scope": switch.scope.value,
                    "engaged_by": switch.engaged_by,
                    "risk": int(risk),
                },
            ),
            risk=risk,
        )
        reason = self._screen.free_text("reason", command.reason)
        affected = await self._covered(switch)
        released = switch.model_copy(
            update={
                "active": False,
                "released_by": decided.subject,
                "released_at": self._clock.now(),
                "release_reason": reason,
            }
        )
        await self._switches.update(released)
        self._metrics.kill_switch_events.labels("release", switch.scope.value).inc()
        await self._refresh_gauge()
        await self._gov.recorder.record(
            decided.subject,
            "killswitch.release",
            f"kill_switch:{switch.id}",
            "success",
            {"reason": reason, "engaged_by": switch.engaged_by},
        )
        statuses: list[DeploymentStatus] = []
        identity_actions: dict[str, str] = {}
        for spec in affected:
            still_killed = await self._reconciler.killed_by(spec)
            if not still_killed:
                identity_actions[spec.name] = await self._identity(
                    "reinstate", spec, f"kill switch {switch.id} released: {reason}"
                )
            else:
                identity_actions[spec.name] = "still_killed"
            statuses.append(await self._reconciler.reconcile(spec.name))
        return KillSwitchResult(
            kill_switch=released,
            affected=tuple(s.name for s in affected),
            statuses=tuple(statuses),
            identity_actions=identity_actions,
        )

    async def is_killed(self, deployment: str) -> tuple[str, ...]:
        spec = await self._deployments.get(deployment)
        if spec is None:
            raise NotFoundError(f"deployment {deployment} not found")
        return await self._reconciler.killed_by(spec)
