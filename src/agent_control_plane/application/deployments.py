"""Deployment desired state: apply, approve, delete.

A deployment holds at most two revisions: ``current`` (what the reconciler
enforces) and ``pending`` (a change awaiting human approval). Policy decides
whether a change applies immediately or needs approval; production changes
to high-risk agents need an approver who is not the requester. Every applied
version gets its own identity in the identity fabric; the identity of the
version it replaces is revoked once the new rollout is available.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.policy import Resource

from agent_control_plane.application.commands import (
    ApplyDeployment,
    Approve,
    DeploymentResult,
    Reason,
)
from agent_control_plane.application.governance import Caller, Governance
from agent_control_plane.domain.errors import (
    ConflictError,
    ControlPlaneError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from agent_control_plane.domain.models import (
    ENV_NAME,
    RESERVED_ENV_PREFIX,
    AgentRecord,
    AgentStatus,
    Approval,
    DeploymentSpec,
    DeploymentState,
    DeploymentStatus,
    Lifecycle,
    Revision,
)
from agent_control_plane.domain.ports import (
    AgentRepository,
    AgentVersionRepository,
    BundleRepository,
    Clock,
    DeploymentRepository,
    IdentityRegistrar,
    StatusRepository,
    ToolRepository,
)
from agent_control_plane.orchestration.reconciler import Reconciler
from agent_control_plane.security.content import TextScreen

USABLE_TOOL_STATES = frozenset({Lifecycle.APPROVED, Lifecycle.DEPRECATED})


class DeploymentService:
    def __init__(
        self,
        *,
        deployments: DeploymentRepository,
        statuses: StatusRepository,
        agents: AgentRepository,
        versions: AgentVersionRepository,
        tools: ToolRepository,
        bundles: BundleRepository,
        registrar: IdentityRegistrar | None,
        reconciler: Reconciler,
        governance: Governance,
        screen: TextScreen,
        clock: Clock,
        allowed_namespaces: frozenset[str],
    ) -> None:
        self._deployments = deployments
        self._statuses = statuses
        self._agents = agents
        self._versions = versions
        self._tools = tools
        self._bundles = bundles
        self._registrar = registrar
        self._reconciler = reconciler
        self._gov = governance
        self._screen = screen
        self._clock = clock
        self._allowed = allowed_namespaces

    async def get(self, name: str) -> DeploymentSpec:
        spec = await self._deployments.get(name)
        if spec is None:
            raise NotFoundError(f"deployment {name} not found")
        return spec

    async def list(
        self, *, state: DeploymentState | None, agent_key: str | None, limit: int, offset: int
    ) -> Sequence[DeploymentSpec]:
        return await self._deployments.list(
            states=[state] if state else None, agent_key=agent_key, limit=limit, offset=offset
        )

    async def status(self, name: str) -> DeploymentStatus | None:
        await self.get(name)
        return await self._statuses.get(name)

    # --------------------------------------------------------------- validation

    async def _validate(
        self, command: ApplyDeployment, existing: DeploymentSpec | None
    ) -> AgentRecord:
        if command.namespace not in self._allowed:
            raise ForbiddenError(
                f"namespace {command.namespace} is not managed by this control plane"
            )
        agent = await self._agents.get(command.agent_namespace, command.agent_name)
        if agent is None:
            raise NotFoundError(f"agent {command.agent_namespace}/{command.agent_name} not found")
        if agent.status is not AgentStatus.ACTIVE:
            raise InvalidStateError(f"agent {agent.key} is retired")
        await self._validate_version(agent, command, existing)
        bundle = command.policy_bundle
        if await self._bundles.get(bundle.name, bundle.version) is None:
            raise NotFoundError(f"policy bundle {bundle.key} not found")
        self._validate_config(command)
        if existing is not None and existing.state is not DeploymentState.DELETED:
            self._validate_immutable(existing, agent, command)
        return agent

    async def _validate_version(
        self, agent: AgentRecord, command: ApplyDeployment, existing: DeploymentSpec | None
    ) -> None:
        version = await self._versions.get(agent.namespace, agent.name, command.version)
        if version is None:
            raise NotFoundError(f"agent version {agent.key}@{command.version} not found")
        running = existing.current.version if existing and existing.current else None
        keeps_running = version.state is Lifecycle.DEPRECATED and running == version.version
        if version.state is not Lifecycle.APPROVED and not keeps_running:
            raise InvalidStateError(
                f"version {version.key} is {version.state.value}; only approved versions deploy"
            )
        for ref in version.tools:
            tool = await self._tools.get(ref.name, ref.version)
            if tool is None or tool.state not in USABLE_TOOL_STATES:
                raise InvalidStateError(f"tool {ref.key} is not approved")

    def _validate_config(self, command: ApplyDeployment) -> None:
        for key in command.env:
            if not ENV_NAME.fullmatch(key) or key.startswith(RESERVED_ENV_PREFIX):
                raise ControlPlaneError(
                    f"env {key!r} must match {ENV_NAME.pattern} and not use {RESERVED_ENV_PREFIX}"
                )
        self._screen.config_values(command.env)
        self._screen.config_values(command.service_account_annotations)

    @staticmethod
    def _validate_immutable(
        existing: DeploymentSpec, agent: AgentRecord, command: ApplyDeployment
    ) -> None:
        fixed = {
            "agent": (existing.agent_key, agent.key),
            "namespace": (existing.namespace, command.namespace),
            "environment": (existing.environment, command.environment),
        }
        changed = [k for k, (old, new) in fixed.items() if old != new]
        if changed:
            raise ConflictError(f"deployment {existing.name} cannot change {changed}")
        if existing.state is DeploymentState.DELETING:
            raise InvalidStateError(f"deployment {existing.name} is being deleted")

    # ------------------------------------------------------------------ apply

    async def apply(self, command: ApplyDeployment, caller: Caller) -> DeploymentResult:
        existing = await self._deployments.get(command.name)
        agent = await self._validate(command, existing)
        decided = await self._gov.check(
            caller,
            action="controlplane:deployment:apply",
            resource=Resource(
                type="deployment",
                id=command.name,
                classification=agent.max_classification,
                attributes={
                    "environment": command.environment.value,
                    "risk": int(agent.risk),
                    "namespace": command.namespace,
                },
            ),
            risk=agent.risk,
            approval_workflow=True,
        )
        now = self._clock.now()
        reusable = existing if existing and existing.state is not DeploymentState.DELETED else None
        revision = Revision(
            generation=reusable.next_generation if reusable else 1,
            version=command.version,
            replicas=command.replicas,
            policy_bundle=command.policy_bundle,
            ingress_namespaces=command.ingress_namespaces,
            env=dict(command.env),
            service_account_annotations=dict(command.service_account_annotations),
            created_by=decided.subject,
            created_at=now,
        )
        base = reusable or DeploymentSpec(
            name=command.name,
            agent_namespace=command.agent_namespace,
            agent_name=command.agent_name,
            environment=command.environment,
            namespace=command.namespace,
            state=DeploymentState.PENDING_APPROVAL,
            created_at=now,
            updated_at=now,
        )
        if decided.decision is Decision.REQUIRE_APPROVAL:
            spec = base.model_copy(update={"pending": revision, "updated_at": now})
            outcome = "approval_required"
        else:
            spec = await self._promote(base, revision)
            outcome = "applied"
        if existing is None:
            await self._deployments.add(spec)
        else:
            await self._deployments.update(spec)
        await self._gov.recorder.record(
            decided.subject,
            "deployment.apply",
            f"deployment:{spec.name}",
            outcome,
            {
                "generation": revision.generation,
                "version": revision.version,
                "replicas": revision.replicas,
                "environment": spec.environment.value,
                "policy_bundle": revision.policy_bundle.key,
                "policy_digest": decided.policy_digest,
            },
        )
        status = await self._reconciler.reconcile(spec.name) if outcome == "applied" else None
        return DeploymentResult(outcome=outcome, deployment=spec, status=status)

    async def _promote(self, spec: DeploymentSpec, revision: Revision) -> DeploymentSpec:
        """Make ``revision`` current, registering a fresh identity when the version changes."""
        update: dict[str, object] = {
            "current": revision,
            "pending": None,
            "state": DeploymentState.ACTIVE,
            "updated_at": self._clock.now(),
        }
        version_changed = spec.current is None or spec.current.version != revision.version
        if self._registrar is not None and (version_changed or spec.identity_uri is None):
            agent = await self._agents.get(spec.agent_namespace, spec.agent_name)
            version = await self._versions.get(
                spec.agent_namespace, spec.agent_name, revision.version
            )
            if agent is None or version is None:
                raise NotFoundError(f"deployment {spec.name} references a missing agent version")
            uri = await self._registrar.register(agent, version, spec)
            update["identity_uri"] = uri
            if spec.identity_uri and spec.identity_uri != uri:
                update["superseded_identities"] = (*spec.superseded_identities, spec.identity_uri)
            await self._gov.recorder.record(
                "system:control-plane",
                "identity.register",
                uri,
                "success",
                {"deployment": spec.name, "version": revision.version},
            )
        return spec.model_copy(update=update)

    # ---------------------------------------------------------------- approve

    async def approve(self, name: str, command: Approve, caller: Caller) -> DeploymentResult:
        spec = await self.get(name)
        if spec.pending is None:
            raise InvalidStateError(f"deployment {name} has no change awaiting approval")
        agent = await self._agents.get(spec.agent_namespace, spec.agent_name)
        if agent is None:
            raise NotFoundError(f"agent {spec.agent_key} not found")
        decided = await self._gov.check(
            caller,
            action="controlplane:deployment:approve",
            resource=Resource(
                type="deployment",
                id=name,
                classification=agent.max_classification,
                attributes={
                    "environment": spec.environment.value,
                    "risk": int(agent.risk),
                    "created_by": spec.pending.created_by,
                },
            ),
            risk=agent.risk,
        )
        comment = self._screen.free_text("comment", command.comment)
        approval = Approval(
            actor=decided.subject,
            at=self._clock.now(),
            comment=comment,
            policy_digest=decided.policy_digest,
        )
        revision = spec.pending.model_copy(
            update={"approvals": (*spec.pending.approvals, approval)}
        )
        promoted = await self._promote(spec, revision)
        await self._deployments.update(promoted)
        await self._gov.recorder.record(
            decided.subject,
            "deployment.approve",
            f"deployment:{name}",
            "success",
            {"generation": revision.generation, "requested_by": revision.created_by},
        )
        status = await self._reconciler.reconcile(name)
        return DeploymentResult(outcome="applied", deployment=promoted, status=status)

    # ----------------------------------------------------------------- delete

    async def delete(self, name: str, command: Reason, caller: Caller) -> DeploymentResult:
        spec = await self.get(name)
        if spec.state in {DeploymentState.DELETING, DeploymentState.DELETED}:
            raise InvalidStateError(f"deployment {name} is already {spec.state.value}")
        agent = await self._agents.get(spec.agent_namespace, spec.agent_name)
        decided = await self._gov.check(
            caller,
            action="controlplane:deployment:delete",
            resource=Resource(
                type="deployment",
                id=name,
                attributes={"environment": spec.environment.value},
            ),
            risk=agent.risk if agent else RiskLevel.HIGH,
        )
        reason = self._screen.free_text("reason", command.reason)
        deleting = spec.model_copy(
            update={"state": DeploymentState.DELETING, "updated_at": self._clock.now()}
        )
        await self._deployments.update(deleting)
        await self._gov.recorder.record(
            decided.subject,
            "deployment.delete",
            f"deployment:{name}",
            "accepted",
            {"reason": reason},
        )
        status = await self._reconciler.reconcile(name)
        final = await self.get(name)
        return DeploymentResult(outcome="deleting", deployment=final, status=status)
