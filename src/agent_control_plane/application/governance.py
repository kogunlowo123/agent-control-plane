"""Who is calling, what policy says, and the audit record of both.

Every use case asks its ``Caller`` for a decision before acting. Operators
on the REST API are decided by the local policy set; agents on the MCP and
A2A surfaces are decided by the configured ``Authorizer`` (the identity
fabric, or the local policy). Denials and approval outcomes are audited
just like successes.
"""

from __future__ import annotations

from typing import Any, Protocol

from agentic_core.audit import AuditLog
from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.observability import correlation_id
from agentic_core.policy import Resource

from agent_control_plane.domain.errors import ApprovalRequiredError, ForbiddenError
from agent_control_plane.security.authorization import Authorizer, AuthzOutcome, PolicyGate
from agent_control_plane.security.oidc import Principal


class Caller(Protocol):
    async def decide(self, *, action: str, resource: Resource, risk: RiskLevel) -> AuthzOutcome: ...


class OperatorCaller:
    """An authenticated operator or pipeline, decided by the local policy set."""

    def __init__(self, principal: Principal, gate: PolicyGate) -> None:
        self.principal = principal
        self._gate = gate

    async def decide(self, *, action: str, resource: Resource, risk: RiskLevel) -> AuthzOutcome:
        return self._gate.evaluate(self.principal, action=action, resource=resource, risk=risk)


class AgentCaller:
    """An agent presenting a bearer credential, decided by the configured authorizer."""

    def __init__(self, authorization: str | None, authorizer: Authorizer) -> None:
        self._authorization = authorization
        self._authorizer = authorizer
        self.subject: str | None = None
        self.last: AuthzOutcome | None = None

    async def decide(self, *, action: str, resource: Resource, risk: RiskLevel) -> AuthzOutcome:
        outcome = await self._authorizer.authorize(
            self._authorization, action=action, resource=resource, risk=risk
        )
        self.subject, self.last = outcome.subject, outcome
        return outcome


class Recorder:
    """Writes control-plane events to the signed agentic-core audit chain."""

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    async def record(
        self,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        await self._audit.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details or {},
        )


class Governance:
    def __init__(self, recorder: Recorder) -> None:
        self.recorder = recorder

    async def check(
        self,
        caller: Caller,
        *,
        action: str,
        resource: Resource,
        risk: RiskLevel = RiskLevel.LOW,
        approval_workflow: bool = False,
    ) -> AuthzOutcome:
        """Decide and audit. Raises on deny; on require_approval unless the
        use case has an approval workflow (then the caller handles it)."""
        outcome = await caller.decide(action=action, resource=resource, risk=risk)
        target = f"{resource.type}:{resource.id}"
        if outcome.decision is Decision.DENY:
            await self.recorder.record(
                outcome.subject,
                action,
                target,
                "denied",
                {"reason": outcome.reason, "rules": list(outcome.matched_rules)},
            )
            raise ForbiddenError(f"{action} denied: {outcome.reason}")
        if outcome.decision is Decision.REQUIRE_APPROVAL and not approval_workflow:
            await self.recorder.record(
                outcome.subject,
                action,
                target,
                "approval_required",
                {"reason": outcome.reason, "rules": list(outcome.matched_rules)},
            )
            raise ApprovalRequiredError(f"{action} requires human approval: {outcome.reason}")
        return outcome
