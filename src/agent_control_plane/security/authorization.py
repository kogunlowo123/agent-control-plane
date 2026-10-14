"""Authorization decisions for operators and for agents.

Operators (REST API) are authenticated against the enterprise IdP and
decided by the local policy set. Agents calling the MCP and A2A surfaces
are decided by agent-identity-fabric (``POST /v1/authorize``) when it is
configured; otherwise the same local policy decides on the caller's IdP
roles. There is no allow-all mode.
"""

from __future__ import annotations

from typing import Any, Protocol

from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict

from agent_control_plane.security.oidc import OperatorAuthenticator, Principal


class AuthzOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    subject: str
    reason: str
    policy_digest: str
    matched_rules: tuple[str, ...] = ()
    source: str = "local"


class PolicyGate:
    """Evaluates the local control-plane policy set for an authenticated principal."""

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    def evaluate(
        self,
        principal: Principal,
        *,
        action: str,
        resource: Resource,
        risk: RiskLevel = RiskLevel.LOW,
        environment: dict[str, Any] | None = None,
    ) -> AuthzOutcome:
        decision = self._engine.evaluate(
            PolicyRequest(
                subject=Subject(id=principal.subject, kind=principal.kind, roles=principal.roles),
                action=action,
                resource=resource,
                risk=risk,
                environment=environment or {},
            )
        )
        return AuthzOutcome(
            decision=decision.decision,
            subject=principal.subject,
            reason=decision.reason,
            policy_digest=decision.policy_digest,
            matched_rules=decision.matched_rules,
        )


class Authorizer(Protocol):
    async def authorize(
        self,
        authorization: str | None,
        *,
        action: str,
        resource: Resource,
        risk: RiskLevel = RiskLevel.LOW,
    ) -> AuthzOutcome: ...


class LocalAuthorizer:
    def __init__(self, authenticator: OperatorAuthenticator, gate: PolicyGate) -> None:
        self._authenticator = authenticator
        self._gate = gate

    async def authorize(
        self,
        authorization: str | None,
        *,
        action: str,
        resource: Resource,
        risk: RiskLevel = RiskLevel.LOW,
    ) -> AuthzOutcome:
        principal = await self._authenticator.authenticate(authorization)
        agent = principal.model_copy(update={"kind": "agent"})
        return self._gate.evaluate(agent, action=action, resource=resource, risk=risk)
