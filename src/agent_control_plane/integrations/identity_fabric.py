"""Typed client for agent-identity-fabric (github.com/kogunlowo123/agent-identity-fabric).

Wire formats follow the fabric's published contract: RFC 7523 jwt-bearer
issuance and RFC 7662 introspection under ``/oauth2``, the policy decision
point at ``/v1/authorize``, and the administrative registry under
``/v1/agents``. Administrative calls carry a token for the control plane's
own service principal, obtained from the enterprise IdP with the OAuth 2.0
client-credentials grant.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import quote

import httpx
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import Resource
from pydantic import BaseModel, ConfigDict, SecretStr

from agent_control_plane.domain.errors import (
    ConflictError,
    ControlPlaneError,
    DependencyError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    UnauthorizedError,
)
from agent_control_plane.domain.models import AgentRecord, AgentVersion, DeploymentSpec
from agent_control_plane.security.authorization import AuthzOutcome
from agent_control_plane.security.oidc import bearer_token

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class TokenProvider(Protocol):
    async def token(self) -> str: ...


class IssuedCredential(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str = "Bearer"  # noqa: S105
    # RFC 6750 token type name, not a credential.
    expires_in: int
    scope: str = ""


class FabricDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...] = ()
    policy_version: str = ""
    policy_digest: str = ""
    reason: str = ""
    delegation_chain: tuple[str, ...] = ()


class ClientCredentialsTokenProvider:
    """OAuth 2.0 client-credentials grant (RFC 6749 section 4.4) with expiry-aware caching."""

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        token_url: str,
        client_id: str,
        client_secret: SecretStr,
        scope: str,
        clock: Callable[[], float] = time.monotonic,
        refresh_margin_s: float = 60.0,
    ) -> None:
        self._http = http
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._clock = clock
        self._margin = refresh_margin_s
        self._cached: tuple[str, float] | None = None

    async def token(self) -> str:
        now = self._clock()
        if self._cached is not None and now < self._cached[1]:
            return self._cached[0]
        try:
            response = await self._http.post(
                self._token_url,
                data={"grant_type": "client_credentials", "scope": self._scope},
                auth=(self._client_id, self._client_secret.get_secret_value()),
            )
        except httpx.HTTPError as exc:
            raise DependencyError("identity provider unreachable") from exc
        if response.status_code != 200:
            raise DependencyError(
                f"identity provider rejected client credentials ({response.status_code})"
            )
        body = response.json()
        token = body.get("access_token")
        expires_in = body.get("expires_in", 300)
        if not isinstance(token, str) or not isinstance(expires_in, int):
            raise DependencyError("identity provider returned a malformed token response")
        self._cached = (token, now + max(0.0, expires_in - self._margin))
        return token


class FabricClient:
    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        base_url: str,
        admin_tokens: TokenProvider | None = None,
    ) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._admin_tokens = admin_tokens

    @staticmethod
    def _raise_for(response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        try:
            body = response.json()
            message = str(body.get("error_description") or body.get("error") or response.text)
        except ValueError:
            message = response.text[:200]
        status = response.status_code
        mapped: dict[int, type[ControlPlaneError]] = {
            401: UnauthorizedError,
            403: ForbiddenError,
            404: NotFoundError,
        }
        if status in mapped:
            raise mapped[status](f"identity fabric: {message}")
        if status == 409:
            error = (body or {}).get("error") if isinstance(body, dict) else None
            if error == "invalid_state":
                raise InvalidStateError(f"identity fabric: {message}")
            raise ConflictError(f"identity fabric: {message}")
        if status >= 500:
            raise DependencyError(f"identity fabric unavailable ({status})")
        raise ControlPlaneError(f"identity fabric: {message}")

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._http.request(method, f"{self._base}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise DependencyError(f"identity fabric unreachable: {type(exc).__name__}") from exc
        self._raise_for(response)
        return response

    async def _admin_headers(self) -> dict[str, str]:
        if self._admin_tokens is None:
            raise DependencyError("identity fabric administrative credentials are not configured")
        return {"Authorization": f"Bearer {await self._admin_tokens.token()}"}

    # ----------------------------------------------------------------- OAuth

    async def issue_token(
        self, client_id: str, assertion: str, *, scope: str | None = None
    ) -> IssuedCredential:
        """RFC 7523 jwt-bearer grant: a workload token in, a short-lived agent credential out."""
        data = {"grant_type": JWT_BEARER, "client_id": client_id, "assertion": assertion}
        if scope:
            data["scope"] = scope
        response = await self._send("POST", "/oauth2/token", data=data)
        return IssuedCredential.model_validate(response.json())

    async def introspect(self, token: str) -> dict[str, Any]:
        response = await self._send("POST", "/oauth2/introspect", data={"token": token})
        body: dict[str, Any] = response.json()
        return body

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        classification: DataClassification,
        attributes: dict[str, Any],
        environment: dict[str, Any] | None = None,
    ) -> FabricDecision:
        response = await self._send(
            "POST",
            "/v1/authorize",
            json={
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_classification": int(classification),
                "resource_attributes": attributes,
                "environment": environment or {},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        return FabricDecision.model_validate(response.json())

    # -------------------------------------------------------------- registry

    async def register_agent(self, registration: dict[str, Any]) -> dict[str, Any]:
        response = await self._send(
            "POST", "/v1/agents", json=registration, headers=await self._admin_headers()
        )
        body: dict[str, Any] = response.json()
        return body

    async def get_agent(self, agent_uri: str) -> dict[str, Any]:
        response = await self._send(
            "GET", f"/v1/agents/{quote(agent_uri, safe=':/')}", headers=await self._admin_headers()
        )
        body: dict[str, Any] = response.json()
        return body

    async def change_status(self, operation: str, agent_uri: str, reason: str) -> dict[str, Any]:
        if operation not in {"suspend", "reinstate", "revoke-agent"}:
            raise ValueError(f"unknown lifecycle operation {operation}")
        response = await self._send(
            "POST",
            f"/v1/{operation}",
            params={"agent_uri": agent_uri},
            json={"reason": reason},
            headers=await self._admin_headers(),
        )
        body: dict[str, Any] = response.json()
        return body


class FabricAuthorizer:
    """Delegates agent authorization to the identity fabric's policy decision point.

    The fabric validates the credential (signature, expiry, revocation,
    credential epoch, every agent in a delegation chain) and evaluates its
    policy. Any failure to obtain a decision fails closed.
    """

    def __init__(self, client: FabricClient) -> None:
        self._client = client

    async def authorize(
        self,
        authorization: str | None,
        *,
        action: str,
        resource: Resource,
        risk: RiskLevel = RiskLevel.LOW,
    ) -> AuthzOutcome:
        decision = await self._client.authorize(
            bearer_token(authorization),
            action=action,
            resource_type=resource.type,
            resource_id=resource.id,
            classification=resource.classification,
            attributes={**resource.attributes, "risk": int(risk)},
        )
        return AuthzOutcome(
            decision=decision.decision,
            subject=decision.agent,
            reason=decision.reason,
            policy_digest=decision.policy_digest,
            matched_rules=decision.matched_rules,
            source="identity-fabric",
        )


class FabricIdentityRegistrar:
    """Registers each deployed agent version as its own workload identity.

    The identity is bound to the deployment's Kubernetes service account
    and to the version's pinned image digest, so only that exact build,
    running as that service account, can attest and obtain credentials.
    """

    def __init__(
        self,
        client: FabricClient,
        *,
        trust_domain: str,
        workload_issuer: str,
        workload_audience: str,
    ) -> None:
        self._client = client
        self._trust_domain = trust_domain
        self._issuer = workload_issuer
        self._audience = workload_audience

    def identity_uri(
        self, agent: AgentRecord, version: AgentVersion, deployment: DeploymentSpec
    ) -> str:
        name = deployment.identity_name(version.version)
        return f"spiffe://{self._trust_domain}/agent/{agent.namespace}/{name}"

    def registration(
        self, agent: AgentRecord, version: AgentVersion, deployment: DeploymentSpec
    ) -> dict[str, Any]:
        protected = sorted({f"tool:{t.name}" for t in version.tools})
        return {
            "namespace": agent.namespace,
            "name": deployment.identity_name(version.version),
            "display_name": f"{agent.display_name} ({deployment.name} {version.version})"[:120],
            "mandate": {
                "mission": agent.mission,
                "business_owner": agent.owners.business,
                "technical_owner": agent.owners.technical,
                "protected_resources": protected,
                "disallowed_actions": list(agent.disallowed_actions),
                "escalation_contact": agent.owners.escalation_contact,
            },
            "scopes": sorted(version.scopes),
            "risk": int(agent.risk),
            "max_classification": int(agent.max_classification),
            "workload": {
                "issuer": self._issuer,
                "subject": f"system:serviceaccount:{deployment.namespace}:{deployment.name}",
                "audience": self._audience,
                "image_digests": [version.image.digest],
            },
        }

    async def register(
        self, agent: AgentRecord, version: AgentVersion, deployment: DeploymentSpec
    ) -> str:
        expected = self.identity_uri(agent, version, deployment)
        try:
            created = await self._client.register_agent(
                self.registration(agent, version, deployment)
            )
        except ConflictError:
            # Registered by an earlier attempt or another replica: confirm and reuse it.
            existing = await self._client.get_agent(expected)
            return str(existing["agent_id"])
        uri = str(created["agent_id"])
        if uri != expected:
            raise ControlPlaneError(
                f"identity fabric trust domain mismatch: expected {expected}, got {uri}"
            )
        return uri

    async def suspend(self, identity_uri: str, reason: str) -> None:
        await self._client.change_status("suspend", identity_uri, reason)

    async def reinstate(self, identity_uri: str, reason: str) -> None:
        await self._client.change_status("reinstate", identity_uri, reason)

    async def revoke(self, identity_uri: str, reason: str) -> None:
        await self._client.change_status("revoke-agent", identity_uri, reason)
