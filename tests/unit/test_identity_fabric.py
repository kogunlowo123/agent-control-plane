"""Identity fabric client: wire formats, error mapping, token caching, registrar."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import Resource
from pydantic import SecretStr

from agent_control_plane.domain.errors import (
    ConflictError,
    ControlPlaneError,
    DependencyError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    UnauthorizedError,
)
from agent_control_plane.domain.models import (
    AgentRecord,
    AgentVersion,
    DeploymentSpec,
    DeploymentState,
    Environment,
    Owners,
)
from agent_control_plane.integrations.identity_fabric import (
    ClientCredentialsTokenProvider,
    FabricAuthorizer,
    FabricClient,
    FabricIdentityRegistrar,
)
from tests.conftest import CLUSTER_ISSUER, version_command
from tests.fakes import ADMIN_CLIENT, FABRIC, IDP_TOKEN_URL, TRUST_DOMAIN, FakeFabric

NOW = datetime(2026, 10, 14, tzinfo=UTC)


def provider(http: httpx.AsyncClient, now: list[float]) -> ClientCredentialsTokenProvider:
    return ClientCredentialsTokenProvider(
        http=http,
        token_url=IDP_TOKEN_URL,
        client_id=ADMIN_CLIENT[0],
        client_secret=SecretStr(ADMIN_CLIENT[1]),
        scope="identity-fabric-admin/.default",
        clock=lambda: now[0],
    )


def fabric_client(fake: FakeFabric) -> tuple[FabricClient, list[float]]:
    http = httpx.AsyncClient(transport=fake.transport())
    now = [0.0]
    return FabricClient(http=http, base_url=FABRIC + "/", admin_tokens=provider(http, now)), now


def records() -> tuple[AgentRecord, AgentVersion, DeploymentSpec]:
    agent = AgentRecord(
        namespace="claims",
        name="claims-triage",
        display_name="Claims triage",
        mission="Triage incoming insurance claims for adjusters.",
        owners=Owners(business="claims-ops", technical="claims-eng", escalation_contact="oncall"),
        risk=RiskLevel.HIGH,
        max_classification=DataClassification.RESTRICTED,
        disallowed_actions=("claims:pay:*",),
        created_by="dev",
        created_at=NOW,
        updated_at=NOW,
    )
    version = AgentVersion(
        namespace="claims",
        name="claims-triage",
        created_by="dev",
        created_at=NOW,
        updated_at=NOW,
        **version_command().model_dump(),
    )
    spec = DeploymentSpec(
        name="claims-triage-prod",
        agent_namespace="claims",
        agent_name="claims-triage",
        environment=Environment.PRODUCTION,
        namespace="agents-prod",
        state=DeploymentState.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )
    return agent, version, spec


async def test_client_credentials_are_cached_until_near_expiry() -> None:
    fake = FakeFabric()
    async with httpx.AsyncClient(transport=fake.transport()) as http:
        now = [0.0]
        tokens = provider(http, now)
        assert await tokens.token() == "admin-token-1"
        now[0] = 3000.0
        assert await tokens.token() == "admin-token-1"
        now[0] = 3541.0  # within the 60 s refresh margin of a 3600 s token
        assert await tokens.token() == "admin-token-2"


async def test_client_credentials_failures() -> None:
    def rejecting(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    def malformed(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    for handler, match in [
        (rejecting, "rejected"),
        (malformed, "malformed"),
        (unreachable, "unreachable"),
    ]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(DependencyError, match=match):
                await provider(http, [0.0]).token()


async def test_registrar_registers_and_reuses_existing_identity() -> None:
    fake = FakeFabric()
    client, _ = fabric_client(fake)
    registrar = FabricIdentityRegistrar(
        client,
        trust_domain=TRUST_DOMAIN,
        workload_issuer=CLUSTER_ISSUER,
        workload_audience="identity-fabric",
    )
    agent, version, spec = records()
    uri = await registrar.register(agent, version, spec)
    assert uri == f"spiffe://{TRUST_DOMAIN}/agent/claims/claims-triage-prod-1.0.0"
    body = fake.agents[uri]["registration"]
    assert body["risk"] == 3
    assert body["max_classification"] == 3
    assert body["mandate"]["disallowed_actions"] == ["claims:pay:*"]
    assert body["scopes"] == sorted(version.scopes)
    # A second registration (retry, other replica) resolves to the same identity.
    assert await registrar.register(agent, version, spec) == uri
    await registrar.revoke(uri, "test")
    assert fake.agents[uri]["status"] == "revoked"


async def test_registrar_detects_trust_domain_mismatch() -> None:
    fake = FakeFabric()
    client, _ = fabric_client(fake)
    registrar = FabricIdentityRegistrar(
        client, trust_domain="other.domain", workload_issuer=CLUSTER_ISSUER, workload_audience="x"
    )
    with pytest.raises(ControlPlaneError, match="trust domain mismatch"):
        await registrar.register(*records())


async def test_error_mapping() -> None:
    fake = FakeFabric()
    client, _ = fabric_client(fake)
    with pytest.raises(NotFoundError):
        await client.change_status("suspend", "spiffe://x/agent/a/b", "reason")
    fake.agents["spiffe://x/agent/a/b"] = {"agent_id": "spiffe://x/agent/a/b", "status": "revoked"}
    with pytest.raises(InvalidStateError):
        await client.change_status("reinstate", "spiffe://x/agent/a/b", "reason")
    with pytest.raises(ValueError, match="unknown lifecycle"):
        await client.change_status("delete", "spiffe://x/agent/a/b", "reason")
    fake.agents["spiffe://agents.corp.test/agent/a/b"] = {"agent_id": "x", "status": "active"}
    with pytest.raises(ConflictError):
        await client.register_agent({"namespace": "a", "name": "b"})
    fake.fail_status["/v1/agents"] = 503
    with pytest.raises(DependencyError, match="unavailable"):
        await client.register_agent({"namespace": "a", "name": "c"})
    fake.fail_status = {"/oauth2/introspect": 403}
    with pytest.raises(ForbiddenError):
        await client.introspect("t")
    fake.fail_status = {"/oauth2/introspect": 418}
    with pytest.raises(ControlPlaneError, match="identity fabric"):
        await client.introspect("t")
    fake.fail_status = {}
    fake.down = True
    with pytest.raises(DependencyError, match="unreachable"):
        await client.introspect("t")


async def test_non_json_error_body() -> None:
    def teapot(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="not json")

    async with httpx.AsyncClient(transport=httpx.MockTransport(teapot)) as http:
        with pytest.raises(ControlPlaneError, match="not json"):
            await FabricClient(http=http, base_url=FABRIC).introspect("t")


async def test_admin_calls_need_admin_credentials() -> None:
    async with httpx.AsyncClient(transport=FakeFabric().transport()) as http:
        with pytest.raises(DependencyError, match="administrative credentials"):
            await FabricClient(http=http, base_url=FABRIC).register_agent({})


async def test_jwt_bearer_issuance_and_introspection() -> None:
    fake = FakeFabric()
    client, _ = fabric_client(fake)
    uri = "spiffe://agents.corp.test/agent/claims/runner-1.0.0"
    fake.agents[uri] = {"agent_id": uri, "status": "pending", "registration": {"scopes": ["a:b"]}}
    issued = await client.issue_token(uri, f"workload-token-for:{uri}", scope="a:b")
    assert issued.expires_in == 600
    assert issued.scope == "a:b"
    assert (await client.introspect(issued.access_token))["active"] is True
    assert (await client.introspect("unknown"))["active"] is False
    with pytest.raises(ControlPlaneError):
        await client.issue_token(uri, "forged-assertion")


async def test_fabric_authorizer_maps_decisions() -> None:
    fake = FakeFabric()
    fake.grant(
        "agent-token", "spiffe://agents.corp.test/agent/sec/responder", "controlplane:registry:read"
    )
    client, _ = fabric_client(fake)
    authorizer = FabricAuthorizer(client)
    allowed = await authorizer.authorize(
        "Bearer agent-token",
        action="controlplane:registry:read",
        resource=Resource(type="agent", id="*"),
        risk=RiskLevel.LOW,
    )
    assert allowed.decision is Decision.ALLOW
    assert allowed.source == "identity-fabric"
    assert allowed.subject.endswith("/sec/responder")
    denied = await authorizer.authorize(
        "Bearer agent-token",
        action="controlplane:killswitch:engage",
        resource=Resource(type="kill_switch", id="*"),
    )
    assert denied.decision is Decision.DENY
    with pytest.raises(UnauthorizedError):
        await authorizer.authorize(
            "Bearer forged", action="controlplane:registry:read", resource=Resource(type="agent")
        )
    with pytest.raises(UnauthorizedError):
        await authorizer.authorize(None, action="x:y", resource=Resource(type="agent"))
