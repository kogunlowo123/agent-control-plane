"""MCP tools and the A2A agent, authorized by local policy and by the identity fabric."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import PROD_NS, deploy, headers, seed
from tests.fakes import FakeFabric, FakeIdp, FakeKubeApiServer

pytestmark = pytest.mark.e2e

MCP_HEADERS = {"accept": "application/json, text/event-stream"}
RESPONDER = "spiffe://agents.corp.test/agent/security/incident-responder"


def prepare(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]

    async def setup() -> None:
        await seed(container)
        await deploy(container)

    client.portal.call(setup)  # type: ignore[attr-defined]


def mcp(
    client: TestClient, auth: dict[str, str], method: str, params: dict[str, Any] | None = None
) -> Any:
    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers={**MCP_HEADERS, **auth},
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def call(client: TestClient, auth: dict[str, str], tool: str, **arguments: Any) -> Any:
    return mcp(client, auth, "tools/call", {"name": tool, "arguments": arguments})


def a2a(client: TestClient, auth: dict[str, str], data: dict[str, Any] | None, **extra: Any) -> Any:
    parts = (
        [{"kind": "data", "data": data}] if data is not None else [{"kind": "text", "text": "hi"}]
    )
    payload = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "message": {"kind": "message", "role": "user", "messageId": "m-1", "parts": parts}
        },
        **extra,
    }
    return client.post("/a2a", json=payload, headers=auth)


# ------------------------------------------------------------- local policy


def test_mcp_tools_have_typed_schemas(client: TestClient, operator_idp: FakeIdp) -> None:
    reader = headers(operator_idp, "reader-agent", "acp-agent-reader")
    tools = {t["name"]: t for t in mcp(client, reader, "tools/list")["tools"]}
    assert set(tools) == {
        "list_agents",
        "get_deployment",
        "detect_drift",
        "runtime_status",
        "engage_kill_switch",
    }
    for tool in tools.values():
        assert tool["inputSchema"]["type"] == "object"
        assert tool["outputSchema"]["type"] == "object"
    assert tools["engage_kill_switch"]["annotations"]["destructiveHint"] is True
    assert tools["engage_kill_switch"]["inputSchema"]["required"] == ["scope", "target", "reason"]


def test_mcp_reads_and_kill_switch_with_local_policy(
    client: TestClient, operator_idp: FakeIdp, kube: FakeKubeApiServer
) -> None:
    prepare(client)
    reader = headers(operator_idp, "reader-agent", "acp-agent-reader")
    listing = call(client, reader, "list_agents")
    assert listing["structuredContent"]["agents"][0]["agent"] == "claims/claims-triage"
    deployment = call(client, reader, "get_deployment", deployment="claims-triage-prod")
    assert deployment["structuredContent"]["status"]["phase"] == "Available"
    drift = call(client, reader, "detect_drift", deployment="claims-triage-prod")
    assert drift["structuredContent"]["in_sync"] is True

    denied = call(
        client,
        reader,
        "engage_kill_switch",
        scope="deployment",
        target="claims-triage-prod",
        reason="testing",
    )
    assert denied["isError"] is True
    assert "forbidden" in denied["content"][0]["text"]
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 2

    automation = headers(operator_idp, "soar-agent", "acp-security-automation")
    stopped = call(
        client,
        automation,
        "engage_kill_switch",
        scope="deployment",
        target="claims-triage-prod",
        reason="exfiltration pattern detected",
    )
    assert stopped["isError"] is False
    assert stopped["structuredContent"]["phases"] == {"claims-triage-prod": "Killed"}
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0

    runtime = headers(operator_idp, "claims-runtime", "acp-agent-runtime")
    status = call(client, runtime, "runtime_status", deployment="claims-triage-prod")
    assert status["structuredContent"]["run_permitted"] is False
    rest = client.get("/v1/runtime/claims-triage-prod", headers=runtime).json()
    assert rest["run_permitted"] is False
    assert rest["killed_by"]

    invalid = call(client, reader, "get_deployment", deployment="Not_Valid")
    assert invalid["isError"] is True
    missing = call(client, reader, "get_deployment", deployment="unknown")
    assert "not_found" in missing["content"][0]["text"]


def test_mcp_without_credentials_is_refused(client: TestClient) -> None:
    result = call(client, {}, "list_agents")
    assert result["isError"] is True
    assert "unauthorized" in result["content"][0]["text"]


def test_agent_card(client: TestClient) -> None:
    card = client.get("/.well-known/agent-card.json").json()
    assert card["url"] == "https://acp.corp.test/a2a"
    assert card["securitySchemes"]["bearer"]["scheme"] == "bearer"
    assert {s["id"] for s in card["skills"]} == {
        "list-agents",
        "deployment-status",
        "drift-report",
        "engage-kill-switch",
    }
    for key in ("name", "description", "version", "capabilities", "protocolVersion"):
        assert card[key]


def test_a2a_message_send_with_local_policy(client: TestClient, operator_idp: FakeIdp) -> None:
    prepare(client)
    reader = headers(operator_idp, "reader-agent", "acp-agent-reader")
    response = a2a(
        client,
        reader,
        {"skill": "deployment-status", "arguments": {"deployment": "claims-triage-prod"}},
    )
    task = response.json()["result"]
    assert task["kind"] == "task"
    assert task["status"]["state"] == "completed"
    assert task["artifacts"][0]["parts"][0]["data"]["version"] == "1.0.0"
    listing = a2a(client, reader, {"skill": "list-agents"}).json()["result"]
    assert listing["artifacts"][0]["parts"][0]["data"]["count"] == 1
    drift = a2a(
        client, reader, {"skill": "drift-report", "arguments": {"deployment": "claims-triage-prod"}}
    )
    assert drift.json()["result"]["artifacts"][0]["parts"][0]["data"]["in_sync"] is True

    rejected = a2a(
        client,
        reader,
        {
            "skill": "engage-kill-switch",
            "arguments": {"scope": "global", "target": "*", "reason": "testing it"},
        },
    ).json()["result"]
    assert rejected["status"]["state"] == "rejected"
    failed = a2a(
        client, reader, {"skill": "deployment-status", "arguments": {"deployment": "nope"}}
    )
    assert failed.json()["result"]["status"]["state"] == "failed"
    automation = headers(operator_idp, "soar-agent", "acp-security-automation")
    killed = a2a(
        client,
        automation,
        {
            "skill": "engage-kill-switch",
            "arguments": {"scope": "agent", "target": "claims/claims-triage", "reason": "contain"},
        },
    ).json()["result"]
    assert killed["status"]["state"] == "completed"


def test_a2a_protocol_errors(client: TestClient, operator_idp: FakeIdp) -> None:
    reader = headers(operator_idp, "reader-agent", "acp-agent-reader")
    assert client.post("/a2a", json={}).status_code == 401
    parse = client.post(
        "/a2a", content=b"{not json", headers={**reader, "content-type": "application/json"}
    )
    assert parse.json()["error"]["code"] == -32700
    assert client.post("/a2a", json=[1], headers=reader).json()["error"]["code"] == -32600
    unknown = client.post(
        "/a2a", json={"jsonrpc": "2.0", "id": 1, "method": "do/thing"}, headers=reader
    )
    assert unknown.json()["error"]["code"] == -32601
    streaming = client.post(
        "/a2a", json={"jsonrpc": "2.0", "id": 1, "method": "message/stream"}, headers=reader
    )
    assert streaming.json()["error"]["code"] == -32004
    bad_params = client.post(
        "/a2a",
        json={"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}},
        headers=reader,
    )
    assert bad_params.json()["error"]["code"] == -32602
    assert a2a(client, reader, None).json()["error"]["code"] == -32005
    assert a2a(client, reader, {"skill": "rm -rf"}).json()["error"]["code"] == -32602
    bad_args = a2a(
        client, reader, {"skill": "deployment-status", "arguments": {"deployment": "BAD"}}
    )
    assert bad_args.json()["error"]["code"] == -32602
    anonymous = a2a(client, {"Authorization": "Bearer junk"}, {"skill": "list-agents"})
    assert anonymous.status_code == 401


def test_a2a_approval_required_maps_to_input_required(
    client: TestClient, operator_idp: FakeIdp
) -> None:
    """A policy that routes an agent action to a human yields task state input-required."""
    prepare(client)
    container = client.app.state.container  # type: ignore[attr-defined]
    from agentic_core.policy import PolicyEngine, PolicySet

    policy = container.gate._engine.policy
    gated = policy.model_copy(
        update={
            "rules": (
                *policy.rules,
                PolicySet.model_validate(
                    {
                        "name": "x",
                        "version": "1",
                        "rules": [
                            {
                                "id": "approve-global-kill-by-agents",
                                "effect": "require_approval",
                                "actions": ["controlplane:killswitch:engage"],
                                "conditions": [
                                    {
                                        "attribute": "subject.kind",
                                        "operator": "eq",
                                        "value": "agent",
                                    }
                                ],
                            }
                        ],
                    }
                ).rules[0],
            )
        }
    )
    container.gate._engine = PolicyEngine(gated)
    automation = headers(operator_idp, "soar-agent", "acp-security-automation")
    result = a2a(
        client,
        automation,
        {
            "skill": "engage-kill-switch",
            "arguments": {"scope": "global", "target": "*", "reason": "contain all"},
        },
    ).json()["result"]
    assert result["status"]["state"] == "input-required"


# ----------------------------------------------------------- identity fabric


def test_agents_authorized_by_identity_fabric(
    fabric_client: TestClient, fabric: FakeFabric, kube: FakeKubeApiServer
) -> None:
    prepare(fabric_client)
    fabric.grant(
        "responder-token",
        RESPONDER,
        "controlplane:registry:read",
        "controlplane:deployments:read",
        "controlplane:killswitch:engage",
    )
    fabric.grant(
        "reader-token", "spiffe://agents.corp.test/agent/ops/reader", "controlplane:registry:read"
    )
    responder = {"Authorization": "Bearer responder-token"}
    reader = {"Authorization": "Bearer reader-token"}

    assert call(fabric_client, reader, "list_agents")["structuredContent"]["count"] == 1
    refused = call(fabric_client, reader, "get_deployment", deployment="claims-triage-prod")
    assert refused["isError"] is True
    forged = call(fabric_client, {"Authorization": "Bearer forged"}, "list_agents")
    assert forged["isError"] is True
    assert "unauthorized" in forged["content"][0]["text"]

    stopped = a2a(
        fabric_client,
        responder,
        {
            "skill": "engage-kill-switch",
            "arguments": {
                "scope": "deployment",
                "target": "claims-triage-prod",
                "reason": "credential theft",
            },
        },
    ).json()["result"]
    assert stopped["status"]["state"] == "completed"
    switch = stopped["artifacts"][0]["parts"][0]["data"]["kill_switch"]
    assert switch["engaged_by"] == RESPONDER  # attributed to the agent identity
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0
    assert ("POST", "/v1/authorize") in fabric.calls

    container = fabric_client.app.state.container  # type: ignore[attr-defined]
    metrics = container.metrics.registry
    assert (
        metrics.get_sample_value(
            "acp_mcp_tool_calls_total", {"tool": "list_agents", "outcome": "ok"}
        )
        == 1
    )
    assert (
        metrics.get_sample_value(
            "acp_a2a_requests_total", {"method": "message/send", "outcome": "completed"}
        )
        == 1
    )
