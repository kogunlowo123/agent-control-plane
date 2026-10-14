"""The full lifecycle over HTTP, as platform teams, approvers and security use it."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    PROD_NS,
    bundle_command,
    deploy_command,
    headers,
    tool_command,
    version_command,
)
from tests.fakes import FakeIdp, FakeKubeApiServer

pytestmark = pytest.mark.e2e


def as_json(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json")  # type: ignore[no-any-return]


def ok(response: Any, status: int = 200) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def register_everything(client: TestClient, idp: FakeIdp, risk: int = 2) -> None:
    dev = headers(idp, "dev@corp.test")
    from tests.conftest import agent_command

    agent = as_json(agent_command())
    agent["risk"] = risk
    ok(client.post("/v1/agents", json=agent, headers=dev), 201)
    ok(client.post("/v1/tools", json=as_json(tool_command()), headers=dev), 201)
    for action, who in [("submit", dev), ("approve", headers(idp, "approver@corp.test"))]:
        ok(
            client.post(
                "/v1/tools/claims.search/1.0.0/transitions", json={"action": action}, headers=who
            )
        )
    ok(
        client.post(
            "/v1/agents/claims/claims-triage/versions", json=as_json(version_command()), headers=dev
        ),
        201,
    )
    path = "/v1/agents/claims/claims-triage/versions/1.0.0/transitions"
    ok(client.post(path, json={"action": "submit"}, headers=dev))
    approvers = (
        ["approver@corp.test", "approver2@corp.test"] if risk >= 3 else ["approver@corp.test"]
    )
    for approver in approvers:
        ok(
            client.post(
                path,
                json={"action": "approve", "comment": "CAB ok"},
                headers=headers(idp, approver),
            )
        )
    ok(
        client.post(
            "/v1/policy-bundles",
            json=as_json(bundle_command()),
            headers=headers(idp, "policy@corp.test"),
        ),
        201,
    )


def test_full_lifecycle(client: TestClient, operator_idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    register_everything(client, operator_idp, risk=3)
    for phase in (
        inventory,
        deploy_with_approval,
        drift_round_trip,
        kill_and_release,
        retire,
        audit,
    ):
        phase(client, operator_idp, kube)


def inventory(client: TestClient, idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    auditor = headers(idp, "auditor@corp.test")
    agents = ok(client.get("/v1/agents", headers=auditor))
    assert [a["name"] for a in agents["items"]] == ["claims-triage"]
    assert ok(client.get("/v1/agents/claims/claims-triage", headers=auditor))["risk"] == 3
    versions = ok(client.get("/v1/agents/claims/claims-triage/versions", headers=auditor))
    assert versions["items"][0]["state"] == "approved"
    assert len(versions["items"][0]["approvals"]) == 2
    assert (
        ok(client.get("/v1/agents/claims/claims-triage/versions/1.0.0", headers=auditor))[
            "framework"
        ]
        == "langgraph"
    )
    assert ok(client.get("/v1/tools", headers=auditor))["items"][0]["state"] == "approved"
    assert ok(client.get("/v1/tools/claims.search/1.0.0", headers=auditor))["schema_digest"]
    bundle = ok(client.get("/v1/policy-bundles/claims-policy/1.0.0", headers=auditor))
    assert bundle["verified"] is True
    assert ok(client.get("/v1/policy-bundles", headers=auditor))["items"]
    assert client.get("/v1/policy-bundles/signing-key").json()["keys"][0]["crv"] == "Ed25519"


def deploy_with_approval(client: TestClient, idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    auditor = headers(idp, "auditor@corp.test")
    # Production deployment of a high-risk agent needs approval by someone else.
    requested = client.post(
        "/v1/deployments",
        json=as_json(deploy_command()),
        headers=headers(idp, "deployer@corp.test"),
    )
    assert requested.status_code == 202
    assert requested.json()["outcome"] == "approval_required"
    approved = ok(
        client.post(
            "/v1/deployments/claims-triage-prod/approve",
            json={"comment": "CHG-77"},
            headers=headers(idp, "approver@corp.test"),
        )
    )
    assert approved["status"]["phase"] == "Available"
    detail = ok(client.get("/v1/deployments/claims-triage-prod", headers=auditor))
    assert detail["deployment"]["state"] == "active"
    assert ok(client.get("/v1/deployments?state=active", headers=auditor))["items"]
    manifests = ok(client.get("/v1/deployments/claims-triage-prod/manifests", headers=auditor))
    assert [m["kind"] for m in manifests["items"]] == [
        "ServiceAccount",
        "ConfigMap",
        "NetworkPolicy",
        "Deployment",
    ]


def drift_round_trip(client: TestClient, idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    auditor = headers(idp, "auditor@corp.test")
    # Someone edits the cluster by hand; drift is reported, then corrected.
    kube.tamper(
        "Deployment",
        PROD_NS,
        "claims-triage-prod",
        lambda o: o["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "DEBUG", "value": "1"}
        ),
    )
    drift = ok(client.get("/v1/deployments/claims-triage-prod/drift", headers=auditor))
    assert drift["in_sync"] is False
    assert drift["drift"][0]["change"] == "unexpected"
    reconciled = ok(
        client.post(
            "/v1/deployments/claims-triage-prod/reconcile",
            headers=headers(idp, "deployer@corp.test"),
        )
    )
    assert reconciled["corrected"] is True


def kill_and_release(client: TestClient, idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    auditor = headers(idp, "auditor@corp.test")
    # Security stops the agent, a second officer releases it.
    engaged = ok(
        client.post(
            "/v1/kill-switches",
            json={
                "scope": "agent",
                "target": "claims/claims-triage",
                "reason": "suspected prompt injection",
            },
            headers=headers(idp, "secops@corp.test"),
        ),
        201,
    )
    switch_id = engaged["kill_switch"]["id"]
    assert engaged["statuses"][0]["phase"] == "Killed"
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0
    assert (
        ok(client.get("/v1/kill-switches?active=true", headers=auditor))["items"][0]["id"]
        == switch_id
    )
    assert ok(client.get(f"/v1/kill-switches/{switch_id}", headers=auditor))["active"] is True
    denied = client.post(
        f"/v1/kill-switches/{switch_id}/release",
        json={"reason": "all clear now"},
        headers=headers(idp, "secops@corp.test"),
    )
    assert denied.status_code == 403
    ok(
        client.post(
            f"/v1/kill-switches/{switch_id}/release",
            json={"reason": "all clear now"},
            headers=headers(idp, "secops2@corp.test"),
        )
    )
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 2


def retire(client: TestClient, idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod") is not None
    # Retire: delete the deployment, then the agent.
    ok(
        client.post(
            "/v1/deployments/claims-triage-prod/delete",
            json={"reason": "decommissioned"},
            headers=headers(idp, "deployer@corp.test"),
        ),
        202,
    )
    retired = ok(
        client.post(
            "/v1/agents/claims/claims-triage/retire",
            json={"reason": "decommissioned"},
            headers=headers(idp, "admin@corp.test"),
        )
    )
    assert retired["agent"]["status"] == "retired"


def audit(client: TestClient, idp: FakeIdp, kube: FakeKubeApiServer) -> None:
    auditor = headers(idp, "auditor@corp.test")
    # The audit trail is complete and verifiable.
    chains = ok(client.get("/v1/audit/chains", headers=auditor))["chains"]
    assert len(chains) == 1
    events = ok(client.get(f"/v1/audit/events?chain={chains[0]}&limit=500", headers=auditor))
    actions = [e["action"] for e in events["items"]]
    for expected in [
        "agent.create",
        "agent_version.approve",
        "policy_bundle.publish",
        "deployment.apply",
        "deployment.approve",
        "deployment.drift_corrected",
        "killswitch.engage",
        "killswitch.release",
        "deployment.deleted",
        "agent.retire",
    ]:
        assert expected in actions, expected
    assert "denied" in {e["outcome"] for e in events["items"]}
    verified = ok(client.get(f"/v1/audit/verify?chain={chains[0]}", headers=auditor))
    assert verified["verified"] is True
    assert verified["events"] == len(events["items"])


def test_operator_authentication_and_roles(client: TestClient, operator_idp: FakeIdp) -> None:
    missing = client.get("/v1/agents")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert missing.json()["error"] == "unauthorized"
    assert client.get("/v1/agents", headers={"Authorization": "Bearer junk"}).status_code == 401
    no_role = headers(operator_idp, "nobody@corp.test", "some-other-app-role")
    assert client.get("/v1/agents", headers=no_role).status_code == 403
    assert (
        client.get("/v1/audit/chains", headers=headers(operator_idp, "dev@corp.test")).status_code
        == 403
    )
    invalid = client.post(
        "/v1/agents", json={"namespace": "x"}, headers=headers(operator_idp, "dev@corp.test")
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "invalid_request"
    assert (
        client.get(
            "/v1/agents/claims/missing", headers=headers(operator_idp, "auditor@corp.test")
        ).status_code
        == 404
    )


def test_operations_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    response = client.get("/metrics")
    assert "acp_http_request_duration_seconds" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    traced = client.get("/healthz", headers={"X-Correlation-ID": "trace-123"})
    assert traced.headers["x-correlation-id"] == "trace-123"
    assert (
        len(
            client.get("/healthz", headers={"X-Correlation-ID": "x" * 100}).headers[
                "x-correlation-id"
            ]
        )
        == 32
    )


def test_audit_verification_detects_tampering(client: TestClient, operator_idp: FakeIdp) -> None:
    register_everything(client, operator_idp)
    auditor = headers(operator_idp, "auditor@corp.test")
    chain = client.get("/v1/audit/chains", headers=auditor).json()["chains"][0]
    container = client.app.state.container  # type: ignore[attr-defined]
    from sqlalchemy import update

    from agent_control_plane.infrastructure.database import audit_events

    async def tamper() -> None:
        async with container.engine.begin() as conn:
            row = (
                await conn.execute(audit_events.select().where(audit_events.c.sequence == 1))
            ).first()
            document = row.document.replace('"outcome":"success"', '"outcome":"failure"')
            await conn.execute(
                update(audit_events).where(audit_events.c.sequence == 1).values(document=document)
            )

    client.portal.call(tamper)  # type: ignore[attr-defined]
    result = client.get(f"/v1/audit/verify?chain={chain}", headers=auditor).json()
    assert result["verified"] is False
    assert result["failed_sequence"] == 1
