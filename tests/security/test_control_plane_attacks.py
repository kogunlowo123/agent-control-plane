"""Adversarial tests mapped to docs/security/threat-model.md (T1..T14)."""

from __future__ import annotations

import pytest
from agentic_core.domain.classification import RiskLevel
from fastapi.testclient import TestClient

from agent_control_plane.application.commands import Approve, EngageKillSwitch, Reason, Transition
from agent_control_plane.domain.errors import (
    ConflictError,
    ForbiddenError,
    UnsafeContentError,
)
from agent_control_plane.domain.models import KillScope, LifecycleAction, Phase
from agent_control_plane.runtime.container import Container
from tests.conftest import (
    OPERATOR_AUDIENCE,
    OPERATOR_ISSUER,
    PROD_NS,
    agent_command,
    deploy,
    headers,
    op,
    seed,
    tool_command,
    version_command,
)
from tests.fakes import FakeIdp, FakeKubeApiServer

pytestmark = pytest.mark.security


def test_t1_forged_operator_token(client: TestClient) -> None:
    """T1 spoofing: a token from an attacker key claiming admin roles is rejected."""
    attacker = FakeIdp(OPERATOR_ISSUER, kid="operator-1")
    forged = attacker.mint(sub="mallory", aud=OPERATOR_AUDIENCE, roles=["acp-platform-admin"])
    response = client.get("/v1/agents", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_t2_token_for_another_audience(client: TestClient, operator_idp: FakeIdp) -> None:
    """T2 confused deputy: a valid IdP token for a different application is rejected."""
    token = operator_idp.mint(sub="alice", aud="some-other-app", roles=["acp-platform-admin"])
    assert client.get("/v1/agents", headers={"Authorization": f"Bearer {token}"}).status_code == 401


async def test_t3_self_approval_is_denied(container: Container) -> None:
    """T3 elevation: one person cannot submit and approve (separation of duties)."""
    both = op(container, "insider@corp.test", "acp-agent-developer", "acp-approver")
    await container.registry.create_agent(agent_command(), both)
    await container.registry.create_version(
        "claims", "claims-triage", version_command(tools=()), both
    )
    await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", Transition(action=LifecycleAction.SUBMIT), both
    )
    with pytest.raises(ForbiddenError):
        await container.registry.transition_version(
            "claims", "claims-triage", "1.0.0", Transition(action=LifecycleAction.APPROVE), both
        )


async def test_t4_single_approver_cannot_approve_high_risk_twice(container: Container) -> None:
    """T4: the two-person rule cannot be satisfied by one approver approving twice."""
    dev = op(container, "dev@corp.test")
    await container.registry.create_agent(agent_command(risk=RiskLevel.CRITICAL), dev)
    await container.registry.create_version(
        "claims", "claims-triage", version_command(tools=()), dev
    )
    await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", Transition(action=LifecycleAction.SUBMIT), dev
    )
    approver = op(container, "approver@corp.test")
    approve = Transition(action=LifecycleAction.APPROVE)
    await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", approve, approver
    )
    with pytest.raises(ConflictError):
        await container.registry.transition_version(
            "claims", "claims-triage", "1.0.0", approve, approver
        )


async def test_t5_tool_definition_cannot_change_silently(container: Container) -> None:
    """T5 tampering ('rug pull'): a tool version is immutable; a changed schema is a new
    version with a new digest that must be reviewed again."""
    dev = op(container, "dev@corp.test")
    original = await container.registry.create_tool(tool_command(), dev)
    widened = tool_command().model_copy(
        update={"input_schema": {"type": "object", "properties": {"sql": {"type": "string"}}}}
    )
    with pytest.raises(ConflictError):
        await container.registry.create_tool(widened, dev)
    new_version = await container.registry.create_tool(
        widened.model_copy(update={"version": "1.1.0"}), dev
    )
    assert new_version.schema_digest != original.schema_digest
    assert new_version.state.value == "draft"


async def test_t6_redeploy_cannot_bypass_kill_switch(
    container: Container, kube: FakeKubeApiServer
) -> None:
    """T6: while a kill switch is active, applying desired state never restarts the agent."""
    await seed(container)
    await deploy(container)
    await container.kill_switches.engage(
        EngageKillSwitch(scope=KillScope.GLOBAL, target="*", reason="estate-wide containment"),
        op(container, "secops@corp.test"),
    )
    result = await deploy(container, replicas=10)
    assert result.status is not None
    assert result.status.phase is Phase.KILLED
    kube.tamper("Deployment", PROD_NS, "claims-triage-prod", lambda o: o["spec"].update(replicas=3))
    status = await container.reconciler.reconcile("claims-triage-prod")
    assert status.phase is Phase.KILLED
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0


async def test_t7_kill_switch_release_needs_second_person(container: Container) -> None:
    await seed(container)
    await deploy(container)
    engaged = await container.kill_switches.engage(
        EngageKillSwitch(scope=KillScope.DEPLOYMENT, target="claims-triage-prod", reason="contain"),
        op(container, "secops@corp.test"),
    )
    with pytest.raises(ForbiddenError):
        await container.kill_switches.release(
            engaged.kill_switch.id,
            Reason(reason="my own release"),
            op(container, "secops@corp.test"),
        )


async def test_t8_injected_sidecar_and_privilege_escalation_are_reverted(
    container: Container, kube: FakeKubeApiServer
) -> None:
    """T8: out-of-band edits that add containers or privileges are detected and reverted."""
    await seed(container)
    await deploy(container)

    def implant(obj: dict) -> None:
        pod = obj["spec"]["template"]["spec"]
        pod["hostNetwork"] = True
        pod["containers"].append({"name": "implant", "image": "attacker/implant:latest"})

    kube.tamper("Deployment", PROD_NS, "claims-triage-prod", implant)
    status = await container.reconciler.reconcile("claims-triage-prod")
    assert status.corrected
    paths = {i.path for i in status.drift}
    assert "spec.template.spec.containers[implant]" in paths
    assert "spec.template.spec.hostNetwork" in paths
    pod = kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["template"]["spec"]
    assert [c["name"] for c in pod["containers"]] == ["agent"]
    assert "hostNetwork" not in pod


async def test_t9_network_policy_tampering_is_reverted(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await seed(container)
    await deploy(container)
    kube.tamper(
        "NetworkPolicy",
        PROD_NS,
        "claims-triage-prod",
        lambda o: o["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}),
    )
    status = await container.reconciler.reconcile("claims-triage-prod")
    assert any(i.kind == "NetworkPolicy" for i in status.drift)
    egress = kube.get("NetworkPolicy", PROD_NS, "claims-triage-prod")["spec"]["egress"]
    assert {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]} not in egress


async def test_t10_credentials_never_enter_desired_state(container: Container) -> None:
    """T10 disclosure: inline secrets in env or annotations are refused."""
    await seed(container)
    with pytest.raises(UnsafeContentError):
        await deploy(container, env={"DB_PASSWORD_URL": "postgres://u:AKIAIOSFODNN7EXAMPLE@db"})
    with pytest.raises(UnsafeContentError):
        await container.kill_switches.engage(
            EngageKillSwitch(
                scope=KillScope.GLOBAL,
                target="*",
                reason="leaked " + "xoxb-" + "123456789012-abcdefghijkl",
            ),
            op(container, "secops@corp.test"),
        )


async def test_t11_policy_bundle_tampering_is_detectable(container: Container) -> None:
    from tests.conftest import bundle_command

    bundle = await container.bundles.publish(bundle_command(), op(container, "policy@corp.test"))
    weakened = bundle.model_copy(
        update={
            "policies": (
                {
                    "name": "claims-agent",
                    "version": "x",
                    "rules": [{"id": "all", "effect": "allow", "actions": ["*"]}],
                },
            )
        }
    )
    assert not container.bundles.verify(weakened)


async def test_t12_deployments_only_into_managed_namespaces(container: Container) -> None:
    await seed(container)
    with pytest.raises(ForbiddenError):
        await deploy(container, namespace="kube-system")


def test_t13_agents_without_credentials_get_nothing(client: TestClient) -> None:
    assert client.get("/v1/runtime/claims-triage-prod").status_code == 401
    assert client.post("/a2a", json={"jsonrpc": "2.0"}).status_code == 401


async def test_t14_production_change_requires_independent_approval(container: Container) -> None:
    await seed(container, risk=RiskLevel.HIGH)
    requester = op(container, "release@corp.test", "acp-deployer", "acp-approver")
    from tests.conftest import deploy_command

    pending = await container.deployments.apply(deploy_command(), requester)
    assert pending.outcome == "approval_required"
    with pytest.raises(ForbiddenError):
        await container.deployments.approve("claims-triage-prod", Approve(), requester)


def test_auditors_cannot_change_anything(client: TestClient, operator_idp: FakeIdp) -> None:
    auditor = headers(operator_idp, "auditor@corp.test")
    from tests.e2e.test_http_lifecycle import as_json

    assert (
        client.post("/v1/agents", json=as_json(agent_command()), headers=auditor).status_code == 403
    )
    assert (
        client.post(
            "/v1/kill-switches",
            json={"scope": "global", "target": "*", "reason": "auditor trying"},
            headers=auditor,
        ).status_code
        == 403
    )
