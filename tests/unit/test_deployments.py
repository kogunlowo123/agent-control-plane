"""Deployment desired state: apply, approval, upgrade with identity rotation, delete."""

from __future__ import annotations

import pytest
from agentic_core.domain.classification import RiskLevel

from agent_control_plane.application.commands import Approve, Reason
from agent_control_plane.domain.errors import (
    ConflictError,
    ControlPlaneError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    UnsafeContentError,
)
from agent_control_plane.domain.models import DeploymentState, Environment, Phase
from agent_control_plane.orchestration.manifests import SPEC_HASH
from agent_control_plane.runtime.container import Container
from tests.conftest import (
    DEV_NS,
    DIGEST_V2,
    PROD_NS,
    deploy,
    deploy_command,
    op,
    seed,
)
from tests.fakes import TRUST_DOMAIN, FakeFabric, FakeKubeApiServer


async def test_apply_reconciles_objects_into_the_cluster(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await seed(container)
    result = await deploy(container)
    assert result.outcome == "applied"
    assert result.status is not None
    assert result.status.phase is Phase.AVAILABLE
    assert result.status.ready_replicas == 2
    for kind, name in [
        ("ServiceAccount", "claims-triage-prod"),
        ("ConfigMap", "claims-triage-prod-runtime"),
        ("NetworkPolicy", "claims-triage-prod"),
        ("Deployment", "claims-triage-prod"),
    ]:
        obj = kube.get(kind, PROD_NS, name)
        assert obj is not None, kind
        assert obj["metadata"]["annotations"][SPEC_HASH] == result.status.spec_hash
    # Second reconcile is a no-op: no writes, no drift.
    writes = [r for r in kube.requests if r[0] in {"POST", "PUT"}]
    status = await container.reconciler.reconcile("claims-triage-prod")
    assert status.drift == ()
    assert [r for r in kube.requests if r[0] in {"POST", "PUT"}] == writes


async def test_production_change_to_high_risk_agent_needs_a_different_approver(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await seed(container, risk=RiskLevel.HIGH)
    pending = await deploy(container)
    assert pending.outcome == "approval_required"
    assert pending.deployment.state is DeploymentState.PENDING_APPROVAL
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod") is None
    status = await container.reconciler.reconcile("claims-triage-prod")
    assert status.phase is Phase.PENDING_APPROVAL

    with pytest.raises(ForbiddenError):  # the requester cannot approve their own change
        await container.deployments.approve(
            "claims-triage-prod",
            Approve(),
            op(container, "deployer@corp.test", "acp-deployer", "acp-approver"),
        )
    approved = await container.deployments.approve(
        "claims-triage-prod", Approve(comment="CAB-1234"), op(container, "approver@corp.test")
    )
    assert approved.outcome == "applied"
    assert approved.deployment.current is not None
    assert approved.deployment.current.approvals[0].actor == "approver@corp.test"
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod") is not None
    with pytest.raises(InvalidStateError):
        await container.deployments.approve(
            "claims-triage-prod", Approve(), op(container, "approver2@corp.test")
        )


async def test_development_deploys_of_high_risk_agents_apply_directly(
    container: Container,
) -> None:
    await seed(container, risk=RiskLevel.HIGH)
    result = await deploy(
        container, name="claims-triage-dev", environment=Environment.DEVELOPMENT, namespace=DEV_NS
    )
    assert result.outcome == "applied"


async def test_upgrade_registers_new_identity_and_revokes_old_once_available(
    fabric_container: Container, fabric: FakeFabric, kube: FakeKubeApiServer
) -> None:
    c = fabric_container
    await seed(c)
    first = await deploy(c)
    uri_v1 = f"spiffe://{TRUST_DOMAIN}/agent/claims/claims-triage-prod-1.0.0"
    assert first.deployment.identity_uri == uri_v1
    registration = fabric.agents[uri_v1]["registration"]
    assert registration["workload"] == {
        "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/TESTCLUSTER",
        "subject": f"system:serviceaccount:{PROD_NS}:claims-triage-prod",
        "audience": "identity-fabric",
        "image_digests": ["sha256:" + "b" * 64],
    }
    assert registration["mandate"]["protected_resources"] == ["tool:claims.search"]

    await seed(c, version="1.1.0", digest=DIGEST_V2)
    kube.auto_ready = False  # the new pods are not ready yet
    upgraded = await deploy(c, version="1.1.0")
    uri_v2 = f"spiffe://{TRUST_DOMAIN}/agent/claims/claims-triage-prod-1.1.0"
    assert upgraded.deployment.identity_uri == uri_v2
    assert upgraded.status is not None
    assert upgraded.status.phase is Phase.PROGRESSING
    assert fabric.agents[uri_v1]["status"] == "pending"  # not revoked while rolling out

    kube.mark_ready(PROD_NS, "claims-triage-prod")
    status = await c.reconciler.reconcile("claims-triage-prod")
    assert status.phase is Phase.AVAILABLE
    assert fabric.agents[uri_v1]["status"] == "revoked"
    spec = await c.deployments.get("claims-triage-prod")
    assert spec.superseded_identities == ()


async def test_scaling_without_version_change_keeps_identity(
    fabric_container: Container, fabric: FakeFabric
) -> None:
    await seed(fabric_container)
    first = await deploy(fabric_container)
    scaled = await deploy(fabric_container, replicas=5)
    assert scaled.deployment.identity_uri == first.deployment.identity_uri
    assert scaled.deployment.current is not None
    assert scaled.deployment.current.generation == 2
    assert len([u for u in fabric.agents if "claims-triage-prod" in u]) == 1


async def test_delete_removes_objects_and_revokes_identity(
    fabric_container: Container, fabric: FakeFabric, kube: FakeKubeApiServer
) -> None:
    await seed(fabric_container)
    applied = await deploy(fabric_container)
    result = await fabric_container.deployments.delete(
        "claims-triage-prod",
        Reason(reason="agent replaced by v2 service"),
        op(fabric_container, "deployer@corp.test"),
    )
    assert result.deployment.state is DeploymentState.DELETED
    assert not [k for k in kube.objects if k[1] == PROD_NS]
    assert fabric.agents[str(applied.deployment.identity_uri)]["status"] == "revoked"
    with pytest.raises(InvalidStateError):
        await fabric_container.deployments.delete(
            "claims-triage-prod",
            Reason(reason="again please"),
            op(fabric_container, "deployer@corp.test"),
        )
    # The name can be reused after deletion.
    again = await deploy(fabric_container)
    assert again.deployment.state is DeploymentState.ACTIVE


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"namespace": "kube-system"}, ForbiddenError),
        ({"version": "9.9.9"}, NotFoundError),
        ({"agent": ("claims", "unknown-agent")}, NotFoundError),
        ({"env": {"API_TOKEN": "ghp_" + "a" * 36}}, UnsafeContentError),
        ({"env": {"ACP_DEPLOYMENT": "spoof"}}, ControlPlaneError),
        ({"env": {"lowercase": "x"}}, ControlPlaneError),
    ],
)
async def test_invalid_deployments_are_rejected(
    container: Container, change: dict[str, object], error: type[Exception]
) -> None:
    await seed(container)
    with pytest.raises(error):
        await deploy(container, **change)  # type: ignore[arg-type]


async def test_unapproved_version_cannot_deploy(container: Container) -> None:
    await seed(container)
    dev = op(container, "dev@corp.test")
    from tests.conftest import version_command

    await container.registry.create_version(
        "claims", "claims-triage", version_command("2.0.0"), dev
    )
    with pytest.raises(InvalidStateError, match="only approved versions deploy"):
        await deploy(container, version="2.0.0")


async def test_immutable_fields_cannot_change(container: Container) -> None:
    await seed(container)
    await deploy(container)
    with pytest.raises(ConflictError, match="namespace"):
        await deploy(container, namespace=DEV_NS)


async def test_missing_bundle_and_deployment(container: Container) -> None:
    await seed(container)
    command = deploy_command().model_copy(
        update={
            "policy_bundle": deploy_command().policy_bundle.model_copy(update={"version": "9.0.0"})
        }
    )
    with pytest.raises(NotFoundError, match="policy bundle"):
        await container.deployments.apply(command, op(container, "deployer@corp.test"))
    with pytest.raises(NotFoundError):
        await container.deployments.get("nope")
    with pytest.raises(NotFoundError):
        await container.deployments.status("nope")


async def test_listing_and_status(container: Container) -> None:
    await seed(container)
    await deploy(container)
    listed = await container.deployments.list(
        state=DeploymentState.ACTIVE, agent_key="claims/claims-triage", limit=10, offset=0
    )
    assert [d.name for d in listed] == ["claims-triage-prod"]
    status = await container.deployments.status("claims-triage-prod")
    assert status is not None
    assert status.phase is Phase.AVAILABLE
