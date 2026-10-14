"""Kill switch: immediate stop, identity suspension, two-person release, overlap."""

from __future__ import annotations

import pytest

from agent_control_plane.application.commands import EngageKillSwitch, Reason
from agent_control_plane.domain.errors import (
    ControlPlaneError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from agent_control_plane.domain.models import Environment, KillScope, Phase
from agent_control_plane.runtime.container import Container
from tests.conftest import DEV_NS, PROD_NS, deploy, op, seed
from tests.fakes import FakeFabric, FakeKubeApiServer


def engage(scope: KillScope, target: str) -> EngageKillSwitch:
    return EngageKillSwitch(scope=scope, target=target, reason="anomalous tool calls observed")


async def two_deployments(c: Container) -> None:
    await seed(c)
    await deploy(c)
    await deploy(c, name="claims-triage-dev", environment=Environment.DEVELOPMENT, namespace=DEV_NS)


async def test_agent_kill_switch_stops_every_deployment(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await two_deployments(container)
    result = await container.kill_switches.engage(
        engage(KillScope.AGENT, "claims/claims-triage"), op(container, "secops@corp.test")
    )
    assert set(result.affected) == {"claims-triage-prod", "claims-triage-dev"}
    assert {s.phase for s in result.statuses} == {Phase.KILLED}
    assert result.identity_actions == {
        "claims-triage-prod": "no_identity",
        "claims-triage-dev": "no_identity",
    }
    for ns, name in [(PROD_NS, "claims-triage-prod"), (DEV_NS, "claims-triage-dev")]:
        assert kube.get("Deployment", ns, name)["spec"]["replicas"] == 0
        assert "ingress" not in kube.get("NetworkPolicy", ns, name)["spec"]
        assert "egress" not in kube.get("NetworkPolicy", ns, name)["spec"]
    # Re-applying desired state while killed keeps it stopped.
    redeploy = await deploy(container, replicas=5)
    assert redeploy.status is not None
    assert redeploy.status.phase is Phase.KILLED
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0
    assert await container.kill_switches.is_killed("claims-triage-prod") == (result.kill_switch.id,)


async def test_release_requires_another_officer_and_restores(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await two_deployments(container)
    engaged = await container.kill_switches.engage(
        engage(KillScope.DEPLOYMENT, "claims-triage-prod"), op(container, "secops@corp.test")
    )
    switch_id = engaged.kill_switch.id
    reason = Reason(reason="root cause fixed in 1.0.1")
    with pytest.raises(ForbiddenError):
        await container.kill_switches.release(switch_id, reason, op(container, "secops@corp.test"))
    released = await container.kill_switches.release(
        switch_id, reason, op(container, "secops2@corp.test")
    )
    assert released.kill_switch.active is False
    assert released.kill_switch.released_by == "secops2@corp.test"
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 2
    with pytest.raises(InvalidStateError):
        await container.kill_switches.release(switch_id, reason, op(container, "secops2@corp.test"))
    assert [s.id for s in await container.kill_switches.list(active=False)] == [switch_id]


async def test_overlapping_switches_keep_target_stopped(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await two_deployments(container)
    officer = op(container, "secops@corp.test")
    everything = await container.kill_switches.engage(engage(KillScope.GLOBAL, "*"), officer)
    one = await container.kill_switches.engage(
        engage(KillScope.DEPLOYMENT, "claims-triage-prod"), officer
    )
    released = await container.kill_switches.release(
        everything.kill_switch.id,
        Reason(reason="platform incident over"),
        op(container, "secops2@corp.test"),
    )
    assert released.identity_actions["claims-triage-prod"] == "still_killed"
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0
    assert kube.get("Deployment", DEV_NS, "claims-triage-dev")["spec"]["replicas"] == 2
    assert container.metrics.registry.get_sample_value("acp_kill_switches_active") == 1
    assert (await container.kill_switches.get(one.kill_switch.id)).active


async def test_identities_are_suspended_and_reinstated(
    fabric_container: Container, fabric: FakeFabric
) -> None:
    c = fabric_container
    await seed(c)
    applied = await deploy(c)
    uri = str(applied.deployment.identity_uri)
    pending = await c.kill_switches.engage(
        engage(KillScope.DEPLOYMENT, "claims-triage-prod"), op(c, "secops@corp.test")
    )
    # Never attested yet: the fabric refuses to suspend a pending identity; the kill proceeds.
    assert pending.identity_actions == {"claims-triage-prod": "not_applicable"}
    await c.kill_switches.release(
        pending.kill_switch.id, Reason(reason="false positive"), op(c, "secops2@corp.test")
    )

    fabric.agents[uri]["status"] = "active"  # the workload attested and runs
    engaged = await c.kill_switches.engage(
        engage(KillScope.AGENT, "claims/claims-triage"), op(c, "secops@corp.test")
    )
    assert engaged.identity_actions == {"claims-triage-prod": "success"}
    assert fabric.agents[uri]["status"] == "suspended"
    released = await c.kill_switches.release(
        engaged.kill_switch.id, Reason(reason="contained and patched"), op(c, "secops2@corp.test")
    )
    assert released.identity_actions == {"claims-triage-prod": "success"}
    assert fabric.agents[uri]["status"] == "active"


async def test_fabric_outage_does_not_block_the_kill(
    fabric_container: Container, fabric: FakeFabric, kube: FakeKubeApiServer
) -> None:
    await seed(fabric_container)
    await deploy(fabric_container)
    fabric.down = True
    result = await fabric_container.kill_switches.engage(
        engage(KillScope.DEPLOYMENT, "claims-triage-prod"), op(fabric_container, "secops@corp.test")
    )
    assert result.identity_actions["claims-triage-prod"].startswith("failed")
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0


@pytest.mark.parametrize(
    ("scope", "target", "error"),
    [
        (KillScope.GLOBAL, "claims/claims-triage", ControlPlaneError),
        (KillScope.AGENT, "claims/unknown", NotFoundError),
        (KillScope.AGENT, "no-slash", NotFoundError),
        (KillScope.DEPLOYMENT, "unknown", NotFoundError),
    ],
)
async def test_invalid_targets(
    container: Container, scope: KillScope, target: str, error: type[Exception]
) -> None:
    await seed(container)
    with pytest.raises(error):
        await container.kill_switches.engage(
            engage(scope, target), op(container, "secops@corp.test")
        )


async def test_unauthorised_roles_cannot_engage(container: Container) -> None:
    await seed(container)
    await deploy(container)
    with pytest.raises(ForbiddenError):
        await container.kill_switches.engage(
            engage(KillScope.DEPLOYMENT, "claims-triage-prod"), op(container, "dev@corp.test")
        )
    with pytest.raises(NotFoundError):
        await container.kill_switches.get("f" * 32)
    with pytest.raises(NotFoundError):
        await container.kill_switches.is_killed("unknown")
