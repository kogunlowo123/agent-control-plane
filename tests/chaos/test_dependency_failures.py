"""Fault injection: the control plane degrades safely and fails closed."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.application.commands import EngageKillSwitch
from agent_control_plane.domain.errors import DependencyError
from agent_control_plane.domain.models import KillScope, Phase
from agent_control_plane.infrastructure.database import make_engine
from agent_control_plane.runtime.container import Container
from tests.conftest import PROD_NS, deploy, op, seed
from tests.fakes import FakeFabric, FakeKubeApiServer

pytestmark = pytest.mark.chaos


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200  # liveness unaffected
    finally:
        container.engine = healthy


async def test_kubernetes_outage_degrades_and_recovers(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await seed(container)
    await deploy(container)
    kube.down = True
    statuses = await container.reconciler.reconcile_all()
    assert [s.phase for s in statuses] == [Phase.DEGRADED]
    assert (
        container.metrics.registry.get_sample_value("acp_deployments", {"phase": "Degraded"}) == 1
    )
    assert not await container.loop._cluster.ping()
    kube.down = False
    assert (await container.reconciler.reconcile("claims-triage-prod")).phase is Phase.AVAILABLE


async def test_concurrent_writer_conflict_is_retried_next_pass(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await seed(container)
    await deploy(container)
    kube.tamper("Deployment", PROD_NS, "claims-triage-prod", lambda o: o["spec"].update(replicas=7))
    kube.fail_next.append(("PUT", "Deployment", 409))
    first = await container.reconciler.reconcile("claims-triage-prod")
    assert first.phase is Phase.DEGRADED
    second = await container.reconciler.reconcile("claims-triage-prod")
    assert second.phase is Phase.AVAILABLE
    assert second.corrected


async def test_kill_switch_holds_even_if_cluster_is_down_at_engagement(
    container: Container, kube: FakeKubeApiServer
) -> None:
    """The switch is recorded first; the next successful reconcile enforces it."""
    await seed(container)
    await deploy(container)
    kube.down = True
    result = await container.kill_switches.engage(
        EngageKillSwitch(
            scope=KillScope.DEPLOYMENT, target="claims-triage-prod", reason="contain now"
        ),
        op(container, "secops@corp.test"),
    )
    assert result.statuses[0].phase is Phase.DEGRADED
    kube.down = False
    assert (await container.reconciler.reconcile("claims-triage-prod")).phase is Phase.KILLED
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 0


async def test_fabric_outage_blocks_new_identities_not_running_agents(
    fabric_container: Container, fabric: FakeFabric
) -> None:
    await seed(fabric_container)
    await deploy(fabric_container)
    fabric.down = True
    # Changing replicas needs no new identity: still works.
    assert (await deploy(fabric_container, replicas=3)).outcome == "applied"
    # A new version needs a new identity: fails without changing anything.
    from tests.conftest import DIGEST_V2

    fabric.down = False
    await seed(fabric_container, version="1.1.0", digest=DIGEST_V2)
    fabric.down = True
    with pytest.raises(DependencyError):
        await deploy(fabric_container, version="1.1.0")
    spec = await fabric_container.deployments.get("claims-triage-prod")
    assert spec.current is not None
    assert spec.current.version == "1.0.0"


async def test_revocation_of_superseded_identity_retries(
    fabric_container: Container, fabric: FakeFabric
) -> None:
    from tests.conftest import DIGEST_V2

    await seed(fabric_container)
    first = await deploy(fabric_container)
    await seed(fabric_container, version="1.1.0", digest=DIGEST_V2)
    fabric.fail_status["/v1/revoke-agent"] = 503
    await deploy(fabric_container, version="1.1.0")
    spec = await fabric_container.deployments.get("claims-triage-prod")
    assert spec.superseded_identities == (first.deployment.identity_uri,)
    fabric.fail_status = {}
    await fabric_container.reconciler.reconcile("claims-triage-prod")
    assert (
        await fabric_container.deployments.get("claims-triage-prod")
    ).superseded_identities == ()
    assert fabric.agents[str(first.deployment.identity_uri)]["status"] == "revoked"


async def test_audit_failure_blocks_the_change(container: Container) -> None:
    """If evidence cannot be written, the action must not complete silently."""
    from tests.conftest import agent_command

    async def broken_append(_: object) -> None:
        raise OSError("audit storage unavailable")

    container.recorder._audit._sink.append = broken_append  # type: ignore[method-assign]
    with pytest.raises(OSError, match="audit storage"):
        await container.registry.create_agent(agent_command(), op(container, "dev@corp.test"))
