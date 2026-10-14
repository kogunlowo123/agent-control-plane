"""Reconciliation: rollout vs drift, read-only detection, the leader-gated loop."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from agent_control_plane.domain.errors import InvalidStateError, NotFoundError
from agent_control_plane.domain.models import Phase
from agent_control_plane.infrastructure.database import SqlLeaseStore
from agent_control_plane.orchestration.reconciler import ReconcileLoop
from agent_control_plane.runtime.container import Container
from tests.conftest import PROD_NS, FakeClock, deploy, seed
from tests.fakes import FakeKubeApiServer


async def deployed(c: Container) -> None:
    await seed(c)
    await deploy(c)


def metric(c: Container, name: str, **labels: str) -> float:
    value = c.metrics.registry.get_sample_value(name, labels or None)
    return float(value or 0)


async def test_out_of_band_edit_is_drift_and_is_corrected(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await deployed(container)

    def scale_and_privilege(obj: dict) -> None:
        obj["spec"]["replicas"] = 9
        obj["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True

    kube.tamper("Deployment", PROD_NS, "claims-triage-prod", scale_and_privilege)
    report = await container.reconciler.detect_drift("claims-triage-prod")
    assert not report.in_sync
    assert {i.path for i in report.drift} == {
        "spec.replicas",
        "spec.template.spec.containers[agent].securityContext.privileged",
    }
    assert report.pending_rollout == ()
    # Detection changed nothing.
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 9

    status = await container.reconciler.reconcile("claims-triage-prod")
    assert status.corrected
    assert len(status.drift) == 2
    live = kube.get("Deployment", PROD_NS, "claims-triage-prod")
    assert live["spec"]["replicas"] == 2
    assert (
        live["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False
    )
    assert metric(container, "acp_drift_detected_total", kind="Deployment", change="changed") == 2
    assert (await container.reconciler.detect_drift("claims-triage-prod")).in_sync


async def test_deleted_object_is_recreated(container: Container, kube: FakeKubeApiServer) -> None:
    await deployed(container)
    del kube.objects[("NetworkPolicy", PROD_NS, "claims-triage-prod")]
    report = await container.reconciler.detect_drift("claims-triage-prod")
    assert [(i.kind, i.change) for i in report.pending_rollout] == [("NetworkPolicy", "absent")]
    await container.reconciler.reconcile("claims-triage-prod")
    assert kube.get("NetworkPolicy", PROD_NS, "claims-triage-prod") is not None


async def test_new_revision_is_a_rollout_not_drift(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await deployed(container)
    result = await deploy(container, replicas=4)
    assert result.status is not None
    assert result.status.drift == ()
    assert kube.get("Deployment", PROD_NS, "claims-triage-prod")["spec"]["replicas"] == 4


async def test_reconcile_all_and_phase_gauge(container: Container) -> None:
    await deployed(container)
    statuses = await container.reconciler.reconcile_all()
    assert [s.phase for s in statuses] == [Phase.AVAILABLE]
    assert metric(container, "acp_deployments", phase="Available") == 1


async def test_cluster_errors_degrade_the_status(
    container: Container, kube: FakeKubeApiServer
) -> None:
    await deployed(container)
    kube.down = True
    status = await container.reconciler.reconcile("claims-triage-prod")
    assert status.phase is Phase.DEGRADED
    assert "unavailable" in status.message
    assert metric(container, "acp_reconcile_errors_total", error="DependencyError") == 1
    kube.down = False
    assert (await container.reconciler.reconcile("claims-triage-prod")).phase is Phase.AVAILABLE


async def test_missing_references_and_unknown_deployments(container: Container) -> None:
    with pytest.raises(NotFoundError):
        await container.reconciler.reconcile("unknown")
    await deployed(container)
    spec = await container.deployments.get("claims-triage-prod")
    with pytest.raises(InvalidStateError):
        await container.reconciler.desired(spec.model_copy(update={"current": None}))


async def test_loop_runs_only_on_the_leader(container: Container, clock: FakeClock) -> None:
    await deployed(container)
    loop = container.loop
    assert await loop.run_once()
    assert metric(container, "acp_reconciler_leader") == 1
    assert metric(container, "acp_cluster_reachable") == 1

    other = ReconcileLoop(
        container.reconciler,
        SqlLeaseStore(container.engine),
        holder="another-replica",
        interval_s=1,
        lease_ttl_s=30,
        clock=clock,
        metrics=container.metrics,
        cluster=container.cluster,
    )
    assert not await other.run_once()  # lease held by the first replica
    clock.advance(int(container.settings.lease_ttl_s) + 1)
    assert await other.run_once()  # expired lease is taken over
    assert not await loop.run_once()


async def test_run_forever_survives_errors_and_wakes_on_trigger(container: Container) -> None:
    calls: list[str] = []
    loop = container.loop

    async def failing_once() -> bool:
        calls.append("run")
        if len(calls) == 1:
            raise RuntimeError("transient")
        return True

    loop.run_once = failing_once  # type: ignore[method-assign]
    waits: list[float] = []

    async def wait(event: asyncio.Event, seconds: float) -> None:
        waits.append(seconds)
        if len(waits) >= 3:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await loop.run_forever(wait)
    assert calls == ["run", "run", "run"]

    loop.trigger()
    from agent_control_plane.orchestration import reconciler as module

    await module._wait_for(loop._wake, 5)  # returns immediately when triggered
    await module._wait_for(asyncio.Event(), 0.01)  # times out quietly


async def test_lease_is_renewed_by_its_holder(container: Container, clock: FakeClock) -> None:
    leases = SqlLeaseStore(container.engine)
    assert await leases.acquire("x", "a", ttl_s=10, now=clock.now())
    assert await leases.acquire("x", "a", ttl_s=10, now=clock.now() + timedelta(seconds=5))
    assert not await leases.acquire("x", "b", ttl_s=10, now=clock.now() + timedelta(seconds=9))
    assert await leases.acquire("x", "b", ttl_s=10, now=clock.now() + timedelta(seconds=16))
