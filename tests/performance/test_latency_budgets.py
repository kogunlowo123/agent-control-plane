"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time

import pytest
from agentic_core.domain.classification import RiskLevel
from agentic_core.policy import Resource

from agent_control_plane.domain.models import Environment
from agent_control_plane.orchestration.drift import detect
from agent_control_plane.runtime.container import Container
from agent_control_plane.security.oidc import Principal
from tests.conftest import DEV_NS, deploy, seed
from tests.unit.test_manifests import inputs

pytestmark = pytest.mark.performance


def test_render_and_diff_budget() -> None:
    from agent_control_plane.orchestration.manifests import render

    started = time.perf_counter()
    for _ in range(200):
        objects = render(**inputs())  # type: ignore[arg-type]
        for obj in objects:
            assert detect(obj, obj) == []
    per_deployment_ms = (time.perf_counter() - started) * 1000 / 200
    assert per_deployment_ms < 15


def test_policy_decision_budget(container: Container) -> None:
    principal = Principal(subject="approver@corp.test", roles=frozenset({"acp-approver"}))
    resource = Resource(
        type="agent_version",
        id="a@1.0.0",
        attributes={"risk": 3, "approvals": 0, "submitted_by": "dev"},
    )
    started = time.perf_counter()
    for _ in range(2000):
        container.gate.evaluate(
            principal,
            action="controlplane:registry:approve",
            resource=resource,
            risk=RiskLevel.HIGH,
        )
    per_decision_ms = (time.perf_counter() - started) * 1000 / 2000
    assert per_decision_ms < 1


async def test_steady_state_reconcile_budget(container: Container) -> None:
    """A converged deployment reconciles (read four objects, compare, record) quickly."""
    await seed(container)
    for index in range(10):
        await deploy(
            container,
            name=f"claims-triage-{index}",
            environment=Environment.DEVELOPMENT,
            namespace=DEV_NS,
        )
    started = time.perf_counter()
    statuses = await container.reconciler.reconcile_all()
    per_deployment_ms = (time.perf_counter() - started) * 1000 / len(statuses)
    assert len(statuses) == 10
    assert per_deployment_ms < 250
