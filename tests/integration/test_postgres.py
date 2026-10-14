"""Repositories, lease and audit chain against a real PostgreSQL (CI service container).

Runs when ACP_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://acp:acp@localhost:5432/acp
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentic_core.audit import AuditLog, verify_chain

from agent_control_plane.domain.models import DeploymentState, Phase
from agent_control_plane.infrastructure.database import (
    SqlAuditSink,
    SqlLeaseStore,
    create_schema,
    make_engine,
)
from agent_control_plane.security.signing import SigningKey
from tests.conftest import FakeClock, base_settings, build, deploy, seed
from tests.fakes import FakeIdp, FakeKubeApiServer

URL = os.environ.get("ACP_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_lease_and_audit_chain_on_postgres() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)  # idempotent
    leases = SqlLeaseStore(engine)
    now = datetime.now(UTC)
    name = f"pg-{now.timestamp():.0f}"
    assert await leases.acquire(name, "a", ttl_s=30, now=now)
    assert not await leases.acquire(name, "b", ttl_s=30, now=now + timedelta(seconds=10))
    assert await leases.acquire(name, "b", ttl_s=30, now=now + timedelta(seconds=31))

    key = SigningKey.ephemeral("audit")
    sink = SqlAuditSink(engine, name)
    log = AuditLog(sink, key, key_id=key.key_id)
    for n in range(5):
        await log.record(actor="pg", action=f"x.{n}", resource="r", outcome="success")
    events = [e async for e in sink.read()]
    assert verify_chain(events, {key.key_id: key.public}) == 5
    await engine.dispose()


async def test_full_flow_on_postgres(tmp_path: Path) -> None:
    settings = base_settings(tmp_path, database_url=URL, instance_id=f"pg-{tmp_path.name[-10:]}")
    container = await build(
        settings,
        FakeKubeApiServer(),
        FakeIdp("https://login.corp.test/tenant", kid="operator-1"),
        FakeClock(),
    )
    try:
        await seed(container)
        result = await deploy(container, name="claims-triage-pg")
        assert result.status is not None
        assert result.status.phase is Phase.AVAILABLE
        listed = await container.deployments.list(
            state=DeploymentState.ACTIVE, agent_key="claims/claims-triage", limit=500, offset=0
        )
        assert result.deployment.name in {d.name for d in listed}
    finally:
        await container.aclose()
