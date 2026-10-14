"""Settings validation, composition root, persistence and published contracts."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentic_core.audit import AuditLog, verify_chain
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_control_plane.contracts import main as contracts_main
from agent_control_plane.infrastructure.database import (
    SqlAuditSink,
    create_schema,
    list_chains,
    make_engine,
    read_chain,
)
from agent_control_plane.integrations.identity_fabric import FabricAuthorizer
from agent_control_plane.runtime.container import build_container
from agent_control_plane.security.authorization import LocalAuthorizer
from agent_control_plane.security.signing import SigningKey
from tests.conftest import ROOT, FakeClock, base_settings, build, fabric_overrides
from tests.fakes import FakeFabric, FakeIdp, FakeKubeApiServer, make_cluster


def test_settings_validation(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="production"):
        base_settings(tmp_path, environment="production")
    with pytest.raises(ValidationError, match="signing configuration incomplete"):
        base_settings(tmp_path, dev_ephemeral_keys=False)
    with pytest.raises(ValidationError, match="managed namespace"):
        base_settings(tmp_path, managed_namespaces=frozenset())
    with pytest.raises(ValidationError, match="identity fabric integration incomplete"):
        base_settings(tmp_path, fabric_url="https://identity.corp.test")
    with pytest.raises(ValidationError, match="KUBECONFIG_PATH"):
        base_settings(tmp_path, kubeconfig_path=None)
    settings = base_settings(tmp_path, **fabric_overrides())
    assert settings.fabric_url_str == "https://identity.corp.test"
    assert settings.public_url_str == "https://acp.corp.test"
    assert base_settings(tmp_path).fabric_url_str is None


def _write_key(path: Path) -> Path:
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


async def test_container_with_key_files_and_local_authorizer(
    tmp_path: Path, kube: FakeKubeApiServer, operator_idp: FakeIdp, clock: FakeClock
) -> None:
    settings = base_settings(
        tmp_path,
        environment="production",
        dev_ephemeral_keys=False,
        audit_key_file=_write_key(tmp_path / "audit-2026-10.pem"),
        bundle_key_file=_write_key(tmp_path / "bundle-2026-10.pem"),
    )
    container = await build(settings, kube, operator_idp, clock)
    try:
        assert container.audit_key.key_id == "audit-2026-10"
        assert isinstance(container.agent_authorizer, LocalAuthorizer)
    finally:
        await container.aclose()


async def test_container_with_fabric_uses_fabric_authorizer(
    fabric_settings: object, kube: FakeKubeApiServer, operator_idp: FakeIdp, clock: FakeClock
) -> None:
    container = await build(fabric_settings, kube, operator_idp, clock, FakeFabric())  # type: ignore[arg-type]
    try:
        assert isinstance(container.agent_authorizer, FabricAuthorizer)
    finally:
        await container.aclose()


async def test_container_builds_its_own_cluster_client(tmp_path: Path) -> None:
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: 'https://k8s.test'}}]\n"
        "contexts: [{name: c, context: {cluster: c, user: u}}]\ncurrent-context: c\n"
        "users: [{name: u, user: {token: t}}]\n",
        encoding="utf-8",
    )
    container = await build_container(base_settings(tmp_path, kubeconfig_path=str(kubeconfig)))
    await container.aclose()


async def test_sql_audit_sink_chains_per_replica(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}")
    await create_schema(engine)
    await create_schema(engine)  # idempotent
    key = SigningKey.ephemeral("audit")
    for chain in ("replica-a", "replica-b"):
        log = AuditLog(SqlAuditSink(engine, chain), key, key_id=key.key_id)
        for n in range(3):
            await log.record(actor="a", action=f"x.{n}", resource="r", outcome="success")
    # A restarted replica continues its chain from the stored tail.
    resumed = AuditLog(SqlAuditSink(engine, "replica-a"), key, key_id=key.key_id)
    event = await resumed.record(actor="a", action="x.3", resource="r", outcome="success")
    assert event.sequence == 3
    assert await list_chains(engine) == ["replica-a", "replica-b"]
    events = [e async for e in SqlAuditSink(engine, "replica-a").read()]
    assert verify_chain(events, {key.key_id: key.public}) == 4
    page = [e async for e in read_chain(engine, "replica-a", limit=2, offset=1)]
    assert [e.sequence for e in page] == [1, 2]
    assert await SqlAuditSink(engine, "empty").tail() is None
    await engine.dispose()


def test_committed_contracts_are_current() -> None:
    assert contracts_main(["--check"], root=ROOT) == 0


def test_export_and_check_round_trip(tmp_path: Path) -> None:
    assert contracts_main(["--check"], root=tmp_path) == 1
    assert contracts_main([], root=tmp_path) == 0
    assert contracts_main(["--check"], root=tmp_path) == 0
    assert (tmp_path / "schemas" / "apply-deployment.request.schema.json").is_file()
    assert (tmp_path / "docs" / "api" / "openapi.json").is_file()


def test_policy_file_parses() -> None:
    from agentic_core.policy import PolicySet

    policy = PolicySet.from_file(ROOT / "policies" / "control-plane.yaml")
    assert policy.name == "agent-control-plane"
    assert len({r.id for r in policy.rules}) == len(policy.rules)


def test_make_cluster_helper_is_isolated() -> None:
    a, b = FakeKubeApiServer(), FakeKubeApiServer()
    assert make_cluster(a) is not make_cluster(b)
