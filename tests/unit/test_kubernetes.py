"""KubernetesCluster over the official client: CRUD, conflicts, outages, config loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from kubernetes.config.config_exception import ConfigException

from agent_control_plane.domain.errors import ConflictError, DependencyError
from agent_control_plane.infrastructure.kubernetes import KubernetesCluster, load_api_client
from tests.fakes import FakeKubeApiServer, make_cluster


def config_map(name: str = "cm", data: dict[str, str] | None = None) -> dict[str, object]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "agents-dev", "labels": {"a": "b"}},
        "data": data or {"k": "v"},
    }


async def test_crud_round_trip(kube: FakeKubeApiServer) -> None:
    cluster = make_cluster(kube)
    assert await cluster.read("ConfigMap", "agents-dev", "cm") is None
    created = await cluster.create(config_map())
    assert created["metadata"]["resourceVersion"]
    assert ("POST", "/api/v1/namespaces/agents-dev/configmaps") in kube.requests
    live = await cluster.read("ConfigMap", "agents-dev", "cm")
    assert live is not None
    assert live["data"] == {"k": "v"}
    replaced = await cluster.replace(
        config_map(data={"k": "w"}), live["metadata"]["resourceVersion"]
    )
    assert replaced["data"] == {"k": "w"}
    assert await cluster.delete("ConfigMap", "agents-dev", "cm") is True
    assert await cluster.delete("ConfigMap", "agents-dev", "cm") is False
    assert await cluster.ping() is True
    cluster.close()


async def test_optimistic_concurrency_and_conflicts(kube: FakeKubeApiServer) -> None:
    cluster = make_cluster(kube)
    await cluster.create(config_map())
    with pytest.raises(ConflictError):
        await cluster.create(config_map())
    with pytest.raises(ConflictError):
        await cluster.replace(config_map(), "stale-version")


async def test_api_errors_and_outages(kube: FakeKubeApiServer) -> None:
    cluster = make_cluster(kube)
    kube.fail_next.append(("GET", "ConfigMap", 500))
    with pytest.raises(DependencyError, match="read ConfigMap failed: 500"):
        await cluster.read("ConfigMap", "agents-dev", "cm")
    kube.fail_next.append(("POST", "ConfigMap", 403))
    with pytest.raises(DependencyError, match="create ConfigMap failed: 403"):
        await cluster.create(config_map())
    await cluster.create(config_map())
    kube.fail_next.append(("PUT", "ConfigMap", 422))
    live = await cluster.read("ConfigMap", "agents-dev", "cm")
    assert live is not None
    with pytest.raises(DependencyError, match="replace ConfigMap failed: 422"):
        await cluster.replace(config_map(), live["metadata"]["resourceVersion"])
    kube.fail_next.append(("DELETE", "ConfigMap", 500))
    with pytest.raises(DependencyError, match="delete ConfigMap failed"):
        await cluster.delete("ConfigMap", "agents-dev", "cm")
    kube.down = True
    with pytest.raises(DependencyError, match="unavailable"):
        await cluster.read("ConfigMap", "agents-dev", "cm")
    assert await cluster.ping() is False


async def test_unsupported_kinds_are_refused(kube: FakeKubeApiServer) -> None:
    cluster = make_cluster(kube)
    with pytest.raises(ValueError, match="unsupported kind"):
        await cluster.read("Secret", "agents-dev", "x")


def test_kubeconfig_loading(tmp_path: Path) -> None:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(
        """
apiVersion: v1
kind: Config
clusters:
  - name: ci
    cluster:
      server: https://k8s.ci.internal:6443
      insecure-skip-tls-verify: false
contexts:
  - name: ci
    context: {cluster: ci, user: acp}
current-context: ci
users:
  - name: acp
    user: {token: ci-only-token}
""",
        encoding="utf-8",
    )
    api = load_api_client("kubeconfig", str(kubeconfig))
    assert api.configuration.host == "https://k8s.ci.internal:6443"
    KubernetesCluster(api).close()
    with pytest.raises(ConfigException, match=r"Service host/port is not set"):
        load_api_client("in-cluster")
