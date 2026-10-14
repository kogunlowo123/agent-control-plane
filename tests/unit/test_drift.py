"""Drift rules: tolerate server defaults, catch out-of-band changes that matter."""

from __future__ import annotations

import copy
from typing import Any

from agent_control_plane.orchestration.drift import detect, diff

DEPLOYMENT: dict[str, Any] = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "a", "namespace": "n", "labels": {"app": "a"}},
    "spec": {
        "replicas": 2,
        "template": {
            "spec": {
                "securityContext": {"runAsNonRoot": True},
                "containers": [
                    {
                        "name": "agent",
                        "image": "r@sha256:1",
                        "env": [{"name": "A", "value": "1"}],
                        "securityContext": {"privileged": False},
                        "resources": {"limits": {"cpu": "1"}},
                    }
                ],
            }
        },
    },
}


def live(**mutations: Any) -> dict[str, Any]:
    obj = copy.deepcopy(DEPLOYMENT)
    obj["metadata"].update({"resourceVersion": "7", "uid": "u", "annotations": {"x": "y"}})
    obj["metadata"]["labels"]["added-by-someone"] = "ok"
    pod = obj["spec"]["template"]["spec"]
    pod.update({"dnsPolicy": "ClusterFirst", "restartPolicy": "Always"})
    pod["containers"][0]["terminationMessagePath"] = "/dev/termination-log"
    obj["status"] = {"readyReplicas": 2}
    for path, value in mutations.items():
        target = obj
        keys = path.split("__")
        for key in keys[:-1]:
            target = target[int(key)] if isinstance(target, list) else target[key]
        target[keys[-1]] = value
    return obj


def test_server_defaults_and_extra_metadata_are_not_drift() -> None:
    assert detect(DEPLOYMENT, live()) == []


def test_absent_object() -> None:
    [item] = detect(DEPLOYMENT, None)
    assert item.change == "absent"
    assert item.kind == "Deployment"


def test_changed_scalar() -> None:
    [item] = detect(DEPLOYMENT, live(spec__replicas=5))
    assert (item.path, item.change, item.expected, item.actual) == (
        "spec.replicas",
        "changed",
        2,
        5,
    )


def test_injected_sidecar_and_env_are_unexpected() -> None:
    obj = live()
    obj["spec"]["template"]["spec"]["containers"].append({"name": "miner", "image": "evil"})
    obj["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "HTTPS_PROXY", "value": "x"}
    )
    items = {(i.path, i.change) for i in detect(DEPLOYMENT, obj)}
    assert ("spec.template.spec.containers[miner]", "unexpected") in items
    assert ("spec.template.spec.containers[agent].env[HTTPS_PROXY]", "unexpected") in items


def test_strict_security_context_and_resources() -> None:
    obj = live()
    container = obj["spec"]["template"]["spec"]["containers"][0]
    container["securityContext"]["capabilities"] = {"add": ["NET_ADMIN"]}
    container["resources"]["requests"] = {"cpu": "8"}
    obj["spec"]["template"]["spec"]["securityContext"]["runAsUser"] = 0
    paths = {i.path for i in detect(DEPLOYMENT, obj) if i.change == "unexpected"}
    assert "spec.template.spec.containers[agent].securityContext.capabilities" in paths
    assert "spec.template.spec.containers[agent].resources.requests" in paths
    assert "spec.template.spec.securityContext.runAsUser" in paths


def test_host_namespaces_and_init_containers_are_always_drift() -> None:
    obj = live()
    obj["spec"]["template"]["spec"]["hostNetwork"] = True
    obj["spec"]["template"]["spec"]["initContainers"] = [{"name": "setup", "image": "x"}]
    paths = {i.path for i in detect(DEPLOYMENT, obj)}
    assert "spec.template.spec.hostNetwork" in paths
    assert "spec.template.spec.initContainers[setup]" in paths


def test_missing_named_item_and_missing_key() -> None:
    obj = live()
    obj["spec"]["template"]["spec"]["containers"][0]["env"] = []
    del obj["spec"]["replicas"]
    changes = {(i.path, i.change) for i in detect(DEPLOYMENT, obj)}
    assert ("spec.replicas", "missing") in changes
    assert ("spec.template.spec.containers[agent].env[A]", "missing") in changes


def test_omitted_empty_collections_match() -> None:
    policy = {
        "kind": "NetworkPolicy",
        "metadata": {"name": "a"},
        "spec": {"policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []},
    }
    observed = {"metadata": {"name": "a"}, "spec": {"policyTypes": ["Ingress", "Egress"]}}
    assert detect(policy, observed) == []
    reopened = {
        "metadata": {"name": "a"},
        "spec": {"policyTypes": ["Ingress", "Egress"], "egress": [{"to": []}]},
    }
    [item] = detect(policy, reopened)
    assert item.path == "spec.egress"
    assert item.change == "changed"


def test_type_and_length_mismatches() -> None:
    assert diff({"a": 1}, "x", kind="K", name="n")[0].change == "changed"
    assert diff([1], {"a": 1}, kind="K", name="n")[0].change == "changed"
    assert diff([1, 2], [1], kind="K", name="n")[0].path == ""
    assert diff([1, 2], [1, 3], kind="K", name="n")[0].path == "[1]"


def test_configmap_data_is_strict() -> None:
    desired = {"kind": "ConfigMap", "metadata": {"name": "c"}, "data": {"a": "1"}}
    observed = {"metadata": {"name": "c"}, "data": {"a": "1", "injected": "2"}}
    [item] = detect(desired, observed)
    assert item.path == "data.injected"
    assert item.change == "unexpected"
