"""Render the Kubernetes objects that realise one deployment revision.

Every agent workload gets its own ServiceAccount (its workload identity),
a ConfigMap carrying the signed policy bundle and run contract, a
NetworkPolicy that denies everything not explicitly allowed, and a
Deployment with a hardened pod spec. A projected service-account token with
the identity fabric's audience is mounted so the agent can attest and obtain
short-lived credentials. When a kill switch covers the deployment the same
objects are rendered with zero replicas and a deny-all NetworkPolicy.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from agentic_core.domain.provenance import canonical_json, content_digest
from pydantic import BaseModel, ConfigDict

from agent_control_plane.domain.models import (
    AgentRecord,
    AgentVersion,
    DeploymentSpec,
    PolicyBundle,
    Revision,
    ToolVersion,
)
from agent_control_plane.domain.ports import Manifest

PREFIX = "acp.kogunlowo123.github.io"
SPEC_HASH = f"{PREFIX}/spec-hash"
GENERATION = f"{PREFIX}/generation"
BUNDLE_DIGEST = f"{PREFIX}/policy-bundle-digest"
KILL_SWITCH = f"{PREFIX}/kill-switch"
MANAGED_BY = "agent-control-plane"
WORKLOAD_TOKEN_PATH = "/var/run/secrets/acp/workload/token"  # noqa: S105  # nosec B105
# File path of the projected service-account token, not a credential.
RUNTIME_DIR = "/etc/acp"
SCRATCH_DIR = "/tmp"  # noqa: S108  # nosec B108
# Mount point of a per-pod, size-limited emptyDir; the root filesystem is read-only.
AGENT_PORT = 8080


class RenderContext(BaseModel):
    """Platform-wide values injected into every agent workload."""

    model_config = ConfigDict(frozen=True)

    control_plane_url: str
    fabric_url: str | None
    workload_audience: str
    platform_namespace: str
    token_ttl_s: int = 3600


def selector_labels(spec: DeploymentSpec) -> dict[str, str]:
    return {
        "app.kubernetes.io/name": spec.agent_name,
        "app.kubernetes.io/instance": spec.name,
    }


def _labels(spec: DeploymentSpec, version: str) -> dict[str, str]:
    return {
        **selector_labels(spec),
        "app.kubernetes.io/version": version,
        "app.kubernetes.io/component": "agent",
        "app.kubernetes.io/part-of": spec.agent_namespace,
        "app.kubernetes.io/managed-by": MANAGED_BY,
        f"{PREFIX}/environment": spec.environment.value,
    }


def run_contract(
    spec: DeploymentSpec,
    agent: AgentRecord,
    version: AgentVersion,
    tools: Sequence[ToolVersion],
) -> dict[str, Any]:
    return {
        "deployment": spec.name,
        "agent": agent.key,
        "version": version.version,
        "framework": version.framework.value,
        "entrypoint": version.entrypoint,
        "identity": spec.identity_uri,
        "scopes": sorted(version.scopes),
        "max_classification": int(agent.max_classification),
        "risk": int(agent.risk),
        "disallowed_actions": list(agent.disallowed_actions),
        "tools": [
            {
                "name": t.name,
                "version": t.version,
                "endpoint": t.endpoint,
                "schema_digest": t.schema_digest,
            }
            for t in sorted(tools, key=lambda t: t.key)
        ],
    }


def render(
    spec: DeploymentSpec,
    *,
    revision: Revision,
    agent: AgentRecord,
    version: AgentVersion,
    tools: Sequence[ToolVersion],
    bundle: PolicyBundle,
    context: RenderContext,
    killed_by: Sequence[str] = (),
) -> list[Manifest]:
    killed = bool(killed_by)
    labels = _labels(spec, version.version)
    annotations = {GENERATION: str(revision.generation)}
    if killed:
        annotations[KILL_SWITCH] = ",".join(sorted(killed_by))

    def meta(name: str, extra: dict[str, str] | None = None) -> dict[str, Any]:
        return {
            "name": name,
            "namespace": spec.namespace,
            "labels": dict(labels),
            "annotations": {**annotations, **(extra or {})},
        }

    service_account: Manifest = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": meta(spec.name, dict(revision.service_account_annotations)),
        "automountServiceAccountToken": False,
    }

    bundle_document = {
        **bundle.signed_payload(),
        "digest": bundle.digest,
        "signature": bundle.signature,
        "key_id": bundle.key_id,
    }
    config_map: Manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": meta(f"{spec.name}-runtime", {BUNDLE_DIGEST: bundle.digest}),
        "data": {
            "policy-bundle.json": json.dumps(bundle_document, sort_keys=True, indent=2),
            "run-contract.json": json.dumps(
                run_contract(spec, agent, version, tools), sort_keys=True, indent=2
            ),
        },
    }

    network_policy: Manifest = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": meta(spec.name),
        "spec": {
            "podSelector": {"matchLabels": selector_labels(spec)},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [] if killed else _ingress(revision),
            "egress": [] if killed else _egress(version, context),
        },
    }

    deployment: Manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta(spec.name),
        "spec": {
            "replicas": 0 if killed else revision.replicas,
            "revisionHistoryLimit": 5,
            "selector": {"matchLabels": selector_labels(spec)},
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0},
            },
            "template": {
                "metadata": {
                    "labels": dict(labels),
                    "annotations": {
                        BUNDLE_DIGEST: bundle.digest,
                        GENERATION: str(revision.generation),
                    },
                },
                "spec": _pod_spec(spec, revision, agent, version, context),
            },
        },
    }

    objects = [service_account, config_map, network_policy, deployment]
    digest = spec_hash(objects)
    for obj in objects:
        obj["metadata"]["annotations"][SPEC_HASH] = digest
    return objects


def spec_hash(objects: Sequence[Manifest]) -> str:
    return content_digest(canonical_json(list(objects)))


def rendered_hash(objects: Sequence[Manifest]) -> str:
    """The spec hash stamped on rendered objects by ``render``."""
    return str(objects[0]["metadata"]["annotations"][SPEC_HASH])


def _ingress(revision: Revision) -> list[dict[str, Any]]:
    if not revision.ingress_namespaces:
        return []
    return [
        {
            "from": [
                {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}}
                for ns in sorted(revision.ingress_namespaces)
            ],
            "ports": [{"port": AGENT_PORT, "protocol": "TCP"}],
        }
    ]


def _egress(version: AgentVersion, context: RenderContext) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                    },
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                }
            ],
            "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
        },
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": context.platform_namespace}
                    }
                }
            ],
            "ports": [{"port": 8080, "protocol": "TCP"}, {"port": 443, "protocol": "TCP"}],
        },
    ]
    for rule in version.egress:
        rules.append(
            {
                "to": [{"ipBlock": {"cidr": rule.cidr}}],
                "ports": [{"port": p, "protocol": rule.protocol} for p in rule.ports],
            }
        )
    return rules


def _pod_spec(
    spec: DeploymentSpec,
    revision: Revision,
    agent: AgentRecord,
    version: AgentVersion,
    context: RenderContext,
) -> dict[str, Any]:
    platform_env = {
        "ACP_DEPLOYMENT": spec.name,
        "ACP_AGENT": agent.key,
        "ACP_AGENT_VERSION": version.version,
        "ACP_FRAMEWORK": version.framework.value,
        "ACP_ENTRYPOINT": version.entrypoint,
        "ACP_CONTROL_PLANE_URL": context.control_plane_url,
        "ACP_WORKLOAD_TOKEN_FILE": WORKLOAD_TOKEN_PATH,
        "ACP_POLICY_BUNDLE_FILE": f"{RUNTIME_DIR}/policy-bundle.json",
        "ACP_RUN_CONTRACT_FILE": f"{RUNTIME_DIR}/run-contract.json",
    }
    if spec.identity_uri:
        platform_env["ACP_IDENTITY_URI"] = spec.identity_uri
    if context.fabric_url:
        platform_env["ACP_FABRIC_URL"] = context.fabric_url
    env = [{"name": k, "value": v} for k, v in sorted(platform_env.items())]
    env += [{"name": k, "value": v} for k, v in sorted(revision.env.items())]

    container: dict[str, Any] = {
        "name": "agent",
        "image": version.image.reference,
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"name": "http", "containerPort": AGENT_PORT, "protocol": "TCP"}],
        "env": env,
        "resources": {
            "requests": {
                "cpu": version.resources.cpu_request,
                "memory": version.resources.memory_request,
            },
            "limits": {
                "cpu": version.resources.cpu_limit,
                "memory": version.resources.memory_limit,
            },
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "privileged": False,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [
            {
                "name": "workload-token",
                "mountPath": "/var/run/secrets/acp/workload",
                "readOnly": True,
            },
            {"name": "runtime", "mountPath": RUNTIME_DIR, "readOnly": True},
            {"name": "tmp", "mountPath": SCRATCH_DIR},
        ],
    }
    if version.health_path:
        probe = {"httpGet": {"path": version.health_path, "port": "http"}, "periodSeconds": 10}
        container["readinessProbe"] = probe
        container["livenessProbe"] = {**probe, "periodSeconds": 20}

    return {
        "serviceAccountName": spec.name,
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "fsGroup": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [container],
        "volumes": [
            {
                "name": "workload-token",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "audience": context.workload_audience,
                                "expirationSeconds": context.token_ttl_s,
                                "path": "token",
                            }
                        }
                    ]
                },
            },
            {"name": "runtime", "configMap": {"name": f"{spec.name}-runtime"}},
            {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
        ],
    }
