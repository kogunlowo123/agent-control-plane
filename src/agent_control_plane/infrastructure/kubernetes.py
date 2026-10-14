"""ClusterGateway backed by the official Kubernetes Python client.

The client is synchronous; every call runs in a worker thread. Reads use
``_preload_content=False`` so the reconciler compares the exact wire JSON the
API server returned rather than a lossy model round trip. Writes send plain
dict bodies, which the client serializes unchanged.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any, Literal

from kubernetes import client, config
from kubernetes.client import ApiClient, ApiException

from agent_control_plane.domain.errors import ConflictError, DependencyError
from agent_control_plane.domain.ports import Manifest

FIELD_MANAGER = "agent-control-plane"
MANAGED_KINDS = ("ServiceAccount", "ConfigMap", "NetworkPolicy", "Deployment")


def load_api_client(
    mode: Literal["in-cluster", "kubeconfig"], kubeconfig_path: str | None = None
) -> ApiClient:
    configuration = client.Configuration()
    # The config loaders and ApiClient.close carry no annotations upstream.
    if mode == "in-cluster":
        config.load_incluster_config(  # type: ignore[no-untyped-call]
            client_configuration=configuration
        )
    else:
        config.load_kube_config(  # type: ignore[no-untyped-call]
            config_file=kubeconfig_path, client_configuration=configuration
        )
    return ApiClient(configuration)


class KubernetesCluster:
    def __init__(self, api_client: ApiClient, *, request_timeout_s: float = 10.0) -> None:
        self._api_client = api_client
        self._core = client.CoreV1Api(api_client)
        self._apps = client.AppsV1Api(api_client)
        self._net = client.NetworkingV1Api(api_client)
        self._timeout = request_timeout_s

    # Operation tables keep kind dispatch in one place.
    def _readers(self) -> dict[str, Callable[..., Any]]:
        return {
            "ServiceAccount": self._core.read_namespaced_service_account,
            "ConfigMap": self._core.read_namespaced_config_map,
            "NetworkPolicy": self._net.read_namespaced_network_policy,
            "Deployment": self._apps.read_namespaced_deployment,
        }

    def _creators(self) -> dict[str, Callable[..., Any]]:
        return {
            "ServiceAccount": self._core.create_namespaced_service_account,
            "ConfigMap": self._core.create_namespaced_config_map,
            "NetworkPolicy": self._net.create_namespaced_network_policy,
            "Deployment": self._apps.create_namespaced_deployment,
        }

    def _replacers(self) -> dict[str, Callable[..., Any]]:
        return {
            "ServiceAccount": self._core.replace_namespaced_service_account,
            "ConfigMap": self._core.replace_namespaced_config_map,
            "NetworkPolicy": self._net.replace_namespaced_network_policy,
            "Deployment": self._apps.replace_namespaced_deployment,
        }

    def _deleters(self) -> dict[str, Callable[..., Any]]:
        return {
            "ServiceAccount": self._core.delete_namespaced_service_account,
            "ConfigMap": self._core.delete_namespaced_config_map,
            "NetworkPolicy": self._net.delete_namespaced_network_policy,
            "Deployment": self._apps.delete_namespaced_deployment,
        }

    @staticmethod
    def _kind(kind: str) -> str:
        if kind not in MANAGED_KINDS:
            raise ValueError(f"unsupported kind {kind}")
        return kind

    async def _call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Manifest:
        def run() -> Manifest:
            response = fn(*args, _preload_content=False, _request_timeout=self._timeout, **kwargs)
            data: Manifest = json.loads(response.data or b"{}")
            return data

        try:
            return await asyncio.to_thread(run)
        except ApiException as exc:
            if exc.status == 409:
                raise ConflictError(f"kubernetes conflict: {exc.reason}") from exc
            raise
        except Exception as exc:  # urllib3 connection/timeouts, TLS, DNS
            raise DependencyError(f"kubernetes API unavailable: {type(exc).__name__}") from exc

    async def read(self, kind: str, namespace: str, name: str) -> Manifest | None:
        try:
            return await self._call(self._readers()[self._kind(kind)], name, namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise DependencyError(f"kubernetes read {kind} failed: {exc.status}") from exc

    async def create(self, manifest: Manifest) -> Manifest:
        kind = self._kind(manifest["kind"])
        try:
            return await self._call(
                self._creators()[kind],
                manifest["metadata"]["namespace"],
                manifest,
                field_manager=FIELD_MANAGER,
            )
        except ApiException as exc:
            raise DependencyError(f"kubernetes create {kind} failed: {exc.status}") from exc

    async def replace(self, manifest: Manifest, resource_version: str) -> Manifest:
        kind = self._kind(manifest["kind"])
        body = json.loads(json.dumps(manifest))
        body["metadata"]["resourceVersion"] = resource_version
        try:
            return await self._call(
                self._replacers()[kind],
                body["metadata"]["name"],
                body["metadata"]["namespace"],
                body,
                field_manager=FIELD_MANAGER,
            )
        except ApiException as exc:
            raise DependencyError(f"kubernetes replace {kind} failed: {exc.status}") from exc

    async def delete(self, kind: str, namespace: str, name: str) -> bool:
        try:
            await self._call(
                self._deleters()[self._kind(kind)],
                name,
                namespace,
                propagation_policy="Foreground",
            )
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise DependencyError(f"kubernetes delete {kind} failed: {exc.status}") from exc
        return True

    async def ping(self) -> bool:
        def run() -> bool:
            client.VersionApi(self._api_client).get_code(
                _preload_content=False, _request_timeout=self._timeout
            )
            return True

        try:
            return await asyncio.to_thread(run)
        except Exception:
            return False

    def close(self) -> None:
        self._api_client.close()  # type: ignore[no-untyped-call]
