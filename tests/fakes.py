"""In-process stand-ins for external systems, speaking their real wire formats.

FakeKubeApiServer replaces the urllib3 connection pool of a genuine
``kubernetes.client.ApiClient``, so the official client builds URLs,
serializes bodies and raises ``ApiException`` exactly as against a cluster.
It applies server-side defaults and ``omitempty`` the way the API server
does, tracks resourceVersion for optimistic concurrency, and reports
Deployment status.

FakeFabric answers agent-identity-fabric's HTTP contract (and the IdP's
client-credentials token endpoint) through ``httpx.MockTransport``.
"""

from __future__ import annotations

import base64
import copy
import fnmatch
import itertools
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import jwt
import urllib3
from cryptography.hazmat.primitives.asymmetric import ec
from kubernetes.client import ApiClient, Configuration

from agent_control_plane.infrastructure.kubernetes import KubernetesCluster

# ------------------------------------------------------------------- identity


@dataclass
class FakeIdp:
    """Minimal OIDC issuer: ES256 keypair plus JWKS."""

    issuer: str
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


# ----------------------------------------------------------------- kubernetes

PATHS = {
    "Deployment": ("/apis/apps/v1", "deployments"),
    "ServiceAccount": ("/api/v1", "serviceaccounts"),
    "ConfigMap": ("/api/v1", "configmaps"),
    "NetworkPolicy": ("/apis/networking.k8s.io/v1", "networkpolicies"),
}
KIND_BY_PLURAL = {plural: kind for kind, (_, plural) in PATHS.items()}
ROUTE = re.compile(
    r"^(?P<group>/api/v1|/apis/[a-z0-9.]+/v1)/namespaces/(?P<ns>[^/]+)/(?P<plural>[a-z]+)(?:/(?P<name>[^/]+))?$"
)


class FakeHTTPResponse:
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status = status
        self.reason = {200: "OK", 201: "Created", 404: "Not Found", 409: "Conflict"}.get(
            status, "Error"
        )
        self.data = json.dumps(body).encode()
        self.headers = {"content-type": "application/json"}

    def getheaders(self) -> dict[str, str]:
        return self.headers

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)


def _status(code: int, reason: str, message: str) -> dict[str, Any]:
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code,
    }


def _prune_empty(spec: dict[str, Any], keys: tuple[str, ...]) -> None:
    for key in keys:
        if spec.get(key) in ([], {}):
            del spec[key]


class FakeKubeApiServer:
    """The four namespaced resources the control plane manages, with API-server semantics."""

    def __init__(self, *, auto_ready: bool = True) -> None:
        self.objects: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.requests: list[tuple[str, str]] = []
        self.auto_ready = auto_ready
        self.down = False
        self.fail_next: list[tuple[str, str, int]] = []  # (method, kind, status)
        self._versions = itertools.count(1000)

    # urllib3.PoolManager interface used by kubernetes.client.rest
    def request(self, method: str, url: str, **kwargs: Any) -> FakeHTTPResponse:
        if self.down:
            raise urllib3.exceptions.ProtocolError("connection refused by fake API server")
        parsed = urlparse(url)
        self.requests.append((method, parsed.path))
        if parsed.path.rstrip("/") == "/version":
            return FakeHTTPResponse(200, {"major": "1", "minor": "31", "gitVersion": "v1.31.2"})
        match = ROUTE.match(parsed.path)
        if not match or match["plural"] not in KIND_BY_PLURAL:
            return FakeHTTPResponse(404, _status(404, "NotFound", "unknown path"))
        kind = KIND_BY_PLURAL[match["plural"]]
        for index, (m, k, code) in enumerate(self.fail_next):
            if m == method and k == kind:
                del self.fail_next[index]
                return FakeHTTPResponse(code, _status(code, "InternalError", "injected"))
        ns, name = match["ns"], unquote(match["name"]) if match["name"] else None
        body = json.loads(kwargs["body"]) if kwargs.get("body") else None
        handler = getattr(self, f"_{method.lower()}")
        response: FakeHTTPResponse = handler(kind, ns, name, body, parse_qs(parsed.query))
        return response

    def clear(self) -> None:
        """PoolManager.clear(), called by ApiClient.close()."""

    def _get(self, kind: str, ns: str, name: str | None, *_: Any) -> FakeHTTPResponse:
        obj = self.objects.get((kind, ns, name or ""))
        if obj is None:
            return FakeHTTPResponse(404, _status(404, "NotFound", f"{kind} {name} not found"))
        return FakeHTTPResponse(200, obj)

    def _post(
        self, kind: str, ns: str, _: str | None, body: dict[str, Any], *__: Any
    ) -> FakeHTTPResponse:
        name = body["metadata"]["name"]
        if (kind, ns, name) in self.objects:
            return FakeHTTPResponse(409, _status(409, "AlreadyExists", f"{name} exists"))
        stored = self._store(kind, ns, name, body, generation=1)
        return FakeHTTPResponse(201, stored)

    def _put(
        self, kind: str, ns: str, name: str | None, body: dict[str, Any], *_: Any
    ) -> FakeHTTPResponse:
        current = self.objects.get((kind, ns, name or ""))
        if current is None:
            return FakeHTTPResponse(404, _status(404, "NotFound", f"{name} not found"))
        if body["metadata"].get("resourceVersion") != current["metadata"]["resourceVersion"]:
            return FakeHTTPResponse(409, _status(409, "Conflict", "object has been modified"))
        generation = current["metadata"].get("generation", 1) + 1
        stored = self._store(kind, ns, name or "", body, generation=generation)
        return FakeHTTPResponse(200, stored)

    def _delete(self, kind: str, ns: str, name: str | None, *_: Any) -> FakeHTTPResponse:
        obj = self.objects.pop((kind, ns, name or ""), None)
        if obj is None:
            return FakeHTTPResponse(404, _status(404, "NotFound", f"{name} not found"))
        return FakeHTTPResponse(200, {"kind": "Status", "apiVersion": "v1", "status": "Success"})

    def _store(
        self, kind: str, ns: str, name: str, body: dict[str, Any], *, generation: int
    ) -> dict[str, Any]:
        obj = copy.deepcopy(body)
        meta = obj.setdefault("metadata", {})
        meta.update(
            {
                "namespace": ns,
                "uid": f"uid-{kind.lower()}-{name}",
                "resourceVersion": str(next(self._versions)),
                "creationTimestamp": "2026-10-14T00:00:00Z",
                "generation": generation,
            }
        )
        meta.setdefault("annotations", {})
        if kind == "Deployment":
            self._default_deployment(obj)
        if kind == "NetworkPolicy":
            _prune_empty(obj["spec"], ("ingress", "egress"))
        if kind == "ConfigMap":
            obj.pop("status", None)
        self.objects[(kind, ns, name)] = obj
        return obj

    def _default_deployment(self, obj: dict[str, Any]) -> None:
        spec = obj["spec"]
        spec.setdefault("progressDeadlineSeconds", 600)
        pod = spec["template"]["spec"]
        pod.setdefault("dnsPolicy", "ClusterFirst")
        pod.setdefault("restartPolicy", "Always")
        pod.setdefault("schedulerName", "default-scheduler")
        pod.setdefault("terminationGracePeriodSeconds", 30)
        for container in pod.get("containers", []):
            container.setdefault("terminationMessagePath", "/dev/termination-log")
            container.setdefault("terminationMessagePolicy", "File")
        for volume in pod.get("volumes", []):
            for source in ("configMap", "projected"):
                if source in volume:
                    volume[source].setdefault("defaultMode", 420)
        replicas = spec.get("replicas", 1)
        status: dict[str, Any] = {"observedGeneration": obj["metadata"]["generation"]}
        if replicas:
            status["replicas"] = replicas
            if self.auto_ready:
                status["readyReplicas"] = replicas
                status["availableReplicas"] = replicas
        obj["status"] = status

    # helpers for tests -------------------------------------------------------

    def get(self, kind: str, ns: str, name: str) -> dict[str, Any] | None:
        return self.objects.get((kind, ns, name))

    def tamper(self, kind: str, ns: str, name: str, mutate: Any) -> None:
        """An out-of-band edit (kubectl edit): mutate in place, bump resourceVersion."""
        obj = self.objects[(kind, ns, name)]
        mutate(obj)
        obj["metadata"]["resourceVersion"] = str(next(self._versions))

    def mark_ready(self, ns: str, name: str) -> None:
        obj = self.objects[("Deployment", ns, name)]
        replicas = obj["spec"].get("replicas", 1)
        obj["status"]["readyReplicas"] = replicas


def make_cluster(server: FakeKubeApiServer) -> KubernetesCluster:
    api = ApiClient(Configuration(host="https://k8s.test"))
    api.rest_client.pool_manager = server
    return KubernetesCluster(api, request_timeout_s=5.0)


# ------------------------------------------------------------- identity fabric

FABRIC = "https://identity.corp.test"
TRUST_DOMAIN = "agents.corp.test"
IDP_TOKEN_URL = "https://login.corp.test/oauth2/v2.0/token"
ADMIN_CLIENT = ("acp-control-plane", "client-secret-for-tests")


@dataclass
class FakeFabric:
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    tokens: dict[str, tuple[str, frozenset[str]]] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    admin_tokens_issued: int = 0
    down: bool = False
    fail_status: dict[str, int] = field(default_factory=dict)  # path prefix -> status

    def grant(self, token: str, subject: str, *scopes: str) -> None:
        """Make ``token`` a valid credential for an active agent ``subject`` with ``scopes``."""
        self.tokens[token] = (subject, frozenset(scopes))
        self.agents.setdefault(subject, {"agent_id": subject, "status": "active"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        self.calls.append((request.method, url.path))
        if self.down:
            raise httpx.ConnectError("fabric unreachable", request=request)
        for prefix, status in self.fail_status.items():
            if url.path.startswith(prefix):
                return httpx.Response(status, json={"error": "server_error"})
        if str(url).startswith(IDP_TOKEN_URL):
            return self._client_credentials(request)
        routes = {
            ("POST", "/v1/agents"): self._register,
            ("POST", "/v1/suspend"): self._suspend,
            ("POST", "/v1/reinstate"): self._reinstate,
            ("POST", "/v1/revoke-agent"): self._revoke,
            ("POST", "/oauth2/token"): self._token,
            ("POST", "/v1/authorize"): self._authorize,
            ("POST", "/oauth2/introspect"): self._introspect,
        }
        handler = routes.get((request.method, url.path))
        if handler is not None:
            return handler(request)
        if request.method == "GET" and url.path.startswith("/v1/agents/"):
            return self._get_agent(request)
        return httpx.Response(404, json={"error": "not_found", "error_description": "no route"})

    def _client_credentials(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        expected = "Basic " + base64.b64encode(":".join(ADMIN_CLIENT).encode()).decode()
        if (
            form.get("grant_type") != ["client_credentials"]
            or request.headers.get("authorization") != expected
        ):
            return httpx.Response(401, json={"error": "invalid_client"})
        self.admin_tokens_issued += 1
        return httpx.Response(
            200,
            json={
                "access_token": f"admin-token-{self.admin_tokens_issued}",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )

    def _admin(self, request: httpx.Request) -> httpx.Response | None:
        if not request.headers.get("authorization", "").startswith("Bearer admin-token-"):
            return httpx.Response(401, json={"error": "unauthorized", "error_description": "admin"})
        return None

    def _register(self, request: httpx.Request) -> httpx.Response:
        if (denied := self._admin(request)) is not None:
            return denied
        body = json.loads(request.content)
        uri = f"spiffe://{TRUST_DOMAIN}/agent/{body['namespace']}/{body['name']}"
        if uri in self.agents:
            return httpx.Response(
                409, json={"error": "conflict", "error_description": f"agent {uri} exists"}
            )
        self.agents[uri] = {"agent_id": uri, "status": "pending", "registration": body}
        return httpx.Response(201, json={"agent_id": uri, "status": "pending", **body})

    def _get_agent(self, request: httpx.Request) -> httpx.Response:
        if (denied := self._admin(request)) is not None:
            return denied
        uri = unquote(request.url.path[len("/v1/agents/") :])
        agent = self.agents.get(uri)
        if agent is None:
            return httpx.Response(404, json={"error": "not_found", "error_description": uri})
        return httpx.Response(200, json={"agent_id": uri, "status": agent["status"]})

    def _transition(self, request: httpx.Request, allowed: set[str], target: str) -> httpx.Response:
        if (denied := self._admin(request)) is not None:
            return denied
        uri = request.url.params.get("agent_uri", "")
        agent = self.agents.get(uri)
        if agent is None:
            return httpx.Response(404, json={"error": "not_found", "error_description": uri})
        if agent["status"] not in allowed:
            return httpx.Response(
                409,
                json={"error": "invalid_state", "error_description": f"{uri} is {agent['status']}"},
            )
        agent["status"] = target
        return httpx.Response(200, json={"agent_id": uri, "status": target})

    def _suspend(self, request: httpx.Request) -> httpx.Response:
        return self._transition(request, {"active"}, "suspended")

    def _reinstate(self, request: httpx.Request) -> httpx.Response:
        return self._transition(request, {"suspended"}, "active")

    def _revoke(self, request: httpx.Request) -> httpx.Response:
        return self._transition(request, {"pending", "active", "suspended"}, "revoked")

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        client = form.get("client_id", "")
        agent = self.agents.get(client)
        if form.get("assertion") != f"workload-token-for:{client}" or agent is None:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "no"})
        if agent["status"] == "pending":
            agent["status"] = "active"  # first credential after attestation
        if agent["status"] != "active":
            return httpx.Response(
                400, json={"error": "invalid_grant", "error_description": agent["status"]}
            )
        token = f"agent-credential-{len(self.tokens) + 1}"
        scopes = agent.get("registration", {}).get("scopes", [])
        self.tokens[token] = (client, frozenset(scopes))
        return httpx.Response(
            200,
            json={
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 600,
                "scope": " ".join(scopes),
                "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
            },
        )

    def _bearer_subject(self, request: httpx.Request) -> tuple[str, frozenset[str]] | None:
        auth = request.headers.get("authorization", "")
        entry = self.tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
        if entry is None or self.agents.get(entry[0], {}).get("status") != "active":
            return None
        return entry

    def _authorize(self, request: httpx.Request) -> httpx.Response:
        entry = self._bearer_subject(request)
        if entry is None:
            return httpx.Response(
                401,
                json={"error": "unauthorized", "error_description": "token invalid"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        subject, scopes = entry
        body = json.loads(request.content)
        allowed = any(fnmatch.fnmatchcase(body["action"], s) for s in scopes)
        return httpx.Response(
            200,
            json={
                "decision": "allow" if allowed else "deny",
                "agent": subject,
                "action": body["action"],
                "resource": f"{body['resource_type']}:{body['resource_id']}",
                "matched_rules": ["allow-scoped-actions"] if allowed else [],
                "policy_version": "2026.10.0",
                "policy_digest": "sha256:" + "f" * 64,
                "reason": "explicit allow" if allowed else "no matching allow rule (default deny)",
                "delegation_chain": [],
            },
        )

    def _introspect(self, request: httpx.Request) -> httpx.Response:
        token = parse_qs(request.content.decode()).get("token", [""])[0]
        entry = self.tokens.get(token)
        if entry is None:
            return httpx.Response(200, json={"active": False})
        return httpx.Response(
            200, json={"active": True, "sub": entry[0], "scope": " ".join(sorted(entry[1]))}
        )
