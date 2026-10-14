"""Rendered Kubernetes objects: hardened, identity-bound, deny-by-default, killable."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from agentic_core.domain.classification import DataClassification, RiskLevel

from agent_control_plane.domain.models import (
    AgentRecord,
    AgentVersion,
    BundleRef,
    DeploymentSpec,
    DeploymentState,
    Environment,
    Owners,
    PolicyBundle,
    Revision,
    ToolVersion,
)
from agent_control_plane.orchestration.manifests import (
    BUNDLE_DIGEST,
    KILL_SWITCH,
    SPEC_HASH,
    WORKLOAD_TOKEN_PATH,
    RenderContext,
    render,
    rendered_hash,
)
from tests.conftest import BUNDLE_POLICY, TOOL_SCHEMA, version_command

NOW = datetime(2026, 10, 14, tzinfo=UTC)
CONTEXT = RenderContext(
    control_plane_url="https://acp.corp.test",
    fabric_url="https://identity.corp.test",
    workload_audience="identity-fabric",
    platform_namespace="agent-platform",
)


def inputs(health: str | None = "/healthz") -> dict[str, object]:
    agent = AgentRecord(
        namespace="claims",
        name="claims-triage",
        display_name="Claims triage",
        mission="Triage incoming insurance claims for adjusters.",
        owners=Owners(business="claims-ops", technical="claims-eng", escalation_contact="oncall"),
        risk=RiskLevel.MODERATE,
        max_classification=DataClassification.CONFIDENTIAL,
        created_by="dev",
        created_at=NOW,
        updated_at=NOW,
    )
    version = AgentVersion(
        namespace="claims",
        name="claims-triage",
        created_by="dev",
        created_at=NOW,
        updated_at=NOW,
        **{**version_command().model_dump(), "health_path": health},
    )
    tool = ToolVersion(
        name="claims.search",
        version="1.0.0",
        description="Search claims by identifier.",
        owner="claims-eng",
        risk=RiskLevel.LOW,
        endpoint="https://mcp.claims.corp.test/mcp/",
        input_schema=TOOL_SCHEMA,
        schema_digest=ToolVersion.digest_of(TOOL_SCHEMA),
        created_by="dev",
        created_at=NOW,
        updated_at=NOW,
    )
    bundle = PolicyBundle(
        name="claims-policy",
        version="1.0.0",
        policies=(BUNDLE_POLICY,),
        digest="sha256:" + "d" * 64,
        signature="sig",
        key_id="bundle-1",
        published_by="policy",
        published_at=NOW,
    )
    revision = Revision(
        generation=3,
        version="1.0.0",
        replicas=2,
        policy_bundle=BundleRef(name="claims-policy", version="1.0.0"),
        ingress_namespaces=("agent-gateway",),
        env={"CLAIMS_REGION": "us-east-1"},
        service_account_annotations={"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/x"},
        created_by="deployer",
        created_at=NOW,
    )
    spec = DeploymentSpec(
        name="claims-triage-prod",
        agent_namespace="claims",
        agent_name="claims-triage",
        environment=Environment.PRODUCTION,
        namespace="agents-prod",
        state=DeploymentState.ACTIVE,
        current=revision,
        identity_uri="spiffe://agents.corp.test/agent/claims/claims-triage-prod-1.0.0",
        created_at=NOW,
        updated_at=NOW,
    )
    return {
        "spec": spec,
        "revision": revision,
        "agent": agent,
        "version": version,
        "tools": [tool],
        "bundle": bundle,
        "context": CONTEXT,
    }


def objects(killed: tuple[str, ...] = (), health: str | None = "/healthz") -> dict[str, dict]:
    rendered = render(**inputs(health), killed_by=killed)  # type: ignore[arg-type]
    return {o["kind"]: o for o in rendered}


def test_pod_is_hardened_and_identity_bound() -> None:
    deployment = objects()["Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["image"] == "ghcr.io/corp/claims-triage@sha256:" + "b" * 64
    assert pod["automountServiceAccountToken"] is False
    assert pod["serviceAccountName"] == "claims-triage-prod"
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "privileged": False,
        "capabilities": {"drop": ["ALL"]},
    }
    token = pod["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"]
    assert token == {"audience": "identity-fabric", "expirationSeconds": 3600, "path": "token"}
    env = {e["name"]: e["value"] for e in container["env"]}
    assert env["ACP_WORKLOAD_TOKEN_FILE"] == WORKLOAD_TOKEN_PATH
    assert env["ACP_IDENTITY_URI"].endswith("claims-triage-prod-1.0.0")
    assert env["ACP_FABRIC_URL"] == "https://identity.corp.test"
    assert env["CLAIMS_REGION"] == "us-east-1"
    assert container["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert deployment["spec"]["template"]["metadata"]["annotations"][BUNDLE_DIGEST].startswith(
        "sha256:"
    )


def test_probes_are_optional() -> None:
    container = objects(health=None)["Deployment"]["spec"]["template"]["spec"]["containers"][0]
    assert "readinessProbe" not in container


def test_network_policy_is_deny_by_default_with_declared_egress() -> None:
    spec = objects()["NetworkPolicy"]["spec"]
    assert spec["policyTypes"] == ["Ingress", "Egress"]
    assert spec["ingress"][0]["from"] == [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "agent-gateway"}}}
    ]
    blocks = [peer for rule in spec["egress"] for peer in rule["to"] if "ipBlock" in peer]
    assert blocks == [{"ipBlock": {"cidr": "10.40.0.0/16"}}]


def test_runtime_config_carries_signed_bundle_and_contract() -> None:
    data = objects()["ConfigMap"]["data"]
    bundle = json.loads(data["policy-bundle.json"])
    contract = json.loads(data["run-contract.json"])
    assert bundle["signature"] == "sig"
    assert bundle["policies"][0]["name"] == "claims-agent"
    assert contract["tools"][0]["schema_digest"].startswith("sha256:")
    assert contract["framework"] == "langgraph"
    assert contract["identity"].startswith("spiffe://")


def test_killed_variant_stops_everything() -> None:
    killed = objects(killed=("k1", "k2"))
    assert killed["Deployment"]["spec"]["replicas"] == 0
    assert killed["NetworkPolicy"]["spec"]["ingress"] == []
    assert killed["NetworkPolicy"]["spec"]["egress"] == []
    assert killed["Deployment"]["metadata"]["annotations"][KILL_SWITCH] == "k1,k2"


def test_spec_hash_is_deterministic_and_sensitive() -> None:
    first = render(**inputs())  # type: ignore[arg-type]
    second = render(**inputs())  # type: ignore[arg-type]
    killed = render(**inputs(), killed_by=("k",))  # type: ignore[arg-type]
    assert rendered_hash(first) == rendered_hash(second)
    assert rendered_hash(first) != rendered_hash(killed)
    assert {o["metadata"]["annotations"][SPEC_HASH] for o in first} == {rendered_hash(first)}
