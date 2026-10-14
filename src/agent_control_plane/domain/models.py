"""Registry, deployment and kill-switch aggregates.

Lifecycle of a registered version (agents and tools alike)::

    draft -> in_review -> approved -> deprecated -> retired
       \\________^  (reject)    \\______________________^

Only approved versions may be deployed. Deprecated versions keep running
where they are deployed but cannot be newly deployed. Retired is terminal.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from agentic_core.domain.classification import DataClassification, RiskLevel
from agentic_core.domain.identifiers import Segment
from agentic_core.domain.provenance import canonical_json, content_digest
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from agent_control_plane.domain.errors import InvalidStateError

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9a-z][0-9a-z.\-]*)?$")
SCOPE = re.compile(r"^[a-z][a-z0-9_.\-]*(:[a-z0-9_.\-*]+)+$")
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_.\-]{1,63}$")
IMAGE_REPOSITORY = re.compile(r"^[a-z0-9]+([._\-/:][a-z0-9]+)*$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ENTRYPOINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
CPU = re.compile(r"^([1-9]\d{0,4}m|\d{1,3}(\.\d{1,3})?)$")
MEMORY = re.compile(r"^[1-9]\d{0,5}(Ki|Mi|Gi)$")
RESERVED_ENV_PREFIX = "ACP_"


def _semver(value: str) -> str:
    if not SEMVER.fullmatch(value):
        raise ValueError(f"{value!r} is not a semantic version (MAJOR.MINOR.PATCH[-pre])")
    return value


def _dns_label(value: str) -> str:
    if not DNS_LABEL.fullmatch(value):
        raise ValueError(f"{value!r} is not a DNS-1123 label")
    return value


def _scope(value: str) -> str:
    if not SCOPE.fullmatch(value):
        raise ValueError(f"invalid scope {value!r}; expected resource:action[:qualifier]")
    return value


SemVer = Annotated[str, Field(min_length=5, max_length=23), AfterValidator(_semver)]
DnsLabel = Annotated[str, Field(min_length=1, max_length=40), AfterValidator(_dns_label)]
Scope = Annotated[str, Field(max_length=200), AfterValidator(_scope)]


class Lifecycle(StrEnum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class LifecycleAction(StrEnum):
    SUBMIT = "submit"
    APPROVE = "approve"
    REJECT = "reject"
    DEPRECATE = "deprecate"
    RETIRE = "retire"


TRANSITIONS: dict[tuple[Lifecycle, LifecycleAction], Lifecycle] = {
    (Lifecycle.DRAFT, LifecycleAction.SUBMIT): Lifecycle.IN_REVIEW,
    (Lifecycle.DRAFT, LifecycleAction.RETIRE): Lifecycle.RETIRED,
    (Lifecycle.IN_REVIEW, LifecycleAction.APPROVE): Lifecycle.APPROVED,
    (Lifecycle.IN_REVIEW, LifecycleAction.REJECT): Lifecycle.DRAFT,
    (Lifecycle.APPROVED, LifecycleAction.DEPRECATE): Lifecycle.DEPRECATED,
    (Lifecycle.APPROVED, LifecycleAction.RETIRE): Lifecycle.RETIRED,
    (Lifecycle.DEPRECATED, LifecycleAction.RETIRE): Lifecycle.RETIRED,
}


def next_state(current: Lifecycle, action: LifecycleAction) -> Lifecycle:
    target = TRANSITIONS.get((current, action))
    if target is None:
        raise InvalidStateError(f"cannot {action.value} a version in state {current.value}")
    return target


class Framework(StrEnum):
    """Agent frameworks with a platform run-contract adapter (agent_control_plane.adapters)."""

    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    GOOGLE_ADK = "google_adk"
    MICROSOFT_AGENT_FRAMEWORK = "microsoft_agent_framework"
    AWS_STRANDS = "aws_strands"


class Environment(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Approval(BaseModel):
    model_config = ConfigDict(frozen=True)

    actor: str
    at: datetime
    comment: str = ""
    policy_digest: str = ""


class Owners(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    business: str = Field(min_length=3, max_length=200)
    technical: str = Field(min_length=3, max_length=200)
    escalation_contact: str = Field(min_length=3, max_length=200)


# ---------------------------------------------------------------------- agents


class AgentStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


class AgentRecord(BaseModel):
    """A logical agent: what it is for, who owns it, how risky it is."""

    model_config = ConfigDict(frozen=True)

    namespace: Segment
    name: Segment
    display_name: str = Field(min_length=3, max_length=120)
    mission: str = Field(min_length=10, max_length=2000)
    owners: Owners
    risk: RiskLevel
    max_classification: DataClassification
    disallowed_actions: tuple[str, ...] = ()
    status: AgentStatus = AgentStatus.ACTIVE
    created_by: str
    created_at: datetime
    updated_at: datetime

    @property
    def key(self) -> str:
        return f"{self.namespace}/{self.name}"


class ImageRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repository: str = Field(min_length=3, max_length=255, pattern=IMAGE_REPOSITORY.pattern)
    digest: str = Field(
        pattern=DIGEST.pattern, description="Pinned sha256 digest; tags are not accepted"
    )

    @property
    def reference(self) -> str:
        return f"{self.repository}@{self.digest}"


class ToolRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=TOOL_NAME.pattern)
    version: SemVer

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


class EgressRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cidr: str = Field(description="Destination network, e.g. 10.20.0.0/16")
    ports: tuple[int, ...] = Field(min_length=1, max_length=16)
    protocol: str = Field(default="TCP", pattern="^(TCP|UDP)$")

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, value: str) -> str:
        return str(ipaddress.ip_network(value, strict=True))

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(not 1 <= p <= 65535 for p in value):
            raise ValueError("ports must be within 1-65535")
        return tuple(sorted(set(value)))

    @property
    def unrestricted(self) -> bool:
        return ipaddress.ip_network(self.cidr).prefixlen == 0


class Resources(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cpu_request: str = Field(default="250m", pattern=CPU.pattern)
    cpu_limit: str = Field(default="1", pattern=CPU.pattern)
    memory_request: str = Field(default="256Mi", pattern=MEMORY.pattern)
    memory_limit: str = Field(default="512Mi", pattern=MEMORY.pattern)


class AgentVersion(BaseModel):
    """An immutable, reviewable build of an agent."""

    model_config = ConfigDict(frozen=True)

    namespace: Segment
    name: Segment
    version: SemVer
    framework: Framework
    entrypoint: str = Field(pattern=ENTRYPOINT.pattern, description="module:attribute of the agent")
    image: ImageRef
    tools: tuple[ToolRef, ...] = ()
    scopes: frozenset[Scope] = Field(min_length=1)
    egress: tuple[EgressRule, ...] = ()
    resources: Resources = Resources()
    health_path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9/_\-.]{0,100}$")
    release_notes: str = Field(default="", max_length=4000)
    state: Lifecycle = Lifecycle.DRAFT
    submitted_by: str | None = None
    approvals: tuple[Approval, ...] = ()
    created_by: str
    created_at: datetime
    updated_at: datetime

    @property
    def agent_key(self) -> str:
        return f"{self.namespace}/{self.name}"

    @property
    def key(self) -> str:
        return f"{self.namespace}/{self.name}@{self.version}"

    @property
    def unrestricted_egress(self) -> bool:
        return any(rule.unrestricted for rule in self.egress)

    def transition(
        self, action: LifecycleAction, *, actor: str, at: datetime, approval: Approval | None = None
    ) -> AgentVersion:
        update: dict[str, Any] = {"state": next_state(self.state, action), "updated_at": at}
        if action is LifecycleAction.SUBMIT:
            update["submitted_by"] = actor
            update["approvals"] = ()
        if action is LifecycleAction.REJECT:
            update["approvals"] = ()
        if approval is not None:
            update["approvals"] = (*self.approvals, approval)
        return self.model_copy(update=update)

    def with_approval(self, approval: Approval, *, at: datetime) -> AgentVersion:
        """Record an approval that does not yet complete the review."""
        if self.state is not Lifecycle.IN_REVIEW:
            raise InvalidStateError(f"version {self.key} is {self.state.value}, not in_review")
        return self.model_copy(update={"approvals": (*self.approvals, approval), "updated_at": at})


# ----------------------------------------------------------------------- tools


class ToolVersion(BaseModel):
    """A tool agents may call, pinned by the digest of its input schema."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=TOOL_NAME.pattern)
    version: SemVer
    description: str = Field(min_length=10, max_length=2000)
    owner: str = Field(min_length=3, max_length=200)
    risk: RiskLevel
    endpoint: str = Field(pattern=r"^https://[^\s]+$", description="MCP server URL (HTTPS)")
    input_schema: dict[str, Any]
    schema_digest: str
    state: Lifecycle = Lifecycle.DRAFT
    submitted_by: str | None = None
    approvals: tuple[Approval, ...] = ()
    created_by: str
    created_at: datetime
    updated_at: datetime

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    @staticmethod
    def digest_of(schema: dict[str, Any]) -> str:
        return content_digest(canonical_json(schema))

    def transition(
        self, action: LifecycleAction, *, actor: str, at: datetime, approval: Approval | None = None
    ) -> ToolVersion:
        update: dict[str, Any] = {"state": next_state(self.state, action), "updated_at": at}
        if action is LifecycleAction.SUBMIT:
            update["submitted_by"] = actor
            update["approvals"] = ()
        if action is LifecycleAction.REJECT:
            update["approvals"] = ()
        if approval is not None:
            update["approvals"] = (*self.approvals, approval)
        return self.model_copy(update=update)

    def with_approval(self, approval: Approval, *, at: datetime) -> ToolVersion:
        if self.state is not Lifecycle.IN_REVIEW:
            raise InvalidStateError(f"tool {self.key} is {self.state.value}, not in_review")
        return self.model_copy(update={"approvals": (*self.approvals, approval), "updated_at": at})


# --------------------------------------------------------------- policy bundles


class PolicyBundle(BaseModel):
    """Versioned, signed set of agentic-core policy sets distributed to agents."""

    model_config = ConfigDict(frozen=True)

    name: DnsLabel
    version: SemVer
    description: str = Field(default="", max_length=2000)
    policies: tuple[dict[str, Any], ...] = Field(min_length=1)
    digest: str
    signature: str
    key_id: str
    published_by: str
    published_at: datetime

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    def signed_payload(self) -> dict[str, Any]:
        """Fields covered by the digest and signature."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "policies": list(self.policies),
        }


class BundleRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: DnsLabel
    version: SemVer

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


# ------------------------------------------------------------------ deployments


class DeploymentState(StrEnum):
    PENDING_APPROVAL = "pending_approval"  # nothing running yet; first revision awaits approval
    ACTIVE = "active"  # a current revision is reconciled to the cluster
    DELETING = "deleting"  # objects are being removed
    DELETED = "deleted"  # terminal


class Revision(BaseModel):
    """One desired-state revision of a deployment."""

    model_config = ConfigDict(frozen=True)

    generation: int = Field(ge=1)
    version: SemVer
    replicas: int = Field(ge=0, le=50)
    policy_bundle: BundleRef
    ingress_namespaces: tuple[DnsLabel, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)
    service_account_annotations: dict[str, str] = Field(default_factory=dict)
    created_by: str
    created_at: datetime
    approvals: tuple[Approval, ...] = ()


class DeploymentSpec(BaseModel):
    """Desired state of one agent deployment in one Kubernetes namespace."""

    model_config = ConfigDict(frozen=True)

    name: DnsLabel
    agent_namespace: Segment
    agent_name: Segment
    environment: Environment
    namespace: DnsLabel = Field(description="Kubernetes namespace the agent runs in")
    state: DeploymentState
    current: Revision | None = None
    pending: Revision | None = None
    identity_uri: str | None = None
    superseded_identities: tuple[str, ...] = Field(
        default=(),
        description="Identities of replaced versions, revoked once the rollout is available",
    )
    created_at: datetime
    updated_at: datetime

    @property
    def agent_key(self) -> str:
        return f"{self.agent_namespace}/{self.agent_name}"

    @property
    def next_generation(self) -> int:
        generations = [r.generation for r in (self.current, self.pending) if r is not None]
        return max(generations, default=0) + 1

    def identity_name(self, version: str) -> str:
        """Identity fabric registration name: one immutable identity per deployed version."""
        return f"{self.name}-{version}"


class Phase(StrEnum):
    PENDING_APPROVAL = "PendingApproval"
    PROGRESSING = "Progressing"
    AVAILABLE = "Available"
    KILLED = "Killed"
    DEGRADED = "Degraded"
    DELETED = "Deleted"


class DriftItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str
    name: str
    path: str
    change: str = Field(description="missing | changed | unexpected | absent")
    expected: Any = None
    actual: Any = None


class DeploymentStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    phase: Phase
    observed_generation: int = 0
    desired_replicas: int = 0
    ready_replicas: int = 0
    killed_by: tuple[str, ...] = ()
    drift: tuple[DriftItem, ...] = ()
    corrected: bool = False
    spec_hash: str = ""
    message: str = ""
    reconciled_at: datetime


# ------------------------------------------------------------------ kill switch


class KillScope(StrEnum):
    GLOBAL = "global"
    AGENT = "agent"
    DEPLOYMENT = "deployment"


class KillSwitch(BaseModel):
    """An emergency stop. While active, matching deployments run zero replicas with
    deny-all network policy, and their identities are suspended in the identity fabric."""

    model_config = ConfigDict(frozen=True)

    id: str
    scope: KillScope
    target: str = Field(description="'*' for global, namespace/name for agent, name for deployment")
    reason: str
    engaged_by: str
    engaged_at: datetime
    active: bool = True
    released_by: str | None = None
    released_at: datetime | None = None
    release_reason: str | None = None

    def covers(self, deployment: DeploymentSpec) -> bool:
        if not self.active:
            return False
        match self.scope:
            case KillScope.GLOBAL:
                return True
            case KillScope.AGENT:
                return self.target == deployment.agent_key
            case KillScope.DEPLOYMENT:
                return self.target == deployment.name
