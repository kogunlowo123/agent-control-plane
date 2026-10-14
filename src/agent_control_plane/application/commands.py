"""Use-case inputs and outputs. Published as JSON Schemas under schemas/."""

from __future__ import annotations

from typing import Any

from agentic_core.domain.classification import DataClassification, RiskLevel
from agentic_core.domain.identifiers import Segment
from pydantic import BaseModel, ConfigDict, Field

from agent_control_plane.domain.models import (
    TOOL_NAME,
    AgentRecord,
    AgentVersion,
    BundleRef,
    DeploymentSpec,
    DeploymentStatus,
    DnsLabel,
    EgressRule,
    Environment,
    Framework,
    ImageRef,
    KillScope,
    KillSwitch,
    LifecycleAction,
    Owners,
    Resources,
    Scope,
    SemVer,
    ToolRef,
    ToolVersion,
)


class _Command(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CreateAgent(_Command):
    namespace: Segment
    name: Segment
    display_name: str = Field(min_length=3, max_length=120)
    mission: str = Field(min_length=10, max_length=2000)
    owners: Owners
    risk: RiskLevel
    max_classification: DataClassification
    disallowed_actions: tuple[str, ...] = Field(default=(), max_length=50)


class CreateAgentVersion(_Command):
    version: SemVer
    framework: Framework
    entrypoint: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
    image: ImageRef
    tools: tuple[ToolRef, ...] = Field(default=(), max_length=50)
    scopes: frozenset[Scope] = Field(min_length=1, max_length=50)
    egress: tuple[EgressRule, ...] = Field(default=(), max_length=20)
    resources: Resources = Resources()
    health_path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9/_\-.]{0,100}$")
    release_notes: str = Field(default="", max_length=4000)


class CreateTool(_Command):
    name: str = Field(pattern=TOOL_NAME.pattern)
    version: SemVer
    description: str = Field(min_length=10, max_length=2000)
    owner: str = Field(min_length=3, max_length=200)
    risk: RiskLevel
    endpoint: str = Field(pattern=r"^https://[^\s]+$", max_length=500)
    input_schema: dict[str, Any] = Field(
        description="JSON Schema of the tool input; pinned by digest"
    )


class Transition(_Command):
    action: LifecycleAction
    comment: str = Field(default="", max_length=1000)


class PublishBundle(_Command):
    name: DnsLabel
    version: SemVer
    description: str = Field(default="", max_length=2000)
    policies: tuple[dict[str, Any], ...] = Field(
        min_length=1, max_length=20, description="agentic-core PolicySet documents"
    )


class ApplyDeployment(_Command):
    name: DnsLabel
    agent_namespace: Segment
    agent_name: Segment
    environment: Environment
    namespace: DnsLabel
    version: SemVer
    replicas: int = Field(default=2, ge=0, le=50)
    policy_bundle: BundleRef
    ingress_namespaces: tuple[DnsLabel, ...] = Field(default=(), max_length=20)
    env: dict[str, str] = Field(default_factory=dict, max_length=50)
    service_account_annotations: dict[str, str] = Field(default_factory=dict, max_length=20)


class Approve(_Command):
    comment: str = Field(default="", max_length=1000)


class Reason(_Command):
    reason: str = Field(min_length=5, max_length=500)


class EngageKillSwitch(_Command):
    scope: KillScope
    target: str = Field(
        min_length=1,
        max_length=200,
        description="'*' for global, namespace/name for an agent, deployment name",
    )
    reason: str = Field(min_length=5, max_length=500)


# ------------------------------------------------------------------- results


class AgentVersionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: str = Field(description="applied | approval_recorded")
    version: AgentVersion


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: str = Field(description="applied | approval_recorded")
    tool: ToolVersion


class DeploymentResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: str = Field(description="applied | approval_required | deleting")
    deployment: DeploymentSpec
    status: DeploymentStatus | None = None


class KillSwitchResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    kill_switch: KillSwitch
    affected: tuple[str, ...]
    statuses: tuple[DeploymentStatus, ...] = ()
    identity_actions: dict[str, str] = Field(default_factory=dict)


class AgentResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent: AgentRecord
    retired_versions: tuple[str, ...] = ()
