"""Response bodies that wrap domain objects for the HTTP API."""

from __future__ import annotations

from typing import Any

from agentic_core.audit import AuditEvent
from pydantic import BaseModel, ConfigDict

from agent_control_plane.domain.models import (
    AgentRecord,
    AgentVersion,
    DeploymentSpec,
    DeploymentStatus,
    KillSwitch,
    PolicyBundle,
    ToolVersion,
)


class Page(BaseModel):
    model_config = ConfigDict(frozen=True)

    limit: int
    offset: int


class AgentList(Page):
    items: list[AgentRecord]


class VersionList(BaseModel):
    items: list[AgentVersion]


class ToolList(Page):
    items: list[ToolVersion]


class BundleList(Page):
    items: list[PolicyBundle]


class BundleView(BaseModel):
    bundle: PolicyBundle
    verified: bool


class DeploymentList(Page):
    items: list[DeploymentSpec]


class DeploymentDetail(BaseModel):
    deployment: DeploymentSpec
    status: DeploymentStatus | None


class ManifestList(BaseModel):
    deployment: str
    killed_by: list[str]
    items: list[dict[str, Any]]


class KillSwitchList(BaseModel):
    items: list[KillSwitch]


class AuditChains(BaseModel):
    chains: list[str]


class AuditEvents(Page):
    chain: str
    items: list[AuditEvent]


class AuditVerification(BaseModel):
    chain: str
    verified: bool
    events: int
    key_id: str
    error: str | None = None
    failed_sequence: int | None = None


class OAuthError(BaseModel):
    error: str
    error_description: str
