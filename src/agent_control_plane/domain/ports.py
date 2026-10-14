"""Ports the application layer depends on. Adapters live in infrastructure and integrations."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from agent_control_plane.domain.models import (
    AgentRecord,
    AgentStatus,
    AgentVersion,
    DeploymentSpec,
    DeploymentState,
    DeploymentStatus,
    KillSwitch,
    Lifecycle,
    PolicyBundle,
    ToolVersion,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class AgentRepository(Protocol):
    async def add(self, agent: AgentRecord) -> None: ...

    async def get(self, namespace: str, name: str) -> AgentRecord | None: ...

    async def update(self, agent: AgentRecord) -> None: ...

    async def list(
        self, *, status: AgentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[AgentRecord]: ...


class AgentVersionRepository(Protocol):
    async def add(self, version: AgentVersion) -> None: ...

    async def get(self, namespace: str, name: str, version: str) -> AgentVersion | None: ...

    async def update(self, version: AgentVersion) -> None: ...

    async def list_for(self, namespace: str, name: str) -> Sequence[AgentVersion]: ...


class ToolRepository(Protocol):
    async def add(self, tool: ToolVersion) -> None: ...

    async def get(self, name: str, version: str) -> ToolVersion | None: ...

    async def update(self, tool: ToolVersion) -> None: ...

    async def list(
        self, *, state: Lifecycle | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[ToolVersion]: ...


class BundleRepository(Protocol):
    async def add(self, bundle: PolicyBundle) -> None: ...

    async def get(self, name: str, version: str) -> PolicyBundle | None: ...

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[PolicyBundle]: ...


class DeploymentRepository(Protocol):
    async def add(self, spec: DeploymentSpec) -> None: ...

    async def get(self, name: str) -> DeploymentSpec | None: ...

    async def update(self, spec: DeploymentSpec) -> None: ...

    async def list(
        self,
        *,
        states: Sequence[DeploymentState] | None = None,
        agent_key: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> Sequence[DeploymentSpec]: ...


class StatusRepository(Protocol):
    async def put(self, status: DeploymentStatus) -> None: ...

    async def get(self, name: str) -> DeploymentStatus | None: ...


class KillSwitchRepository(Protocol):
    async def add(self, switch: KillSwitch) -> None: ...

    async def get(self, switch_id: str) -> KillSwitch | None: ...

    async def update(self, switch: KillSwitch) -> None: ...

    async def list(
        self, *, active: bool | None = None, limit: int = 200
    ) -> Sequence[KillSwitch]: ...


class LeaseStore(Protocol):
    async def acquire(self, name: str, holder: str, *, ttl_s: float, now: datetime) -> bool: ...


Manifest = dict[str, Any]


class ClusterGateway(Protocol):
    """The subset of the Kubernetes API the reconciler needs, in wire (JSON) form."""

    async def read(self, kind: str, namespace: str, name: str) -> Manifest | None: ...

    async def create(self, manifest: Manifest) -> Manifest: ...

    async def replace(self, manifest: Manifest, resource_version: str) -> Manifest: ...

    async def delete(self, kind: str, namespace: str, name: str) -> bool: ...

    async def ping(self) -> bool: ...


class IdentityRegistrar(Protocol):
    """Registers deployed agent versions as workload identities (agent-identity-fabric)."""

    async def register(
        self, agent: AgentRecord, version: AgentVersion, deployment: DeploymentSpec
    ) -> str: ...

    async def suspend(self, identity_uri: str, reason: str) -> None: ...

    async def reinstate(self, identity_uri: str, reason: str) -> None: ...

    async def revoke(self, identity_uri: str, reason: str) -> None: ...
