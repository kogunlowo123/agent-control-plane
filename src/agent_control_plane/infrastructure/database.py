"""SQLAlchemy Core persistence. PostgreSQL in production; any async dialect works.

Aggregates are stored as validated JSON documents next to the few columns
queries filter on (``parent``, ``state``). The audit chain lives in its own
append-only table, one chain per control-plane replica.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from agentic_core.audit import AuditEvent
from pydantic import BaseModel
from sqlalchemy import (
    Column,
    ColumnElement,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agent_control_plane.domain.errors import ConflictError, NotFoundError
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

metadata = MetaData()


def _document_table(name: str) -> Table:
    return Table(
        name,
        metadata,
        Column("key", String(300), primary_key=True),
        Column("parent", String(300), nullable=True),
        Column("state", String(32), nullable=False),
        Column("document", Text, nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
        Index(f"ix_{name}_parent", "parent"),
        Index(f"ix_{name}_state", "state"),
    )


agents = _document_table("agents")
agent_versions = _document_table("agent_versions")
tools = _document_table("tools")
policy_bundles = _document_table("policy_bundles")
deployments = _document_table("deployments")
deployment_status = _document_table("deployment_status")
kill_switches = _document_table("kill_switches")

audit_events = Table(
    "audit_events",
    metadata,
    Column("chain_id", String(128), primary_key=True),
    Column("sequence", Integer, primary_key=True, autoincrement=False),
    Column("event_id", String(64), nullable=False, unique=True),
    Column("action", String(200), nullable=False),
    Column("document", Text, nullable=False),
    Column("recorded_at", DateTime(timezone=True), nullable=False),
    Index("ix_audit_action", "action"),
)

leases = Table(
    "leases",
    metadata,
    Column("name", String(128), primary_key=True),
    Column("holder", String(128), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class DocumentStore[M: BaseModel]:
    """Typed access to one document table."""

    def __init__(self, engine: AsyncEngine, table: Table, model: type[M], label: str) -> None:
        self._engine = engine
        self._table = table
        self._model = model
        self._label = label

    async def insert(self, key: str, parent: str | None, state: str, item: M, at: datetime) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(self._table).values(
                        key=key,
                        parent=parent,
                        state=state,
                        document=item.model_dump_json(),
                        updated_at=at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"{self._label} {key} already exists") from exc

    async def upsert(self, key: str, parent: str | None, state: str, item: M, at: datetime) -> None:
        async with self._engine.begin() as conn:
            values = {
                "parent": parent,
                "state": state,
                "document": item.model_dump_json(),
                "updated_at": at,
            }
            result = await conn.execute(
                update(self._table).where(self._table.c.key == key).values(**values)
            )
            if result.rowcount == 0:
                await conn.execute(insert(self._table).values(key=key, **values))

    async def replace(self, key: str, state: str, item: M, at: datetime) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(self._table)
                .where(self._table.c.key == key)
                .values(state=state, document=item.model_dump_json(), updated_at=at)
            )
            if result.rowcount == 0:
                raise NotFoundError(f"{self._label} {key} not found")

    async def get(self, key: str) -> M | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(self._table.c.document).where(self._table.c.key == key))
            ).first()
        return self._model.model_validate_json(row[0]) if row else None

    async def select(
        self,
        *,
        where: Sequence[ColumnElement[bool]] = (),
        limit: int = 100,
        offset: int = 0,
    ) -> list[M]:
        query = (
            select(self._table.c.document)
            .where(*where)
            .order_by(self._table.c.key)
            .limit(limit)
            .offset(offset)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [self._model.model_validate_json(r[0]) for r in rows]

    @property
    def columns(self) -> Any:
        return self._table.c


class SqlAgentRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, agents, AgentRecord, "agent")

    async def add(self, agent: AgentRecord) -> None:
        await self._store.insert(agent.key, None, agent.status.value, agent, agent.updated_at)

    async def get(self, namespace: str, name: str) -> AgentRecord | None:
        return await self._store.get(f"{namespace}/{name}")

    async def update(self, agent: AgentRecord) -> None:
        await self._store.replace(agent.key, agent.status.value, agent, agent.updated_at)

    async def list(
        self, *, status: AgentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[AgentRecord]:
        c = self._store.columns
        where = [c.state == status.value] if status is not None else []
        return await self._store.select(where=where, limit=limit, offset=offset)


class SqlAgentVersionRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, agent_versions, AgentVersion, "agent version")

    async def add(self, version: AgentVersion) -> None:
        await self._store.insert(
            version.key, version.agent_key, version.state.value, version, version.updated_at
        )

    async def get(self, namespace: str, name: str, version: str) -> AgentVersion | None:
        return await self._store.get(f"{namespace}/{name}@{version}")

    async def update(self, version: AgentVersion) -> None:
        await self._store.replace(version.key, version.state.value, version, version.updated_at)

    async def list_for(self, namespace: str, name: str) -> Sequence[AgentVersion]:
        c = self._store.columns
        return await self._store.select(where=[c.parent == f"{namespace}/{name}"], limit=1000)


class SqlToolRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, tools, ToolVersion, "tool")

    async def add(self, tool: ToolVersion) -> None:
        await self._store.insert(tool.key, tool.name, tool.state.value, tool, tool.updated_at)

    async def get(self, name: str, version: str) -> ToolVersion | None:
        return await self._store.get(f"{name}@{version}")

    async def update(self, tool: ToolVersion) -> None:
        await self._store.replace(tool.key, tool.state.value, tool, tool.updated_at)

    async def list(
        self, *, state: Lifecycle | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[ToolVersion]:
        c = self._store.columns
        where = [c.state == state.value] if state is not None else []
        return await self._store.select(where=where, limit=limit, offset=offset)


class SqlBundleRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, policy_bundles, PolicyBundle, "policy bundle")

    async def add(self, bundle: PolicyBundle) -> None:
        await self._store.insert(bundle.key, bundle.name, "published", bundle, bundle.published_at)

    async def get(self, name: str, version: str) -> PolicyBundle | None:
        return await self._store.get(f"{name}@{version}")

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[PolicyBundle]:
        return await self._store.select(limit=limit, offset=offset)


class SqlDeploymentRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, deployments, DeploymentSpec, "deployment")

    async def add(self, spec: DeploymentSpec) -> None:
        await self._store.insert(spec.name, spec.agent_key, spec.state.value, spec, spec.updated_at)

    async def get(self, name: str) -> DeploymentSpec | None:
        return await self._store.get(name)

    async def update(self, spec: DeploymentSpec) -> None:
        await self._store.replace(spec.name, spec.state.value, spec, spec.updated_at)

    async def list(
        self,
        *,
        states: Sequence[DeploymentState] | None = None,
        agent_key: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> Sequence[DeploymentSpec]:
        c = self._store.columns
        where: list[ColumnElement[bool]] = []
        if states is not None:
            where.append(c.state.in_([s.value for s in states]))
        if agent_key is not None:
            where.append(c.parent == agent_key)
        return await self._store.select(where=where, limit=limit, offset=offset)


class SqlStatusRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, deployment_status, DeploymentStatus, "status")

    async def put(self, status: DeploymentStatus) -> None:
        await self._store.upsert(
            status.name, None, status.phase.value, status, status.reconciled_at
        )

    async def get(self, name: str) -> DeploymentStatus | None:
        return await self._store.get(name)


class SqlKillSwitchRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._store = DocumentStore(engine, kill_switches, KillSwitch, "kill switch")

    @staticmethod
    def _state(switch: KillSwitch) -> str:
        return "active" if switch.active else "released"

    async def add(self, switch: KillSwitch) -> None:
        await self._store.insert(
            switch.id, switch.target, self._state(switch), switch, switch.engaged_at
        )

    async def get(self, switch_id: str) -> KillSwitch | None:
        return await self._store.get(switch_id)

    async def update(self, switch: KillSwitch) -> None:
        at = switch.released_at or switch.engaged_at
        await self._store.replace(switch.id, self._state(switch), switch, at)

    async def list(self, *, active: bool | None = None, limit: int = 200) -> Sequence[KillSwitch]:
        c = self._store.columns
        where = [] if active is None else [c.state == ("active" if active else "released")]
        return await self._store.select(where=where, limit=limit)


class SqlLeaseStore:
    """Leader lease for the periodic reconcile loop.

    Acquisition is a single conditional UPDATE (holder is us, or the lease
    expired), so two replicas racing for an expired lease cannot both win.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def acquire(self, name: str, holder: str, *, ttl_s: float, now: datetime) -> bool:
        now = _aware(now)
        expires = now + timedelta(seconds=ttl_s)
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(leases)
                .where(
                    and_(
                        leases.c.name == name,
                        or_(leases.c.holder == holder, leases.c.expires_at < now),
                    )
                )
                .values(holder=holder, expires_at=expires)
            )
            if result.rowcount == 1:
                return True
            exists = (
                await conn.execute(select(leases.c.name).where(leases.c.name == name))
            ).first()
            if exists:
                return False
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(leases).values(name=name, holder=holder, expires_at=expires)
                )
        except IntegrityError:
            return False
        return True


class SqlAuditSink:
    """agentic-core AuditSink storing one hash chain per control-plane replica.

    The table is append-only by convention and, in production, by database
    privileges (the service role holds INSERT and SELECT only; see
    docs/runbooks/startup.md).
    """

    def __init__(self, engine: AsyncEngine, chain_id: str) -> None:
        self._engine = engine
        self.chain_id = chain_id

    async def append(self, event: AuditEvent) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(audit_events).values(
                    chain_id=self.chain_id,
                    sequence=event.sequence,
                    event_id=event.event_id,
                    action=event.action,
                    document=event.model_dump_json(),
                    recorded_at=event.timestamp,
                )
            )

    async def read(self) -> AsyncIterator[AuditEvent]:
        async for event in read_chain(self._engine, self.chain_id):
            yield event

    async def tail(self) -> AuditEvent | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(audit_events.c.document)
                    .where(audit_events.c.chain_id == self.chain_id)
                    .order_by(audit_events.c.sequence.desc())
                    .limit(1)
                )
            ).first()
        return AuditEvent.model_validate_json(row[0]) if row else None


async def read_chain(
    engine: AsyncEngine, chain_id: str, *, limit: int | None = None, offset: int = 0
) -> AsyncIterator[AuditEvent]:
    query = (
        select(audit_events.c.document)
        .where(audit_events.c.chain_id == chain_id)
        .order_by(audit_events.c.sequence)
        .offset(offset)
    )
    if limit is not None:
        query = query.limit(limit)
    async with engine.connect() as conn:
        rows = (await conn.execute(query)).all()
    for row in rows:
        yield AuditEvent.model_validate_json(row[0])


async def list_chains(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                select(audit_events.c.chain_id).distinct().order_by(audit_events.c.chain_id)
            )
        ).all()
    return [r[0] for r in rows]


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
