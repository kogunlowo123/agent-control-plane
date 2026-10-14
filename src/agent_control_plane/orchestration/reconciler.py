"""Desired-state reconciliation of agent deployments to Kubernetes.

For each deployment the reconciler renders the objects of its current
revision (killed variant if a kill switch covers it), reads the live
objects, and classifies differences:

* rollout - the live object carries a different spec hash: the desired
  state moved on (new revision, kill switch, bundle change). Expected.
* drift   - the live object carries the current spec hash but no longer
  matches it: someone changed the cluster outside the control plane.

Both are corrected by replacing the object; drift is additionally counted,
audited, and reported in the deployment status. ``detect_drift`` performs
the same comparison without changing anything.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime

from agentic_core.observability import get_logger
from pydantic import BaseModel, ConfigDict

from agent_control_plane.application.governance import Recorder
from agent_control_plane.domain.errors import (
    ControlPlaneError,
    DependencyError,
    InvalidStateError,
    NotFoundError,
)
from agent_control_plane.domain.models import (
    AgentRecord,
    AgentVersion,
    DeploymentSpec,
    DeploymentState,
    DeploymentStatus,
    DriftItem,
    KillSwitch,
    Phase,
    PolicyBundle,
    Revision,
    ToolVersion,
)
from agent_control_plane.domain.ports import (
    AgentRepository,
    AgentVersionRepository,
    BundleRepository,
    Clock,
    ClusterGateway,
    DeploymentRepository,
    IdentityRegistrar,
    KillSwitchRepository,
    LeaseStore,
    Manifest,
    StatusRepository,
    ToolRepository,
)
from agent_control_plane.observability.metrics import ControlPlaneMetrics
from agent_control_plane.orchestration import drift as drift_rules
from agent_control_plane.orchestration.manifests import (
    SPEC_HASH,
    RenderContext,
    render,
    rendered_hash,
)

log = get_logger("agent_control_plane.reconciler")
SYSTEM_ACTOR = "system:reconciler"
DELETE_ORDER = ("Deployment", "NetworkPolicy", "ConfigMap", "ServiceAccount")


class DriftReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    spec_hash: str
    in_sync: bool
    drift: tuple[DriftItem, ...]
    pending_rollout: tuple[DriftItem, ...]
    killed_by: tuple[str, ...]


class Reconciler:
    def __init__(
        self,
        *,
        deployments: DeploymentRepository,
        statuses: StatusRepository,
        agents: AgentRepository,
        versions: AgentVersionRepository,
        tools: ToolRepository,
        bundles: BundleRepository,
        kill_switches: KillSwitchRepository,
        cluster: ClusterGateway,
        context: RenderContext,
        registrar: IdentityRegistrar | None,
        recorder: Recorder,
        metrics: ControlPlaneMetrics,
        clock: Clock,
    ) -> None:
        self._deployments = deployments
        self._statuses = statuses
        self._agents = agents
        self._versions = versions
        self._tools = tools
        self._bundles = bundles
        self._kill_switches = kill_switches
        self._cluster = cluster
        self._context = context
        self._registrar = registrar
        self._recorder = recorder
        self._metrics = metrics
        self._clock = clock
        self._locks: dict[str, asyncio.Lock] = {}

    # --------------------------------------------------------------- render

    async def killed_by(self, spec: DeploymentSpec) -> tuple[str, ...]:
        switches: Sequence[KillSwitch] = await self._kill_switches.list(active=True)
        return tuple(sorted(s.id for s in switches if s.covers(spec)))

    async def _inputs(
        self, spec: DeploymentSpec, revision: Revision
    ) -> tuple[AgentRecord, AgentVersion, list[ToolVersion], PolicyBundle]:
        agent = await self._agents.get(spec.agent_namespace, spec.agent_name)
        version = await self._versions.get(spec.agent_namespace, spec.agent_name, revision.version)
        ref = revision.policy_bundle
        bundle = await self._bundles.get(ref.name, ref.version)
        if agent is None or version is None or bundle is None:
            raise NotFoundError(
                f"deployment {spec.name} references a missing agent, version or bundle"
            )
        tools: list[ToolVersion] = []
        for tool_ref in version.tools:
            tool = await self._tools.get(tool_ref.name, tool_ref.version)
            if tool is None:
                raise NotFoundError(f"tool {tool_ref.key} referenced by {version.key} is missing")
            tools.append(tool)
        return agent, version, tools, bundle

    async def desired(self, spec: DeploymentSpec) -> tuple[list[Manifest], tuple[str, ...]]:
        if spec.current is None:
            raise InvalidStateError(f"deployment {spec.name} has no approved revision")
        agent, version, tools, bundle = await self._inputs(spec, spec.current)
        killed = await self.killed_by(spec)
        objects = render(
            spec,
            revision=spec.current,
            agent=agent,
            version=version,
            tools=tools,
            bundle=bundle,
            context=self._context,
            killed_by=killed,
        )
        return objects, killed

    # ---------------------------------------------------------------- drift

    async def _compare(
        self, objects: Sequence[Manifest]
    ) -> list[tuple[Manifest, Manifest | None, list[DriftItem], bool]]:
        """Per object: desired, live, differences, whether they are drift (vs rollout)."""
        results = []
        for obj in objects:
            meta = obj["metadata"]
            live = await self._cluster.read(obj["kind"], meta["namespace"], meta["name"])
            items = drift_rules.detect(obj, live)
            live_hash = ((live or {}).get("metadata", {}).get("annotations") or {}).get(SPEC_HASH)
            is_drift = (
                bool(items) and live is not None and live_hash == meta["annotations"][SPEC_HASH]
            )
            results.append((obj, live, items, is_drift))
        return results

    async def detect_drift(self, name: str) -> DriftReport:
        spec = await self._get(name)
        objects, killed = await self.desired(spec)
        compared = await self._compare(objects)
        drift = tuple(i for _, _, items, is_drift in compared if is_drift for i in items)
        rollout = tuple(i for _, _, items, is_drift in compared if not is_drift for i in items)
        return DriftReport(
            name=name,
            spec_hash=rendered_hash(objects),
            in_sync=not drift and not rollout,
            drift=drift,
            pending_rollout=rollout,
            killed_by=killed,
        )

    # ------------------------------------------------------------ reconcile

    async def _get(self, name: str) -> DeploymentSpec:
        spec = await self._deployments.get(name)
        if spec is None:
            raise NotFoundError(f"deployment {name} not found")
        return spec

    def _lock(self, name: str) -> asyncio.Lock:
        return self._locks.setdefault(name, asyncio.Lock())

    async def reconcile(self, name: str) -> DeploymentStatus:
        async with self._lock(name):
            started = time.perf_counter()
            spec = await self._get(name)
            try:
                status = await self._reconcile(spec)
                outcome = "ok"
            except ControlPlaneError as exc:
                outcome = "error"
                self._metrics.reconcile_errors.labels(type(exc).__name__).inc()
                status = DeploymentStatus(
                    name=spec.name,
                    phase=Phase.DEGRADED,
                    observed_generation=spec.current.generation if spec.current else 0,
                    message=exc.message,
                    reconciled_at=self._clock.now(),
                )
                await self._recorder.record(
                    SYSTEM_ACTOR,
                    "deployment.reconcile",
                    f"deployment:{name}",
                    "failure",
                    {"error": exc.message},
                )
            await self._statuses.put(status)
            self._metrics.reconcile_duration.labels(outcome).observe(time.perf_counter() - started)
            return status

    async def _reconcile(self, spec: DeploymentSpec) -> DeploymentStatus:
        now = self._clock.now()
        if spec.state is DeploymentState.DELETED:
            return DeploymentStatus(name=spec.name, phase=Phase.DELETED, reconciled_at=now)
        if spec.state is DeploymentState.DELETING:
            return await self._delete(spec)
        if spec.current is None:
            return DeploymentStatus(
                name=spec.name,
                phase=Phase.PENDING_APPROVAL,
                observed_generation=0,
                desired_replicas=spec.pending.replicas if spec.pending else 0,
                message="first revision awaits approval",
                reconciled_at=now,
            )

        return await self._converge(spec, spec.current, now)

    async def _apply(self, objects: Sequence[Manifest]) -> tuple[list[DriftItem], bool]:
        """Create or replace every object that differs. Returns (drift found, rolled out)."""
        drift: list[DriftItem] = []
        rolled = False
        for obj, live, items, is_drift in await self._compare(objects):
            if not items:
                continue
            if is_drift:
                drift += items
                for item in items:
                    self._metrics.drift_detected.labels(item.kind, item.change).inc()
            else:
                rolled = True
            if live is None:
                await self._cluster.create(obj)
            else:
                await self._cluster.replace(obj, str(live["metadata"]["resourceVersion"]))
        return drift, rolled

    async def _converge(
        self, spec: DeploymentSpec, revision: Revision, now: datetime
    ) -> DeploymentStatus:
        objects, killed = await self.desired(spec)
        digest = rendered_hash(objects)
        drift, rolled = await self._apply(objects)

        live_deployment = await self._cluster.read("Deployment", spec.namespace, spec.name)
        ready = int(((live_deployment or {}).get("status") or {}).get("readyReplicas") or 0)
        desired_replicas = 0 if killed else revision.replicas
        if killed:
            phase = Phase.KILLED
        elif ready >= desired_replicas:
            phase = Phase.AVAILABLE
        else:
            phase = Phase.PROGRESSING

        target = f"deployment:{spec.name}"
        if drift:
            summary = [i.model_dump(mode="json", exclude={"expected", "actual"}) for i in drift]
            await self._recorder.record(
                SYSTEM_ACTOR,
                "deployment.drift_corrected",
                target,
                "success",
                {"spec_hash": digest, "items": summary},
            )
        if rolled:
            await self._recorder.record(
                SYSTEM_ACTOR,
                "deployment.rollout",
                target,
                "success",
                {
                    "generation": revision.generation,
                    "version": revision.version,
                    "spec_hash": digest,
                    "killed_by": list(killed),
                },
            )
        if phase is Phase.AVAILABLE and spec.superseded_identities:
            await self._retire_identities(spec)

        message = (
            f"killed by {', '.join(killed)}"
            if killed
            else f"{ready}/{desired_replicas} replicas ready"
        )
        return DeploymentStatus(
            name=spec.name,
            phase=phase,
            observed_generation=revision.generation,
            desired_replicas=desired_replicas,
            ready_replicas=ready,
            killed_by=killed,
            drift=tuple(drift),
            corrected=bool(drift),
            spec_hash=digest,
            message=message,
            reconciled_at=now,
        )

    async def _retire_identities(self, spec: DeploymentSpec) -> None:
        if self._registrar is None:
            return
        remaining: list[str] = []
        for uri in spec.superseded_identities:
            try:
                await self._registrar.revoke(uri, f"superseded by {spec.identity_uri}")
                outcome = "success"
            except (NotFoundError, InvalidStateError):
                outcome = "already_gone"
            except DependencyError:
                remaining.append(uri)  # retried on the next reconcile
                outcome = "retry"
            await self._recorder.record(
                SYSTEM_ACTOR, "identity.revoke", uri, outcome, {"deployment": spec.name}
            )
        await self._deployments.update(
            spec.model_copy(
                update={
                    "superseded_identities": tuple(remaining),
                    "updated_at": self._clock.now(),
                }
            )
        )

    async def _delete(self, spec: DeploymentSpec) -> DeploymentStatus:
        names = {
            "Deployment": spec.name,
            "NetworkPolicy": spec.name,
            "ConfigMap": f"{spec.name}-runtime",
            "ServiceAccount": spec.name,
        }
        removed = [
            kind
            for kind in DELETE_ORDER
            if await self._cluster.delete(kind, spec.namespace, names[kind])
        ]
        identities = [u for u in (spec.identity_uri, *spec.superseded_identities) if u]
        if self._registrar is not None:
            for uri in identities:
                try:
                    await self._registrar.revoke(uri, f"deployment {spec.name} deleted")
                except (NotFoundError, InvalidStateError):
                    continue
        now = self._clock.now()
        await self._deployments.update(
            spec.model_copy(
                update={
                    "state": DeploymentState.DELETED,
                    "superseded_identities": (),
                    "updated_at": now,
                }
            )
        )
        await self._recorder.record(
            SYSTEM_ACTOR,
            "deployment.deleted",
            f"deployment:{spec.name}",
            "success",
            {"removed": removed, "identities_revoked": identities},
        )
        return DeploymentStatus(
            name=spec.name, phase=Phase.DELETED, message="objects removed", reconciled_at=now
        )

    async def reconcile_all(self) -> list[DeploymentStatus]:
        specs = await self._deployments.list(
            states=[DeploymentState.ACTIVE, DeploymentState.DELETING]
        )
        statuses = [await self.reconcile(spec.name) for spec in specs]
        phases: dict[Phase, int] = dict.fromkeys(Phase, 0)
        for status in statuses:
            phases[status.phase] += 1
        for phase, count in phases.items():
            self._metrics.deployments.labels(phase.value).set(count)
        return statuses


class ReconcileLoop:
    """Periodic reconciliation, run only by the replica holding the leader lease.

    API-triggered reconciles (apply, approve, kill switch) run immediately on
    the replica that served the request; per-deployment locks and resource
    versions keep concurrent writers safe.
    """

    LEASE = "reconciler"

    def __init__(
        self,
        reconciler: Reconciler,
        leases: LeaseStore,
        *,
        holder: str,
        interval_s: float,
        lease_ttl_s: float,
        clock: Clock,
        metrics: ControlPlaneMetrics,
        cluster: ClusterGateway,
    ) -> None:
        self._reconciler = reconciler
        self._leases = leases
        self._holder = holder
        self._interval = interval_s
        self._ttl = lease_ttl_s
        self._clock = clock
        self._metrics = metrics
        self._cluster = cluster
        self._wake = asyncio.Event()

    def trigger(self) -> None:
        self._wake.set()

    async def run_once(self) -> bool:
        leader = await self._leases.acquire(
            self.LEASE, self._holder, ttl_s=self._ttl, now=self._clock.now()
        )
        self._metrics.leader.set(1 if leader else 0)
        if not leader:
            return False
        self._metrics.cluster_reachable.set(1 if await self._cluster.ping() else 0)
        await self._reconciler.reconcile_all()
        return True

    async def run_forever(
        self, wait: Callable[[asyncio.Event, float], Awaitable[None]] | None = None
    ) -> None:
        waiter = wait or _wait_for
        while True:
            try:
                await self.run_once()
            except Exception:
                log.exception("reconcile_loop_failed")
            await waiter(self._wake, self._interval)
            self._wake.clear()


async def _wait_for(event: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(seconds):
            await event.wait()
