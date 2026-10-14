"""Agent-side runtime: enforce the platform contract around any framework adapter.

Agent images build their framework object, wrap it in the matching adapter
and run every request through ``PlatformRunner``::

    runner = PlatformRunner.from_environment(LangGraphAdapter(graph), http=httpx.AsyncClient())
    result = await runner.run(request)

Before each run the runner asks the control plane whether the deployment
may run (kill switch) using the agent's own short-lived credential, which
it obtains from the identity fabric with its projected workload token. If
the control plane cannot be reached the run is blocked (fail closed).
Inputs are screened for credential material and prompt injection, outputs
for credential material (blocked) and personal data (redacted). The step
budget and timeout are enforced regardless of framework.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import httpx
from agentic_core.domain.classification import TrustLevel
from agentic_core.models import Message, ModelRequest, Role
from agentic_core.security import ContentGuard
from pydantic import BaseModel, ConfigDict

from agent_control_plane.adapters.base import FrameworkAdapter
from agent_control_plane.adapters.contract import RunRequest, RunResult, RunStatus
from agent_control_plane.domain.errors import ControlPlaneError, DependencyError, UnauthorizedError
from agent_control_plane.integrations.identity_fabric import FabricClient

DEFAULT_TOKEN_FILE = "/var/run/secrets/acp/workload/token"  # noqa: S105  # nosec B105
# Path of the projected service-account token, not a credential.


class RunPermission(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_permitted: bool
    killed_by: tuple[str, ...] = ()


class CredentialSource(Protocol):
    async def bearer(self) -> str: ...


class StatusProbe(Protocol):
    async def check(self, deployment: str) -> RunPermission: ...


class FabricCredentialSource:
    """The agent's own credential: jwt-bearer grant with its projected workload token.

    The token file is re-read on every exchange because the kubelet rotates it.
    """

    def __init__(
        self,
        client: FabricClient,
        *,
        identity_uri: str,
        workload_token_file: Path,
        clock: Callable[[], float] = time.monotonic,
        refresh_margin_s: float = 60.0,
    ) -> None:
        self._client = client
        self._identity = identity_uri
        self._token_file = workload_token_file
        self._clock = clock
        self._margin = refresh_margin_s
        self._cached: tuple[str, float] | None = None

    async def bearer(self) -> str:
        now = self._clock()
        if self._cached is not None and now < self._cached[1]:
            return self._cached[0]
        try:
            assertion = (await asyncio.to_thread(self._token_file.read_text, "utf-8")).strip()
        except OSError as exc:
            raise UnauthorizedError("workload token is not mounted") from exc
        issued = await self._client.issue_token(self._identity, assertion)
        self._cached = (issued.access_token, now + max(0.0, issued.expires_in - self._margin))
        return issued.access_token


class ControlPlaneStatusProbe:
    def __init__(
        self, *, http: httpx.AsyncClient, base_url: str, credentials: CredentialSource
    ) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._credentials = credentials

    async def check(self, deployment: str) -> RunPermission:
        token = await self._credentials.bearer()
        try:
            response = await self._http.get(
                f"{self._base}/v1/runtime/{deployment}",
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise DependencyError("control plane unreachable") from exc
        if response.status_code != 200:
            raise DependencyError(
                f"control plane refused the status check ({response.status_code})"
            )
        return RunPermission.model_validate(response.json())


class PlatformRunner:
    def __init__(
        self,
        adapter: FrameworkAdapter,
        *,
        deployment: str,
        probe: StatusProbe,
        guard: ContentGuard | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._adapter = adapter
        self._deployment = deployment
        self._probe = probe
        self._guard = guard or ContentGuard()
        self._clock = clock

    @classmethod
    def from_environment(
        cls,
        adapter: FrameworkAdapter,
        *,
        http: httpx.AsyncClient,
        environ: dict[str, str] | None = None,
    ) -> PlatformRunner:
        """Wire the runner from the variables the reconciler injects into every agent pod."""
        env = dict(os.environ) if environ is None else environ
        required = ("ACP_DEPLOYMENT", "ACP_CONTROL_PLANE_URL", "ACP_FABRIC_URL", "ACP_IDENTITY_URI")
        missing = [k for k in required if not env.get(k)]
        if missing:
            raise ValueError(f"agent runtime environment incomplete: {missing}")
        credentials = FabricCredentialSource(
            FabricClient(http=http, base_url=env["ACP_FABRIC_URL"]),
            identity_uri=env["ACP_IDENTITY_URI"],
            workload_token_file=Path(
                env.get("ACP_WORKLOAD_TOKEN_FILE", "/var/run/secrets/acp/workload/token")
            ),
        )
        probe = ControlPlaneStatusProbe(
            http=http, base_url=env["ACP_CONTROL_PLANE_URL"], credentials=credentials
        )
        return cls(adapter, deployment=env["ACP_DEPLOYMENT"], probe=probe)

    def _result(self, run: _Run, status: RunStatus, **fields: object) -> RunResult:
        return RunResult.model_validate(
            {
                "run_id": run.request.run_id,
                "deployment": run.request.deployment,
                "framework": self._adapter.framework,
                "status": status,
                "started_at": run.started_at,
                "duration_ms": max(0.0, (self._clock() - run.started) * 1000),
                **fields,
            }
        )

    async def run(self, request: RunRequest) -> RunResult:
        run = _Run(request=request, started_at=datetime.now(UTC), started=self._clock())
        refused = await self._preflight(run)
        if refused is not None:
            return refused
        return await self._execute(run)

    async def _preflight(self, run: _Run) -> RunResult | None:
        """Checks that must pass before the framework is invoked; a result means refused."""
        request = run.request
        if request.deployment != self._deployment:
            return self._result(
                run,
                RunStatus.BLOCKED,
                error=f"request targets {request.deployment}, runtime serves {self._deployment}",
            )
        try:
            permission = await self._probe.check(self._deployment)
        except ControlPlaneError as exc:
            return self._result(
                run,
                RunStatus.BLOCKED,
                error=f"run status unavailable, failing closed: {exc.message}",
            )
        if not permission.run_permitted:
            return self._result(
                run,
                RunStatus.BLOCKED,
                error="deployment is stopped by kill switch",
                findings=tuple(f"kill_switch:{k}" for k in permission.killed_by),
            )
        screened = self._guard.inspect_request(
            ModelRequest(
                messages=tuple(
                    Message(
                        role=Role.USER if m.role == "user" else Role.ASSISTANT,
                        content=m.content,
                        trust=TrustLevel.USER,
                    )
                    for m in request.messages
                ),
                classification=request.classification,
            )
        )
        if screened.blocked:
            return self._result(
                run,
                RunStatus.BLOCKED,
                error="input rejected by content guard",
                findings=screened.reasons,
            )
        return None

    async def _execute(self, run: _Run) -> RunResult:
        request = run.request
        try:
            async with asyncio.timeout(request.timeout_s):
                outcome = await self._adapter.invoke(request)
        except TimeoutError:
            return self._result(
                run, RunStatus.TIMED_OUT, error=f"run exceeded {request.timeout_s}s"
            )
        except Exception as exc:
            return self._result(
                run, RunStatus.FAILED, error=f"{type(exc).__name__}: {str(exc)[:300]}"
            )
        measured = {
            "usage": outcome.usage,
            "tool_calls": outcome.tool_calls,
            "stop_reason": outcome.stop_reason,
        }
        if outcome.tool_calls > request.max_steps:
            return self._result(run, RunStatus.FAILED, error="step budget exceeded", **measured)
        checked = self._guard.inspect_output(outcome.output)
        if checked.blocked:
            return self._result(
                run,
                RunStatus.BLOCKED,
                error="output withheld by content guard",
                findings=checked.reasons,
                **measured,
            )
        return self._result(
            run,
            outcome.status,
            output=checked.text if checked.text is not None else outcome.output,
            findings=checked.reasons,
            **measured,
        )


@dataclass(frozen=True)
class _Run:
    request: RunRequest
    started_at: datetime
    started: float
