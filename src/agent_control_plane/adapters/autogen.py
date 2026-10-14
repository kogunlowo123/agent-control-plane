"""AutoGen AgentChat adapter: ``await agent_or_team.run(task=..., cancellation_token=...)``.

``TaskResult.messages`` holds chat messages and agent events; each may carry
``models_usage`` (``RequestUsage``: prompt/completion tokens). Tool calls
appear as ``ToolCallRequestEvent`` messages. When the platform cancels a run
(timeout) the adapter cancels AutoGen's ``CancellationToken`` so in-flight
model and tool calls stop too.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, Protocol

from agent_control_plane.adapters.base import as_int, field, text_of
from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest, RunStatus, Usage
from agent_control_plane.domain.models import Framework


class CancellationTokenLike(Protocol):
    def cancel(self) -> None: ...


class AutoGenTaskRunner(Protocol):
    async def run(self, *, task: Any = None, cancellation_token: Any = None) -> Any: ...


class AutoGenAdapter:
    framework = Framework.AUTOGEN

    def __init__(
        self,
        runner: AutoGenTaskRunner,
        *,
        cancellation_token_factory: Callable[[], CancellationTokenLike],
    ) -> None:
        self._runner = runner
        self._tokens = cancellation_token_factory

    async def invoke(self, request: RunRequest) -> AdapterOutcome:
        token = self._tokens()
        try:
            result = await self._runner.run(task=request.prompt, cancellation_token=token)
        except asyncio.CancelledError:
            token.cancel()
            raise
        messages = list(field(result, "messages") or [])
        usage = Usage()
        tool_calls = 0
        final = ""
        for message in messages:
            used = field(message, "models_usage")
            if used is not None:
                usage = usage + Usage(
                    input_tokens=as_int(field(used, "prompt_tokens")),
                    output_tokens=as_int(field(used, "completion_tokens")),
                )
            kind = field(message, "type") or type(message).__name__
            if kind == "ToolCallRequestEvent":
                tool_calls += len(field(message, "content") or [])
            elif field(message, "source") != "user" and isinstance(field(message, "content"), str):
                final = text_of(field(message, "content"))
        stop = str(field(result, "stop_reason") or "")
        status = RunStatus.INTERRUPTED if "handoff" in stop.lower() else RunStatus.COMPLETED
        return AdapterOutcome(
            status=status, output=final, usage=usage, tool_calls=tool_calls, stop_reason=stop
        )
