"""Google ADK adapter: ``Runner.run_async(user_id, session_id, new_message)``.

ADK runs inside a session owned by the runner's session service; the
adapter creates it on first use. ``run_async`` yields events: function
calls (``get_function_calls()``), usage (``usage_metadata`` with
prompt/candidates token counts) and finally an event whose
``is_final_response()`` is true. Long-running tool calls pause the run for
a human. ``new_message`` must be a ``google.genai.types.Content``; the agent
image supplies the factory (``lambda text: types.Content(role="user",
parts=[types.Part(text=text)])``) so this module does not import the SDK.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any, Protocol

from agent_control_plane.adapters.base import as_int, field, text_of
from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest, RunStatus, Usage
from agent_control_plane.domain.models import Framework


class AdkSessionService(Protocol):
    async def get_session(self, *, app_name: str, user_id: str, session_id: str) -> Any: ...

    async def create_session(
        self, *, app_name: str, user_id: str, session_id: str | None = None
    ) -> Any: ...


class AdkRunner(Protocol):
    app_name: str
    session_service: AdkSessionService

    def run_async(
        self, *, user_id: str, session_id: str, new_message: Any
    ) -> AsyncIterator[Any]: ...


class GoogleAdkAdapter:
    framework = Framework.GOOGLE_ADK

    def __init__(self, runner: AdkRunner, *, content_factory: Callable[[str], Any]) -> None:
        self._runner = runner
        self._content = content_factory

    async def invoke(self, request: RunRequest) -> AdapterOutcome:
        service = self._runner.session_service
        app = self._runner.app_name
        session = await service.get_session(
            app_name=app, user_id=request.user_id, session_id=request.thread
        )
        if session is None:
            await service.create_session(
                app_name=app, user_id=request.user_id, session_id=request.thread
            )
        usage = Usage()
        tool_calls = 0
        final = ""
        status = RunStatus.COMPLETED
        stop = "final_response"
        async for event in self._runner.run_async(
            user_id=request.user_id,
            session_id=request.thread,
            new_message=self._content(request.prompt),
        ):
            meta = field(event, "usage_metadata")
            if meta is not None:
                usage = usage + Usage(
                    input_tokens=as_int(field(meta, "prompt_token_count")),
                    output_tokens=as_int(field(meta, "candidates_token_count")),
                )
            calls = field(event, "get_function_calls")
            tool_calls += len(calls() if callable(calls) else [])
            if tool_calls > request.max_steps:
                return AdapterOutcome(
                    status=RunStatus.FAILED,
                    output="",
                    usage=usage,
                    tool_calls=tool_calls,
                    stop_reason="step_budget_exceeded",
                )
            if field(event, "error_code"):
                status = RunStatus.FAILED
                stop = str(field(event, "error_code"))
            if field(event, "long_running_tool_ids"):
                status = RunStatus.INTERRUPTED
                stop = "long_running_tool"
            is_final = field(event, "is_final_response")
            if callable(is_final) and is_final():
                content = field(event, "content")
                final = text_of(field(content, "parts")) or final
        return AdapterOutcome(
            status=status, output=final, usage=usage, tool_calls=tool_calls, stop_reason=stop
        )
