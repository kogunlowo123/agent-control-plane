"""Microsoft Agent Framework adapter: ``await agent.run(messages, thread=...)``.

Conversations continue on an ``AgentThread`` obtained from
``agent.get_new_thread()``; threads are kept per session (bounded LRU).
``AgentRunResponse`` exposes ``text``, ``messages`` (whose ``contents``
include ``function_call`` items) and ``usage_details`` with input/output
token counts. User-input requests (``user_input_requests``) pause the run
for a human approval.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Protocol

from agent_control_plane.adapters.base import as_int, field
from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest, RunStatus, Usage
from agent_control_plane.domain.models import Framework


class MafAgent(Protocol):
    def get_new_thread(self) -> Any: ...

    async def run(self, messages: Any = None, *, thread: Any = None) -> Any: ...


class MicrosoftAgentFrameworkAdapter:
    framework = Framework.MICROSOFT_AGENT_FRAMEWORK

    def __init__(self, agent: MafAgent, *, max_threads: int = 1024) -> None:
        self._agent = agent
        self._threads: OrderedDict[str, Any] = OrderedDict()
        self._max_threads = max_threads

    def _thread(self, session: str) -> Any:
        thread = self._threads.pop(session, None)
        if thread is None:
            thread = self._agent.get_new_thread()
        self._threads[session] = thread
        while len(self._threads) > self._max_threads:
            self._threads.popitem(last=False)
        return thread

    async def invoke(self, request: RunRequest) -> AdapterOutcome:
        thread = self._thread(request.thread)
        response = await self._agent.run(request.prompt, thread=thread)
        details = field(response, "usage_details")
        tool_calls = 0
        for message in field(response, "messages") or []:
            for content in field(message, "contents") or []:
                if field(content, "type") == "function_call":
                    tool_calls += 1
        pending = field(response, "user_input_requests") or []
        return AdapterOutcome(
            status=RunStatus.INTERRUPTED if pending else RunStatus.COMPLETED,
            output=str(field(response, "text") or ""),
            usage=Usage(
                input_tokens=as_int(field(details, "input_token_count")),
                output_tokens=as_int(field(details, "output_token_count")),
            ),
            tool_calls=tool_calls,
            stop_reason="user_input_requested" if pending else "completed",
        )
