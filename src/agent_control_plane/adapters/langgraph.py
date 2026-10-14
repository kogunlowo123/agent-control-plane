"""LangGraph adapter: ``CompiledStateGraph.ainvoke(input, config)``.

Input is the MessagesState convention (``{"messages": [...]}``) plus any
structured parameters as extra state keys. The thread id comes from the
run's session so LangGraph checkpointers resume conversations; the step
budget maps to ``recursion_limit``. A returned ``__interrupt__`` (a node
called ``interrupt()``) is a human-in-the-loop pause.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from agent_control_plane.adapters.base import as_int, field, text_of
from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest, RunStatus, Usage
from agent_control_plane.domain.models import Framework


class LangGraphRunnable(Protocol):
    async def ainvoke(self, input: Any, config: Any = None) -> Any: ...  # noqa: A002


def _describe(value: Any) -> str:
    """Interrupt payloads are whatever the node passed to ``interrupt()``."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _is_ai(message: Any) -> bool:
    return field(message, "type") == "ai" or field(message, "role") in {"assistant", "ai"}


class LangGraphAdapter:
    framework = Framework.LANGGRAPH

    def __init__(self, graph: LangGraphRunnable, *, messages_key: str = "messages") -> None:
        self._graph = graph
        self._key = messages_key

    async def invoke(self, request: RunRequest) -> AdapterOutcome:
        state = await self._graph.ainvoke(
            {
                **request.parameters,
                self._key: [{"role": m.role, "content": m.content} for m in request.messages],
            },
            config={
                "configurable": {"thread_id": request.thread},
                "recursion_limit": request.max_steps,
                "run_name": request.deployment,
                "tags": ["agent-control-plane", request.deployment],
                "metadata": {"run_id": request.run_id, **request.metadata},
            },
        )
        interrupts = field(state, "__interrupt__") or []
        messages = list(field(state, self._key) or [])
        usage = Usage()
        tool_calls = 0
        for message in messages:
            if _is_ai(message):
                meta = field(message, "usage_metadata") or {}
                usage = usage + Usage(
                    input_tokens=as_int(field(meta, "input_tokens")),
                    output_tokens=as_int(field(meta, "output_tokens")),
                )
                tool_calls += len(field(message, "tool_calls") or [])
        if interrupts:
            prompts = [_describe(field(i, "value")) for i in interrupts]
            return AdapterOutcome(
                status=RunStatus.INTERRUPTED,
                output="\n".join(prompts),
                usage=usage,
                tool_calls=tool_calls,
                stop_reason="interrupt",
            )
        final = next((m for m in reversed(messages) if _is_ai(m)), None)
        return AdapterOutcome(
            status=RunStatus.COMPLETED,
            output=text_of(field(final, "content")) if final is not None else "",
            usage=usage,
            tool_calls=tool_calls,
            stop_reason="end",
        )
