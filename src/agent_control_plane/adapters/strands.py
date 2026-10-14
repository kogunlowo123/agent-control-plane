"""AWS Strands Agents adapter: ``await agent.invoke_async(prompt)`` returning ``AgentResult``.

``AgentResult.message`` is the final assistant message (Bedrock Converse
shape: ``{"role": "assistant", "content": [{"text": ...}, {"toolUse": ...}]}``),
``stop_reason`` the event loop's reason (``end_turn``, ``max_tokens``,
``tool_use``, ``interrupt``, ``guardrail_intervened``) and
``metrics.accumulated_usage`` the token totals; ``metrics.tool_metrics``
counts tool calls per tool.
"""

from __future__ import annotations

from typing import Any, Protocol

from agent_control_plane.adapters.base import as_int, field, text_of
from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest, RunStatus, Usage
from agent_control_plane.domain.models import Framework

STATUS = {
    "interrupt": RunStatus.INTERRUPTED,
    "guardrail_intervened": RunStatus.BLOCKED,
    "cancelled": RunStatus.FAILED,
}


class StrandsAgent(Protocol):
    async def invoke_async(self, prompt: Any = None, **kwargs: Any) -> Any: ...


class StrandsAdapter:
    framework = Framework.AWS_STRANDS

    def __init__(self, agent: StrandsAgent) -> None:
        self._agent = agent

    async def invoke(self, request: RunRequest) -> AdapterOutcome:
        result = await self._agent.invoke_async(request.prompt)
        message = field(result, "message") or {}
        metrics = field(result, "metrics")
        accumulated = field(metrics, "accumulated_usage") or {}
        tool_metrics = field(metrics, "tool_metrics") or {}
        tool_calls = sum(as_int(field(m, "call_count")) for m in tool_metrics.values())
        stop = str(field(result, "stop_reason") or "")
        return AdapterOutcome(
            status=STATUS.get(stop, RunStatus.COMPLETED),
            output=text_of(field(message, "content")),
            usage=Usage(
                input_tokens=as_int(field(accumulated, "inputTokens")),
                output_tokens=as_int(field(accumulated, "outputTokens")),
            ),
            tool_calls=tool_calls,
            stop_reason=stop,
        )
