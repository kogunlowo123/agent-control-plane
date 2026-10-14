"""CrewAI adapter: ``Crew.kickoff_async(inputs=...)`` returning ``CrewOutput``.

CrewAI interpolates ``inputs`` into task descriptions, so the run's prompt
is passed as ``input``, the earlier conversation as ``history``, and the
structured parameters alongside. ``CrewOutput.raw`` is the final answer and
``CrewOutput.token_usage`` (``UsageMetrics``) carries token counts.
"""

from __future__ import annotations

from typing import Any, Protocol

from agent_control_plane.adapters.base import as_int, field
from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest, RunStatus, Usage
from agent_control_plane.domain.models import Framework


class CrewKickoff(Protocol):
    async def kickoff_async(self, inputs: dict[str, Any] | None = None) -> Any: ...


class CrewAIAdapter:
    framework = Framework.CREWAI

    def __init__(self, crew: CrewKickoff) -> None:
        self._crew = crew

    async def invoke(self, request: RunRequest) -> AdapterOutcome:
        history = "\n".join(f"{m.role}: {m.content}" for m in request.messages[:-1])
        output = await self._crew.kickoff_async(
            inputs={**request.parameters, "input": request.prompt, "history": history}
        )
        usage = field(output, "token_usage")
        tasks = field(output, "tasks_output") or []
        return AdapterOutcome(
            status=RunStatus.COMPLETED,
            output=str(field(output, "raw") or ""),
            usage=Usage(
                input_tokens=as_int(field(usage, "prompt_tokens")),
                output_tokens=as_int(field(usage, "completion_tokens")),
            ),
            tool_calls=0,
            stop_reason=f"tasks_completed:{len(tasks)}",
        )
