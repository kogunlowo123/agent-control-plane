"""Framework adapters translate the platform run contract to each framework's API.

Each fake reproduces the shape of the framework object the adapter calls
(method names, keyword arguments, result attributes) as documented by the
framework, and records how it was invoked.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_control_plane.adapters import ADAPTERS
from agent_control_plane.adapters.autogen import AutoGenAdapter
from agent_control_plane.adapters.base import as_int, text_of
from agent_control_plane.adapters.base import field as read_field
from agent_control_plane.adapters.contract import RunMessage, RunRequest, RunStatus, Usage
from agent_control_plane.adapters.crewai import CrewAIAdapter
from agent_control_plane.adapters.google_adk import GoogleAdkAdapter
from agent_control_plane.adapters.langgraph import LangGraphAdapter
from agent_control_plane.adapters.microsoft_agent_framework import MicrosoftAgentFrameworkAdapter
from agent_control_plane.adapters.strands import StrandsAdapter
from agent_control_plane.domain.models import Framework


def request(**overrides: Any) -> RunRequest:
    values: dict[str, Any] = {
        "deployment": "claims-triage-prod",
        "session_id": "conv-42",
        "messages": (
            RunMessage(role="user", content="What is the status of claim C-1?"),
            RunMessage(role="assistant", content="Looking it up."),
            RunMessage(role="user", content="And C-2?"),
        ),
        "parameters": {"region": "us-east-1"},
        "max_steps": 10,
        "metadata": {"ticket": "INC-9"},
    }
    values.update(overrides)
    return RunRequest(**values)


def test_every_framework_has_an_adapter() -> None:
    assert set(ADAPTERS) == set(Framework)
    for framework, adapter in ADAPTERS.items():
        assert adapter.framework is framework


def test_request_helpers() -> None:
    r = request()
    assert r.prompt == "And C-2?"
    assert r.thread == "conv-42"
    only_assistant = request(
        messages=(RunMessage(role="assistant", content="hi"),), session_id=None
    )
    assert only_assistant.prompt == "hi"
    assert only_assistant.thread == only_assistant.run_id
    assert Usage(input_tokens=1) + Usage(output_tokens=2) == Usage(input_tokens=1, output_tokens=2)


def test_base_helpers() -> None:
    assert text_of(None) == ""
    assert text_of([{"type": "text", "text": "a"}, "b", {"type": "image"}]) == "ab"
    assert text_of(42) == "42"
    assert as_int(-3) == 0
    assert as_int(2.9) == 2
    assert as_int("7") == 0
    assert read_field({"a": 1}, "a") == 1


# ----------------------------------------------------------------- LangGraph


@dataclass
class AIMessage:  # langchain_core.messages.AIMessage shape
    content: Any
    type: str = "ai"
    usage_metadata: dict[str, int] | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Interrupt:  # langgraph.types.Interrupt shape
    value: Any


class FakeGraph:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result
        self.calls: list[tuple[Any, Any]] = []

    async def ainvoke(self, input: Any, config: Any = None) -> Any:  # noqa: A002
        self.calls.append((input, config))
        return self.result


async def test_langgraph_adapter() -> None:
    graph = FakeGraph(
        {
            "messages": [
                {"role": "user", "content": "q"},
                AIMessage(
                    "",
                    usage_metadata={"input_tokens": 10, "output_tokens": 2},
                    tool_calls=[{"name": "claims.search"}],
                ),
                {"type": "tool", "content": "C-2: open"},
                AIMessage(
                    [{"type": "text", "text": "C-2 is open."}],
                    usage_metadata={"input_tokens": 20, "output_tokens": 5},
                ),
            ]
        }
    )
    outcome = await LangGraphAdapter(graph).invoke(request())
    assert outcome.status is RunStatus.COMPLETED
    assert outcome.output == "C-2 is open."
    assert outcome.usage == Usage(input_tokens=30, output_tokens=7)
    assert outcome.tool_calls == 1
    state, config = graph.calls[0]
    assert state["messages"][-1] == {"role": "user", "content": "And C-2?"}
    assert state["region"] == "us-east-1"
    assert config["configurable"] == {"thread_id": "conv-42"}
    assert config["recursion_limit"] == 10
    assert config["metadata"]["ticket"] == "INC-9"


async def test_langgraph_interrupt_is_human_in_the_loop() -> None:
    graph = FakeGraph({"messages": [], "__interrupt__": [Interrupt({"text": "Approve payout?"})]})
    outcome = await LangGraphAdapter(graph).invoke(request())
    assert outcome.status is RunStatus.INTERRUPTED
    assert "Approve payout?" in outcome.output
    empty = await LangGraphAdapter(FakeGraph({"messages": []})).invoke(request())
    assert empty.output == ""


# -------------------------------------------------------------------- CrewAI


@dataclass
class UsageMetrics:
    prompt_tokens: int
    completion_tokens: int


@dataclass
class CrewOutput:
    raw: str
    token_usage: UsageMetrics
    tasks_output: list[Any]


class FakeCrew:
    def __init__(self) -> None:
        self.inputs: dict[str, Any] | None = None

    async def kickoff_async(self, inputs: dict[str, Any] | None = None) -> CrewOutput:
        self.inputs = inputs
        return CrewOutput("Routed to adjuster queue B.", UsageMetrics(100, 40), ["t1", "t2"])


async def test_crewai_adapter() -> None:
    crew = FakeCrew()
    outcome = await CrewAIAdapter(crew).invoke(request())
    assert outcome.output == "Routed to adjuster queue B."
    assert outcome.usage == Usage(input_tokens=100, output_tokens=40)
    assert outcome.stop_reason == "tasks_completed:2"
    assert crew.inputs is not None
    assert crew.inputs["input"] == "And C-2?"
    assert "assistant: Looking it up." in crew.inputs["history"]
    assert crew.inputs["region"] == "us-east-1"


# ------------------------------------------------------------------- AutoGen


@dataclass
class RequestUsage:
    prompt_tokens: int
    completion_tokens: int


@dataclass
class ChatMessage:
    source: str
    content: Any
    type: str = "TextMessage"
    models_usage: RequestUsage | None = None


@dataclass
class TaskResult:
    messages: list[Any]
    stop_reason: str | None


class FakeToken:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class FakeAutoGenTeam:
    def __init__(self, result: TaskResult | None = None, *, hang: bool = False) -> None:
        self.result = result
        self.hang = hang
        self.calls: list[dict[str, Any]] = []

    async def run(self, *, task: Any = None, cancellation_token: Any = None) -> TaskResult:
        self.calls.append({"task": task, "token": cancellation_token})
        if self.hang:
            await asyncio.sleep(3600)
        assert self.result is not None
        return self.result


async def test_autogen_adapter() -> None:
    team = FakeAutoGenTeam(
        TaskResult(
            messages=[
                ChatMessage("user", "And C-2?"),
                ChatMessage(
                    "triage",
                    [{"id": "1"}, {"id": "2"}],
                    type="ToolCallRequestEvent",
                    models_usage=RequestUsage(12, 3),
                ),
                ChatMessage("triage", "C-2 is open.", models_usage=RequestUsage(30, 8)),
            ],
            stop_reason="Text 'TERMINATE' mentioned",
        )
    )
    tokens: list[FakeToken] = []

    def factory() -> FakeToken:
        tokens.append(FakeToken())
        return tokens[-1]

    outcome = await AutoGenAdapter(team, cancellation_token_factory=factory).invoke(request())
    assert outcome.output == "C-2 is open."
    assert outcome.tool_calls == 2
    assert outcome.usage == Usage(input_tokens=42, output_tokens=11)
    assert team.calls[0]["task"] == "And C-2?"
    assert team.calls[0]["token"] is tokens[0]
    handoff = FakeAutoGenTeam(TaskResult([], "Handoff to user from triage detected."))
    paused = await AutoGenAdapter(handoff, cancellation_token_factory=factory).invoke(request())
    assert paused.status is RunStatus.INTERRUPTED


async def test_autogen_cancellation_propagates_to_token() -> None:
    token = FakeToken()
    adapter = AutoGenAdapter(FakeAutoGenTeam(hang=True), cancellation_token_factory=lambda: token)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.05):
            await adapter.invoke(request())
    assert token.cancelled


# ---------------------------------------------------------------- Google ADK


@dataclass
class Part:
    text: str | None = None


@dataclass
class Content:
    role: str
    parts: list[Part]


@dataclass
class UsageMetadata:
    prompt_token_count: int
    candidates_token_count: int


@dataclass
class Event:  # google.adk.events.Event shape
    author: str
    content: Content | None = None
    usage_metadata: UsageMetadata | None = None
    function_calls: list[Any] = field(default_factory=list)
    final: bool = False
    error_code: str | None = None
    long_running_tool_ids: set[str] | None = None

    def get_function_calls(self) -> list[Any]:
        return self.function_calls

    def is_final_response(self) -> bool:
        return self.final


class FakeSessionService:
    def __init__(self) -> None:
        self.sessions: set[tuple[str, str, str]] = set()

    async def get_session(self, *, app_name: str, user_id: str, session_id: str) -> Any:
        return (
            (app_name, user_id, session_id)
            if (app_name, user_id, session_id) in self.sessions
            else None
        )

    async def create_session(
        self, *, app_name: str, user_id: str, session_id: str | None = None
    ) -> Any:
        self.sessions.add((app_name, user_id, str(session_id)))
        return session_id


class FakeAdkRunner:
    app_name = "claims"

    def __init__(self, events: list[Event]) -> None:
        self.session_service = FakeSessionService()
        self.events = events
        self.messages: list[Any] = []

    async def _stream(self) -> AsyncIterator[Event]:
        for event in self.events:
            yield event

    def run_async(self, *, user_id: str, session_id: str, new_message: Any) -> AsyncIterator[Event]:
        self.messages.append((user_id, session_id, new_message))
        return self._stream()


def content(text: str) -> Content:
    return Content(role="user", parts=[Part(text=text)])


async def test_google_adk_adapter_creates_session_and_reads_final_event() -> None:
    runner = FakeAdkRunner(
        [
            Event("triage", function_calls=["claims.search"], usage_metadata=UsageMetadata(50, 5)),
            Event(
                "triage",
                content=Content("model", [Part("C-2 is "), Part("open.")]),
                final=True,
                usage_metadata=UsageMetadata(70, 9),
            ),
        ]
    )
    adapter = GoogleAdkAdapter(runner, content_factory=content)
    outcome = await adapter.invoke(request())
    assert outcome.output == "C-2 is open."
    assert outcome.tool_calls == 1
    assert outcome.usage == Usage(input_tokens=120, output_tokens=14)
    assert runner.session_service.sessions == {("claims", "platform", "conv-42")}
    assert runner.messages[0][2] == content("And C-2?")
    await adapter.invoke(request())  # existing session reused
    assert len(runner.session_service.sessions) == 1


async def test_google_adk_errors_pauses_and_step_budget() -> None:
    failing = FakeAdkRunner([Event("triage", error_code="SAFETY")])
    assert (
        await GoogleAdkAdapter(failing, content_factory=content).invoke(request())
    ).status is RunStatus.FAILED
    paused = FakeAdkRunner([Event("triage", long_running_tool_ids={"approval-1"})])
    outcome = await GoogleAdkAdapter(paused, content_factory=content).invoke(request())
    assert outcome.status is RunStatus.INTERRUPTED
    looping = FakeAdkRunner([Event("triage", function_calls=["x"] * 6) for _ in range(3)])
    budget = await GoogleAdkAdapter(looping, content_factory=content).invoke(request(max_steps=10))
    assert budget.status is RunStatus.FAILED
    assert budget.stop_reason == "step_budget_exceeded"


# --------------------------------------------------- Microsoft Agent Framework


@dataclass
class FunctionCallContent:
    name: str
    type: str = "function_call"


@dataclass
class MafMessage:
    contents: list[Any]


@dataclass
class UsageDetails:
    input_token_count: int
    output_token_count: int


@dataclass
class AgentRunResponse:
    text: str
    messages: list[MafMessage]
    usage_details: UsageDetails | None
    user_input_requests: list[Any] = field(default_factory=list)


class FakeMafAgent:
    def __init__(self, response: AgentRunResponse) -> None:
        self.response = response
        self.threads_created = 0
        self.calls: list[tuple[Any, Any]] = []

    def get_new_thread(self) -> Any:
        self.threads_created += 1
        return f"thread-{self.threads_created}"

    async def run(self, messages: Any = None, *, thread: Any = None) -> AgentRunResponse:
        self.calls.append((messages, thread))
        return self.response


async def test_microsoft_agent_framework_adapter_keeps_threads() -> None:
    agent = FakeMafAgent(
        AgentRunResponse(
            text="C-2 is open.",
            messages=[MafMessage([FunctionCallContent("claims_search"), {"type": "text"}])],
            usage_details=UsageDetails(80, 12),
        )
    )
    adapter = MicrosoftAgentFrameworkAdapter(agent, max_threads=1)
    outcome = await adapter.invoke(request())
    assert (outcome.output, outcome.tool_calls) == ("C-2 is open.", 1)
    assert outcome.usage == Usage(input_tokens=80, output_tokens=12)
    await adapter.invoke(request())
    assert agent.threads_created == 1  # same session, same thread
    await adapter.invoke(request(session_id="other"))
    await adapter.invoke(request())
    assert agent.threads_created == 3  # LRU of one evicted conv-42
    assert agent.calls[0] == ("And C-2?", "thread-1")
    pending = FakeMafAgent(AgentRunResponse("", [], None, user_input_requests=["approve"]))
    paused = await MicrosoftAgentFrameworkAdapter(pending).invoke(request())
    assert paused.status is RunStatus.INTERRUPTED


# ---------------------------------------------------------------- AWS Strands


@dataclass
class ToolMetrics:
    call_count: int


@dataclass
class EventLoopMetrics:
    accumulated_usage: dict[str, int]
    tool_metrics: dict[str, ToolMetrics]


@dataclass
class AgentResult:
    stop_reason: str
    message: dict[str, Any]
    metrics: EventLoopMetrics


class FakeStrandsAgent:
    def __init__(self, result: AgentResult) -> None:
        self.result = result
        self.prompts: list[Any] = []

    async def invoke_async(self, prompt: Any = None, **kwargs: Any) -> AgentResult:
        self.prompts.append(prompt)
        return self.result


@pytest.mark.parametrize(
    ("stop", "status"),
    [
        ("end_turn", RunStatus.COMPLETED),
        ("max_tokens", RunStatus.COMPLETED),
        ("interrupt", RunStatus.INTERRUPTED),
        ("guardrail_intervened", RunStatus.BLOCKED),
        ("cancelled", RunStatus.FAILED),
    ],
)
async def test_strands_adapter(stop: str, status: RunStatus) -> None:
    agent = FakeStrandsAgent(
        AgentResult(
            stop_reason=stop,
            message={
                "role": "assistant",
                "content": [{"text": "C-2 is open."}, {"toolUse": {"name": "x"}}],
            },
            metrics=EventLoopMetrics(
                {"inputTokens": 64, "outputTokens": 16, "totalTokens": 80},
                {"claims_search": ToolMetrics(2), "notify": ToolMetrics(1)},
            ),
        )
    )
    outcome = await StrandsAdapter(agent).invoke(request())
    assert outcome.status is status
    assert outcome.output == "C-2 is open."
    assert outcome.usage == Usage(input_tokens=64, output_tokens=16)
    assert outcome.tool_calls == 3
    assert agent.prompts == ["And C-2?"]
