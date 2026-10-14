"""The platform run contract every agent framework adapter implements.

A run is one request to a deployed agent: a conversation (messages),
optional structured parameters, limits (timeout, step budget) and the data
classification of what is being processed. The result is framework
independent: status, final output, token usage, tool-call count and the
framework's own stop reason.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from agentic_core.domain.classification import DataClassification
from agentic_core.domain.identifiers import new_id
from pydantic import BaseModel, ConfigDict, Field

from agent_control_plane.domain.models import Framework


class RunMessage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=100_000)


class RunRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(default_factory=new_id, pattern=r"^[A-Za-z0-9_\-]{8,64}$")
    deployment: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$")
    session_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_\-.:]{1,128}$", description="Conversation thread"
    )
    user_id: str = Field(default="platform", min_length=1, max_length=200)
    messages: tuple[RunMessage, ...] = Field(min_length=1, max_length=200)
    parameters: dict[str, Any] = Field(default_factory=dict, description="Structured inputs")
    timeout_s: float = Field(default=120.0, gt=0, le=3600)
    max_steps: int = Field(default=25, ge=1, le=500, description="Step / tool-call budget")
    classification: DataClassification = DataClassification.INTERNAL
    metadata: dict[str, str] = Field(default_factory=dict)

    @property
    def prompt(self) -> str:
        """The latest user message: what the agent is being asked now."""
        for message in reversed(self.messages):
            if message.role == "user":
                return message.content
        return self.messages[-1].content

    @property
    def thread(self) -> str:
        return self.session_id or self.run_id


class RunStatus(StrEnum):
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"  # waiting for human input (human-in-the-loop)
    BLOCKED = "blocked"  # kill switch, control plane unreachable, or content guard
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class Usage(BaseModel):
    model_config = ConfigDict(frozen=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


class AdapterOutcome(BaseModel):
    """What a framework adapter reports back for one invocation."""

    model_config = ConfigDict(frozen=True)

    status: RunStatus = RunStatus.COMPLETED
    output: str = ""
    usage: Usage = Usage()
    tool_calls: int = Field(default=0, ge=0)
    stop_reason: str = ""


class RunResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    deployment: str
    framework: Framework
    status: RunStatus
    output: str = ""
    usage: Usage = Usage()
    tool_calls: int = 0
    stop_reason: str = ""
    error: str | None = None
    findings: tuple[str, ...] = ()
    started_at: datetime
    duration_ms: float = Field(ge=0)
