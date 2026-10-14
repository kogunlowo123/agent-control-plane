"""Framework-neutral run contract and adapters for LangGraph, CrewAI, AutoGen,
Google ADK, Microsoft Agent Framework and AWS Strands."""

from agent_control_plane.adapters.autogen import AutoGenAdapter
from agent_control_plane.adapters.base import FrameworkAdapter
from agent_control_plane.adapters.contract import (
    AdapterOutcome,
    RunMessage,
    RunRequest,
    RunResult,
    RunStatus,
    Usage,
)
from agent_control_plane.adapters.crewai import CrewAIAdapter
from agent_control_plane.adapters.google_adk import GoogleAdkAdapter
from agent_control_plane.adapters.langgraph import LangGraphAdapter
from agent_control_plane.adapters.microsoft_agent_framework import MicrosoftAgentFrameworkAdapter
from agent_control_plane.adapters.runner import PlatformRunner
from agent_control_plane.adapters.strands import StrandsAdapter
from agent_control_plane.domain.models import Framework

ADAPTERS: dict[Framework, type] = {
    Framework.LANGGRAPH: LangGraphAdapter,
    Framework.CREWAI: CrewAIAdapter,
    Framework.AUTOGEN: AutoGenAdapter,
    Framework.GOOGLE_ADK: GoogleAdkAdapter,
    Framework.MICROSOFT_AGENT_FRAMEWORK: MicrosoftAgentFrameworkAdapter,
    Framework.AWS_STRANDS: StrandsAdapter,
}

__all__ = [
    "ADAPTERS",
    "AdapterOutcome",
    "AutoGenAdapter",
    "CrewAIAdapter",
    "FrameworkAdapter",
    "GoogleAdkAdapter",
    "LangGraphAdapter",
    "MicrosoftAgentFrameworkAdapter",
    "PlatformRunner",
    "RunMessage",
    "RunRequest",
    "RunResult",
    "RunStatus",
    "StrandsAdapter",
    "Usage",
]
