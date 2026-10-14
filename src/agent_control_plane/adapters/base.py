"""Adapter protocol and helpers shared by the framework adapters.

Adapters depend only on the *shape* of each framework's invocation API
(structural typing), not on the framework packages, so the control plane
ships without six agent frameworks installed and each agent image brings
the one it uses.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from agent_control_plane.adapters.contract import AdapterOutcome, RunRequest
from agent_control_plane.domain.models import Framework


class FrameworkAdapter(Protocol):
    framework: Framework

    async def invoke(self, request: RunRequest) -> AdapterOutcome: ...


def field(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from an attribute-style object or a mapping."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def text_of(content: Any) -> str:
    """Flatten message content: a string, or a list of content blocks/parts with text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        value = content.get("text")
        return value if isinstance(value, str) else ""
    if isinstance(content, Iterable):
        texts: list[str] = []
        for block in content:
            if isinstance(block, str):
                texts.append(block)
                continue
            value = field(block, "text")
            if isinstance(value, str):
                texts.append(value)
        return "".join(texts)
    return str(content)


def as_int(value: Any) -> int:
    return int(value) if isinstance(value, int | float) and value >= 0 else 0
