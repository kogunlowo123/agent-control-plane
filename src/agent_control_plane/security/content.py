"""Free-text and configuration screening with the agentic-core ContentGuard.

Reasons, comments and descriptions end up in the audit chain and in
Kubernetes objects; deployment environment values end up in pod specs.
Neither may carry credentials (those belong in a secret store), and
personal data in free text is redacted before it is persisted.
"""

from __future__ import annotations

from collections.abc import Mapping

from agentic_core.security import ContentGuard, SecretScanner

from agent_control_plane.domain.errors import UnsafeContentError


class TextScreen:
    def __init__(self, guard: ContentGuard | None = None) -> None:
        self._guard = guard or ContentGuard()
        self._secrets = SecretScanner()

    def free_text(self, field: str, text: str) -> str:
        """Block credential material; return the text with PII redacted."""
        result = self._guard.inspect_output(text)
        if result.blocked:
            raise UnsafeContentError(f"{field} contains credential material")
        return result.text if result.text is not None else text

    def config_values(self, values: Mapping[str, str]) -> None:
        """Configuration may not inline credentials; reference a secret instead."""
        for key, value in values.items():
            if self._secrets.detect(value):
                raise UnsafeContentError(
                    f"env {key} contains credential material; mount it from a secret store"
                )
