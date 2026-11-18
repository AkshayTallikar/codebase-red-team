"""The LLM backend protocol and the errors every backend raises."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class LLMError(RuntimeError):
    """A backend could not produce a usable structured answer."""


class LLMRefusal(LLMError):
    """The model declined the request, optionally with a safety category."""

    def __init__(self, message: str, category: str | None = None) -> None:
        super().__init__(message)
        self.category = category


@runtime_checkable
class LLMBackend(Protocol):
    """Returns one JSON object that matches the given JSON schema."""

    name: str

    def complete_json(self, *, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Send a system prompt and a user prompt, and return the parsed JSON object."""
        ...
