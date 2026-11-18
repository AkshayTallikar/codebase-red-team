"""Pluggable LLM backends for the attacker and patcher agents."""

from __future__ import annotations

from redteam.llm.anthropic_backend import DEFAULT_MODEL, AnthropicBackend
from redteam.llm.base import LLMBackend, LLMError, LLMRefusal
from redteam.llm.fake import FakeBackend

__all__ = [
    "DEFAULT_MODEL",
    "AnthropicBackend",
    "FakeBackend",
    "LLMBackend",
    "LLMError",
    "LLMRefusal",
    "make_backend",
]

_BACKEND_NAMES = ("offline", "anthropic")


def make_backend(name: str, model: str | None = None) -> LLMBackend | None:
    """Return the backend called `name`, or None for offline mode (no LLM)."""
    if name == "offline":
        return None
    if name == "anthropic":
        return AnthropicBackend(model or DEFAULT_MODEL)
    valid = ", ".join(_BACKEND_NAMES)
    raise ValueError(f"unknown LLM backend {name!r}; valid names are: {valid}")
