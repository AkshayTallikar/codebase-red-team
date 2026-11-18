"""A scripted backend for tests of the LLM-driven agents."""

from __future__ import annotations

import copy
from collections import deque
from collections.abc import Iterable
from typing import Any

from redteam.llm.base import LLMError


class FakeBackend:
    """Returns queued responses in order and records every call it receives."""

    name = "fake"

    def __init__(self, responses: Iterable[dict[str, Any] | Exception] = ()) -> None:
        self._queue: deque[dict[str, Any] | Exception] = deque(responses)
        self.calls: list[dict[str, Any]] = []

    def queue(self, response: dict[str, Any] | Exception) -> None:
        """Add one response (or an exception to raise) to the end of the queue."""
        self._queue.append(response)

    def complete_json(self, *, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Record the call, then return a copy of the next queued response."""
        self.calls.append({"system": system, "prompt": prompt, "schema": schema})
        if not self._queue:
            raise LLMError("FakeBackend has no queued responses")
        item = self._queue.popleft()
        if isinstance(item, Exception):
            raise item
        return copy.deepcopy(item)
