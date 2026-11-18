"""Append-only event ledger: one JSON line per event, with secrets redacted."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

Redactor = Callable[[str], str]


class Ledger:
    """Keeps every event of a run in memory and, when given a directory, in events.jsonl."""

    def __init__(
        self,
        out_dir: str | Path | None = None,
        *,
        redact: Redactor | None = None,
    ) -> None:
        self.out_dir: Path | None = Path(out_dir) if out_dir is not None else None
        if self.out_dir is not None:
            self.out_dir.mkdir(parents=True, exist_ok=True)
        self._redact = redact
        self.events: list[dict[str, Any]] = []
        self.round = 0

    def log(self, kind: str, **data: Any) -> dict[str, Any]:
        """Record one event tagged with the current round, and return the stored record."""
        record = self._scrub(
            {"seq": len(self.events) + 1, "round": self.round, "kind": kind, **data}
        )
        self.events.append(record)
        if self.out_dir is not None:
            line = self._serialize(record)
            with (self.out_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return record

    def _scrub(self, value: Any) -> Any:
        """Redact every string inside a nested structure."""
        if self._redact is None:
            return value
        if isinstance(value, str):
            return self._redact(value)
        if isinstance(value, dict):
            return {key: self._scrub(item) for key, item in value.items()}
        if isinstance(value, list | tuple):
            return [self._scrub(item) for item in value]
        return value

    def _serialize(self, record: dict[str, Any]) -> str:
        """Render one record as JSON, redacting the whole line as a last safety net."""
        line = json.dumps(record, default=str)
        return self._redact(line) if self._redact is not None else line
