"""Decides whether a probe result counts as a successful exploit."""

from __future__ import annotations

from typing import Literal

from redteam.models import Finding, ProbeResult

REDACTED = "[CANARY]"
EVIDENCE_LIMIT = 200


class Oracle:
    """Leak oracle (canary in the response) and crash oracle (any 5xx)."""

    def __init__(self, canary: str) -> None:
        self.canary = canary

    def redact(self, text: str) -> str:
        """Replace every occurrence of the canary so it never reaches a report."""
        return text.replace(self.canary, REDACTED)

    def judge(self, result: ProbeResult) -> Finding | None:
        """Return a Finding if the response leaks the canary or crashes, else None."""
        kind: Literal["leak", "crash"]
        if self.canary in result.body:
            kind = "leak"
        elif result.status >= 500:
            kind = "crash"
        else:
            return None

        vuln_class = result.probe.vuln_class
        if kind == "crash" and vuln_class == "unknown":
            vuln_class = "crash"

        return Finding(
            kind=kind,
            vuln_class=vuln_class,
            endpoint=result.probe.endpoint,
            probe=result.probe,
            status=result.status,
            evidence=self.redact(result.body)[:EVIDENCE_LIMIT],
        )
