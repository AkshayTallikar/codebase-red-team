"""Held-out audit: replays a target's audit probes against a final app, each in a fresh copy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redteam.models import Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox
from redteam.targets import Target


@dataclass(frozen=True)
class AuditResult:
    """Which held-out exploits still get in. `landed` maps vuln class to the probes that landed."""

    target: str
    total: int
    landed: dict[str, list[Probe]] = field(default_factory=dict)

    @property
    def exposed_classes(self) -> list[str]:
        """Sorted vulnerability classes with at least one landed probe."""
        return sorted(cls for cls, probes in self.landed.items() if probes)

    @property
    def landed_count(self) -> int:
        """Number of audit probes that landed, across all classes."""
        return sum(len(probes) for probes in self.landed.values())

    @property
    def clean(self) -> bool:
        """True when no audit probe landed."""
        return self.landed_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Plain data for summary.json."""
        return {
            "target": self.target,
            "total": self.total,
            "landed_count": self.landed_count,
            "clean": self.clean,
            "exposed_classes": self.exposed_classes,
            "landed": {
                cls: [probe.to_dict() for probe in probes]
                for cls, probes in sorted(self.landed.items())
                if probes
            },
        }


def audit(source: str, target: Target) -> AuditResult:
    """Replay every audit probe of `target` against `source`, resetting the app before each one.

    Raises TargetLoadError if `source` does not load.
    """
    landed: dict[str, list[Probe]] = {}
    total = 0
    with Sandbox(source, target=target) as sandbox:
        oracle = Oracle(sandbox.canary)
        for probe in target.audit_probes:
            sandbox.reset()
            total += 1
            if oracle.judge(sandbox.send(probe)) is not None:
                landed.setdefault(probe.vuln_class, []).append(probe)
    return AuditResult(target=target.name, total=total, landed=landed)
