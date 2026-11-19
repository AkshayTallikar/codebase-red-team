"""The Target value: everything the loop needs to know about one app under attack."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from redteam.models import FixAttempt, FunctionalCheck, Probe


@dataclass(frozen=True)
class Target:
    """One deliberately vulnerable app, plus the playbook and fixes that go with it."""

    name: str
    description: str
    seed_path: Path
    vuln_classes: tuple[str, ...]
    attacker_token: str
    user_token: str
    functional_checks: tuple[FunctionalCheck, ...]
    seed_probes: tuple[Probe, ...]
    fix_catalog: Mapping[str, tuple[FixAttempt, ...]]
    patch_guidance: str
    write_data: Callable[[Path, str], None]
    audit_probes: tuple[Probe, ...] = ()
    isolate_probes: bool = False

    def load_source(self) -> str:
        """Return the source text of the seed app."""
        return self.seed_path.read_text(encoding="utf-8")
