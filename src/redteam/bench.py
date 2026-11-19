"""Benchmark: every target under four attack and patch strategies, scored by the held-out audit."""

from __future__ import annotations

import difflib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig, ArenaResult
from redteam.targets import Target

ATTACKERS: tuple[str, ...] = ("adaptive", "one-shot")
PATCHERS: tuple[str, ...] = ("naive-first", "correct-first")


@dataclass(frozen=True)
class BenchRow:
    """One run of one target under one attacker and one patcher strategy."""

    target: str
    attacker: str
    patcher: str
    rounds: int
    exploits_found: int
    bypasses_caught: int
    patches_accepted: int
    lines_changed: int
    loop_hardened: bool
    audit_landed: int
    audit_total: int
    exposed_classes: tuple[str, ...]

    @property
    def false_confidence(self) -> bool:
        """The loop reported hardened while the audit still got in."""
        return self.loop_hardened and self.audit_landed > 0

    def to_dict(self) -> dict[str, Any]:
        """Plain data for scorecard.json."""
        return {
            "target": self.target,
            "attacker": self.attacker,
            "patcher": self.patcher,
            "rounds": self.rounds,
            "exploits_found": self.exploits_found,
            "bypasses_caught": self.bypasses_caught,
            "patches_accepted": self.patches_accepted,
            "lines_changed": self.lines_changed,
            "loop_hardened": self.loop_hardened,
            "audit_landed": self.audit_landed,
            "audit_total": self.audit_total,
            "exposed_classes": list(self.exposed_classes),
            "false_confidence": self.false_confidence,
        }


def _lines_changed(seed: str, final: str) -> int:
    """Count added and removed lines between the seed and the final source, headers excluded."""
    diff = difflib.unified_diff(seed.splitlines(), final.splitlines(), lineterm="")
    # The first two lines of a unified diff are the ---/+++ file headers.
    body = list(diff)[2:]
    return sum(1 for line in body if line[:1] in ("+", "-"))


def _row(target: Target, attacker: str, patcher: str, result: ArenaResult) -> BenchRow:
    """Summarise one finished run as a scorecard row."""
    if result.audit is None:
        raise RuntimeError("arena result carries no audit")
    return BenchRow(
        target=target.name,
        attacker=attacker,
        patcher=patcher,
        rounds=len(result.rounds),
        exploits_found=len(result.regressions),
        bypasses_caught=len(result.bypassed_keys),
        patches_accepted=sum(result.accepted_patches.values()),
        lines_changed=_lines_changed(target.load_source(), result.final_source),
        loop_hardened=result.hardened,
        audit_landed=result.audit.landed_count,
        audit_total=result.audit.total,
        exposed_classes=tuple(result.audit.exposed_classes),
    )


def run_bench(targets: Sequence[Target], *, rounds: int = 6, budget: int = 40) -> list[BenchRow]:
    """Run every target under each attacker and patcher strategy and return one row per run."""
    config = ArenaConfig(rounds=rounds, budget=budget)
    rows: list[BenchRow] = []
    for target in targets:
        for attacker_label in ATTACKERS:
            for patcher_label in PATCHERS:
                attacker = PlaybookAttacker(target, adaptive=attacker_label == "adaptive")
                patcher = ReferencePatcher(target, skip_naive=patcher_label == "correct-first")
                result = Arena(attacker, patcher, target=target, config=config).run()
                rows.append(_row(target, attacker_label, patcher_label, result))
    return rows


def _headline(rows: Sequence[BenchRow]) -> str:
    """One sentence on false confidence, computed from the rows."""
    flagged = [row for row in rows if row.false_confidence]
    if not flagged:
        return "No run reported a hardened app that the audit could break into."
    combos = sorted({f"{row.attacker} with {row.patcher} fixes" for row in flagged})
    where = f"all of them {combos[0]}" if len(combos) == 1 else f"from {', '.join(combos)}"
    sentence = (
        f"{len(flagged)} of {len(rows)} runs reported a hardened app that the audit still "
        f"broke into, {where}."
    )
    adaptive = [row for row in rows if row.attacker == "adaptive" and row.loop_hardened]
    if not adaptive:
        return sentence + " No adaptive run reported hardened."
    if all(row.audit_landed == 0 for row in adaptive):
        return sentence + " Every adaptive run that reported hardened passed the audit."
    return sentence + " Some adaptive runs that reported hardened also failed the audit."


def render_scorecard(rows: Sequence[BenchRow]) -> str:
    """Render SCORECARD.md: the headline, one table row per run, and the exposure left behind."""
    totals: dict[str, int] = {}
    for row in rows:
        totals.setdefault(row.target, row.audit_total)
    totals_text = ", ".join(f"{name}: {total}" for name, total in totals.items())
    lines = [
        "# Benchmark scorecard",
        "",
        "Every target was attacked under four strategies. After each run, the held-out exploits "
        "the attacker never saw were replayed against the final app "
        f"({totals_text}).",
        "",
        f"**Headline:** {_headline(rows)}",
        "",
        "| Target | Attacker | Patcher | Rounds | Exploits found | Bypasses caught | Patches "
        "| Lines changed | Loop says | Audit | False confidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        loop = "hardened" if row.loop_hardened else "not hardened"
        lines.append(
            f"| {row.target} | {row.attacker} | {row.patcher} | {row.rounds} | "
            f"{row.exploits_found} | {row.bypasses_caught} | {row.patches_accepted} | "
            f"{row.lines_changed} | {loop} | {row.audit_landed} of {row.audit_total} landed | "
            f"{'yes' if row.false_confidence else 'no'} |"
        )

    lines += ["", "## Exposure left behind", ""]
    exposed = [row for row in rows if row.audit_landed > 0]
    if not exposed:
        lines.append("None: every final app passed the audit.")
    for row in exposed:
        classes = ", ".join(row.exposed_classes)
        lines.append(
            f"- `{row.target}`, {row.attacker}, {row.patcher}: {classes} still exploitable."
        )

    lines += [
        "",
        "## How to read this",
        "",
        '- "Loop says" is the arena\'s own verdict: whether every weakness it found was closed.',
        '- "Audit" replays held-out exploits that the attacker never saw against the final app.',
        '- "False confidence" means the loop reported hardened while the audit still got in.',
    ]
    return "\n".join(lines) + "\n"


def write_bench(out_dir: Path, rows: Sequence[BenchRow]) -> None:
    """Write SCORECARD.md and scorecard.json into `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "SCORECARD.md").write_text(render_scorecard(rows), encoding="utf-8")
    data = [row.to_dict() for row in rows]
    (out_dir / "scorecard.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
