"""Benchmark: every target under four attack and patch strategies, scored by the held-out audit."""

from __future__ import annotations

import difflib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from redteam.agents.attacker import PlaybookAttacker, ScoutAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig, ArenaResult
from redteam.scout import scout_target
from redteam.targets import Target

ATTACKERS: tuple[str, ...] = ("adaptive", "one-shot", "white-box")
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
    probes_sent: int = 0
    scout_leads_left: int = 0
    loop_untested: bool = False

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
            "probes_sent": self.probes_sent,
            "scout_leads_left": self.scout_leads_left,
            "loop_untested": self.loop_untested,
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
        probes_sent=sum(summary.probes_sent for summary in result.rounds),
        scout_leads_left=len(scout_target(target, result.final_source)),
        loop_untested=result.untested,
    )


def _make_attacker(label: str, target: Target) -> PlaybookAttacker | ScoutAttacker:
    """The attacker for one benchmark label."""
    if label == "white-box":
        return ScoutAttacker(target)
    return PlaybookAttacker(target, adaptive=label == "adaptive")


def run_bench(targets: Sequence[Target], *, rounds: int = 6, budget: int = 40) -> list[BenchRow]:
    """Run every target under each attacker and patcher strategy and return one row per run."""
    config = ArenaConfig(rounds=rounds, budget=budget)
    rows: list[BenchRow] = []
    for target in targets:
        for attacker_label in ATTACKERS:
            for patcher_label in PATCHERS:
                attacker = _make_attacker(attacker_label, target)
                patcher = ReferencePatcher(target, skip_naive=patcher_label == "correct-first")
                result = Arena(attacker, patcher, target=target, config=config).run()
                rows.append(_row(target, attacker_label, patcher_label, result))
    return rows


def _headline(rows: Sequence[BenchRow]) -> str:
    """Sentences on false confidence and on the adaptive and white-box rows, from the rows."""
    parts = [
        _false_confidence_sentence(rows),
        _adaptive_sentence(rows),
        _white_box_sentence(rows),
        _untested_sentence(rows),
    ]
    return " ".join(part for part in parts if part)


def _untested_sentence(rows: Sequence[BenchRow]) -> str:
    """One sentence per target and attacker whose runs sent no probes, with the audit they got."""
    groups: dict[tuple[str, str], list[BenchRow]] = {}
    for row in rows:
        if row.loop_untested:
            groups.setdefault((row.target, row.attacker), []).append(row)
    sentences = []
    for (target, attacker), group in groups.items():
        audits = [row.audit_landed for row in group]
        total = group[0].audit_total
        low, high = min(audits), max(audits)
        landed = f"{low} of {total}" if low == high else f"{low} to {high} of {total}"
        sentences.append(
            f"On {target} the {attacker} attacker sent no probes, so those runs are reported "
            f"untested; the audit landed {landed} there."
        )
    return " ".join(sentences)


def _false_confidence_sentence(rows: Sequence[BenchRow]) -> str:
    """One sentence on runs that reported hardened while the audit still got in."""
    flagged = [row for row in rows if row.false_confidence]
    if not flagged:
        return "No run reported a hardened app that the audit could break into."
    combos = sorted({f"{row.attacker} with {row.patcher} fixes" for row in flagged})
    where = f"all of them {combos[0]}" if len(combos) == 1 else f"from {', '.join(combos)}"
    return (
        f"{len(flagged)} of {len(rows)} runs reported a hardened app that the audit still "
        f"broke into, {where}."
    )


def _adaptive_sentence(rows: Sequence[BenchRow]) -> str:
    """One sentence on the adaptive playbook runs that reported hardened."""
    adaptive = [row for row in rows if row.attacker == "adaptive" and row.loop_hardened]
    if not adaptive:
        return "No adaptive run reported hardened."
    if all(row.audit_landed == 0 for row in adaptive):
        return "Every adaptive run that reported hardened passed the audit."
    return "Some adaptive runs that reported hardened also failed the audit."


def _white_box_sentence(rows: Sequence[BenchRow]) -> str:
    """One sentence on the white-box runs: the audit verdict for those that reported hardened."""
    white = [row for row in rows if row.attacker == "white-box"]
    if not white:
        return ""
    hardened = [row for row in white if row.loop_hardened]
    if not hardened:
        return "No white-box run reported hardened."
    if all(row.audit_landed == 0 for row in hardened):
        return (
            "Every white-box run that reported hardened passed the audit, "
            "starting from no hand-written exploits."
        )
    return "Some white-box runs that reported hardened also failed the audit."


def render_scorecard(rows: Sequence[BenchRow]) -> str:
    """Render SCORECARD.md: the headline, one table row per run, and the exposure left behind."""
    totals: dict[str, int] = {}
    for row in rows:
        totals.setdefault(row.target, row.audit_total)
    totals_text = ", ".join(f"{name}: {total}" for name, total in totals.items())
    lines = [
        "# Benchmark scorecard",
        "",
        "Every target was attacked under six strategies: three attackers, each with two patchers. "
        "After each run, the held-out exploits the attacker never saw were replayed against the "
        f"final app ({totals_text}).",
        "",
        f"**Headline:** {_headline(rows)}",
        "",
        "| Target | Attacker | Patcher | Rounds | Probes sent | Exploits found "
        "| Bypasses caught | Patches | Lines changed | Loop says | Audit | Scout leads left "
        "| False confidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        loop = _loop_word(row)
        lines.append(
            f"| {row.target} | {row.attacker} | {row.patcher} | {row.rounds} | "
            f"{row.probes_sent} | {row.exploits_found} | {row.bypasses_caught} | "
            f"{row.patches_accepted} | {row.lines_changed} | {loop} | "
            f"{row.audit_landed} of {row.audit_total} landed | {row.scout_leads_left} | "
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
        '- "Probes sent" is the attack cost: every probe the attacker sent over the run.',
        '- "Scout leads left" counts the static leads the scout still sees in the final app. '
        "Zero means the scout agrees the app is fixed.",
        '- "False confidence" means the loop reported hardened while the audit still got in.',
        '- "untested" means the attacker sent no probes, so the loop tested nothing and the run is '
        "not reported hardened.",
    ]
    return "\n".join(lines) + "\n"


def _loop_word(row: BenchRow) -> str:
    """The loop's verdict for one row, as the scorecard and the CLI print it."""
    if row.loop_untested:
        return "untested"
    return "hardened" if row.loop_hardened else "not hardened"


def write_bench(out_dir: Path, rows: Sequence[BenchRow]) -> None:
    """Write SCORECARD.md and scorecard.json into `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "SCORECARD.md").write_text(render_scorecard(rows), encoding="utf-8")
    data = [row.to_dict() for row in rows]
    (out_dir / "scorecard.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
