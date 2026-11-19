"""Attack and patch strategies, the one-shot replay, and the benchmark scorecard."""

from __future__ import annotations

import json

import pytest

from redteam.agents.attacker import PlaybookAttacker, ScoutAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import STOP_CLEAN, Arena
from redteam.bench import BenchRow, render_scorecard, run_bench
from redteam.cli import main
from redteam.models import Finding
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox
from redteam.targets import BILLING, NOTES, TARGETS, Target


def _seed_finding(target: Target, key: str) -> Finding:
    """The finding that the first seed probe for `key` produces on the untouched seed app."""
    probe = next(p for p in target.seed_probes if f"{p.vuln_class}:{p.endpoint}" == key)
    with Sandbox(target=target) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, key
    return finding


@pytest.fixture(scope="module")
def rows() -> list[BenchRow]:
    return run_bench([NOTES, BILLING])


def test_one_shot_attacker_resends_the_seeds_and_stops_clean() -> None:
    attacker = PlaybookAttacker(NOTES, adaptive=False)
    assert attacker.name == "one-shot"
    result = Arena(attacker, ReferencePatcher(NOTES), target=NOTES).run()

    assert result.stop_reason == STOP_CLEAN
    assert len(result.rounds) == 2
    assert result.rounds[1].probes_sent == len(NOTES.seed_probes)
    assert result.rounds[1].findings == []


def test_adaptive_attacker_keeps_its_name_and_mutates() -> None:
    attacker = PlaybookAttacker(NOTES)
    assert attacker.name == "playbook"
    result = Arena(attacker, ReferencePatcher(NOTES), target=NOTES).run()
    assert len(result.rounds) > 2


def test_correct_first_sqli_fix_is_the_parameterised_query() -> None:
    finding = _seed_finding(NOTES, "sqli:GET /notes/search")
    patch = ReferencePatcher(NOTES, skip_naive=True).propose(finding, NOTES.load_source(), 0)

    assert patch is not None
    assert "parameterised" in patch.rationale
    assert patch.author == "reference-correct-first"


def test_naive_first_sqli_fix_is_the_keyword_block() -> None:
    finding = _seed_finding(NOTES, "sqli:GET /notes/search")
    patch = ReferencePatcher(NOTES).propose(finding, NOTES.load_source(), 0)

    assert patch is not None
    assert "OR keyword" in patch.rationale
    assert patch.author == "reference"


def test_bench_covers_both_targets_under_six_strategies(rows: list[BenchRow]) -> None:
    assert len(rows) == 12
    assert {row.target for row in rows} == {"notes", "billing"}
    combos = {(row.attacker, row.patcher) for row in rows}
    assert combos == {
        (attacker, patcher)
        for attacker in ("adaptive", "one-shot", "white-box")
        for patcher in ("naive-first", "correct-first")
    }


def test_bench_rows_are_ordered_per_target_then_attacker_then_patcher(
    rows: list[BenchRow],
) -> None:
    order = [(row.target, row.attacker, row.patcher) for row in rows]
    expected = [
        (target, attacker, patcher)
        for target in ("notes", "billing")
        for attacker in ("adaptive", "one-shot", "white-box")
        for patcher in ("naive-first", "correct-first")
    ]
    assert order == expected


def test_white_box_rows_use_the_scout_and_send_probes(rows: list[BenchRow]) -> None:
    white = [row for row in rows if row.attacker == "white-box"]
    assert len(white) == 4
    assert all(row.probes_sent > 0 for row in white)
    assert all(row.exploits_found > 0 for row in white)
    assert ScoutAttacker(NOTES).name == "white-box"


def test_white_box_correct_first_runs_end_hardened_with_no_leads(rows: list[BenchRow]) -> None:
    correct = [r for r in rows if r.attacker == "white-box" and r.patcher == "correct-first"]
    assert len(correct) == 2
    assert all(row.loop_hardened and row.audit_landed == 0 for row in correct)
    assert all(row.scout_leads_left == 0 for row in correct)


def test_adaptive_runs_are_hardened_and_pass_the_audit(rows: list[BenchRow]) -> None:
    adaptive = [row for row in rows if row.attacker == "adaptive"]
    assert len(adaptive) == 4
    assert all(row.loop_hardened for row in adaptive)
    assert all(row.audit_landed == 0 for row in adaptive)


def test_one_shot_naive_first_reports_hardened_while_the_audit_gets_in(
    rows: list[BenchRow],
) -> None:
    flagged = [r for r in rows if r.attacker == "one-shot" and r.patcher == "naive-first"]
    assert len(flagged) == 2
    assert all(row.loop_hardened and row.false_confidence for row in flagged)
    assert all(row.audit_landed > 0 for row in flagged)


def test_false_confidence_appears_only_for_one_shot_naive_first(rows: list[BenchRow]) -> None:
    others = [r for r in rows if (r.attacker, r.patcher) != ("one-shot", "naive-first")]
    assert not any(row.false_confidence for row in others)


def test_correct_first_runs_catch_no_bypass(rows: list[BenchRow]) -> None:
    correct = [row for row in rows if row.patcher == "correct-first"]
    assert len(correct) == 6
    assert all(row.bypasses_caught == 0 for row in correct)


def test_scorecard_has_the_table_header_and_headline(rows: list[BenchRow]) -> None:
    text = render_scorecard(rows)
    assert (
        "| Target | Attacker | Patcher | Rounds | Probes sent | Exploits found "
        "| Bypasses caught | Patches | Lines changed | Loop says | Audit | Scout leads left "
        "| False confidence |"
    ) in text
    assert "**Headline:** 2 of 12 runs reported a hardened app" in text
    assert "## Exposure left behind" in text
    assert "Every adaptive run that reported hardened passed the audit." in text
    assert "starting from no hand-written exploits." in text
    assert '- "Probes sent" is the attack cost' in text
    assert '- "Scout leads left" counts the static leads' in text


def test_headline_says_so_when_no_run_has_false_confidence() -> None:
    row = BenchRow(
        target="notes",
        attacker="adaptive",
        patcher="correct-first",
        rounds=2,
        exploits_found=4,
        bypasses_caught=0,
        patches_accepted=4,
        lines_changed=24,
        loop_hardened=True,
        audit_landed=0,
        audit_total=10,
        exposed_classes=(),
    )
    text = render_scorecard([row])
    assert "No run reported a hardened app that the audit could break into." in text
    assert "None: every final app passed the audit." in text


def test_bench_command_writes_the_scorecard_and_json(tmp_path) -> None:
    assert main(["bench", "--out", str(tmp_path)]) == 0

    scorecard = (tmp_path / "SCORECARD.md").read_text(encoding="utf-8")
    assert "| notes | adaptive | naive-first |" in scorecard
    data = json.loads((tmp_path / "scorecard.json").read_text(encoding="utf-8"))
    assert len(data) == 6 * len(TARGETS)
    assert all("false_confidence" in entry for entry in data)
    assert all("probes_sent" in entry and "scout_leads_left" in entry for entry in data)
