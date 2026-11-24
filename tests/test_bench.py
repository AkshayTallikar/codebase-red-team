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
from redteam.targets import BILLING, LIBRARY, NOTES, TARGETS, Target

TARGET_ORDER = ("notes", "billing", "library")


def _seed_finding(target: Target, key: str) -> Finding:
    """The finding that the first seed probe for `key` produces on the untouched seed app."""
    probe = next(p for p in target.seed_probes if f"{p.vuln_class}:{p.endpoint}" == key)
    with Sandbox(target=target) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, key
    return finding


@pytest.fixture(scope="module")
def rows() -> list[BenchRow]:
    return run_bench([NOTES, BILLING, LIBRARY])


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


def test_bench_covers_every_target_under_six_strategies(rows: list[BenchRow]) -> None:
    assert len(rows) == 18
    assert {row.target for row in rows} == set(TARGET_ORDER)
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
        for target in TARGET_ORDER
        for attacker in ("adaptive", "one-shot", "white-box")
        for patcher in ("naive-first", "correct-first")
    ]
    assert order == expected


def test_white_box_rows_use_the_scout_and_send_probes(rows: list[BenchRow]) -> None:
    white = [row for row in rows if row.attacker == "white-box" and row.target != "library"]
    assert len(white) == 4
    assert all(row.probes_sent > 0 for row in white)
    assert all(row.exploits_found > 0 for row in white)
    assert ScoutAttacker(NOTES).name == "white-box"


def test_white_box_correct_first_runs_end_hardened_with_no_leads(rows: list[BenchRow]) -> None:
    correct = [
        r
        for r in rows
        if r.attacker == "white-box" and r.patcher == "correct-first" and r.target != "library"
    ]
    assert len(correct) == 2
    assert all(row.loop_hardened and row.audit_landed == 0 for row in correct)
    assert all(row.scout_leads_left == 0 for row in correct)


def test_white_box_runs_on_library_are_untested_and_not_hardened(rows: list[BenchRow]) -> None:
    library = [r for r in rows if r.attacker == "white-box" and r.target == "library"]
    assert len(library) == 2
    assert all(row.loop_untested for row in library)
    assert all(row.probes_sent == 0 and row.exploits_found == 0 for row in library)
    assert all(not row.loop_hardened for row in library)
    # The scout finds no leads on library, so the loop never attacks it. The audit still lands.
    assert all(row.audit_landed == 10 and row.audit_total == 11 for row in library)


def test_only_library_white_box_runs_are_untested(rows: list[BenchRow]) -> None:
    untested = [row for row in rows if row.loop_untested]
    assert {(row.target, row.attacker) for row in untested} == {("library", "white-box")}


def test_adaptive_runs_are_hardened_and_pass_the_audit(rows: list[BenchRow]) -> None:
    adaptive = [row for row in rows if row.attacker == "adaptive"]
    assert len(adaptive) == 6
    assert all(row.loop_hardened for row in adaptive)
    assert all(row.audit_landed == 0 for row in adaptive)


def test_one_shot_naive_first_reports_hardened_while_the_audit_gets_in(
    rows: list[BenchRow],
) -> None:
    flagged = [r for r in rows if r.attacker == "one-shot" and r.patcher == "naive-first"]
    assert len(flagged) == 3
    assert all(row.loop_hardened and row.false_confidence for row in flagged)
    assert all(row.audit_landed > 0 for row in flagged)


def test_library_one_shot_naive_first_lets_five_held_out_exploits_in(
    rows: list[BenchRow],
) -> None:
    row = next(
        r
        for r in rows
        if (r.target, r.attacker, r.patcher) == ("library", "one-shot", "naive-first")
    )
    assert row.loop_hardened and row.false_confidence
    assert (row.audit_landed, row.audit_total) == (5, 11)
    assert row.scout_leads_left == 0
    assert set(row.exposed_classes) == {"auth_bypass", "path_traversal", "sqli"}


def test_false_confidence_appears_only_for_one_shot_naive_first(rows: list[BenchRow]) -> None:
    others = [r for r in rows if (r.attacker, r.patcher) != ("one-shot", "naive-first")]
    assert not any(row.false_confidence for row in others)


def test_correct_first_runs_catch_no_bypass(rows: list[BenchRow]) -> None:
    correct = [row for row in rows if row.patcher == "correct-first"]
    assert len(correct) == 9
    assert all(row.bypasses_caught == 0 for row in correct)


def test_untested_row_serialises_its_flag(rows: list[BenchRow]) -> None:
    library_white = next(
        row
        for row in rows
        if (row.target, row.attacker, row.patcher) == ("library", "white-box", "naive-first")
    )
    entry = library_white.to_dict()
    assert entry["loop_untested"] is True
    assert entry["loop_hardened"] is False
    assert entry["probes_sent"] == 0


def test_scorecard_has_the_table_header_and_headline(rows: list[BenchRow]) -> None:
    text = render_scorecard(rows)
    assert (
        "| Target | Attacker | Patcher | Rounds | Probes sent | Exploits found "
        "| Bypasses caught | Patches | Lines changed | Loop says | Audit | Scout leads left "
        "| False confidence |"
    ) in text
    assert "**Headline:** 3 of 18 runs reported a hardened app" in text
    assert "## Exposure left behind" in text
    assert "Every adaptive run that reported hardened passed the audit." in text
    assert "starting from no hand-written exploits." in text
    assert (
        "On library the white-box attacker sent no probes, so those runs are reported untested; "
        "the audit landed 10 of 11 there."
    ) in text
    assert "| library | white-box | naive-first | 1 | 0 | 0 | 0 | 0 | 0 | untested |" in text
    assert '- "Probes sent" is the attack cost' in text
    assert '- "Scout leads left" counts the static leads' in text
    assert '- "untested" means the attacker sent no probes' in text


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
    assert "untested" not in text.split("## Exposure left behind")[0]


def test_bench_command_writes_the_scorecard_and_json(tmp_path, capsys) -> None:
    assert main(["bench", "--out", str(tmp_path)]) == 0

    scorecard = (tmp_path / "SCORECARD.md").read_text(encoding="utf-8")
    assert "| notes | adaptive | naive-first |" in scorecard
    data = json.loads((tmp_path / "scorecard.json").read_text(encoding="utf-8"))
    assert len(data) == 6 * len(TARGETS)
    assert all("false_confidence" in entry for entry in data)
    assert all("probes_sent" in entry and "scout_leads_left" in entry for entry in data)
    assert all("loop_untested" in entry for entry in data)

    printed = capsys.readouterr().out.splitlines()
    assert "library white-box naive-first: untested, audit 10/11" in printed
    assert "library one-shot naive-first: hardened, audit 5/11 (false confidence)" in printed
