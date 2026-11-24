"""Arena, ledger, report and CLI behaviour, end to end on the offline agents."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import (
    Arena,
    ArenaConfig,
    ArenaResult,
    PatchOutcome,
    RoundSummary,
    render_report,
)
from redteam.cli import main
from redteam.ledger import Ledger
from redteam.models import Edit, Finding, Patch, Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox

SQLI_KEY = "sqli:GET /notes/search"
IDOR_KEY = "idor:GET /notes/{note_id}"
TRAVERSAL_KEY = "path_traversal:GET /files"
CRASH_KEY = "crash:GET /notes"
ALL_KEYS = {SQLI_KEY, IDOR_KEY, TRAVERSAL_KEY, CRASH_KEY}


class NoFixPatcher:
    """A patcher that never proposes anything."""

    name = "none"

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        return None


class BreakingPatcher:
    """Fixes everything with the reference catalog, except the idor weakness.

    For idor it proposes a patch that makes every note read return 404, which
    the gate must reject because alice can no longer read her own notes.
    """

    name = "breaking"

    def __init__(self) -> None:
        self._reference = ReferencePatcher()

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        if finding.key != IDOR_KEY:
            return self._reference.propose(finding, source, attempt)
        edit = Edit(
            old="    def get_note(note_id: int, user: User):\n",
            new=(
                "    def get_note(note_id: int, user: User):\n"
                '        raise HTTPException(status_code=404, detail="gone")\n'
            ),
        )
        return Patch(
            finding_key=finding.key,
            edits=(edit,),
            rationale="Disable note reads.",
            author=self.name,
        )


@pytest.fixture(scope="module")
def offline_result(tmp_path_factory: pytest.TempPathFactory) -> tuple[ArenaResult, Path]:
    out = tmp_path_factory.mktemp("offline") / "run"
    arena = Arena(PlaybookAttacker(), ReferencePatcher(), out_dir=out)
    return arena.run(), out


def test_offline_arena_hardens_the_target(offline_result: tuple[ArenaResult, Path]) -> None:
    result, _ = offline_result
    assert result.hardened
    assert result.stop_reason == "clean_round"
    assert result.rounds[-1].findings == []
    assert result.accepted_patches == {
        SQLI_KEY: 2,
        TRAVERSAL_KEY: 2,
        IDOR_KEY: 1,
        CRASH_KEY: 1,
    }


def test_round_two_shows_the_sqli_and_traversal_bypasses(
    offline_result: tuple[ArenaResult, Path],
) -> None:
    result, _ = offline_result
    keys = {finding.key for finding in result.rounds[1].findings}
    assert {SQLI_KEY, TRAVERSAL_KEY} <= keys


def test_final_source_contains_the_correct_fixes(offline_result: tuple[ArenaResult, Path]) -> None:
    result, _ = offline_result
    assert "LIKE ?" in result.final_source
    assert "realpath" in result.final_source
    assert 'replace("../", "")' not in result.final_source
    assert '" OR " in q' not in result.final_source


def test_every_regression_probe_is_blocked_on_the_final_source(
    offline_result: tuple[ArenaResult, Path],
) -> None:
    result, _ = offline_result
    assert set(result.regressions) == ALL_KEYS
    with Sandbox(result.final_source) as sandbox:
        oracle = Oracle(sandbox.canary)
        for probes in result.regressions.values():
            for probe in probes:
                assert oracle.judge(sandbox.send(probe)) is None, probe


def test_output_files_are_written(offline_result: tuple[ArenaResult, Path]) -> None:
    _, out = offline_result
    for name in (
        "events.jsonl",
        "regressions.json",
        "summary.json",
        "final_app.py",
        "ARMS_RACE.md",
    ):
        assert (out / name).is_file(), name

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["hardened"] is True
    assert summary["stop_reason"] == "clean_round"


def test_no_output_file_contains_the_canary(offline_result: tuple[ArenaResult, Path]) -> None:
    _, out = offline_result
    for path in out.iterdir():
        assert "CANARY-" not in path.read_text(encoding="utf-8"), path.name


def test_report_has_scoreboard_with_bypassed_sqli(
    offline_result: tuple[ArenaResult, Path],
) -> None:
    _, out = offline_result
    report = (out / "ARMS_RACE.md").read_text(encoding="utf-8")
    assert "Scoreboard" in report
    sqli_row = next(line for line in report.splitlines() if f"`{SQLI_KEY}`" in line)
    assert "| yes |" in sqli_row


def test_events_are_one_json_object_per_line(offline_result: tuple[ArenaResult, Path]) -> None:
    _, out = offline_result
    events = [
        json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    kinds = [event["kind"] for event in events]
    assert kinds[0] == "run_started"
    assert kinds[-1] == "run_finished"
    assert "bypass" in kinds
    assert "patch_accepted" in kinds


def test_patcher_with_no_fix_leaves_every_weakness_open() -> None:
    result = Arena(PlaybookAttacker(), NoFixPatcher(), config=ArenaConfig(rounds=3)).run()
    assert not result.hardened
    assert set(result.open_findings) == ALL_KEYS
    assert result.stop_reason in ("round_limit", "attacker_exhausted")
    assert result.accepted_patches == {}
    for summary in result.rounds:
        assert all(not outcome.accepted for outcome in summary.outcomes)


def test_gate_rejects_a_patch_that_breaks_alice_and_keeps_idor_open() -> None:
    result = Arena(PlaybookAttacker(), BreakingPatcher(), config=ArenaConfig(rounds=3)).run()
    assert IDOR_KEY in result.open_findings
    assert IDOR_KEY not in result.accepted_patches
    rejected = [
        outcome
        for summary in result.rounds
        for outcome in summary.outcomes
        if outcome.key == IDOR_KEY
    ]
    assert rejected
    assert all(not outcome.accepted for outcome in rejected)
    assert any("functional check failed" in reason for reason in rejected[0].reasons)


def test_render_report_escapes_pipes_in_probe_values() -> None:
    probe = Probe(
        "GET",
        "/notes/search",
        "GET /notes/search",
        vuln_class="sqli",
        params={"q": "a|b"},
    )
    finding = Finding(
        kind="leak",
        vuln_class="sqli",
        endpoint="GET /notes/search",
        probe=probe,
        status=200,
        evidence="",
    )
    result = ArenaResult(
        rounds=[
            RoundSummary(
                number=1,
                probes_sent=1,
                findings=[finding],
                outcomes=[
                    PatchOutcome(
                        key=finding.key,
                        attempt=0,
                        patch=None,
                        accepted=False,
                        reasons=("patcher has no fix",),
                    )
                ],
                probes_landed=1,
            )
        ],
        final_source="",
        regressions={finding.key: [probe]},
        accepted_patches={},
        open_findings={finding.key: finding},
        stop_reason="round_limit",
    )
    report = render_report(result, "playbook", "none")
    assert 'q="a\\|b"' in report
    assert "| `a|b`" not in report


def test_ledger_redacts_the_canary_in_strings_and_lines(tmp_path: Path) -> None:
    canary = "CANARY-deadbeefdeadbeef"
    ledger = Ledger(tmp_path, redact=lambda text: text.replace(canary, "[CANARY]"))
    record = ledger.log("probe", note=f"saw {canary}", nested={"items": [canary]})
    assert canary not in json.dumps(record)
    assert canary not in (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert record["kind"] == "probe"
    assert ledger.events == [record]


def test_cli_run_returns_zero_and_writes_report(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert main(["run", "--out", str(out)]) == 0
    assert (out / "ARMS_RACE.md").is_file()


def test_cli_anthropic_backend_failure_returns_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(sys.modules, "anthropic", None)
    code = main(["run", "--backend", "anthropic", "--out", str(tmp_path / "run")])
    assert code == 2
    assert "anthropic" in capsys.readouterr().err


class SilentAttacker:
    """An attacker whose plan is always empty, so it never sends a probe."""

    name = "silent"

    def plan(self, routes: list[str], history, budget: int) -> list[Probe]:
        return []


def test_attacker_that_sends_no_probes_is_untested_not_hardened(tmp_path: Path) -> None:
    out = tmp_path / "run"
    result = Arena(
        SilentAttacker(), ReferencePatcher(), config=ArenaConfig(rounds=3), out_dir=out
    ).run()

    assert result.untested
    assert not result.hardened
    assert result.stop_reason == "attacker_exhausted"

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["untested"] is True
    assert summary["hardened"] is False

    events = [
        json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    finished = events[-1]
    assert finished["kind"] == "run_finished"
    assert finished["untested"] is True
    assert finished["hardened"] is False


def test_report_names_the_untested_verdict_and_says_nothing_was_tested(tmp_path: Path) -> None:
    out = tmp_path / "run"
    Arena(SilentAttacker(), ReferencePatcher(), config=ArenaConfig(rounds=3), out_dir=out).run()

    report = (out / "ARMS_RACE.md").read_text(encoding="utf-8")
    assert "Result: untested, 0 open" in report
    assert "The attacker sent no probes, so nothing was tested." in report
    assert "Result: hardened" not in report


def test_cli_prints_untested_for_a_white_box_run_that_finds_no_leads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "run"
    code = main(["run", "--target", "library", "--attacker", "white-box", "--out", str(out)])

    assert code == 1
    printed = capsys.readouterr().out
    assert (
        f"result: untested, the attacker sent no probes after 1 rounds "
        f"(stopped: attacker_exhausted). output: {out}"
    ) in printed
    assert "result: hardened" not in printed
