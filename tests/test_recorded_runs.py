"""The committed recorded runs must stay honest: each hardened app blocks every recorded exploit.

Each recorded run is regenerated offline, so these tests also check that the recording
matches a fresh Arena run and that the benchmark scorecard matches its rows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker, ScoutAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig, ArenaResult
from redteam.audit import audit
from redteam.bench import run_bench
from redteam.cli import DEFAULT_BUDGET, DEFAULT_ROUNDS
from redteam.models import Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox
from redteam.targets import BILLING, NOTES, Target
from redteam.timeline import build_timeline, render_svg

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
CANARY_PATTERN = re.compile(rb"CANARY-[0-9a-f]{16}")
RUNS = [("notes-run", NOTES), ("billing-run", BILLING), ("billing-whitebox-run", BILLING)]
# The attacker each recording was made with, as the CLI names it.
ATTACKER = {"notes-run": "playbook", "billing-run": "playbook", "billing-whitebox-run": "white-box"}


def _regressions(run: str) -> dict[str, list[Probe]]:
    data = json.loads((EXAMPLES / run / "regressions.json").read_text(encoding="utf-8"))
    return {key: [Probe.from_dict(p) for p in group] for key, group in data.items()}


@pytest.fixture(scope="module")
def fresh_runs() -> dict[str, ArenaResult]:
    """One offline Arena run per recording, shared by every test in this module."""
    runs = {}
    for run, target in RUNS:
        attacker = (
            ScoutAttacker(target) if ATTACKER[run] == "white-box" else PlaybookAttacker(target)
        )
        runs[run] = Arena(
            attacker,
            ReferencePatcher(target),
            target=target,
            config=ArenaConfig(rounds=DEFAULT_ROUNDS, budget=DEFAULT_BUDGET),
        ).run()
    return runs


@pytest.fixture(scope="module")
def bench_rows() -> list[dict]:
    """One benchmark over both targets, shared by every test in this module."""
    rows = run_bench([NOTES, BILLING], rounds=DEFAULT_ROUNDS, budget=DEFAULT_BUDGET)
    return [row.to_dict() for row in rows]


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_summary_says_hardened(run: str, target: Target) -> None:
    summary = json.loads((EXAMPLES / run / "summary.json").read_text(encoding="utf-8"))
    assert summary["hardened"] is True
    assert summary["open_keys"] == []
    assert summary["target"] == target.name
    assert summary["audit"]["clean"] is True


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_every_recorded_exploit_is_blocked_by_the_final_app(run: str, target: Target) -> None:
    probes = [probe for group in _regressions(run).values() for probe in group]
    assert probes
    final_source = (EXAMPLES / run / "final_app.py").read_text(encoding="utf-8")

    with Sandbox(final_source, target=target) as sandbox:
        oracle = Oracle(sandbox.canary)
        for probe in probes:
            sandbox.reset()
            assert oracle.judge(sandbox.send(probe)) is None, probe


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_first_exploit_per_weakness_lands_on_the_seed_app(run: str, target: Target) -> None:
    # Later probes in a group are bypasses of naive fixes, so only the first one
    # is expected to work against the untouched seed.
    groups = _regressions(run)
    assert groups
    with Sandbox(target=target) as sandbox:
        oracle = Oracle(sandbox.canary)
        for key, group in groups.items():
            assert oracle.judge(sandbox.send(group[0])) is not None, key


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_final_app_still_serves_normal_use(run: str, target: Target) -> None:
    final_source = (EXAMPLES / run / "final_app.py").read_text(encoding="utf-8")
    with Sandbox(final_source, target=target) as sandbox:
        for check in target.functional_checks:
            result = sandbox.send(check.probe, token=target.user_token)
            assert result.status == check.expect_status, check.name
            if check.expect_text is not None:
                assert check.expect_text in result.body, check.name


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_final_app_passes_the_independent_audit(run: str, target: Target) -> None:
    final_source = (EXAMPLES / run / "final_app.py").read_text(encoding="utf-8")
    assert audit(final_source, target).clean is True


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_final_app_matches_a_fresh_offline_run(
    run: str, target: Target, fresh_runs: dict[str, ArenaResult]
) -> None:
    recorded = (EXAMPLES / run / "final_app.py").read_text(encoding="utf-8")
    assert recorded == fresh_runs[run].final_source


@pytest.mark.parametrize(("run", "target"), RUNS, ids=[name for name, _ in RUNS])
def test_timeline_matches_a_fresh_offline_run(
    run: str, target: Target, fresh_runs: dict[str, ArenaResult]
) -> None:
    # Offline runs name the patcher "reference"; the attacker name depends on the recording.
    title = f"Arms race on {target.name}: {ATTACKER[run]} vs reference"
    recorded = (EXAMPLES / run / "timeline.svg").read_text(encoding="utf-8")
    assert recorded == render_svg(build_timeline(fresh_runs[run]), title=title)


def test_bench_scorecard_matches_its_rows(bench_rows: list[dict]) -> None:
    recorded = json.loads((EXAMPLES / "bench" / "scorecard.json").read_text(encoding="utf-8"))
    assert recorded == bench_rows


def test_bench_scorecard_has_a_headline() -> None:
    text = (EXAMPLES / "bench" / "SCORECARD.md").read_text(encoding="utf-8")
    assert any(line.startswith("**Headline:**") for line in text.splitlines())


def test_bench_scorecard_records_twelve_runs_with_the_new_columns() -> None:
    recorded = json.loads((EXAMPLES / "bench" / "scorecard.json").read_text(encoding="utf-8"))
    assert len(recorded) == 12
    assert {entry["attacker"] for entry in recorded} == {"adaptive", "one-shot", "white-box"}
    assert all(isinstance(entry["probes_sent"], int) for entry in recorded)
    assert all(isinstance(entry["scout_leads_left"], int) for entry in recorded)
    text = (EXAMPLES / "bench" / "SCORECARD.md").read_text(encoding="utf-8")
    assert "| Probes sent |" in text
    assert "| Scout leads left |" in text
    assert "| white-box | naive-first |" in text


def test_no_recorded_file_leaks_a_canary() -> None:
    files = [path for path in EXAMPLES.rglob("*") if path.is_file()]
    assert files
    leaks = [str(path) for path in files if CANARY_PATTERN.search(path.read_bytes())]
    assert leaks == []


def test_whitebox_recording_shows_the_gate_rejecting_naive_fixes() -> None:
    text = (EXAMPLES / "billing-whitebox-run" / "ARMS_RACE.md").read_text(encoding="utf-8")
    assert "Attacker: white-box" in text
    assert "attempt 0, rejected" in text
