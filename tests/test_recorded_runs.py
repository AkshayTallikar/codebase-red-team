"""The committed recorded runs must stay honest: each hardened app blocks every recorded exploit.

Each recorded run is regenerated offline, so these tests also check that the recording
matches a fresh Arena run and that the benchmark scorecard matches its rows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig, ArenaResult
from redteam.audit import audit
from redteam.bench import run_bench
from redteam.cli import DEFAULT_BUDGET, DEFAULT_ROUNDS
from redteam.models import Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox
from redteam.targets import BILLING, NOTES, Target

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
CANARY_PATTERN = re.compile(rb"CANARY-[0-9a-f]{16}")
RUNS = [("notes-run", NOTES), ("billing-run", BILLING)]


def _regressions(run: str) -> dict[str, list[Probe]]:
    data = json.loads((EXAMPLES / run / "regressions.json").read_text(encoding="utf-8"))
    return {key: [Probe.from_dict(p) for p in group] for key, group in data.items()}


@pytest.fixture(scope="module")
def fresh_runs() -> dict[str, ArenaResult]:
    """One offline Arena run per target, shared by every test in this module."""
    return {
        target.name: Arena(
            PlaybookAttacker(target),
            ReferencePatcher(target),
            target=target,
            config=ArenaConfig(rounds=DEFAULT_ROUNDS, budget=DEFAULT_BUDGET),
        ).run()
        for target in (NOTES, BILLING)
    }


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
    assert recorded == fresh_runs[target.name].final_source


def test_bench_scorecard_matches_its_rows(bench_rows: list[dict]) -> None:
    recorded = json.loads((EXAMPLES / "bench" / "scorecard.json").read_text(encoding="utf-8"))
    assert recorded == bench_rows


def test_bench_scorecard_has_a_headline() -> None:
    text = (EXAMPLES / "bench" / "SCORECARD.md").read_text(encoding="utf-8")
    assert any(line.startswith("**Headline:**") for line in text.splitlines())


def test_no_recorded_file_leaks_a_canary() -> None:
    files = [path for path in EXAMPLES.rglob("*") if path.is_file()]
    assert files
    leaks = [str(path) for path in files if CANARY_PATTERN.search(path.read_bytes())]
    assert leaks == []
