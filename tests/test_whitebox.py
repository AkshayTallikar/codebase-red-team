"""The white-box attacker: it starts from the scout's leads, never from hand-written exploits."""

from __future__ import annotations

import dataclasses
import json

import pytest

from redteam.agents.attacker import PlaybookAttacker, ScoutAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import STOP_CLEAN, Arena, ArenaConfig, ArenaResult
from redteam.audit import audit
from redteam.cli import main
from redteam.targets import BILLING, NOTES, Target

NAIVE_FIXED = {
    "notes": frozenset({"sqli:GET /notes/search", "path_traversal:GET /files"}),
    "billing": frozenset(
        {
            "mass_assignment:PATCH /me",
            "ssrf:GET /invoices/import",
            "auth_bypass:GET /admin/settings",
        }
    ),
}


def _run(target: Target, *, skip_naive: bool = False, attacker: ScoutAttacker | None = None):
    patcher = ReferencePatcher(target, skip_naive=skip_naive)
    arena = Arena(
        attacker or ScoutAttacker(target),
        patcher,
        target=target,
        config=ArenaConfig(rounds=6, budget=40),
    )
    return arena.run()


@pytest.fixture(scope="module")
def correct_first_runs() -> dict[str, ArenaResult]:
    return {target.name: _run(target, skip_naive=True) for target in (NOTES, BILLING)}


@pytest.mark.parametrize("target", [NOTES, BILLING], ids=["notes", "billing"])
def test_naive_first_run_ends_hardened_with_a_clean_audit(target: Target) -> None:
    result = _run(target)
    assert result.hardened
    assert result.audit is not None and result.audit.clean


@pytest.mark.parametrize("target", [NOTES, BILLING], ids=["notes", "billing"])
def test_every_naive_fix_is_rejected_by_the_gate_or_bypassed_later(target: Target) -> None:
    """The scout sends several variants up front, so a naive fix either fails the gate
    (another variant still lands) or ships and is bypassed in a later round."""
    result = _run(target)
    rejected = {
        outcome.key
        for summary in result.rounds
        for outcome in summary.outcomes
        if not outcome.accepted
    }
    caught = rejected | set(result.bypassed_keys)
    assert caught == NAIVE_FIXED[target.name]
    assert rejected, "expected the gate to reject at least one naive fix"


def test_rejected_patch_escalates_to_the_next_fix() -> None:
    """After the gate rejects attempt 0, the patcher is asked for attempt 1, not attempt 0 again."""
    result = _run(NOTES)
    attempts: dict[str, list[tuple[int, bool]]] = {}
    for summary in result.rounds:
        for outcome in summary.outcomes:
            attempts.setdefault(outcome.key, []).append((outcome.attempt, outcome.accepted))
    for key, history in attempts.items():
        numbers = [attempt for attempt, _ in history]
        assert numbers == list(range(len(numbers))), (key, history)


@pytest.mark.parametrize("target", [NOTES, BILLING], ids=["notes", "billing"])
def test_correct_first_run_ends_hardened_with_a_clean_audit(
    target: Target, correct_first_runs: dict[str, ArenaResult]
) -> None:
    result = correct_first_runs[target.name]
    assert result.hardened
    assert result.audit is not None and result.audit.clean
    assert result.stop_reason == STOP_CLEAN


@pytest.mark.parametrize("target", [NOTES, BILLING], ids=["notes", "billing"])
def test_correct_first_run_has_no_bypasses(
    target: Target, correct_first_runs: dict[str, ArenaResult]
) -> None:
    assert correct_first_runs[target.name].bypassed_keys == frozenset()


def test_white_box_never_reads_hand_written_exploits() -> None:
    normal = _run(NOTES, skip_naive=True)
    blind_target = dataclasses.replace(NOTES, seed_probes=(), audit_probes=())
    blind = _run(blind_target, skip_naive=True)

    assert blind.hardened
    assert set(blind.regressions) == set(normal.regressions)
    # The copy's own audit is empty, so the real target's audit is run on the copy's source.
    assert audit(blind.final_source, NOTES).clean


class _RecordingScout(ScoutAttacker):
    """A ScoutAttacker that keeps every source the arena shows it."""

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.observed: list[str] = []

    def observe_source(self, source: str) -> None:
        self.observed.append(source)
        super().observe_source(source)


def test_observe_source_is_called_each_round_with_the_current_source() -> None:
    attacker = _RecordingScout(NOTES)
    result = _run(NOTES, skip_naive=True, attacker=attacker)

    assert len(attacker.observed) == len(result.rounds)
    assert attacker.observed[0] == NOTES.load_source()
    assert attacker.observed[-1] == result.final_source
    assert attacker.observed[0] != attacker.observed[-1]


def test_scout_attacker_has_the_white_box_name() -> None:
    assert ScoutAttacker(NOTES).name == "white-box"


def test_playbook_run_rounds_are_unchanged() -> None:
    result = Arena(
        PlaybookAttacker(NOTES),
        ReferencePatcher(NOTES),
        target=NOTES,
        config=ArenaConfig(rounds=6, budget=40),
    ).run()
    assert [(r.probes_sent, len(r.findings)) for r in result.rounds] == [(9, 4), (22, 2), (28, 0)]


def test_cli_white_box_on_billing_writes_a_hardened_summary(tmp_path) -> None:
    assert (
        main(["run", "--attacker", "white-box", "--target", "billing", "--out", str(tmp_path)]) == 0
    )
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["hardened"] is True


def test_cli_white_box_writes_a_summary_for_billing(tmp_path) -> None:
    main(["run", "--attacker", "white-box", "--target", "billing", "--out", str(tmp_path)])
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["target"] == "billing"
    assert summary["audit"]["total"] == 11
