"""The source scout: leads for every seeded and naive weakness, none after the real fixes."""

from __future__ import annotations

import json

import pytest

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena
from redteam.cli import main
from redteam.models import Probe
from redteam.oracle import Oracle
from redteam.patching import apply_edits
from redteam.sandbox import Sandbox
from redteam.scout import scout, scout_target
from redteam.targets import BILLING, NOTES, Target

TARGETS = (NOTES, BILLING)


def land(target: Target, source: str, probe: Probe) -> bool:
    """True when the probe gets a leak or a crash out of a fresh copy of `source`."""
    with Sandbox(source, target=target) as sandbox:
        return Oracle(sandbox.canary).judge(sandbox.send(probe)) is not None


def _naive_source(target: Target) -> str:
    """The seed with the attempt-0 fix applied for every key whose first attempt is naive."""
    source = target.load_source()
    for attempts in target.fix_catalog.values():
        if attempts[0].naive:
            source = apply_edits(source, attempts[0].alternatives[0])
    return source


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_seed_leads_are_exactly_the_catalog_keys(target: Target) -> None:
    assert {hyp.key for hyp in scout_target(target)} == set(target.fix_catalog)


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_every_seed_lead_has_a_probe_that_lands(target: Target) -> None:
    seed = target.load_source()
    for hyp in scout_target(target):
        assert any(land(target, seed, probe) for probe in hyp.probes), hyp.key


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_naive_fixes_keep_their_leads(target: Target) -> None:
    naive_keys = {key for key, attempts in target.fix_catalog.items() if attempts[0].naive}
    keys = {hyp.key for hyp in scout_target(target, _naive_source(target))}
    assert naive_keys <= keys
    assert keys == set(target.fix_catalog)


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_real_fixes_leave_no_leads(target: Target) -> None:
    result = Arena(
        PlaybookAttacker(target),
        ReferencePatcher(target, skip_naive=True),
        target=target,
    ).run()
    assert scout_target(target, result.final_source) == []


def test_scout_never_executes_the_source() -> None:
    source = 'raise SystemExit("executed")\n' + NOTES.load_source()
    assert {hyp.key for hyp in scout(source)} == set(NOTES.fix_catalog)


def test_unparseable_source_raises_syntax_error() -> None:
    with pytest.raises(SyntaxError):
        scout("def broken(:\n")


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_each_line_number_points_at_its_evidence(target: Target) -> None:
    for source in (target.load_source(), _naive_source(target)):
        lines = source.splitlines()
        for hyp in scout_target(target, source):
            assert lines[hyp.line - 1].strip() == hyp.evidence, hyp.key


def test_sqli_lead_points_at_the_execute_call() -> None:
    hyp = next(h for h in scout_target(NOTES) if h.vuln_class == "sqli")
    assert "execute(sql)" in hyp.evidence


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_probes_carry_their_lead_and_a_scout_note(target: Target) -> None:
    for hyp in scout_target(target):
        assert hyp.probes
        for probe in hyp.probes:
            assert probe.vuln_class == hyp.vuln_class
            assert probe.endpoint == hyp.endpoint
            assert probe.note.startswith("scout: ")


def test_cli_text_lists_the_billing_auth_bypass(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scout", "--target", "billing"]) == 0
    assert "auth_bypass" in capsys.readouterr().out


def test_cli_json_lists_the_four_notes_leads(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scout", "--target", "notes", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 4
    assert {entry["key"] for entry in data} == set(NOTES.fix_catalog)
