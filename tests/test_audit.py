"""The held-out audit: probes land on the seed, close after real fixes, and expose naive ones."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaResult, render_report
from redteam.audit import AuditResult, audit
from redteam.cli import main
from redteam.models import Finding
from redteam.oracle import Oracle
from redteam.patching import apply_edits
from redteam.sandbox import Sandbox, TargetLoadError
from redteam.targets import BILLING, NOTES, Target

TARGETS = (NOTES, BILLING)


def _seed_finding(target: Target, key: str) -> Finding:
    """The finding that the first seed probe for `key` produces on the untouched seed app."""
    probe = next(p for p in target.seed_probes if f"{p.vuln_class}:{p.endpoint}" == key)
    with Sandbox(target=target) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, key
    return finding


def _first_attempts(target: Target) -> str:
    """Apply attempt 0 of every catalog entry: the naive fix where one exists, else the only fix."""
    source = target.load_source()
    for key in target.fix_catalog:
        patch = ReferencePatcher(target).propose(_seed_finding(target, key), source, 0)
        assert patch is not None, key
        source = apply_edits(source, patch.edits)
    return source


def _lands(source: str, target: Target, probe) -> bool:
    with Sandbox(source, target=target) as sandbox:
        return Oracle(sandbox.canary).judge(sandbox.send(probe)) is not None


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_each_audit_probe_is_a_real_exploit(target: Target) -> None:
    # Every probe breaks the seed app or the app after the naive fixes.
    assert target.audit_probes
    seed, naive = target.load_source(), _first_attempts(target)
    for probe in target.audit_probes:
        assert _lands(seed, target, probe) or _lands(naive, target, probe), probe.note


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_seed_app_fails_the_audit(target: Target) -> None:
    result = audit(target.load_source(), target)
    assert result.total == len(target.audit_probes)
    assert set(result.exposed_classes) == set(target.vuln_classes)


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_audit_is_clean_after_every_real_fix(target: Target) -> None:
    result = Arena(
        PlaybookAttacker(target),
        ReferencePatcher(target, skip_naive=True),
        target=target,
    ).run()

    assert result.hardened
    assert result.audit is not None
    assert result.audit.clean
    assert audit(result.final_source, target).clean


def test_naive_fixes_leave_exposure_the_loop_cannot_see() -> None:
    notes = audit(_first_attempts(NOTES), NOTES)
    assert set(notes.exposed_classes) == {"sqli", "path_traversal"}

    billing = audit(_first_attempts(BILLING), BILLING)
    assert set(billing.exposed_classes) == {"mass_assignment", "ssrf", "auth_bypass"}


def test_to_dict_lists_the_landed_probes_by_class() -> None:
    data = audit(_first_attempts(NOTES), NOTES).to_dict()
    assert data["target"] == "notes"
    assert data["clean"] is False
    assert data["landed_count"] == sum(len(probes) for probes in data["landed"].values())
    assert data["exposed_classes"] == sorted(data["landed"])
    assert all("method" in probe for probes in data["landed"].values() for probe in probes)
    json.dumps(data)


def test_audit_raises_when_the_source_does_not_load() -> None:
    with pytest.raises(TargetLoadError):
        audit("def create_app(:\n", NOTES)


def test_report_names_each_landed_probe_when_the_audit_gets_in() -> None:
    audited = audit(_first_attempts(BILLING), BILLING)
    result = ArenaResult(
        rounds=[],
        final_source=_first_attempts(BILLING),
        regressions={},
        accepted_patches={},
        open_findings={},
        stop_reason="clean_round",
        audit=audited,
    )
    report = render_report(result, "one-shot", "naive-first", target_name="billing")

    assert "## Independent audit" in report
    assert f"{audited.landed_count} landed, in " in report
    assert "- `ssrf`: `GET /invoices/import url=" in report
    assert 'headers={"X-Forwarded-User": "ADMIN"}' in report
    assert 'body={"ROLE": "admin"}' in report


def test_report_says_none_landed_for_a_clean_audit() -> None:
    result = ArenaResult(
        rounds=[],
        final_source=BILLING.load_source(),
        regressions={},
        accepted_patches={},
        open_findings={},
        stop_reason="clean_round",
        audit=AuditResult(target="billing", total=11),
    )
    report = render_report(result, "playbook", "reference", target_name="billing")
    assert "Replayed 11 held-out exploits the attacker never saw: none landed." in report


@pytest.mark.parametrize("name", ["notes", "billing"])
def test_run_writes_a_clean_audit_into_summary_and_report(tmp_path: Path, name: str) -> None:
    out = tmp_path / name
    assert main(["run", "--target", name, "--out", str(out)]) == 0

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["audit"]["clean"] is True
    assert summary["audit"]["total"] > 0
    assert "## Independent audit" in (out / "ARMS_RACE.md").read_text(encoding="utf-8")
