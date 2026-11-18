"""The verification gate: correct patches pass, broken or cheating patches do not."""

import pytest

from redteam.agents.patcher import ReferencePatcher
from redteam.gate import VerificationGate
from redteam.models import Edit, Finding, Patch, Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox, load_seed_source

SQLI = Probe(
    "GET",
    "/notes/search",
    "GET /notes/search",
    vuln_class="sqli",
    params={"q": "' OR 1=1 --"},
)
IDOR = Probe("GET", "/notes/1", "GET /notes/{note_id}", vuln_class="idor")
TRAVERSAL = Probe(
    "GET",
    "/files",
    "GET /files",
    vuln_class="path_traversal",
    params={"name": "../secrets.txt"},
)
CRASH = Probe("GET", "/notes", "GET /notes", vuln_class="crash", params={"limit": "0"})


def _finding(probe: Probe) -> Finding:
    """Send the probe to the seed app and return the finding the oracle reports."""
    with Sandbox() as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, f"seed app is not vulnerable to {probe.path}"
    return finding


def _patch(finding: Finding, source: str, attempt: int = 0) -> Patch:
    patch = ReferencePatcher().propose(finding, source, attempt)
    assert patch is not None
    return patch


@pytest.mark.parametrize("probe", [SQLI, IDOR, TRAVERSAL, CRASH], ids=lambda p: p.endpoint)
def test_reference_attempt_zero_is_accepted(probe):
    seed = load_seed_source()
    finding = _finding(probe)
    result = VerificationGate().verify(seed, _patch(finding, seed), finding, [])
    assert result.accepted, result.reasons
    assert result.reasons == ()
    assert result.source is not None and result.source != seed


def test_deleting_the_idor_route_is_rejected_by_functional_check():
    seed = load_seed_source()
    finding = _finding(IDOR)
    start = seed.index('    @app.get("/notes/{note_id}")')
    end = seed.index('    @app.get("/files")')
    cheat = Patch(
        finding_key=finding.key,
        edits=(Edit(old=seed[start:end], new=""),),
        rationale="remove the endpoint",
        author="test",
    )
    result = VerificationGate().verify(seed, cheat, finding, [])
    assert not result.accepted
    assert any(
        reason.startswith("functional check failed: read own note") for reason in result.reasons
    )


def test_patch_that_does_not_apply_is_rejected():
    seed = load_seed_source()
    finding = _finding(IDOR)
    bogus = Patch(
        finding_key=finding.key,
        edits=(Edit(old="this text is not in the source", new="x"),),
        rationale="",
        author="test",
    )
    result = VerificationGate().verify(seed, bogus, finding, [])
    assert not result.accepted
    assert result.reasons[0].startswith("patch does not apply")


def test_syntactically_broken_patch_is_rejected_at_load():
    seed = load_seed_source()
    finding = _finding(IDOR)
    broken = Patch(
        finding_key=finding.key,
        edits=(Edit(old='    @app.get("/files")', new='    @app.get("/files"('),),
        rationale="",
        author="test",
    )
    result = VerificationGate().verify(seed, broken, finding, [])
    assert not result.accepted
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith("patched app does not load")


def test_fix_that_reopens_an_earlier_regression_is_rejected():
    seed = load_seed_source()
    idor_finding = _finding(IDOR)
    result = VerificationGate().verify(seed, _patch(idor_finding, seed), idor_finding, [SQLI])
    assert not result.accepted
    assert result.reasons == (f"regression reopened: GET /notes/search {dict(SQLI.params)}",)


def test_exploit_that_still_works_is_reported():
    seed = load_seed_source()
    finding = _finding(SQLI)
    noop = Patch(
        finding_key=finding.key,
        edits=(Edit(old="def create_app(", new="def create_app("),),
        rationale="no change",
        author="test",
    )
    result = VerificationGate().verify(seed, noop, finding, [])
    assert not result.accepted
    assert "exploit still works" in result.reasons
