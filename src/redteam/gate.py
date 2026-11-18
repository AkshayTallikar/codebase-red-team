"""Verification gate: a patch is accepted only if it closes the hole without breaking anything."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from redteam.models import Finding, Patch, Probe
from redteam.oracle import Oracle
from redteam.patching import PatchError, apply_edits
from redteam.sandbox import ALICE_TOKEN, Sandbox, TargetLoadError


@dataclass(frozen=True)
class GateResult:
    """Outcome of one gate run. `reasons` is empty when accepted."""

    accepted: bool
    reasons: tuple[str, ...]
    source: str | None


@dataclass(frozen=True)
class FunctionalCheck:
    """A normal-use request that must keep working after every patch."""

    name: str
    probe: Probe
    expect_status: int
    expect_text: str | None = None


FUNCTIONAL_CHECKS: tuple[FunctionalCheck, ...] = (
    FunctionalCheck(
        name="list notes with limit",
        probe=Probe("GET", "/notes", "GET /notes", params={"limit": "10"}),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="list notes without params",
        probe=Probe("GET", "/notes", "GET /notes"),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="search own notes",
        probe=Probe("GET", "/notes/search", "GET /notes/search", params={"q": "Gro"}),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="read own note",
        probe=Probe("GET", "/notes/2", "GET /notes/{note_id}"),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="create note",
        probe=Probe(
            "POST",
            "/notes",
            "POST /notes",
            json_body={"title": "gate check", "body": "ok"},
        ),
        expect_status=200,
        expect_text="id",
    ),
    FunctionalCheck(
        name="read public readme",
        probe=Probe("GET", "/files", "GET /files", params={"name": "readme.txt"}),
        expect_status=200,
        expect_text="Welcome",
    ),
)


def _describe(probe: Probe) -> str:
    """Short human-readable form of a probe for ledger reasons."""
    return f"{probe.method} {probe.path} {dict(probe.params)}"


def _rejected(*reasons: str) -> GateResult:
    return GateResult(accepted=False, reasons=tuple(reasons), source=None)


class VerificationGate:
    """Checks a candidate patched source against the finding, regressions and function."""

    def verify(
        self,
        source: str,
        patch: Patch,
        finding: Finding,
        regressions: Sequence[Probe],
    ) -> GateResult:
        """Return an accepting result with the patched source, or every rejection reason."""
        try:
            candidate = apply_edits(source, patch.edits)
        except PatchError as exc:
            return _rejected(f"patch does not apply: {exc}")

        try:
            sandbox = Sandbox(candidate)
        except TargetLoadError as exc:
            return _rejected(f"patched app does not load: {exc}")

        try:
            reasons = _check_candidate(sandbox, finding, regressions)
        finally:
            sandbox.close()

        if reasons:
            return _rejected(*reasons)
        return GateResult(accepted=True, reasons=(), source=candidate)


def _check_candidate(sandbox: Sandbox, finding: Finding, regressions: Sequence[Probe]) -> list[str]:
    """Run the exploit, regression and functional checks, collecting every failure."""
    reasons: list[str] = []
    oracle = Oracle(sandbox.canary)

    if oracle.judge(sandbox.send(finding.probe)) is not None:
        reasons.append("exploit still works")

    for probe in regressions:
        if oracle.judge(sandbox.send(probe)) is not None:
            reasons.append(f"regression reopened: {_describe(probe)}")

    for check in FUNCTIONAL_CHECKS:
        result = sandbox.send(check.probe, token=ALICE_TOKEN)
        text_ok = check.expect_text is None or check.expect_text in result.body
        if result.status != check.expect_status or not text_ok:
            reasons.append(f"functional check failed: {check.name} (status {result.status})")

    return reasons
