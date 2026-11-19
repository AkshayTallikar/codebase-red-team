"""Verification gate: a patch is accepted only if it closes the hole without breaking anything."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from redteam.models import Finding, FunctionalCheck, Patch, Probe
from redteam.oracle import Oracle
from redteam.patching import PatchError, apply_edits
from redteam.sandbox import Sandbox, TargetLoadError
from redteam.targets import NOTES, Target, default_target

__all__ = ["FUNCTIONAL_CHECKS", "FunctionalCheck", "GateResult", "VerificationGate"]


@dataclass(frozen=True)
class GateResult:
    """Outcome of one gate run. `reasons` is empty when accepted."""

    accepted: bool
    reasons: tuple[str, ...]
    source: str | None


FUNCTIONAL_CHECKS: tuple[FunctionalCheck, ...] = NOTES.functional_checks


def _describe(probe: Probe) -> str:
    """Short human-readable form of a probe for ledger reasons."""
    return f"{probe.method} {probe.path} {dict(probe.params)}"


def _rejected(*reasons: str) -> GateResult:
    return GateResult(accepted=False, reasons=tuple(reasons), source=None)


class VerificationGate:
    """Checks a candidate patched source against the finding, regressions and function."""

    def __init__(self, target: Target | None = None) -> None:
        self.target = target if target is not None else default_target()

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
            sandbox = Sandbox(candidate, target=self.target)
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
    target = sandbox.target

    def fresh() -> None:
        if target.isolate_probes:
            sandbox.reset()

    fresh()
    if oracle.judge(sandbox.send(finding.probe)) is not None:
        reasons.append("exploit still works")

    for probe in regressions:
        fresh()
        if oracle.judge(sandbox.send(probe)) is not None:
            reasons.append(f"regression reopened: {_describe(probe)}")

    for check in target.functional_checks:
        fresh()
        result = sandbox.send(check.probe, token=target.user_token)
        text_ok = check.expect_text is None or check.expect_text in result.body
        if result.status != check.expect_status or not text_ok:
            reasons.append(f"functional check failed: {check.name} (status {result.status})")

    return reasons
