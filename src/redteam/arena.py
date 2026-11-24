"""The arms race: attack rounds, patch attempts and gate checks, with a ledger and reports."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from redteam.agents.attacker import Attacker, AttackHistory
from redteam.agents.patcher import Patcher
from redteam.audit import AuditResult, audit
from redteam.gate import VerificationGate
from redteam.ledger import Ledger
from redteam.models import Finding, Patch, Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox
from redteam.targets import Target, default_target
from redteam.timeline import write_timeline

STOP_CLEAN = "clean_round"
STOP_EXHAUSTED = "attacker_exhausted"
STOP_LIMIT = "round_limit"


@dataclass(frozen=True)
class ArenaConfig:
    """How many rounds to play and how many probes the attacker may send per round."""

    rounds: int = 6
    budget: int = 40


@dataclass
class PatchOutcome:
    """What the gate decided about one patch attempt for one weakness."""

    key: str
    attempt: int
    patch: Patch | None
    accepted: bool
    reasons: tuple[str, ...]


@dataclass
class RoundSummary:
    """One round: what was sent, what landed, and what the patcher tried."""

    number: int
    probes_sent: int
    findings: list[Finding]
    outcomes: list[PatchOutcome]
    probes_landed: int = 0


@dataclass
class ArenaResult:
    """The complete outcome of a run."""

    rounds: list[RoundSummary]
    final_source: str
    regressions: dict[str, list[Probe]]
    accepted_patches: dict[str, int]
    open_findings: dict[str, Finding]
    stop_reason: str
    bypassed_keys: frozenset[str] = field(default_factory=frozenset)
    audit: AuditResult | None = None

    @property
    def untested(self) -> bool:
        """True when the attacker sent no probes at all, so the run tested nothing."""
        return sum(summary.probes_sent for summary in self.rounds) == 0

    @property
    def hardened(self) -> bool:
        """True when no weakness is left open and the attacker sent at least one probe."""
        return not self.open_findings and not self.untested


class Arena:
    """Runs the attacker and patcher against a sandboxed copy of the target."""

    def __init__(
        self,
        attacker: Attacker,
        patcher: Patcher,
        *,
        target: Target | None = None,
        gate: VerificationGate | None = None,
        config: ArenaConfig | None = None,
        out_dir: str | Path | None = None,
        source: str | None = None,
    ) -> None:
        self.attacker = attacker
        self.patcher = patcher
        self.target = target if target is not None else default_target()
        self.gate = gate if gate is not None else VerificationGate(self.target)
        self.config = config if config is not None else ArenaConfig()
        self.out_dir = Path(out_dir) if out_dir is not None else None
        self.source = source

    def run(self) -> ArenaResult:
        """Play the rounds, write outputs if an output directory is set, and return the result."""
        sandbox = Sandbox(self.source, target=self.target)
        try:
            result = _Campaign(self, sandbox).play()
        finally:
            sandbox.close()
        result.audit = audit(result.final_source, self.target)
        if self.out_dir is not None:
            _write_outputs(
                self.out_dir,
                result,
                self.attacker.name,
                self.patcher.name,
                target_name=self.target.name,
            )
        return result


class _Campaign:
    """Bookkeeping for one run: the sandbox, the oracle, the ledger and every round's state."""

    def __init__(self, arena: Arena, sandbox: Sandbox) -> None:
        self.arena = arena
        self.sandbox = sandbox
        self.oracle = Oracle(sandbox.canary)
        self.ledger = Ledger(arena.out_dir, redact=self.oracle.redact)
        self.history = AttackHistory()
        self.regressions: dict[str, list[Probe]] = {}
        self.closed: set[str] = set()
        self.reopened: set[str] = set()
        self.attempts: Counter[str] = Counter()
        # Every proposal for a key, accepted or rejected: a rejected fix escalates the next one.
        self.proposals: Counter[str] = Counter()
        self.open_findings: dict[str, Finding] = {}

    def play(self) -> ArenaResult:
        """Run rounds until the attacker runs dry, a round is clean, or the limit is reached."""
        config = self.arena.config
        self.ledger.log(
            "run_started",
            target=self.arena.target.name,
            attacker=self.arena.attacker.name,
            patcher=self.arena.patcher.name,
            rounds=config.rounds,
            budget=config.budget,
        )
        rounds: list[RoundSummary] = []
        stop_reason = STOP_LIMIT
        for number in range(1, config.rounds + 1):
            self.ledger.round = number
            self.ledger.log("round_started", number=number)
            observe = getattr(self.arena.attacker, "observe_source", None)
            if callable(observe):
                observe(self._source())
            probes = self.arena.attacker.plan(self.sandbox.routes(), self.history, config.budget)
            if not probes:
                rounds.append(RoundSummary(number, 0, [], []))
                stop_reason = STOP_EXHAUSTED
                self.ledger.log("attacker_exhausted", number=number)
                break

            summary = self._play_round(number, probes)
            rounds.append(summary)
            if not summary.findings:
                stop_reason = STOP_CLEAN
                self.ledger.log("round_clean", number=number)
                break

        return self._finish(rounds, stop_reason)

    def _play_round(self, number: int, probes: list[Probe]) -> RoundSummary:
        """Send one batch, record what landed, then try to patch each weakness that landed."""
        landed_count = 0
        round_findings: dict[str, Finding] = {}
        for probe in probes:
            if self.arena.target.isolate_probes:
                self.sandbox.reset()
            finding = self.oracle.judge(self.sandbox.send(probe))
            self.history.record(probe, landed=finding is not None)
            self.ledger.log(
                "probe",
                method=probe.method,
                path=probe.path,
                params=dict(probe.params),
                vuln_class=probe.vuln_class,
                note=probe.note,
                landed=finding is not None,
            )
            if finding is None:
                continue
            landed_count += 1
            self._note_landing(probe, finding, round_findings)

        for key, finding in round_findings.items():
            self.ledger.log(
                "finding",
                key=key,
                finding_kind=finding.kind,
                status=finding.status,
                evidence=finding.evidence,
                method=finding.probe.method,
                path=finding.probe.path,
                params=dict(finding.probe.params),
            )

        summary = RoundSummary(
            number=number,
            probes_sent=len(probes),
            findings=list(round_findings.values()),
            outcomes=[],
            probes_landed=landed_count,
        )
        for finding in round_findings.values():
            summary.outcomes.append(self._patch(finding))
        return summary

    def _note_landing(
        self, probe: Probe, finding: Finding, round_findings: dict[str, Finding]
    ) -> None:
        """Keep the probe as a regression case and reopen the weakness if it was closed."""
        key = finding.key
        bucket = self.regressions.setdefault(key, [])
        signature = probe.signature()
        if all(known.signature() != signature for known in bucket):
            bucket.append(probe)
        round_findings.setdefault(key, finding)
        if key in self.closed:
            self.closed.discard(key)
            self.reopened.add(key)
            self.ledger.log("bypass", key=key, probe=probe.to_dict())

    def _patch(self, finding: Finding) -> PatchOutcome:
        """Ask the patcher for a fix and let the gate decide whether it stays."""
        key = finding.key
        attempt = self.proposals[key]
        source = self._source()
        patch = self.arena.patcher.propose(finding, source, attempt)
        if patch is not None:
            self.proposals[key] += 1
        if patch is None:
            self.open_findings[key] = finding
            self.ledger.log("patch_unavailable", key=key, attempt=attempt)
            return PatchOutcome(key, attempt, None, False, ("patcher has no fix",))

        verdict = self.arena.gate.verify(source, patch, finding, self._gate_probes(key))
        if verdict.accepted and verdict.source is not None:
            self.sandbox.load(verdict.source)
            self.attempts[key] += 1
            self.closed.add(key)
            self.open_findings.pop(key, None)
            self.ledger.log(
                "patch_accepted",
                key=key,
                attempt=attempt,
                rationale=patch.rationale,
                author=patch.author,
                edits=[{"old": edit.old, "new": edit.new} for edit in patch.edits],
            )
            return PatchOutcome(key, attempt, patch, True, ())

        self.open_findings[key] = finding
        self.ledger.log(
            "patch_rejected",
            key=key,
            attempt=attempt,
            rationale=patch.rationale,
            reasons=list(verdict.reasons),
        )
        return PatchOutcome(key, attempt, patch, False, verdict.reasons)

    def _gate_probes(self, key: str) -> list[Probe]:
        """Every regression probe for closed weaknesses plus every probe for `key`, deduplicated."""
        seen: set[str] = set()
        probes: list[Probe] = []
        for owner in [*sorted(self.closed), key]:
            for probe in self.regressions.get(owner, []):
                signature = probe.signature()
                if signature not in seen:
                    seen.add(signature)
                    probes.append(probe)
        return probes

    def _source(self) -> str:
        """Return the sandbox's current source, which is always set after construction."""
        if self.sandbox.source is None:
            raise RuntimeError("sandbox has no source loaded")
        return self.sandbox.source

    def _finish(self, rounds: list[RoundSummary], stop_reason: str) -> ArenaResult:
        """Log the end of the run and assemble the result."""
        final_source = self._source()
        accepted = {key: count for key, count in self.attempts.items() if count}
        open_keys = sorted(self.open_findings)
        result = ArenaResult(
            rounds=rounds,
            final_source=final_source,
            regressions={key: list(probes) for key, probes in self.regressions.items()},
            accepted_patches=accepted,
            open_findings=dict(self.open_findings),
            stop_reason=stop_reason,
            bypassed_keys=frozenset(self.reopened),
        )
        self.ledger.log(
            "run_finished",
            stop_reason=stop_reason,
            hardened=result.hardened,
            untested=result.untested,
            open_keys=open_keys,
            accepted_patches=accepted,
        )
        return result


def _write_outputs(
    out_dir: Path,
    result: ArenaResult,
    attacker_name: str,
    patcher_name: str,
    *,
    target_name: str = "notes",
) -> None:
    """Write the final source, regression cases, a summary and the Markdown report."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "final_app.py").write_text(result.final_source, encoding="utf-8")

    regressions = {
        key: [probe.to_dict() for probe in probes] for key, probes in result.regressions.items()
    }
    _write_json(out_dir / "regressions.json", regressions)

    summary: dict[str, Any] = {
        "target": target_name,
        "stop_reason": result.stop_reason,
        "hardened": result.hardened,
        "untested": result.untested,
        "rounds": len(result.rounds),
        "accepted_patches": result.accepted_patches,
        "open_keys": sorted(result.open_findings),
    }
    if result.audit is not None:
        summary["audit"] = result.audit.to_dict()
    _write_json(out_dir / "summary.json", summary)

    report = render_report(result, attacker_name, patcher_name, target_name=target_name)
    (out_dir / "ARMS_RACE.md").write_text(report, encoding="utf-8")
    write_timeline(
        out_dir,
        result,
        title=f"Arms race on {target_name}: {attacker_name} vs {patcher_name}",
    )


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _cell(text: str) -> str:
    """Make text safe for a Markdown table cell."""
    return text.replace("\n", " ").replace("|", "\\|")


def _probe_text(probe: Probe) -> str:
    """Render a probe as `METHOD /path k="v" ...`."""
    parts = [probe.method, probe.path]
    parts.extend(f'{name}="{value}"' for name, value in probe.params.items())
    return " ".join(parts)


def _patch_line(outcome: PatchOutcome) -> str:
    """One bullet describing a patch attempt, with its rationale or its rejection reasons."""
    if outcome.accepted and outcome.patch is not None:
        detail = outcome.patch.rationale
        verdict = "accepted"
    else:
        detail = "; ".join(outcome.reasons)
        verdict = "rejected"
    return f"- `{outcome.key}` attempt {outcome.attempt}, {verdict}: {detail}"


def _probe_detail(probe: Probe) -> str:
    """`METHOD /path k="v"`, plus the JSON body and headers when the probe has them."""
    text = _probe_text(probe)
    if probe.json_body is not None:
        text += f" body={json.dumps(probe.json_body, sort_keys=True)}"
    if probe.headers:
        text += f" headers={json.dumps(probe.headers, sort_keys=True)}"
    return text


def _audit_lines(audit_result: AuditResult) -> list[str]:
    """The independent audit section: how many held-out exploits landed, and each one."""
    lines = ["", "## Independent audit", ""]
    if audit_result.clean:
        lines.append(
            f"Replayed {audit_result.total} held-out exploits the attacker never saw: none landed."
        )
        return lines
    classes = ", ".join(audit_result.exposed_classes)
    lines.append(
        f"Replayed {audit_result.total} held-out exploits the attacker never saw: "
        f"{audit_result.landed_count} landed, in {classes}."
    )
    lines.append("")
    for cls in audit_result.exposed_classes:
        for probe in audit_result.landed[cls]:
            lines.append(f"- `{cls}`: `{_probe_detail(probe)}`")
    return lines


def _bypassed(result: ArenaResult, key: str) -> bool:
    """A weakness counts as bypassed when it was patched twice or landed again after a fix."""
    return result.accepted_patches.get(key, 0) >= 2 or key in result.bypassed_keys


def render_report(
    result: ArenaResult,
    attacker_name: str,
    patcher_name: str,
    *,
    target_name: str = "notes",
) -> str:
    """Render the arms race as Markdown: a scoreboard, then one section per round."""
    if result.untested:
        verdict = "untested"
    else:
        verdict = "hardened" if result.hardened else "not hardened"
    lines = [
        "# Arms race report",
        "",
        f"Target: {target_name} · "
        f"Attacker: {attacker_name} · Patcher: {patcher_name} · Rounds: {len(result.rounds)} · "
        f"Stopped: {result.stop_reason} · Result: {verdict}, {len(result.open_findings)} open",
        "",
    ]
    if result.untested:
        lines += ["The attacker sent no probes, so nothing was tested.", ""]
    lines += [
        "![Arms-race timeline](timeline.svg)",
        "",
        "## Scoreboard",
        "",
    ]
    if result.regressions:
        lines += [
            "| Weakness | Patches accepted | Bypassed after a fix | Status |",
            "|---|---|---|---|",
        ]
        for key in result.regressions:
            accepted = result.accepted_patches.get(key, 0)
            bypassed = "yes" if _bypassed(result, key) else "no"
            status = "open" if key in result.open_findings else "closed"
            lines.append(f"| `{_cell(key)}` | {accepted} | {bypassed} | {status} |")
    else:
        lines.append("No weakness landed during this run.")

    if result.audit is not None:
        lines += _audit_lines(result.audit)

    last_index = len(result.rounds) - 1
    for index, summary in enumerate(result.rounds):
        lines += ["", f"## Round {summary.number}", ""]
        sentence = f"Sent {summary.probes_sent} probes, {summary.probes_landed} landed."
        if index == last_index and result.stop_reason in (STOP_CLEAN, STOP_EXHAUSTED):
            sentence += " The attacker found nothing new, so the run stopped."
        lines.append(sentence)

        if summary.findings:
            lines += ["", "| Finding | Kind | Probe |", "|---|---|---|"]
            for finding in summary.findings:
                probe = _cell(f"`{_probe_detail(finding.probe)}`")
                lines.append(f"| `{_cell(finding.key)}` | {finding.kind} | {probe} |")

        if summary.outcomes:
            lines += ["", "Patches:"]
            lines += [_patch_line(outcome) for outcome in summary.outcomes]

    return "\n".join(lines) + "\n"
