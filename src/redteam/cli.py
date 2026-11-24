"""Command line entry point: `redteam run` plays the arms race and writes its outputs."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from redteam.agents.attacker import Attacker, LLMAttacker, PlaybookAttacker, ScoutAttacker
from redteam.agents.patcher import LLMPatcher, Patcher, ReferencePatcher
from redteam.arena import Arena, ArenaConfig, ArenaResult
from redteam.bench import run_bench, write_bench
from redteam.llm import LLMError, make_backend
from redteam.sarif import artifact_uri, to_sarif
from redteam.scout import render, scout_target
from redteam.targets import DEFAULT_TARGET, TARGETS, Target, get_target

DEFAULT_ROUNDS = 6
DEFAULT_BUDGET = 40
EXIT_HARDENED = 0
EXIT_OPEN = 1
EXIT_BACKEND_ERROR = 2
ATTACKER_CHOICES = ("playbook", "one-shot", "white-box")
DEFAULT_ATTACKER = "playbook"


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser with its `run` subcommand."""
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="Attack a sandboxed app and patch it, round after round.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="play the attack and patch rounds")
    run.add_argument(
        "--backend",
        choices=("offline", "anthropic"),
        default="offline",
        help="offline uses the deterministic playbook (default)",
    )
    run.add_argument("--model", default=None, help="model id for the anthropic backend")
    run.add_argument(
        "--attacker",
        choices=ATTACKER_CHOICES,
        default=DEFAULT_ATTACKER,
        help="offline attacker: playbook (adaptive), one-shot (seeds only) or white-box "
        "(re-reads the source and attacks the scout's leads); ignored with --backend anthropic",
    )
    run.add_argument(
        "--target",
        choices=sorted(TARGETS),
        default=DEFAULT_TARGET,
        help="app under attack (default %(default)s)",
    )
    run.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help="maximum rounds")
    run.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="probes per round")
    run.add_argument(
        "--out",
        default=None,
        help="output directory (default runs/<UTC timestamp>)",
    )
    bench = commands.add_parser(
        "bench", help="run every target under four strategies and write SCORECARD.md"
    )
    bench.add_argument(
        "--target",
        choices=[*sorted(TARGETS), "all"],
        default="all",
        help="target to benchmark (default %(default)s)",
    )
    bench.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help="maximum rounds")
    bench.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="probes per round")
    bench.add_argument(
        "--out",
        default=None,
        help="output directory (default bench/<UTC timestamp>)",
    )
    scout = commands.add_parser(
        "scout", help="list static exploit leads in a target's source, without running it"
    )
    scout.add_argument(
        "--target",
        choices=sorted(TARGETS),
        default=DEFAULT_TARGET,
        help="app to scout (default %(default)s)",
    )
    scout.add_argument(
        "--source", default=None, help="scout this file instead of the target's seed source"
    )
    scout.add_argument("--json", action="store_true", help="print the leads as JSON")
    scout.add_argument(
        "--sarif",
        default=None,
        metavar="PATH",
        help="also write the leads as SARIF 2.1.0 for code scanning tools",
    )
    return parser


def _default_out() -> str:
    return f"runs/{datetime.now(UTC):%Y%m%d-%H%M%S}"


def _default_bench_out() -> str:
    return f"bench/{datetime.now(UTC):%Y%m%d-%H%M%S}"


def _bench(args: argparse.Namespace) -> int:
    """Benchmark the chosen targets, print one line per run and write the scorecard."""
    targets = list(TARGETS.values()) if args.target == "all" else [get_target(args.target)]
    rows = run_bench(targets, rounds=args.rounds, budget=args.budget)
    out_dir = Path(args.out or _default_bench_out())
    write_bench(out_dir, rows)
    for row in rows:
        if row.loop_untested:
            state = "untested"
        else:
            state = "hardened" if row.loop_hardened else "not hardened"
        suffix = " (false confidence)" if row.false_confidence else ""
        print(
            f"{row.target} {row.attacker} {row.patcher}: {state}, "
            f"audit {row.audit_landed}/{row.audit_total}{suffix}"
        )
    print(f"scorecard: {out_dir / 'SCORECARD.md'}")
    return EXIT_HARDENED


def _scout(args: argparse.Namespace) -> int:
    """Print the static leads for one target, as text or JSON. Always exits 0."""
    target = get_target(args.target)
    source = Path(args.source).read_text(encoding="utf-8") if args.source else None
    hypotheses = scout_target(target, source)
    if args.sarif:
        scanned = Path(args.source) if args.source else target.seed_path
        log = to_sarif(hypotheses, artifact_uri(scanned))
        Path(args.sarif).write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps([hyp.to_dict() for hyp in hypotheses], indent=2))
        return 0
    text = render(hypotheses)
    if text:
        print(text)
    noun = "lead" if len(hypotheses) == 1 else "leads"
    print(f"{len(hypotheses)} {noun} in {target.name}")
    return 0


def _offline_attacker(name: str, target: Target) -> Attacker:
    """The offline attacker for a `--attacker` choice."""
    if name == "white-box":
        return ScoutAttacker(target)
    return PlaybookAttacker(target, adaptive=name == "playbook")


def _build_agents(
    backend_name: str,
    model: str | None,
    target: Target,
    attacker_name: str = DEFAULT_ATTACKER,
) -> tuple[Attacker, Patcher]:
    """Return the attacker and patcher for the chosen backend and target."""
    if backend_name == "offline":
        return _offline_attacker(attacker_name, target), ReferencePatcher(target)
    backend = make_backend(backend_name, model)
    if backend is None:
        raise LLMError(f"no backend available for {backend_name!r}")
    attacker = LLMAttacker(backend, fallback=PlaybookAttacker(target), target=target)
    return attacker, LLMPatcher(backend, target=target)


def _print_rounds(result: ArenaResult) -> None:
    """Print one status line per round."""
    for summary in result.rounds:
        accepted = sum(1 for outcome in summary.outcomes if outcome.accepted)
        rejected = len(summary.outcomes) - accepted
        print(
            f"round {summary.number}: {summary.probes_sent} probes, "
            f"{len(summary.findings)} findings, {accepted} patches accepted, "
            f"{rejected} rejected"
        )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "bench":
        return _bench(args)
    if args.command == "scout":
        return _scout(args)
    target = get_target(args.target)
    try:
        attacker, patcher = _build_agents(args.backend, args.model, target, args.attacker)
    except LLMError as exc:
        print(f"redteam: {exc}", file=sys.stderr)
        return EXIT_BACKEND_ERROR

    out_dir = args.out or _default_out()
    config = ArenaConfig(rounds=args.rounds, budget=args.budget)
    result = Arena(attacker, patcher, target=target, config=config, out_dir=out_dir).run()

    _print_rounds(result)
    if result.untested:
        print(
            f"result: untested, the attacker sent no probes after {len(result.rounds)} "
            f"rounds (stopped: {result.stop_reason}). output: {out_dir}"
        )
    else:
        state = "hardened" if result.hardened else "not hardened"
        print(
            f"result: {state}, {len(result.open_findings)} open after {len(result.rounds)} "
            f"rounds (stopped: {result.stop_reason}). output: {out_dir}"
        )
    if result.audit is not None:
        print(
            f"audit: {result.audit.landed_count} of {result.audit.total} held-out exploits landed"
        )
    return EXIT_HARDENED if result.hardened else EXIT_OPEN
