"""Command line entry point: `redteam run` plays the arms race and writes its outputs."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime

from redteam.agents.attacker import Attacker, LLMAttacker, PlaybookAttacker
from redteam.agents.patcher import LLMPatcher, Patcher, ReferencePatcher
from redteam.arena import Arena, ArenaConfig, ArenaResult
from redteam.llm import LLMError, make_backend

DEFAULT_ROUNDS = 6
DEFAULT_BUDGET = 40
EXIT_HARDENED = 0
EXIT_OPEN = 1
EXIT_BACKEND_ERROR = 2


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
    run.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help="maximum rounds")
    run.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="probes per round")
    run.add_argument(
        "--out",
        default=None,
        help="output directory (default runs/<UTC timestamp>)",
    )
    return parser


def _default_out() -> str:
    return f"runs/{datetime.now(UTC):%Y%m%d-%H%M%S}"


def _build_agents(backend_name: str, model: str | None) -> tuple[Attacker, Patcher]:
    """Return the attacker and patcher for the chosen backend."""
    if backend_name == "offline":
        return PlaybookAttacker(), ReferencePatcher()
    backend = make_backend(backend_name, model)
    if backend is None:
        raise LLMError(f"no backend available for {backend_name!r}")
    return LLMAttacker(backend, fallback=PlaybookAttacker()), LLMPatcher(backend)


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
    try:
        attacker, patcher = _build_agents(args.backend, args.model)
    except LLMError as exc:
        print(f"redteam: {exc}", file=sys.stderr)
        return EXIT_BACKEND_ERROR

    out_dir = args.out or _default_out()
    config = ArenaConfig(rounds=args.rounds, budget=args.budget)
    result = Arena(attacker, patcher, config=config, out_dir=out_dir).run()

    _print_rounds(result)
    state = "hardened" if result.hardened else "not hardened"
    print(
        f"result: {state}, {len(result.open_findings)} open after {len(result.rounds)} "
        f"rounds (stopped: {result.stop_reason}). output: {out_dir}"
    )
    return EXIT_HARDENED if result.hardened else EXIT_OPEN
