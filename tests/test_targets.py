"""The target value: registry, notes definition, sandbox token and reset behaviour."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig
from redteam.cli import main
from redteam.models import Probe
from redteam.sandbox import Sandbox
from redteam.targets import NOTES, TARGETS, get_target


def test_get_target_returns_the_notes_target() -> None:
    assert get_target("notes") is NOTES
    assert TARGETS["notes"] is NOTES


def test_unknown_target_raises_key_error_naming_known_targets() -> None:
    with pytest.raises(KeyError, match="notes"):
        get_target("billing")


def test_notes_functional_checks_pass_on_the_seed_app() -> None:
    with Sandbox(target=NOTES) as sandbox:
        for check in NOTES.functional_checks:
            result = sandbox.send(check.probe, token=NOTES.user_token)
            assert result.status == check.expect_status, check.name
            if check.expect_text is not None:
                assert check.expect_text in result.body, check.name


def test_send_without_token_uses_the_attacker_token() -> None:
    with Sandbox(target=NOTES) as sandbox:
        result = sandbox.send(Probe("GET", "/notes", "GET /notes"))
        assert result.status == 200
        assert "Todo" in result.body
        assert "Groceries" not in result.body


def test_send_with_token_none_sends_no_token_header() -> None:
    with Sandbox(target=NOTES) as sandbox:
        result = sandbox.send(Probe("GET", "/notes", "GET /notes"), token=None)
        assert result.status == 422
        assert "x-token" in result.body


def test_reset_drops_created_notes_and_keeps_the_canary() -> None:
    with Sandbox(target=NOTES) as sandbox:
        canary = sandbox.canary
        created = Probe("POST", "/notes", "POST /notes", json_body={"title": "temp", "body": "x"})
        assert sandbox.send(created).status == 200
        assert "temp" in sandbox.send(Probe("GET", "/notes", "GET /notes")).body

        sandbox.reset()

        assert "temp" not in sandbox.send(Probe("GET", "/notes", "GET /notes")).body
        assert sandbox.canary == canary
        assert canary in (sandbox.data_dir / "secrets.txt").read_text(encoding="utf-8")


def test_arena_with_isolated_probes_still_hardens_the_target(tmp_path: Path) -> None:
    target = dataclasses.replace(NOTES, isolate_probes=True)
    arena = Arena(
        PlaybookAttacker(target),
        ReferencePatcher(target),
        target=target,
        config=ArenaConfig(rounds=6),
        out_dir=tmp_path,
    )
    result = arena.run()
    assert result.hardened
    assert result.open_findings == {}


def test_cli_run_with_notes_target_writes_target_to_summary(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert main(["run", "--target", "notes", "--out", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["target"] == "notes"
    assert "Target: notes" in (out / "ARMS_RACE.md").read_text(encoding="utf-8")


def test_notes_catalog_marks_only_the_first_sqli_and_traversal_attempts_naive() -> None:
    naive = {
        key: [index for index, attempt in enumerate(attempts) if attempt.naive]
        for key, attempts in NOTES.fix_catalog.items()
    }
    assert {key: idx for key, idx in naive.items() if idx} == {
        "sqli:GET /notes/search": [0],
        "path_traversal:GET /files": [0],
    }
