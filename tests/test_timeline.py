"""The arms-race timeline: the grid it is built from, the SVG it renders, and the run outputs."""

from __future__ import annotations

import dataclasses
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaResult
from redteam.cli import main
from redteam.targets import NOTES
from redteam.timeline import Timeline, build_timeline, render_svg, write_timeline

SVG_NS = "{http://www.w3.org/2000/svg}"
TITLE = "Arms race on notes: playbook vs reference"


@pytest.fixture(scope="module")
def notes_result() -> ArenaResult:
    """A fresh offline run of the notes target with the default config."""
    return Arena(PlaybookAttacker(NOTES), ReferencePatcher(NOTES), target=NOTES).run()


@pytest.fixture(scope="module")
def naive_result() -> ArenaResult:
    """A one-shot attacker against the naive-first patcher: the fixes that get bypassed."""
    return Arena(
        PlaybookAttacker(NOTES, adaptive=False),
        ReferencePatcher(NOTES),
        target=NOTES,
    ).run()


def _row(timeline: Timeline, key: str) -> list[str]:
    return [timeline.cells[(key, number)] for number in timeline.rounds]


def test_notes_rows_read_as_the_arms_race_describes(notes_result: ArenaResult) -> None:
    timeline = build_timeline(notes_result)

    assert timeline.rounds == (1, 2, 3)
    assert _row(timeline, "sqli:GET /notes/search") == ["found", "bypassed", "closed"]
    assert _row(timeline, "path_traversal:GET /files") == ["found", "bypassed", "closed"]
    assert _row(timeline, "idor:GET /notes/{note_id}") == ["found", "closed", "closed"]
    assert _row(timeline, "crash:GET /notes") == ["found", "closed", "closed"]


def test_notes_audit_column_is_clean(notes_result: ArenaResult) -> None:
    timeline = build_timeline(notes_result)

    assert set(timeline.audit) == set(timeline.keys)
    assert not any(timeline.audit.values())
    assert timeline.open_keys == frozenset()


def test_naive_first_run_has_no_bypass_and_exposes_the_audit(naive_result: ArenaResult) -> None:
    timeline = build_timeline(naive_result)

    assert "bypassed" not in timeline.cells.values()
    assert timeline.audit["sqli:GET /notes/search"] is True
    assert timeline.audit["path_traversal:GET /files"] is True
    assert timeline.audit["idor:GET /notes/{note_id}"] is False
    assert timeline.audit["crash:GET /notes"] is False


def test_no_audit_means_no_audit_column(notes_result: ArenaResult) -> None:
    timeline = build_timeline(dataclasses.replace(notes_result, audit=None))

    assert timeline.audit == {}
    assert "Audit" not in render_svg(timeline, title=TITLE)


def test_render_svg_is_deterministic(notes_result: ArenaResult) -> None:
    first = render_svg(build_timeline(notes_result), title=TITLE)
    second = render_svg(build_timeline(notes_result), title=TITLE)

    assert first == second
    assert first.endswith("\n")


def test_render_svg_parses_and_carries_title_and_summary(notes_result: ArenaResult) -> None:
    text = render_svg(build_timeline(notes_result), title=TITLE)
    root = ET.fromstring(text)

    assert root.tag == f"{SVG_NS}svg"
    assert root.find(f"{SVG_NS}title").text == TITLE
    assert root.find(f"{SVG_NS}desc").text == (
        "4 weaknesses over 3 rounds; 2 were bypassed after a fix; all closed; audit clean."
    )
    assert "<script" not in text
    assert "href" not in text


def test_render_svg_escapes_markup_in_keys() -> None:
    timeline = Timeline(
        keys=('odd<&>:"x"',),
        rounds=(1,),
        cells={('odd<&>:"x"', 1): "open"},
        audit={},
    )
    text = render_svg(timeline, title="a & b <c>")
    root = ET.fromstring(text)

    labels = [node.text for node in root.iter(f"{SVG_NS}text")]
    assert 'odd<&>:"x"' in labels
    assert root.find(f"{SVG_NS}title").text == "a & b <c>"


def test_render_svg_never_contains_a_canary(notes_result: ArenaResult) -> None:
    assert "CANARY-" not in render_svg(build_timeline(notes_result), title=TITLE)


def test_write_timeline_writes_the_rendered_svg(tmp_path: Path, notes_result: ArenaResult) -> None:
    write_timeline(tmp_path, notes_result, title=TITLE)

    expected = render_svg(build_timeline(notes_result), title=TITLE)
    assert (tmp_path / "timeline.svg").read_text(encoding="utf-8") == expected


def test_cli_run_writes_timeline_and_links_it_from_the_report(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert main(["run", "--target", "notes", "--out", str(out)]) == 0

    assert (out / "timeline.svg").is_file()
    report = (out / "ARMS_RACE.md").read_text(encoding="utf-8")
    assert "![Arms-race timeline](timeline.svg)" in report
    svg = (out / "timeline.svg").read_text(encoding="utf-8")
    assert ET.fromstring(svg).find(f"{SVG_NS}title").text == (
        "Arms race on notes: playbook vs reference"
    )
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["hardened"] is True
