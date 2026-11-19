"""The arms-race timeline: one SVG row per weakness, one column per round, plus an audit column.

The picture is built from the arena result alone, so the same run always gives the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from xml.sax.saxutils import escape

if TYPE_CHECKING:
    from redteam.arena import ArenaResult

CellState = Literal["", "found", "open", "bypassed", "closed"]

FONT_FAMILY = "system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif"
MARGIN = 16
HEADER_HEIGHT = 28
CELL_WIDTH = 88
CELL_HEIGHT = 32
GAP = 6
KEY_CHAR_WIDTH = 7
MIN_KEY_WIDTH = 120
LEGEND_ITEM_WIDTH = 120
LEGEND_STATES: tuple[str, ...] = ("found", "open", "bypassed", "closed")

# Fill and text colours per state. Audit "clean" reuses the closed colours, "exposed" the open ones.
COLOURS: dict[str, tuple[str, str]] = {
    "found": ("#dbeafe", "#1e3a8a"),
    "open": ("#fee2e2", "#991b1b"),
    "bypassed": ("#ffedd5", "#9a3412"),
    "closed": ("#dcfce7", "#166534"),
}
EMPTY_FILL = "#ffffff"
EMPTY_STROKE = "#e5e7eb"


@dataclass(frozen=True)
class Timeline:
    """The grid behind the picture.

    keys are weakness keys in order of first landing (ties sorted). cells holds one state per
    (key, round). audit maps each key to True when the audit still lands in its vulnerability
    class, and is empty when there was no audit. open_keys are the weaknesses still open when
    the run ended; the description needs them and the cells alone cannot say.
    """

    keys: tuple[str, ...]
    rounds: tuple[int, ...]
    cells: dict[tuple[str, int], CellState]
    audit: dict[str, bool]
    open_keys: frozenset[str] = field(default_factory=frozenset)


def build_timeline(result: ArenaResult) -> Timeline:
    """Derive the grid from the rounds' findings and patch outcomes."""
    rounds = tuple(summary.number for summary in result.rounds)
    landed: dict[int, set[str]] = {}
    accepted: dict[int, set[str]] = {}
    first_round: dict[str, int] = {}
    for summary in result.rounds:
        landed[summary.number] = {finding.key for finding in summary.findings}
        accepted[summary.number] = {outcome.key for outcome in summary.outcomes if outcome.accepted}
        for key in sorted(landed[summary.number]):
            first_round.setdefault(key, summary.number)
    keys = tuple(sorted(first_round, key=lambda key: (first_round[key], key)))

    cells: dict[tuple[str, int], CellState] = {}
    patched_before: set[str] = set()
    for number in rounds:
        for key in keys:
            cells[(key, number)] = _cell_state(
                key in landed[number], key in patched_before, key in accepted[number]
            )
        patched_before |= accepted[number]

    audit_map: dict[str, bool] = {}
    if result.audit is not None:
        exposed = set(result.audit.exposed_classes)
        audit_map = {key: key.split(":", 1)[0] in exposed for key in keys}

    return Timeline(
        keys=keys,
        rounds=rounds,
        cells=cells,
        audit=audit_map,
        open_keys=frozenset(key for key in keys if key in result.open_findings),
    )


def _cell_state(landed: bool, patched_before: bool, patched_now: bool) -> CellState:
    """The state of one (weakness, round) cell."""
    if landed:
        if patched_before:
            return "bypassed"
        return "found" if patched_now else "open"
    if patched_before or patched_now:
        return "closed"
    return ""


def _text_width(text: str) -> int:
    """Rough pixel width of a label at the key font size, kept as an integer."""
    return len(text) * KEY_CHAR_WIDTH


def render_svg(timeline: Timeline, *, title: str) -> str:
    """Render the timeline as a standalone SVG document: no scripts, links or fonts to load."""
    has_audit = bool(timeline.audit)
    columns: list[tuple[str, int | None]] = [
        (f"Round {number}", number) for number in timeline.rounds
    ]
    if has_audit:
        columns.append(("Audit", None))

    label_width = max([MIN_KEY_WIDTH] + [_text_width(key) + 2 * MARGIN for key in timeline.keys])
    grid_x = MARGIN + label_width
    grid_y = MARGIN + HEADER_HEIGHT
    grid_width = len(columns) * (CELL_WIDTH + GAP) - GAP
    grid_height = len(timeline.keys) * (CELL_HEIGHT + GAP) - GAP if timeline.keys else 0
    legend_y = grid_y + grid_height + 2 * MARGIN
    legend_width = len(LEGEND_STATES) * LEGEND_ITEM_WIDTH
    width = grid_x + max(grid_width, legend_width) + MARGIN
    height = legend_y + 14 + MARGIN

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc" '
        f'font-family="{escape(FONT_FAMILY)}">',
        f'<title id="title">{escape(title)}</title>',
        f'<desc id="desc">{escape(_describe(timeline))}</desc>',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>',
    ]

    for index, (label, _number) in enumerate(columns):
        x = grid_x + index * (CELL_WIDTH + GAP) + CELL_WIDTH // 2
        parts.append(
            f'<text x="{x}" y="{MARGIN + 16}" font-size="12" fill="#374151" '
            f'text-anchor="middle">{escape(label)}</text>'
        )

    for row, key in enumerate(timeline.keys):
        y = grid_y + row * (CELL_HEIGHT + GAP)
        parts.append(
            f'<text x="{MARGIN}" y="{y + CELL_HEIGHT // 2 + 5}" font-size="13" '
            f'fill="#111827">{escape(key)}</text>'
        )
        for index, (_label, number) in enumerate(columns):
            x = grid_x + index * (CELL_WIDTH + GAP)
            if number is None:
                exposed = timeline.audit.get(key, False)
                parts.append(
                    _cell_svg(
                        x, y, "open" if exposed else "closed", "exposed" if exposed else "clean"
                    )
                )
            else:
                state = timeline.cells.get((key, number), "")
                parts.append(_cell_svg(x, y, state, state))

    for index, state in enumerate(LEGEND_STATES):
        x = grid_x + index * LEGEND_ITEM_WIDTH
        fill, stroke = COLOURS[state]
        parts.append(
            f'<rect x="{x}" y="{legend_y}" width="14" height="14" rx="3" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x + 20}" y="{legend_y + 12}" font-size="12" fill="#374151">{state}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _describe(timeline: Timeline) -> str:
    """One plain sentence summarising the run for the SVG's desc element."""
    bypassed = sum(
        1
        for key in timeline.keys
        if any(timeline.cells.get((key, number)) == "bypassed" for number in timeline.rounds)
    )
    status = "all closed" if not timeline.open_keys else f"{len(timeline.open_keys)} still open"
    if not timeline.audit:
        audit_text = "no audit"
    elif any(timeline.audit.values()):
        audit_text = f"audit exposed in {sum(timeline.audit.values())}"
    else:
        audit_text = "audit clean"
    return (
        f"{len(timeline.keys)} weaknesses over {len(timeline.rounds)} rounds; "
        f"{bypassed} were bypassed after a fix; {status}; {audit_text}."
    )


def _text_width(text: str) -> int:
    """Rough pixel width of a key label at the key font size, kept as an integer."""
    return len(text) * KEY_CHAR_WIDTH


def _cell_svg(x: int, y: int, state: str, label: str) -> str:
    """One rounded cell. Blank cells are outlined with no label."""
    if state == "":
        return (
            f'<rect x="{x}" y="{y}" width="{CELL_WIDTH}" height="{CELL_HEIGHT}" rx="4" '
            f'fill="{EMPTY_FILL}" stroke="{EMPTY_STROKE}" stroke-width="1"/>'
        )
    fill, text_colour = COLOURS[state]
    return (
        f'<rect x="{x}" y="{y}" width="{CELL_WIDTH}" height="{CELL_HEIGHT}" rx="4" '
        f'fill="{fill}"/>'
        f'<text x="{x + CELL_WIDTH // 2}" y="{y + CELL_HEIGHT // 2 + 4}" font-size="12" '
        f'fill="{text_colour}" text-anchor="middle">{label}</text>'
    )


def write_timeline(out_dir: Path, result: ArenaResult, *, title: str) -> None:
    """Write `timeline.svg` into `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "timeline.svg").write_text(
        render_svg(build_timeline(result), title=title), encoding="utf-8"
    )
