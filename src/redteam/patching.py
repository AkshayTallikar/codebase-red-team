"""Applies exact text edits to a source file, failing loudly on any mismatch."""

from __future__ import annotations

from collections.abc import Sequence

from redteam.models import Edit

EXCERPT_LIMIT = 60


class PatchError(ValueError):
    """An edit cannot be applied because its old text is empty, missing or ambiguous."""


def _excerpt(text: str) -> str:
    """Return a short, quoted excerpt of `text` for error messages."""
    short = text if len(text) <= EXCERPT_LIMIT else text[:EXCERPT_LIMIT] + "..."
    return repr(short)


def _count_matches(text: str, needle: str) -> int:
    """Count occurrences of `needle`, including overlapping ones, stopping at 2."""
    count = 0
    start = 0
    while count < 2:
        index = text.find(needle, start)
        if index == -1:
            break
        count += 1
        start = index + 1
    return count


def apply_edits(source: str, edits: Sequence[Edit]) -> str:
    """Apply `edits` in order; each `old` must occur exactly once in the current text."""
    text = source
    for number, edit in enumerate(edits, start=1):
        if not edit.old:
            raise PatchError(f"edit {number} has empty old text")
        matches = _count_matches(text, edit.old)
        if matches == 0:
            raise PatchError(f"edit {number}: old text not found: {_excerpt(edit.old)}")
        if matches > 1:
            raise PatchError(
                f"edit {number}: old text is ambiguous (occurs more than once): "
                f"{_excerpt(edit.old)}"
            )
        text = text.replace(edit.old, edit.new, 1)
    return text


def edits_apply(source: str, edits: Sequence[Edit]) -> bool:
    """Return True if `edits` apply cleanly to `source`."""
    try:
        apply_edits(source, edits)
    except PatchError:
        return False
    return True
