"""Exact text edits: happy path and the three ways an edit can fail."""

import pytest

from redteam.models import Edit
from redteam.patching import PatchError, apply_edits, edits_apply

SOURCE = "alpha\nbeta\ngamma\n"


def test_edits_apply_in_order():
    edits = [Edit("alpha", "one"), Edit("one\nbeta", "two")]
    assert apply_edits(SOURCE, edits) == "two\ngamma\n"
    assert edits_apply(SOURCE, edits)


def test_missing_old_text_is_rejected():
    with pytest.raises(PatchError, match="not found"):
        apply_edits(SOURCE, [Edit("delta", "x")])
    assert not edits_apply(SOURCE, [Edit("delta", "x")])


def test_ambiguous_old_text_is_rejected():
    source = "x = 1\ny = 1\n"
    with pytest.raises(PatchError, match="ambiguous"):
        apply_edits(source, [Edit("= 1", "= 2")])


def test_overlapping_matches_count_as_ambiguous():
    with pytest.raises(PatchError, match="ambiguous"):
        apply_edits("aaa", [Edit("aa", "b")])


def test_empty_old_text_is_rejected():
    with pytest.raises(PatchError, match="empty"):
        apply_edits(SOURCE, [Edit("", "x")])


def test_no_edits_returns_source_unchanged():
    assert apply_edits(SOURCE, []) == SOURCE
