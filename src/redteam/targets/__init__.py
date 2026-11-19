"""Registry of attack targets. Each target is a `Target` value, `notes` by default."""

from __future__ import annotations

from redteam.targets.base import Target
from redteam.targets.notes import NOTES

DEFAULT_TARGET = "notes"
TARGETS: dict[str, Target] = {"notes": NOTES}


def get_target(name: str) -> Target:
    """Return the target registered under `name`, or raise KeyError listing the known names."""
    try:
        return TARGETS[name]
    except KeyError:
        known = ", ".join(sorted(TARGETS))
        raise KeyError(f"unknown target {name!r}; known targets: {known}") from None


def default_target() -> Target:
    """Return the default target."""
    return get_target(DEFAULT_TARGET)


__all__ = ["DEFAULT_TARGET", "NOTES", "TARGETS", "Target", "default_target", "get_target"]
