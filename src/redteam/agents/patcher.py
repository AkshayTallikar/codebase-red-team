"""Patchers propose source edits for a finding: an offline catalog and an LLM."""

from __future__ import annotations

import json
from typing import Any, Protocol

from redteam.llm.base import LLMBackend, LLMError
from redteam.models import Edit, Finding, FixAttempt, Patch
from redteam.patching import edits_apply
from redteam.targets import NOTES, Target, default_target

PATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["rationale", "edits"],
    "properties": {
        "rationale": {"type": "string"},
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["old", "new"],
                "properties": {"old": {"type": "string"}, "new": {"type": "string"}},
            },
        },
    },
}

SYSTEM_PROMPT = """\
You are a security engineer hardening a deliberately vulnerable sample app (a notes
service) that is only ever attacked inside a sandbox. Propose a minimal fix for the one
weakness described in the finding.

Rules:
- Output exact text edits. Every "old" must be copied verbatim from the current source
  and must occur exactly once in it. Every "new" is its replacement.
- Keep legitimate behaviour working: the user alice must still list, search, read and
  create her own notes, and read the public readme.
- Prefer real fixes: parameterised queries, ownership checks, resolved-path containment
  and input validation. Do not rely on keyword blocklists or string stripping, because
  attackers route around them.
- Do not delete endpoints to make a finding go away.
"""


REFERENCE_CATALOG: dict[str, tuple[FixAttempt, ...]] = NOTES.fix_catalog


class Patcher(Protocol):
    """Proposes a patch for a finding, or None when it has no idea to offer."""

    name: str

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        """Return a patch for `finding`; `attempt` counts earlier accepted patches for its key."""
        ...


class ReferencePatcher:
    """Offline patcher that replays a target's fix catalog.

    By default the naive fixes come first. With `skip_naive=True` they are ignored, so
    attempt 0 is the first real fix.
    """

    name: str

    def __init__(self, target: Target | None = None, *, skip_naive: bool = False) -> None:
        self.target = target if target is not None else default_target()
        self.skip_naive = skip_naive
        self.name = "reference-correct-first" if skip_naive else "reference"

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        """Return the first alternative of the catalog entry that applies to `source`."""
        attempts = self.target.fix_catalog.get(finding.key, ())
        if self.skip_naive:
            attempts = tuple(entry for entry in attempts if not entry.naive)
        if not 0 <= attempt < len(attempts):
            return None
        entry = attempts[attempt]
        for edits in entry.alternatives:
            if edits_apply(source, edits):
                return Patch(
                    finding_key=finding.key,
                    edits=edits,
                    rationale=entry.rationale,
                    author=self.name,
                )
        return None


class LLMPatcher:
    """Asks a language model for exact text edits that fix the finding."""

    name = "llm"

    def __init__(self, backend: LLMBackend) -> None:
        self._backend = backend

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        """Return the model's patch, or None on refusal, error or malformed output."""
        prompt = _build_prompt(finding, source, attempt)
        try:
            data = self._backend.complete_json(
                system=SYSTEM_PROMPT, prompt=prompt, schema=PATCH_SCHEMA
            )
        except LLMError:
            return None
        return _parse_patch(finding, data, self.name)


def _build_prompt(finding: Finding, source: str, attempt: int) -> str:
    """Describe the finding with redacted evidence only, then the full current source."""
    probe = finding.probe
    body = json.dumps(probe.json_body, sort_keys=True) if probe.json_body is not None else "none"
    if attempt > 0:
        attempt_note = (
            f"This is attempt {attempt + 1} for this weakness. Earlier patches for it were "
            "bypassed, so close the whole weakness class, not only the probe below."
        )
    else:
        attempt_note = "This is the first patch for this weakness."
    return "\n".join(
        [
            f"Finding key: {finding.key}",
            f"Kind: {finding.kind}",
            f"Probe: {probe.method} {probe.path}",
            f"Probe params: {json.dumps(probe.params, sort_keys=True)}",
            f"Probe JSON body: {body}",
            f"Redacted evidence: {finding.evidence}",
            f"Attempt: {attempt} (zero-based count of accepted patches for this key)",
            attempt_note,
            "",
            "Current source:",
            source,
        ]
    )


def _parse_patch(finding: Finding, data: Any, author: str) -> Patch | None:
    """Turn the model's JSON object into a Patch, or None if it is malformed or empty."""
    if not isinstance(data, dict):
        return None
    rationale = data.get("rationale")
    raw_edits = data.get("edits")
    if not isinstance(rationale, str) or not isinstance(raw_edits, list):
        return None
    edits: list[Edit] = []
    for item in raw_edits:
        if not isinstance(item, dict):
            return None
        old, new = item.get("old"), item.get("new")
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            return None
        edits.append(Edit(old=old, new=new))
    if not edits:
        return None
    return Patch(
        finding_key=finding.key,
        edits=tuple(edits),
        rationale=rationale,
        author=author,
    )
