"""Patchers propose source edits for a finding: an offline catalog and an LLM."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from redteam.llm.base import LLMBackend, LLMError
from redteam.models import Edit, Finding, Patch
from redteam.patching import edits_apply

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


@dataclass(frozen=True)
class _Attempt:
    """One fix for a weakness: a rationale and alternative edit-sets to try in order."""

    rationale: str
    alternatives: tuple[tuple[Edit, ...], ...]


def _edit(old: str, new: str = "") -> Edit:
    return Edit(old=old, new=new)


_SQLI_NAIVE_BLOCK = (
    '        if " OR " in q:\n'
    '            raise HTTPException(status_code=400, detail="invalid query")\n'
)
_SQLI_NAIVE_CHECK = _edit(_SQLI_NAIVE_BLOCK)
_SQLI_SQL_OLD = """        sql = (
            "SELECT id, title, body FROM notes "
            f"WHERE owner_id = {user['id']} AND title LIKE '%{q}%'"
        )
        rows = conn.execute(sql).fetchall()
"""
_SQLI_SQL_NEW = """        rows = conn.execute(
            "SELECT id, title, body FROM notes WHERE owner_id = ? AND title LIKE ?",
            (user["id"], f"%{q}%"),
        ).fetchall()
"""
_TRAVERSAL_NAIVE_LINE = """        name = name.replace("../", "")
"""
_TRAVERSAL_OLD_PATH = """        path = os.path.join(data_dir, "public", name)
"""
_TRAVERSAL_NEW_PATH = """        base = os.path.realpath(os.path.join(data_dir, "public"))
        path = os.path.realpath(os.path.join(base, name))
        if not path.startswith(base + os.sep):
            raise HTTPException(status_code=404, detail="no such file")
"""

REFERENCE_CATALOG: dict[str, tuple[_Attempt, ...]] = {
    "sqli:GET /notes/search": (
        _Attempt(
            rationale="Blocks the OR keyword in the query string. Naive: case changes and "
            "other spellings of the same SQL get through.",
            alternatives=(
                (
                    _edit(
                        "def search_notes(q: str, user: User):\n",
                        "def search_notes(q: str, user: User):\n" + _SQLI_NAIVE_BLOCK,
                    ),
                ),
            ),
        ),
        _Attempt(
            rationale="Uses a parameterised query so user input is never parsed as SQL, and "
            "removes the keyword check.",
            alternatives=(
                (_SQLI_NAIVE_CHECK, _edit(_SQLI_SQL_OLD, _SQLI_SQL_NEW)),
                (_edit(_SQLI_SQL_OLD, _SQLI_SQL_NEW),),
            ),
        ),
    ),
    "idor:GET /notes/{note_id}": (
        _Attempt(
            rationale="Returns 404 unless the note belongs to the requesting user.",
            alternatives=(
                (
                    _edit(
                        "        if row is None:\n"
                        '            raise HTTPException(status_code=404, detail="not found")\n',
                        '        if row is None or row[3] != user["id"]:\n'
                        '            raise HTTPException(status_code=404, detail="not found")\n',
                    ),
                ),
            ),
        ),
    ),
    "path_traversal:GET /files": (
        _Attempt(
            rationale="Strips ../ sequences from the file name before joining. Naive: nested "
            "sequences such as ....// survive the stripping.",
            alternatives=(
                (_edit(_TRAVERSAL_OLD_PATH, _TRAVERSAL_NAIVE_LINE + _TRAVERSAL_OLD_PATH),),
            ),
        ),
        _Attempt(
            rationale="Resolves the real path and refuses anything outside the public directory.",
            alternatives=(
                (_edit(_TRAVERSAL_NAIVE_LINE + _TRAVERSAL_OLD_PATH, _TRAVERSAL_NEW_PATH),),
                (_edit(_TRAVERSAL_OLD_PATH, _TRAVERSAL_NEW_PATH),),
            ),
        ),
    ),
    "crash:GET /notes": (
        _Attempt(
            rationale="Validates limit as an integer between 1 and 100 at the request boundary.",
            alternatives=(
                (
                    _edit(
                        "from fastapi import Depends, FastAPI, Header, HTTPException",
                        "from fastapi import Depends, FastAPI, Header, HTTPException, Query",
                    ),
                    _edit(
                        'def list_notes(user: User, limit: str = "10"):',
                        "def list_notes(\n"
                        "        user: User, limit: Annotated[int, Query(ge=1, le=100)] = 10\n"
                        "    ):",
                    ),
                    _edit("n = int(limit)", "n = limit"),
                ),
            ),
        ),
    ),
}


class Patcher(Protocol):
    """Proposes a patch for a finding, or None when it has no idea to offer."""

    name: str

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        """Return a patch for `finding`; `attempt` counts earlier accepted patches for its key."""
        ...


class ReferencePatcher:
    """Offline patcher that replays a fixed catalog of fixes, naive ones first."""

    name = "reference"

    def propose(self, finding: Finding, source: str, attempt: int) -> Patch | None:
        """Return the first alternative of the catalog entry that applies to `source`."""
        attempts = REFERENCE_CATALOG.get(finding.key, ())
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
