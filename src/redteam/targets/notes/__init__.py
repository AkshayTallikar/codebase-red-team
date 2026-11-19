"""The notes target: a notes service with seeded sqli, idor, path traversal and crash bugs."""

from __future__ import annotations

from pathlib import Path

from redteam.models import Edit, FixAttempt, FunctionalCheck, Probe
from redteam.targets.base import Target


def _write_data(data_dir: Path, canary: str) -> None:
    """Write the public readme and the secret file that holds the canary."""
    public = data_dir / "public"
    public.mkdir(parents=True, exist_ok=True)
    (public / "readme.txt").write_text("Welcome to the notes service.\n", encoding="utf-8")
    (data_dir / "secrets.txt").write_text(f"db_password={canary}\n", encoding="utf-8")


def _edit(old: str, new: str = "") -> Edit:
    return Edit(old=old, new=new)


_FUNCTIONAL_CHECKS: tuple[FunctionalCheck, ...] = (
    FunctionalCheck(
        name="list notes with limit",
        probe=Probe("GET", "/notes", "GET /notes", params={"limit": "10"}),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="list notes without params",
        probe=Probe("GET", "/notes", "GET /notes"),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="search own notes",
        probe=Probe("GET", "/notes/search", "GET /notes/search", params={"q": "Gro"}),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="read own note",
        probe=Probe("GET", "/notes/2", "GET /notes/{note_id}"),
        expect_status=200,
        expect_text="Groceries",
    ),
    FunctionalCheck(
        name="create note",
        probe=Probe(
            "POST",
            "/notes",
            "POST /notes",
            json_body={"title": "gate check", "body": "ok"},
        ),
        expect_status=200,
        expect_text="id",
    ),
    FunctionalCheck(
        name="read public readme",
        probe=Probe("GET", "/files", "GET /files", params={"name": "readme.txt"}),
        expect_status=200,
        expect_text="Welcome",
    ),
)


def _seed_probes() -> tuple[Probe, ...]:
    """The first-round hypotheses, one or more per vulnerability class."""
    probes = [
        Probe(
            method="GET",
            path="/notes/search",
            endpoint="GET /notes/search",
            vuln_class="sqli",
            params={"q": "' OR 1=1 --"},
            note="sqli: tautology in the search query may return other users' notes",
        ),
    ]
    probes.extend(
        Probe(
            method="GET",
            path=f"/notes/{note_id}",
            endpoint="GET /notes/{note_id}",
            vuln_class="idor",
            note="idor: note ids may be read across owners",
        )
        for note_id in range(1, 6)
    )
    probes.append(
        Probe(
            method="GET",
            path="/files",
            endpoint="GET /files",
            vuln_class="path_traversal",
            params={"name": "../secrets.txt"},
            note="path_traversal: name may escape the public data directory",
        )
    )
    probes.extend(
        Probe(
            method="GET",
            path="/notes",
            endpoint="GET /notes",
            vuln_class="crash",
            params={"limit": limit},
            note="crash: unvalidated limit may reach slicing or division",
        )
        for limit in ("0", "abc")
    )
    return tuple(probes)


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

_FIX_CATALOG: dict[str, tuple[FixAttempt, ...]] = {
    "sqli:GET /notes/search": (
        FixAttempt(
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
            naive=True,
        ),
        FixAttempt(
            rationale="Uses a parameterised query so user input is never parsed as SQL, and "
            "removes the keyword check.",
            alternatives=(
                (_SQLI_NAIVE_CHECK, _edit(_SQLI_SQL_OLD, _SQLI_SQL_NEW)),
                (_edit(_SQLI_SQL_OLD, _SQLI_SQL_NEW),),
            ),
        ),
    ),
    "idor:GET /notes/{note_id}": (
        FixAttempt(
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
        FixAttempt(
            rationale="Strips ../ sequences from the file name before joining. Naive: nested "
            "sequences such as ....// survive the stripping.",
            alternatives=(
                (_edit(_TRAVERSAL_OLD_PATH, _TRAVERSAL_NAIVE_LINE + _TRAVERSAL_OLD_PATH),),
            ),
            naive=True,
        ),
        FixAttempt(
            rationale="Resolves the real path and refuses anything outside the public directory.",
            alternatives=(
                (_edit(_TRAVERSAL_NAIVE_LINE + _TRAVERSAL_OLD_PATH, _TRAVERSAL_NEW_PATH),),
                (_edit(_TRAVERSAL_OLD_PATH, _TRAVERSAL_NEW_PATH),),
            ),
        ),
    ),
    "crash:GET /notes": (
        FixAttempt(
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


NOTES = Target(
    name="notes",
    description="a notes service where users list, search, read and create their own notes "
    "and read public files",
    seed_path=Path(__file__).parent / "app.py",
    vuln_classes=("sqli", "idor", "path_traversal", "crash"),
    attacker_token="mallory-token",
    user_token="alice-token",
    functional_checks=_FUNCTIONAL_CHECKS,
    seed_probes=_seed_probes(),
    fix_catalog=_FIX_CATALOG,
    patch_guidance=(
        "Keep legitimate behaviour working: the user alice must still list, search, read and "
        "create her own notes, and read the public readme. Prefer real fixes: parameterised "
        "queries, ownership checks, resolved-path containment and input validation."
    ),
    write_data=_write_data,
)
