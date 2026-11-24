"""A book-lending service that is vulnerable on purpose.

This file is the seed target for the red team loop. It is never edited in
place: the sandbox copies it into a per-run workspace and the patcher edits
that copy. Do not deploy it anywhere.

Seeded weaknesses (the fix catalog lives in the target's __init__.py):
  sqli             GET /books/search        the search term is pasted into the SQL text
  idor             GET /loans/{loan_id}     a loan is returned whoever it belongs to
  path_traversal   GET /covers              the cover name is joined onto the covers folder
  ssrf             POST /covers/fetch       any URL is fetched through an in-memory fake web
  mass_assignment  PATCH /members/me        every field in the body is written to the member
  auth_bypass      GET /staff/report        trusts a caller-supplied as_member cookie
"""

import secrets
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

PARTNER_HOST = "covers.partner.example"


class ProfileUpdate(BaseModel):
    """The fields a member sends when they update their own profile."""

    name: str | None = None
    email: str | None = None


class CoverFetch(BaseModel):
    """A request to fetch the cover for one book from a URL."""

    book_id: int
    url: str


def as_member(row) -> dict:
    return {"id": row[0], "name": row[1], "email": row[2], "is_staff": bool(row[3])}


def as_book(row) -> dict:
    return {"id": row[0], "title": row[1], "notes": row[2]}


def as_loan(row) -> dict:
    return {"id": row[0], "book_id": row[1], "member_id": row[2], "due": row[3], "notes": row[4]}


def cookie_member(raw_cookie: str) -> str | None:
    """Return the as_member value from a raw Cookie header, ignoring case and spacing."""
    for part in raw_cookie.split(";"):
        name, _, value = part.partition("=")
        if name.strip().lower() == "as_member":
            return value.strip().lower()
    return None


def read_cover(covers_dir: Path, name: str) -> str:
    """Read one cover by name from the covers folder."""
    # path_traversal: the resolved path must stay inside the covers folder
    base = covers_dir.resolve()
    path = (base / name).resolve()
    if base not in path.parents:
        raise FileNotFoundError(name)
    return path.read_text(encoding="utf-8")


def fetch_from_fake_web(web: dict[str, dict[str, str]], url: str) -> str:
    """Look up a URL in the in-memory web: host, then path. Pure dict lookups, no I/O."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    return web[host][parts.path]


class LibraryRepo:
    """Every query the app runs. Routes call these helpers and never touch the connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def member_by_token(self, token: str | None) -> dict | None:
        row = self.conn.execute(
            "SELECT id, name, email, is_staff FROM members WHERE token = ?", (token,)
        ).fetchone()
        return None if row is None else as_member(row)

    def member_by_name(self, name: str) -> dict | None:
        row = self.conn.execute(
            "SELECT id, name, email, is_staff FROM members WHERE lower(name) = ?", (name,)
        ).fetchone()
        return None if row is None else as_member(row)

    def member_by_id(self, member_id: int) -> dict:
        row = self.conn.execute(
            "SELECT id, name, email, is_staff FROM members WHERE id = ?", (member_id,)
        ).fetchone()
        return as_member(row)

    def set_member_field(self, member_id: int, field: str, value) -> None:
        # The column is named by the request model's field, so any field it holds is written.
        sql = "UPDATE members SET {} = ? WHERE id = ?"
        self.conn.execute(sql.format(field), (value, member_id))
        self.conn.commit()

    def search_books(self, term: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, title, notes FROM books WHERE staff_only = 0 AND title LIKE ?",
            ("%" + term + "%",),
        ).fetchall()
        return [as_book(row) for row in rows]

    def loan_by_id(self, loan_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT id, book_id, member_id, due, notes FROM loans WHERE id = ?", (loan_id,)
        ).fetchone()
        return None if row is None else as_loan(row)


def create_app(data_dir: str | Path, canary: str) -> FastAPI:
    """Build the library app. The canary sits only behind an exploit: a staff-only book, a staff
    loan, the staff report and profile, a file outside the covers folder, and an internal host.
    """
    app = FastAPI(title="library-service")
    covers_dir = Path(data_dir) / "covers"
    web = {
        PARTNER_HOST: {"/dune.txt": "COVER-DUNE-REMOTE"},
        "metadata.internal": {"/latest/secret": f"instance metadata: vault_key={canary}"},
    }

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE members "
        "(id INTEGER PRIMARY KEY, name TEXT, email TEXT, is_staff INTEGER, token TEXT)"
    )
    conn.execute(
        "CREATE TABLE books (id INTEGER PRIMARY KEY, title TEXT, notes TEXT, staff_only INTEGER)"
    )
    conn.execute(
        "CREATE TABLE loans "
        "(id INTEGER PRIMARY KEY, book_id INTEGER, member_id INTEGER, due TEXT, notes TEXT)"
    )
    conn.executemany(
        "INSERT INTO members VALUES (?, ?, ?, ?, ?)",
        [
            (1, "staff", "staff@library.example", 1, secrets.token_hex(16)),
            (2, "alice", "alice@library.example", 0, "alice-token"),
            (3, "mallory", "mallory@library.example", 0, "mallory-token"),
        ],
    )
    conn.executemany(
        "INSERT INTO books VALUES (?, ?, ?, ?)",
        [
            (1, "Dune", "Desert classic", 0),
            (2, "The Left Hand of Darkness", "Winter planet", 0),
            (3, "Acquisitions Ledger", f"Vault key {canary}", 1),
        ],
    )
    conn.executemany(
        "INSERT INTO loans VALUES (?, ?, ?, ?, ?)",
        [
            (1, 3, 1, "2026-11-30", f"Reconciliation key {canary}"),
            (2, 1, 3, "2026-12-05", "Mallory's loan"),
            (3, 1, 2, "2026-12-01", "Shelf B2"),
            (4, 2, 2, "2026-12-10", "Shelf C4"),
        ],
    )
    conn.commit()
    repo = LibraryRepo(conn)

    def current_member(request: Request, x_token: Annotated[str | None, Header()] = None) -> dict:
        member = repo.member_by_token(x_token)
        if member is None:
            raise HTTPException(status_code=401, detail="unknown token")
        return member

    CurrentMember = Annotated[dict, Depends(current_member)]

    def profile_for(member_id: int) -> dict:
        profile = repo.member_by_id(member_id)
        if profile["is_staff"]:
            profile["reconciliation_key"] = canary
        return profile

    @app.get("/members/me")
    def get_me(member: CurrentMember):
        return profile_for(member["id"])

    @app.patch("/members/me")
    def update_me(update: ProfileUpdate, member: CurrentMember):
        # mass_assignment: every field the model holds is written to the member row
        for field, value in update.model_dump(exclude_unset=True).items():
            repo.set_member_field(member["id"], field, value)
        return profile_for(member["id"])

    @app.get("/books/search")
    def find_books(q: str, member: CurrentMember):
        return {"books": repo.search_books(q)}

    @app.get("/loans/{loan_id}")
    def get_loan(loan_id: int, member: CurrentMember):
        loan = repo.loan_by_id(loan_id)
        # idor: the loan is returned only to the member it belongs to
        if loan is None or loan["member_id"] != member["id"]:
            raise HTTPException(status_code=404, detail="not found")
        return loan

    @app.get("/covers")
    def get_cover(name: str, member: CurrentMember):
        try:
            text = read_cover(covers_dir, name)
        except OSError:
            raise HTTPException(status_code=404, detail="no such cover") from None
        return {"name": name, "text": text}

    @app.post("/covers/fetch")
    def fetch_cover(body: CoverFetch, member: CurrentMember):
        # ssrf: only https links to the partner host are fetched, with no user info
        try:
            parts = urllib.parse.urlsplit(body.url)
            host = (parts.hostname or "").rstrip(".")
            if parts.scheme != "https" or host != PARTNER_HOST or "@" in parts.netloc:
                raise ValueError(body.url)
            text = fetch_from_fake_web(web, body.url)
        except (KeyError, ValueError):
            raise HTTPException(status_code=404, detail="cannot fetch") from None
        return {"book_id": body.book_id, "cover": text}

    @app.get("/staff/report")
    def staff_report(member: CurrentMember):
        if not member["is_staff"]:
            raise HTTPException(status_code=403, detail="staff only")
        return {"open_loans": 3, "reconciliation_key": canary}

    return app
