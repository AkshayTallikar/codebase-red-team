"""A small notes service that is vulnerable on purpose.

This file is the seed target for the red team loop. It is never edited in
place: the sandbox copies it into a per-run workspace and the patcher edits
that copy. Do not deploy it anywhere.

Seeded weaknesses (see docs/design.md):
  sqli            GET /notes/search   query built with string formatting
  idor            GET /notes/{id}     no ownership check
  path_traversal  GET /files          user input joined onto the data dir
  crash           GET /notes          unvalidated limit reaches slicing and division
"""

import os
import secrets
import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel


class NoteIn(BaseModel):
    title: str
    body: str


def create_app(data_dir: str | Path, canary: str) -> FastAPI:
    data_dir = str(data_dir)
    app = FastAPI(title="notes-service")

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, token TEXT)")
    conn.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT)"
    )
    users = [
        (1, "admin", secrets.token_hex(16)),
        (2, "alice", "alice-token"),
        (3, "mallory", "mallory-token"),
    ]
    conn.executemany("INSERT INTO users VALUES (?, ?, ?)", users)
    notes = [
        (1, 1, "Launch plan", f"Internal only. {canary}"),
        (2, 2, "Groceries", "eggs, milk, coffee"),
        (3, 2, "Ideas", "build a red team for my side project"),
        (4, 3, "Todo", "find bugs"),
    ]
    conn.executemany("INSERT INTO notes VALUES (?, ?, ?, ?)", notes)
    conn.commit()

    def current_user(x_token: Annotated[str, Header()]) -> dict:
        row = conn.execute("SELECT id, name FROM users WHERE token = ?", (x_token,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="unknown token")
        return {"id": row[0], "name": row[1]}

    User = Annotated[dict, Depends(current_user)]

    def as_note(row) -> dict:
        return {"id": row[0], "title": row[1], "body": row[2]}

    @app.get("/notes")
    def list_notes(user: User, limit: str = "10"):
        rows = conn.execute(
            "SELECT id, title, body FROM notes WHERE owner_id = ? ORDER BY id", (user["id"],)
        ).fetchall()
        n = int(limit)
        pages = (len(rows) + n - 1) // n
        return {"notes": [as_note(r) for r in rows[:n]], "pages": pages}

    @app.post("/notes")
    def create_note(note: NoteIn, user: User):
        cur = conn.execute(
            "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
            (user["id"], note.title, note.body),
        )
        conn.commit()
        return {"id": cur.lastrowid}

    @app.get("/notes/search")
    def search_notes(q: str, user: User):
        sql = (
            "SELECT id, title, body FROM notes "
            f"WHERE owner_id = {user['id']} AND title LIKE '%{q}%'"
        )
        rows = conn.execute(sql).fetchall()
        return {"notes": [as_note(r) for r in rows]}

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, user: User):
        row = conn.execute(
            "SELECT id, title, body, owner_id FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        return as_note(row)

    @app.get("/files")
    def read_file(name: str, user: User):
        path = os.path.join(data_dir, "public", name)
        try:
            with open(path) as f:
                return {"name": name, "content": f.read()}
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="no such file") from None

    return app
