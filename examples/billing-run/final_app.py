"""An invoicing service that is vulnerable on purpose.

This file is the seed target for the red team loop. It is never edited in
place: the sandbox copies it into a per-run workspace and the patcher edits
that copy. Do not deploy it anywhere.

Seeded weaknesses (see docs/design.md section 7.2):
  mass_assignment  PATCH /me               every known field named in the body is written
  ssrf             GET /invoices/import    any URL is fetched through an in-memory fake web
  auth_bypass      GET /admin/settings     trusts a caller-supplied X-Forwarded-User header
  idor             GET /invoices/{id}      no ownership check
"""

import secrets
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request

FAKE_DNS = {
    "partner.example": "203.0.113.10",
    "metadata.internal": "169.254.169.254",
    "localhost": "127.0.0.1",
}
INTERNAL_ADDRESSES = {"169.254.169.254", "127.0.0.1"}
USER_BY_NAME = "SELECT id, name, email, role FROM users WHERE lower(name) = ?"
USER_BY_TOKEN = "SELECT id, name, email, role FROM users WHERE token = ?"
USER_BY_ID = "SELECT id, name, email, role FROM users WHERE id = ?"


def resolve(host: str) -> str | None:
    """Map a host name or IPv4 literal (dotted or decimal) to an address, or None."""
    host = host.strip().lower().rstrip(".")
    if host.isdigit():
        number = int(host)
        if number >= 2**32:
            return None
        return ".".join(str((number >> shift) & 255) for shift in (24, 16, 8, 0))
    if all(part.isdigit() for part in host.split(".")) and host.count(".") == 3:
        return host
    return FAKE_DNS.get(host)


def fake_fetch(url: str, canary: str) -> str:
    """Return what the fake web serves for `url`. Raises LookupError for unknown hosts."""
    parts = urllib.parse.urlsplit(url)
    address = resolve(parts.hostname or "")
    if address is None:
        raise LookupError(url)
    if address in INTERNAL_ADDRESSES:
        return f"instance metadata: payout_secret={canary}"
    if address == "203.0.113.10":
        return '{"number": "EXT-42", "amount": 250}'
    raise LookupError(url)


def as_user(row) -> dict:
    return {"id": row[0], "name": row[1], "email": row[2], "role": row[3]}


def as_invoice(row) -> dict:
    return {"id": row[0], "number": row[1], "amount": row[2], "memo": row[3]}


def create_app(data_dir: str | Path, canary: str) -> FastAPI:
    app = FastAPI(title="billing-service")
    org_settings = {"org": "Acme Billing", "payout_secret": canary}

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT, token TEXT)"
    )
    conn.execute(
        "CREATE TABLE invoices "
        "(id INTEGER PRIMARY KEY, owner_id INTEGER, number TEXT, amount INTEGER, memo TEXT)"
    )
    users = [
        (1, "admin", "admin@billing.example", "admin", secrets.token_hex(16)),
        (2, "alice", "alice@billing.example", "member", "alice-token"),
        (3, "mallory", "mallory@billing.example", "member", "mallory-token"),
    ]
    conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", users)
    invoices = [
        (1, 1, "INV-1", 990000, f"Payout account {canary}"),
        (2, 2, "INV-2", 120, "Design work"),
        (3, 2, "INV-3", 80, "Hosting"),
        (4, 3, "INV-4", 15, "Stickers"),
    ]
    conn.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?, ?)", invoices)
    conn.commit()

    def current_user(request: Request, x_token: Annotated[str | None, Header()] = None) -> dict:
        row = conn.execute(USER_BY_TOKEN, (x_token,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="unknown token")
        return as_user(row)

    User = Annotated[dict, Depends(current_user)]

    def profile_for(user_id: int) -> dict:
        profile = as_user(conn.execute(USER_BY_ID, (user_id,)).fetchone())
        if profile["role"] == "admin":
            profile["org"] = org_settings
        return profile

    @app.get("/me")
    def get_me(user: User):
        return profile_for(user["id"])

    @app.patch("/me")
    def update_me(user: User, body: Annotated[dict[str, Any], Body()]):
        # mass_assignment: every known field named in the body is written to the user row
        for key, value in body.items():
            field = key.strip().lower()
            if field in ("name", "email"):
                conn.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, user["id"]))
        conn.commit()
        return profile_for(user["id"])

    @app.get("/invoices")
    def list_invoices(user: User):
        rows = conn.execute(
            "SELECT id, number, amount, memo FROM invoices WHERE owner_id = ? ORDER BY id",
            (user["id"],),
        ).fetchall()
        return {"invoices": [as_invoice(r) for r in rows]}

    @app.get("/invoices/import")
    def import_invoice(url: str, user: User):
        # ssrf: the URL is fetched exactly as given, including internal addresses
        # ssrf: only https URLs whose host is the partner are fetched
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        userinfo = parts.username or parts.password
        if parts.scheme != "https" or userinfo or host != "partner.example":
            raise HTTPException(status_code=400, detail="host not allowed")
        try:
            text = fake_fetch(url, canary)
        except LookupError:
            raise HTTPException(status_code=404, detail="cannot fetch") from None
        return {"url": url, "imported": text}

    @app.get("/invoices/{invoice_id}")
    def get_invoice(invoice_id: int, user: User):
        # idor: the invoice is returned whoever owns it
        row = conn.execute(
            "SELECT id, number, amount, memo, owner_id FROM invoices WHERE id = ?",
            (invoice_id,),
        ).fetchone()
        if row is None or row[4] != user["id"]:
            raise HTTPException(status_code=404, detail="not found")
        return as_invoice(row)

    @app.get("/admin/settings")
    def admin_settings(user: User):
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="admins only")
        return org_settings

    return app
