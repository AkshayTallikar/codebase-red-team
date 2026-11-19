"""The billing target: an invoicing service with seeded mass assignment, ssrf and idor bugs."""

from __future__ import annotations

from pathlib import Path

from redteam.models import Edit, FixAttempt, FunctionalCheck, Probe
from redteam.targets.base import Target

APP_PATH = Path(__file__).parent / "app.py"


def _write_data(data_dir: Path, canary: str) -> None:
    """The app keeps its data in memory; the directory is created for parity with notes."""
    data_dir.mkdir(parents=True, exist_ok=True)


def _edit(old: str, new: str = "") -> Edit:
    return Edit(old=old, new=new)


_FUNCTIONAL_CHECKS: tuple[FunctionalCheck, ...] = (
    FunctionalCheck(
        name="read own profile",
        probe=Probe("GET", "/me", "GET /me"),
        expect_status=200,
        expect_text="alice",
    ),
    FunctionalCheck(
        name="update own name",
        probe=Probe("PATCH", "/me", "PATCH /me", json_body={"name": "Alice B"}),
        expect_status=200,
        expect_text="Alice B",
    ),
    FunctionalCheck(
        name="list own invoices",
        probe=Probe("GET", "/invoices", "GET /invoices"),
        expect_status=200,
        expect_text="INV-2",
    ),
    FunctionalCheck(
        name="read own invoice",
        probe=Probe("GET", "/invoices/2", "GET /invoices/{invoice_id}"),
        expect_status=200,
        expect_text="Design work",
    ),
    FunctionalCheck(
        name="import from partner",
        probe=Probe(
            "GET",
            "/invoices/import",
            "GET /invoices/import",
            params={"url": "https://partner.example/invoices/42.json"},
        ),
        expect_status=200,
        expect_text="EXT-42",
    ),
    FunctionalCheck(
        name="admin settings stay forbidden",
        probe=Probe("GET", "/admin/settings", "GET /admin/settings"),
        expect_status=403,
    ),
)


def _seed_probes() -> tuple[Probe, ...]:
    """The first-round hypotheses, one per weakness plus each of the first four invoices."""
    probes = [
        Probe(
            method="PATCH",
            path="/me",
            endpoint="PATCH /me",
            vuln_class="mass_assignment",
            json_body={"role": "admin"},
            note="mass_assignment: a body key may set the role column",
        ),
        Probe(
            method="GET",
            path="/invoices/import",
            endpoint="GET /invoices/import",
            vuln_class="ssrf",
            params={"url": "http://metadata.internal/latest/secret"},
            note="ssrf: the import URL may point at an internal metadata host",
        ),
        Probe(
            method="GET",
            path="/admin/settings",
            endpoint="GET /admin/settings",
            vuln_class="auth_bypass",
            headers={"X-Forwarded-User": "admin"},
            note="auth_bypass: an X-Forwarded-User header may name the admin",
        ),
    ]
    probes.extend(
        Probe(
            method="GET",
            path=f"/invoices/{invoice_id}",
            endpoint="GET /invoices/{invoice_id}",
            vuln_class="idor",
            note="idor: invoice ids may be read across owners",
        )
        for invoice_id in range(1, 5)
    )
    return tuple(probes)


# --- ssrf: a naive host-name block, then a parsed-URL allowlist --------------

_SSRF_DEF = "    def import_invoice(url: str, user: User):\n"
_SSRF_NAIVE_BLOCK = (
    "        # ssrf: a naive guard against one host name\n"
    '        if "metadata.internal" in url:\n'
    '            raise HTTPException(status_code=400, detail="host not allowed")\n'
)
_SSRF_TRY = "        try:\n            text = fake_fetch(url, canary)\n"
_SSRF_REAL_BLOCK = (
    "        # ssrf: only https URLs whose host is the partner are fetched\n"
    "        parts = urllib.parse.urlsplit(url)\n"
    '        host = (parts.hostname or "").lower().rstrip(".")\n'
    "        userinfo = parts.username or parts.password\n"
    '        if parts.scheme != "https" or userinfo or host != "partner.example":\n'
    '            raise HTTPException(status_code=400, detail="host not allowed")\n'
)

# --- mass_assignment: a naive block on the key "role", then an allowlist -----

_MASS_LOOP = "        for key, value in body.items():\n"
_MASS_NAIVE_BLOCK = (
    '        # mass_assignment: a naive guard that only blocks the exact key "role"\n'
    '        if "role" in body:\n'
    '            raise HTTPException(status_code=403, detail="field not allowed")\n'
)
_MASS_ALLOW_OLD = '            if field in ("name", "email", "role"):\n'
_MASS_ALLOW_NEW = '            if field in ("name", "email"):\n'

# --- auth_bypass: a naive exact-value check, then no header trust at all ----

_AUTH_OLD_IF = "        if forwarded:\n"
_AUTH_NAIVE_IF = '        if forwarded and forwarded != "admin":\n'
_AUTH_BLOCK = (
    "        # auth_bypass: an identity header sent by the caller is trusted as the user\n"
    '        forwarded = request.headers.get("x-forwarded-user")\n'
    "        if forwarded:\n"
    "            row = conn.execute(USER_BY_NAME, (forwarded.strip().lower(),)).fetchone()\n"
    "            if row is not None:\n"
    "                return as_user(row)\n"
)
_AUTH_BLOCK_NAIVE = _AUTH_BLOCK.replace(_AUTH_OLD_IF, _AUTH_NAIVE_IF)

# --- idor: an owner check on the invoice row --------------------------------

_IDOR_OLD = (
    "        if row is None:\n"
    '            raise HTTPException(status_code=404, detail="not found")\n'
    "        return as_invoice(row)\n"
)
_IDOR_NEW = (
    '        if row is None or row[4] != user["id"]:\n'
    '            raise HTTPException(status_code=404, detail="not found")\n'
    "        return as_invoice(row)\n"
)


_FIX_CATALOG: dict[str, tuple[FixAttempt, ...]] = {
    "mass_assignment:PATCH /me": (
        FixAttempt(
            rationale="Rejects a body that names the role key. Naive: the key check is exact, "
            "so spelling or spacing changes get through the loop.",
            alternatives=((_edit(_MASS_LOOP, _MASS_NAIVE_BLOCK + _MASS_LOOP),),),
            naive=True,
        ),
        FixAttempt(
            rationale="Only name and email are editable; keys are normalised and everything "
            "else is ignored. Removes the naive role check.",
            alternatives=(
                (
                    _edit(_MASS_NAIVE_BLOCK),
                    _edit(_MASS_ALLOW_OLD, _MASS_ALLOW_NEW),
                ),
                (_edit(_MASS_ALLOW_OLD, _MASS_ALLOW_NEW),),
            ),
        ),
    ),
    "ssrf:GET /invoices/import": (
        FixAttempt(
            rationale="Rejects URLs that name the metadata host. Naive: the check is a substring "
            "match on one spelling of the host.",
            alternatives=((_edit(_SSRF_DEF, _SSRF_DEF + _SSRF_NAIVE_BLOCK),),),
            naive=True,
        ),
        FixAttempt(
            rationale="Parses the URL and fetches only https links whose host is partner.example, "
            "with no userinfo. Removes the naive host check.",
            alternatives=(
                (
                    _edit(_SSRF_NAIVE_BLOCK),
                    _edit(_SSRF_TRY, _SSRF_REAL_BLOCK + _SSRF_TRY),
                ),
                (_edit(_SSRF_TRY, _SSRF_REAL_BLOCK + _SSRF_TRY),),
            ),
        ),
    ),
    "auth_bypass:GET /admin/settings": (
        FixAttempt(
            rationale="Ignores the X-Forwarded-User header when it names admin. Naive: only that "
            "exact value is refused.",
            alternatives=((_edit(_AUTH_OLD_IF, _AUTH_NAIVE_IF),),),
            naive=True,
        ),
        FixAttempt(
            rationale="Stops trusting X-Forwarded-User altogether; the user comes only from the "
            "token. Removes the naive header check.",
            alternatives=(
                (_edit(_AUTH_BLOCK_NAIVE),),
                (_edit(_AUTH_BLOCK),),
            ),
        ),
    ),
    "idor:GET /invoices/{invoice_id}": (
        FixAttempt(
            rationale="Returns 404 unless the invoice belongs to the requesting user.",
            alternatives=((_edit(_IDOR_OLD, _IDOR_NEW),),),
        ),
    ),
}


def _audit_probes() -> tuple[Probe, ...]:
    """Held-out exploit variants, written apart from the playbook. The attacker never sees them.

    Mass assignment, ssrf and auth bypass each have probes that the naive fix lets through.
    The trailing-dot host is still blocked by the naive substring check; it tests the real fix.
    """
    return (
        Probe(
            "PATCH",
            "/me",
            "PATCH /me",
            vuln_class="mass_assignment",
            json_body={"role": "admin"},
            note="audit: lower-case role key",
        ),
        Probe(
            "PATCH",
            "/me",
            "PATCH /me",
            vuln_class="mass_assignment",
            json_body={"ROLE": "admin"},
            note="audit: upper-case role key",
        ),
        Probe(
            "PATCH",
            "/me",
            "PATCH /me",
            vuln_class="mass_assignment",
            json_body={"Role ": "admin"},
            note="audit: role key with a trailing space",
        ),
        Probe(
            "GET",
            "/invoices/import",
            "GET /invoices/import",
            vuln_class="ssrf",
            params={"url": "http://METADATA.internal/latest/secret"},
            note="audit: upper-case metadata host",
        ),
        Probe(
            "GET",
            "/invoices/import",
            "GET /invoices/import",
            vuln_class="ssrf",
            params={"url": "http://169.254.169.254/latest/secret"},
            note="audit: metadata address as a dotted IP",
        ),
        Probe(
            "GET",
            "/invoices/import",
            "GET /invoices/import",
            vuln_class="ssrf",
            params={"url": "http://localhost/admin"},
            note="audit: localhost",
        ),
        Probe(
            "GET",
            "/invoices/import",
            "GET /invoices/import",
            vuln_class="ssrf",
            params={"url": "https://metadata.internal./x"},
            note="audit: metadata host with a trailing dot",
        ),
        Probe(
            "GET",
            "/admin/settings",
            "GET /admin/settings",
            vuln_class="auth_bypass",
            headers={"X-Forwarded-User": "ADMIN"},
            note="audit: upper-case admin in the identity header",
        ),
        Probe(
            "GET",
            "/admin/settings",
            "GET /admin/settings",
            vuln_class="auth_bypass",
            headers={"X-Forwarded-User": " Admin "},
            note="audit: padded admin in the identity header",
        ),
        Probe(
            "GET",
            "/admin/settings",
            "GET /admin/settings",
            vuln_class="auth_bypass",
            headers={"X-Forwarded-User": "admin"},
            note="audit: exact admin in the identity header",
        ),
        Probe(
            "GET",
            "/invoices/1",
            "GET /invoices/{invoice_id}",
            vuln_class="idor",
            note="audit: invoice 1 belongs to the admin",
        ),
    )


BILLING = Target(
    name="billing",
    description="an invoicing service where users manage their profile, list and read their "
    "invoices, and import invoices from a partner URL",
    seed_path=APP_PATH,
    vuln_classes=("mass_assignment", "ssrf", "auth_bypass", "idor"),
    attacker_token="mallory-token",
    user_token="alice-token",
    functional_checks=_FUNCTIONAL_CHECKS,
    seed_probes=_seed_probes(),
    fix_catalog=_FIX_CATALOG,
    patch_guidance=(
        "Keep legitimate behaviour working: alice must still read and rename her own profile, "
        "list and read her own invoices, and import from https://partner.example, while "
        "/admin/settings stays forbidden to her. Prefer real fixes: an allowlist of editable "
        "profile fields, a parsed-URL host allowlist, never trusting identity headers, and "
        "ownership checks."
    ),
    write_data=_write_data,
    isolate_probes=True,
    audit_probes=_audit_probes(),
)
