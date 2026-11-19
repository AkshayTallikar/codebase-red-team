"""The library target: a book-lending service with seeded sqli, idor, path traversal, ssrf,
mass assignment and auth bypass bugs."""

from __future__ import annotations

from pathlib import Path

from redteam.models import Edit, FixAttempt, FunctionalCheck, Probe
from redteam.targets.base import Target

APP_PATH = Path(__file__).parent / "app.py"


def _write_data(data_dir: Path, canary: str) -> None:
    """Write the cover folder and a private file outside it that holds the canary."""
    covers = data_dir / "covers"
    covers.mkdir(parents=True, exist_ok=True)
    (covers / "dune.txt").write_text("Local cover art for Dune\n", encoding="utf-8")
    private = data_dir / "private"
    private.mkdir(parents=True, exist_ok=True)
    (private / "ledger_key.txt").write_text(f"ledger_key={canary}\n", encoding="utf-8")


def _edit(old: str, new: str = "") -> Edit:
    return Edit(old=old, new=new)


_FUNCTIONAL_CHECKS: tuple[FunctionalCheck, ...] = (
    FunctionalCheck(
        name="search the catalogue",
        probe=Probe("GET", "/books/search", "GET /books/search", params={"q": "Dune"}),
        expect_status=200,
        expect_text="Dune",
    ),
    FunctionalCheck(
        name="read own loan",
        probe=Probe("GET", "/loans/3", "GET /loans/{loan_id}"),
        expect_status=200,
        expect_text="Shelf B2",
    ),
    FunctionalCheck(
        name="read a local cover",
        probe=Probe("GET", "/covers", "GET /covers", params={"name": "dune.txt"}),
        expect_status=200,
        expect_text="Local cover art",
    ),
    FunctionalCheck(
        name="fetch a cover from the partner",
        probe=Probe(
            "POST",
            "/covers/fetch",
            "POST /covers/fetch",
            json_body={"book_id": 1, "url": "https://covers.partner.example/dune.txt"},
        ),
        expect_status=200,
        expect_text="COVER-DUNE-REMOTE",
    ),
    FunctionalCheck(
        name="read own profile",
        probe=Probe("GET", "/members/me", "GET /members/me"),
        expect_status=200,
        expect_text="alice",
    ),
    FunctionalCheck(
        name="update own name",
        probe=Probe("PATCH", "/members/me", "PATCH /members/me", json_body={"name": "Alice B"}),
        expect_status=200,
        expect_text="Alice B",
    ),
    FunctionalCheck(
        name="staff report stays forbidden",
        probe=Probe("GET", "/staff/report", "GET /staff/report"),
        expect_status=403,
    ),
)


def _seed_probes() -> tuple[Probe, ...]:
    """The first-round hypotheses, one per weakness plus each of the first four loans."""
    probes = [
        Probe(
            method="GET",
            path="/books/search",
            endpoint="GET /books/search",
            vuln_class="sqli",
            params={"q": "' OR 1=1 --"},
            note="sqli: a tautology in the search term may return staff-only books",
        ),
        Probe(
            method="GET",
            path="/covers",
            endpoint="GET /covers",
            vuln_class="path_traversal",
            params={"name": "../private/ledger_key.txt"},
            note="path_traversal: the cover name may climb out of the covers folder",
        ),
        Probe(
            method="POST",
            path="/covers/fetch",
            endpoint="POST /covers/fetch",
            vuln_class="ssrf",
            json_body={"book_id": 2, "url": "http://metadata.internal/latest/secret"},
            note="ssrf: the cover URL may point at an internal metadata host",
        ),
        Probe(
            method="PATCH",
            path="/members/me",
            endpoint="PATCH /members/me",
            vuln_class="mass_assignment",
            json_body={"is_staff": True},
            note="mass_assignment: a body key may set the is_staff flag",
        ),
        Probe(
            method="GET",
            path="/staff/report",
            endpoint="GET /staff/report",
            vuln_class="auth_bypass",
            headers={"Cookie": "as_member=staff"},
            note="auth_bypass: a Cookie may name the staff member",
        ),
    ]
    probes.extend(
        Probe(
            method="GET",
            path=f"/loans/{loan_id}",
            endpoint="GET /loans/{loan_id}",
            vuln_class="idor",
            note="idor: loan ids may be read across members",
        )
        for loan_id in range(1, 5)
    )
    return tuple(probes)


# --- sqli: a naive guard on the word OR, then a bound parameter -------------

_SQLI_DEF = "    def find_books(q: str, member: CurrentMember):\n"
_SQLI_NAIVE_BLOCK = (
    "        # sqli: a naive guard against the capitalised word OR\n"
    '        if " OR " in q:\n'
    '            raise HTTPException(status_code=400, detail="invalid search")\n'
)
_SQLI_SQL_OLD = (
    "        # sqli: the term is pasted into the SQL text with str.format, "
    "not bound as a parameter\n"
    '        sql = "SELECT id, title, notes FROM books WHERE staff_only = 0 '
    "AND title LIKE '%{}%'\"\n"
    "        rows = self.conn.execute(sql.format(term)).fetchall()\n"
)
_SQLI_SQL_NEW = (
    "        rows = self.conn.execute(\n"
    '            "SELECT id, title, notes FROM books WHERE staff_only = 0 AND title LIKE ?",\n'
    '            ("%" + term + "%",),\n'
    "        ).fetchall()\n"
)

# --- path_traversal: a naive strip of ../, then a resolved-path check --------

_PATH_DEF = "    def get_cover(name: str, member: CurrentMember):\n"
_PATH_NAIVE_LINE = (
    "        # path_traversal: a naive strip of dot-dot-slash from the name\n"
    '        name = name.replace("../", "")\n'
)
_PATH_OLD = (
    "    # path_traversal: the name is joined onto the folder and read with no "
    "containment check\n"
    "    path = covers_dir / name\n"
)
_PATH_NEW = (
    "    # path_traversal: the resolved path must stay inside the covers folder\n"
    "    base = covers_dir.resolve()\n"
    "    path = (base / name).resolve()\n"
    "    if base not in path.parents:\n"
    "        raise FileNotFoundError(name)\n"
)

# --- ssrf: only https links to the partner host, with no user info ----------

_SSRF_OLD = (
    "        # ssrf: the URL in the body is fetched exactly as given, including internal hosts\n"
    "        try:\n"
    "            text = fetch_from_fake_web(web, body.url)\n"
)
_SSRF_NEW = (
    "        # ssrf: only https links to the partner host are fetched, with no user info\n"
    "        try:\n"
    "            parts = urllib.parse.urlsplit(body.url)\n"
    '            host = (parts.hostname or "").rstrip(".")\n'
    '            if parts.scheme != "https" or host != PARTNER_HOST or "@" in parts.netloc:\n'
    "                raise ValueError(body.url)\n"
    "            text = fetch_from_fake_web(web, body.url)\n"
)

# --- mass_assignment: the privileged field leaves the profile model ---------

_MASS_FIELD = "    is_staff: bool | None = None\n"

# --- auth_bypass: a naive exact-cookie guard, then no cookie trust at all ---

_AUTH_IMPERSONATED = "        impersonated = cookie_member(raw_cookie)\n"
_AUTH_NAIVE_BLOCK = (
    "        # auth_bypass: a naive guard that refuses the exact staff cookie\n"
    '        if raw_cookie == "as_member=staff":\n'
    '            raise HTTPException(status_code=403, detail="cookie not allowed")\n'
)
_AUTH_BLOCK = (
    "        # auth_bypass: a caller-supplied as_member cookie is trusted as the member it names\n"
    '        raw_cookie = request.headers.get("cookie", "")\n'
    "        impersonated = cookie_member(raw_cookie)\n"
    "        if impersonated:\n"
    "            member = repo.member_by_name(impersonated)\n"
    "            if member is not None:\n"
    "                return member\n"
)

# --- idor: an owner check on the loan ---------------------------------------

_IDOR_OLD = "        # idor: the loan is returned whoever it belongs to\n        if loan is None:\n"
_IDOR_NEW = (
    "        # idor: the loan is returned only to the member it belongs to\n"
    '        if loan is None or loan["member_id"] != member["id"]:\n'
)


_FIX_CATALOG: dict[str, tuple[FixAttempt, ...]] = {
    "sqli:GET /books/search": (
        FixAttempt(
            rationale="Refuses a search that contains the word OR in capitals. Naive: lower-case "
            "and mixed-case spellings of the same SQL get through.",
            alternatives=((_edit(_SQLI_DEF, _SQLI_DEF + _SQLI_NAIVE_BLOCK),),),
            naive=True,
        ),
        FixAttempt(
            rationale="Binds the search term as a query parameter instead of pasting it into the "
            "SQL text. Removes the naive OR check.",
            alternatives=(
                (_edit(_SQLI_NAIVE_BLOCK), _edit(_SQLI_SQL_OLD, _SQLI_SQL_NEW)),
                (_edit(_SQLI_SQL_OLD, _SQLI_SQL_NEW),),
            ),
        ),
    ),
    "idor:GET /loans/{loan_id}": (
        FixAttempt(
            rationale="Returns a loan only to the member it belongs to; anyone else gets 404.",
            alternatives=((_edit(_IDOR_OLD, _IDOR_NEW),),),
        ),
    ),
    "path_traversal:GET /covers": (
        FixAttempt(
            rationale="Strips the text ../ from the cover name. Naive: a name that folds back "
            "into ../ after the strip still climbs out of the folder.",
            alternatives=((_edit(_PATH_DEF, _PATH_DEF + _PATH_NAIVE_LINE),),),
            naive=True,
        ),
        FixAttempt(
            rationale="Resolves the path and reads only files inside the covers folder. Removes "
            "the naive strip.",
            alternatives=(
                (_edit(_PATH_NAIVE_LINE), _edit(_PATH_OLD, _PATH_NEW)),
                (_edit(_PATH_OLD, _PATH_NEW),),
            ),
        ),
    ),
    "ssrf:POST /covers/fetch": (
        FixAttempt(
            rationale="Fetches only https links whose host is the partner, with no user info. "
            "Internal hosts are refused.",
            alternatives=((_edit(_SSRF_OLD, _SSRF_NEW),),),
        ),
    ),
    "mass_assignment:PATCH /members/me": (
        FixAttempt(
            rationale="Removes is_staff from the profile model, so a request body cannot set it. "
            "Only name and email stay editable.",
            alternatives=((_edit(_MASS_FIELD),),),
        ),
    ),
    "auth_bypass:GET /staff/report": (
        FixAttempt(
            rationale="Refuses the exact staff cookie. Naive: the check compares the raw header "
            "text, so respelled or extra cookies get through.",
            alternatives=((_edit(_AUTH_IMPERSONATED, _AUTH_NAIVE_BLOCK + _AUTH_IMPERSONATED),),),
            naive=True,
        ),
        FixAttempt(
            rationale="Stops trusting the as_member cookie altogether; the member comes only from "
            "the token. Removes the naive cookie check.",
            alternatives=(
                (_edit(_AUTH_NAIVE_BLOCK), _edit(_AUTH_BLOCK)),
                (_edit(_AUTH_BLOCK),),
            ),
        ),
    ),
}


def _audit_probes() -> tuple[Probe, ...]:
    """Held-out exploit variants, written apart from the playbook. The attacker never sees them.

    Each one lands on the seed app or on the app after the naive fixes, and each is blocked by
    the real fixes.
    """
    return (
        Probe(
            "GET",
            "/books/search",
            "GET /books/search",
            vuln_class="sqli",
            params={"q": "' or 'a'='a' --"},
            note="audit: an or-tautology with no capitals, on the seed and the naive app",
        ),
        Probe(
            "GET",
            "/books/search",
            "GET /books/search",
            vuln_class="sqli",
            params={"q": "' Or 1=1 --"},
            note="audit: a mixed-case OR, which the naive guard misses",
        ),
        Probe(
            "GET",
            "/covers",
            "GET /covers",
            vuln_class="path_traversal",
            params={"name": "./../private/ledger_key.txt"},
            note="audit: a leading dot-slash that climbs out of the covers folder",
        ),
        Probe(
            "GET",
            "/covers",
            "GET /covers",
            vuln_class="path_traversal",
            params={"name": "....//private/ledger_key.txt"},
            note="audit: a doubled dot-dot-slash that the naive strip folds back",
        ),
        Probe(
            "GET",
            "/loans/1",
            "GET /loans/{loan_id}",
            vuln_class="idor",
            note="audit: the staff loan, read by a member who does not own it",
        ),
        Probe(
            "POST",
            "/covers/fetch",
            "POST /covers/fetch",
            vuln_class="ssrf",
            json_body={"book_id": 2, "url": "http://METADATA.internal./latest/secret"},
            note="audit: an upper-case metadata host with a trailing dot, over http",
        ),
        Probe(
            "POST",
            "/covers/fetch",
            "POST /covers/fetch",
            vuln_class="ssrf",
            json_body={
                "book_id": 2,
                "url": "https://covers.partner.example@metadata.internal/latest/secret",
            },
            note="audit: a partner name in the user info, with the metadata host after it",
        ),
        Probe(
            "PATCH",
            "/members/me",
            "PATCH /members/me",
            vuln_class="mass_assignment",
            json_body={"is_staff": "yes"},
            note="audit: is_staff set with a string the model reads as true",
        ),
        Probe(
            "PATCH",
            "/members/me",
            "PATCH /members/me",
            vuln_class="mass_assignment",
            json_body={"is_staff": 1},
            note="audit: is_staff set with the integer 1",
        ),
        Probe(
            "GET",
            "/staff/report",
            "GET /staff/report",
            vuln_class="auth_bypass",
            headers={"Cookie": "as_member=STAFF"},
            note="audit: an upper-case staff value in the cookie",
        ),
        Probe(
            "GET",
            "/staff/report",
            "GET /staff/report",
            vuln_class="auth_bypass",
            headers={"Cookie": "theme=dark; as_member=staff"},
            note="audit: the staff cookie among other cookies",
        ),
    )


LIBRARY = Target(
    name="library",
    description="a book-lending service where members search the catalogue, read their loans, "
    "fetch covers from a partner URL and edit their profile",
    seed_path=APP_PATH,
    vuln_classes=("sqli", "idor", "path_traversal", "ssrf", "mass_assignment", "auth_bypass"),
    attacker_token="mallory-token",
    user_token="alice-token",
    functional_checks=_FUNCTIONAL_CHECKS,
    seed_probes=_seed_probes(),
    fix_catalog=_FIX_CATALOG,
    patch_guidance=(
        "Keep legitimate behaviour working: alice must still search the catalogue, read her own "
        "loan and profile, rename herself, read a local cover by name and fetch a cover from "
        "https://covers.partner.example, while /staff/report stays forbidden to her. Prefer real "
        "fixes: bound query parameters, an ownership check on loans, a resolved-path containment "
        "check for files, a parsed-URL host allowlist, an editable-field allowlist, and never "
        "trusting caller-supplied identity."
    ),
    write_data=_write_data,
    isolate_probes=True,
    audit_probes=_audit_probes(),
)
