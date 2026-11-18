"""Behaviour of the seed target app, seen through the sandbox."""

import json

from redteam.models import Probe
from redteam.sandbox import ALICE_TOKEN, ATTACKER_TOKEN, Sandbox


def _get(sandbox: Sandbox, path: str, *, token: str | None, endpoint: str, **params: str):
    probe = Probe(method="GET", path=path, endpoint=endpoint, params=dict(params))
    return sandbox.send(probe, token=token)


def test_normal_behaviour_for_alice():
    with Sandbox() as sandbox:
        listed = _get(sandbox, "/notes", token=ALICE_TOKEN, endpoint="GET /notes", limit="10")
        assert listed.status == 200
        ids = [note["id"] for note in json.loads(listed.body)["notes"]]
        assert ids == [2, 3]

        found = _get(
            sandbox, "/notes/search", token=ALICE_TOKEN, endpoint="GET /notes/search", q="Gro"
        )
        assert found.status == 200
        assert "Groceries" in found.body

        read = _get(sandbox, "/notes/2", token=ALICE_TOKEN, endpoint="GET /notes/{note_id}")
        assert read.status == 200
        assert "eggs, milk, coffee" in read.body

        created = sandbox.send(
            Probe(
                method="POST",
                path="/notes",
                endpoint="POST /notes",
                json_body={"title": "t", "body": "b"},
            ),
            token=ALICE_TOKEN,
        )
        assert created.status == 200
        assert json.loads(created.body) == {"id": 5}

        readme = _get(
            sandbox, "/files", token=ALICE_TOKEN, endpoint="GET /files", name="readme.txt"
        )
        assert readme.status == 200
        assert "Welcome to the notes service." in readme.body


def test_unknown_token_is_rejected():
    with Sandbox() as sandbox:
        result = _get(sandbox, "/notes", token="nope", endpoint="GET /notes")
        assert result.status == 401


def test_seeded_idor_leaks_admin_note():
    with Sandbox() as sandbox:
        result = _get(
            sandbox,
            "/notes/1",
            token=ATTACKER_TOKEN,
            endpoint="GET /notes/{note_id}",
        )
        assert result.status == 200
        assert sandbox.canary in result.body


def test_seeded_sqli_leaks_admin_note():
    with Sandbox() as sandbox:
        result = _get(
            sandbox,
            "/notes/search",
            token=ATTACKER_TOKEN,
            endpoint="GET /notes/search",
            q="' OR 1=1 --",
        )
        assert sandbox.canary in result.body


def test_seeded_path_traversal_leaks_secrets():
    with Sandbox() as sandbox:
        result = _get(
            sandbox,
            "/files",
            token=ATTACKER_TOKEN,
            endpoint="GET /files",
            name="../secrets.txt",
        )
        assert sandbox.canary in result.body


def test_seeded_crash_on_bad_limit():
    with Sandbox() as sandbox:
        zero = _get(sandbox, "/notes", token=ATTACKER_TOKEN, endpoint="GET /notes", limit="0")
        text = _get(sandbox, "/notes", token=ATTACKER_TOKEN, endpoint="GET /notes", limit="abc")
        assert zero.status == 500
        assert text.status == 500
