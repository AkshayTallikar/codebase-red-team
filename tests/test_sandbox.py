"""Sandbox safety boundary, lifecycle and hot reload."""

from pathlib import Path

import pytest

from redteam.models import Probe
from redteam.sandbox import (
    ProbeRejected,
    Sandbox,
    TargetLoadError,
    load_seed_source,
    validate_probe,
)


def _probe(**overrides) -> Probe:
    fields = {"method": "GET", "path": "/notes", "endpoint": "GET /notes"}
    fields.update(overrides)
    return Probe(**fields)


@pytest.mark.parametrize(
    "probe",
    [
        _probe(path="http://evil.example/x"),
        _probe(path="notes"),
        _probe(path="//x"),
        _probe(headers={"Host": "evil.example"}),
        _probe(headers={"host": "evil.example"}),
        _probe(method="TRACE"),
        _probe(path="/notes?x=1 2"),
        _probe(path="/notes\n"),
    ],
)
def test_validate_probe_rejects_unsafe_probes(probe):
    with pytest.raises(ProbeRejected):
        validate_probe(probe)


def test_validate_probe_accepts_normal_probe():
    validate_probe(_probe(method="post", path="/notes/1", headers={"X-Token": "t"}))


def test_two_sandboxes_get_different_canaries():
    with Sandbox() as first, Sandbox() as second:
        assert first.canary != second.canary


def test_broken_source_raises_and_old_app_still_answers():
    with Sandbox() as sandbox:
        old_app = sandbox.app
        with pytest.raises(TargetLoadError):
            sandbox.load("def (")
        assert sandbox.app is old_app
        result = sandbox.send(_probe(path="/notes", endpoint="GET /notes"))
        assert result.status == 200


def test_modified_seed_is_loaded_and_used():
    with Sandbox() as sandbox:
        patched = load_seed_source().replace("notes-service", "notes-service-v2")
        sandbox.load(patched)
        assert sandbox.app.title == "notes-service-v2"
        assert sandbox.source == patched


def test_routes_lists_templates_per_method():
    with Sandbox() as sandbox:
        routes = sandbox.routes()
        assert "GET /notes/{note_id}" in routes
        assert "POST /notes" in routes
        assert routes == sorted(routes)
        assert not any(r.startswith(("HEAD ", "OPTIONS ")) for r in routes)


def test_close_deletes_owned_tempdir_only(tmp_path: Path):
    owned = Sandbox()
    owned_dir = owned.workdir
    owned.close()
    assert not owned_dir.exists()

    passed_in = tmp_path / "keep"
    kept = Sandbox(workdir=passed_in)
    kept.close()
    assert passed_in.exists()
    assert (passed_in / "data" / "secrets.txt").exists()


def test_send_uses_attacker_token_by_default():
    with Sandbox() as sandbox:
        result = sandbox.send(_probe(path="/notes/1", endpoint="GET /notes/{note_id}"))
        assert result.status == 200
        assert sandbox.canary in result.body
