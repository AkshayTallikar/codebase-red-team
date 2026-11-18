"""Attacker behaviour: playbook rounds, mutations, finalize rules and the LLM planner."""

from __future__ import annotations

from redteam.agents.attacker import (
    AttackHistory,
    LLMAttacker,
    PlaybookAttacker,
    finalize,
    mutate,
)
from redteam.llm.base import LLMRefusal
from redteam.llm.fake import FakeBackend
from redteam.models import Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox, load_seed_source

NAIVE_FIX_SOURCE_LINE = '        path = os.path.join(data_dir, "public", name)'
NAIVE_FIX = '        name = name.replace("../", "")\n' + NAIVE_FIX_SOURCE_LINE


def _probe(**overrides) -> Probe:
    fields = {"method": "GET", "path": "/notes", "endpoint": "GET /notes"}
    fields.update(overrides)
    return Probe(**fields)


def _run_round(sandbox: Sandbox, probes: list[Probe], history: AttackHistory) -> list[Probe]:
    """Send probes, judge them, and record each outcome in the history."""
    oracle = Oracle(sandbox.canary)
    findings: list[Probe] = []
    for probe in probes:
        finding = oracle.judge(sandbox.send(probe))
        history.record(probe, landed=finding is not None)
        if finding is not None:
            findings.append(probe)
    return findings


def test_first_round_covers_all_classes_and_finds_each_class():
    with Sandbox() as sandbox:
        routes = sandbox.routes()
        history = AttackHistory()
        batch = PlaybookAttacker().plan(routes, history, budget=50)

        assert len(batch) == 9
        assert {p.vuln_class for p in batch} == {"sqli", "idor", "path_traversal", "crash"}

        oracle = Oracle(sandbox.canary)
        kinds = {}
        for probe in batch:
            finding = oracle.judge(sandbox.send(probe))
            if finding is not None:
                kinds.setdefault(finding.vuln_class, finding.kind)

        assert kinds == {
            "sqli": "leak",
            "idor": "leak",
            "path_traversal": "leak",
            "crash": "crash",
        }


def test_idor_seed_from_note_one_leaks_admin_note():
    with Sandbox() as sandbox:
        seeds = {p.path: p for p in PlaybookAttacker().plan(sandbox.routes(), AttackHistory(), 50)}
        result = sandbox.send(seeds["/notes/1"])
        assert sandbox.canary in result.body


def test_finalize_drops_bad_probes_and_respects_budget():
    routes = ["GET /notes", "GET /files"]
    history = AttackHistory()
    sent = _probe(path="/notes", endpoint="GET /notes", params={"limit": "1"})
    history.record(sent, landed=False)

    probes = [
        _probe(endpoint="GET /unknown"),
        _probe(path="http://x/y"),
        sent,
        _probe(path="/notes", endpoint="GET /notes", params={"limit": "2"}),
        _probe(path="/notes", endpoint="GET /notes", params={"limit": "2"}),
        _probe(path="/files", endpoint="GET /files", params={"name": "a"}),
        _probe(path="/files", endpoint="GET /files", params={"name": "b"}),
    ]

    assert [p.params for p in finalize(probes, routes, history, budget=10)] == [
        {"limit": "2"},
        {"name": "a"},
        {"name": "b"},
    ]
    assert len(finalize(probes, routes, history, budget=1)) == 1
    assert finalize(probes, routes, history, budget=0) == []


def test_mutate_includes_known_bypasses():
    traversal = mutate(
        _probe(
            path="/files",
            endpoint="GET /files",
            vuln_class="path_traversal",
            params={"name": "../secrets.txt"},
        )
    )
    assert "....//secrets.txt" in [p.params["name"] for p in traversal]

    sqli = mutate(
        _probe(
            path="/notes/search",
            endpoint="GET /notes/search",
            vuln_class="sqli",
            params={"q": "' OR 1=1 --"},
        )
    )
    assert "' or 1=1 --" in [p.params["q"] for p in sqli]
    assert all(p.note.startswith("mutation of") for p in sqli)


def test_mutate_idor_hits_neighbours_and_padded_ids():
    paths = [
        p.path
        for p in mutate(_probe(path="/notes/1", endpoint="GET /notes/{note_id}", vuln_class="idor"))
    ]
    assert "/notes/2" in paths
    assert "/notes/01" in paths
    assert (
        mutate(_probe(path="/notes/-1", endpoint="GET /notes/{note_id}", vuln_class="idor")) == []
    )


def test_mutate_unknown_class_returns_nothing():
    assert mutate(_probe(vuln_class="unknown", params={"q": "x"})) == []


def test_second_round_returns_only_new_mutations():
    with Sandbox() as sandbox:
        routes = sandbox.routes()
        history = AttackHistory()
        seeds = PlaybookAttacker().plan(routes, history, budget=50)
        _run_round(sandbox, seeds, history)

        batch = PlaybookAttacker().plan(routes, history, budget=100)

        assert batch
        assert all(p.note.startswith("mutation of") for p in batch)
        assert not any(history.was_sent(p) for p in batch)


def test_adaptation_to_naive_traversal_fix():
    seed = load_seed_source()
    assert NAIVE_FIX_SOURCE_LINE in seed
    patched = seed.replace(NAIVE_FIX_SOURCE_LINE, NAIVE_FIX)

    seed_traversal = next(
        p
        for p in PlaybookAttacker().plan(Sandbox().routes(), AttackHistory(), 50)
        if p.vuln_class == "path_traversal"
    )

    with Sandbox(source=patched) as sandbox:
        assert sandbox.canary not in sandbox.send(seed_traversal).body

        leaked = [
            candidate
            for candidate in mutate(seed_traversal)
            if sandbox.canary in sandbox.send(candidate).body
        ]
        assert any(p.params["name"] == "....//secrets.txt" for p in leaked)


def test_llm_attacker_keeps_valid_probes_and_drops_malformed_ones():
    routes = ["GET /notes/search", "GET /files"]
    canned = {
        "probes": [
            {
                "method": "get",
                "path": "/notes/search",
                "endpoint": "GET /notes/search",
                "vuln_class": "sqli",
                "params": [{"name": "q", "value": "' or 1=1 --"}],
                "note": "tautology",
            },
            {
                "method": "GET",
                "path": "/files",
                "endpoint": "GET /files",
                "vuln_class": "path_traversal",
                "params": "not-a-list",
                "note": "malformed",
            },
            {
                "method": "GET",
                "path": "http://evil.example/files",
                "endpoint": "GET /files",
                "vuln_class": "path_traversal",
                "params": [{"name": "name", "value": "x"}],
                "note": "absolute url",
            },
        ]
    }
    backend = FakeBackend([canned])
    attacker = LLMAttacker(backend)

    batch = attacker.plan(routes, AttackHistory(), budget=10)

    assert [(p.method, p.path, p.params) for p in batch] == [
        ("GET", "/notes/search", {"q": "' or 1=1 --"})
    ]
    assert len(backend.calls) == 1
    assert "GET /notes/search" in backend.calls[0]["prompt"]
    assert "mallory" in backend.calls[0]["prompt"]


def test_llm_refusal_uses_fallback_when_set():
    routes = ["GET /notes/{note_id}"]
    history = AttackHistory()
    backend = FakeBackend([LLMRefusal("declined", category="policy")])
    attacker = LLMAttacker(backend, fallback=PlaybookAttacker())

    batch = attacker.plan(routes, history, budget=10)

    assert batch == PlaybookAttacker().plan(routes, history, budget=10)
    assert [p.path for p in batch] == [f"/notes/{i}" for i in range(1, 6)]


def test_llm_refusal_without_fallback_returns_nothing():
    backend = FakeBackend([LLMRefusal("declined")])
    assert LLMAttacker(backend).plan(["GET /notes"], AttackHistory(), budget=5) == []
