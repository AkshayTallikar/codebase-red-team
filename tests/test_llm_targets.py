"""Target-aware LLM agents: schema, probe parsing, prompts and billing fixes (fake backend)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from redteam.agents.attacker import AttackHistory, LLMAttacker, plan_schema
from redteam.agents.patcher import LLMPatcher, system_prompt
from redteam.cli import main
from redteam.gate import VerificationGate
from redteam.llm import FakeBackend
from redteam.models import Finding, Probe
from redteam.oracle import Oracle
from redteam.patching import edits_apply
from redteam.sandbox import Sandbox
from redteam.targets import BILLING, NOTES

AUTH = "auth_bypass:GET /admin/settings"


def _item(**overrides) -> dict:
    item = {
        "method": "GET",
        "path": "/admin/settings",
        "endpoint": "GET /admin/settings",
        "vuln_class": "auth_bypass",
        "params": [],
        "headers": [{"name": "X-Forwarded-User", "value": "admin"}],
        "json_body": "",
        "note": "forwarded identity",
    }
    item.update(overrides)
    return item


def _plan(*items: dict) -> list[dict]:
    return [{"probes": list(items)}]


def _billing_routes() -> list[str]:
    with Sandbox(target=BILLING) as sandbox:
        return sandbox.routes()


def _billing_finding(probe: Probe) -> Finding:
    with Sandbox(target=BILLING) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None
    return finding


def test_plan_schema_limits_classes_and_requires_new_fields() -> None:
    schema = plan_schema(BILLING)
    item = schema["properties"]["probes"]["items"]
    assert item["properties"]["vuln_class"]["enum"] == list(BILLING.vuln_classes)
    assert "headers" in item["required"]
    assert "json_body" in item["required"]
    assert item["properties"]["json_body"] == {"type": "string"}
    assert item["additionalProperties"] is False
    assert set(item["required"]) == set(item["properties"])


def test_billing_probe_with_json_body_lands_on_seed_app() -> None:
    routes = _billing_routes()
    body = json.dumps({"role": "admin"})
    item = _item(
        method="PATCH",
        path="/me",
        endpoint="PATCH /me",
        vuln_class="mass_assignment",
        headers=[],
        json_body=body,
    )
    backend = FakeBackend(_plan(item))

    batch = LLMAttacker(backend, target=BILLING).plan(routes, AttackHistory(), budget=5)

    assert [p.json_body for p in batch] == [{"role": "admin"}]
    with Sandbox(target=BILLING) as sandbox:
        assert Oracle(sandbox.canary).judge(sandbox.send(batch[0])) is not None


def test_headers_keep_only_allowed_names_and_land_on_admin() -> None:
    routes = _billing_routes()
    item = _item(
        headers=[
            {"name": "X-Forwarded-User", "value": "admin"},
            {"name": "Host", "value": "evil.example"},
            {"name": "X-Token", "value": "x"},
        ]
    )
    backend = FakeBackend(_plan(item))

    batch = LLMAttacker(backend, target=BILLING).plan(routes, AttackHistory(), budget=5)

    assert len(batch) == 1
    assert batch[0].headers == {"X-Forwarded-User": "admin"}
    assert batch[0].path == "/admin/settings"
    with Sandbox(target=BILLING) as sandbox:
        assert Oracle(sandbox.canary).judge(sandbox.send(batch[0])) is not None


@pytest.mark.parametrize("body", ["[1]", "not json", '"text"'])
def test_json_body_that_is_not_an_object_drops_the_probe(body: str) -> None:
    backend = FakeBackend(_plan(_item(json_body=body)))
    batch = LLMAttacker(backend, target=BILLING).plan(_billing_routes(), AttackHistory(), budget=5)
    assert batch == []


def test_class_outside_target_drops_the_probe() -> None:
    backend = FakeBackend(_plan(_item(vuln_class="sqli", headers=[])))
    batch = LLMAttacker(backend, target=BILLING).plan(_billing_routes(), AttackHistory(), budget=5)
    assert batch == []


def test_billing_prompt_names_target_and_only_its_classes() -> None:
    backend = FakeBackend(_plan())
    LLMAttacker(backend, target=BILLING).plan(_billing_routes(), AttackHistory(), budget=5)
    prompt = backend.calls[0]["prompt"]
    assert "Target: billing" in prompt
    assert "mass_assignment" in prompt
    assert "path_traversal" not in prompt


def test_missing_headers_and_body_still_parse() -> None:
    old_style = {
        "method": "GET",
        "path": "/admin/settings",
        "endpoint": "GET /admin/settings",
        "vuln_class": "auth_bypass",
        "params": [],
        "note": "no headers or body keys",
    }
    backend = FakeBackend(_plan(old_style))
    batch = LLMAttacker(backend, target=BILLING).plan(_billing_routes(), AttackHistory(), budget=5)
    assert len(batch) == 1
    assert batch[0].headers == {}
    assert batch[0].json_body is None


def test_billing_patcher_prompt_and_real_auth_fix_pass_the_gate() -> None:
    finding = _billing_finding(
        Probe(
            "GET",
            "/admin/settings",
            "GET /admin/settings",
            vuln_class="auth_bypass",
            headers={"X-Forwarded-User": "admin"},
        )
    )
    seed = BILLING.load_source()
    attempt = BILLING.fix_catalog[AUTH][1]
    edits = next(alt for alt in attempt.alternatives if edits_apply(seed, alt))
    backend = FakeBackend(
        [
            {
                "rationale": attempt.rationale,
                "edits": [{"old": e.old, "new": e.new} for e in edits],
            }
        ]
    )

    patch = LLMPatcher(backend, target=BILLING).propose(finding, seed, 1)

    system = backend.calls[0]["system"]
    assert "partner.example" in system
    assert "notes" not in system.lower()
    assert patch is not None
    result = VerificationGate(BILLING).verify(seed, patch, finding, [])
    assert result.accepted, result.reasons
    user_prompt = backend.calls[0]["prompt"]
    assert 'Probe headers: {"X-Forwarded-User": "admin"}' in user_prompt


def test_patch_prompt_never_contains_canary_for_billing() -> None:
    seed = BILLING.load_source()
    with Sandbox(target=BILLING) as sandbox:
        canary = sandbox.canary
        finding = Oracle(canary).judge(
            sandbox.send(
                Probe(
                    "GET",
                    "/admin/settings",
                    "GET /admin/settings",
                    vuln_class="auth_bypass",
                    headers={"X-Forwarded-User": "admin"},
                )
            )
        )
    assert finding is not None
    backend = FakeBackend([{"rationale": "x", "edits": [{"old": "def", "new": "def"}]}])
    LLMPatcher(backend, target=BILLING).propose(finding, seed, 0)
    assert canary not in backend.calls[0]["prompt"]


def test_notes_system_prompt_keeps_notes_guidance() -> None:
    prompt = system_prompt(NOTES)
    for word in ("alice", "parameterised queries", "ownership checks", "resolved-path"):
        assert word in prompt


def test_cli_anthropic_failure_for_billing_returns_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(sys.modules, "anthropic", None)
    code = main(["run", "--backend", "anthropic", "--target", "billing", "--out", str(tmp_path)])
    assert code == 2
    assert "anthropic" in capsys.readouterr().err
