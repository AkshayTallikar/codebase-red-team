"""The billing target: seeds land, naive fixes are bypassed, real fixes hold."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker, mutate
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig
from redteam.cli import main
from redteam.gate import VerificationGate
from redteam.models import Finding, Probe
from redteam.oracle import Oracle
from redteam.patching import apply_edits
from redteam.sandbox import Sandbox
from redteam.targets import BILLING

CANARY = "CANARY-billing-test"
BANNED_IMPORTS = ("import socket", "httpx", "requests", "urllib.request")
MASS = "mass_assignment:PATCH /me"
SSRF = "ssrf:GET /invoices/import"
AUTH = "auth_bypass:GET /admin/settings"
IDOR = "idor:GET /invoices/{invoice_id}"
BYPASSABLE = (MASS, SSRF, AUTH)
EXPECTED_KEYS = {MASS, SSRF, AUTH, IDOR}


def _seed(vuln_class: str) -> Probe:
    return next(probe for probe in BILLING.seed_probes if probe.vuln_class == vuln_class)


def _lands(source: str, probe: Probe) -> bool:
    """Send one probe to a fresh copy of `source` and report whether the oracle judged it."""
    with Sandbox(source, target=BILLING, canary=CANARY) as sandbox:
        return Oracle(sandbox.canary).judge(sandbox.send(probe)) is not None


def _finding(probe: Probe) -> Finding:
    """The finding that the seed probe produces on the unpatched seed app."""
    with Sandbox(target=BILLING, canary=CANARY) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, probe
    return finding


def _functional_failures(source: str) -> list[str]:
    """Names of the functional checks that fail as alice on `source`."""
    failures: list[str] = []
    for check in BILLING.functional_checks:
        with Sandbox(source, target=BILLING, canary=CANARY) as sandbox:
            result = sandbox.send(check.probe, token=BILLING.user_token)
        text_ok = check.expect_text is None or check.expect_text in result.body
        if result.status != check.expect_status or not text_ok:
            failures.append(check.name)
    return failures


def test_every_functional_check_passes_on_the_seed_app() -> None:
    assert _functional_failures(BILLING.load_source()) == []


def test_each_seed_probe_lands_on_the_seed_app() -> None:
    for probe in BILLING.seed_probes:
        if probe.vuln_class != "idor":
            assert _lands(BILLING.load_source(), probe), probe.endpoint
    # Only invoice 1 belongs to someone other than mallory and carries the canary.
    assert _lands(BILLING.load_source(), _seed("idor"))


def test_app_source_opens_no_network_connection() -> None:
    source = BILLING.load_source()
    for banned in BANNED_IMPORTS:
        assert banned not in source, banned


def test_mutate_returns_nothing_for_an_unknown_class() -> None:
    assert mutate(Probe("GET", "/x", "GET /x", vuln_class="unknown", params={"url": "a"})) == []


def test_mutate_respells_mass_assignment_keys_and_keeps_values() -> None:
    variants = mutate(_seed("mass_assignment"))
    bodies = [variant.json_body for variant in variants]
    assert {"Role": "admin"} in bodies
    assert {"ROLE": "admin"} in bodies
    assert {" role": "admin"} in bodies
    assert {"role ": "admin"} in bodies


def test_mutate_replaces_the_ssrf_host_in_each_form() -> None:
    urls = {variant.params["url"] for variant in mutate(_seed("ssrf"))}
    assert "http://METADATA.INTERNAL/latest/secret" in urls
    assert "http://169.254.169.254/latest/secret" in urls
    assert "http://2852039166/latest/secret" in urls
    assert "http://localhost/latest/secret" in urls


def test_mutate_respells_the_auth_header_value() -> None:
    values = {variant.headers["X-Forwarded-User"] for variant in mutate(_seed("auth_bypass"))}
    assert {"Admin", "ADMIN", " admin"} <= values


@pytest.mark.parametrize("key", BYPASSABLE)
def test_naive_fix_blocks_the_seed_but_a_variant_still_lands(key: str) -> None:
    vuln_class = key.split(":")[0]
    seed = _seed(vuln_class)
    patch = ReferencePatcher(BILLING).propose(_finding(seed), BILLING.load_source(), 0)
    assert patch is not None and patch.finding_key == key
    naive = apply_edits(BILLING.load_source(), patch.edits)

    assert not _lands(naive, seed)
    assert any(_lands(naive, variant) for variant in mutate(seed))
    assert _functional_failures(naive) == []


@pytest.mark.parametrize("key", BYPASSABLE)
def test_real_fix_closes_every_variant_and_keeps_functions_working(key: str) -> None:
    vuln_class = key.split(":")[0]
    seed = _seed(vuln_class)
    naive_patch = ReferencePatcher(BILLING).propose(_finding(seed), BILLING.load_source(), 0)
    assert naive_patch is not None
    naive = apply_edits(BILLING.load_source(), naive_patch.edits)

    real_patch = ReferencePatcher(BILLING).propose(_finding(seed), naive, 1)
    assert real_patch is not None
    fixed = apply_edits(naive, real_patch.edits)

    assert not any(_lands(fixed, probe) for probe in (seed, *mutate(seed)))
    assert _functional_failures(fixed) == []


def test_real_idor_fix_stops_cross_owner_reads_and_keeps_own_reads() -> None:
    seed = _seed("idor")
    patch = ReferencePatcher(BILLING).propose(_finding(seed), BILLING.load_source(), 0)
    assert patch is not None
    fixed = apply_edits(BILLING.load_source(), patch.edits)

    assert not _lands(fixed, seed)
    assert _functional_failures(fixed) == []


def test_gate_accepts_every_catalog_attempt_in_sequence() -> None:
    gate = VerificationGate(BILLING)
    source = BILLING.load_source()
    for key, attempts in BILLING.fix_catalog.items():
        vuln_class = key.split(":")[0]
        seed = _seed(vuln_class)
        finding = _finding(seed)
        for attempt in range(len(attempts)):
            patch = ReferencePatcher(BILLING).propose(finding, source, attempt)
            assert patch is not None, (key, attempt)
            regressions = [seed, *mutate(seed)] if attempt > 0 else []
            verdict = gate.verify(source, patch, finding, regressions)
            assert verdict.accepted, (key, attempt, verdict.reasons)
            assert verdict.source is not None
            source = verdict.source


def test_isolated_probes_keep_a_mass_assignment_from_leaking_later() -> None:
    with Sandbox(target=BILLING, canary=CANARY) as sandbox:
        escalate = _seed("mass_assignment")
        assert Oracle(sandbox.canary).judge(sandbox.send(escalate)) is not None

        sandbox.reset()
        later = Probe("GET", "/admin/settings", "GET /admin/settings")
        assert sandbox.send(later).status == 403


def test_offline_arena_hardens_billing(tmp_path: Path) -> None:
    arena = Arena(
        PlaybookAttacker(BILLING),
        ReferencePatcher(BILLING),
        target=BILLING,
        config=ArenaConfig(),
        out_dir=tmp_path,
    )
    result = arena.run()

    assert result.hardened
    assert result.open_findings == {}
    for key in BYPASSABLE:
        assert result.accepted_patches[key] == 2, key
        assert key in result.bypassed_keys, key
    assert result.accepted_patches[IDOR] == 1
    found = {finding.key for summary in result.rounds for finding in summary.findings}
    assert found <= EXPECTED_KEYS


def test_cli_runs_billing_and_exits_zero(tmp_path: Path) -> None:
    assert main(["run", "--target", "billing", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "summary.json").exists()
