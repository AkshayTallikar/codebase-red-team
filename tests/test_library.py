"""The library target: seeds land, naive fixes are bypassed, real fixes hold."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.attacker import PlaybookAttacker, mutate
from redteam.agents.patcher import ReferencePatcher
from redteam.arena import Arena, ArenaConfig
from redteam.audit import audit
from redteam.cli import main
from redteam.gate import VerificationGate
from redteam.models import Finding, Probe
from redteam.oracle import Oracle
from redteam.patching import apply_edits
from redteam.sandbox import Sandbox
from redteam.targets import LIBRARY

CANARY = "CANARY-library-test"
BANNED_IMPORTS = ("import socket", "httpx", "requests", "urllib.request")
SQLI = "sqli:GET /books/search"
PATH = "path_traversal:GET /covers"
AUTH = "auth_bypass:GET /staff/report"
IDOR = "idor:GET /loans/{loan_id}"
SSRF = "ssrf:POST /covers/fetch"
MASS = "mass_assignment:PATCH /members/me"
NAIVE_KEYS = (SQLI, PATH, AUTH)
EXPECTED_KEYS = {SQLI, PATH, AUTH, IDOR, SSRF, MASS}


def _seed(vuln_class: str) -> Probe:
    return next(probe for probe in LIBRARY.seed_probes if probe.vuln_class == vuln_class)


def _lands(source: str, probe: Probe) -> bool:
    """Send one probe to a fresh copy of `source` and report whether the oracle judged it."""
    with Sandbox(source, target=LIBRARY, canary=CANARY) as sandbox:
        return Oracle(sandbox.canary).judge(sandbox.send(probe)) is not None


def _finding(probe: Probe) -> Finding:
    """The finding that the seed probe produces on the unpatched seed app."""
    with Sandbox(target=LIBRARY, canary=CANARY) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, probe
    return finding


def _functional_failures(source: str) -> list[str]:
    """Names of the functional checks that fail as alice on `source`."""
    failures: list[str] = []
    for check in LIBRARY.functional_checks:
        with Sandbox(source, target=LIBRARY, canary=CANARY) as sandbox:
            result = sandbox.send(check.probe, token=LIBRARY.user_token)
        text_ok = check.expect_text is None or check.expect_text in result.body
        if result.status != check.expect_status or not text_ok:
            failures.append(check.name)
    return failures


def _naive_source() -> str:
    """The seed with attempt 0 of every naive fix applied."""
    source = LIBRARY.load_source()
    for key in NAIVE_KEYS:
        patch = ReferencePatcher(LIBRARY).propose(_finding(_seed(key.split(":")[0])), source, 0)
        assert patch is not None, key
        source = apply_edits(source, patch.edits)
    return source


def test_every_functional_check_passes_on_the_seed_app() -> None:
    assert _functional_failures(LIBRARY.load_source()) == []


def test_each_seed_probe_lands_on_the_seed_app() -> None:
    for probe in LIBRARY.seed_probes:
        if probe.vuln_class != "idor":
            assert _lands(LIBRARY.load_source(), probe), probe.endpoint
    # Only loan 1 belongs to the staff member and carries the canary.
    assert _lands(LIBRARY.load_source(), _seed("idor"))


def test_seed_endpoints_are_real_route_templates() -> None:
    with Sandbox(target=LIBRARY, canary=CANARY) as sandbox:
        routes = set(sandbox.routes())
    for probe in (*LIBRARY.seed_probes, *LIBRARY.audit_probes):
        assert probe.endpoint in routes, probe.endpoint


def test_app_source_opens_no_network_connection() -> None:
    source = LIBRARY.load_source()
    for banned in BANNED_IMPORTS:
        assert banned not in source, banned


def test_mutate_respells_the_naive_sqli_guard_away() -> None:
    variants = [variant.params["q"] for variant in mutate(_seed("sqli"))]
    assert "' or 1=1 --" in variants


def test_naive_sqli_fix_blocks_the_seed_but_a_variant_still_lands() -> None:
    seed = _seed("sqli")
    patch = ReferencePatcher(LIBRARY).propose(_finding(seed), LIBRARY.load_source(), 0)
    assert patch is not None and patch.finding_key == SQLI
    naive = apply_edits(LIBRARY.load_source(), patch.edits)

    assert not _lands(naive, seed)
    assert any(_lands(naive, variant) for variant in mutate(seed))
    assert _functional_failures(naive) == []


def test_naive_path_fix_blocks_the_seed_but_a_variant_still_lands() -> None:
    seed = _seed("path_traversal")
    patch = ReferencePatcher(LIBRARY).propose(_finding(seed), LIBRARY.load_source(), 0)
    assert patch is not None and patch.finding_key == PATH
    naive = apply_edits(LIBRARY.load_source(), patch.edits)

    assert not _lands(naive, seed)
    assert any(_lands(naive, variant) for variant in mutate(seed))
    assert _functional_failures(naive) == []


def test_naive_auth_fix_blocks_the_seed_but_a_variant_still_lands() -> None:
    seed = _seed("auth_bypass")
    patch = ReferencePatcher(LIBRARY).propose(_finding(seed), LIBRARY.load_source(), 0)
    assert patch is not None and patch.finding_key == AUTH
    naive = apply_edits(LIBRARY.load_source(), patch.edits)

    assert not _lands(naive, seed)
    assert any(_lands(naive, variant) for variant in mutate(seed))
    assert _functional_failures(naive) == []


@pytest.mark.parametrize("key", [SSRF, MASS, IDOR])
def test_single_real_fix_closes_every_variant_and_keeps_functions_working(key: str) -> None:
    seed = _seed(key.split(":")[0])
    patch = ReferencePatcher(LIBRARY).propose(_finding(seed), LIBRARY.load_source(), 0)
    assert patch is not None and patch.finding_key == key
    fixed = apply_edits(LIBRARY.load_source(), patch.edits)

    assert not any(_lands(fixed, probe) for probe in (seed, *mutate(seed)))
    assert _functional_failures(fixed) == []


@pytest.mark.parametrize("key", NAIVE_KEYS)
def test_real_fix_closes_every_variant_after_the_naive_fix(key: str) -> None:
    seed = _seed(key.split(":")[0])
    naive_patch = ReferencePatcher(LIBRARY).propose(_finding(seed), LIBRARY.load_source(), 0)
    assert naive_patch is not None
    naive = apply_edits(LIBRARY.load_source(), naive_patch.edits)

    real_patch = ReferencePatcher(LIBRARY).propose(_finding(seed), naive, 1)
    assert real_patch is not None
    fixed = apply_edits(naive, real_patch.edits)

    assert not any(_lands(fixed, probe) for probe in (seed, *mutate(seed)))
    assert _functional_failures(fixed) == []


def test_gate_accepts_every_catalog_attempt_in_sequence() -> None:
    gate = VerificationGate(LIBRARY)
    source = LIBRARY.load_source()
    for key, attempts in LIBRARY.fix_catalog.items():
        seed = _seed(key.split(":")[0])
        finding = _finding(seed)
        for attempt in range(len(attempts)):
            patch = ReferencePatcher(LIBRARY).propose(finding, source, attempt)
            assert patch is not None, (key, attempt)
            regressions = [seed, *mutate(seed)] if attempt > 0 else []
            verdict = gate.verify(source, patch, finding, regressions)
            assert verdict.accepted, (key, attempt, verdict.reasons)
            assert verdict.source is not None
            source = verdict.source


def test_offline_arena_hardens_library(tmp_path: Path) -> None:
    arena = Arena(
        PlaybookAttacker(LIBRARY),
        ReferencePatcher(LIBRARY),
        target=LIBRARY,
        config=ArenaConfig(),
        out_dir=tmp_path,
    )
    result = arena.run()

    assert result.hardened
    assert result.open_findings == {}
    assert result.audit is not None and result.audit.clean
    for key in NAIVE_KEYS:
        assert result.accepted_patches[key] == 2, key
        assert key in result.bypassed_keys, key
    for key in (SSRF, MASS, IDOR):
        assert result.accepted_patches[key] == 1, key
    found = {finding.key for summary in result.rounds for finding in summary.findings}
    assert found <= EXPECTED_KEYS


def test_audit_probes_each_land_on_the_seed_or_the_naive_app() -> None:
    seed, naive = LIBRARY.load_source(), _naive_source()
    for probe in LIBRARY.audit_probes:
        assert _lands(seed, probe) or _lands(naive, probe), probe.note


def test_audit_fails_the_seed_app_on_every_class() -> None:
    result = audit(LIBRARY.load_source(), LIBRARY)
    assert result.total == len(LIBRARY.audit_probes)
    assert set(result.exposed_classes) == set(LIBRARY.vuln_classes)


def test_audit_is_clean_after_every_real_fix() -> None:
    result = Arena(
        PlaybookAttacker(LIBRARY),
        ReferencePatcher(LIBRARY, skip_naive=True),
        target=LIBRARY,
    ).run()

    assert result.hardened
    assert result.audit is not None
    assert result.audit.clean
    assert audit(result.final_source, LIBRARY).clean


def test_cli_runs_library_and_exits_zero(tmp_path: Path) -> None:
    assert main(["run", "--target", "library", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "summary.json").exists()
