"""The committed demo run must stay honest: its hardened app blocks every recorded exploit."""

import json
from pathlib import Path

from redteam.gate import FUNCTIONAL_CHECKS
from redteam.models import Probe
from redteam.oracle import Oracle
from redteam.sandbox import ALICE_TOKEN, Sandbox

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo-run"


def test_demo_summary_says_hardened():
    summary = json.loads((DEMO / "summary.json").read_text())
    assert summary["hardened"] is True
    assert summary["open_keys"] == []


def test_demo_regressions_are_blocked_by_the_final_app():
    regressions = json.loads((DEMO / "regressions.json").read_text())
    probes = [Probe.from_dict(p) for group in regressions.values() for p in group]
    assert len(probes) >= 4

    with Sandbox((DEMO / "final_app.py").read_text()) as sandbox:
        oracle = Oracle(sandbox.canary)
        for probe in probes:
            assert oracle.judge(sandbox.send(probe)) is None, probe


def test_demo_first_exploit_per_weakness_lands_on_the_seed_app():
    # Later probes in a group are bypasses of naive fixes, so only the first one
    # is expected to work against the untouched seed.
    regressions = json.loads((DEMO / "regressions.json").read_text())
    first_probes = [Probe.from_dict(group[0]) for group in regressions.values()]
    assert len(first_probes) == 4

    with Sandbox() as sandbox:
        oracle = Oracle(sandbox.canary)
        for probe in first_probes:
            assert oracle.judge(sandbox.send(probe)) is not None, probe


def test_demo_final_app_still_serves_normal_use():
    with Sandbox((DEMO / "final_app.py").read_text()) as sandbox:
        for check in FUNCTIONAL_CHECKS:
            result = sandbox.send(check.probe, token=ALICE_TOKEN)
            assert result.status == check.expect_status, check.name
