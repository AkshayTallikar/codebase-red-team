"""SARIF output: the scout's leads as a valid-looking SARIF 2.1.0 log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.cli import main
from redteam.sarif import artifact_uri, rule_id, to_sarif
from redteam.scout import scout_target
from redteam.targets import BILLING, NOTES, Target


@pytest.mark.parametrize("target", [NOTES, BILLING], ids=["notes", "billing"])
def test_sarif_log_has_one_result_per_lead(target: Target) -> None:
    leads = scout_target(target)
    log = to_sarif(leads, "app.py")
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    (run,) = log["runs"]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert len(results) == len(leads)
    assert [rule["id"] for rule in rules] == [
        rule_id(cls) for cls in sorted({h.vuln_class for h in leads})
    ]
    for lead, result in zip(leads, results, strict=True):
        assert result["ruleId"] == rule_id(lead.vuln_class)
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == lead.line
        assert region["snippet"]["text"] == lead.evidence
        assert result["partialFingerprints"]["redteamKey/v1"] == lead.key
        assert lead.endpoint in result["message"]["text"]


def test_every_rule_has_a_security_severity() -> None:
    log = to_sarif(scout_target(BILLING), "app.py")
    for rule in log["runs"][0]["tool"]["driver"]["rules"]:
        severity = float(rule["properties"]["security-severity"])
        assert 0.0 < severity <= 10.0
        assert "security" in rule["properties"]["tags"]


def test_empty_scan_is_still_a_valid_log() -> None:
    log = to_sarif([], "app.py")
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_artifact_uri_is_relative_and_never_absolute(tmp_path: Path) -> None:
    inside = tmp_path / "src" / "app.py"
    assert artifact_uri(inside, tmp_path) == "src/app.py"
    outside = Path("/somewhere/else/app.py")
    assert artifact_uri(outside, tmp_path) == "app.py"


def test_cli_writes_sarif(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "scout.sarif"
    assert main(["scout", "--target", "notes", "--sarif", str(out)]) == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    results = log["runs"][0]["results"]
    assert len(results) == 4
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not uri.startswith("/")
    assert uri.endswith("app.py")
    assert "4 leads in notes" in capsys.readouterr().out
