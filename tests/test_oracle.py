"""Oracle verdicts: leak, crash and the redaction of evidence."""

from redteam.models import Finding, Probe, ProbeResult
from redteam.oracle import REDACTED, Oracle


def _result(body: str, status: int = 200, **probe_fields) -> ProbeResult:
    fields = {"method": "GET", "path": "/x", "endpoint": "GET /x"}
    fields.update(probe_fields)
    return ProbeResult(Probe(**fields), status, body)


def test_leak_is_detected_and_evidence_redacted():
    oracle = Oracle("CANARY-abc")
    finding = oracle.judge(
        _result(
            "secret CANARY-abc here",
            vuln_class="idor",
            endpoint="GET /notes/{note_id}",
        )
    )
    assert isinstance(finding, Finding)
    assert finding.kind == "leak"
    assert finding.vuln_class == "idor"
    assert "CANARY-abc" not in finding.evidence
    assert REDACTED in finding.evidence


def test_server_error_is_a_crash():
    finding = Oracle("CANARY-abc").judge(
        _result("boom", status=500, vuln_class="crash", endpoint="GET /notes")
    )
    assert finding is not None
    assert finding.kind == "crash"
    assert finding.vuln_class == "crash"
    assert finding.status == 500


def test_server_error_with_unknown_class_maps_to_crash():
    finding = Oracle("CANARY-abc").judge(
        _result("boom", status=503, vuln_class="unknown", endpoint="GET /notes")
    )
    assert finding is not None
    assert finding.vuln_class == "crash"


def test_plain_success_is_not_a_finding():
    assert Oracle("CANARY-abc").judge(_result('{"ok": true}', status=200)) is None


def test_finding_key_for_sqli_probe():
    finding = Oracle("CANARY-abc").judge(
        _result(
            "CANARY-abc",
            vuln_class="sqli",
            endpoint="GET /notes/search",
        )
    )
    assert finding is not None
    assert finding.key == "sqli:GET /notes/search"
