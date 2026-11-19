"""SARIF 2.1.0 output for the source scout, so its leads read as code-scanning alerts."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from redteam import __version__
from redteam.scout import Hypothesis

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/AkshayTallikar/codebase-red-team"

# Plain-language rule descriptions and a CVSS-like severity GitHub uses to rank alerts.
RULES: dict[str, tuple[str, str, str]] = {
    "sqli": (
        "SqlInjection",
        "SQL text built from request input",
        "9.8",
    ),
    "path_traversal": (
        "PathTraversal",
        "File path built from request input without a containment check",
        "7.5",
    ),
    "idor": (
        "InsecureDirectObjectReference",
        "Object fetched by id without checking it belongs to the caller",
        "7.5",
    ),
    "crash": (
        "UncheckedNumericInput",
        "Request input converted or divided without a range check",
        "5.3",
    ),
    "mass_assignment": (
        "MassAssignment",
        "Request body can write a privileged field",
        "8.8",
    ),
    "ssrf": (
        "ServerSideRequestForgery",
        "Request input chooses where the server fetches from",
        "8.6",
    ),
    "auth_bypass": (
        "IdentityFromCallerInput",
        "Caller identity taken from input other than the auth token",
        "9.1",
    ),
}


def rule_id(vuln_class: str) -> str:
    """The SARIF rule id for a vulnerability class."""
    return f"redteam/{vuln_class}"


def _rule(vuln_class: str) -> dict[str, Any]:
    name, description, severity = RULES.get(
        vuln_class, (vuln_class.title().replace("_", ""), vuln_class, "5.0")
    )
    return {
        "id": rule_id(vuln_class),
        "name": name,
        "shortDescription": {"text": description},
        "fullDescription": {
            "text": f"{description}. Found statically by the redteam source scout; "
            "it is a lead to confirm with the attack loop, not a confirmed exploit."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", vuln_class], "security-severity": severity},
    }


def _result(hyp: Hypothesis, artifact_uri: str, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": rule_id(hyp.vuln_class),
        "ruleIndex": rule_index,
        "level": "error",
        "message": {"text": f"{hyp.endpoint}: {hyp.reason}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": hyp.line, "snippet": {"text": hyp.evidence}},
                }
            }
        ],
        "partialFingerprints": {"redteamKey/v1": hyp.key},
        "properties": {"endpoint": hyp.endpoint, "probes": len(hyp.probes)},
    }


def artifact_uri(path: Path, root: Path | None = None) -> str:
    """`path` as a forward-slash URI relative to `root` (default: the working directory).

    A path outside `root` falls back to its own name, so no absolute local path is ever written.
    """
    base = (root or Path.cwd()).resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return resolved.name


def to_sarif(hypotheses: Sequence[Hypothesis], uri: str) -> dict[str, Any]:
    """One SARIF 2.1.0 log with one run: a rule per class seen and a result per lead."""
    classes = sorted({hyp.vuln_class for hyp in hypotheses})
    index = {cls: i for i, cls in enumerate(classes)}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "redteam-scout",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule(cls) for cls in classes],
                    }
                },
                "results": [_result(hyp, uri, index[hyp.vuln_class]) for hyp in hypotheses],
            }
        ],
    }
