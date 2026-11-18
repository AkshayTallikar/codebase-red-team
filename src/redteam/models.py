"""Plain data types shared by the sandbox, the agents and the arena."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

VulnClass = Literal["sqli", "idor", "path_traversal", "crash", "unknown"]
VULN_CLASSES: tuple[str, ...] = ("sqli", "idor", "path_traversal", "crash")


@dataclass(frozen=True)
class Probe:
    """One request the attacker wants to send to the target.

    `endpoint` is the route template the probe aims at, for example
    "GET /notes/{note_id}". `path` is the concrete path, for example "/notes/1".
    Only a path is allowed, never a host or scheme: the sandbox enforces that.
    """

    method: str
    path: str
    endpoint: str
    vuln_class: str = "unknown"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    json_body: dict[str, Any] | None = None
    note: str = ""

    def signature(self) -> str:
        """Stable identity used to dedupe probes (ignores the free-text note)."""
        return json.dumps(
            [
                self.method.upper(),
                self.path,
                sorted(self.params.items()),
                sorted(self.headers.items()),
                self.json_body,
            ],
            sort_keys=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Probe:
        return cls(
            method=str(data["method"]).upper(),
            path=str(data["path"]),
            endpoint=str(data.get("endpoint", "")),
            vuln_class=str(data.get("vuln_class", "unknown")),
            params={str(k): str(v) for k, v in (data.get("params") or {}).items()},
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            json_body=data.get("json_body"),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    status: int
    body: str


@dataclass(frozen=True)
class Finding:
    """A probe that the oracle says succeeded.

    kind is "leak" (the canary showed up in the response) or "crash" (5xx).
    evidence is a short excerpt of the response with the canary redacted.
    """

    kind: Literal["leak", "crash"]
    vuln_class: str
    endpoint: str
    probe: Probe
    status: int
    evidence: str

    @property
    def key(self) -> str:
        return f"{self.vuln_class}:{self.endpoint}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["key"] = self.key
        return data


@dataclass(frozen=True)
class Edit:
    """Replace exactly one occurrence of `old` with `new` in the target source."""

    old: str
    new: str


@dataclass(frozen=True)
class Patch:
    finding_key: str
    edits: tuple[Edit, ...]
    rationale: str
    author: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "edits": [asdict(e) for e in self.edits],
            "rationale": self.rationale,
            "author": self.author,
        }
