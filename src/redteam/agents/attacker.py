"""Attacker agents: an offline playbook and an LLM-driven planner.

Every attacker returns its batch through `finalize`, which enforces the
sandbox boundary, the route list, the attack history and the budget.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from redteam.llm.base import LLMBackend, LLMError
from redteam.models import VULN_CLASSES, Probe
from redteam.sandbox import ProbeRejected, validate_probe


@dataclass
class AttackHistory:
    """Everything the attacker has sent so far, split by outcome."""

    landed: list[Probe] = field(default_factory=list)
    blocked: list[Probe] = field(default_factory=list)
    sent: set[str] = field(default_factory=set)

    def record(self, probe: Probe, landed: bool) -> None:
        """Remember one sent probe and whether it produced a finding."""
        self.sent.add(probe.signature())
        (self.landed if landed else self.blocked).append(probe)

    def was_sent(self, probe: Probe) -> bool:
        """Return True if an identical probe was already sent."""
        return probe.signature() in self.sent


class Attacker(Protocol):
    """Plans one batch of probes for the next round."""

    name: str

    def plan(self, routes: list[str], history: AttackHistory, budget: int) -> list[Probe]:
        """Return at most `budget` new, valid probes aimed at known routes."""
        ...


def finalize(
    probes: Iterable[Probe],
    routes: list[str],
    history: AttackHistory,
    budget: int,
) -> list[Probe]:
    """Keep only valid, new, unique probes on known routes, up to `budget`."""
    known = set(routes)
    seen: set[str] = set()
    kept: list[Probe] = []
    for probe in probes:
        if len(kept) >= budget:
            break
        if probe.endpoint not in known:
            continue
        try:
            validate_probe(probe)
        except ProbeRejected:
            continue
        if history.was_sent(probe):
            continue
        signature = probe.signature()
        if signature in seen:
            continue
        seen.add(signature)
        kept.append(probe)
    return kept


# --- Playbook (offline, deterministic) -------------------------------------

_SQLI_OPERATORS: tuple[tuple[str, Any], ...] = (
    ("lowercase OR", lambda p: p.replace("OR", "or")),
    ("mixed-case OR", lambda p: p.replace("OR", "Or")),
    ("quoted tautology", lambda _p: "' or '1'='1' --"),
    ("percent-quote tautology", lambda _p: "%' or 1=1 --"),
    ("comment as C-style", lambda p: p.replace("--", "/*")),
    ("space as inline comment", lambda p: p.replace(" ", "/**/")),
)

_TRAVERSAL_OPERATORS: tuple[tuple[str, Any], ...] = (
    ("doubled dot-dot-slash", lambda p: p.replace("../", "....//")),
    ("dot-slash mix", lambda p: p.replace("../", "..././")),
    ("leading dot-slash", lambda p: "./" + p),
    ("encoded slash", lambda p: p.replace("../", "..%2f")),
    ("encoded dots", lambda p: p.replace("../", "%2e%2e/")),
)

_CRASH_VALUES: tuple[str, ...] = (
    "-0",
    "00",
    "",
    " ",
    "999999999999999999999",
    "1e3",
    "0x10",
    "-5",
    "None",
)


def _param_mutations(probe: Probe, key: str, candidates: Iterable[tuple[str, str]]) -> list[Probe]:
    """Build one probe per candidate value that differs from the original."""
    original = probe.params.get(key)
    if original is None:
        return []
    mutations: list[Probe] = []
    for operator, value in candidates:
        if value == original:
            continue
        mutations.append(
            replace(
                probe,
                params={**probe.params, key: value},
                note=f"mutation of {original!r}: {operator}",
            )
        )
    return mutations


def _mutate_idor(probe: Probe) -> list[Probe]:
    """Try neighbouring and zero-padded note ids."""
    prefix, _, id_text = probe.path.rpartition("/")
    if not id_text.isdigit():
        return []
    number = int(id_text)
    candidates = [(f"id {number}->{number + step}", str(number + step)) for step in range(1, 6)]
    candidates.append(("zero-padded id", "0" + str(number)))
    return [
        replace(
            probe,
            path=f"{prefix}/{value}",
            note=f"mutation of {probe.path!r}: {operator}",
        )
        for operator, value in candidates
    ]


def mutate(probe: Probe) -> list[Probe]:
    """Return deterministic variants of a probe that keep its endpoint and class."""
    if probe.vuln_class == "sqli":
        original = probe.params.get("q")
        if original is None:
            return []
        return _param_mutations(
            probe,
            "q",
            [(name, transform(original)) for name, transform in _SQLI_OPERATORS],
        )
    if probe.vuln_class == "path_traversal":
        original = probe.params.get("name")
        if original is None:
            return []
        return _param_mutations(
            probe,
            "name",
            [(name, transform(original)) for name, transform in _TRAVERSAL_OPERATORS],
        )
    if probe.vuln_class == "idor":
        return _mutate_idor(probe)
    if probe.vuln_class == "crash":
        return _param_mutations(
            probe,
            "limit",
            [(f"limit={value!r}", value) for value in _CRASH_VALUES],
        )
    return []


def _seed_probes() -> list[Probe]:
    """The first-round hypotheses, one or more per vulnerability class."""
    probes = [
        Probe(
            method="GET",
            path="/notes/search",
            endpoint="GET /notes/search",
            vuln_class="sqli",
            params={"q": "' OR 1=1 --"},
            note="sqli: tautology in the search query may return other users' notes",
        ),
    ]
    probes.extend(
        Probe(
            method="GET",
            path=f"/notes/{note_id}",
            endpoint="GET /notes/{note_id}",
            vuln_class="idor",
            note="idor: note ids may be read across owners",
        )
        for note_id in range(1, 6)
    )
    probes.append(
        Probe(
            method="GET",
            path="/files",
            endpoint="GET /files",
            vuln_class="path_traversal",
            params={"name": "../secrets.txt"},
            note="path_traversal: name may escape the public data directory",
        )
    )
    probes.extend(
        Probe(
            method="GET",
            path="/notes",
            endpoint="GET /notes",
            vuln_class="crash",
            params={"limit": limit},
            note="crash: unvalidated limit may reach slicing or division",
        )
        for limit in ("0", "abc")
    )
    return probes


class PlaybookAttacker:
    """Replays the seed playbook, then mutates whatever landed or was blocked."""

    name = "playbook"

    def plan(self, routes: list[str], history: AttackHistory, budget: int) -> list[Probe]:
        """Return the seed probes first, then mutations of known exploits."""
        if not history.sent:
            batch = _seed_probes()
        else:
            batch = []
            for probe in history.landed:
                batch.extend(mutate(probe))
            for probe in history.blocked:
                if probe.note.startswith("mutation of"):
                    batch.extend(mutate(probe))
        return finalize(batch, routes, history, budget)


# --- LLM planner ------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a security tester attacking a deliberately vulnerable sample app "
    "inside a local test sandbox. You must only output request specs in the "
    "required JSON schema. Adapt to fixes: when a payload was blocked, try "
    "variants of that payload rather than repeating it."
)

PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["probes"],
    "properties": {
        "probes": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["method", "path", "endpoint", "vuln_class", "params", "note"],
                "properties": {
                    "method": {"type": "string"},
                    "path": {"type": "string"},
                    "endpoint": {"type": "string"},
                    "vuln_class": {"type": "string", "enum": list(VULN_CLASSES)},
                    "params": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["name", "value"],
                            "properties": {
                                "name": {"type": "string"},
                                "value": {"type": "string"},
                            },
                        },
                    },
                    "note": {"type": "string"},
                },
            },
        }
    },
}


def _compact(probe: Probe) -> dict[str, Any]:
    return {
        "method": probe.method,
        "path": probe.path,
        "params": probe.params,
        "vuln_class": probe.vuln_class,
    }


def _build_prompt(routes: list[str], history: AttackHistory, budget: int) -> str:
    landed = [_compact(p) for p in history.landed[-20:]]
    blocked = [_compact(p) for p in history.blocked[-20:]]
    lines = [
        "Routes (METHOD /path-template):",
        *(f"- {route}" for route in routes),
        "",
        'Your own token is already sent as the X-Token header for user "mallory". '
        "Do not add headers or a host.",
        "Goal: make the app leak the secret canary of another user, or return a 5xx.",
        f"Vulnerability classes: {', '.join(VULN_CLASSES)}.",
        "Probes that landed (produced a finding), oldest first:",
        json.dumps(landed, separators=(",", ":"), sort_keys=True),
        "Probes that were blocked (sent, no finding), oldest first:",
        json.dumps(blocked, separators=(",", ":"), sort_keys=True),
        f"Return at most {budget} probes, each on one of the routes above.",
    ]
    return "\n".join(lines)


def _probe_from_spec(item: Any) -> Probe | None:
    """Turn one model-written item into a Probe, or None if it is malformed."""
    if not isinstance(item, dict):
        return None
    text_keys = ("method", "path", "endpoint", "vuln_class", "note")
    if not all(isinstance(item.get(key), str) for key in text_keys):
        return None
    if item["vuln_class"] not in VULN_CLASSES:
        return None
    raw_params = item.get("params")
    if not isinstance(raw_params, list):
        return None
    params: dict[str, str] = {}
    for pair in raw_params:
        if not isinstance(pair, dict):
            return None
        name, value = pair.get("name"), pair.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            return None
        params[name] = value
    return Probe(
        method=item["method"].upper(),
        path=item["path"],
        endpoint=item["endpoint"],
        vuln_class=item["vuln_class"],
        params=params,
        note=item["note"],
    )


class LLMAttacker:
    """Asks an LLM for a batch of probes; falls back when the model fails."""

    name = "llm"

    def __init__(self, backend: LLMBackend, *, fallback: Attacker | None = None) -> None:
        self.backend = backend
        self.fallback = fallback

    def plan(self, routes: list[str], history: AttackHistory, budget: int) -> list[Probe]:
        """Return validated probes from the model, or the fallback's probes on failure."""
        prompt = _build_prompt(routes, history, budget)
        try:
            response = self.backend.complete_json(
                system=SYSTEM_PROMPT, prompt=prompt, schema=PLAN_SCHEMA
            )
        except LLMError:
            if self.fallback is not None:
                return self.fallback.plan(routes, history, budget)
            return []
        raw = response.get("probes") if isinstance(response, dict) else None
        if not isinstance(raw, list):
            return []
        probes = [probe for item in raw if (probe := _probe_from_spec(item)) is not None]
        return finalize(probes, routes, history, budget)
