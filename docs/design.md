# Design: Codebase Red Team

Status: milestone 1 shipped; milestone 2 accepted (section 7)
Author: Akshay Tallikar

## 1. Problem

Security review of a codebase is usually a one-shot event: a scanner runs, a
list of findings lands in a ticket, someone patches a few of them, and nobody
checks whether the patch actually closed the hole or just moved it. Real
attackers do not work that way. They adapt. A naive fix (strip `../` from a
path, block the word `OR` in a query) invites the next payload that walks
straight around it.

This project treats hardening as an **adversarial loop**. One agent attacks a
running application, a second agent patches it, and every patch has to survive
the attacker's next round, which deliberately mutates the payloads that were
just blocked. The history of that arms race (what was tried, what broke, what
the fix was, whether the fix held) is the main output, together with a
regression suite that grows every round.

## 2. Goals and non-goals

Goals

- An attacker agent that probes a live app and adapts to what gets blocked.
- A patcher agent that edits source code and must pass a verification gate
  before its patch is accepted.
- Every confirmed exploit becomes a permanent regression case.
- A readable, replayable ledger of every round.
- Deterministic offline mode, so tests and CI need no API key.
- A pluggable LLM backend, with Claude as the real one.

Non-goals

- Scanning arbitrary third-party code or live systems. The attacker only ever
  talks to the bundled sample app, in process, through an ASGI transport. There
  is no network client in the attack path.
- Being a general-purpose SAST or DAST product.

## 3. Safety boundary

The sample app (`src/redteam/target/vulnerable_app.py`) is deliberately
vulnerable and exists only to be attacked by this project.

- The sandbox loads the app's source from a working copy and mounts it on an
  `httpx.ASGITransport`. Requests never leave the Python process.
- A probe is only a method, a path that must start with `/`, query params,
  headers and a JSON body. The sandbox rejects anything that looks like an
  absolute URL or a host.
- The only secrets in play are per-run random canaries created by the sandbox.
- The seed source file is never edited. Patches go to a per-run working copy.

## 4. Architecture

```
            +-------------------+          probes           +-----------------------+
            |  Attacker agent   | ------------------------> |       Sandbox         |
            |  playbook + LLM   | <------------------------ |  working copy of the  |
            +-------------------+     responses + oracle    |  target, ASGI only    |
                     |                                       +-----------------------+
                     | findings                                        ^
                     v                                                 | candidate source
            +-------------------+     proposed edits      +-----------------------+
            |   Patcher agent   | ----------------------> |   Verification gate   |
            |  reference + LLM  | <---------------------- | compile, exploit gone,|
            +-------------------+     accept / reject     | regressions, function |
                     |                                    +-----------------------+
                     v
            +-------------------+
            |  Arena + Ledger   |  rounds, JSONL events, ARMS_RACE.md, regressions.json
            +-------------------+
```

### 4.1 Target app

A small FastAPI notes service with token auth (`X-Token` header) and three
seeded users: `admin`, `alice` (a normal user whose data must keep working) and
`mallory` (the attacker's identity). It exposes `create_app(data_dir, canary)`.

Seeded weaknesses, one per class:

| Class            | Endpoint                 | Weakness                                   |
|------------------|--------------------------|--------------------------------------------|
| `sqli`           | `GET /notes/search?q=`   | query built with string formatting         |
| `idor`           | `GET /notes/{note_id}`   | no ownership check                         |
| `path_traversal` | `GET /files?name=`       | joins user input onto the data directory   |
| `crash`          | `GET /notes?limit=`      | unvalidated input reaches a slice and math |

The admin's private note and `data_dir/secrets.txt` both contain the canary.

### 4.2 Sandbox and oracle

`Sandbox` copies the seed source into a workspace, writes the data directory,
generates a fresh canary, imports the module under a unique name and returns an
ASGI client. `Sandbox.reload(source)` swaps in patched code.

The oracle is intentionally simple and hard to fool:

- **Leak**: the canary appears anywhere in a response the attacker received.
  Covers SQL injection, IDOR and path traversal with one rule.
- **Crash**: any 5xx status.

### 4.3 Attacker

Input: the app's OpenAPI route list, the attack history (which probes landed,
which were blocked). Output: a batch of probes.

- `PlaybookAttacker` (offline, deterministic): seed payloads per class plus a
  mutation engine. Every previously successful exploit is replayed next round;
  if it is now blocked, the engine mutates it (case changes, quote variants,
  doubled traversal sequences, URL encoding, boundary integers) to look for a
  bypass of the new patch.
- `LLMAttacker`: sends the route list and history to the model and asks for
  probes as structured JSON, validated before use.

### 4.4 Patcher

Input: the finding (class, endpoint, the probe that worked), the current
source, and how many times this weakness has been patched before. Output: a
list of `{old, new}` text edits.

- `ReferencePatcher` (offline): a fix catalog for the bundled target. Its first
  fix for some classes is deliberately naive, the kind of patch a hurried
  developer writes, so the offline demo exercises the full loop of
  patch, bypass and re-patch. Its second fix is the correct one.
- `LLMPatcher`: sends the finding and source to the model and asks for edits as
  structured JSON.

### 4.5 Verification gate

A patch is accepted only if all of these hold on the patched working copy:

1. The source compiles and `create_app` still builds.
2. The probe that produced the finding no longer triggers the oracle.
3. Every regression case recorded so far still does not trigger the oracle.
4. Functional checks still pass: alice can read and search her own notes,
   create a note, list with a normal limit, and read the public readme.

Check 4 is what stops a patcher from "fixing" a bug by deleting the endpoint.
A rejected patch is rolled back and logged, and the weakness stays open for
the next round.

### 4.6 Arena and ledger

```
for round in 1..N:
    probes   = attacker.plan(routes, history)
    findings = dedupe(oracle(sandbox.run(p)) for p in probes)
    for f in findings:
        regressions.add(f.probe)
        edits = patcher.propose(f, source, attempts[f.key])
        if gate.verify(source + edits): accept, source = patched
        else: reject
    stop early when a round produces no findings
```

Every event is appended to `events.jsonl`. At the end the arena writes
`ARMS_RACE.md` (a round-by-round table), `regressions.json` and the final
hardened source `final_app.py`.

### 4.7 LLM backend

```python
class LLMBackend(Protocol):
    def complete_json(self, *, system: str, prompt: str, schema: dict) -> dict: ...
```

- `AnthropicBackend`: Claude through the official `anthropic` SDK with
  structured outputs (`output_config.format` with a JSON schema). Optional
  dependency, used only when selected.
- `FakeBackend`: returns queued responses; used in tests of the LLM agents.

## 5. Milestone 1 scope

1. Design doc, project scaffold, CI.
2. Vulnerable target, sandbox and oracle.
3. Pluggable LLM backend.
4. Attacker agent with the mutation engine.
5. Patcher agent and verification gate.
6. Arena loop, ledger and CLI.
7. README, architecture diagram and a recorded demo run.

## 6. Later ideas

- Let the attacker read the source (white-box mode) as well as the API.
- Run several attacker strategies as a population and keep the ones that land.
- Multi-step attack chains (log in, escalate, then read).

## 7. Milestone 2: more targets, and a measured answer

Milestone 1 shows the loop on one app. It cannot yet answer the question the
project exists to ask: **does an adaptive attacker catch weak fixes that a
one-shot scan would wave through?** Milestone 2 makes targets pluggable, adds a
second app with three new weakness classes, and measures the answer with a
held-out exploit audit.

### 7.1 Target interface

A target is a value, not a hard-coded path:

```python
@dataclass(frozen=True)
class Target:
    name: str                    # "notes", "billing"
    description: str             # one line, used in LLM prompts
    seed_path: Path              # the deliberately vulnerable app source
    vuln_classes: tuple[str, ...]
    attacker_token: str          # identity every probe is sent as
    user_token: str              # the legitimate user the gate checks
    functional_checks: tuple[FunctionalCheck, ...]
    seed_probes: tuple[Probe, ...]       # the playbook's first hypotheses
    audit_probes: tuple[Probe, ...]      # held-out exploits, never shown to attackers
    fix_catalog: dict[str, tuple[FixAttempt, ...]]
    patch_guidance: str          # what must keep working, for the LLM patcher
    isolate_probes: bool         # rebuild app state before every probe
    write_data: Callable[[Path, str], None]   # data dir for a given canary
```

The sandbox, gate, attackers, patchers, arena and CLI all take a target, and
default to `notes`, so milestone 1 behaviour and its demo stay identical.
`isolate_probes` exists because some exploits change state (a user promotes
themselves to admin); without a reset, one landed probe would make every later
probe look like an exploit.

### 7.2 Second target: `billing`

An invoicing service with users `admin`, `alice` and `mallory`. The canary is
the organisation's payout secret, visible only to admins, and the body of an
internal metadata endpoint.

| Class | Endpoint | Weakness | Naive first fix | Bypass |
|---|---|---|---|---|
| `mass_assignment` | `PATCH /me` | copies any known field from the JSON body, keys normalised | reject the key `role` | `Role`, `ROLE`, ` role` |
| `ssrf` | `GET /invoices/import?url=` | fetches any URL through an in-memory fake web | block the text `metadata.internal` | upper case host, trailing dot, raw IP, decimal IP, `localhost` |
| `auth_bypass` | `GET /admin/settings` | trusts an `X-Forwarded-User` header | reject the value `admin` | `Admin`, ` admin` |
| `idor` | `GET /invoices/{invoice_id}` | no ownership check | (real fix only) | |

The fake web is a dictionary behind a tiny resolver (lower-cases the host,
drops a trailing dot, maps names and decimal IPs to addresses). No socket is
ever opened. The real fixes are an editable-field allowlist, a parsed-URL host
allowlist, dropping header trust, and an owner check.

### 7.3 Held-out audit and the benchmark

`audit(source, target)` replays the target's `audit_probes`, each in a fresh
copy of the app, and reports which classes are still exploitable. The loop never
sees these probes, so the audit is an independent measure of residual risk.

`redteam bench` runs every target under four strategies and audits each result:

| Attacker | Patcher |
|---|---|
| adaptive (seeds, then mutations of what landed and what was blocked) | naive first (rushed fix, then the real one) |
| one-shot (seeds only, like a single scanner pass) | correct first (real fix straight away) |

`SCORECARD.md` reports, per run: rounds, exploits found, bypasses caught,
patches accepted, lines changed by patches, the loop's verdict, and the audit's
verdict. The headline cell is **false confidence**: the loop said "hardened"
while the audit still got in. The expectation, which the scorecard must show
rather than assume, is that one-shot plus naive-first reports hardened apps that
are not, and adaptive closes that gap.

### 7.4 LLM agents

Both LLM agents become target-aware: the attacker schema accepts headers and a
JSON body and limits classes to the target's, and the patcher's system prompt is
built from the target's description and guidance. Tests still use the offline
fake, so CI needs no key.

### 7.5 Milestone 2 scope

1. Target interface, with `notes` moved behind it unchanged.
2. The `billing` target, its playbook seeds and mutations, and its fix catalog.
3. Held-out audit, `redteam bench`, and `SCORECARD.md`.
4. Target-aware LLM attacker and patcher.
5. README, design and recorded runs for both targets plus the scorecard.
