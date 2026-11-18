# Design: Codebase Red Team

Status: accepted for milestone 1
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

- More weakness classes (mass assignment, SSRF against a mocked fetcher, auth
  bypass via header confusion).
- Let the attacker read the source (white-box mode) as well as the API.
- Score patches by diff size and readability, not only by correctness.
- Run several attacker strategies as a population and keep the ones that land.
