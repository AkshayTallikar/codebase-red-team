# Adding a target

A target is one deliberately vulnerable app plus what the loop needs in order to attack it, patch it and grade it. Each target lives in its own package under `src/redteam/targets/`, and `notes` and `billing` are working examples to copy.

## 1. Write the app

Create `src/redteam/targets/<name>/app.py` with a `create_app(data_dir, canary) -> FastAPI` function.

- Put the canary somewhere only a successful exploit can reach, such as an admin's row, a file outside the public folder, or a secret setting. The oracle counts any response that contains it as a leak, and any 5xx as a crash.
- Give each seeded weakness its own small block of code, with a comment naming it. Fixes are exact text edits, so clearly separated blocks make the catalog easy to write.
- Authenticate with the `X-Token` header, and give the app at least a legitimate user and an attacker user.
- Import no network client. The sandbox serves the app in process, and anything that "fetches" must use an in-memory fake, as `billing` does.
- Start the module docstring with the list of seeded weaknesses and the words "Do not deploy it anywhere".

## 2. Describe it

In `src/redteam/targets/<name>/__init__.py`, build a `Target` (see `targets/base.py`):

| Field | What to put there |
|---|---|
| `name`, `description` | a short id, and one sentence the LLM agents read |
| `seed_path` | the `app.py` beside this file |
| `vuln_classes` | the classes this target seeds, from `models.VULN_CLASSES` |
| `attacker_token`, `user_token` | the attacker's and the legitimate user's tokens |
| `functional_checks` | requests the legitimate user must keep making after every patch; the gate rejects any patch that breaks one |
| `seed_probes` | the black-box playbook's first hypotheses, one or more per weakness |
| `fix_catalog` | per `"class:METHOD /route"` key, a tuple of `FixAttempt`s: optionally a naive fix first (`naive=True`), then the real one |
| `patch_guidance` | what the LLM patcher must keep working and which fixes count as real |
| `write_data` | creates any files the app reads, under the run's data folder |
| `audit_probes` | held-out exploits the attackers never see |
| `isolate_probes` | `True` if an exploit changes state (for example a user promoting themself) |

Then register the target in `targets/__init__.py`.

Two things are easy to get wrong:

- **Real fixes need two alternatives.** A real fix may be applied to the seed app (correct-first) or on top of the naive fix (naive-first, or after the gate rejected the naive fix). Give one alternative that removes the naive block and one that does not, as both existing catalogs do.
- **Audit probes must earn their place.** Each one must land on the seed app or on the app after the naive fixes, and every one must be blocked after the real fixes. `tests/test_audit.py` checks both.

## 3. Check it

```bash
python -m redteam scout --target <name>              # the scout should find every seeded weakness
python -m redteam scout --target <name> --sarif scout.sarif  # the same leads, as SARIF for code scanning
python -m redteam run --target <name> --out runs/x   # black-box playbook
python -m redteam run --target <name> --attacker white-box --out runs/y
python -m redteam bench --target <name> --out runs/bench
```

The scout is a useful early warning. If it misses a weakness, the white-box attacker will miss it too, and the leak is probably shaped differently from what its rules expect (see `docs/design.md` section 8.1). If it flags something you did not seed, either you have an extra bug or the rule needs a tighter guard.

Add a `tests/test_<name>.py` modelled on `tests/test_billing.py`. It should check that every functional check passes on the seed app, that each seed probe lands, that each naive fix is bypassed by a mutation, that each real fix closes the weakness, and that a full offline run ends hardened with a clean audit.
