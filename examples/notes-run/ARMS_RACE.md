# Arms race report

Target: notes · Attacker: playbook · Patcher: reference · Rounds: 3 · Stopped: clean_round · Result: hardened, 0 open

## Scoreboard

| Weakness | Patches accepted | Bypassed after a fix | Status |
|---|---|---|---|
| `sqli:GET /notes/search` | 2 | yes | closed |
| `idor:GET /notes/{note_id}` | 1 | no | closed |
| `path_traversal:GET /files` | 2 | yes | closed |
| `crash:GET /notes` | 1 | no | closed |

## Independent audit

Replayed 11 held-out exploits the attacker never saw: none landed.

## Round 1

Sent 9 probes, 5 landed.

| Finding | Kind | Probe |
|---|---|---|
| `sqli:GET /notes/search` | leak | `GET /notes/search q="' OR 1=1 --"` |
| `idor:GET /notes/{note_id}` | leak | `GET /notes/1` |
| `path_traversal:GET /files` | leak | `GET /files name="../secrets.txt"` |
| `crash:GET /notes` | crash | `GET /notes limit="0"` |

Patches:
- `sqli:GET /notes/search` attempt 0, accepted: Blocks the OR keyword in the query string. Naive: case changes and other spellings of the same SQL get through.
- `idor:GET /notes/{note_id}` attempt 0, accepted: Returns 404 unless the note belongs to the requesting user.
- `path_traversal:GET /files` attempt 0, accepted: Strips ../ sequences from the file name before joining. Naive: nested sequences such as ....// survive the stripping.
- `crash:GET /notes` attempt 0, accepted: Validates limit as an integer between 1 and 100 at the request boundary.

## Round 2

Sent 22 probes, 7 landed.

| Finding | Kind | Probe |
|---|---|---|
| `sqli:GET /notes/search` | leak | `GET /notes/search q="' or 1=1 --"` |
| `path_traversal:GET /files` | leak | `GET /files name="....//secrets.txt"` |

Patches:
- `sqli:GET /notes/search` attempt 1, accepted: Uses a parameterised query so user input is never parsed as SQL, and removes the keyword check.
- `path_traversal:GET /files` attempt 1, accepted: Resolves the real path and refuses anything outside the public directory.

## Round 3

Sent 28 probes, 0 landed. The attacker found nothing new, so the run stopped.
