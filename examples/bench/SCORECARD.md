# Benchmark scorecard

Every target was attacked under six strategies: three attackers, each with two patchers. After each run, the held-out exploits the attacker never saw were replayed against the final app (notes: 11, billing: 11).

**Headline:** 2 of 12 runs reported a hardened app that the audit still broke into, all of them one-shot with naive-first fixes. Every adaptive run that reported hardened passed the audit. Every white-box run that reported hardened passed the audit, starting from no hand-written exploits.

| Target | Attacker | Patcher | Rounds | Probes sent | Exploits found | Bypasses caught | Patches | Lines changed | Loop says | Audit | Scout leads left | False confidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| notes | adaptive | naive-first | 3 | 59 | 4 | 2 | 6 | 24 | hardened | 0 of 11 landed | 0 | no |
| notes | adaptive | correct-first | 2 | 31 | 4 | 0 | 4 | 24 | hardened | 0 of 11 landed | 0 | no |
| notes | one-shot | naive-first | 2 | 18 | 4 | 0 | 4 | 13 | hardened | 3 of 11 landed | 2 | yes |
| notes | one-shot | correct-first | 2 | 18 | 4 | 0 | 4 | 24 | hardened | 0 of 11 landed | 0 | no |
| notes | white-box | naive-first | 3 | 95 | 4 | 1 | 5 | 24 | hardened | 0 of 11 landed | 0 | no |
| notes | white-box | correct-first | 2 | 55 | 4 | 0 | 4 | 24 | hardened | 0 of 11 landed | 0 | no |
| billing | adaptive | naive-first | 3 | 45 | 4 | 3 | 7 | 16 | hardened | 0 of 11 landed | 0 | no |
| billing | adaptive | correct-first | 2 | 22 | 4 | 0 | 4 | 16 | hardened | 0 of 11 landed | 0 | no |
| billing | one-shot | naive-first | 2 | 14 | 4 | 0 | 4 | 10 | hardened | 7 of 11 landed | 3 | yes |
| billing | one-shot | correct-first | 2 | 14 | 4 | 0 | 4 | 16 | hardened | 0 of 11 landed | 0 | no |
| billing | white-box | naive-first | 3 | 77 | 4 | 1 | 5 | 16 | hardened | 0 of 11 landed | 0 | no |
| billing | white-box | correct-first | 2 | 44 | 4 | 0 | 4 | 16 | hardened | 0 of 11 landed | 0 | no |

## Exposure left behind

- `notes`, one-shot, naive-first: path_traversal, sqli still exploitable.
- `billing`, one-shot, naive-first: auth_bypass, mass_assignment, ssrf still exploitable.

## How to read this

- "Loop says" is the arena's own verdict: whether every weakness it found was closed.
- "Audit" replays held-out exploits that the attacker never saw against the final app.
- "Probes sent" is the attack cost: every probe the attacker sent over the run.
- "Scout leads left" counts the static leads the scout still sees in the final app. Zero means the scout agrees the app is fixed.
- "False confidence" means the loop reported hardened while the audit still got in.
