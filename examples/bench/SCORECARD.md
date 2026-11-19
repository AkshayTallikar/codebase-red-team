# Benchmark scorecard

Every target was attacked under four strategies. After each run, the held-out exploits the attacker never saw were replayed against the final app (notes: 11, billing: 11).

**Headline:** 2 of 8 runs reported a hardened app that the audit still broke into, all of them one-shot with naive-first fixes. Every adaptive run that reported hardened passed the audit.

| Target | Attacker | Patcher | Rounds | Exploits found | Bypasses caught | Patches | Lines changed | Loop says | Audit | False confidence |
|---|---|---|---|---|---|---|---|---|---|---|
| notes | adaptive | naive-first | 3 | 4 | 2 | 6 | 24 | hardened | 0 of 11 landed | no |
| notes | adaptive | correct-first | 2 | 4 | 0 | 4 | 24 | hardened | 0 of 11 landed | no |
| notes | one-shot | naive-first | 2 | 4 | 0 | 4 | 13 | hardened | 3 of 11 landed | yes |
| notes | one-shot | correct-first | 2 | 4 | 0 | 4 | 24 | hardened | 0 of 11 landed | no |
| billing | adaptive | naive-first | 3 | 4 | 3 | 7 | 16 | hardened | 0 of 11 landed | no |
| billing | adaptive | correct-first | 2 | 4 | 0 | 4 | 16 | hardened | 0 of 11 landed | no |
| billing | one-shot | naive-first | 2 | 4 | 0 | 4 | 10 | hardened | 7 of 11 landed | yes |
| billing | one-shot | correct-first | 2 | 4 | 0 | 4 | 16 | hardened | 0 of 11 landed | no |

## Exposure left behind

- `notes`, one-shot, naive-first: path_traversal, sqli still exploitable.
- `billing`, one-shot, naive-first: auth_bypass, mass_assignment, ssrf still exploitable.

## How to read this

- "Loop says" is the arena's own verdict: whether every weakness it found was closed.
- "Audit" replays held-out exploits that the attacker never saw against the final app.
- "False confidence" means the loop reported hardened while the audit still got in.
