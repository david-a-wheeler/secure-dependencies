# AGENTS.md

## Size, reuse, and ecosystem sharing

Try to keep implementation short and simple
while still providing functionality and security.

In particular, define and use methods instead of repeating
code constructs where reasonable.

Try to share constructs between ecosystems, such as patterns to search for,
so lessons learned from one ecosystem are more likely to be shared.

## Style

Do not use long dashes (em dashes or en dashes).
A `--` should only be used to introduce long-name options.
Instead use other constructs such as colons, semicolons, or parentheses.

Where reasonable, keep text lines at 78 or fewer characters.

## Command injection prevention (verify on every subprocess call)

All subprocess calls MUST pass arguments as a Python list (never as a
shell string), and MUST NOT use `shell=True`. Use `['cmd', 'arg1', 'arg2']`
form. Place all options before `'--'` and put untrusted values (package
names, versions, URLs) after `'--'`, so the tool cannot interpret them as
flags. Validate package names against a strict allowlist regex before use.
This is the primary defence against command injection (CWE-78).

## Regular expression safety (ReDoS prevention)

All regular expressions used for scanning MUST be written to avoid
catastrophic backtracking (ReDoS, CWE-400). Rules:

- Prefer anchored patterns and character classes with bounded quantifiers
  such as `{0,200}` to limit the search space on any single match.
- Never use nested unbounded quantifiers such as `(a+)+` or `(a|ab)*`
  that allow exponential backtracking.
- Prefer mutually exclusive character classes (e.g. `[^)]{0,200}`) over
  overlapping alternatives on the same position.
- When adding a new pattern, mentally trace the worst-case input and
  confirm the engine visits O(n) or O(n^2) states at most per line.
