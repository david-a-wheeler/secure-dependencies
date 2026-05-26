# TODO: Reduce Unnecessary AI Work

Principle: deterministic scripts should do everything that does not require
judgment. AI tiers should receive only what they need to make a decision,
and nothing more.

Items are ordered roughly by impact (tokens saved / complexity removed).

---

## 1. ~~Tier 2: read `signals.txt` instead of `run-log.txt`~~ DONE

**Current behaviour:** `package-analysis-brief.md` Step 1 redirects
`dep_review.py` stdout to `run-log.txt`, then Step 2 tells tier 2 to read
`run-log.txt`, and Step 4 tells tier 2 to also read `signals.txt`.

**Problem:** `run-log.txt` is the full terminal narrative, designed for
human reading. `signals.txt` is purpose-built for AI consumption: compact,
structured, machine-readable, and containing all the same information.
Tier 2 reads both, doubling its input for no benefit.

**Fix:**
- In `references/package-analysis-brief.md`, remove Step 2 ("read
  `run-log.txt`") entirely.
- Redirect dep_review.py output to `run-log.txt` with `> run-log.txt 2>&1`
  (already done for Step 1; the `tee -a` in the `--deeper` and
  `--install-probe` commands at lines 169 and 182 still need fixing -- change
  `| tee -a run-log.txt` to `>> run-log.txt 2>&1`).
- Tier 2 goes straight from running the script (Step 1) to the adversarial
  gate check and `signals.txt` (Steps 3/4).
- `run-log.txt` is retained as a human-readable log but tier 2 never reads it.

---

## 2. ~~Adversarial gate: auto-enforce in `dep_session.py complete`~~ DONE

**Current behaviour:** Brief Step 3 tells tier 2 to read the `ADVERSARIAL_GATE`
line in `signals.txt` and, if `ABORT`, return `CRITICAL / DO_NOT_INSTALL`.
This is a mechanical rule, not a judgment.

**Problem:** Requires an AI read-and-act loop for a decision that has zero
ambiguity. Also, the gate result is already stored in `session-update.json`
(field `adversarial_gate`) which `dep_session.py complete` reads anyway.

**Fix:**
- In `dep_session.py`, in `cmd_complete()`: after loading `session-update.json`,
  check `data.get('adversarial_gate') == 'ABORT'`. If so, override the
  caller-supplied recommendation/risk to `DO_NOT_INSTALL` / `CRITICAL` and
  print a warning explaining the override.
- Remove Step 3 from `references/package-analysis-brief.md`. The gate is now
  enforced deterministically regardless of what tier 2 returns.
- Keep the explanatory text about semantic injection (the note that the gate
  is a heuristic and tier 2 should remain vigilant) but move it to a general
  security-awareness section rather than an action step.

---

## 3. ~~Ecosystem detection: move from tier 1 to a script~~ DONE

**Current behaviour:** SKILL.md Step 1b tells tier 1 to look for indicator
files (`Gemfile`, `package.json`, `pyproject.toml`, etc.) to detect the
ecosystem and check for a corresponding analyzer.

**Problem:** File existence checks are fully deterministic. Tier 1 is
spending tokens on mechanical filesystem inspection.

**Fix:**
- Add an `ecosystem-detect` subcommand to `dep_session.py` (or extend
  `env-check`) that:
  - Checks for indicator files in `--root` directory.
  - Reports detected ecosystems and whether an analyzer exists for each.
  - Warns if an ecosystem is detected but has no analyzer.
- Tier 1 calls `dep_session.py ecosystem-detect --root PROJECT_ROOT`, reads
  the one-line-per-ecosystem output, and reports to the user if action is
  needed (missing analyzer). No filesystem inspection by the AI.
- Update SKILL.md Step 1b accordingly.

---

## 4. ~~Changed-package identification: script parses lockfile diff~~ DONE

**Current behaviour (UPDATE mode):** Tier 1 reads the git diff of lockfiles
(`Gemfile.lock`, `requirements.txt`, etc.) and extracts package names and
old/new versions to pass to `dep_session.py init`.

**Problem:** Parsing a structured lockfile diff is deterministic. Tier 1 is
doing mechanical text extraction that a script can do reliably and without
consuming AI tokens.

**Fix:**
- Add a `diff-packages` subcommand to `dep_session.py`:
  ```
  dep_session.py diff-packages --root PROJECT_ROOT [--since COMMIT]
  ```
  It runs `git diff` on known lockfiles, parses the added/removed version
  lines, and emits the list of changed packages in the exact format needed
  for `dep_session.py init` (i.e. `--update PKG OLD NEW` flags).
- Ecosystem-specific parsers needed for each lockfile format:
  - Ruby: `Gemfile.lock` (indented `    name (version)` lines)
  - Python: `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`
  - JavaScript: `package-lock.json` (JSON diff), `yarn.lock`, `pnpm-lock.yaml`
- Tier 1 calls `diff-packages`, gets back the `--update` flags, passes them
  directly to `dep_session.py init`. No diff reading by the AI.
- Update SKILL.md Path A (UPDATE mode) accordingly.

---

## 5. ~~Deeper analysis trigger: script decides for CONCERN_LEVEL HIGH~~ DONE

**Current behaviour:** Brief Step 5b tells tier 2 to read the `CONCERN_SUMMARY`
block in `signals.txt` and decide whether to run `--deeper`, with the note
"there is no fixed threshold."

**Problem:** For `CONCERN_LEVEL: HIGH` the answer is always yes. Only
`CONCERN_LEVEL: MEDIUM` genuinely requires judgment (is the mix of concerns
serious enough?). Tier 2 is making a mechanical decision for the HIGH case.

**Fix:**
- `dep_review.py` already writes `CONCERN_LEVEL` to `signals.txt` and
  `concern_level` to `signals.json`. It also writes `session-update.json`.
- Add `concern_level` to `session-update.json`.
- In `dep_session.py`, add a `deeper-needed` subcommand (or extend
  `print_next_action`) that checks `concern_level` from `session-update.json`
  and emits `NEXT_ACTION: RUN_DEEPER` automatically when it is `HIGH`.
- For `MEDIUM`: still require tier 2 judgment (keep current Step 5b but note
  that HIGH is handled automatically).
- Update the brief to reflect that `RUN_DEEPER` may be emitted automatically
  and tier 2 should just follow the NEXT_ACTION in that case.

---

## 6. Assessment template: pre-fill factual fields from `signals.json`

**Current behaviour:** Brief Step 6 tells tier 2 to read
`assets/assessment-template.txt` and fill in every field, then write
`assessment.txt`.

**Problem:** All factual fields (SHA256, license, scan counts, risk flags,
MFA status, CONCERN_LEVEL, source URL, etc.) are already structured data in
`signals.json`. Tier 2 re-derives them by reading narrative files and typing
them into the template. This is mechanical transcription.

**Fix:**
- Add a `pre-fill-assessment` subcommand to `dep_session.py` (or a standalone
  helper script):
  ```
  dep_session.py pre-fill-assessment --root PROJECT_ROOT PKGNAME VERSION
  ```
  It reads `signals.json` from the work dir and writes a partially-filled
  `assessment.txt` using the template, substituting all structured fields.
  Fields requiring narrative judgment are left as `[TODO: ...]` placeholders.
- Tier 2's Step 6 becomes: read the pre-filled `assessment.txt` (already in
  the work dir), fill in the `[TODO]` placeholders with narrative, and save.
- Fields that can be auto-filled: sha256, license_line, adversarial_gate,
  risk_flags, concern_level, scan match counts, source_url, mfa_required,
  scorecard score, best_practices badge, transitive dep counts.
- Fields that still require AI narrative: risk_rationale, recommendation
  rationale, notable findings, mitigations.

---

## 7. Rename `assessment.txt` to `assessment.md`

**Current behaviour:** Tier 2 writes its narrative security report to
`assessment.txt`. Humans review it with `less assessment.txt`.

**Problem:** Plain text cannot use headings, bold, tables, or code blocks.
A security assessment with risk ratings, scan findings, and recommendations
is much easier to review with markdown structure. The `.txt` extension also
signals "raw text" to editors and viewers that could render it better.

**Fix:** This is a mechanical rename touching several files:
- `dep_session.py`: update the `assessment.txt` string in `cmd_complete()`
  (line 764 warning), `_parse_assessment_summary()` (line 1139),
  `_parse_assessment_fields()` (line 1254), `generate_manifest()` (line 1409),
  and the `print_next_action()` ANALYZE block (line 546).
  Note: `_parse_assessment_summary()` and `_parse_assessment_fields()` parse
  specific text patterns from the file; verify the markdown format remains
  compatible with these parsers (or update them).
- `references/package-analysis-brief.md`: update Steps 6 and 7.
- `SKILL.md`: update the `less assessment.txt` instruction and path references.
- `assets/assessment-template.txt`: rename to `assessment-template.md` and
  rewrite using markdown (headings with `##`, bold for labels, fenced code
  for SHA256/scan output, a table for the risk summary).
- `docs/ARCHITECTURE.md`: update references.
- `scripts/tests/test_file_parsing.py`: update fixture path (line 70).
- `scripts/tests/fixtures/assessment.txt`: rename fixture file.

**Cons to be aware of:**
- `less assessment.md` still works but shows raw markdown syntax in terminals
  that do not render it. Users comfortable with markdown will not mind;
  others may prefer `glow assessment.md` or a rendered view.
- The two `dep_session.py` parsers (`_parse_assessment_summary`,
  `_parse_assessment_fields`) extract structured fields by pattern-matching
  headings and key-value lines. The markdown template must preserve those
  patterns, or the parsers must be updated alongside.

---

## AI tier inputs and outputs (reference)

### Tier 1: Overall orchestrator

**Inputs (what it reads):**
- `SKILL.md` -- full instructions, read once at session start
- User messages -- free-form (mode detection, confirmations, questions)
- `dep_session.py env-check` stdout -- tool availability; relayed to user
- `dep_session.py vuln-audit` stdout -- CVE/outdated report (UPDATE/CURRENT)
- `dep_session.py health-scan` stdout -- triage table (CURRENT mode)
- `dep_session.py init` stdout -- first NEXT_ACTION block + session token
- `dep_session.py complete` stdout -- NEXT_ACTION block after each package
- `dep_session.py status` stdout -- optional, for resuming interrupted sessions
- Two lines per tier 2 sub-agent -- `RISK_ASSESSMENT` + `SUMMARY_RECOMMENDATION`

**Outputs (what it produces):**
- User-facing text -- explanations, status updates, confirmation requests
- Tier 2 sub-agent spawns -- short prompt: path to brief + session parameters
- `dep_session.py init` calls -- initialises the BFS session queue
- `dep_session.py complete PKGNAME VERSION RECOMMENDATION RISK` calls -- records verdicts

---

### Tier 2: Per-package sub-agent (one per package, context discarded after)

**Inputs (what it reads):**
- Short spawn prompt from tier 1 -- brief path + session file, project root,
  scripts dir, deeper flag, install-probe flag (6 lines)
- `references/package-analysis-brief.md` -- full instructions, read first
- `signals.txt` -- machine-readable signal table, CONCERN_SUMMARY,
  ADVERSARIAL_GATE; the primary input for the security judgment
- Supporting files read conditionally (per table in brief):
  - `manifest-analysis.txt` -- parsed manifest fields (always)
  - `clone-status.txt`, `source-url.txt` -- source repo link (always)
  - `license.txt` -- license evaluation result (always)
  - `project-health.txt` -- Scorecard, Best Practices, activity (always)
  - `extra-in-package.txt` -- unexpected extra files (if count > 0)
  - `binary-files.txt` -- precompiled executables found (if count > 0)
  - `install-scripts.txt` -- extracted install-time code (if present)
  - `diff-semantic.txt` -- tier 3 diff review verdict (UPDATE mode, always)
  - `new-deps.txt`, `dep-lockfile-check.txt` -- new runtime deps (if any)
  - `dep-registry.txt` -- registry data for deps not in lockfile (if any)
  - `transitive-deps.txt` -- transitive footprint (NEW/CURRENT always)
  - `provenance.txt` -- MFA/signing data (if MFA unknown or concerning)
  - `source-review.txt` -- tier 3 source review verdict (if --deeper ran)
  - `summary-scan-LABEL.txt` -- scan match file paths (if scan had matches)
- `assets/assessment-template.txt` -- report template (Step 6)
- `run-log.txt` -- human-readable dep_review.py log (currently; TODO item 1
  removes this read; the file is retained as a human log only)

**Outputs (what it produces):**
- Runs `dep_review.py` -- all structured output files written to work dir
- Optionally runs `dep_review.py --deeper` -- adds reproducibility outputs
- Optionally runs `dep_review.py --install-probe` -- adds install probe output
- `assessment.txt` -- narrative security report for human review
- Two lines to tier 1 -- `RISK_ASSESSMENT: ...` and `SUMMARY_RECOMMENDATION: ...`

---

### Tier 3: Sandboxed AI (invoked by dep_review.py, not by AI agents)

**Inputs (received via stdin from dep_review.py):**
- System prompt -- adversarial content warning + strict JSON output schema,
  embedded in `dep_review.py`; never comes from the package
- Package content -- raw diff (for diff review) or source file listing with
  scan-match context (for source review); truncated at 500,000 characters;
  this is the only tier that reads attacker-controlled content directly

**Outputs (what it produces):**
- JSON object -- validated by `run_ai_sandbox()` against a strict schema;
  written by dep_review.py to:
  - `diff-semantic.txt` -- diff review verdict (changed files, risk assessment)
  - `source-review.txt` -- source review verdict (deeper mode only)
- On parse failure or schema mismatch: sentinel string written instead
  (`AI_REVIEW_FAILED` or `AI_REVIEW_SKIPPED`), never unvalidated text

---

## Implementation order (suggested)

1. Item 1 (read signals.txt not run-log.txt) -- brief change only, low risk
2. Item 2 (adversarial gate auto-enforce) -- dep_session.py + brief change
3. Item 7 (assessment.txt -> assessment.md) -- mechanical rename, many files
4. Item 3 (ecosystem detection script) -- new dep_session.py subcommand
5. Item 5 (deeper trigger for HIGH) -- dep_session.py + brief change
6. Item 6 (pre-fill assessment) -- new script/subcommand + brief change
7. Item 4 (lockfile diff parsing) -- most complex; ecosystem-specific parsers
