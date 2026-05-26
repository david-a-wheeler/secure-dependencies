# ARCHITECTURE.md

## How it works

This skill uses *deterministic scripts* to do mechanical work (such as
gather bulk data and registry metadata,
derive important *signals* from that data, and track progress).
We then use AI agents to do what deterministic scripts can't do well (such as
analyze the initial signals for patterns and investigate further) to
develop a final *assessment* for each package.
These assessments are then wrapped into a final *report*.

Using deterministic scripts to acquire data and signals, combined
with AI to analyze them and produce an assessment, has many advantages
because it's:

- Gentle on AI token use (AI is only used where it is needed)
- Faster (bulk data is first gathered and analyzed by faster processes)
- More consistent (AI agents always begin with the same data and same
  derived signals, if the situation is the same)
- Improves final results (AI agents get the same full initial set of
  information from the deterministic scripts; without this the
  AI agents might completely skip signal-gathering steps).

A session file tracks the BFS queue across the full dependency graph so the
AI never has to manage that bookkeeping manually.
(AI systems sometimes lazily "skip steps" if there are many steps;
using a deterministic tracker makes it much easier for the AIs to focus.)

## Examine before installing

This skill **downloads and inspects before installing**.
Downloading and unpacking a package does not execute its code; installing does.
This skill keeps those steps strictly separate and never runs untrusted code
to examine untrusted code. If it decides to analyze more deeply, or do
a test installation, it uses sandboxes to reduce risk.
We can't *guarantee* that a malicious package won't slip through, but we
take steps to reduce the risk.

## Three tiers of AI agents

A core design principle is that **no AI agent that can take action should
directly read attacker-controlled content**. To enforce this, the system
uses three strictly separated tiers:

### Tier 1: Overall orchestrator

The overall orchestrator (the agent running the top-level SKILL.md
instructions) manages the session lifecycle, decides which packages to
evaluate, and synthesizes final recommendations. Its context persists
across the whole session, so it is the most valuable to protect.

**Inputs:**
- `SKILL.md` -- full instructions, read once at session start
- User messages -- free-form (mode detection, confirmations, questions)
- `dep_session.py env-check` stdout -- tool availability
- `dep_session.py vuln-audit` stdout -- CVE/outdated report (UPDATE/CURRENT)
- `dep_session.py health-scan` stdout -- triage table (CURRENT mode)
- `dep_session.py init` stdout -- first NEXT_ACTION block + session token
- `dep_session.py complete` stdout -- NEXT_ACTION block after each package
- Two lines per tier 2 sub-agent: `RISK_ASSESSMENT` + `SUMMARY_RECOMMENDATION`

**Outputs:**
- User-facing text -- explanations, status updates, confirmation requests
- Tier 2 sub-agent spawns -- short prompt: path to brief + session parameters
- `dep_session.py init` calls -- initialises the BFS session queue
- `dep_session.py complete` calls -- records verdicts and advances the queue

It never reads raw package source, diffs, filenames, or any file that could
contain attacker-controlled text. It never reads `assessment.txt`.

### Tier 2: Per-package agent

For each package, a fresh sub-agent is spawned (its context is discarded
after the package is done, which limits cross-package contamination). It
invokes deterministic scripts, reads their clean structured outputs, and
writes a human-readable assessment.

**Inputs:**
- Short spawn prompt from tier 1 -- brief path + session parameters (6 lines)
- `references/package-analysis-brief.md` -- full instructions, read first
- `signals.txt` -- machine-readable signal table, CONCERN_SUMMARY,
  ADVERSARIAL_GATE; primary input for the security judgment
- Supporting files read conditionally (per table in the brief):
  - `manifest-analysis.txt`, `clone-status.txt`, `source-url.txt`,
    `license.txt`, `project-health.txt` -- always read
  - `extra-in-package.txt`, `binary-files.txt`, `install-scripts.txt` --
    if those counts are non-zero
  - `diff-semantic.txt` -- tier 3 diff review verdict (UPDATE mode)
  - `new-deps.txt`, `dep-lockfile-check.txt`, `dep-registry.txt`,
    `transitive-deps.txt`, `provenance.txt` -- if relevant signals present
  - `source-review.txt` -- tier 3 source review (if --deeper ran)
  - `summary-scan-LABEL.txt` -- scan match paths (if scan had matches)
- `assets/assessment-template.txt` -- report template

**Outputs:**
- Runs `dep_review.py` (and optionally `--deeper`, `--install-probe`) --
  all structured output files written to the package work directory
- `assessment.txt` -- narrative security report written for human review
- Two lines to tier 1: `RISK_ASSESSMENT: ...` and `SUMMARY_RECOMMENDATION: ...`

Tier 2 is **prohibited** from reading `raw-*` files (raw package content),
`diff-filenames.txt`, or `source-deep-diff.txt`. The SKILL.md instructions
enforce this explicitly.

### Tier 3: Sandboxed AI (reads adversarial content)

Tier 3 AI agents are invoked as sandboxed subprocesses by the deterministic
Python scripts, not directly by AI agents. They are the only tier that
directly reads attacker-controlled content.

**Inputs (via stdin from dep_review.py):**
- System prompt -- adversarial content warning + strict JSON output schema,
  embedded in `dep_review.py`; never comes from the package
- Package content -- raw diff (diff review) or source file listing with
  scan-match context (source review); truncated at 500,000 characters

**Outputs:**
- JSON object validated by `run_ai_sandbox()` against a strict schema,
  written by dep_review.py to `diff-semantic.txt` (diff review) or
  `source-review.txt` (source review)
- On parse failure or schema mismatch: a sentinel string
  (`AI_REVIEW_FAILED` or `AI_REVIEW_SKIPPED`) -- never unvalidated text

Additional constraints:
- Run with `--allowedTools ''` to prevent any tool use
- No network access (the invoking script controls the subprocess environment)

The schema validation in `run_ai_sandbox()` (`analysis_shared.py`) rejects
any response that does not match the expected structure: correct field names,
correct value types, non-empty strings for string fields, and enum values
drawn from a fixed allowed set.

Content piped to tier 3 is truncated at 500,000 characters before being sent,
to prevent resource exhaustion from an unusually large file.

### Tier selection and configuration

The tier 3 AI backend is selected by the `SECURE_DEPS_SANDBOX_AI` environment
variable:

- `claude`: uses the `claude` CLI with `claude -p PROMPT --allowedTools ''`
- `copilot`: uses `gh copilot` (stub; not yet implemented)
- Unset or unknown: tier 3 features are skipped with a SKIPPED sentinel

Run `dep_session.py env-check` to verify which backend is configured and
whether the required CLI tool is available.

## Deterministic sandbox for build scripts

In some cases we want to run deterministic programs that might be
malicious. These are also run in a sandbox.

For example,
when a package includes install-time build scripts (`extconf.rb`, `Makefile`,
Rakefile install tasks, etc.), the scripts must be executed as part of deeper
analysis or the install probe. These are run inside a **deterministic
sandbox** using one of: `bwrap`, `firejail`, `docker`, or `podman` (selected
based on what is available). The sandbox:

- Disables network access (`--unshare-net` for bwrap/firejail)
- Restricts file system access to the package directory
- Runs with a timeout

This is separate from the AI sandbox: the deterministic sandbox is for
*executing deterministic scripts* (like build scripts),
while the AI sandbox is for *AI review of adversarial text*.

## Adversarial content detection and gating

Before any content is processed, the deterministic scripts scan for known
adversarial patterns. If a high-confidence pattern is detected, the script
writes `ADVERSARIAL_GATE: ABORT` to `signals.txt`, which causes the tier 2
agent to stop the analysis and escalate immediately without reading further
content. The gate covers two categories:

- **Prompt-injection text**: text that explicitly tries to override AI
  instructions, impersonate the `NEXT_ACTION` system, or manipulate the AI
  into approving the package.
- **Campaign fingerprints**: zero-false-positive literal strings specific to
  known malware campaigns. Currently includes Mini Shai-Hulud indicators:
  `firedalazer` (C2 dead-drop keyword), `WormyBoi` (exfiltration commit
  prefix), `niagA oG eW ereH` (reversed campaign string), and the hardcoded
  C2 polling URL `api.github.com/search/commits?q=firedalazer`.

This gate fires *before* tier 3 is invoked: a package that contains explicit
injection instructions or a known campaign fingerprint is treated as an
attack, not as something to be analyzed further.

## Mitigations for supply chain attacks like Shai-Halud

The Shai-Halud npm supply-chain worm (late 2025, major waves May 2026)
used several techniques for persistence and
propagation. This skill includes specific deterministic patterns and
heuristics to detect and counter Shai-Halud and similar attacks:

- **Alternative-runtime bootstrapping**: Detects when an install script
  invokes a secondary runtime (like Bun, Deno, or `tsx`) to evade the
  standard environment's security model.
- **Self-propagation patterns**: Flags attempts to run `npm publish`,
  `gem push`, or `twine upload` during installation. This is a clear signal of
  a worm attempting to infect the developer's other packages.
- **IDE and AI-tool configuration poisoning**: Monitors for unauthorized
  writes to sensitive configuration paths like `.vscode/tasks.json`,
  `.idea/`, or `.claude/settings.json`. These are used for persistence
  or to subvert the developer's AI assistant.
- **CLI credential harvesting**: Specifically scans for calls to credential
  management tools (e.g., `gh auth token`, `aws configure get`,
  `gcloud auth print-access-token`) inside install hooks.
- **Exfiltration relay detection**: Maintains a blocklist of known C2
  and exfiltration relay domains (e.g., `webhook.site`, `pipedream.net`,
  `m-kosche.com`) frequently used by attackers.
- **Bulk environment enumeration**: Detects patterns that attempt to
  serialize the entire environment (e.g., `JSON.stringify(process.env)`
  or `json.dumps(os.environ)`), which is a common precursor to
  credential exfiltration.
- **Destructive "dead man's switch" payloads**: Scans for commands that
  wipe the filesystem (e.g., `shred`, `rm -rf ~/`) if the attack is detected
  or its token is revoked.
- **Campaign-specific fingerprints**: Scans for unique literal strings from
  the Mini Shai-Hulud worm (May 2026 GitHub/Nx-Console breach): the C2
  dead-drop keyword `firedalazer`, the exfiltration commit prefix `WormyBoi`,
  the backdoor persistence path `~/.local/share/kitty/cat.py`, and the
  dead-man's-switch script name `gh-token-monitor`. These are zero-false-positive
  abort signals; any match halts the analysis immediately.

These checks are integrated into the basic analysis phase and apply
across all supported ecosystems (JavaScript, Python, and Ruby).

## Output sanitization

The `Printer` class in `analysis_shared.py` wraps all writes to output files
that might contain attacker-controlled text. It strips:

- Unicode bidirectional control characters (used in "Trojan Source" attacks
  to make code appear different from what it does)
- Zero-width and invisible characters
- ANSI terminal escape sequences; note that it strips the *entire*
  sequence, so hidden text in this sequences is completely removed instead
  of being revealed.
- Other non-printable control characters

This happens automatically as part of printing; the code doesn't need to
consistently "remember" to call a sanitizer before printing.
Making sanitization the default is a common practice for reducing security
vulnerabilities (e.g., it's the common countermeasure for XSS attacks).

Tier 2 agents only read files produced through this sanitization layer (or
validated tier 3 JSON). They should never encounter raw terminal output or
unfiltered package content.

## NEXT_ACTION replay prevention

The SKILL.md instructions require the tier 2 sub-agent to end its response
with exactly two lines: `NEXT_ACTION: <action>` and a session-specific secret
token that is generated fresh for each package session. The session token is
included in the SKILL.md prompt provided to the sub-agent. The orchestrator
(tier 1) validates both lines and rejects any response that does not include
the correct token. This prevents a compromised package from injecting a fake
`NEXT_ACTION: APPROVE` that the orchestrator would accept.

## Tier 2 partial exposure to package-derived data

Tier 2 cannot be completely shielded from package-derived content:
it must read `signals.txt` and related structured files to do its job,
and those files include values drawn from the package (name, version,
source URL, pattern-match results, etc.).

Several measures limit the risk from this unavoidable exposure:

- **Character-level sanitization**: all values pass through `Printer`
  before being written to any file tier 2 reads, stripping bidi controls,
  zero-width characters, terminal escape sequences, and other non-printable
  characters used in "Trojan Source" and similar attacks.
- **Structured field labels**: each piece of package-derived data appears
  after an explicit label (`PACKAGE:`, `VERSION:`, `SOURCE_URL:`, etc.),
  providing framing that makes it harder for a field value to be
  mistaken for an instruction.
- **Adversarial gate**: before tier 2 reads anything, the deterministic
  scripts scan for explicit prompt-injection patterns and known campaign
  fingerprints; a match aborts the analysis immediately (see above).
- **No raw content**: tier 2 never reads raw source files, diffs, or file
  listings; only summarized signals and validated tier 3 JSON reach it.

A sufficiently crafted package name or description could still attempt
injection through a structured field. The field-label framing reduces this
risk; the adversarial gate is the primary defense against explicit attempts.

## "Download before install" principle

A core workflow constraint: the package is always downloaded and analyzed
*before* any install is considered. The hash of the downloaded package is
recorded in the session data. If a human later decides to install the package,
`dep_session.py` can re-verify the hash against the recorded value to confirm
that the package to be installed is the same one that was analyzed. This
closes the TOCTOU (time-of-check/time-of-use) window where an attacker might
serve a different artifact for download than for install.

## Security properties of the scripts themselves

The scripts that analyze untrusted packages are themselves attack surfaces.
Several properties are maintained to keep them safe.

### Command injection prevention (CWE-78)

All calls to external tools (pip, npm, gem, git, grep, diff, etc.) pass
arguments as Python lists with `shell=False` (the default for
`subprocess.run` and `subprocess.Popen`). Shell interpolation is never
used.  Untrusted values (package names, versions, file paths) are placed
after an explicit `--` separator so the tool cannot interpret them as
command-line flags.  Package names are validated against a strict character
allowlist regex before reaching any command. These measures together prevent
a malicious package name like `; rm -rf ~` or `--dangerous-flag` from being
interpreted as shell syntax or a flag.

### Archive extraction hardening (CWE-409, CWE-22)

Archives (`.whl`, `.zip`, `.tgz`, `.tar.gz`, `.gem`) are extracted with
explicit resource limits and symlink filtering:

- **Decompression bomb prevention (CWE-409):** `extract_zip_securely()`
  and `tarfile_extractall_safe()` in `analysis_shared.py` stream each file
  entry in 64 KB chunks and accumulate a running byte count.  Extraction is
  aborted with `ArchiveSecurityError` if total uncompressed size exceeds
  1 GB or the file count exceeds 10,000.

- **Path traversal and symlink prevention (CWE-22):** Every entry path is
  validated with `_is_safe_extract_path()` before writing.  Symlink entries
  are skipped entirely at extraction time (no post-extraction race window).
  For tar archives, only `isfile()` members with an empty `linkname` are
  extracted; directories are created on demand.

### Subprocess output limits (CWE-400)

`run_cmd()` uses two background threads to read stdout and stderr
concurrently (preventing pipe deadlocks) and caps each stream at 10 MB.
Output beyond the cap is discarded and a truncation marker is appended.
This prevents a tool that emits gigabytes of output from exhausting memory.

### HTTP fetch limits (CWE-400)

`http_get()` and `http_post()` only accept `https://` URLs (blocking
`file://`, `ext::` shell vectors, and HTTP downgrade) and cap the response
body at 10 MB (`_HTTP_MAX_BYTES`).  This prevents server-side request
forgery (SSRF) against internal hosts and memory exhaustion from infinite
HTTP streams.

### AI output isolation and validation

Tier 3 AI output is parsed through `run_ai_sandbox()`, which:

- Strips optional markdown fences before calling `json.loads()` (a
  misbehaving AI might wrap its JSON in ` ```json ... ``` `).
- Validates the parsed object against a strict schema (correct field names,
  allowed enum values, non-empty strings, typed integers).
- Returns a FAILED sentinel on any parse or validation error; it never
  passes through free-form text to tier 2.

## Levels of analysis

This skill implements several kinds of analysis: alternatives check,
basic analysis, deeper analysis, and install probe.

**Alternatives check** (supported by the
`--alternatives` script option) is used when adding a
new dependency (including when you update a component and that updated
version brings in a new dependency).
It attempts to detect cases where the wrong dependency is used.
If a high-confidence attack signal is found, it
stops and does not proceed to basic analysis.
It screens the proposed package name for:

- typosquatting attacks (names that are close to a popular package)
- slopsquatting (names that a language model might hallucinate)
- dependency confusion (a public package that shadows a private one), and
- overlap with the standard library.

It queries [packages.ecosyste.ms](https://packages.ecosyste.ms) for the
package's reverse-dependency count. Zero dependent repositories is a strong
signal for a squatting package: legitimate packages tend to accumulate
users, while squatting packages often have few.
Attackers can take steps to increase the number of packages that use something,
but repository managers would notice a brazen attempt to create a large
number at once.

**Basic analysis** (`--basic`) is the standard starting point. For each
package it:

- Downloads the published package and computes a SHA-256 hash
- Scans for suspicious content: Unicode bidi controls, zero-width characters,
  homoglyph attacks, prompt-injection text aimed at AI reviewers, and
  campaign-specific fingerprints (Mini Shai-Hulud and similar).
  If any abort-gate pattern is detected, analysis stops immediately.
- Runs language-specific dangerous-pattern detection against the full
  package source: patterns include `eval` variants, shell execution calls,
  obfuscated exec (Base64-decode-then-eval style), `Marshal.load`,
  network calls at load time, credential environment variable access,
  writes to home directories or shell config files, and `at_exit` hooks.
- Checks the manifest for native extensions, post-install hooks, and
  new executable files; when install-time scripts are found
  (`extconf.rb`, `Makefile.in`, Rakefile install tasks), copies them
  sanitized to `install-scripts.txt` and directs the AI to read and
  review them before approving the package
- Clones the source repository and compares it to the published package:
  files present in the tarball but absent from the repo, precompiled
  binaries, and overall source match (exact, close, divergent, or unknown)
- Checks whether the published version corresponds to a tagged commit,
  flags when the commit had to be inferred from history (lower confidence),
  and strongly flags if a package release has no corresponding source change.
- For updates: invokes a tier 3 AI to review the diff for newly introduced
  dangerous patterns and summarizes the result in `diff-semantic.txt`
  (the raw diff is never passed to tier 2)
- Queries the registry for license, last-release date, maintainer count,
  MFA enforcement status, and OpenSSF Scorecard score
- Queries [packages.ecosyste.ms](https://packages.ecosyste.ms) for
  cross-ecosystem signals: how many packages and repositories depend on
  this package (reverse-dependency count), whether it is flagged as a
  widely-critical package, and whether it has been deprecated or archived.
  These signals are particularly useful for spotting typosquatting and
  slopsquatting: a package with zero dependent repositories has no known
  users in the wild, which is a strong red flag for a newly-published name.
- Surfaces six key OpenSSF Scorecard sub-checks individually (Branch-Protection,
  CI-Tests, Maintained, Security-Policy, Vulnerabilities, Contributors)
  directly from the already-fetched scorecard JSON at no extra network cost
- Checks the OpenSSF Best Practices badge site
  (bestpractices.coreinfrastructure.org):
  projects have self-attested to meeting various security practices,
  especially those that meet at least the `passing` or `baseline-1` criteria.
- Queries the OSV vulnerability database for known CVEs affecting the
  specific version under review; writes `vulnerabilities.txt`
- Queries [OSS Rebuild](https://oss-rebuild.dev) to check whether the
  published package artifact can be independently reproduced from source.
  A regression (version fails but older versions passed) is a classic
  supply chain attack pattern and is flagged as a high-priority concern.
  See [docs/oss-rebuild.md](docs/oss-rebuild.md) for details.
- Checks commit activity in the last 12 months (separate from release recency:
  a project may cut no release but still be active, or may have gone silent)
- Checks for a `SECURITY.md` vulnerability disclosure policy in the repo
- Scans source code for `#TODO`/`#FIXME`/`#HACK` comment density as an
  indicator of incomplete or rushed code, alongside the adversarial and
  language-specific dangerous-pattern scans
- Flags new transitive dependencies by download count and age, since very
  new or low-download packages carry higher supply-chain risk
- Produces a machine-readable concern summary and a risk assessment

**Deeper analysis** (`--deeper`) is run on top of basic when the concern
level warrants it, or when the human requests it upfront. It adds:

- Reproducible-build verification: rebuilds the package from source and
  compares the result to the published artifact byte-by-byte.
  Ideally they are the same (a "reproducible build"), but in some cases
  the differences may be explainable and cause no functional difference
  (a "functionally equivalent build"). This counters attacks like
  the xz utils supply chain attack, which intentionally created a release
  that was not built from the repo source code.
- A tier 3 AI source review that examines the package file listing and
  selected source content for structural anomalies, summarized in
  `source-review.txt`

**Install probe** (`--install-probe`) goes further still and runs the
package installer inside a sandbox with honeytoken credentials, monitoring
for suspicious activity: unexpected network calls, credential access, and
writes outside expected locations. This is the most invasive level and is
used when the other levels raise serious concerns or when the human
requests it upfront.

## Session reports

At the end of a session, the tier 1 orchestrator calls `dep_session.py wrap-up`
to generate a session-level Markdown report at
`temp/dep-review/report-YYYY-MM-DD-SEQ.md`.
This is a single report covering *all* packages analyzed in the session.
The sequence number allows multiple wrap-ups per day
(for example, when analysis is done in stages).
The report includes, for each analyzed package:

- The package name, version, and risk level
- Key risk factors extracted from that package's `assessment.txt`
- The concern summary
- Links to the per-package supporting files (`signals.txt`, `assessment.txt`,
  `diff-semantic.txt`, `source-review.txt`, etc.)

The per-package detail files live under `temp/dep-review/<package-version>/`.
The session report provides the human-readable cross-package summary with
pointers into those detail files.

## Scripts

Scripts live in `scripts/`:

| Script | Purpose |
|---|---|
| `dep_session.py` | Session management: init, status, vuln-audit, health-scan |
| `dep_review.py` | Per-package analysis: download, inspect, diff, health |
| `analysis_shared.py` | Shared utilities including tier 3 AI sandbox |
| `fetch_json.py` | Registry JSON fetcher with caching |
| `analyzer_ruby.py` | Ruby-specific ecosystem analyzer (RubyGems) |
| `analyzer_python.py` | Python-specific ecosystem analyzer (PyPI) |
| `analyzer_js.py` | JavaScript-specific ecosystem analyzer (npm) |

Run the test suite with:

```
make test
```

### Key constructs in scripts

**`analysis_shared.py`**: the shared foundation used by all other scripts.

- Classes and dataclasses:
  - `Printer`: write-through printer that auto-sanitizes every line
    through `sanitize()` before writing; used everywhere output might
    contain attacker-controlled text.
  - `ArchiveSecurityError`: raised by the extraction helpers when an
    archive violates security limits (path traversal, decompression
    bomb, etc.).
  - `PackageManifest` (dataclass): typed result from
    `EcosystemAnalyzer.read_manifest()`; holds name, version, license,
    deps, source URL, and other fields with safe defaults.
  - `SignalContext` (dataclass): bundles all inputs to `write_signals()`
    so the call site stays stable as new signals are added.
  - `SignalReport` (dataclass): machine-readable summary written as
    `signals.json` alongside `signals.txt`; mirrors what
    `_parse_signals()` extracts.
  - `EcosystemAnalyzer` (ABC): abstract base class implemented by each
    ecosystem module; defines the full analysis contract (manifest
    reading, lockfile checks, registry queries, typosquat detection,
    reproducible build). Notable members:
    - `LOCKFILE_FORMAT_MAP` (class attribute): maps lockfile filenames
      to format tokens; used by the concrete `_detect_lockfile_format()`
      helper.
    - `REPRO_BUILT_DIR_SUFFIX` (class attribute): names the work
      subdirectory for built artifacts (e.g., `raw-built-whl`).
    - `reproducible_build()` (template method): orchestrates the common
      build/compare skeleton; delegates ecosystem-specific steps to
      `_repro_setup()`, `_repro_run_build()`, `_repro_compare()`.
    - `_lev_check()` / `_check_strip_rules()` (concrete helpers):
      shared typosquat detection logic (Levenshtein near-match and
      prefix/suffix shadow checks).
    - `get_old_license()` / `get_old_dep_lines()` (concrete helpers):
      extract license and dep lines from the old version's manifest
      via the abstract `_read_old_manifest()`.

- Key module-level functions:
  - `sanitize()` / `sanitize_line()`: strip terminal escapes, bidi
    controls, and disallowed Unicode; the foundation of output safety.
  - `run_cmd()`: run a subprocess, return `(rc, stdout, stderr)`,
    never raises; each stream capped at 10 MB.
  - `run_sandboxed()`: run a build command inside bwrap/firejail/
    docker/podman; returns `(rc, combined_output)` or `None` if no
    sandbox is available.
  - `run_ai_sandbox()`: invoke the tier-3 AI subprocess, validate the
    JSON response against a schema, return a parsed dict or a FAILED
    sentinel.
  - `levenshtein()`: edit distance between two strings; used for
    typosquat detection.
  - `extract_zip_securely()` / `tarfile_extractall_safe()`: archive
    extraction with size, file-count, path-traversal, and symlink
    limits.
  - `clone_source_repo()`: shallow-clone the upstream source at the
    version tag into the work directory.
  - `http_get()` / `http_post()`: HTTPS-only fetches capped at 10 MB;
    reject `file://` and other non-HTTPS schemes.
  - `blind_scan()`: run grep on package files, save raw matches (never
    read by AI), write a sanitized count summary.
  - `compare_pkg_vs_source()`: compare the distributed package file
    tree vs the cloned source; finds files present in the tarball but
    absent from the repo.
  - `finish_reproducible_build()` / `compare_repro_sha256()` /
    `classify_repro_diffs()`: helpers used by the `reproducible_build()`
    template method after the build step.

**`analyzer_python.py`**, **`analyzer_ruby.py`**,
**`analyzer_js.py`**: one file per ecosystem; each contains a single
class that implements `EcosystemAnalyzer`:

- `PythonAnalyzer`: PyPI/wheel ecosystem.
- `RubyAnalyzer`: RubyGems/gem ecosystem.
- `JavaScriptAnalyzer`: npm/tarball ecosystem.

Each class defines class-level constants (`ECOSYSTEM`,
`LOCKFILE_FORMAT_MAP`, `REPRO_BUILT_DIR_SUFFIX`, `DANGEROUS_PATTERNS`,
`DIFF_PATTERNS`, `NATIVE_BINARY_SUFFIXES`) and implements:

- `read_manifest()`: parse the ecosystem manifest (METADATA, gemspec,
  package.json) into a `PackageManifest`.
- `fetch_all_registry_data()`: query the ecosystem registry (PyPI,
  RubyGems, npm) for metadata signals.
- `check_lockfile()`: compare new vs. old runtime deps; flag VCS deps
  and deps absent from the lockfile.
- `check_alternatives()`: screen the package name for typosquatting,
  slopsquatting, and dependency confusion.
- `get_transitive_deps()`: look up declared dependencies and
  cross-check against the lockfile.
- `_repro_setup()` / `_repro_run_build()` / `_repro_compare()`: the
  three ecosystem-specific hooks for `reproducible_build()`.
- `_read_old_manifest()` / `_extract_old_dep_lines()`: read the old
  version's manifest for license and dep comparison.

**`dep_review.py`**: orchestrates the full per-package analysis
pipeline; no classes.

- `run_analysis()`: top-level driver: downloads, unpacks, scans,
  diffs, clones, and writes all per-package output files.
- `write_signals()`: writes `signals.txt` (the main structured output
  read by the tier-2 AI) using a `SignalContext`.
- `run_scans()`: runs adversarial, TODO, and dangerous-pattern grep
  scans over the full package source.
- `run_diff_scans()`: runs diff-specific pattern scans on
  `raw-diff-full.txt`.
- `write_dep_files()`: writes `new-deps.txt`, `dep-lockfile-check.txt`,
  `dep-registry.txt`.
- `write_health_file()` / `write_license_file()`: write
  `project-health.txt` and `license.txt`.
- `main()`: CLI entry point; dispatches subcommands (`--basic`,
  `--deeper`, `--alternatives`, `--install-probe`).

**`dep_session.py`**: manages the BFS session queue and all
cross-package state; no classes.

- `cmd_init()`: create a new session file with the initial package
  queue.
- `cmd_complete()`: mark a package done, consume its
  `session-update.json`, advance the queue, and print the next
  `NEXT_ACTION`.
- `cmd_resolve()`: resolve an unknown version for a queued dep, then
  print `NEXT_ACTION`.
- `print_next_action()`: emit the machine-readable `NEXT_ACTION` block
  with the session token (replay-prevention).
- `cmd_report()` / `cmd_wrap_up()`: generate per-package summary cards
  and the final session Markdown report.
- `cmd_vuln_audit()`: run `bundler-audit`, `pip-audit`, or `npm audit`
  and format the output.
- `cmd_health_scan()`: fetch registry health metadata for all installed
  packages and print a triage table.
- `load_session()` / `save_session()`: read and write the JSON session
  file; `load_session` validates the `session_version` field and exits
  on any mismatch.

**`fetch_json.py`**: a small standalone CLI tool for fetching and
caching registry JSON; no classes.

- `fetch_json()`: fetch an HTTPS URL and parse as JSON.
- `get_nested()`: walk a dot-separated key path into a nested
  dict/list; returns `None` if any step is missing.
- `main()`: CLI entry point; caches fetched JSON to a local file for
  reuse across calls.

## Security

We presume that this skill will be run *within* a virtual machine or
container that does *not* have unlimited rights, so even if the AI itself
becomes subverted, any damage will be contained within that environment.

The three-tier AI architecture described above is the primary systemic
defense against prompt injection. Rather than relying on the AI to resist
adversarial text, the architecture structurally prevents tiers 1 and 2 from
reading attacker-controlled content at all. Tier 3, which does read that
content, runs as a sandboxed subprocess with no tools, no network, and no
output path except a narrow validated JSON channel.
Tier 3 *might* output data that subverted tier 1 and 2, but other
countermeasures make this more difficult.

Additional layered defenses:

- **Adversarial gate**: explicit injection patterns halt the analysis before
  any AI tier processes the content
- **Output sanitization**: the `Printer` class strips terminal escapes, bidi
  characters, and control characters from all files that tier 2 reads
- **Schema validation**: tier 3 output is validated field-by-field against
  a strict schema before tier 2 sees it; a malformed response produces a
  failure sentinel, not unvalidated text
- **Context isolation**: each tier 2 sub-agent starts fresh for each package,
  so a successful injection in one package cannot accumulate state across
  packages or persist into the tier 1 context
- **NEXT_ACTION token**: a per-session secret prevents a compromised package
  from injecting a fake approval that the orchestrator would accept
- **Deterministic sandbox**: build scripts run in an isolated environment
  (bwrap, firejail, docker, or podman) with network access disabled
- **Content truncation**: content sent to tier 3 is capped at 500,000
  characters to prevent resource exhaustion

None of these defenses are individually foolproof. A sufficiently sophisticated
attacker might find a way to inject content that survives schema validation, or
to exploit a vulnerability in the AI model itself. The goal is defense in depth:
multiple independent barriers that an attacker must defeat simultaneously.

This skill is *not* intended to do a long deep security analysis of some
particular program. Consult other skills and tools if you want that.

See [SECURITY.md](./SECURITY.md) for how to report vulnerabilities in
this program.
