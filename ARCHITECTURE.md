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
instructions) interacts with theh scripts to manage the session queue,
decides which packages to evaluate,
and synthesizes final recommendations. It reads only:

- The session queue file and status metadata
- Per-package assessment summaries produced by tier 2 (below)
- The final session report

It never reads raw package source, diffs, filenames from the package, or any
other file that could contain attacker-controlled text. Its context persists
across the whole session, so it is the most valuable to protect.

### Tier 2: Per-package agent

For each package, a fresh sub-agent is spawned (its context is discarded
after the package is done, which limits cross-package contamination). This
agent manages the evaluation of one package by:

- Invoking deterministic scripts and reading their clean, structured outputs
- Invoking tier 3 AI for any content that is or might be attacker-controlled
- Writing the package assessment

Tier 2 reads structured text files such as `signals.txt`, `metadata.txt`,
`assessment.txt`, `diff-semantic.txt`, and `source-review.txt`. These files
are either produced by deterministic scripts (which do their own sanitization)
or are JSON summaries produced by a tier 3 agent and validated against a
schema.

Tier 2 is **prohibited** from reading `raw-*` files (raw package content),
`diff-filenames.txt`, `source-deep-diff.txt`, or any file that contains
unfiltered package data. The SKILL.md instructions enforce this explicitly
(which should be adequate since it never directly sees data to tell it
otherwise).

### Tier 3: Sandboxed AI (reads adversarial content)

Tier 3 AI agents are invoked as sandboxed subprocesses
by the deterministic Python scripts,
not directly by AI agents.
They are the only tier that directly reads attacker-controlled
content such as source diffs and file listings. They:

- Receive content via stdin (never via file system access)
- Are given a fixed system prompt warning them about adversarial content
- Return only a JSON object validated against a strict schema
- Run with `--allowedTools ''` to prevent any tool use
- Have no network access (the invoking script controls the subprocess
  environment)

The schema validation in `run_ai_sandbox()` (`analysis_shared.py`) rejects
any response that does not match the expected structure: correct field names,
correct value types, non-empty strings for string fields, and enum values
drawn from a fixed allowed set. A failure or schema mismatch produces a
sentinel value (e.g., `DIFF_REVIEW_FAILED`) that tier 2 can see and report,
rather than passing through unvalidated text.

Content piped to tier 3 is truncated at 500,000 characters before being sent,
to prevent resource exhaustion from an unusually large file.
This does mean that in some cases the AI won't see everything, but
at that point the AI would be less effective anyway.

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
prompt-injection patterns: text that explicitly tries to override AI
instructions, impersonate the `NEXT_ACTION` system, or manipulate the AI into
approving the package. If a high-confidence injection pattern is detected,
the script writes `ADVERSARIAL_GATE: ABORT` to `signals.txt`, which causes
the tier 2 agent to stop the analysis and escalate immediately without
reading further content.

This gate fires *before* tier 3 is invoked: a package that contains explicit
injection instructions is treated as an attack, not as something to be
analyzed further. These can only detect fairly naive attacks, but
nevertheless they provide some limited protection against naive attacks.

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

## "Download before install" principle

A core workflow constraint: the package is always downloaded and analyzed
*before* any install is considered. The hash of the downloaded package is
recorded in the session data. If a human later decides to install the package,
`dep_session.py` can re-verify the hash against the recorded value to confirm
that the package to be installed is the same one that was analyzed. This
closes the TOCTOU (time-of-check/time-of-use) window where an attacker might
serve a different artifact for download than for install.

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
  homoglyph attacks, and prompt-injection text aimed at AI reviewers.
  If it detects likely attacks on AI reviewers it stops immediately.
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

Scripts live in `references/scripts/`:

| Script | Purpose |
|---|---|
| `dep_session.py` | Session management: init, status, vuln-audit, health-scan |
| `dep_review.py` | Per-package analysis: download, inspect, diff, health |
| `analysis_shared.py` | Shared utilities including tier 3 AI sandbox |
| `fetch_json.py` | Registry JSON fetcher with caching |
| `hooks_ruby.py` | Ruby-specific ecosystem hooks (RubyGems) |
| `hooks_python.py` | Python-specific ecosystem hooks (PyPI) |

Run the test suite with:

```
make test
```

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
