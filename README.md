# secure-dependencies

This is a general-purpose AI skill for evaluating software dependency security.
It is not tied to any specific AI assistant (Claude, Copilot, Gemini, etc.).
Currently it implements Ruby, but we plan to soon expand to many
ecosystems.

Its core principle is **download and inspect before you install**.
Downloading and unpacking a package does not execute its code; installing does.
This skill keeps those steps strictly separate and never runs untrusted code
to examine untrusted code. If it decides to analyze more deeply, it
uses sandboxes to reduce risk.

## What it does

This skill helps with three types of dependency work:

| Mode | When to use |
|---|---|
| **Update** | Updating existing dependencies |
| **New** | When you're considering adding a new dependency |
| **Audit** | Reviewing already-installed dependencies |

In all three modes, the skill guards against:

- **Unintentional vulnerabilities**: insecure code patterns, dangerous
  defaults, known CVEs in installed versions
- **Long-term risk**: abandoned projects, missing or proprietary licenses
  (license health is a leading indicator of security abandonment)
- **Supply chain attacks**: typosquatting, slopsquatting, compromised
  maintainer accounts, malicious package developers
- **Adversarial content**: package files crafted to manipulate AI reviewers

## Requirements

- Python 3.10 or later (standard library only, no extra installation needed)
- Optional tools (detected automatically): `bundler-audit`, `pip-audit`,
  `npm audit`, `scorecard`

Analysis output goes to `temp/dep-review/` inside your project root.
Add `temp/` to your `.gitignore`.

## How it works

The skill runs deterministic Python scripts to gather most data, then uses AI
to analyze the results and investigate further. The scripts handle the
mechanical work (fetching registry metadata, computing SHA256 hashes,
diffing source vs. published package, walking the dependency graph); the
AI handles judgment calls. As a result, it tends to be gentle on
AI token use, even when you have many dependencies.

For each package, the scripts produce:

- SHA256 and file counts from the published package
- Source comparison (what is in the tarball vs. the repository)
- License status
- Project health signals (last release, maintainer count, OpenSSF Scorecard)
- Transitive dependency footprint

A session file tracks the BFS queue across the full dependency graph so the
AI never has to manage that bookkeeping manually.

## Levels of analysis

This skill implements three kinds of analysis: alternatives check,
basic analysis, and deeper analysis.

**Alternatives check** (supported by the
`--alternatives` script option) is used when adding a
new dependency (including when you update a component and that updated
version brings in a new dependency).
It attempts to detect cases where the wrong dependency is used.
If a high-confidence attack signal is found, the skill
stops and does not proceed to basic analysis.
It screens the proposed package name for:

- typosquatting attacks (names that are close to a popular package)
- slopsquatting (names that a language model might hallucinate)
- dependency confusion (a public package that shadows a private one), and
- overlap with the standard library.

**Basic analysis** (`--basic`) is the standard starting point. For each
package it:

- Downloads the published package and computes a SHA256 hash
- Scans for suspicious content: Unicode bidi controls, zero-width characters,
  homoglyph attacks, and prompt-injection text aimed at AI reviewers.
  If it detects attacks on AI reviewers it stops immediately.
- Compares the published package against the source repository (extra files,
  missing files, precompiled binaries)
- Checks the manifest for native extensions, post-install hooks, and
  new executable files
- Queries the registry for license, last-release date, maintainer count,
  and OpenSSF Scorecard score
- Produces a machine-readable concern summary and a risk assessment

**Deeper analysis** (`--deeper`) is run on top of basic when the concern
level warrants it or the human demands it. It adds:

- Reproducible-build verification: rebuilds the package from source and
  compares the result to the published artifact byte-by-byte.
  Ideally they are the same (a "reproducible build"), but in some cases
  the differences may explainable and cause no functional difference
  (a "functionally equivalent build").
- A full file-level source diff to help understand what changed between
  the source repository and the distributed package
- Sandbox detection checks

The AI runs the script that does these analyses, reads the
output of these scripts, and applies judgment.
For example, a large code difference may be a routine refactor
or evidence of a massive code injection.
The AI anlaysis distinguishes these where automated tools cannot.

None of these options perform
a full security review of every line of code. They are
targeted signal-gathering passes designed to surface the most likely risk
indicators quickly, so that the AI and human attention
can focus where it matters most.

## Scripts

Scripts live in `references/scripts/`:

| Script | Purpose |
|---|---|
| `dep_session.py` | Session management: init, status, vuln-audit, health-scan |
| `dep_review.py` | Per-package analysis: download, inspect, diff, health |
| `analysis_shared.py` | Shared utilities used by the above |
| `fetch_json.py` | Registry JSON fetcher with caching |
| `hooks_ruby.py` | Ruby-specific dangerous-pattern detection |

Run the test suite with:

```
make test
```

## Using the skill

This repository is a
[skill](https://docs.github.com/en/copilot/customizing-copilot/copilot-skills)
that can be used by Claude Code, GitHub Copilot, and some other
AI tools.
To use it, add it to your AI assistant's skill configuration and then ask
something like:

- "Update my dependencies"
- "Is it safe to add left-pad?"
- "Audit our dependencies for license problems"
- "Apply the Dependabot alerts"

The skill will ask clarifying questions as needed and keep you informed at
each step before taking action.

## License

MIT. See [LICENSE.md](LICENSE.md).
