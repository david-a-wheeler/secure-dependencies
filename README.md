# secure-dependencies

This is a general-purpose AI skill for evaluating software dependency security,
building on guidance such as the
[OpenSSF Concise Guide for Evaluating Open Source Software](https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software.html).
Its purpose is to provide some reasonable level of due diligence when
adding dependencies, updating dependencies, or examining current dependencies.
This skill is not tied to any specific AI assistant
(such as Claude Code, GitHub Copilot, etc.).

This skill can support *any* ecosystem.
That's because if the human permits it, the AI agent using this skill can
generate support for whatever ecosystem you need.
The agent will simply use the existing ecosystem support code as a template
and hook in the many data sources that are ecosystem-independent.
That said, you'll need to give the AI agent some time to generate support
for an ecosystem we don't directly support yet.
Currently this skill includes direct support for Ruby, Python, and JavaScript.

Its core principle is **download and inspect before you install**.
Downloading and unpacking a package does not execute its code; installing does.
This skill keeps those steps strictly separate and never runs untrusted code
to examine untrusted code. If it decides to analyze more deeply, or do
a test installation, it uses sandboxes to reduce risk.

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

This skill uses *deterministic scripts* to do mechanical work (such as
gather bulk data and registry metadata,
derive important *signals* from that data, and track progress).
We then use AI agents to do what deterministic scripts can't do well (such as
analyze the initial signals for patterns and investigate further) to
develop a final *assessment*.
This approach (deterministic scripts to acquire data and signals along
with AI to analyze them) has many advantages:

- It's gentle on AI token use (AI is only used where needed)
- Faster (bulk data is first gathered and analyzed by faster processes)
- More consistent (AI agents always begin with the same data and same
  derived signals, if the situation is the same)
- Improves final results (AI agents get the same full initial set of
  information from the
  deterministic scripts; without this the AI agents might skip steps).

A session file tracks the BFS queue across the full dependency graph so the
AI never has to manage that bookkeeping manually.

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
  or flags when the commit had to be inferred from history (lower confidence)
- For updates: scans the diff for newly introduced dangerous patterns
  (SQL injection, command injection, hardcoded secrets, eval)
- Queries the registry for license, last-release date, maintainer count,
  MFA enforcement status, and OpenSSF Scorecard score
- Surfaces six key OpenSSF Scorecard sub-checks individually (Branch-Protection,
  CI-Tests, Maintained, Security-Policy, Vulnerabilities, Contributors)
  directly from the already-fetched scorecard JSON at no extra network cost
- Checks the OpenSSF Best Practices badge site
  (bestpractices.coreinfrastructure.org):
  projects have self-attested to meeting various security practices,
  especially those that meet at least the `passing` or `baseline-1` criteria.
- Queries the OSV vulnerability database for known CVEs affecting the
  specific version under review; writes `vulnerabilities.txt`
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
- A full file-level source diff to help understand what changed between
  the source repository and the distributed package

**Install probe** (`--install-probe`) goes further still and runs the
package installer inside a sandbox with honeytoken credentials, monitoring
for suspicious activity: unexpected network calls, credential access, and
writes outside expected locations. This is the most invasive level and is
used when the other levels raise serious concerns or when the human
requests it upfront.

### Requesting a deeper level upfront

You can tell the AI which level to use before it starts. The AI sets this
once at the beginning of the session and applies it to every package:

| What to say | What happens |
|---|---|
| (nothing special) | Standard: alternatives check + basic analysis, doing more if indicators suggest it |
| "thorough analysis", "deep analysis", "careful review" | Always runs `--deeper` on every package |
| "install probe", "sandbox analysis", "full analysis" | Runs `--deeper` and `--install-probe` on every package |

If the AI cannot tell which level you want, it will ask one question before
starting.

The AI runs the script that does these analyses, reads the
output of these scripts, and applies judgment.
For example, a large code difference may be a routine refactor
or evidence of a massive code injection.
The AI analysis distinguishes these where automated tools cannot.

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
| `hooks_ruby.py` | Ruby-specific ecosystem hooks (RubyGems) |
| `hooks_python.py` | Python-specific ecosystem hooks (PyPI) |

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

## Current status

This is *not* yet production-ready. We hope you'll work with us to
make it that way.

Most of the code is currently vibe-coded. That's not as bad as you might
think in this case, because most of the code involves "download data from X"
or "do trivial analysis of downloaded data and provide the various summaries
to an AI sub-agent". The point of the deterministic code is to provide
a rich source of data for the AI sub-agent to review
and heuristically summarize. So for a vibe-coding task this is a
relatively easy task. That doesn't mean we can just trust the vibe-coded
code; that's something that needs to be reviewed.

## License

MIT. See [LICENSE.md](LICENSE.md).
