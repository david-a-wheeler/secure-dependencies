# ARCHITECTURE.md

## How it works

This skill uses *deterministic scripts* to do mechanical work (such as
gather bulk data and registry metadata,
derive important *signals* from that data, and track progress).
We then use AI agents to do what deterministic scripts can't do well (such as
analyze the initial signals for patterns and investigate further) to
develop a final *assessment*.

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

## Three tiers of AI agents

There are 3 tiers of AI agents:

1. Orchestrator. This handles the whole set of packages to be analyzed.
   It never *directly* sees possibly-malicious text from packages.
2. Package. This manages overall package evaluation by invoking
   deterministic scripts (which may be sandboxed, e.g., if they
   build something) and tier 3 agents in sandboxes.
   It never *directly* sees possibly-malicious text from packages.
3. AI agents that directly see potentially-malicious text.
   These examine the text (after warnings about malicious text) and provide
   summaries; they do *not* have network access or general file access.
   Their results are then forcefully sanitized.

It's possible that malicious attackers might trick a tier 3 agent to
re-send data that would subvert tier 2 or even tier 1, but these defensive
measures should make it harder for attacker to subvert them.
We presume the entire system is in a virtual machine or container that
*itself* has limited access, so no matter what the damage would be
contained.

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
- For updates: scans the diff for newly introduced dangerous patterns
  (SQL injection, command injection, hardcoded secrets, eval)
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
- A full file-level source diff to help understand what changed between
  the source repository and the distributed package

**Install probe** (`--install-probe`) goes further still and runs the
package installer inside a sandbox with honeytoken credentials, monitoring
for suspicious activity: unexpected network calls, credential access, and
writes outside expected locations. This is the most invasive level and is
used when the other levels raise serious concerns or when the human
requests it upfront.

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

## Security

We presume that this skill will be run *within* a virtual machine or
container that does *not* have unlimited rights, so even if the AI itself
becomes malicious, any damage will be contained.

This skill uses AI, which sometimes makes mistakes and may follow
malicious instructions if the AI sees them.
To compensate, the AI orchestrator calls on AI sub-agents to evaluate
each package, reducing the blast radius of any mistaks.
The AI sub-agents call on deterministic scripts to gather data, which is
generally sanitized before providing it to the sub-agents.
If the system tries to reproduce a build, it will do that within a sandbox
so the rebuild has limited access.
However, these mechanisms can't be foolproof.
In particular, the AI sub-agent may evaluate code or code differences, and
malicious instruction in that data might fool or manipulate the AI.

In the end, this skill cannot be perfect.
It attempts to do due diligence to estimate the risk
of adding or updating a dependency. Just like a human, it may not notice
a problem, or realize its severity, or consider something excessively
vulnerable or malicious even when it isn't.
Still, because it deterministically collects a lot of information, and then
evaluates that information holistically, it should provide a helpful
defense against unintentional or malicious dependencies.

This skill is *not* intended to do a deep security analysis of some
particular program. Consult other skills and tools if you want that.

See [SECURITY.md](./SECURITY.md) for how to report vulnerabilities in
this program.
