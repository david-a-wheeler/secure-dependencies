# TODO: Gaps vs OpenSSF Concise Guide for Evaluating Open Source Software

Source: https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software.html

For each check, the current implementation status is noted.

---

## Initial Assessment

### Consider Necessity
**Status: not implemented.**
The guide recommends evaluating whether a dependency can be avoided using
existing components, since every new dependency increases attack surface.
Possible approach: for the alternatives check, surface whether stdlib or
existing lockfile packages could cover the use case, and emit a note when
the dependency is very small (e.g., single-function packages).

### Verify Authenticity
**Status: partial.**
`check_alternatives` flags suspiciously similar package names (typosquatting).
Missing: no check that the evaluated package is the canonical upstream and
not a personal/attacker-controlled fork. For GitHub-hosted projects, this
could cross-reference the repo URL found in registry metadata against a
list of known foundation-affiliated orgs, or at least flag when the repo
owner differs from the package name.

---

## Maintenance and Sustainability

### Activity Level (commits in last 12 months)
**Status: implemented.**
`count_recent_commits()` runs `git log --since=1.year.ago` on the cloned
repo and surfaces the count. Zero commits in 12 months triggers a health
concern. The scorecard `Maintained` sub-check is also now surfaced
individually via `parse_scorecard_checks()`.

### Communication (recent releases or announcements)
**Status: partial.**
Release recency is checked via `last_release_days`. Missing: no check for
project announcements, mailing lists, or discussion activity that would
indicate the maintainer is reachable.

### Maintainer Diversity (more than one maintainer, ideally from different orgs)
**Status: partial.**
`owner_count == 1` triggers a health concern. The scorecard `Contributors`
sub-check is now surfaced individually. Missing: no check for organizational
diversity among maintainers (two maintainers from the same company is still
a single-point-of-failure).

### Version Stability (version string indicates instability)
**Status: implemented.**
`version_stability == 'pre-release'` is flagged in health concerns when the
version begins with `0` or contains `alpha`/`beta`.

---

## Security Practices

### Security Audits
**Status: not implemented.**
No check for the existence of prior security audits or whether identified
vulnerabilities were fixed. Possible approach: query
https://github.com/ossf/security-reviews for the package name, or surface
a manual prompt to the reviewer.

### Security Documentation (assurance case)
**Status: partial.**
No check for documentation explaining why the software is secure. The
presence of `SECURITY.md` (now checked by `check_security_policy()`) is a
useful proxy but is not the same as a full assurance case.

### Security Response (timely bug/CVE fixes, LTS, backports)
**Status: partial.**
No automated check for how quickly the project fixes security bugs or
whether it offers LTS releases. The scorecard `Vulnerabilities` and
`Maintained` sub-checks are now surfaced individually. Could also check
the GitHub Security Advisories API for the project.

### Vulnerability Status (current version free of known CVEs)
**Status: implemented.**
`lookup_vulnerabilities()` POSTs to `https://api.osv.dev/v1/query` with
the package name, ecosystem, and version. Known CVEs trigger a
`KNOWN_VULNERABILITIES(N)` risk flag and a concern entry pointing to
`vulnerabilities.txt`.

### Testing Practices (CI pipeline, test coverage)
**Status: implemented.**
`parse_scorecard_checks()` reads the already-fetched `raw-scorecard.json`
and surfaces the `CI-Tests` sub-check score individually in the report and
in `project-health.txt`.

### Repository Security (branch protection, etc.)
**Status: implemented.**
The scorecard `Branch-Protection` sub-check is now surfaced individually
via `parse_scorecard_checks()`. Six key sub-checks are reported:
Branch-Protection, CI-Tests, Maintained, Security-Policy, Vulnerabilities,
and Contributors.

---

## Usability and Security

### Interface Design, Interface Stability, Secure Defaults, Security Guidance
**Status: not implemented.**
These are inherently manual checks. A useful addition would be a checklist
prompt in the report reminding the reviewer to consider them, rather than
leaving them entirely invisible.

### Vulnerability Reporting (instructions for reporting vulnerabilities)
**Status: implemented.**
`check_security_policy()` checks for `SECURITY.md`, `.github/SECURITY.md`,
and `docs/SECURITY.md` in the cloned repo. Presence adds a
`SECURITY_POLICY_FOUND` positive flag; absence adds a `no_security_policy`
concern. The scorecard `Security-Policy` sub-check is also now surfaced.

---

## Adoption and Licensing

### Adoption (significant use, download counts)
**Status: partial.**
Registry metadata often includes download counts or dependent-count data.
For RubyGems, `downloads` is fetched. For PyPI, `info.downloads` is
typically `-1` (PyPI deprecated this field); a query to pypistats.org
would be needed for real download counts. Neither is currently reported
prominently in the review output.

### Suitability
**Status: not implemented (inherently manual).**
No automated check is possible. Consider adding a checklist prompt in the
report.

---

## Practical Testing

### Behavior Testing (does it exfiltrate data at runtime?)
**Status: partial.**
The sandbox (`bwrap`/`firejail`/`nsjail`/`docker`) is used for the
reproducible-build check. Missing: no network-egress monitoring during
install or test runs that would catch exfiltration. This would require
sandbox-level network policy enforcement.

### Dependency Impact (unnecessary or dev-only transitive deps in production)
**Status: partial.**
`get_transitive_deps` lists indirect deps and flags those not in the
lockfile. Missing: no classification of whether a transitive dep is
dev-only being pulled into production (e.g., a test framework in `install`
deps instead of `dev` deps).

---

## Code Evaluation

### Code Completeness (TODO density, incomplete software signals)
**Status: implemented.**
`STRUCTURAL_PATTERNS` in `analysis_shared.py` now includes a `todo-fixme`
pattern that flags `#TODO`, `#FIXME`, `#HACK`, and `#XXX` comments in
scanned package source via the existing `blind_scan` machinery.

### Static Analysis (SAST tool results)
**Status: not implemented.**
No static analysis tool (Bandit, Semgrep, etc.) is run against the package
source. Possible approach: run Bandit (Python) or Brakeman (Ruby) inside
the sandbox and include the finding count in the report.

### Test Validation (run the package's own test suite)
**Status: not implemented.**
We do not run the package's test suite. Possible approach: attempt
`python3 -m pytest` / `bundle exec rspec` inside the sandbox and report
pass/fail counts.

### Security Implementations (rigorous input validation, parameterized queries)
**Status: not implemented (inherently requires manual review).**
No automated check. A useful proxy: include parameterized-query and
input-validation patterns in `DANGEROUS_PATTERNS` to flag obvious
anti-patterns (raw string SQL concatenation, `eval` on untrusted input).
Some of these may already be in `ADVERSARIAL_PATTERNS`; a review and gap
analysis of those pattern lists against OWASP Top 10 anti-patterns would
be worthwhile.

### Security Reviews (cross-reference OpenSSF security reviews list)
**Status: not implemented.**
No query to https://github.com/ossf/security-reviews. A simple check:
search that repo for the package name and surface a link if found.
