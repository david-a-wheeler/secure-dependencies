# Shai-Halud Detection Ideas

This document analyzes the Shai-Halud npm supply-chain worm and proposes
concrete approaches for improving detection in the secure-dependencies skill.
Each idea is assessed for pros, cons, effectiveness enhancements, and
implementation path in the deterministic scripts.

---

## Attack Summary

Shai-Halud (also tracked as "Mini Shai-Hulud") is a self-propagating npm worm
(late 2025, major waves May 2026). Once it gains a foothold it:

- Runs during install via lifecycle hooks (`preinstall`) using the Bun runtime
- Harvests developer credentials and cloud secrets via TruffleHog and env dumps
- Publishes infected versions of every package the victim maintains
- Establishes persistence in `.vscode/tasks.json` and `.claude/settings.json`
- Uses `webhook.site` and `t.m-kosche.com` for C2 and exfiltration
- Forges SLSA provenance by stealing OIDC tokens from GitHub Actions runners
- Leaves Dune-universe-themed repositories on GitHub and drops a
  "dead man's switch" that wipes files if its token is revoked

The IoCs fall into five categories: file/code artifacts, persistence
mechanisms, behavioral signals, network infrastructure, and repository markers.

The worm has also bridged into PyPI, so detection ideas marked with
[JS only] apply to `hooks_js.py` only; others should be added to
`hooks_python.py` and `hooks_ruby.py` as well.

---

## Implementation Status

### Done

**Group A (Ideas 1-6):** All install-script command scanning implemented in
`hooks_js.py` via `_INSTALL_CMD_CHECKS`. Several ideas were extended beyond
the original spec during implementation:

- Idea 1: Split into `INSTALL_BOOTSTRAP_RUNTIME` (bun/deno/pkgx/bunx, high
  confidence) and `INSTALL_TSRUNNER_IN_HOOK` (ts-node/tsx, lower urgency) to
  reduce false positives on TypeScript build scripts. Added `bunx`, `.cjs`.
- Idea 2: `INSTALL_SELF_PUBLISH` implemented. Also extended cross-ecosystem:
  `self-publish` added to Python (`twine upload`, `poetry publish`, `flit
  publish`, `hatch publish`) and Ruby (`gem push`) `DANGEROUS_PATTERNS`.
- Idea 3: `INSTALL_IDE_CONFIG_WRITE` in `_INSTALL_CMD_CHECKS`. Also added
  `ide-config-write` to all three ecosystems' `DANGEROUS_PATTERNS` via the
  shared `IDE_CONFIG_PATHS_RE` constant (see architecture note below).
- Idea 4: `INSTALL_CREDENTIAL_CLI` extended with `gh auth status`,
  `cat ~/.npmrc`, `cat ~/.netrc` beyond the original spec.
- Idea 5: `INSTALL_DESTRUCTIVE_WIPE` extended to catch `$HOME`/`${HOME}`
  variants. Home-dir write detection also added to JS `DANGEROUS_PATTERNS`
  via shared `HOME_PATHS_RE`; Python/Ruby already had `home-or-shell-write`.
- Idea 6: `INSTALL_CLOUD_SECRET_API` extended with AWS SSM Parameter Store
  and Azure Key Vault. Also added as `cloud-secret-api` to all three
  ecosystems' `DANGEROUS_PATTERNS` (see Idea 8 below).

**Idea 8 (Group B):** `cloud-secret-api` added to `DANGEROUS_PATTERNS` in all
three ecosystems (JS, Python, Ruby) using the shared `CLOUD_SECRET_HOSTS_RE`
constant. Python adds boto3 SDK patterns; Ruby adds `Aws::SecretsManager`;
JS adds AWS SDK v3 require/constructor patterns.

**Cross-ecosystem shared constants (beyond the ideas document):** Four shared
PCRE fragment constants added to `analysis_shared.py`:
`IDE_CONFIG_PATHS_RE`, `CLOUD_SECRET_HOSTS_RE`, `CRED_KEYWORDS_RE`,
`HOME_PATHS_RE`. All ecosystem hooks compose their `DANGEROUS_PATTERNS`
entries from these constants plus any ecosystem-specific additions. New
threat intelligence added to any constant propagates to all ecosystems
automatically.

### Not yet implemented

- Idea 7: `process.env` enumeration (Group B)
- Idea 9: Exfiltration relay and C2 domains (Group B)
- Ideas 10-11: File-tree scan for binaries and suspicious directories (Group C)
- Ideas 12-13: Git-ref dependency and lockfile foreign URL detection (Group D)
- Ideas 14-16: Publisher velocity, SLSA provenance, repo metadata (Group E)

---

## Gap Analysis: What the Current Skill Already Covers

The current `hooks_js.py` already detects many relevant signals:

- `HAS_PREINSTALL`, `HAS_POSTINSTALL`, `HAS_INSTALL_SCRIPT` with script text
- `credential-env-vars` pattern: `process.env.AWS_*`, `GITHUB_*`, `GH_*`, etc.
- `child-process-exec` pattern: `child_process.exec/spawn`
- `network-at-load-scope` pattern: `require('http').get()`, top-level `fetch()`
- `obfuscated-exec` pattern: Buffer.from(base64).eval()
- SHA256 hash and source repo comparison
- Binary file detection
- Extra files in package not present in source repo
- Maintainer count, package age, OSV vulnerability lookup
- OSS Rebuild reproducibility check

The ideas below address gaps not yet covered.

---

## Implementation Architecture Note

`DANGEROUS_PATTERNS` entries are `(label, pattern_string)` 2-tuples passed to
`blind_scan()`, which invokes `grep -rnP`. The pattern is a Perl-compatible
regular expression, not a Python `re` object. Do NOT pass `re.IGNORECASE` as a
third tuple element; use inline `(?i)` in the pattern string for
case-insensitive matching.

In contrast, patterns used in Python-only helpers (like install-script command
scanning in `read_manifest()`) use `re.compile(r'...', re.IGNORECASE)` normally.

**Shared regex fragments:** `analysis_shared.py` defines named string constants
(`IDE_CONFIG_PATHS_RE`, `CLOUD_SECRET_HOSTS_RE`, `CRED_KEYWORDS_RE`,
`HOME_PATHS_RE`) that are shared across ecosystems. When a pattern concept
applies to all ecosystems, add it as a constant there and reference it from each
hook file. Ecosystem-specific alternatives are concatenated with `'|'`:

```python
('cloud-secret-api',
 r'\bAws::SecretsManager::Client\b'          # Ruby SDK
 r'|\bAws::SSM::Client\b'                    # Ruby SDK
 r'|' + shared.CLOUD_SECRET_HOSTS_RE),       # shared provider hostnames
```

---

## Idea Group A: Install-Script Command Scanning

*These ideas all examine the command strings in `package.json`'s `scripts`
field (preinstall/install/postinstall). They share a single implementation
block in `read_manifest()` and should be coded together for efficiency.*

The existing code already extracts those script strings and writes them to
`install-scripts.txt`. What is missing is a deterministic pass that checks the
command strings themselves (not the JS files they invoke) against red-flag
patterns, emitting named signals for each match.

A single helper function in `hooks_js.py`:

```python
_INSTALL_CMD_CHECKS: list[tuple[str, re.Pattern]] = [
    ('INSTALL_BOOTSTRAP_RUNTIME', re.compile(
        r'\b(?:bun|deno|tsx|ts-node|pkgx)\s+(?:run\s+)?[\w./]{1,120}\.(?:js|ts|mjs)\b'
        r'|\bsetup_bun\.js\b|\bbun_environment\.js\b',
        re.IGNORECASE,
    )),
    ('INSTALL_SELF_PUBLISH', re.compile(
        r'\bnpm\s+(?:publish|unpublish|deprecate)\b'
        r'|\b(?:pnpm|yarn)\s+publish\b'
        r'|\bnpm\s+(?:token|adduser|set\s+registry)\b',
        re.IGNORECASE,
    )),
    ('INSTALL_IDE_CONFIG_WRITE', re.compile(
        r'(?:\.vscode|\.idea|\.claude|\.cursor)[/\\](?:tasks|settings|extensions|launch)\.json'
        r'|\.config[/\\](?:claude|copilot|cursor|codeium)[/\\]',
        re.IGNORECASE,
    )),
    ('INSTALL_SHELL_CONFIG_WRITE', re.compile(
        r'(?:~|HOME)[^\n]{0,60}\.(?:bashrc|zshrc|profile|bash_profile)\b',
        re.IGNORECASE,
    )),
    ('INSTALL_DESTRUCTIVE_WIPE', re.compile(
        r'\bdel\s+/[FQS]'
        r'|\brm\s+-[rf]{1,3}\s+[~/]'
        r'|\bshred\s+-[uvzn]{1,6}'
        r'|\bcipher\s+/W:'
        r'|\bdd\s+if=/dev/zero\s+of=',
        re.IGNORECASE,
    )),
    ('INSTALL_CREDENTIAL_CLI', re.compile(
        r'\bgh\s+auth\s+token\b'
        r'|\bgit\s+config\s+--get\b[^\n]{0,80}credential'
        r'|\bnpm\s+token\s+(?:list|create)\b'
        r'|\baws\s+configure\s+(?:get|list)\b'
        r'|\bgcloud\s+auth\s+print-access-token\b'
        r'|\baz\s+account\s+get-access-token\b',
        re.IGNORECASE,
    )),
    ('INSTALL_CLOUD_SECRET_API', re.compile(
        r'secretsmanager\.[a-z0-9-]{1,50}\.amazonaws\.com'
        r'|secretmanager\.googleapis\.com'
        r'|kms\.[a-z0-9-]{1,50}\.amazonaws\.com',
        re.IGNORECASE,
    )),
]
```

Called from `read_manifest()` after extracting each script string:

```python
for sig_name, pat in _INSTALL_CMD_CHECKS:
    if pat.search(preinstall_val) or pat.search(install_val) or pat.search(postinstall_val):
        failures.append(f'INSTALL_CMD:{sig_name}')
        install_hook_context.append(f'CRITICAL: {sig_name} detected in install scripts.')
```

These signals then propagate to `signals.txt` via the existing `failures`
mechanism, making them visible to the tier 2 AI.

### Idea 1: Alternative-Runtime Bootstrap [JS only] -- DONE

**Signal:** `INSTALL_BOOTSTRAP_RUNTIME`

**What it catches:** `preinstall: "bun run index.js"` or `"setup_bun.js"` --
a script that downloads and launches a secondary runtime to evade npm's own
security model. Shai-Halud specifically bootstraps Bun this way.

**Pros:** High precision; very few legitimate packages need to bootstrap a
secondary JS runtime during install.

**Cons:** False positives for packages that use Bun as their build tool
(uncommon for published packages). Attackers can rename the script.

**To make more effective:** The existing `blind_scan` via `DANGEROUS_PATTERNS`
already scans the full package source (including `setup_bun.js` if present),
so the payload itself is caught. This signal catches the launcher reference in
`package.json` -- a different, earlier detection point.

---

### Idea 2: Self-Publishing Pattern [cross-ecosystem] -- DONE

**Signal:** `INSTALL_SELF_PUBLISH`

**What it catches:** `npm publish --force` in install scripts. The worm
propagates by republishing every package the compromised developer maintains.

**Pros:** Near-zero false-positive rate. This is a high-confidence signal even
though "zero false positives" would be an overstatement: rare legitimate cases
exist (monorepo orchestration tools that publish workspace sub-packages, CI
scaffolding tools that emit companion packages). The key point is that the
overlap between "packages a developer would install as a dependency" and
"packages that legitimately run npm publish at install time" is vanishingly
small. Treat as CRITICAL-requiring-human-confirmation rather than auto-reject.

**Cons:** Attackers can obfuscate the command. The `obfuscated-exec`
DANGEROUS_PATTERN already catches base64+eval, so plain-text is the main gap
this fills. Also catches false positives from testing frameworks that mock
`npm publish` calls or packages whose test scripts accidentally leak into
install hooks.

---

### Idea 3: IDE and AI-Tool Config Modification [cross-ecosystem] -- DONE

**Signal:** `INSTALL_IDE_CONFIG_WRITE`

**What it catches:** Install scripts referencing `.vscode/tasks.json`,
`.claude/settings.json`, or other developer-tool config paths -- Shai-Halud's
persistence mechanism.

**Pros:** Legitimate packages almost never write to `.vscode/` or `.claude/`
paths during install.

**Cons:** Scaffolding tools like `create-react-app` legitimately write
`.vscode/` configs. Context (is this a scaffolding tool?) should be noted.

**To make more effective:** Also check the published package file list for
pre-bundled `.vscode/` or `.claude/` directories. A package shipping its own
`.claude/settings.json` is poisoning the developer's AI tool configuration.
This requires no code change since the existing extra-files check already
surfaces unexpected files.

---

### Idea 4: CLI Credential Harvesting [JS only] -- DONE

**Signal:** `INSTALL_CREDENTIAL_CLI`

**What it catches:** Calls to `gh auth token`, `git config --get credential.*`,
`aws configure get`, `gcloud auth print-access-token`, etc. inside install
scripts. Shai-Halud specifically uses `gh auth token` to extract the victim's
GitHub token without reading env vars (bypassing the existing
`credential-env-vars` pattern).

**Important note on `gh` availability:** This detection does NOT require `gh`
to be installed on the reviewer's machine. We are pattern-matching the string
`gh auth token` inside the package's install script code -- we scan what the
malicious package would call, not what we call. The existing `shared.http_get()`
and direct HTTPS calls are sufficient for all registry and GitHub API queries in
this skill; `gh` is not needed anywhere in the scripts.

**Pros:** Catches the credential-CLI harvest class that bypasses env-var checks.
Low false-positive rate.

**Cons:** Requires the command to appear as a string literal or near-literal in
the install script. Dynamic construction (split across variables) evades it.

---

### Idea 5: Destructive Wipe Commands [cross-ecosystem] -- DONE

**Signal:** `INSTALL_DESTRUCTIVE_WIPE`

**What it catches:** `shred -uvz`, `cipher /W:`, `rm -rf ~/`, `del /F /Q /S`
-- the dead-man's-switch payload that Shai-Halud activates when it loses
contact with its C2.

**Pros:** Zero legitimate use for wipe commands inside install scripts. No
false positives for `cipher /W:` or `shred -uvz`.

**Cons:** Splitting the command across variables evades it. The `obfuscated-exec`
pattern catches the base64-encoded variant.

**Cross-ecosystem note:** The Python analog of this (install scripts in `setup.py`
or `pyproject.toml` calling `subprocess.run(['shred', ...])`) should be added to
`hooks_python.py` as a separate Python-syntax pattern check.

---

### Idea 6: Cloud Secret Manager API Calls [cross-ecosystem] -- DONE

**Signal:** `INSTALL_CLOUD_SECRET_API`

**What it catches:** Plaintext references to `secretsmanager.*.amazonaws.com`,
`secretmanager.googleapis.com`, or `kms.*.amazonaws.com` inside install scripts.
Shai-Halud calls the AWS `BatchGetSecretValueCommand` endpoint during install.

**Pros:** These endpoints have no legitimate use in install scripts. Very high
precision.

**Cons:** Obfuscated URLs (split across variables, base64-encoded domain) evade
this. The obfuscated-exec pattern catches many such cases.

**To make more effective:** Also add a DANGEROUS_PATTERN for these endpoints in
the full-source scan (see Idea Group B), since a module may call the API at
runtime rather than install time.

---

## Idea Group B: DANGEROUS_PATTERNS Additions

*These entries go into `hooks_js.py`'s `DANGEROUS_PATTERNS` list and are
applied to all package source files via `blind_scan` (grep PCRE). They share
the existing scan infrastructure with no additional code.*

Reminder: entries must be 2-tuples `(label, pattern_string)`. For
case-insensitive matching, use inline `(?i)`. The pattern is PCRE, not Python
re. Follow AGENTS.md: use bounded quantifiers `{0,N}`, no nested unbounded
quantifiers, no catastrophic backtracking.

### Idea 7: Process.env Enumeration [JS only] -- NOT YET IMPLEMENTED

**Entry:**
```python
('env-enumeration',
 r'(?:JSON\.stringify|Object\.(?:keys|values|entries|assign|fromEntries))'
 r'\s*\(\s*process\.env\s*\)'
 r'|for\s*\(\s*(?:const|let|var)\s+\w{1,40}\s+(?:in|of)\s+process\.env\s*\)'),
```

**What it catches:** `JSON.stringify(process.env)`, `Object.keys(process.env)`,
`for (const k of process.env)` -- the "collect everything" harvest pattern.
This is broader than the existing `credential-env-vars` pattern and catches
attackers who avoid known credential prefixes.

**Pros:** Legitimate packages very rarely enumerate the entire env object.

**Cons:** `dotenv`-style configuration loaders may iterate process.env; tier 3
AI review of match context will distinguish these.

---

### Idea 8: Cloud Secret Manager API in Source [cross-ecosystem] -- DONE

**Entry (JS):**
```python
('cloud-secret-api',
 r'secretsmanager\.[a-z0-9-]{1,50}\.amazonaws\.com'
 r'|secretmanager\.googleapis\.com'
 r'|vault\.[a-z0-9-]{1,50}\.hashicorp\.com'
 r'|kms\.[a-z0-9-]{1,50}\.amazonaws\.com'),
```

**What it catches:** Cloud secret manager endpoints appearing anywhere in
package source, not just in install scripts. A module importing and calling
`BatchGetSecretValueCommand` at runtime is also harvesting credentials.

**Pros:** High precision. These endpoints have very few legitimate uses in
published open-source packages.

**Cross-ecosystem:** Add the same patterns in string-literal form to
`hooks_python.py` and `hooks_ruby.py`.

---

### Idea 9: Exfiltration Relay and C2 Domains [cross-ecosystem] -- NOT YET IMPLEMENTED

**Entry:**
```python
('exfil-relay-domain',
 r'(?i)(?:webhook\.site|pipedream\.net|requestbin\.(?:com|net)'
 r'|beeceptor\.com|ngrok\.(?:io|app)'
 r'|burpcollaborator\.net'
 r'|m-kosche\.com)'),
```

**What it catches:** Known exfiltration relay services and the Shai-Halud
C2 domain embedded as string literals in package source.

**Pros:** Exfiltration relay services (webhook.site, pipedream) have essentially
no legitimate use in published packages. C2 domain match is a near-certain
attack signal.

**Cons:** Static domains go stale as campaigns evolve. A developer testing
their own webhook might reference webhook.site in a shipped test file (rare).

**To make more effective:** The blocklist can be updated as new IoCs emerge
without code changes, just by updating the pattern string. Consider loading
the blocklist from a separate file that non-developers can update without
touching the scripts.

**Note on the previous regex:** The earlier draft used
`r'["\x27`]https?://[^"\'`\s]{0,200}(?:domain)...'` which has a Python
string quoting ambiguity (the backtick `` ` `` inside a raw string after
`\x27` is not a string delimiter but the `\'` creates a literal backslash
in the class). The simpler `(?i)` inline pattern above avoids the issue by
not trying to parse the surrounding quote context.

---

## Idea Group C: Package File-Tree Scan

*Ideas 10 and 11 both walk the unpacked directory. Implement as a single shared
helper `scan_suspicious_paths(unpacked_dir, work, p)` callable from
`download_new()` (after unpacking), which emits all anomalies in one pass.*

### Idea 10: Embedded Security-Tool Binary Detection -- NOT YET IMPLEMENTED

**What it catches:** Shai-Halud drops `.truffler-cache/trufflehog.exe` to
scan the victim's filesystem. Any npm package shipping an embedded copy of
a credential scanner or offensive tool is an unambiguous attack signal.

**Implementation:**

```python
SUSPICIOUS_BINARY_NAMES: frozenset[str] = frozenset({
    'trufflehog', 'trufflehog.exe',
    'gitleaks', 'gitleaks.exe',
    'detect-secrets',
    'mimikatz', 'mimikatz.exe',
    'lazagne', 'lazagne.exe',
    'msfconsole',
})

def _check_magic_bytes(path: Path) -> str:
    """Return 'PE', 'ELF', or '' based on file magic bytes."""
    try:
        header = path.read_bytes()[:4]
        if header[:2] == b'MZ':
            return 'PE'
        if header[:4] == b'\x7fELF':
            return 'ELF'
    except OSError:
        pass
    return ''
```

Walk the unpacked directory; emit `SUSPICIOUS_BINARY: <path>` to `signals.txt`
for filename matches. Also emit `UNEXPECTED_BINARY: <path> (<type>)` for any
PE or ELF binary without a corresponding `binding.gyp` (i.e., not part of a
declared native addon).

**Pros:** Zero false positives for named tools. The magic-byte check catches
renamed binaries.

**Cons:** An attacker can XOR-obfuscate or self-extract the binary to evade the
magic-byte check.

**To make more effective:** Flag _any_ executable binary (PE/ELF/Mach-O) in an
npm package that is not under a platform-specific prebuilds directory and not
accompanied by `binding.gyp`. Even without a filename match, a lone binary is
suspicious.

---

### Idea 11: Suspicious Directory Detection -- NOT YET IMPLEMENTED

**What it catches:** `results/` (Shai-Halud credential staging area),
`.truffler-cache/` (TruffleHog cache), and other directories with no
legitimate role in published packages.

**Implementation:**

```python
SUSPICIOUS_TOP_DIRS: frozenset[str] = frozenset({
    'results', '.truffler-cache', 'loot', 'dump', 'harvest', 'exfil',
})
UNUSUAL_HIDDEN_DIRS: re.Pattern = re.compile(
    r'^\.(?!github|npmignore|gitignore|editorconfig|eslintrc'
    r'|prettierrc|husky|changeset|turbo|nx)[^/]{1,60}$'
)
```

In the single file-tree walk (shared with Idea 10):
- Emit `SUSPICIOUS_DIRECTORY: <name>` for exact matches to `SUSPICIOUS_TOP_DIRS`.
- Emit `UNUSUAL_HIDDEN_DIRECTORY: <name>` for top-level hidden directories
  not in the allowlist (rare in legitimate packages).

**Pros:** Low implementation cost; shares the file walk with Idea 10.

**Cons:** `tmp/` and `cache/` excluded because they have legitimate uses;
focus on names specific to attack staging.

---

## Idea Group D: Dependency Manifest Analysis

*Ideas 12 and 13 both examine dependency specifications. They can share a
helper that iterates the combined `dependencies` + `optionalDependencies` dict.*

### Idea 12: Git-Reference Dependency Detection [JS only] -- NOT YET IMPLEMENTED

**Signal:** `GIT_REF_DEPENDENCY`

**What it catches:** `"G2": "github:antvis/G2#7cb42f57..."` in
`optionalDependencies` -- Shai-Halud's technique for pulling a dependency
directly from a specific commit, bypassing the registry and all registry-level
security controls.

**Implementation:**
```python
_RE_GIT_DEP = re.compile(
    r'^(?:github:|gitlab:|bitbucket:|git\+?(?:https?|ssh)://)',
    re.IGNORECASE,
)
_RE_COMMIT_HASH = re.compile(r'#[0-9a-f]{7,40}$', re.IGNORECASE)
```

In `read_manifest()`, after building `all_runtime`, iterate and check each
dep spec. Emit `GIT_REF_DEPENDENCY: <name>@<spec>` for any match.
Distinguish severity:

- Raw commit hash (`#7cb42f5...`): HIGH (pinned to an unauditable point)
- Named tag (`#v1.2.3`): MEDIUM (unusual but potentially intentional)

**Pros:** Cheap check on already-parsed data. Git-ref deps in production npm
packages are rare and anomalous.

**Cons:** Some legitimate rapid-development packages or monorepos use GitHub
references. Named-tag references are less alarming than raw hashes.

---

### Idea 13: Lockfile Foreign Resolved URL Detection [JS only] -- NOT YET IMPLEMENTED

**Signal:** `LOCKFILE_FOREIGN_RESOLVED`

**What it catches:** A poisoned `package-lock.json` where the `resolved` field
for a dependency points to an attacker-controlled server instead of the
registry. This bypasses `npm install`'s security model at the lockfile level.

**Scope clarification:** This check operates on the _project's_ lockfile
(the file being reviewed, e.g., the user's `package-lock.json`), not on the
lockfile inside the package under analysis. It is most valuable in UPDATE mode
when the lockfile diff is being evaluated.

**Implementation:** In `check_lockfile()` for npm v2/v3 format, parse the
`resolved` fields and check against the trusted registry host (which is already
available as `self.registry_url` or defaults to `registry.npmjs.org`):

```python
_RE_LOCKFILE_RESOLVED = re.compile(r'"resolved"\s*:\s*"(https?://[^"]{1,300})"')

TRUSTED_REGISTRY_HOSTS: frozenset[str] = frozenset({
    'registry.npmjs.org',
    'registry.yarnpkg.com',
})
```

For each resolved URL not starting with a trusted host (or
`self.registry_url`), emit `LOCKFILE_FOREIGN_RESOLVED: <dep> -> <url>`.

**Pros:** Catches attacks where the lockfile (not the manifest) is the injection
point -- an increasingly common vector.

**Cons:** Private registries (Verdaccio, Nexus, Artifactory) will trip this
unless `self.registry_url` is configured. The check needs the user to have
run `dep_session.py init --registry` correctly.

**To make more effective:** Especially valuable when diffing the old vs. new
lockfile: a newly-resolved URL that wasn't present before is much more
suspicious than one that was already there.

---

## Idea Group E: Registry and Provenance API Additions

*These ideas add network calls. All use `shared.http_get()` (pure Python
stdlib, no external tools needed -- no `gh`, no `curl`, no sigstore CLI).*

### Idea 14: Publisher Velocity Anomaly Check [JS only] -- NOT YET IMPLEMENTED

**Signal:** `PUBLISHER_VELOCITY_ANOMALOUS`

**What it catches:** Shai-Halud propagates by publishing infected versions of
every package the compromised developer maintains, often dozens within hours.
A publisher with many recent publishes is a strong account-takeover or worm
indicator.

**Implementation:**
After extracting `_npmUser.name` from the version-specific endpoint, query
the npm search API (no authentication, no `gh` needed):

```
GET https://registry.npmjs.org/-/v1/search?text=maintainer:<username>&size=250
```

The response is JSON: `{ "objects": [{ "package": { "name": "...", "date": "2026-..." } }] }`.
The `date` field gives the last-publish time for each package. Count how many
have a `date` within the last 72 hours. If the count exceeds a threshold (10 is
a reasonable starting point), emit `PUBLISHER_VELOCITY_ANOMALOUS`.

One API call (plus the already-fetched package endpoint) -- no pagination
needed for the detection purpose.

**Pros:** Directly catches the Shai-Halud propagation signature. One extra
network call per package analysis session.

**Cons:** High-volume CI publishers (monorepos like Babel or Jest that release
many scoped packages together) may trip the threshold. Tuning or a
known-high-volume-publisher exemption list may be needed.

**To make more effective:** Combine with account-age check (already available
from the package `time.created` field): a new account publishing many packages
is a stronger signal than an established maintainer's CI pipeline. Flag the
combination as HIGH; either signal alone as MEDIUM.

---

### Idea 15: SLSA Provenance Issuer Validation [JS only] -- NOT YET IMPLEMENTED

**Signal:** `SIGSTORE_REPO_MISMATCH`

**What it catches:** Shai-Halud forges SLSA provenance by stealing OIDC tokens
from GitHub Actions runners. The signatures appear valid (they pass cryptographic
verification) but were produced by a different workflow than the package's own CI.

**Simpler approach (no gh, no sigstore CLI, no Rekor):**
npm publishes provenance attestations via a standard API endpoint:

```
GET https://registry.npmjs.org/-/package/<encoded-name>/provenance
```

This returns JSON containing the `buildConfig.workflowPath` and
`sourceRepositoryURI` fields -- the GitHub repo and workflow that signed the
package. No external tools needed, just `shared.http_get()`.

Compare `sourceRepositoryURI` against the package's declared repository URL
(already available from `_extract_source_url()`). A mismatch means the package
was signed by a different repository's workflow.

```python
prov_url = f'{api_base}/-/package/{encoded_name}/provenance'
prov_data = shared.http_get(prov_url)
if prov_data:
    prov_json = json.loads(prov_data.decode('utf-8', errors='replace'))
    # attestations[0].predicateType and .predicate.buildDefinition.externalParameters
    # contain sourceRepositoryURI
    signer_repo = extract_signer_repo(prov_json)
    if signer_repo and source_url and not urls_match(signer_repo, source_url):
        p(f'SIGSTORE_REPO_MISMATCH: signer={signer_repo} declared={source_url}')
```

**Pros:** Uses the npm registry's own provenance API -- the same source npm's
official tooling uses. No external tools, no Rekor log queries. One additional
HTTP call.

**Cons:** The provenance API may not be available for all packages (only those
published with `--provenance`). A mismatch is a strong signal but not
conclusive: some monorepos legitimately publish from a parent repository's
workflow. Surface the mismatch for AI review rather than hard-failing.

**To make more effective:** Also check `buildConfig.workflowPath`: a signing
workflow named `release.yml` or `publish.yml` is more trustworthy than an
ad-hoc or generic workflow name. Surface this for the AI to assess.

---

## Idea 16: Repo Description and GitHub Metadata Check [cross-ecosystem] -- NOT YET IMPLEMENTED

**Signal:** `REPO_CAMPAIGN_MARKER`

**What it catches:** Shai-Halud writes reversed campaign strings into the
descriptions of compromised GitHub repositories:
`"niagA oG eW ereH :duluH-iahS"`, `"TeamPCP"`, and `"Sha1-Hulud"`.
These appear in the GitHub repo metadata, not in the npm package itself.

**No `gh` needed:** Use the GitHub REST API directly via `shared.http_get()`:

```
GET https://api.github.com/repos/<owner>/<repo>
```

Returns `{ "description": "...", "name": "...", ... }`. No authentication
needed for public repos (unauthenticated rate limit: 60 req/hr, sufficient for
package analysis since the source clone already identifies the repo URL).

```python
CAMPAIGN_STRINGS: frozenset[str] = frozenset({
    'niagA oG eW ereH :duluH-iahS',
    'Sha1-Hulud',
    'TeamPCP',
})

if any(s in repo_description for s in CAMPAIGN_STRINGS):
    p('REPO_CAMPAIGN_MARKER: YES')
```

Also check for a `results/` directory in the repo root via
`GET https://api.github.com/repos/<owner>/<repo>/contents/results` -- a 200
response with JSON content is a strong signal.

**Pros:** Literal campaign strings are zero false-positive. The API call reuses
the already-derived source URL and requires no additional auth.

**Cons:** Attackers clean up these markers once detected. The check is reactive
(only catches known campaigns). The rate limit (60/hr unauthenticated) is a
concern for batch audits; add `If-None-Match` caching with an ETag to avoid
re-fetching unchanged repo metadata.

---

## Prioritization and Grouping

Grouped by the code they touch, so each group is one focused PR:

### Group A: Install-Script Command Scanning -- DONE
Implemented Ideas 1-6 (with improvements) in `hooks_js.py` via
`_INSTALL_CMD_CHECKS`. Self-publish, ide-config-write, and cloud-secret-api
also extended to Python and Ruby `DANGEROUS_PATTERNS`.

### Group B: DANGEROUS_PATTERNS Additions (append to list in hooks_js.py)
Idea 8 (cloud-secret-api) -- DONE, all ecosystems.
Ideas 7 and 9 -- **not yet implemented**.
Idea 7 (env enumeration) and Idea 9 (exfil domains): three new entries, no new
code paths. Estimated effort: 30 minutes.
Priority: **high** -- nearly zero implementation cost.

### Group C: File-Tree Scan (one new helper shared between download_new and scan)
Implements Ideas 10-11: binary magic bytes + suspicious directory names.
Estimated effort: 1-2 hours.
Priority: **high** -- catches the embedded TruffleHog pattern.

### Group D: Dependency Manifest Analysis (extend read_manifest / check_lockfile)
Implements Ideas 12-13. Works on already-parsed data.
Estimated effort: 1-2 hours.
Priority: **medium** -- catches the git-ref dependency technique.

### Group E: Registry API Additions (new HTTP calls in fetch_all_registry_data)
Implements Ideas 14-16. Adds 1-3 network calls per package.
Estimated effort: 2-4 hours.
Priority: **medium** -- adds breadth but requires network round-trips.

---

## General Principles Extracted from Shai-Halud

Several patterns recur across campaigns and are worth encoding as general
principles for all future detection work:

1. **"Bring your own runtime" is always suspicious.** Any install script that
   invokes a secondary JavaScript/WASM runtime (Bun, Deno, tsx) is evading
   npm's own security model. Flag regardless of binary name.

2. **Credential-targeted actions during install are always CRITICAL.** Any
   install script that reads credentials (env vars, CLI tokens, file-based
   secrets) AND makes a network call should be treated as a confirmed attack.

3. **Packages that republish themselves are almost certainly worms.** `npm
   publish` in a postinstall script has near-zero legitimate use cases among
   packages that developers install as dependencies. Treat as CRITICAL-requiring-
   human-confirmation: the AI should flag it prominently and require explicit
   user acknowledgment before proceeding, but should not auto-reject without
   review, since rare legitimate monorepo tools exist.

4. **Lockfiles and provenance can be forged.** SLSA signatures and lockfile
   hashes increase confidence but are not absolute. Check the _issuer_ and
   the _matching repo_, not just presence.

5. **Publisher context matters more than package context alone.** A single
   anomalous package by a long-established maintainer is less alarming than
   the same package appearing as one of dozens published in the same 24-hour
   window.

6. **No external tool dependencies.** Every data-gathering step should be
   implementable with Python stdlib plus `shared.http_get()`. Do not require
   `gh`, `curl`, `sigstore`, or `cosign` to be installed on the reviewer's
   machine; the skill must work in minimal environments.
