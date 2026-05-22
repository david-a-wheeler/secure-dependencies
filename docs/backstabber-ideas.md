# Backstabber ideas

This document is the result of a review of [Ohm2020]. Here we review
various indicators we could use to identify potentially-malicious software
so we are much more likely to detect them. We identify specific ways we
could detect them, and how we could modify our code to do so, in a way
that minimizes false+ and minimizes false- while still providing useful
data. We emphasize practical steps. We emphasize what can be done across
all ecosystems, and how we can maximize that commonality, so that when we
add support for new ecosystems we'll already have many defenses built in.

Tool-status codes used below:
- *(1) Implemented* -- in the codebase now.
- *(2) Not applicable* -- not practical or not useful for this tool.
- *(3) Worth implementing* -- not yet done; a reasonable future addition.

## Overall

The "Backstabber's Knife Collection" (Ohm et al., 2020) provides a
systematic analysis of 174 malicious packages across npm, PyPI, and
RubyGems. The paper establishes a taxonomy of attacks based on two primary
dimensions: **Injection Techniques** and **Execution Stages**. A key
takeaway is that most malicious behavior is triggered at installation time
(56%) and often involves data exfiltration or backdoors.

The analysis below is a reasonable starting point but is not a
comprehensive treatment. Many of the proposed techniques are either
already implemented, impractical for a static per-package reviewer, or
high false+ risks. The most actionable items are in section 4.4.

## 1. Injection Techniques (How it gets in)

Attackers use several methods to trick users or systems into including
malicious code:

*   **Typosquatting:** Registering names similar to popular packages
    (e.g., `djanga` instead of `django`).
    *(1) Partially implemented: Levenshtein distance against Node.js
    built-in module names and against the project's existing lockfile deps
    (JS and Ruby). Flags exact matches (dependency confusion) and
    near-matches (distance 1 = concern, distance 2 = note). No external
    Top-N popularity list is used; see 4.1 for why.*

*   **Dependency Confusion:** Exploiting package manager resolution order
    (internal vs. public) to force the download of a malicious public
    package with the same name as a private one.
    *(1) Partially implemented: the EXACT_BUILTIN_MATCH signal (JS/Ruby)
    catches the case where an external package shadows a built-in module,
    which is the most likely dependency-confusion vector in those ecosystems.
    General private-vs-public confusion requires knowing an organisation's
    internal package namespace, which is not available to the tool.*

*   **Account Takeover:** Gaining control of a legitimate maintainer's
    account.
    *(1) Partially implemented: recent maintainer-count changes and
    ownership signals are surfaced via the registry data. The version-age
    flag (version_published_days < 3) is specifically motivated by account-
    takeover attacks, where a brief delay gives the community time to detect
    injected malware.*

*   **Self-Published Malware:** New packages that seem useful but contain
    hidden logic.
    *(1) Implemented: package age, owner count, download count, and
    health signals in PROJECT HEALTH section; DANGEROUS_PATTERNS and
    install-hook checks cover the payload-detection side.*

*   **Bitsquatting (Niche):** Registering names that differ by a single
    bit from popular packages (e.g., `mic2osoft` vs `microsoft`).
    *(2) Not applicable: a per-package deep-dive reviewer is the wrong
    place for this. It requires a registry-wide scanner comparing all
    registered names. The threat is also low-probability in practice.*

## 2. Execution Triggers (When it runs)

Malicious code rarely waits for a specific function call; it prefers early
execution:

*   **Install-Time (56%):** Using hooks like `preinstall`, `postinstall`
    (npm) or `setup.py` (PyPI).
    *(1) Implemented: _INSTALL_CMD_CHECKS (JS) and the install-script
    analysis for Python/Ruby cover this execution stage thoroughly. The
    sandbox (run_sandboxed) also exercises this stage dynamically.*

*   **Import-Time:** Code that runs as a side-effect of `require()` or
    `import`.
    *(1) Implemented: `network-at-load-scope` in DANGEROUS_PATTERNS (JS
    and Python) catches network calls at module scope.*

*   **Conditional Execution (41%):** Evasion techniques that check for CI
    environments, sandboxes, or specific environment variables before
    activating.
    *(1) Partially implemented: the sandbox sets a realistic environment;
    some CI-detection patterns (e.g., `CI` env var checks) are surfaced
    by `credential-env-vars`. A dedicated anti-sandbox-evasion pattern is
    not yet implemented but is a lower priority since the sandbox itself
    can catch actual behavior.*

## 3. Malicious Behaviors (What it does)

Once executed, the payload typically performs one of the following:

*   **Data Exfiltration:** Stealing environment variables, credentials,
    or system files.
    *(1) Implemented: `credential-env-vars`, `HOME_PATHS_RE`, and
    `home-or-shell-write` in DANGEROUS_PATTERNS (all ecosystems) cover
    the source side. `EXFIL_RELAY_DOMAINS_RE` and
    `GITHUB_COMMIT_SEARCH_RE` cover sink detection.*

*   **Persistence/Backdoor:** Establishing reverse shells or adding SSH
    keys.
    *(1) Implemented: `home-or-shell-write` (shell config writes),
    `INSTALL_SHELL_CONFIG_WRITE`, and `INSTALL_DESTRUCTIVE_WIPE` cover
    shell-config writes and destructive wipes. New patterns added (all
    ecosystems, via shared constants in `analysis_shared.py`):
    `reverse-shell` (bash `/dev/tcp/`, `nc -e /bin/`, `socat EXEC:/bin/`);
    `cron-persistence` (`/etc/cron.d/`, `| crontab -`);
    `system-persistence` (`/etc/systemd/system/*.service`, `systemctl
    enable`, `Library/LaunchAgents/`, `Library/LaunchDaemons/`).*

*   **Resource Hijacking:** Cryptojacking or using the host as a botnet
    node.
    *(1) Implemented: `cryptominer` pattern added (all ecosystems) via
    `CRYPTOMINER_RE` in `analysis_shared.py`: flags named miner binaries
    (`xmrig`, `cpuminer`, `ethminer`, `minerd`, `ccminer`, `t-rex`,
    `lolminer`, `nbminer`) and the Stratum mining pool protocol
    (`stratum+tcp://`, `stratum+ssl://`). Both have near-zero false+ in
    npm/PyPI/RubyGems package source.*

## 4. Technical Implementation Details

### 4.1. Typosquatting Detection

**Algorithm:** Hybrid approach using **Sift4** for fast bulk filtering
and **Damerau-Levenshtein** (distance $\le 2$) for final verification.

*   **Reference Dataset Sources:**
    *   **npm:** Use the [npm-rank](https://github.com/LeoDog896/npm-rank)
        or [Socket.dev Popularity List](https://socket.dev/npm/category/popular).
    *   **PyPI:** Query the BigQuery public dataset
        `bigquery-public-data.pypi.file_downloads` (via `pypinfo`).
    *   **Critical Software:** Incorporate the **Linux Foundation Census
        III** (2024) Top 500 lists for npm and non-npm libraries
        (Java/Maven, Go, Python). This includes widely used but
        potentially "stale" or deprecated packages like `minimist` and
        `request`.
    *   *(2) Not applicable: maintaining and shipping an up-to-date
        reference list of tens of thousands of popular packages is an
        infrastructure problem outside this tool's scope. The tool already
        compares against the project's own lockfile deps and against
        language built-ins, which are the highest-value cases. Registry-
        wide Top-N comparison is better done by registry-level tooling
        (e.g., npm audit, Deps.dev) rather than a per-package reviewer.*

*   **Heuristics:**
    *   **Homoglyph:** Identify confusable characters (e.g., `l` vs `I`,
        `o` vs `0`).
        *(2) Not applicable: useful for a registry-level scanner; the
        per-package reviewer only sees the package the user has chosen to
        evaluate. The ADVERSARIAL_PATTERNS `non-ascii-in-identifiers`
        check catches Unicode homoglyphs in the package's own source code,
        which is a different (and more directly dangerous) form.*
    *   **Keyboard Adjacency:** Higher risk score if the substitution is
        an adjacent key on QWERTY.
        *(2) Not applicable: same reason as homoglyph above.*
    *   **Metadata Check:** High risk if `Distance <= 2` AND `Package Age
        < 30 days` AND `Downloads < 100`.
        *(1) Partially implemented: package age is available via
        version_published_days; download counts are reported where
        available from registry metadata. The combined scoring is not
        automated, but the AI reviewer sees all three signals.*

### 4.2. Data Exfiltration Patterns (Regex)

Detecting the *source* of the data:

*   **Environment Dumps:**
    *   Node.js: `process\.env`
    *   Python: `os\.environ`
    *   Ruby: `ENV\.to_h`
    *   *(1) Implemented: `credential-env-vars` in DANGEROUS_PATTERNS
        (all three ecosystems) covers these and additional env-var access
        patterns. `env-enumeration` catches bulk `process.env` harvest
        (Object.keys/values on process.env) in JS.*

*   **Sensitive Files:**
    *   SSH: `~\/\.ssh\/(id_rsa|authorized_keys)`
    *   AWS: `~\/\.aws\/(credentials|config)`
    *   NPM: `~\/\.npmrc` (specifically looking for `_authToken`)
    *   *(1) Implemented: `HOME_PATHS_RE` in `analysis_shared.py` covers
        all of these and more (`~/.gnupg`, `~/.config`, etc.), referenced
        by `home-or-shell-write` in all three ecosystems.*

*   **Specific Secrets:**
    *   Discord Token: `[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9]{27}`
        *(1) Implemented: `discord-token-format` in DANGEROUS_PATTERNS
        (all three ecosystems) using `DISCORD_TOKEN_RE` from
        `analysis_shared.py`. The 24.6.27 base64 format is highly
        specific; a match means either a hardcoded stolen token or code
        that extracts tokens in this format.*
    *   Generic API Key: `(?:key|secret|token|auth|pwd)[a-z0-9_-]{16,}`
        *(2) Not useful: this pattern matches virtually every package that
        handles authentication legitimately. The false+ rate would be
        enormous. Credential keyword patterns in DIFF_PATTERNS (which
        scope to new lines in package updates) are a better-targeted form
        of this idea.*

### 4.3. Network Exfiltration (Sinks)

Identify where the data is going:

*   **Known "Drop" Services:** `requestbin\.net`, `hookbin\.com`,
    `burpcollaborator\.net`, `webhook\.site`.
    *(1) Implemented: `EXFIL_RELAY_DOMAINS_RE` in `analysis_shared.py`
    covers webhook.site, pipedream.net, requestbin, beeceptor.com, ngrok,
    burpcollaborator.net, m-kosche.com. Referenced as `exfil-relay-domain`
    in all three ecosystems' DANGEROUS_PATTERNS. Note: `hookbin.com` is
    not in the list and could be added if it is confirmed still active.*

*   **DNS Tunneling:** `[a-z0-9]{10,}\.attacker-domain\.com`.
    *(2) Not applicable: the attacker domain is unknown in advance. A
    static regex cannot detect arbitrary DNS tunnel subdomains. Dynamic
    detection (sandbox DNS monitoring) would catch this, but that is an
    infrastructure concern beyond the current sandbox.*

*   **Suspicious TLDs:** High-volume connections during install-time to
    `.xyz`, `.top`, `.pw`.
    *(2) Not applicable: (a) requires real-time network monitoring during
    install, not static analysis; (b) many legitimate services use these
    TLDs; (c) the sandbox already captures actual outbound connections.
    Adding a static regex for all `.xyz` domains would generate enormous
    false+.*

### 4.4. Obfuscation Detection

**Algorithm:** Shannon Entropy calculation vs. Line length analysis.

*   **Entropy Threshold:** Flag files with entropy $> 5.8$ bits/byte
    (indicative of packed/encrypted data).
    *(2) Not practical with the current grep-based scanning approach.
    Per-file entropy requires reading and computing over the whole file,
    not pattern matching. Would be a substantial standalone addition with
    uncertain benefit since the most dangerous obfuscation (base64+eval)
    is already caught by `obfuscated-exec`. Lower priority.*

*   **Structure Heuristics:**
    *   **Long Lines:** Single lines $> 1000$ characters without common
        minification patterns (like `webpack` headers).
        *(1) Implemented: `long-line-obfuscation` in DANGEROUS_PATTERNS
        (all three ecosystems) using `LONG_LINE_RE` (`[^\n]{5000,}`) from
        `analysis_shared.py`. Threshold of 5000 chars keeps false+ low
        for normal source; matches in minified dist/ files are expected
        and the file path in grep output lets the AI distinguish build
        output from source or install scripts.*
    *   **Hex/Base64 Blobs:** Large strings matching `[a-fA-F0-9]{100,}`
        or `(?:[A-Za-z0-9+\/]{4}){25,}`.
        *(1) Partially implemented: `obfuscated-exec` catches the
        dangerous form (base64-decode-then-eval or hex-decode-then-eval).
        Raw blobs without a paired eval are not currently flagged. Adding
        a standalone `hex-blob` or `base64-blob` pattern risks false+ on
        packages that legitimately embed binary assets or test fixtures as
        hex/base64 strings.*
    *   **String Splitting:** Detecting
        `('p' + 'r' + 'o' + 'c' + 'e' + 's' + 's' + '.' + 'e' + 'n' + 'v')`.
        *(1) Implemented: `string-split-obfuscation` in DANGEROUS_PATTERNS
        (all three ecosystems) using `STRING_SPLIT_RE` from
        `analysis_shared.py`. Matches 5+ adjacent single-char string
        literals joined by `+`; 5-char minimum keeps false+ low while
        catching keyword assembly. No eval/exec co-occurrence required
        since the concatenation pattern alone is already unusual.*

## 5. Practical Steps for Our Code

1.  **Phase 1: Metadata Audit.** Implement the Top-N comparison and
    package age check. Seed the reference list with **Census III** data
    to ensure coverage of critical-but-boring dependencies.
    *(1) Partially implemented: version_published_days covers package age;
    download and owner counts are reported from registry metadata. Top-N
    reference list comparison is not implemented; see 4.1 for why it is
    not practical in this tool.*

2.  **Phase 2: Install-Script Sandbox.** Run `npm install` in an
    instrumented container to catch real-time network calls to the "Drop
    Services" identified in 4.3.
    *(1) Implemented: `run_sandboxed()` in `analysis_shared.py` uses
    bwrap/firejail/docker/podman. Kernel-level Landlock hardening is
    the remaining TODO (see `docs/github-vs-idea.md`).*

3.  **Phase 3: Static Analysis (AST).** Move beyond regex to AST-based
    detection of "Suspicious Pairs" (e.g., code that reads an environment
    variable and then calls an HTTP client within the same function).
    *(2) Not practical: AST parsing requires language-specific parsers
    for all three ecosystems, and keeping them current is a significant
    maintenance burden. The regex approach with bounded quantifiers already
    catches co-occurrence on the same line and within bounded windows.
    AI review of flagged files provides the semantic pairing that AST
    would otherwise give.*

4.  **Phase 4: Baselines.** For the Top-N packages, baseline their
    legitimate network destinations to detect "Account Takeover" updates
    that introduce new C2 domains.
    *(2) Not in scope: requires maintaining a per-package behavioral
    baseline database updated on every new version. This is a registry-
    level or CI-integration concern, not a per-package static reviewer.*

## Summary: What was added from this document

All three items have been implemented:

1.  **`long-line-obfuscation`** -- *(1) Implemented* in DANGEROUS_PATTERNS
    (all ecosystems) via `LONG_LINE_RE` (`[^\n]{5000,}`). Threshold of
    5000 chars; matches in minified dist/ are expected and noted as such.

2.  **`string-split-obfuscation`** -- *(1) Implemented* in
    DANGEROUS_PATTERNS (all ecosystems) via `STRING_SPLIT_RE`. Matches
    5+ adjacent single-char string literals joined by `+`.

3.  **`discord-token-format`** -- *(1) Implemented* in DANGEROUS_PATTERNS
    (all ecosystems) via `DISCORD_TOKEN_RE` (`[a-zA-Z0-9]{24}.[a-zA-Z0-9]{6}.[a-zA-Z0-9]{27}`).

## Bibliography

[Ohm2020] [Ohm et al, 2020, "Backstabber's Knife Collection: A Review
of Open Source Software Supply Chain Attacks"](https://arxiv.org/abs/2005.09535)

[Census III] [Linux Foundation, 2024, "Census III of Free and Open
Source Software - Application Libraries"](https://www.linuxfoundation.org/resources/publications/census-iii-of-free-and-open-source-software-application-libraries)
