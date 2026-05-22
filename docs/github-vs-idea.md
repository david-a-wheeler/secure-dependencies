# Investigation: GitHub Internal Repository Breach via Malicious VS Code Extension

## Overview
On May 18, 2026, GitHub confirmed a significant security breach resulting in the exfiltration of approximately **3,800 internal source code repositories** [Lakshmanan2026, Baran2026]. The attack was executed by a threat group known as **TeamPCP** (tracked as **UNC6780**), who utilized a compromised version of the popular **Nx Console** Visual Studio Code extension to gain initial access to developer workstations [Kurmi2026, ThreatLocker2026].

The attack delivered a sophisticated worm dubbed **"Mini Shai-Hulud,"** which was designed to harvest credentials, establish persistence, and propagate through internal networks and CI/CD pipelines [Lakshmanan2026, McCarthy2026].

## Timeline of the Compromise
- **May 18, 2026:** Attackers used a stolen contributor token and marketplace credentials (`VSCE_PAT`) to publish a malicious version (**v18.95.0**) of the **Nx Console** extension (`nrwl.angular-console`) [Kurmi2026, Baran2026].
- **Exposure Window:** The malicious extension was live on the VS Code Marketplace for approximately **11-18 minutes** before being removed [Kurmi2026, Lakshmanan2026].
- **Execution:** Upon activation, the extension executed an obfuscated JavaScript payload fetched from a "dangling orphan commit" (`558b09d7`) in the official `nrwl/nx` repository [Kurmi2026, Lakshmanan2026].

## Indicators of Compromise (IoCs)

### Malicious Artifacts
- **Extension ID:** `nrwl.angular-console` (Nx Console)
- **Compromised Version:** `18.95.0` [Kurmi2026, Lakshmanan2026, ThreatLocker2026]
- **VSIX Hash (SHA-256):** `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8` [Kurmi2026, Lakshmanan2026]
- **`main.js` Hash (SHA-256):** `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74` [Lakshmanan2026]
- **Payload Source:** Orphan commit `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2` on GitHub [Kurmi2026, Lakshmanan2026].

### Persistence & Filesystem Markers
- **Backdoor Script:** `~/.local/share/kitty/cat.py` (Python-based backdoor) [Kurmi2026, Lakshmanan2026].
- **Persistence Mechanism:** `~/Library/LaunchAgents/com.user.kitty-monitor.plist` (macOS) [Kurmi2026].
- **AI/CLI Hooks:**
    - `.claude/settings.json` (Targeted for secret harvesting) [Kurmi2026, Dixit2026].
    - `.claude/router_runtime.js` [Dixit2026].
- **Hidden Configs:** `~/.config/sysmon`, `~/.config/audiomon` [Levy2026].
- **Staging/State Files:**
    - `/var/tmp/.gh_update_state`
    - `/tmp/kitty-*`
    - Environment variable `__DAEMONIZED=1` [Kurmi2026].

### Network & Exfiltration
- **C2 Subnet:** `83.142.209.0/24` [Cipollone2026].
- **Known C2 Domains:** `git-service[.]com`, `git-tanstack[.]com`, `modesl[.]litellm[.]cloud`, `checkmarx[.]zone` [Lakshmanan2026].
- **C2 Polling Query:** `api.github.com/search/commits?q=firedalazer` [Kurmi2026].
- **Exfiltration Repositories:** Public repositories created on victim accounts named **"A Mini Shai-Hulud has Appeared"** [Plate2025, Machluf2026].
- **Commit Messages:** Patterns including `EveryBoiWeBuildIsAWormyBoi:<base64-token>` [Machluf2026].

## Detection & Prevention Strategies

### 1. Pre-Installation Review & Policies
To detect and prevent malicious content *before* installation:
- **Minimum Age Policy:** Implement a "quarantine" period (e.g., 48-72 hours) for new extension or
  package versions before they are allowed in production environments [Kurmi2026, Lakshmanan2026].
  - *(Tool: (3) worth implementing -- we check `last_release_days` but not the age of a specific
    new version. Add a flag when `ver.published_at` is within the last 72 hours; applies to all
    ecosystems via the registry API.)*
- **Publisher Whitelisting:** Use VS Code's `extensions.allowed` setting to restrict installations
  to verified, corporate-approved publishers [Lakshmanan2026].
  - *(Tool: (2) not applicable -- VS Code policy, not a package registry scanner.)*
- **Disable Auto-Updates:** Set `"extensions.autoUpdate": false` in high-security environments to
  prevent "direct push" attacks from compromised publishers [Kurmi2026, Lakshmanan2026].
  - *(Tool: (2) not applicable -- VS Code policy, not a package registry scanner.)*
- **Pre-Install Sandboxing:** Run new extensions in a sandboxed or containerized environment to
  monitor for unexpected network requests or shell executions.
  - *(Tool: (1) already implemented -- `run_sandboxed()` in `analysis_shared.py` wraps the
    reproducible-build step in bwrap/firejail/docker/podman. Applicable to all ecosystems.)*

### 2. Behavioral Detection (EDR/SIEM)
- **Runtime Monitoring:** Monitor for the **Bun runtime** (`bun`) being executed by IDE processes,
  as the "Mini Shai-Hulud" worm used it to bypass Node.js-based security tools
  [Plate2025, Lakshmanan2026].
  - *(Tool: (1) already implemented for install hooks -- `INSTALL_BOOTSTRAP_RUNTIME` in
    `hooks_js.py:_INSTALL_CMD_CHECKS`. Runtime process monitoring of live IDE processes is an
    EDR feature outside our scope.)*
- **Shell Command Auditing:** Alert on VS Code child processes executing shell commands related to
  "MCP setup tasks" or hidden directory creation [Kurmi2026, Lakshmanan2026].
  - *(Tool: (1) already implemented for install hooks -- `INSTALL_IDE_CONFIG_WRITE` in
    `hooks_js.py:_INSTALL_CMD_CHECKS` catches IDE config writes. Live process auditing is EDR.)*
- **Credential Access:** Monitor for unauthorized access to `~/.aws/credentials`, `~/.ssh/`, or
  CLI tools like `op` (1Password) and `bw` (Bitwarden) [Kurmi2026, Lakshmanan2026].
  - *(Tool: (1) already implemented -- `INSTALL_CREDENTIAL_CLI` (install hooks), `credential-env-vars`
    and `home-or-shell-write` in `DANGEROUS_PATTERNS` (all ecosystems), `HOME_PATHS_RE` covers
    `~/.ssh/` and `~/.aws/` write attempts.)*
- **DNS Tunneling Detection:** Monitor for high volumes of encoded subdomains, which the payload
  used as a redundant exfiltration path [Lakshmanan2026].
  - *(Tool: (2) not applicable -- network-layer EDR/SIEM feature; requires runtime traffic
    analysis. Static package scanning cannot observe DNS query behavior.)*

### 3. Immediate Remediation Warnings
- **Dead-Man's Switch:** The worm includes logic to detect token revocation. If it detects its
  harvested tokens are revoked within 24 hours without the device being isolated, it may attempt
  to execute `rm -rf ~/` [Dixit2026, McCarthy2026].
  - *(Tool: (1) already implemented -- `INSTALL_DESTRUCTIVE_WIPE` in `hooks_js.py:_INSTALL_CMD_CHECKS`
    catches `rm -rf ~/` and similar patterns in install hooks.)*
- **Isolation First:** Always isolate the compromised workstation from the network *before* revoking
  credentials.
  - *(Tool: (2) not applicable -- operational incident-response guidance, not a scanner feature.)*

## Generalized Risk Detection & Resilience Framework

To move beyond reactive IoC-based defense, we must implement generalized detection mechanisms that
focus on **behavioral invariants** and **deception**. These strategies are designed to be
ecosystem-agnostic and difficult for attackers to bypass.

### 1. Behavioral Heuristics (The "Shadow Runtime" Check)
Attackers use alternative runtimes to bypass static analysis or security filters.
-   **Mechanism:** Scan for calls to "Shadow Runtimes" (`bun`, `deno`, `pkgx`, `tsx`, `go`,
    `rustc`) across the entire package.
-   **Contextual Refinement (False Positive Reduction):**
    -   **Manifest Check:** Ignore the signal if the runtime is explicitly declared in the
        project's `engines`, `devDependencies`, or equivalent manifests.
    -   **Path Scoping:** Downgrade the concern if the runtime is found exclusively in `tests/`,
        `examples/`, or `docs/`.
    -   **Direct Bootstrapping:** Raise to **Critical** if the package includes its own binary
        for a runtime (e.g., a `bin/bun` inside an npm package) or downloads one during
        installation.
-   **Why it works:** Legitimate packages rarely bring their own entire runtime binary to "evade"
    the host environment.

> **Tool assessment:** The install-hook check (`INSTALL_BOOTSTRAP_RUNTIME` in
> `hooks_js.py:_INSTALL_CMD_CHECKS`) already covers bun/deno/pkgx in lifecycle scripts.
> **(3) Worth extending** to scan source code files via `DANGEROUS_PATTERNS` in `hooks_js.py`
> (and adding a lower-priority `INSTALL_TSRUNNER_IN_HOOK` already exists for tsx/ts-node).
> The "manifest check" refinement (skip if declared in `engines`/`devDependencies`) would reduce
> false positives but adds complexity -- worth a future iteration. Ruby and Python hooks currently
> have no equivalent; adding it there is lower priority since bun/deno are JS-ecosystem runtimes.

### 2. High-Signal Deception ("Honey-Secrets")
Deception scales better for defenders than attackers.
-   **Mechanism:** Place "Canary Files" in standard sensitive locations (e.g.,
    `~/.aws/credentials_canary`, `~/.npmrc_canary`, `~/.ssh/id_rsa_canary`).
-   **The Trick:** These files contain unique, non-functional tokens. Any `read()` or `open()` call
    by an unauthorized process triggers an immediate alert.
-   **Why it's hard to counter:** Attackers use automated "credential grabbers" that cannot
    distinguish between a real secret and a canary without attempting to use it, which exposes them.

> **Tool assessment:** *(2) Not applicable to our tool* -- this is a host-side defensive measure
> that requires the reviewer's workstation to be configured with canary files. Our scanner analyzes
> packages statically; it cannot observe filesystem access at runtime. Useful organisationally but
> not something we implement in the package analysis tool.

### 3. Repository Integrity: The "Orphan Check"
The Nx Console attack leveraged "orphan commits" to hide malicious payloads within a trusted
repository.
-   **Mechanism:** When a package fetches resources via a Git SHA, verify that the SHA is
    **reachable** from the default branch:
    `git merge-base --is-ancestor <SHA> <default_branch>`.
-   **Why it works:** Most supply chain attacks using "imposter commits" rely on GitHub's internal
    object storage. Verifying reachability ensures the code passed through the project's standard
    PR/Review process.

> **Tool assessment:** The full reachability check is *(2) not practical* in our scanner --
> it requires authenticated GitHub API calls (rate-limited at 60/hr unauthenticated) for every SHA
> found in package code. However, a simplified form is *(3) worth implementing*: scan package
> source for raw `githubusercontent.com` or GitHub blob URLs containing a 40-hex-char commit SHA
> as a path component (e.g., `raw.githubusercontent.com/owner/repo/<sha>/file`). Add as a
> DANGEROUS_PATTERNS entry `github-fetch-by-sha` that flags direct-SHA fetches for AI review.
> This is distinct from checking the package's *own* source tag (which we already do via
> `clone_source_repo`).

### 4. OS-Level "Landlocking" (Enforced Least Privilege)
IDEs often have excessive permissions. We can use OS-native primitives to enforce "Project
Isolation."
-   **Mechanism:** Use **Linux Landlock** or **macOS Sandbox/Seatbelt** to restrict the IDE's
    extension host process to *only* the current project directory.
-   **The Trick:** Explicitly deny access to `~/.ssh`, `~/.aws`, and other configuration folders
    at the kernel level.

> **Tool assessment:** *(1) Partially implemented* -- `run_sandboxed()` in `analysis_shared.py`
> already uses bwrap/firejail/docker/podman to sandbox the reproducible-build step. True Linux
> Landlock syscall-level restrictions are not yet used. *(3) Worth implementing* as a hardening
> step: wrap the install probe using Landlock on Linux, blocking access to `~/.ssh`, `~/.aws`,
> `~/.npmrc`, etc. at the kernel level (harder to bypass than seccomp). Applies to all ecosystems
> run on Linux hosts.

### 5. Network Egress Baselines
Most malware must eventually communicate with a C2 or exfiltrate data.
-   **Mechanism:** Baseline "known good" endpoints for an extension. Flag any connection to a new,
    low-reputation domain or high-entropy subdomains (DNS tunneling).

> **Tool assessment:** *(2) Not applicable* -- requires maintaining an organisational historical
> baseline of "known good" network destinations, which is an EDR/SIEM function. Our scanner
> handles static package analysis; we do flag known C2 domains via `EXFIL_RELAY_DOMAINS_RE` and
> the C2 domain list, but dynamic baselining is out of scope.

### 6. Identity Isolation via Credential Proxying
Stop giving long-lived, high-privilege tokens to local environments.
-   **Mechanism:** Replace local credentials with **Local Proxy Tokens** that require context
    validation (e.g., "is this a standard `npm install`?") before being exchanged for real, scoped
    tokens.

> **Tool assessment:** *(2) Not applicable* -- organisational credential infrastructure change.
> Not a package scanner feature. Good advice for the organisations using our tool.

## Integration with Existing Security Skill

The findings from the GitHub/Nx Console breach provide high-value signals for our deterministic
scripts.

### 1. New Deterministic Signals

| Signal | Logic | Value | AI Interpretation Guidance | Tool Status |
| :--- | :--- | :--- | :--- | :--- |
| **`REPO_ORPHAN_COMMIT`** | Verify SHA reachability from default branch. | **Critical** | **Problem:** Almost always tampering or "imposter commit" injection. **Fine:** Extremely rare non-standard branch/tag flows. | *(2/3) Full reachability via GitHub API is impractical unauthenticated. Worth implementing as a simpler heuristic: flag direct-SHA GitHub raw content URLs in package source (see section 3 above). Add `github-fetch-by-sha` to `DANGEROUS_PATTERNS`.* |
| **`SHADOW_RUNTIME`** | Scan for `bun`, `deno`, `pkgx`, `tsx`, `ts-node` calls. | **High** | **Problem:** Runtime used in `scripts`, `hooks`, or `main` but *not* declared in manifest. **Fine:** Runtime is a declared dependency or used only in `tests/` for benchmarking. | *(1/3) Partially implemented: `INSTALL_BOOTSTRAP_RUNTIME` covers install hooks; `INSTALL_TSRUNNER_IN_HOOK` covers tsx/ts-node. Worth adding to `DANGEROUS_PATTERNS` for source file scans in `hooks_js.py`.* |
| **`IDE_CONFIG_POISONING`** | Flag `.vscode/`, `.idea/`, or `.claude/` content in the package. | **High** | **Problem:** Hidden configs targeting credentials or shell tasks. **Fine:** Standard `.vscode/extensions.json` for recommended plugins. | *(1/3) Partially implemented: `ide-config-write` in `DANGEROUS_PATTERNS` (all ecosystems) catches source code that *writes to* IDE config paths; `INSTALL_IDE_CONFIG_WRITE` catches install-hook writes. Missing: detecting packages that *bundle* `.vscode/`/`.idea/`/`.claude/` directories. Worth adding a file-tree check in `read_manifest()`.* |
| **`C2_DOMAIN_POLLING`** | Add `api.github.com/search/commits` + suspicious query. | **Medium** | **Problem:** Search for specific "dead-drop" triggers like `firedalazer`. **Fine:** Legitimate use of Search API (requires manual inspection of query logic). | *(3) Worth implementing -- add `api\.github\.com/search/commits` to `DANGEROUS_PATTERNS` or `EXFIL_RELAY_DOMAINS_RE` in `analysis_shared.py`. The specific `?q=firedalazer` form belongs in `ADVERSARIAL_PATTERNS` for zero-FP detection.* |

### 2. Sandbox Improvements (Install Probe)

| Improvement | Mechanism | Value | Pros/Cons | Tool Status |
| :--- | :--- | :--- | :--- | :--- |
| **Kernel Landlocking** | Use **Linux Landlock** to restrict `install-probe`. | **High** | **Pros:** Hardest to bypass. **Cons:** Linux-only. | *(3) Worth implementing -- `run_sandboxed()` currently uses bwrap/firejail. Adding Landlock LSM rules to block access to `~/.ssh`, `~/.aws`, etc. would harden the sandbox; Linux-only but that covers most CI environments.* |
| **Canary/Honeytoken Audit** | Alert on access to `~/.aws/credentials_canary`. | **Critical** | **Pros:** Definitive proof of intent. **Cons:** Requires host setup. | *(2) Not applicable -- requires the reviewer's host to be pre-configured with canary files. Cannot be implemented inside the package analysis tool itself.* |

### 4. High-Fidelity Static Indicators (Mini Shai-Hulud Suite)

While behavioral invariants provide long-term protection, we can implement immediate, deterministic
scans for the "fingerprints" of the current Mini Shai-Hulud attack. These indicators are
"essentially no false+" and should be classified as **`ADVERSARIAL_GATE`** (immediate abort) when
found in production code or install hooks.

| Indicator | Type | Logic/Pattern | Why High-Fidelity? | Tool Status |
| :--- | :--- | :--- | :--- | :--- |
| **`firedalazer`** | C2 String | Search for the string `firedalazer` in any JS/Python source. | Unique "dead-drop" keyword for GitHub commit search C2. No known legitimate use. | *(1) IMPLEMENTED: `mini-shai-hulud-firedalazer` in `ADVERSARIAL_PATTERNS` + `ADVERSARIAL_ABORT_LABELS` (`analysis_shared.py`). Triggers gate abort on match.* |
| **`WormyBoi`** | Commit Template | `EveryBoiWeBuildIsAWormyBoi` | Unique exfiltration prefix for stolen tokens. Highly specific. | *(1) IMPLEMENTED: `mini-shai-hulud-wormyboi` in `ADVERSARIAL_PATTERNS` + `ADVERSARIAL_ABORT_LABELS` (`analysis_shared.py`). Triggers gate abort on match.* |
| **`Kitty/cat.py`** | Persistence Path | `~/.local/share/kitty/cat.py` or `.kitty-monitor` | Specific persistence path for the Python backdoor. Legitimate kitty terminal does not use this subpath for Python scripts. | *(1) IMPLEMENTED: `mini-shai-hulud-paths` entry in `DANGEROUS_PATTERNS` for all three ecosystems, referencing `MINI_SHAI_HULUD_PATHS_RE` in `analysis_shared.py`.* |
| **`gh-token-monitor`** | Dead-man's Switch | `gh-token-monitor.sh` or `com.user.gh-token-monitor` | Part of the destructive dead-man's switch. Specifically targets token revocation events. | *(1) IMPLEMENTED: covered by `MINI_SHAI_HULUD_PATHS_RE` and `mini-shai-hulud-paths` in all ecosystem `DANGEROUS_PATTERNS` (`analysis_shared.py`).* |
| **`niagA oG eW ereH`** | Reversed String | `niagA oG eW ereH :duluH-iahS` | Reversed Dune-themed strings to evade simple text filters. | *(1) IMPLEMENTED: `mini-shai-hulud-reversed-string` in `ADVERSARIAL_PATTERNS` + `ADVERSARIAL_ABORT_LABELS` (`analysis_shared.py`). Also already in `CAMPAIGN_STRINGS` for GitHub repo description checks.* |
| **`firedalazer` Query** | Network URL | `api.github.com/search/commits?q=firedalazer` | Hardcoded C2 polling URL. Definitively malicious when found in a package. | *(1) IMPLEMENTED: `mini-shai-hulud-c2-url` in `ADVERSARIAL_PATTERNS` + `ADVERSARIAL_ABORT_LABELS` (`analysis_shared.py`). The `firedalazer` literal also catches abbreviated forms.* |

### 5. Implementation in Deterministic Scans
1.  **`ADVERSARIAL_PATTERNS` Expansion:** Add `firedalazer` and `WormyBoi` to the global
    `shared.ADVERSARIAL_PATTERNS`.
    - *(1) IMPLEMENTED: `mini-shai-hulud-firedalazer`, `mini-shai-hulud-wormyboi`,
      `mini-shai-hulud-reversed-string`, and `mini-shai-hulud-c2-url` added to
      `ADVERSARIAL_PATTERNS` and `ADVERSARIAL_ABORT_LABELS` in `analysis_shared.py`.*
2.  **`DANGEROUS_PATTERNS` Expansion:** Add the "Kitty" and "Token-Monitor" patterns to
    language-specific hooks (`hooks_js.py`, `hooks_python.py`).
    - *(1) IMPLEMENTED: `MINI_SHAI_HULUD_PATHS_RE` constant added to `analysis_shared.py`
      covering `\.local/share/kitty/cat\.py`, `kitty-monitor`, `gh-token-monitor`. Referenced
      as `mini-shai-hulud-paths` in all three ecosystem `DANGEROUS_PATTERNS` lists.*
3.  **AI Signaling:** If these specific patterns match, the deterministic report should explicitly
    label them as "MINI_SHAI_HULUD_FINGERPRINT," allowing the AI to bypass general heuristic
    analysis and jump straight to a CRITICAL/DO_NOT_INSTALL recommendation.
    - *(1) Partially implemented: the four `mini-shai-hulud-*` labels in `ADVERSARIAL_ABORT_LABELS`
      already trigger gate abort, which signals CRITICAL to the AI reviewer. The specific label
      prefix `mini-shai-hulud-` in the report output identifies these as campaign fingerprints.
      A dedicated named constant `MINI_SHAI_HULUD_FINGERPRINT` is not needed; the abort gate
      mechanism already provides the right behavior.*

## Future-Proofing: Detection via Behavioral Invariants

To defend against future, unknown supply chain attacks, we must shift from identifying *malicious
implementations* to identifying **violations of behavioral invariants**. These are "ground truths"
about how benign software must behave, regardless of the language, runtime, or delivery method.

### 1. The Boundary Violations Framework

| Boundary | Invariant (Benign Behavior) | Anomaly (Attack Signal) | Tool Status |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Libraries should never access `~/.ssh`, `~/.aws`, or `.env`. | Any `open()` or `stat()` on sensitive system paths. | *(1) Already implemented: `credential-env-vars` and `home-or-shell-write` in `DANGEROUS_PATTERNS` (all ecosystems); `INSTALL_CREDENTIAL_CLI` in JS install hooks; `HOME_PATHS_RE` covers the path targets.* |
| **Installation vs. Runtime** | Packages should not require outbound network connectivity during the `install` phase. | Network activity during `postinstall`, `setup.py`, or `extconf.rb`. | *(1) Partially implemented: `network-at-load-scope` in `DANGEROUS_PATTERNS` (JS and Python); `INSTALL_BOOTSTRAP_RUNTIME` flags secondary runtime downloads; sandbox blocks outbound calls during reproducible build.* |
| **Execution Transparency** | Software should execute well-defined, named binaries. | Spawning `/bin/sh` to execute an obfuscated or base64-encoded string. | *(1) Partially implemented: `child-process-exec`/`subprocess-shell`/`shell-exec` in `DANGEROUS_PATTERNS`; `obfuscated-exec` catches base64-decode-then-eval patterns.* |
| **Identity Integrity** | A package's runtime behavior should match its declared metadata. | A JS library spawning a `python` or `curl` process to side-load payloads. | *(3) Partially implemented: subprocess patterns catch obvious cases. Worth adding a cross-language spawn pattern to `DANGEROUS_PATTERNS` in `hooks_js.py`: flag `child_process.exec/spawn` calls that invoke `python`, `curl`, `wget`, or `nc` (common second-stage loaders).* |

### 2. Detection of "Integrity Gaps"

An "Integrity Gap" occurs when there is a mismatch between the *claimed* state of a package and
its *actual* content. These are universal red flags:

*   **The "Shadow dependency" Invariant:** Benign packages declare their dependencies in a
    manifest.
    *   *Detection:* Flag any package containing pre-compiled binaries (`.exe`, `.so`, `.wasm`) or
        minified JS that is not represented in the source repository or dependency list.
    *   *(Tool: (1) partially implemented -- `NATIVE_BINARY_SUFFIXES` in all three ecosystem hooks
        flags `.node`/`.so`/`.bundle` native binaries. The "not in source" comparison would require
        cross-referencing the source clone, which is complex; low priority given sandbox already
        catches the runtime behaviour.)*
*   **The "Reactivity" Invariant:** Benign software typically reacts to user input or application
    calls.
    *   *Detection:* Use **Process Lineage Baselining** to flag "unprovoked" activity. If a package
        manager (`npm install`) spawns a child process that begins a network scan or filesystem
        crawl, the lineage is inherently suspicious.
    *   *(Tool: (2) not applicable -- EDR/process-lineage feature requiring runtime OS integration.
        Not feasible as static package analysis; the sandbox provides partial coverage by observing
        install-time network activity.)*

### 3. High-Fidelity "Tricks" for Future Defense

To maintain low false positives while detecting novel attacks:

*   **First-Seen Network Destinations:** Alert only when a development process connects to a
    **destination IP/CIDR never seen before** in the organisation's history.
    *   *(Tool: (2) not applicable -- requires an organisational baseline database. Not feasible
        as a standalone package scanner.)*
*   **Reconnaissance Detection (Stat-without-Open):** Flag processes that `stat` or `list`
    sensitive directories (`~/.ssh`) without actually `open`-ing a file.
    *   *(Tool: (2) not applicable -- EDR filesystem-event-monitoring feature.
        Not feasible via static analysis.)*
*   **JA3/s Fingerprinting:** Monitor the TLS handshake of development tools. A malicious script
    will often have a unique TLS fingerprint (JA3) differing from legitimate tools like `npm` or
    `git`.
    *   *(Tool: (2) not applicable -- EDR TLS-traffic-monitoring feature.
        Not feasible via static analysis.)*

### 4. Implementation Logic for AI Agents

When evaluating *any* signal from an unknown attack, the AI should apply the
**"Principle of Least Justification"**:
1.  **Functional Mapping:** Does this action (e.g., network call, shell spawn) map to the
    package's stated purpose?
2.  **Manifest Correlation:** Is the tool/runtime used declared in the manifest?
3.  **Path Provenance:** Is the behavior occurring in a production file or a test/example file?

By grounding detection in these **Invariants**, we create a defense that remains effective even as
attackers switch from JavaScript to Rust, or from VS Code to new AI-native IDEs.

*(Tool: (1) IMPLEMENTED -- added as Step 5a "Principle of Least Justification" in
`references/package-analysis-brief.md`, between the file-reading table and the existing
Step 5b (deeper-analysis decision). The three questions (Functional Mapping, Manifest
Correlation, Path Provenance) are now explicit instructions the tier-2 agent applies when
evaluating any `DANGEROUS_PATTERNS` scan hit.)*

## Sources

- [Kurmi2026] [Ashish Kurmi, May 18, 2026, "NX CONSOLE VS CODE EXTENSION COMPROMISED",
  StepSecurity](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised)
- [Lakshmanan2026] [Ravie Lakshmanan, May 21, 2026, "GITHUB INTERNAL REPOSITORIES BREACHED VIA
  MALICIOUS NX CONSOLE VS CODE EXTENSION", The Hacker News](https://thehackernews.com/2026/05/github-internal-repositories-breached.html)
- [Brown2026] [Shaun Brown, May 20, 2026, "GITHUB BREACHED VIA A MALICIOUS VS CODE EXTENSION:
  WHY DEVELOPER DEVICES ARE THE REAL TARGET", Aikido](https://www.aikido.dev/blog/github-breached-vs-code-extension)
- [ThreatLocker2026] [ThreatLocker Threat Intelligence, May 21, 2026, "GITHUB CONFIRMS COMPROMISED
  NX CONSOLE EXTENSION WAS INITIAL ACCESS VECTOR",
  ThreatLocker](https://www.threatlocker.com/blog/github-breach-likely-caused-by-nx-console-compromise)
- [Baran2026] [Guru Baran, May 21, 2026, "GITHUB INTERNAL REPOSITORIES BREACHED VIA WEAPONIZED VS
  CODE EXTENSION",
  CybersecurityNews](https://cybersecuritynews.com/github-internal-repositories-breached/)
- [Dixit2026] [Tanmay Dixit, May 2026, "Mini Shai Hulud Worm Infects 170+ npm and PyPI Packages
  in Autonomous Supply Chain Attack",
  Qualysec](https://qualysec.com/mini-shai-hulud-worm-infects-170-npm-and-pypi-packages-in-autonomous-supply-chain-attack/)
- [Levy2026] [Ox Security Research Team, 2026, "THE MOTHER OF ALL AI SUPPLY CHAINS",
  Ox Security](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains/)
- [Cipollone2026] [Francesco Cipollone, May 20, 2026, "TeamPCP Wave Four: GitHub Breach via
  Poisoned VS Code Extension",
  Phoenix Security](https://phoenix.security/blog/teampcp-wave-four-github-breach-via-poisoned-vs-code-extension/)
- [Plate2025] [Henrik Plate, Kiran Raj, and Cris Staicu, Nov 24, 2025, "SHAI-HULUD 2 MALWARE
  CAMPAIGN TARGETS GITHUB AND CLOUD CREDENTIALS USING BUN RUNTIME",
  Endor Labs](https://www.endorlabs.com/blog/shai-hulud-2-malware-campaign-targets-github-and-cloud-credentials-using-bun-runtime)
- [Machluf2026] [Lidor Machluf, May 4, 2026, "A Mini Shai-Hulud Has Appeared: Dissecting a
  Multi-Vector npm Supply Chain Worm",
  Upwind](https://www.upwind.io/feed/mini-shai-hulud-npm-supply-chain-worm)
- [McCarthy2026] [Rami McCarthy, Amitai Cohen, and Benjamin Read, May 12, 2026, "MINI SHAI-HULUD
  STRIKES AGAIN: TANSTACK + MORE NPM PACKAGES COMPROMISED",
  Wiz](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
