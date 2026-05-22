# Backstabber ideas

This document is the result of a review of [Ohm2020]. Here we review various indicators we could use to identify potentially-malicious software so we are much more likely to detect them. We identify specific ways we could detect them, and how we could modify our code to do so, in a way that minimizes false+ and minimizes false- while still providing useful data. We emphasize practical steps. We emphasize what can be done across all ecosystems, and how we can maximize that commonality, so that when we add support for new ecosystems we'll already have many defenses built in.

## Overall

The "Backstabber's Knife Collection" (Ohm et al., 2020) provides a systematic analysis of 174 malicious packages across npm, PyPI, and RubyGems. The paper establishes a taxonomy of attacks based on two primary dimensions: **Injection Techniques** and **Execution Stages**. A key takeaway is that most malicious behavior is triggered at installation time (56%) and often involves data exfiltration or backdoors.

## 1. Injection Techniques (How it gets in)

Attackers use several methods to trick users or systems into including malicious code:

*   **Typosquatting:** Registering names similar to popular packages (e.g., `djanga` instead of `django`).
*   **Dependency Confusion:** Exploiting package manager resolution order (internal vs. public) to force the download of a malicious public package with the same name as a private one.
*   **Account Takeover:** Gaining control of a legitimate maintainer's account.
*   **Self-Published Malware:** New packages that seem useful but contain hidden logic.

## 2. Execution Triggers (When it runs)

Malicious code rarely waits for a specific function call; it prefers early execution:

*   **Install-Time (56%):** Using hooks like `preinstall`, `postinstall` (npm) or `setup.py` (PyPI).
*   **Import-Time:** Code that runs as a side-effect of `require()` or `import`.
*   **Conditional Execution (41%):** Evasion techniques that check for CI environments, sandboxes, or specific environment variables before activating.

## 3. Malicious Behaviors (What it does)

Once executed, the payload typically performs one of the following:

*   **Data Exfiltration:** Stealing environment variables, credentials, or system files.
*   **Persistence/Backdoor:** Establishing reverse shells or adding SSH keys.
*   **Resource Hijacking:** Cryptojacking or using the host as a botnet node.

## 4. Technical Implementation Details

### 4.1. Typosquatting Detection
**Algorithm:** Hybrid approach using **Sift4** for fast bulk filtering and **Damerau-Levenshtein** (distance $\le 2$) for final verification.
*   **Reference Dataset:** Maintain a local list of the Top 1,000 - 5,000 most downloaded packages per ecosystem.
*   **Heuristics:**
    *   **Bit-flipping:** Check for names with exactly one bit difference.
    *   **Homoglyph:** Identify confusable characters (e.g., `l` vs `I`, `o` vs `0`).
    *   **Keyboard Adjacency:** Higher risk score if the substitution is an adjacent key on QWERTY.
    *   **Metadata Check:** High risk if `Distance <= 2` AND `Package Age < 30 days` AND `Downloads < 100`.

### 4.2. Data Exfiltration Patterns (Regex)
Detecting the *source* of the data:
*   **Environment Dumps:**
    *   Node.js: `process\.env`
    *   Python: `os\.environ`
    *   Ruby: `ENV\.to_h`
*   **Sensitive Files:**
    *   SSH: `~\/\.ssh\/(id_rsa|authorized_keys)`
    *   AWS: `~\/\.aws\/(credentials|config)`
    *   NPM: `~\/\.npmrc` (specifically looking for `_authToken`)
*   **Specific Secrets:**
    *   Discord Token: `[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9]{27}`
    *   Generic API Key: `(?:key|secret|token|auth|pwd)[a-z0-9_-]{16,}` (Case insensitive)

### 4.3. Network Exfiltration (Sinks)
Identify where the data is going:
*   **Known "Drop" Services:** `requestbin\.net`, `hookbin\.com`, `burpcollaborator\.net`, `webhook\.site`.
*   **DNS Tunneling:** `[a-z0-9]{10,}\.attacker-domain\.com`.
*   **Suspicious TLDs:** High-volume connections during install-time to `.xyz`, `.top`, `.pw`.

### 4.4. Obfuscation Detection
**Algorithm:** Shannon Entropy calculation vs. Line length analysis.
*   **Entropy Threshold:** Flag files with entropy $> 5.8$ bits/byte (indicative of packed/encrypted data).
*   **Structure Heuristics:**
    *   **Long Lines:** Single lines $> 1000$ characters without common minification patterns (like `webpack` headers).
    *   **Hex/Base64 Blobs:** Large strings matching `[a-fA-F0-9]{100,}` or `(?:[A-Za-z0-9+\/]{4}){25,}`.
    *   **String Splitting:** Detecting `('p' + 'r' + 'o' + 'c' + 'e' + 's' + 's' + '.' + 'e' + 'n' + 'v')`.

## 5. Practical Steps for Our Code

1.  **Phase 1: Metadata Audit.** Implement the Top-N comparison and package age check. This has the highest signal-to-noise ratio.
2.  **Phase 2: Install-Script Sandbox.** Run `npm install` in an instrumented container to catch real-time network calls to the "Drop Services" identified in 4.3.
3.  **Phase 3: Static Analysis (AST).** Move beyond regex to AST-based detection of "Suspicious Pairs" (e.g., code that reads an environment variable and then calls an HTTP client within the same function).
4.  **Phase 4: Baselines.** For the Top-N packages, baseline their legitimate network destinations to detect "Account Takeover" updates that introduce new C2 domains.

## Bibliography

[Ohm2020] [Ohm et al, 2020, "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks"](https://arxiv.org/abs/2005.09535)
