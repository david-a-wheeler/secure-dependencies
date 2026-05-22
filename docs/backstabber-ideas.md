# Backstabber ideas

This document is the result of a review of [Ohm2020]. Here we review various indicators we could use to identify potentially-malicious software so we are much more likely to detect them. We identify specific ways we could detect them, and how we could modify our code to do so, in a way that minimizes false+ and minimizes false- while still providing useful data. We emphasize practical steps. We emphasize what can be done across all ecosystems, and how we can maximize that commonality, so that when we add support for new ecosystems we'll already have many defenses built in.

## Overall

The "Backstabber's Knife Collection" (Ohm et al., 2020) provides a systematic analysis of 174 malicious packages across npm, PyPI, and RubyGems. The paper establishes a taxonomy of attacks based on two primary dimensions: **Injection Techniques** and **Execution Stages**. A key takeaway is that most malicious behavior is triggered at installation time (56%) and often involves data exfiltration or backdoors.

## 1. Injection Techniques (How it gets in)

Attackers use several methods to trick users or systems into including malicious code:

*   **Typosquatting:** Registering names similar to popular packages (e.g., `djanga` instead of `django`). Detection: Check Levenshtein distance against top-N packages.
*   **Dependency Confusion:** Exploiting package manager resolution order (internal vs. public) to force the download of a malicious public package with the same name as a private one. Detection: Audit name collisions between internal and public registries.
*   **Account Takeover:** Gaining control of a legitimate maintainer's account. Detection: Monitor for sudden changes in author email, sudden spikes in version numbers, or removals of multi-factor authentication (if visible).
*   **Self-Published Malware:** New packages that seem useful but contain hidden logic. Detection: Monitor "new author" + "no repository link" + "sudden popularity".

## 2. Execution Triggers (When it runs)

Malicious code rarely waits for a specific function call; it prefers early execution:

*   **Install-Time (56%):** Using hooks like `preinstall`, `postinstall` (npm) or `setup.py` (PyPI). This is the most common trigger.
*   **Import-Time:** Code that runs as a side-effect of `require()` or `import`.
*   **Conditional Execution (41%):** Evasion techniques that check for CI environments, sandboxes, or specific environment variables before activating.

## 3. Malicious Behaviors (What it does)

Once executed, the payload typically performs one of the following:

*   **Data Exfiltration:** Stealing `process.env`, `~/.ssh`, `~/.aws/credentials`, cookies, or browser history.
*   **Persistence/Backdoor:** Establishing reverse shells or adding SSH keys.
*   **Resource Hijacking:** Cryptojacking or using the host as a botnet node.

## 4. Detection Strategies & Indicators

To minimize false positives (the "Semantic-Safety Gap"), we should look for **Behavioral Sequences** rather than isolated API calls.

### Indicators of Interest
| Indicator | Malicious Context | Legitimate Context (False Positive) |
| :--- | :--- | :--- |
| **Install scripts** | Data exfiltration, shell setup | Native compilation, environment checks |
| **Network activity** | Sending secrets to unknown IPs | Telemetry, update checks, asset downloads |
| **Sensitive FS access** | Reading `.ssh`, `.env`, `/etc/passwd` | CLI config, template engines, dev tools |
| **Obfuscation** | Hiding C2 IPs or second-stage logic | Minification, embedded binary assets |

### Practical Detection Heuristics
1.  **Sequence Detection:** Flag the *combination* of "Read sensitive file" followed by "Network request to unknown domain".
2.  **Environment Evasion:** Flag code that explicitly checks for `process.env.CI` or `is-virtual-machine` before performing sensitive actions.
3.  **Entropy Analysis:** Detect high-entropy strings (Base64/Hex) in unexpected places, but filter out known minified patterns.
4.  **Metadata Cross-Reference:** Low download count + New author + Typosquatting name = High Risk.

## 5. Practical Steps for Our Code

To implement these findings, we should:
*   **Abstract Ecosystem Differences:** Create a common model for "Execution Hooks" (npm scripts vs PyPI setup.py) so detection logic works across all.
*   **Focus on Installation:** Prioritize scanning the installation manifests and scripts.
*   **Implement "Suspicious Pair" logic:** Don't just flag `fs.readFile`; flag it if the path matches a credential pattern AND it's in a package with no repository link.
*   **Baseline Regular Behavior:** For popular packages, maintain a "baseline" of expected network domains to detect anomalies in updates (detecting Account Takeover).

## Bibliography

[Ohm2020] [Ohm et al, 2020, "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks"](https://arxiv.org/abs/2005.09535)
