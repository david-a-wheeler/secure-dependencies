# Investigation: GitHub Internal Repository Breach via Malicious VS Code Extension

## Overview
On May 18, 2026, GitHub confirmed a significant security breach resulting in the exfiltration of approximately **3,800 internal source code repositories** [Lakshmanan2026, Baran2026]. The attack was executed by a threat group known as **TeamPCP** (tracked as **UNC6780**), who utilized a compromised version of the popular **Nx Console** Visual Studio Code extension to gain initial access to developer workstations [Kurmi2026, ThreatLocker2026].

The attack delivered a sophisticated worm dubbed **"Mini Shai-Hulud,"** which was designed to harvest credentials, establish persistence, and propagate through internal networks and CI/CD pipelines [Lakshmanan2026, McCarthy2026].

## Timeline of the Compromise
- **May 18, 2026:** Attackers used a stolen contributor token and marketplace credentials (`VSCE_PAT`) to publish a malicious version (**v18.95.0**) of the **Nx Console** extension (`nrwl.angular-console`) [Kurmi2026, Baran2026].
- **Exposure Window:** The malicious extension was live on the VS Code Marketplace for approximately **11–18 minutes** before being removed [Kurmi2026, Lakshmanan2026].
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
    - `.claude/settings.json` (Targeted for secret harvesting) [Kurmi2026, Qualysec2026].
    - `.claude/router_runtime.js` [Qualysec2026].
- **Hidden Configs:** `~/.config/sysmon`, `~/.config/audiomon` [OxSecurity2026].
- **Staging/State Files:**
    - `/var/tmp/.gh_update_state`
    - `/tmp/kitty-*`
    - Environment variable `__DAEMONIZED=1` [Kurmi2026].

### Network & Exfiltration
- **C2 Subnet:** `83.142.209.0/24` [PhoenixSecurity2026].
- **Known C2 Domains:** `git-service[.]com`, `git-tanstack[.]com`, `modesl[.]litellm[.]cloud`, `checkmarx[.]zone` [Lakshmanan2026].
- **C2 Polling Query:** `api.github.com/search/commits?q=firedalazer` [Kurmi2026].
- **Exfiltration Repositories:** Public repositories created on victim accounts named **"A Mini Shai-Hulud has Appeared"** [Plate2025, Upwind2026].
- **Commit Messages:** Patterns including `EveryBoiWeBuildIsAWormyBoi:<base64-token>` [Upwind2026].

## Detection & Prevention Strategies

### 1. Pre-Installation Review & Policies
To detect and prevent malicious content *before* installation:
- **Minimum Age Policy:** Implement a "quarantine" period (e.g., 48–72 hours) for new extension or package versions before they are allowed in production environments [Kurmi2026, Lakshmanan2026].
- **Publisher Whitelisting:** Use VS Code's `extensions.allowed` setting to restrict installations to verified, corporate-approved publishers [Lakshmanan2026].
- **Disable Auto-Updates:** Set `"extensions.autoUpdate": false` in high-security environments to prevent "direct push" attacks from compromised publishers [Kurmi2026, Lakshmanan2026].
- **Pre-Install Sandboxing:** Run new extensions in a sandboxed or containerized environment to monitor for unexpected network requests or shell executions.

### 2. Behavioral Detection (EDR/SIEM)
- **Runtime Monitoring:** Monitor for the **Bun runtime** (`bun`) being executed by IDE processes, as the "Mini Shai-Hulud" worm used it to bypass Node.js-based security tools [Plate2025, Lakshmanan2026].
- **Shell Command Auditing:** Alert on VS Code child processes executing shell commands related to "MCP setup tasks" or hidden directory creation [Kurmi2026, Lakshmanan2026].
- **Credential Access:** Monitor for unauthorized access to `~/.aws/credentials`, `~/.ssh/`, or CLI tools like `op` (1Password) and `bw` (Bitwarden) [Kurmi2026, Lakshmanan2026].
- **DNS Tunneling Detection:** Monitor for high volumes of encoded subdomains, which the payload used as a redundant exfiltration path [Lakshmanan2026].

### 3. Immediate Remediation Warnings
- **Dead-Man's Switch:** The worm includes logic to detect token revocation. If it detects its harvested tokens are revoked within 24 hours without the device being isolated, it may attempt to execute `rm -rf ~/` [Qualysec2026, McCarthy2026].
- **Isolation First:** Always isolate the compromised workstation from the network *before* revoking credentials.

... (rest of sections) ...

## Sources
- [Kurmi2026] [Ashish Kurmi, May 18, 2026, "NX CONSOLE VS CODE EXTENSION COMPROMISED", StepSecurity](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised)
- [Lakshmanan2026] [Ravie Lakshmanan, May 21, 2026, "GITHUB INTERNAL REPOSITORIES BREACHED VIA MALICIOUS NX CONSOLE VS CODE EXTENSION", The Hacker News](https://thehackernews.com/2026/05/github-internal-repositories-breached.html)
- [Brown2026] [Shaun Brown, May 20, 2026, "GITHUB BREACHED VIA A MALICIOUS VS CODE EXTENSION: WHY DEVELOPER DEVICES ARE THE REAL TARGET", Aikido](https://www.aikido.dev/blog/github-breached-vs-code-extension)
- [ThreatLocker2026] [ThreatLocker Threat Intelligence, May 21, 2026, "GITHUB CONFIRMS COMPROMISED NX CONSOLE EXTENSION WAS INITIAL ACCESS VECTOR", ThreatLocker](https://www.threatlocker.com/blog/github-breach-likely-caused-by-nx-console-compromise)
- [Baran2026] [Guru Baran, May 21, 2026, "GITHUB INTERNAL REPOSITORIES BREACHED VIA WEAPONIZED VS CODE EXTENSION", CybersecurityNews](https://cybersecuritynews.com/github-internal-repositories-breached/)
- [Qualysec2026] [Tanmay Dixit, May 2026, "Mini Shai Hulud Worm Infects 170+ npm and PyPI Packages in Autonomous Supply Chain Attack", Qualysec](https://qualysec.com/mini-shai-hulud-worm-infects-170-npm-and-pypi-packages-in-autonomous-supply-chain-attack/)
- [OxSecurity2026] [Lior Levy, May 2026, "The Mother of All AI Supply Chains", Ox Security](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains/)
- [PhoenixSecurity2026] [Francesco Cipollone, May 2026, "TeamPCP Wave Four: GitHub Breach via Poisoned VS Code Extension", Phoenix Security](https://phoenix.security/blog/teampcp-wave-four-github-breach-via-poisoned-vs-code-extension/)
- [Plate2025] [Henrik Plate, Kiran Raj, and Cris Staicu, Nov 24, 2025, "SHAI-HULUD 2 MALWARE CAMPAIGN TARGETS GITHUB AND CLOUD CREDENTIALS USING BUN RUNTIME", Endor Labs](https://www.endorlabs.com/blog/shai-hulud-2-malware-campaign-targets-github-and-cloud-credentials-using-bun-runtime)
- [Upwind2026] [Avital Harel, May 2026, "A Mini Shai-Hulud Has Appeared: Dissecting a Multi-Vector npm Supply Chain Worm", Upwind](https://www.upwind.io/blog/a-mini-shai-hulud-has-appeared)
- [McCarthy2026] [Rami McCarthy, Amitai Cohen, and Benjamin Read, May 12, 2026, "MINI SHAI-HULUD STRIKES AGAIN: TANSTACK + MORE NPM PACKAGES COMPROMISED", Wiz](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
