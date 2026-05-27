# secure-dependencies

This is a general-purpose AI skill for evaluating software dependency security,
building on guidance such as the
[OpenSSF Concise Guide for Evaluating Open Source Software](https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software.html).
Its purpose is to provide support a reasonable level of due diligence
analysis when
adding dependencies, updating dependencies, or examining current dependencies.
It determines what will be done and estimates its security risk.
This skill is not tied to any specific AI assistant
(such as Claude Code, Gemini CLI, GitHub Copilot, etc.) and
is intended to comply with the [Agent Skills Standard](https://agentskills.io).
It takes various steps to protect itself from malicious packages
(though we presume it will be run in a sandboxed environment).

The video [Secure-dependencies presentation by David A. Wheeler](https://www.youtube.com/watch?v=8DzOV-yArRE) presents this in more detail.

## Ecosystems supported

This skill can support *any* ecosystem.
That's because if the human permits it, the AI agent using this skill can
generate support for whatever ecosystem you need.
The agent will simply use the existing ecosystem support code as a template
and hook in the many data sources that are ecosystem-independent.
That said, you'll need to give the AI agent some time to generate support
for an ecosystem we don't directly support yet.
Currently this skill includes direct support for Ruby, Python, and JavaScript.

## What it does

This skill helps with three types of dependency work:

| Mode | When to use |
|---|---|
| **Update** | Updating existing dependencies |
| **New** | When you're considering adding a new dependency |
| **Audit** | Reviewing already-installed dependencies |

In all three modes, the skill guards against:

- **Unintentional vulnerabilities**: For example,
  insecure code patterns, dangerous
  defaults, and known vulnerabilities (e.g., CVEs) in installed versions.
- **Long-term risk**: For example,
  abandoned projects and missing/problematic licenses.
- **Supply chain attacks**: For example,
  typosquatting, slopsquatting, compromised
  maintainer accounts, and malicious package developers.
  We build on lessons learned from various places such as
  the Shai-Halud attacks and the
  [Backstabber's Knife Collection analysis](https://arxiv.org/abs/2005.09535).
- **AI Adversarial content**: These are
  package files crafted to manipulate AI reviewers, for example, packages
  with embedded "ignore previous instructions" statements.

## Requirements

- Python 3.10 or later (standard library only, no extra installation needed)
- Optional tools (detected automatically): `bundler-audit`, `pip-audit`,
  `npm audit`, `scorecard`

Several external services are queried during analysis (all free, no API key
necessarily required): the package registry, [OSV](https://osv.dev),
[OSS Rebuild](https://oss-rebuild.dev),
[OpenSSF Scorecard](https://securityscorecards.dev),
[OpenSSF Best Practices](https://bestpractices.dev), and
[packages.ecosyste.ms](https://packages.ecosyste.ms).
The ecosyste.ms API has a polite rate-limit pool for users who provide a
contact email. The first time a 429 is encountered, the script explains how to
opt in (or out) via `dep_session.py configure-email`.

Analysis output goes to `temp/dep-review/` inside your project root.
Add `temp/` to your `.gitignore`.

## How it works

See [ARCHITECTURE.md](./ARCHITECTURE.md) for information on
how this skill works. This skill uses deterministic scripts to gather data
where possible, and uses AI to analyze their results or do tasks that
only AI can do. Sandboxes reduce risk during execution.

## Levels of analysis

This skill implements several kinds of analysis: alternatives check,
basic analysis, deeper analysis, and install probe.

* **Alternatives check** is used when adding a
  new dependency (including when you update a component and that updated
  version brings in a new dependency). This includes countering typosquatting.
* **Basic analysis** is the standard starting point for analyzing a package.
  It gathers information from various databases, etc.
* **Deeper analysis** run on top of basic when the concern
  level warrants it, or when the human requests it upfront. It adds
  checks such as reproducible-build verification and a full
  file-level source diff.
* **Install probe** goes further still and runs the
  package installer inside a sandbox with honeytoken credentials, monitoring
  for suspicious activity. This is the most invasive level and is
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

## Installing this skill

This repository is an
[agent skill](https://agentskills.io)
intended to be compatible with Claude Code, Gemini CLI, GitHub Copilot CLI,
and other AI tools that
support the [Agent Skills Standard](https://agentskills.io).
We plan to eventually better align with that standard; see
[TODO-SKILL-SPEC.md](TODO-SKILL-SPEC.md) for the changes we expect to make.

Skills can be installed at two scopes:

- **Personal** (shared across all your projects): clone into a
 `~/.claude/skills/`, `~/.gemini/skills/`,
 `~/.copilot/skills/`, or `~/.agents/skills/`
  directory, depending on your AI tool.
- **Project** (specific to one repository): clone into
 `.claude/skills/`, `.gemini/skills/`,
 `.github/skills/`, or `.agents/skills/`
  inside that repository.

Here are examples of how to install this skill for personal use:

For Claude Code, use `~/.claude/skills/`:

```bash
git clone https://github.com/ossf/secure-dependencies ~/.claude/skills/secure-dependencies
```

For Gemini CLI, use `~/.gemini/skills/`:

```bash
git clone https://github.com/ossf/secure-dependencies ~/.gemini/skills/secure-dependencies
```

For GitHub Copilot CLI, use `~/.copilot/skills/`:

```bash
git clone https://github.com/ossf/secure-dependencies ~/.copilot/skills/secure-dependencies
```

The skill is picked up automatically on next launch; no further
configuration is required.

Eventually we'll want to put this skill in a "marketplace" but I want to
give people time to discuss the name first.

## Using the skill

Once installed, ask your AI assistant something like:

- "Update my dependencies"
- "Is it safe to add left-pad?"
- "Audit our dependencies for license problems"
- "Apply the Dependabot alerts"

The skill will ask clarifying questions as needed and keep you informed at
each step before taking action.

## Security

We presume that this skill will be run *within* a virtual machine or
container that does *not* have unlimited rights, so even if the AI itself
becomes malicious, any damage will be contained.
We take active steps to counter subverted AI agents, but since we use
AI agents to read potentially-malicious text, there's only so much we can do.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for how we work to counter
attacks, including specific mitigations for patterns observed in
Shai-Halud.

See [SECURITY.md](./SECURITY.md) for how to report vulnerabilities in
this program.

## Current status

This is an early-stage technology demonstration.
It is *not* yet production-ready. We hope you'll work with us to
make it that way.

In particular, this code it *not* really ready for malicious packages.
There's been some security analysis of it (thank you to Andrew Nesbitt)
and known problems have been addressed, but it will require effort to
make it more ready for that.

Most of the code is currently vibe-coded. That's not as bad as you might
think in this case, because most of the code involves "download data from X"
or "do trivial analysis of downloaded data and provide the various summaries
to an AI sub-agent". There's also not a lot of code in the first place.
The point of nearly all of the deterministic code is to provide
a rich source of data for an AI sub-agent to review
and heuristically summarize. So for a vibe-coding task this is a
relatively easy task that it's more likely to get correct.
That doesn't mean we can just trust the vibe-coded
code; that's something that needs to be reviewed.

## License of this skill

MIT. See [LICENSE.md](LICENSE.md).
