# TODO: Agent Skills Standard Compliance

This document tracks changes needed to align this repository with the [Agent Skills Standard](https://agentskills.io). The goal is to better meet this specification so users can choose whichever AIs best meet their needs. A key need to implement the standard is to separate the "human-facing repository" from the "agent-facing skill package" to maximize interoperability and context efficiency.

## 1. Directory Structure Changes
- [ ] **Move Python scripts:** Relocate all executable logic from `references/scripts/` to a top-level `scripts/` directory.
  *   *Why:* The standard expects deterministic tools in `scripts/`. This allows agents to execute them without necessarily loading the source code into the context window, and provides a standard discovery path for tool-calling. This will requiring changing other files (including Markdown and Python) to deal with the move correctly.
- [ ] **Organize "Human" documentation:** Move files like `ARCHITECTURE.md`, `SECURITY.md`, and `demo.txt` into a `docs/` folder.
  *   *Why:* Keeps the root clean and prevents agents from accidentally consuming thousands of tokens of meta-documentation that doesn't help with the immediate task. These files should be excluded from the final `.skill` package.
- [ ] **Asset Management:** Move any output-related assets (templates, static resources) into the `assets/` directory.
  *   *Why:* Assets are intended for use in the agent's *output* but are not instructions for the agent's *process*. Separation prevents context contamination.
- [ ] **Naming Conventions:** Standardize all agent-facing files to use `lowercase-hyphen-case.md`.
  *   *Why:* Strict adherence to the spec's naming recommendations ensures consistency across different skill implementations and platforms.

## 2. SKILL.md Refinement
- [ ] **Condense Frontmatter:** Change the `description` field from a multiline block to a single-line string.
  *   *Why:* The spec requires a single-line description for activation performance. This is the only part read during the discovery phase.
- [ ] **Context Efficiency (The 500-Line Rule):** Offload detailed reference material into separate files in `references/`.
  *   *Why:* Preserves the agent's context window. A lean `SKILL.md` body ensures more room for conversation history and file content.
- [ ] **Path Resolution:** Update all `SCRIPTS_DIR` references to point to the new top-level `scripts/` location.

## 3. Packaging & Distribution Process
- [ ] **Create a Packaging Script:** Implement a process that generates the `.skill` file while explicitly excluding "human-only" files.
  *   *Why:* Prevents the "skill" from becoming a 20MB bloatware package containing `.git` history, archives, and human READMEs.
- [ ] **Validation:** Integrate a validation step to ensure the generated package meets the spec requirements (YAML checks, no TODOs in body) before release.

## 4. Pending Decisions

### A. Namespace Management for Scripts
*   **Option 1: Flattened (all scripts in `scripts/`)**
    *   *Pros:* Maximum discoverability; simplest for agents to reference.
    *   *Cons:* Becomes cluttered as more ecosystem hooks are added.
*   **Option 2: Nested (e.g., `scripts/hooks/`)**
    *   *Pros:* Better organization; clearly separates core logic from language-specific hooks.
    *   *Cons:* Requires explicit path instructions in `SKILL.md`; some platforms might not auto-index nested scripts.

### B. Agentic Error Handling
*   **Option 1: Python scripts detect "Agent Mode" via environment variables.**
    *   *Pros:* Allows scripts to provide verbose tracebacks for humans but clean, "signal-only" output for agents.
    *   *Cons:* Adds complexity to the Python logic.
*   **Option 2: Scripts are always concise by default.**
    *   *Pros:* Simpler implementation; follows the "Agentic Ergonomics" principle of the spec.
    *   *Cons:* Harder for human developers to debug script failures without standard stack traces.

### C. Discovery vs. Execution expectations
*   **The Issue:** Claude Code and Gemini CLI may have slight variations in how they "activate" a skill (automatic vs. manual).
*   **Approach:** Should the instructions in `SKILL.md` be "Universal" or include platform-specific hints?
    *   *Universal Pros:* Cleaner, smaller file.
    *   *Hint Pros:* Better user experience for platform-specific quirks.

### D. Ecosystem Support Generation
*   **The Issue:** The skill claims the AI can "generate support" for new ecosystems.
*   **Option 1: Instructions in `SKILL.md` guide the agent to use existing hooks as templates.**
    *   *Pros:* Leverages AI flexibility; requires no new code.
    *   *Cons:* High token cost; quality of generated hooks may vary.
*   **Option 2: Provide a dedicated `scripts/generate-hook.py` utility.**
    *   *Pros:* Lower token cost; more consistent output structure.
    *   *Cons:* Another script to maintain.

## 5. Metadata Improvements
- [ ] **Versioning:** Sync `version` in frontmatter with repository tags/releases.
- [ ] **License Field:** Add an explicit `license` field to the `SKILL.md` frontmatter.
- [ ] **Standard Link:** Ensure the `SKILL.md` points to `agentskills.io` for specification reference.
