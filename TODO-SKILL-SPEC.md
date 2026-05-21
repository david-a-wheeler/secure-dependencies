# TODO: Agent Skills Standard Compliance

This document tracks changes needed to align this repository with the
[Agent Skills Standard](https://agentskills.io/specification). The goal is
to better meet this specification so users can choose whichever AI best
meets their needs. A key need is to separate the "human-facing repository"
from the "agent-facing skill package" to maximize interoperability and
context efficiency.

**Spec sources reviewed 2026-05-20**:
- agentskills.io/specification
- agentskills.io/skill-creation/best-practices
- agentskills.io/skill-creation/using-scripts

**Current state summary**:
- SKILL.md is 787 lines; spec recommends fewer than 500 lines
- Scripts are in `references/scripts/`; spec expects `scripts/` at skill root
- Frontmatter has non-spec top-level `version` field
- `license` and `compatibility` frontmatter fields are absent
- Several TODO items below were based on incorrect assumptions about the
  spec; corrections are noted inline

---

## 1. Directory Structure Changes

### 1.1 Move Python scripts to top-level `scripts/`

- [ ] Move all executable scripts from `references/scripts/` to a new
  top-level `scripts/` directory, including the `tests/` and `__pycache__`
  subdirectories and all `.py` files.

  Files to move:
  - `references/scripts/analysis_shared.py` -> `scripts/analysis_shared.py`
  - `references/scripts/dep_review.py` -> `scripts/dep_review.py`
  - `references/scripts/dep_session.py` -> `scripts/dep_session.py`
  - `references/scripts/fetch_json.py` -> `scripts/fetch_json.py`
  - `references/scripts/hooks_js.py` -> `scripts/hooks_js.py`
  - `references/scripts/hooks_python.py` -> `scripts/hooks_python.py`
  - `references/scripts/hooks_ruby.py` -> `scripts/hooks_ruby.py`
  - `references/scripts/tests/` -> `scripts/tests/`

  Also check and update any references in: `Makefile`, `.github/workflows/`
  and within the scripts themselves (import paths, test fixtures).

  *Why*: The spec defines `scripts/` at the skill root as the standard
  location. Agents expect to find executable code there, not inside
  `references/`.

### 1.2 Move human-facing documentation into `docs/`

- [ ] Move `ARCHITECTURE.md`, `SECURITY.md`, and `demo.txt` into `docs/`.
  A `docs/` directory already exists in the repo.

  *Why*: Prevents agents from loading thousands of tokens of meta-
  documentation that does not help with the immediate task. These files
  are for human readers, not agent instructions.

  *Note*: This is a best practice, not a strict spec requirement. The spec
  only mandates `SKILL.md` at the root; all other files are optional.

### 1.3 Asset management

- [ ] Identify candidates for an `assets/` directory. The assessment
  report template (currently embedded inside the sub-agent brief in
  SKILL.md, around lines 510-580) is a candidate. Short templates can
  stay inline in SKILL.md; longer or conditionally-loaded ones fit better
  in `assets/` with an explicit loading instruction.

  *Why*: The spec defines `assets/` for "templates, images, data files."
  Templates stored there load only when needed, saving context.

### 1.4 Naming conventions

**Correction to original TODO**: The spec does NOT mandate lowercase-
hyphen-case for all agent-facing files. The spec itself uses uppercase for
its canonical filenames (`SKILL.md`, and examples show `REFERENCE.md` and
`FORMS.md`). Domain-specific reference files (e.g., `ruby-ecosystem.md`)
already follow lowercase convention. The `name` frontmatter field must
be lowercase-hyphen-case, but that is already the case (`secure-
dependencies`). No bulk file renames are needed.

---

## 2. SKILL.md Refinement

### 2.1 Description field format

**Correction to original TODO**: The spec does NOT require a single-line
description string. The requirement is 1-1024 characters, non-empty. A
YAML block scalar (`|`) is valid. The current description is 222 characters,
well within the limit.

- [ ] Verify the description includes the right trigger keywords for
  activation. See agentskills.io/skill-creation/optimizing-descriptions.

### 2.2 Context efficiency: reduce SKILL.md to fewer than 500 lines

**Highest-priority spec requirement.** The spec recommends keeping
`SKILL.md` under 500 lines and 5000 tokens. It is currently 787 lines.

- [ ] Move the sub-agent brief template (approximately lines 364-597) to
  `references/package-analysis-brief.md`. Replace it in SKILL.md with an
  explicit loading instruction, for example:

  > "Before spawning each per-package sub-agent, read
  > `references/package-analysis-brief.md` for the complete brief template."

  This is the single change with the largest line-count impact.

  *Filename rationale*: "package-analysis" describes the agent's job (analyze
  one package), not its position in the hierarchy. This keeps it distinct from
  any future briefs such as `references/deeper-analysis-brief.md` or
  `references/install-probe-brief.md`, without relying on vague ordinal terms
  like "sub-sub-agent."

- [ ] After moving the brief, check whether SKILL.md is under 500 lines.
  If further cuts are needed, consider moving the assessment report
  template (inside the brief) to `assets/assessment-template.txt` and
  the Red Flags tables to `references/red-flags.md`.

  *Why*: The spec says the full SKILL.md body loads into context on every
  activation. A 787-line body costs the agent roughly 6x more context than
  the 500-line target on every invocation of the skill.

### 2.3 Script path references: switch to relative paths

After moving scripts (1.1), update ALL path references in SKILL.md:

- [ ] **Step 2-0** currently states "Scripts live in the `references/scripts/`
  subdirectory of wherever this skill file is installed." Change to: "Scripts
  live in the `scripts/` subdirectory of wherever this skill file is
  installed."

- [ ] **All `SCRIPTS_DIR` placeholder references** (e.g.,
  `python3 SCRIPTS_DIR/dep_session.py`) should become relative paths from
  the skill root: `scripts/dep_session.py`, `scripts/dep_review.py`, etc.
  Per the spec: "use relative paths from the skill directory root."

- [ ] **`references/package-analysis-brief.md`** (moved in Phase 2) also
  references `PROJECT_ROOT/temp/dep-review/scripts/` as the session-scoped
  copy destination. Verify whether this copy-to-temp pattern is still needed
  after the move, and update accordingly.

### 2.4 Fix `version` frontmatter field

- [ ] The current SKILL.md has `version: 0.3.0` as a top-level frontmatter
  field. The spec does NOT define a top-level `version` field. Move it into
  the `metadata` mapping:

  ```yaml
  metadata:
    version: "0.3.0"
  ```

### 2.5 Add `license` field

- [ ] The spec defines an optional `license` field. A `LICENSE.md` file
  exists in the repo containing the MIT license. Add to frontmatter:

  ```yaml
  license: MIT
  ```

  Or, if the license file name is what agents should reference:
  `license: See LICENSE.md`.

### 2.6 Add `compatibility` field

- [ ] The spec defines an optional `compatibility` field (max 500 chars)
  for environment requirements. The skill's Python requirement is currently
  documented only in the SKILL.md body text. Add to frontmatter:

  ```yaml
  compatibility: Requires Python 3.10+ (standard library only, no install
    needed). Works with any Agent Skills-compatible agent. Optional: bwrap,
    firejail, Docker, or podman for sandboxed install probes.
  ```

### 2.7 Consider `allowed-tools` field

- [ ] The spec defines an experimental `allowed-tools` field for pre-
  approving tools the skill will use:

  ```yaml
  allowed-tools: Bash Read
  ```

  This could reduce permission prompts in Claude Code and similar agents.
  Support varies by platform (see Pending Decision C). Add only if the
  primary target platforms support it.

---

## 3. Packaging and Validation

### 3.1 Packaging script

**Correction to original TODO**: The current spec page does NOT define a
`.skill` binary packaging format. The spec defines skills as *directories*.
Before implementing a packaging script that generates `.skill` files,
verify whether such a format exists (check the agentskills GitHub repo).

If packaging does exist, the script should exclude: `.git/`, `archives/`,
`NOTES`, `result`, `docs/` (human-facing), temp files, and `__pycache__`.

### 3.2 Validation

**Correction**: The spec references `skills-ref` as a validator, but that tool
carries an explicit disclaimer: "intended for demonstration purposes only, not
for production use." It is also unpublished on PyPI (see agentskills/agentskills#114).
Do not add it as a CI dependency. See Phase 5 of the implementation plan for
the alternative approach (a small custom validation script).

---

## 4. Pending Decisions

### A. Namespace management for scripts

**Resolved by spec**: The spec expects `scripts/` at the skill root
(flat, not nested). No `scripts/hooks/` subdirectory is described. The
existing file naming (`hooks_ruby.py`, `hooks_python.py`, etc.) is
descriptive enough without a subdirectory. Keep scripts flat in `scripts/`.

### B. Agentic error handling

- **Option 1**: Scripts detect "Agent Mode" via an environment variable
  and suppress stack traces for agents.
  - Pros: Verbose for humans, clean for agents.
  - Cons: Added complexity in each script.
- **Option 2**: Scripts are always concise (spec recommendation).
  - Pros: Simpler; matches the spec guidance to "include helpful error
    messages" and "handle edge cases gracefully."
  - Cons: Harder for human developers to debug without full tracebacks.

The spec's guidance leans toward Option 2 with clear, actionable error
messages rather than conditional verbosity.

### C. Discovery vs. execution expectations

The spec's progressive disclosure (name+description at startup, full body
on activation) is universal across platforms. Claude Code-specific
activation is handled by `AGENTS.md`/`CLAUDE.md`, which is separate from
the Agent Skills spec format. The `allowed-tools` field (2.7) provides
platform-specific hints while keeping `SKILL.md` itself universal.

**Recommendation**: Keep `SKILL.md` universal. Use the `compatibility`
field (2.6) for environment requirements. Add `allowed-tools` if testing
confirms Claude Code and other target platforms support it.

### D. Ecosystem support generation

- **Option 1**: `SKILL.md` guides the agent to use existing hooks files
  as templates. Lower maintenance cost, higher token cost per invocation.
- **Option 2**: A `scripts/generate-hook.py` utility produces a consistent
  skeleton. More to maintain, lower per-invocation cost.

Generating a new hooks file is a rare, one-off task, not a recurring
workflow the agent repeatedly reinvents. Per spec best practices, bundle
scripts only when "the agent independently reinvents the same logic each
run." Option 1 is adequate.

---

## 5. Metadata Improvements

- [ ] **`version`**: Move from top-level field to `metadata.version` (2.4).
- [ ] **`license`**: Add `license: MIT` field (2.5).
- [ ] **`compatibility`**: Add `compatibility` field for Python 3.10+ (2.6).
- **`name` matches directory**: `name: secure-dependencies` already matches
  the directory name `secure-dependencies/`. No change needed.
- **Standard link**: Pointing `SKILL.md` to agentskills.io is not a spec
  requirement. The spec page link is for human readers, not agents. No
  action needed.

---

## 6. Implementation Plan

Each phase is a single commit. Phases 1-2 are safe to do in any order.
Phase 3 (script move) must be one atomic commit with Phase 3's path updates
-- do not split them.

### Phase 1: Frontmatter fixes

Low risk; no structural changes. Affects only SKILL.md lines 1-23.

- [ ] Move `version: 0.3.0` to `metadata.version: "0.3.0"` (2.4)
- [ ] Add `license: MIT` field (2.5)
- [ ] Add `compatibility` field documenting Python 3.10+ requirement (2.6)

### Phase 2: Reduce SKILL.md to fewer than 500 lines

Highest spec compliance impact. Create the new file first, then cut SKILL.md.

- [ ] Create `references/package-analysis-brief.md` containing the
  sub-agent brief template (currently lines ~364-597 of SKILL.md, from
  the opening `---` through the closing `---` before "### After Each
  Sub-Agent Completes")
- [ ] Replace those lines in SKILL.md with the explicit loading instruction:
  "Before spawning each per-package sub-agent, read
  `references/package-analysis-brief.md` for the complete brief template."
- [ ] Count lines in SKILL.md. If still above 500, move the Red Flags
  tables (currently after line 740) to `references/red-flags.md` with a
  conditional loading instruction ("Read `references/red-flags.md` if you
  need the full red-flag reference tables"). Note: the assessment report
  template lives inside the brief and moves with it to
  `references/package-analysis-brief.md` in this phase; moving it further
  to `assets/` would require splitting that file and is a separate decision.

### Phase 3: Move scripts and update all path references (atomic)

Do not split this phase across commits. The skill is broken between the
script move and the path update.

- [ ] Move source files from `references/scripts/` to `scripts/`:
  - Move the seven `.py` files:
    `analysis_shared.py`, `dep_review.py`, `dep_session.py`,
    `fetch_json.py`, `hooks_js.py`, `hooks_python.py`, `hooks_ruby.py`
  - Move `tests/` subdirectory (preserving internal structure)
  - Do NOT move `__pycache__/` (generated; will rebuild) or `temp/`
    (runtime output; not source)
- [ ] Update `analysis_shared.py` docstring path strings: lines 2705,
  2753, 2796, 2950, 2955, and 3437 each contain `'references/scripts'`
  or `references/scripts directory` in doctest runner code or comments.
  Change each to `'scripts'` / `scripts directory`. (Neither test file
  needs changes -- both use `Path(__file__).parent.parent` which resolves
  dynamically.)
- [ ] In SKILL.md Step 2-0: change `references/scripts/` to `scripts/`
- [ ] In SKILL.md: update all `SCRIPTS_DIR` placeholder examples (the
  example path `secure-dependencies/references/scripts` → `secure-dependencies/scripts`)
- [ ] In `references/package-analysis-brief.md`: update the `SCRIPTS_DIR`
  placeholder examples and any `references/scripts/` path references.
  Also verify whether `**Scripts dir**: PROJECT_ROOT/temp/dep-review/scripts/`
  (the session-scoped copy destination) still reflects the intended behavior.
- [ ] In `Makefile`: three lines need updating:
  - Line 7: `references/scripts/tests` → `scripts/tests`
  - Line 11: `references/scripts/*.py` → `scripts/*.py`
  - Line 18: `./references/scripts/temp` → `./scripts/temp`
- [ ] `ci.yml` calls `make` and has no direct path references -- no
  changes needed there.
- [ ] Run the test suite (`python -m unittest discover -s scripts/tests -v`)
  and verify it passes
- [ ] Delete the now-empty `references/scripts/` directory (confirm
  `temp/` contents are not needed before deleting)

### Phase 4: Move human-facing docs

Low risk; no functional impact. Verify first that nothing links to these.

- [ ] Confirm SKILL.md, AGENTS.md, and Makefile do not reference
  `ARCHITECTURE.md`, `SECURITY.md`, or `demo.txt`
- [ ] Move `ARCHITECTURE.md`, `SECURITY.md`, and `demo.txt` into `docs/`
- [ ] Update `ARCHITECTURE.md` line 422: it mentions `references/scripts/`
  and should be updated to `scripts/` while editing the file

### Phase 5: Add frontmatter validation

**Do not use `skills-ref`.** Its README states "This library is intended for
demonstration purposes only. It is not meant to be used in production." It is
also not published on PyPI (agentskills/agentskills#114), requiring a fragile
git-subdirectory install. It is not a reliable CI dependency.

Instead, add a small validation script or Makefile target that checks the
spec requirements we care about directly:

- [ ] Add a `validate` target to `Makefile` that checks SKILL.md frontmatter:
  - `name` is present, lowercase-hyphen-only, max 64 chars, matches directory
    name `secure-dependencies`
  - `description` is present and under 1024 characters
  - `license` field is present
  - No unknown top-level frontmatter keys (i.e., no bare `version:`)
  - SKILL.md body is under 500 lines (warn, not fail)

  A small Python script (e.g., `scripts/validate_skill.py`) reading the YAML
  frontmatter with the standard library `tomllib` or a `---`-block parser is
  sufficient. Alternatively, use a simple `grep`/`awk` Makefile rule.

- [ ] Add `validate` to the `all` target in Makefile.
- [ ] Add a `make validate` step to `.github/workflows/ci.yml`.

### Phase 6: Investigate packaging (before implementing)

- [ ] Check the agentskills GitHub repo for a `.skill` packaging format
- [ ] If it exists: implement a packaging script that excludes `.git/`,
  `archives/`, `NOTES`, `result`, `docs/`, and `__pycache__`
- [ ] If it does not exist: close this item as not applicable

### Phase 7: Optional -- `allowed-tools` field

- [ ] Test whether Claude Code acts on the `allowed-tools` frontmatter
  field when running this skill
- [ ] If supported: add `allowed-tools: Bash Read` to SKILL.md frontmatter
  and verify it reduces permission prompts in practice

### Phase 8: Final check

- [ ] Ensure Python files will work in their new directory location
- [ ] Test if `make` test succeeds
