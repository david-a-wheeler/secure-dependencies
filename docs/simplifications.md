# Code Simplifications for Dependency Analysis

This document records proposed simplifications for the dependency analysis
codebase, with assessments grounded in the actual code state. It is a
living document: completed items are marked DONE and left for reference.
The primary focus is reducing complexity in `dep_review.py` and eliminating
structural redundancy across the ecosystem hooks
(`hooks_js.py`, `hooks_python.py`, `hooks_ruby.py`).

See Section 6 for the current roadmap and status summary.

## 1. Summary of Issues

Measurements at the start of this effort (2026-05-22):

*   `dep_review.py`: 2,400 lines; `write_signals()` alone ~970 lines,
    47 arguments.
*   `hooks_js.py`: 1,869 lines; `hooks_python.py`: 1,689;
    `hooks_ruby.py`: 1,415; `analysis_shared.py`: 4,003 lines.

Current measurements (after Phases 1-2):

*   `dep_review.py`: 2,407 lines; `write_signals()`: 48 arguments.
*   `hooks_js.py`: 1,670 lines; `hooks_python.py`: 1,667;
    `hooks_ruby.py`: 1,377; `analysis_shared.py`: 4,215 lines.

(`analysis_shared.py` grew because the 12 shared patterns and the
provenance/velocity methods moved there from the ecosystem files.)

Problems remaining:

*   **Wide interface**: `write_signals()` has 48 arguments, making it
    fragile to extend and hard to test in isolation.
*   **Misleading names**: `EcosystemHooks` and the subclass `Hooks` use
    "hook" in the plugin-callback sense, but these classes own full
    analysis implementations, not callback intercept points.

Problems now solved (do not re-implement):

*   **Structural pattern duplication** (DONE, Phase 1): The 12 universal
    `DANGEROUS_PATTERNS` entries that appeared in all three hook files are
    now `BASE_DANGEROUS_PATTERNS` on `EcosystemHooks`. Each ecosystem
    file declares only its own additions and calls
    `all_dangerous_patterns()` to get the combined list. Patterns are now
    3-tuples `(label, regex, description)`.
*   **JS-only advanced checks** (DONE, Phase 2): SLSA provenance and
    publisher velocity checks are now `check_provenance()` and
    `check_publisher_velocity()` on `EcosystemHooks`. The JS hook
    populates `_provenance` and `_publisher_stats` dict keys;
    `dep_review.py` calls the shared methods for all ecosystems.
*   **Health thresholds**: `compute_health_concerns()` in
    `analysis_shared.py` already centralizes all health-concern logic.
*   **Shared regex constants**: Common patterns are defined as
    `shared.XYZ_RE` and referenced from each hook.
*   **`EcosystemHooks` ABC**: Already exists in `analysis_shared.py`
    with all required abstract methods.

## 2. Proposed Architectural Changes

### A. Narrow the `write_signals()` Interface (DONE, Phase 5 + 6)

**Problem**: 48 arguments is genuinely hard to manage. Adding one new signal
requires changing both the caller and the callee.

**Recommendation**: Bundle all inputs into a `@dataclass`. This narrows the
interface without requiring a full OOP reporting pipeline.

```python
@dataclass
class SignalContext:
    work: Path
    pkgname: str
    old_ver: str
    new_ver: str
    diff_mode: bool
    manifest: dict          # or PackageManifest once C is done
    scan_details: list[tuple[str, int]]
    total_matches: int
    # ... remaining fields
    analyzer: EcosystemAnalyzer
```

The function signature becomes:

```python
def write_signals(ctx: SignalContext, p: Printer) -> None:
```

**Why prefer `@dataclass` over a full `SignalAccumulator` class:**

The original proposal included `add_alert()`, `add_warning()`, `add_data()`
methods and a `write_report()` method all on the same class. This conflates
two concerns: (1) bundling inputs and (2) generating the report. Keeping them
separate is cleaner: the dataclass holds inputs, and `write_signals()` still
owns the rendering logic. That makes both independently testable.

If we later want structured collections of alerts/warnings as outputs (not
just inputs), a separate lightweight struct makes sense:

```python
@dataclass
class SignalReport:
    alerts: list[str] = field(default_factory=list)      # SCAN_MATCHES, etc.
    warnings: list[tuple[str, str]] = field(default_factory=list)
    positives: list[str] = field(default_factory=list)
```

The terminology shift (data/alerts/warnings/positives) is sound and worth
keeping; it accurately reflects that these are inputs to a risk judgment, not
the judgment itself.

### B. Base Class Patterns (PARTIALLY ACCEPTED)

**Split into two sub-proposals with different verdicts:**

#### B1. `BASE_DANGEROUS_PATTERNS` in `EcosystemHooks` (DONE, Phase 1)

Previously, 12 DANGEROUS_PATTERNS labels were structurally repeated across
all three hook files. They are now `BASE_DANGEROUS_PATTERNS` on the base
class. Each ecosystem declares only its own additions, and
`all_dangerous_patterns()` returns the combined list.

Patterns are 3-tuples `(label, regex, description)`. The description
drives the "Scanned for:" report line via `dangerous_what()`, eliminating
the parallel `DANGEROUS_WHAT` string that had to be kept in sync manually.

Adding Go or Rust now requires only the ecosystem-specific entries; the
12 shared ones come from the base class automatically.

#### B2. `evaluate_health()` virtual method (MINOR, PENDING)

The current `compute_health_concerns()` function in `analysis_shared.py`
already centralizes health thresholds, so this is partially done. If an
ecosystem needs to override a threshold (e.g., a different staleness
window), making `evaluate_health()` a virtual method on `EcosystemHooks`
with a `super()` call is cleaner than a separate function with an extra
argument. This is a minor, low-urgency cleanup.

#### B3. Decorator-based `EcosystemRegistry` (REJECTED)

The original proposal included:

```python
@shared.EcosystemRegistry.register('javascript')
class Hooks(shared.EcosystemHooks):
    ...
```

This adds metaclass/registry machinery that provides nothing over Python's
existing module system. The driver already selects the right hooks module by
name. A decorator that duplicates what `import` already does is fad
architecture: it looks organized but adds indirection and failure modes with
no benefit.

### C. Standardized Manifest Data Objects (DONE, Phase 4)

`read_manifest()` in each hook returns an untyped `dict` with 15+ keys.
Key names can drift between ecosystems silently. A `@dataclass` fixes this:

```python
@dataclass
class PackageManifest:
    source_url: str = ""
    extensions: str = "NO"
    executables: str = "NO"
    runtime_deps: list[str] = field(default_factory=list)
    license_raw: str = ""
    install_cmd_warnings: list[str] = field(default_factory=list)
    post_install_msg: str = "NO"
    # ... etc.
```

Benefits:
*   Type errors caught at definition time, not at `dict.get()` call sites
*   IDE completion across all callers
*   A new ecosystem that forgets a field gets a type error, not a silent None

Migration cost is real (all hook `read_manifest()` implementations and all
driver callers need updating), but the long-term benefit is proportional.
This is the highest-value cleanup that doesn't require restructuring control
flow.

### D. Generalize SLSA Provenance and Velocity Checks (DONE, Phase 2)

`check_provenance()` and `check_publisher_velocity()` are now concrete
methods on `EcosystemHooks` in `analysis_shared.py`. They own all policy
and report emission. Ecosystems that support these checks populate
`registry_data['_provenance']` and `registry_data['_publisher_stats']`
in their `fetch_all_registry_data()` implementation; ecosystems that do
not support them simply leave those keys absent and the base methods
return immediately.

The JS hook populates both keys from the npm provenance and search APIs.
Python and Ruby leave them absent (pending future work for PyPI provenance).
`dep_review.py` calls the shared methods unconditionally for all ecosystems.

This differs from the original proposal (which suggested no-op overrides
that each ecosystem would replace): instead the base class owns the logic
and ecosystems supply data, cleanly separating fetching from policy.

## 3. Pattern Deduplication (DONE)

The original duplication was in `DANGEROUS_PATTERNS`: 12 universal pattern
labels appeared in all three hook files. Those 12 entries are now
`BASE_DANGEROUS_PATTERNS` on the base class (Phase 1, done).

Pattern breakdown after Phase 1:
- 12 universal patterns: `BASE_DANGEROUS_PATTERNS` on `EcosystemHooks`
- 2 labels appear in Python + Ruby only (`self-publish`, `shell-exec`),
  still in each hook's `DANGEROUS_PATTERNS`
- 7 labels are Python-only, 3 Ruby-only, 4 JS-only

A new ecosystem (Go, Rust) inherits the 12 shared patterns automatically
and only needs to declare its own additions.

## 4. Benefits: Achieved and Pending

Achieved:

*   **Easier new ecosystems** (Phase 1): Go or Rust needs only its unique
    patterns; the 12 shared ones come from the base class automatically.
*   **Universal provenance dispatch** (Phase 2): SLSA and velocity checks
    are available to all ecosystems via `check_provenance()` and
    `check_publisher_velocity()` on the base class.

Pending:

*   **Interface stability** (DONE, Phase 5): `write_signals(ctx: SignalContext, p)`
    absorbs new signals without changing the call site.
*   **Type safety** (DONE, Phase 4): `PackageManifest` makes key-name drift a
    type error rather than a silent `None` at `dict.get()` call sites.

## 5. Renaming and Restructuring: EcosystemAnalyzer

### The naming problem

The current class is `EcosystemHooks` with subclasses all named `Hooks`.
In software, "hook" typically means a callback invoked at a lifecycle
event: Git pre-commit hooks, pytest hooks, plugin hooks. The current class
is nothing like that. It owns full analysis implementations: downloading
and unpacking packages, reading manifests, fetching registry data,
checking lockfiles, detecting typosquats. "Hook" is the wrong word.

"Analysis" is also ambiguous: it is both a process (verb) and a result
(noun), and "Python analysis" does not clearly identify the class as an
agent. The right grammatical form is an agent noun: the thing that does
the analyzing.

Chosen names: `EcosystemAnalyzer` as the base class, with subclasses
`PythonAnalyzer`, `RubyAnalyzer`, `JavaScriptAnalyzer`. Each name
unambiguously reads as "the thing that analyzes Python/Ruby/JS packages."

The local variable in `dep_review.py` (currently `hooks`) becomes
`analyzer`, which is similarly self-describing.

The module files `hooks_python.py`, `hooks_ruby.py`, `hooks_js.py` have
the same naming problem. Renaming them to `analyzer_python.py`,
`analyzer_ruby.py`, `analyzer_js.py` is consistent with the class names
(and distinct from `analysis_shared.py` which contains shared utilities).
File renames are a separate step because they break `git blame` continuity
and require updating test infrastructure (`test_doctests.py` imports
`hooks_ruby` by name).

### The module-level code problem

A significant fraction of each hook file lives *outside* the class at
module scope. Current measurement:

- `hooks_js.py`: ~293 module-level lines out of 1,670 total
- `hooks_python.py`: ~270 module-level lines out of 1,667 total
- `hooks_ruby.py`: ~125 module-level lines out of 1,377 total

That module-level code includes regex constants, helper functions, and
size/line thresholds. All of them are only used inside the class; none
are imported by other modules or tests (verified by grep). They live at
module scope for historical reasons, not because they need to.

There are three distinct cases with different recommendations:

**Case 1: threshold constants** (e.g., `_SETUP_PY_WARN_BYTES = 40_000`,
`_INSTALL_HOOK_WARN_BYTES = 10_000`): Move to class-level attributes on
the subclass. This is the pattern already used on the base class
(`VELOCITY_WINDOW_SECS`, `VELOCITY_THRESHOLD`, `NEW_PUBLISHER_DAYS`).
Thresholds as class attributes are overridable: a stricter subclass or
test can tighten them without patching call sites.

**Case 2: cross-cutting helper functions** that implement the same concept
in each ecosystem but with ecosystem-specific mechanics. The clearest
examples:

- `extract_source_url()`: present in Ruby (`_extract_source_url()`),
  JS (`_extract_source_url()`), and inlined in Python
- `extract_license()`: present in all three under different names
- Package unpacking: `_unpack_pkg()` (Python), `_unpack_tgz()` (JS),
  inline in Ruby

These should become overridable instance methods on `EcosystemAnalyzer`.
The base class provides a default (typically returning `''` or doing
nothing), and each subclass overrides with its ecosystem-specific
implementation. This is the **template method pattern**: the base class
owns the algorithm skeleton (e.g., `read_manifest()` calling
`self.extract_source_url()` and `self.extract_license()`), and subclasses
fill in the steps.

The benefit is real: the base class can call `self.extract_source_url()`
from shared methods; a subclass can call `super().extract_source_url()`
and add normalization on top; a new ecosystem (Go, Rust) overrides only
what is different. This is meaningfully better than module-level functions,
which the base class cannot call at all.

Note that making these `@staticmethod` on the *subclass* would not achieve
this: `@staticmethod` methods are not called polymorphically by the base
class. The value comes specifically from them being instance methods on
the *base class*.

This also connects directly to `PackageManifest` (Phase 4): if
`read_manifest()` calls `self.extract_source_url()` and
`self.extract_license()`, those overridable seams make it natural to
build a `PackageManifest` incrementally with ecosystem-specific steps.

**Case 3: ecosystem-specific helpers** with no cross-ecosystem equivalent:
`_find_dist_info()`, `_parse_metadata()`, `_load_package_json()`,
`_parse_npm_date()`, `_get_pkg_file()`. These stay inside the subclass as
regular instance methods (not `@staticmethod`). Moving from module-level
function to instance method is a small improvement: it makes them callable
as `self._find_dist_info()` without an import, and establishes them
clearly as part of the class rather than loose module utilities.

### Pros

- **Name accuracy**: `PythonAnalyzer` is unambiguously the agent that
  analyzes Python packages. A new contributor reading
  `class PythonAnalyzer(EcosystemAnalyzer)` immediately understands the
  design without needing to know what "hooks" means here.
- **Template method pattern**: Cross-cutting helpers as base class methods
  let shared code call `self.extract_source_url()`, let subclasses refine
  with `super()`, and let new ecosystems override only what differs.
- **Threshold overridability**: Class-level attributes like
  `SETUP_PY_WARN_BYTES` can be tightened in a subclass or in tests
  without patching call sites. Consistent with the base class pattern.
- **Self-contained classes**: With all helpers inside the class hierarchy,
  each `PythonAnalyzer`, `RubyAnalyzer`, `JavaScriptAnalyzer` is fully
  self-contained. There is no parallel set of module-level functions to
  discover and maintain.

### Cons

- **Churn with no behavior change for Step 1**: Every `import hooks_python`,
  every `hooks.ECOSYSTEM`, every `shared.EcosystemHooks`, and every
  `.Hooks(registry_url=...)` in `dep_review.py` needs updating. The
  `REGISTRY_TO_HOOKS` map, SKILL.md, and documentation also change.
- **Discovery mechanism requires a design decision**: The current pattern
  `importlib.import_module(hooks_module).Hooks(registry_url=...)` relies
  on all subclasses being named `Hooks`. With named subclasses, `dep_review`
  can no longer assume the class name. The cleanest fix is a module-level
  alias in each hook file:
  ```python
  Analyzer = PythonAnalyzer   # used by dep_review.py for instantiation
  ```
  Then `dep_review.py` does `.Analyzer(registry_url=...)` uniformly.
  One line per module; no factory function needed.
- **Step 2 is larger than Step 1**: Moving helpers and threshold constants
  into the class touches more lines per file, though each change is
  mechanical. Doing one file per commit keeps it reviewable.
- **File renames break tests**: `test_doctests.py` imports `hooks_ruby`
  by name. File renames require updating the test file and any direct
  references in documentation or tooling.
- **File renames break git blame**: `git blame analyzer_python.py` only
  shows history from the rename commit forward; prior blame requires
  `git log --follow`.

### Plan (if we proceed)

Split into four commit groups to keep each reviewable in isolation:

**Step 1: rename the base class and all subclasses (one commit)**

  - `EcosystemHooks` -> `EcosystemAnalyzer` in `analysis_shared.py`.
  - `class Hooks(shared.EcosystemHooks)` -> `class PythonAnalyzer
    (shared.EcosystemAnalyzer)` (and analogously for Ruby and JS).
  - Add `Analyzer = PythonAnalyzer` (etc.) at module level in each file
    so `dep_review.py` can instantiate via `.Analyzer(registry_url=...)`.
  - Update `dep_review.py`: rename the local variable `hooks` to
    `analyzer`; change `.Hooks(registry_url=...)` to
    `.Analyzer(registry_url=...)`; update `shared.EcosystemHooks`
    references.
  - Update SKILL.md and any documentation that names the class.
  - No file renames; no helper migration yet.
  - Two find-and-replace passes and a few targeted edits; large diff
    but entirely mechanical and easily verified.

**Step 2: restructure module-level code (one commit per hook file)**

  For each hook file (`hooks_python.py`, `hooks_ruby.py`, `hooks_js.py`):

  a. Move threshold constants to class-level attributes, updating
     call sites from `_CONSTANT` to `self.CONSTANT`.

  b. Add cross-cutting helpers as overridable instance methods on
     `EcosystemAnalyzer` with a default implementation (usually
     returning `''` or equivalent). Override in each subclass.
     Primary targets:
     - `extract_source_url(self, raw_data) -> str`
     - `extract_license(self, raw_data) -> str`
     - `unpack_archive(self, ...)` (unifies `_unpack_pkg`,
       `_unpack_tgz`, and Ruby's inline unpacking)

  c. Move ecosystem-specific helpers to regular instance methods on
     the subclass (e.g., `self._find_dist_info()`,
     `self._parse_metadata()`).

  d. Update `read_manifest()` to call `self.extract_source_url()` and
     `self.extract_license()` instead of module-level functions.
     This sets up the template method structure that `PackageManifest`
     (Phase 4) will build on.

**Step 3: rename the files** (separate commit, own PR if preferred)

  - `git mv hooks_python.py analyzer_python.py` (and analogously for
    ruby and js).
  - Update `dep_review.py`'s `REGISTRY_TO_HOOKS` map values.
  - Update `scripts/tests/test_doctests.py` (imports `hooks_ruby` by
    name).
  - Commit the renames alone so `git log --follow` works cleanly and
    reviewers can confirm the commit contains only renames.

### Is it worth it?

**Step 1 (rename)**: Yes. The name is genuinely wrong and compounds with
time. `PythonAnalyzer` is self-documenting; `Hooks` requires explanation.
The churn is real but one-time and mechanical.

**Step 2 (restructure)**: Yes, with the nuance that the value comes
primarily from the cross-cutting base class methods (Case 2) and the
threshold constants (Case 1). Moving ecosystem-specific helpers into the
subclass as instance methods (Case 3) is a smaller but still positive
change: it makes the class self-contained and removes the artificial
module/class split. None of this changes behavior; all of it makes the
class hierarchy easier to extend and understand.

**Step 3 (file renames)**: Optional and low-urgency. The class names carry
the meaning; the file names are secondary. Defer until there is another
reason to touch the files heavily.

### Interaction with PackageManifest (Phase 4)

Do Step 2b (cross-cutting helpers as base class methods) before or
alongside `PackageManifest`. The template method structure created in
Step 2 provides the natural seams for `PackageManifest` to slot into:
`read_manifest()` calls `self.extract_source_url()` and
`self.extract_license()`, and those results populate `PackageManifest`
fields. Doing Step 1 (rename) before Phase 4 also keeps the
`PackageManifest` diff clean.

## 6. Implementation Roadmap

All planned phases are complete as of 2026-05-23.

1.  **Phase 1** (done, commit 30a25dd): Add `BASE_DANGEROUS_PATTERNS` to
    `EcosystemAnalyzer`. Each analyzer file removed its shared entries and
    calls `all_dangerous_patterns()`. Immediate structural win, no behavior
    change.

2.  **Phase 2** (done, commit ebfdd07): Promote SLSA provenance and velocity
    checks to base class. `check_provenance()` and `check_publisher_velocity()`
    now live on `EcosystemAnalyzer`; `analyzer_js.py` populates `_provenance`
    and `_publisher_stats` dict keys; `dep_review.py` calls the shared methods.

3.  **Phase 3a** (done, commit a2952c5): Renamed `EcosystemHooks` to
    `EcosystemAnalyzer` and `class Hooks` to `PythonAnalyzer`,
    `RubyAnalyzer`, `JavaScriptAnalyzer`.

4.  **Phase 3b** (done, commits 597515a/093309a/7b704a5): Moved module-level
    code into the class hierarchy. One commit per file. Threshold constants
    became class-level attributes; cross-cutting helpers became overridable
    base class methods; ecosystem-specific helpers became instance methods.

5.  **Phase 3c** (done, commit 1844ce6): Renamed the files from
    `hooks_*.py` to `analyzer_*.py`.

6.  **Phase 4** (done, commit 6d61353): Introduced `PackageManifest`
    dataclass. `read_manifest()` returns typed data; all `manifest.get(...)`
    calls replaced with attribute access.

7.  **Phase 5** (done, commit ec6d621): Bundled `write_signals()` inputs
    into `SignalContext`. Signature is now `(ctx: SignalContext, p: Printer)`.

8.  **Phase 6** (done, commit f94e9cb): Added `SignalReport` output struct.
    `write_signals()` returns it; caller writes `signals.json` alongside
    `signals.txt`. `_parse_signals()` reads JSON first, falls back to text
    for pre-existing results.

Remaining optional item: **B2** (`evaluate_health()` as a virtual method on
`EcosystemAnalyzer`) is minor and low-urgency; the current function-based
approach in `analysis_shared.py` works correctly.
