# Proposed Code Simplifications for Dependency Analysis

This document reviews a set of proposed simplifications for the dependency
analysis codebase, with assessments grounded in the actual code state.
The primary focus is reducing complexity in `dep_review.py` and eliminating
structural redundancy across the ecosystem hooks
(`hooks_js.py`, `hooks_python.py`, `hooks_ruby.py`).

## 1. Summary of Current Issues

Actual measurements (as of 2026-05-22):

*   `dep_review.py`: 2,400 lines total; `write_signals()` alone is ~970 lines
    with 47 arguments.
*   `hooks_js.py`: 1,869 lines; `hooks_python.py`: 1,689; `hooks_ruby.py`: 1,415
*   `analysis_shared.py`: 4,003 lines

Real problems worth solving:

*   **Wide interface**: `write_signals()` takes 47 arguments, making it fragile
    to extend and hard to test in isolation.
*   **Structural pattern duplication**: 20 of ~26 DANGEROUS_PATTERNS labels
    appear in all three hook files. The regex bodies reference `shared.XYZ_RE`
    constants, but each hook still re-declares the full entry. A new ecosystem
    (Go, Rust) must copy-paste all 20 shared entries before adding its own.
*   **JS-only advanced checks**: SLSA provenance and publisher velocity checks
    (`_check_slsa_provenance`, `_check_publisher_velocity`) live in
    `hooks_js.py` even though the concepts apply to all ecosystems.

Already solved (do not re-implement):

*   **Health thresholds**: `compute_health_concerns()` in `analysis_shared.py`
    already centralizes all health-concern logic (staleness, age, owner count,
    Scorecard score, etc.). The doc's example of threshold repetition across
    hooks does not reflect current code.
*   **Shared regex constants**: Common patterns are defined as `shared.XYZ_RE`
    and referenced from each hook; the regex bodies are not literally repeated.
*   **`EcosystemHooks` ABC**: Already exists in `analysis_shared.py` with all
    required abstract methods.

## 2. Proposed Architectural Changes

### A. Narrow the `write_signals()` Interface (ACCEPTED, with adjustments)

**Problem**: 47 arguments is genuinely hard to manage. Adding one new signal
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
    hooks: EcosystemHooks
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

#### B1. `BASE_DANGEROUS_PATTERNS` in `EcosystemHooks` (ACCEPTED)

Currently, 20 DANGEROUS_PATTERNS labels are structurally repeated across all
three hook files. Each hook re-declares entries like `exfil-relay-domain`,
`reverse-shell`, `cron-persistence`, etc., even though they reference the
same `shared.XYZ_RE` constant.

Defining `BASE_DANGEROUS_PATTERNS` in the base class means each new ecosystem
only declares its own additions:

```python
class EcosystemHooks(ABC):
    BASE_DANGEROUS_PATTERNS: list[tuple[str, str]] = [
        ('exfil-relay-domain', shared.EXFIL_RELAY_DOMAINS_RE),
        ('reverse-shell',      shared.REVERSE_SHELL_RE),
        ('cron-persistence',   shared.CRON_PERSISTENCE_RE),
        # ... all 20 shared entries ...
    ]
    DANGEROUS_PATTERNS: list[tuple[str, str]] = []  # ecosystem-specific only

    def all_dangerous_patterns(self) -> list[tuple[str, str]]:
        return self.BASE_DANGEROUS_PATTERNS + self.DANGEROUS_PATTERNS
```

This is the most direct win: adding Go or Rust becomes ~5 ecosystem-specific
entries instead of re-copying 25+.

#### B2. `evaluate_health()` virtual method (MINOR, LOW PRIORITY)

The current `compute_health_concerns()` function in `analysis_shared.py`
already centralizes health thresholds, so this is partially done. If an
ecosystem needs to override a threshold (e.g., a different staleness window),
making `evaluate_health()` a virtual method on `EcosystemHooks` with a
`super()` call is cleaner than a separate function with an extra argument.
This is a minor, low-urgency cleanup.

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

### C. Standardized Manifest Data Objects (ACCEPTED, HIGH VALUE)

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

### D. Generalize SLSA Provenance and Velocity Checks (ACCEPTED)

`_check_slsa_provenance()` and `_check_publisher_velocity()` are currently
in `hooks_js.py` only. PyPI has introduced provenance too, so Python could
benefit immediately. The right approach:

1.  Define abstract/optional hook methods in `EcosystemHooks`:

    ```python
    def check_provenance(self, registry_data: dict, p: Printer) -> None:
        pass  # default: no-op

    def check_publisher_velocity(self, registry_data: dict, p: Printer) -> None:
        pass  # default: no-op
    ```

2.  Move the npm-specific implementation to `hooks_js.py` as an override.
3.  Add a PyPI provenance implementation to `hooks_python.py`.
4.  The driver calls `hooks.check_provenance(registry, p)` for all ecosystems.

This is straightforward because the check already lives in a helper function;
it just needs to be called through the right hook dispatch instead of
conditionally in `dep_review.py`.

## 3. Pattern Deduplication: The Actual Opportunity

The Section 3 example in the original proposal used `compute_health_concerns()`
as an example of repeated logic, but that function already exists and
centralizes the health policy. The real remaining duplication is in
`DANGEROUS_PATTERNS`.

Current state:
- 20 pattern labels appear in all 3 hook files
- 2 labels appear in Python + Ruby only (`self-publish`, `shell-exec`)
- 7 labels are Python-only, 3 Ruby-only, 4 JS-only

Moving the 20 shared entries to `BASE_DANGEROUS_PATTERNS` (proposal B1) is
the actual deduplication win here.

## 4. Expected Benefits

1.  **Interface stability**: `write_signals(ctx: SignalContext, p)` can absorb
    new signals without changing the call site.
2.  **Easier new ecosystems**: Go or Rust hooks need only their ~5 unique
    patterns; the 20 shared ones come from the base class automatically.
3.  **Universal provenance**: SLSA and velocity checks become available to all
    ecosystems via hook dispatch.
4.  **Type safety**: `PackageManifest` makes key-name drift a compile-time
    error rather than a runtime KeyError.

## 5. Implementation Roadmap

Ordered by value-to-effort ratio:

1.  **Phase 1**: Add `BASE_DANGEROUS_PATTERNS` to `EcosystemHooks` (proposal
    B1). Each hook removes its 20 shared entries and calls
    `all_dangerous_patterns()`. Immediate structural win, no behavior change.

2.  **Phase 2**: Promote SLSA provenance and velocity checks to hook dispatch
    (proposal D). Move `_check_slsa_provenance` and `_check_publisher_velocity`
    out of the JS-only path in `dep_review.py` and add PyPI provenance.

3.  **Phase 3**: Introduce `PackageManifest` dataclass (proposal C). Migrate
    one hook at a time; this is mechanical but requires touching many callers.

4.  **Phase 4**: Bundle `write_signals()` inputs into `SignalContext` (proposal
    A). Replace the 47-argument signature. This is the highest-impact cleanup
    for `dep_review.py` but requires updating every call site in the driver.

5.  **Phase 5**: Add `SignalReport` output struct if the output structure needs
    to be programmatically consumed (e.g., for structured JSON output).
    Skip if not needed: the current line-by-line printer is fine for AI input.
