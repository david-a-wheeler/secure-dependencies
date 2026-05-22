# Proposed Code Simplifications for Dependency Analysis

This document outlines a variety of ways to simplify the dependency analysis codebase, reduce technical debt, and improve maintainability across ecosystems. The primary focus is on reducing the extreme complexity of `dep_review.py` and the redundancies in the ecosystem hooks (`hooks_js.py`, `hooks_python.py`, `hooks_ruby.py`).

## 1. Summary of Current Issues

*   **Monolithic Reporting**: `write_signals()` in `dep_review.py` is nearly 1,900 lines long. It manually handles every single data point, flag, and concern, making it extremely difficult to review and extend.
*   **Massive Redundancy**: Ecosystem hooks repeat dozens of high-level dangerous and diff patterns (e.g., IDE config writes, cloud secret APIs, exfiltration relays).
*   **Fragmented Logic**: Advanced security checks (like SLSA provenance and publisher velocity) are currently JS-only, even though they are conceptually universal.
*   **Complex Argument Passing**: The driver passes 30+ arguments to `write_signals()`, leading to fragile interfaces.

## 2. Proposed Architectural Changes

### A. Introduce a `SignalAccumulator` Class
Instead of a giant function that prints line-by-line, we should use an object that accumulates findings and knows how to report them.

**Example Implementation (`analysis_shared.py`):**

```python
class SignalAccumulator:
    def __init__(self, hooks: EcosystemHooks):
        self.hooks = hooks
        self.data = {}        # Neutral objective data (size, version, etc.)
        self.alerts = []      # [!] High-urgency binary security triggers (e.g. SCAN_MATCHES)
        self.warnings = []    # [?] Contextual health concerns (e.g. STALE_PACKAGE)
        self.positives = []   # [v] Positive signals (e.g. MFA_ENABLED, REPRODUCED)

    def add_data(self, key: str, value: Any):
        """Add neutral objective data for the AI's core context."""
        self.data[key] = value

    def add_alert(self, flag: str):
        """Trigger a binary security alert."""
        self.alerts.append(flag)

    def add_warning(self, label: str, value: str, annotation: str):
        """Add a contextual health warning with an explanatory annotation."""
        self.warnings.append((label, f"{value}  [{annotation}]"))

    def write_report(self, p: Printer):
        # 1. Neutral Data first (The Foundation)
        p("=== Data & Metadata ===")
        for k, v in self.data.items():
            p(f"{k}: {v}")

        # 2. Alerts (The Critical Red Flags)
        p("\n=== Security Alerts ===")
        # ... logic to write [!] alerts ...

        # 3. Warnings (The Contextual Evidence)
        p("\n=== Health Warnings ===")
        # ... logic to write [?] warnings ...
```

**Example (Using the new terminology):**

```python
acc.add_data("package_size_bytes", 102456)
acc.add_alert("NATIVE_EXTENSION")
acc.add_alert("SCAN_MATCHES(2)")
acc.add_warning("last_release", "730 days ago", "exceeds 18-month threshold")
```
```

**Example (Accumulating diverse data types):**

```python
acc.add_data("package_size_bytes", 102456)
acc.add_data("publish_date", "2026-05-22")
acc.add_data("has_native_code", True)
acc.add_data("author_count", 3)
```
```

### B. Declarative Hook & Pattern Registration
Instead of manual list concatenation and hardcoded maps in `dep_review.py`, use a decorator-based registry where the base class provides **concrete security policies** that subclasses can extend.

**Example (`analysis_shared.py`):**

```python
class EcosystemHooks(ABC):
    # Default thresholds and base patterns
    STALE_THRESHOLD_DAYS = 548
    BASE_DANGEROUS_PATTERNS = [('exfil-relay', EXFIL_RELAY_DOMAINS_RE)]

    def evaluate_health(self, acc: SignalAccumulator, registry_data: dict):
        """Universal health policy. Subclasses override and call super() to extend."""
        days = registry_data.get('last_release_days')
        if days and days > self.STALE_THRESHOLD_DAYS:
            acc.add_warning('last_release', f"{days} days ago", "exceeds threshold")

class SignalAccumulator:
    def __init__(self, hooks: EcosystemHooks):
        self.hooks = hooks
        # ... categories as defined in 2A ...
```

**Example Hook Override (`hooks_js.py`):**

```python
@shared.EcosystemRegistry.register('javascript')
class Hooks(shared.EcosystemHooks):
    STALE_THRESHOLD_DAYS = 365  # JS specific threshold

    def evaluate_health(self, acc: SignalAccumulator, registry_data: dict):
        # 1. Run the universal checks (stale, etc.)
        super().evaluate_health(acc, registry_data)

        # 2. Add JS-specific checks (e.g. publisher velocity)
        if self._has_velocity_anomaly(registry_data):
            acc.add_warning('publisher_velocity', 'ANOMALOUS', 'high release volume')
```

**The Simplification Win:**
*   **Standard Idiomatic Python**: No "magic" callbacks or unusual naming conventions. Every Python developer knows how `super()` works.
*   **Encapsulation**: The policy lives with the ecosystem it belongs to, but common ground is shared automatically.
*   **Clean Driver**: The driver just calls `acc.hooks.evaluate_health(acc, data)`, and the right thing happens regardless of the ecosystem.

### C. Standardized Manifest Data Objects
Instead of returning giant dictionaries with 15+ keys from `read_manifest()`, use a `dataclass`. This provides type safety and prevents "key-name drift" between ecosystems.

**Example (`analysis_shared.py`):**

```python
@dataclass
class PackageManifest:
    source_url: str = ""
    extensions: str = "NO"
    executables: str = "NO"
    runtime_deps: list[str] = field(default_factory=list)
    license_raw: str = ""
    # ... etc
```

### D. Generalized Registry/Provenance Checks
Move "Idea 14-16" checks (publisher velocity, SLSA provenance, repo metadata) to `analysis_shared.py` so all ecosystems benefit.

**Example (`analysis_shared.py`):**

```python
def check_publisher_velocity(p: Printer, registry_data: dict):
    # Move the JS-only logic here and make it use
    # standardized registry_data fields.
```
## 3. Specific Simplification Examples

The "Proposed" implementation in `analysis_shared.py` might look slightly longer for a *single* check, but the goal is to simplify the **Hook Code** and the **Driver Code**, which are the parts we expect to grow.

### Example: Consolidating Registry Logic
Currently, every ecosystem (JS, Python, Ruby) has to "know" our security policies (e.g., that 18 months is the stale threshold).

**Current (Code repeated in every hook or the driver):**
```python
# Hook/Driver must remember the threshold, label, and exact annotation string
_last_rel = registry.get('last_release_days')
if _last_rel is not None and _last_rel > 548:
    _concerns.append(('last_release', f'{_last_rel} days ago [exceeds 18-month...]'))
# ... then repeat this pattern for 40 other flags ...
```

**Proposed (Hook Code becomes a single line):**
```python
# The hook developer doesn't need to know the policy. They just pass the data.
shared.evaluate_health(registry, accumulator)
```

**The Simplification Win:**
*   **Centralized Policy**: If we decide to change the "stale" threshold from 18 to 24 months, we change it in **one** place in `analysis_shared.py`, and all 10+ ecosystems (JS, Python, Ruby, etc.) are updated automatically.
*   **Reduced Hook Complexity**: The hook for a new ecosystem (e.g., Go or Rust) becomes a simple "data provider" rather than having to re-implement 40+ security checks.
*   **Collapsing `dep_review.py`**: The giant `write_signals` function (1,900 lines) is replaced by a few dozen calls to these shared evaluators.

### Example: Eliminating Fragile Argument Lists
Currently, the interface between the driver and the reporting logic is extremely "wide" and fragile.

**Current (`dep_review.py`):**
```python
# The function signature has 35+ arguments.
# Adding ONE signal requires changing this and the call site.
def write_signals(
    work, p, pkgname, old_ver, new_ver, diff_mode, deeper, sha256, manifest,
    scan_details, total_matches, diff_scan_details, diff_scan_matches,
    clone_ok, version_tag, commit_guessed, source_url, badge, # ... and 15 more
):
```

**Proposed:**
```python
# The interface is "narrow" and stable.
def write_signals(accumulator: SignalAccumulator):
    # The accumulator already contains all findings gathered during the run.
```

## 4. Expected Benefits

1.  **Reduced LOC**: `dep_review.py` could likely be reduced from 2,400 lines to under 1,000.
2.  **Universal Features**: Every ecosystem will automatically get features like SLSA provenance and velocity checks.
3.  **Easier Review**: Adding a new security check will involve adding a single entry to a list or a small helper function, rather than modifying a 1,900-line monolithic block.
4.  **Consistency**: The format of `signals.txt` will be more consistent across ecosystems because it's generated by shared code.

## 6. Terminology Shift: From "Risks" to "Alerts & Warnings"

This refactor introduces a deliberate shift in terminology to better reflect the role of these signals in the security assessment:

*   **Old Model**: Used "Risks" and "Concerns" somewhat interchangeably, which was confusing and conflated **findings** with the **final assessment**.
*   **New Model (Alert Model)**: Uses **Data**, **Alerts**, and **Warnings**.
    *   These are the **inputs** to the risk determination process.
    *   An "Alert" (like a scan match) or a "Warning" (like a stale package) is a piece of evidence.
    *   The **Risk Assessment** (LOW/MEDIUM/HIGH/CRITICAL) remains the **output**—the final judgment made by the AI after weighing all these inputs.

This separation of "finding" from "judgment" makes the system's logic clearer and more aligned with professional security auditing workflows.

## 8. Simplification Metric: Why the Refactor Overhead is Worth It

While this reorg adds a few new classes and methods, it is a net win for the following reasons:

1.  **Deduplication (Radical Line Count Reduction)**: The current 1,900-line monolith contains dozens of near-identical `if/elif` blocks for checking thresholds. By parametersizing these in shared evaluators, we eliminate hundreds of lines of redundant string-formatting and annotation boilerplate.
2.  **Cost of Extension**:
    *   **Current**: Adding a new ecosystem (e.g., Go) requires adding hundreds of lines of logic to both the hook and the driver's monolithic reporter.
    *   **Proposed**: Adding a new ecosystem adds **zero** lines to the shared reporting logic. The hook only provides the raw data.
3.  **Narrow Interfaces**: Replacing a 35+ argument function with a single `SignalAccumulator` object makes the code radically easier to test and debug. You can test a single security policy (like `evaluate_health`) in isolation without setting up the entire driver state.

The goal is not just to "move" the 1,900 lines, but to **collapse** the redundant parts and **isolate** the ecosystem-specific parts, making the system's "surface area for bugs" much smaller.

## 9. Implementation Roadmap

1.  **Phase 1**: Move Idea 14-16 checks (publisher velocity, SLSA provenance, repo metadata) to `analysis_shared.py`. This provides immediate value by enabling these advanced checks for all ecosystems, regardless of whether the larger refactor proceeds.
2.  **Phase 2**: Extract universal `DANGEROUS_PATTERNS` and `DIFF_PATTERNS` into `analysis_shared.py`.
3.  **Phase 3**: Implement the `SignalAccumulator` and migrate the first 10-20 flags from `write_signals()` to use the new structured reporting.
4.  **Phase 4**: Refactor `dep_review.py` main loop and `EcosystemHooks` to use the new registry and narrowed interfaces.
5.  **Phase 5**: Update all remaining ecosystem hooks to use the new simplified patterns and data objects.
