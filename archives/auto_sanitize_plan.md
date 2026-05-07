# Auto-Sanitization Refactor Plan

## Goals

1. **Automatic sanitization.** Adversarial content (bidi overrides, zero-width
   characters, C0/C1 controls, prompt-injection text) must be stripped from
   every byte that reaches an AI-readable output file. Today that relies on
   developers calling `sanitize_line()` on each individual value; a single
   forgotten call is a gap. After this change, sanitization is in the
   infrastructure, not the call sites.

2. **Code reduction.** Every function that writes a structured output file
   currently follows the same three-part boilerplate:
   - `lines: list[str] = []` at the top
   - many `lines.append(f'... {sanitize_line(x)} ...')` calls in the middle
   - `(work / 'file.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')`
     at the bottom

   This pattern appears in roughly 25 functions across ~10,000 lines of
   scripts. The refactor eliminates all three parts from each function.

3. **Separation of concerns.** Functions currently decide both *what* to output
   and *where* it goes (which file under `work/`). After the change, functions
   decide what to output; callers decide where it goes. This makes each
   function independently testable by injecting `Printer(io.StringIO())`.

4. **No new dependencies.** `Printer` uses only the stdlib and the existing
   `sanitize()` function already in `analysis_shared.py`.

---

## What we are changing

### From (current pattern)

```python
def lookup_openssf_badge(source_url, pkgname, work: Path, ...) -> dict:
    badge_lines = [
        f'=== OpenSSF Best Practices Badge: {pkgname} ===',
        f'SOURCE_URL_QUERIED: {sanitize_line(source_url)}',
        f'BADGE_FOUND: {"yes" if result["found"] else "no"}',
    ]
    if result['found']:
        badge_lines.extend([
            f'BADGE_PROJECT_ID: {sanitize_line(str(result["id"]))}',
            f'BADGE_LEVEL (metal): {sanitize_line(str(result["level"]))}',
        ])
        if result['tiered']:
            badge_lines.append(
                f'METAL_TIERED_PERCENTAGE: {result["tiered"]}'
                ' (passing=100, silver=200, gold=300)'
            )
    (work / 'badge-status.txt').write_text(
        '\n'.join(badge_lines) + '\n', encoding='utf-8'
    )
```

### To (new pattern)

```python
def lookup_openssf_badge(source_url, pkgname, p: Printer, ...) -> dict:
    p(f'=== OpenSSF Best Practices Badge: {pkgname} ===')
    p(f'SOURCE_URL_QUERIED: {source_url}')
    p(f'BADGE_FOUND: {"yes" if result["found"] else "no"}')
    if result['found']:
        p(f'BADGE_PROJECT_ID: {result["id"]}')
        p(f'BADGE_LEVEL (metal): {result["level"]}')
        if result['tiered']:
            p(f'METAL_TIERED_PERCENTAGE: {result["tiered"]} (passing=100, silver=200, gold=300)')
```

Caller:

```python
with Printer(work / 'badge-status.txt') as p:
    badge = lookup_openssf_badge(source_url, pkgname, p, ...)
```

### Key differences per call site

| Before | After |
|--------|-------|
| `lines: list[str] = []` | removed |
| `lines.append(f'k: {sanitize_line(v)}')` | `p(f'k: {v}')` |
| `lines.extend([...])` | one `p(...)` call per item |
| multi-line string concat in append | single `p(f'...')` line |
| `write_text('\n'.join(lines)+'\n', ...)` | removed (Printer handles it) |
| `work: Path` parameter (for output) | `p: Printer` parameter |
| explicit `sanitize_line()` on each value | automatic inside `Printer.__call__` |

---

## The Printer class

Add to `analysis_shared.py`, immediately after the existing `sanitize_line`
function (they are logically related: Printer is the output-layer consumer of
sanitize).

```python
class Printer:
    """Write-through, auto-sanitizing printer. Call like print().

    Pass a Path (opens and owns the file), a file object such as sys.stdout
    or io.StringIO() (does not close it), or nothing (defaults to sys.stdout).

    Every call sanitizes all output via sanitize(), which strips adversarial
    characters (bidi overrides, zero-width chars, C0/C1 controls) while
    preserving newlines within multi-line blocks.

    Use as a context manager to ensure owned files are closed:
        with Printer(work / 'out.txt') as p:
            p('line one')
            p(f'value: {external_data}')
    """

    def __init__(self, dest: 'Path | IO[str]' = sys.stdout) -> None:
        if isinstance(dest, Path):
            self._f: IO[str] = dest.open('w', encoding='utf-8')
            self._owned = True
        else:
            self._f = dest
            self._owned = False

    def __call__(self, *args: object, sep: str = ' ', end: str = '\n') -> None:
        self._f.write(sanitize(sep.join(str(a) for a in args)) + end)

    def close(self) -> None:
        if self._owned:
            self._f.close()

    def getvalue(self) -> str:
        """Return accumulated output; only valid for StringIO-backed Printers."""
        return self._f.getvalue()  # type: ignore[attr-defined]

    def __enter__(self) -> 'Printer': return self
    def __exit__(self, *_: object) -> None: self.close()
```

**Why `sanitize()` and not `sanitize_line()`:** `sanitize()` preserves
newlines, which allows a single `p(...)` call to emit a legitimately
multi-line block (install scripts, diffs, commit lists). `sanitize_line()`
would collapse those to spaces. Since each call to `p(...)` is already a
deliberate unit of output, stripping newlines at the Printer level would
destroy structure rather than protect it.

**Existing `sanitize_line()` calls** at individual call sites become
redundant but harmless after this change. They can be removed gradually or
left as documentation of intent; either is correct.

**Imports:** `dep_review.py` and each hook file will need:
```python
from analysis_shared import Printer
```
Add this alongside the existing `from analysis_shared import ...` line in each
file. `analysis_shared.py` itself needs no import change since `Printer` is
defined there.

---

## The raw-file convention (do not change these)

Files whose names begin with `raw-` (`raw-git-clone-output.txt`,
`raw-diff-full.txt`, `raw-pkg-paths.txt`, etc.) are intentionally written
without sanitization. The AI is explicitly instructed never to read them.
All writes to raw files stay as plain `path.write_text(...)` calls.

**Rule:** if the filename starts with `raw-`, use `write_text`. If it does
not, use `Printer`. This is already visible as a naming convention in the
codebase; the refactor makes it structurally enforced.

---

## Functions to convert

### analysis_shared.py (standalone functions)

These are pure-output functions. They lose `work: Path` and gain `p: Printer`.
Their callers in `dep_review.py` create the Printer inline.

| Function | Output file | Raw files (keep write_text) |
|----------|-------------|----------------------------|
| `blind_scan` | `summary-scan-{label}.txt` | `raw-scan-{label}.txt` |
| `lookup_openssf_badge` | `badge-status.txt` | `raw-badge-search.json`, `raw-badge-data.json` |
| `count_recent_commits` | `recent-commits.txt` | none |
| `lookup_vulnerabilities` | `vulnerabilities.txt` | none |
| `check_security_policy` | `security-policy.txt` | none |
| `detect_binary_files` | `binary-files.txt` | `raw-binary-in-package.txt` |
| `compare_pkg_vs_source` | `extra-in-package.txt` | `raw-pkg-paths.txt`, `raw-src-paths.txt`, `raw-extra-in-package.txt` |
| `detect_sandbox` | `sandbox-detection.txt` | none |
| `lookup_oss_rebuild` | `oss-rebuild.txt` | none |
| `write_transitive_deps` | `transitive-deps.txt` | `raw-transitive-deps.txt` |
| `write_alternatives` | `alternatives.txt` | none |
| `lookup_ecosystems_package` | `raw-ecosystems.json` (already raw, no change) | — |

**`clone_source_repo` is a special case.** It both writes output *and*
creates the `work/source/` subdirectory for the git clone. It keeps a
`source_dir: Path` parameter for the filesystem work but gains `p: Printer`
for output. The caller passes `work / 'source'` for the directory and
`Printer(work / 'clone-status.txt')` for output.

**`finish_reproducible_build`, `compare_repro_sha256`, `classify_repro_diffs`**
currently accept `lines: list` as a shared accumulator parameter. These
become `p: Printer` parameters instead.

### dep_review.py (pure-output functions)

These functions exist solely to write non-raw output files. They drop
`work: Path` entirely and take only `p: Printer` plus their data parameters.

| Function | Output file |
|----------|-------------|
| `write_signals` | `signals.txt` |
| `write_health_file` | `project-health.txt` |
| `write_license_file` | `license.txt` |

**`write_dep_files` is a mixed function** (like `clone_source_repo`). It writes
`raw-deps-new.txt` and `raw-deps-old.txt` directly, so it must keep
`work: Path`. It also writes three non-raw files; those become three `Printer`
parameters (`p_deps`, `p_lock`, `p_reg`), created by its caller:

```python
with (
    Printer(work / 'new-deps.txt') as p_deps,
    Printer(work / 'dep-lockfile-check.txt') as p_lock,
    Printer(work / 'dep-registry.txt') as p_reg,
):
    write_dep_files(work, p_deps, p_lock, p_reg, ...)
```

### hooks_ruby.py, hooks_python.py, hooks_js.py

Hook methods that write output files gain a `p: Printer` parameter (and in
some cases a second printer for a second file). The abstract method signatures
in `EcosystemHooks` are updated accordingly.

| Method | Output file |
|--------|-------------|
| `read_manifest` | `manifest-analysis.txt` (and optionally `install-scripts.txt`) |
| `fetch_all_registry_data` | `provenance.txt` (raw: `raw-registry-*.json`) |
| `get_transitive_deps` | `transitive-deps.txt` (raw: `raw-transitive-deps.txt`) |
| `reproducible_build` | contributes to `deeper-analysis.txt` via shared Printer |

`check_lockfile` and `check_dep_registry` return data dicts and write no
files; they do not change.

---

## Migration order and risk reduction

Perform the migration in phases. Run `python3 -m pytest
references/scripts/tests/` after every phase. All existing doctests and
file-parsing tests must continue to pass.

### Phase 0: Add Printer, add test (zero risk)

1. Add the `Printer` class to `analysis_shared.py` after `sanitize_line`.
2. Add a doctest on `Printer.__call__` verifying sanitization:
   ```python
   >>> import io
   >>> p = Printer(io.StringIO())
   >>> p('hello ‮ world')
   >>> p.getvalue()
   'hello ? world\n'
   ```
3. Run tests. Nothing else changes; this phase cannot break anything.

### Phase 1: Pure-output functions in analysis_shared.py

Convert one function at a time in the order listed in the table above
(simplest first). For each function:

- Change its signature: replace `work: Path` with `p: Printer` (keeping
  any other path params it needs for operations).
- Replace every `lines.append(...)` / `lines.extend([...])` with `p(...)`.
- Delete the `lines: list[str] = []` declaration.
- Delete the final `write_text('\n'.join(lines)+'\n', ...)` call.
- Remove `sanitize_line()` wrappers from values passed to `p(...)`.
- Leave all `raw-*` writes as plain `write_text` calls unchanged.
- Update its callers in `dep_review.py` to create `Printer(work / 'file')`
  and pass it in.
- Run tests.

### Phase 2: Pure-output functions in dep_review.py

Convert `write_signals`, `write_health_file`, `write_license_file` using the
same process as Phase 1. Convert `write_dep_files` as a mixed function
(keeps `work: Path`, gains three Printers). These are the highest line-count
functions; `write_signals` alone removes roughly 40 lines of boilerplate and
eliminates ~30 `sanitize_line()` calls.

The existing `sec()` helper (returns `'\n=== TITLE ==='`) composes naturally:
`lines.append(sec('LICENSE'))` becomes `p(sec('LICENSE'))`. No change to
`sec()` itself.

### Phase 3: Mixed functions (clone_source_repo, deep_source_comparison, etc.)

These keep filesystem-operation parameters and gain `p: Printer`. Because
they have complex branching with multiple early-return points that each
previously wrote the output file, trace carefully: every early-return path
must call `p(...)` before returning rather than accumulating into a list and
writing at the end.

### Phase 4: Hook methods

Convert `read_manifest`, `fetch_all_registry_data`, `get_transitive_deps`,
`reproducible_build` in all three hook files. Update the abstract method
signatures in `EcosystemHooks` last (after all three implementations agree).

---

## Checklist for each function conversion

- [ ] Signature updated: `work: Path` removed (if pure output) or `p: Printer`
      added (if mixed)
- [ ] `lines = []` declaration deleted
- [ ] All `lines.append(...)` converted to `p(...)`
- [ ] All `lines.extend([...])` converted to individual `p(...)` calls
- [ ] Multi-line string concatenations inside append collapsed to single
      `p(f'...')` lines
- [ ] Final `write_text('\n'.join(lines)+'\n', ...)` call deleted
- [ ] All `sanitize_line()` / `sanitize()` wrappers removed from values
      passed to `p(...)` (they are now redundant)
- [ ] All `raw-*` `write_text` calls left unchanged
- [ ] Caller updated to create `Printer(work / 'file.txt')` and pass it
- [ ] `with Printer(...) as p:` used at caller so file is closed on exit
- [ ] Tests pass

---

## Expected outcome

| Metric | Before | Estimated after |
|--------|--------|-----------------|
| Lines in scripts | ~10,362 | ~9,500 (roughly 8% reduction) |
| Explicit `sanitize_line` call sites | ~60 | ~10 (only at non-output boundaries) |
| Functions containing `lines = []` boilerplate | ~25 | 0 |
| Functions that can be unit-tested by injecting `io.StringIO()` | 0 | ~25 |
| Possible "forgot to sanitize" gaps at output | yes | no (structural guarantee) |
