# Simplifications: Phase 3 Proposals

The three analyzer subclasses total ~4,668 lines.
The proposals below are based on reading the actual code, not hypotheticals.
Each is assessed skeptically: only included if it genuinely reduces lines,
makes adding a new ecosystem analyzer easier, or propagates a fix to all
ecosystems automatically.

Savings estimates are net (after adding the base-class helper).

---

## Proposal A: Extract the Levenshtein check loop into a base class helper

**What:** `check_alternatives` in all three analyzers contains nearly
identical loop bodies that appear 2-3 times each:

```python
dist = shared.levenshtein(pkg_lower, name_lower)
if dist == 1:
    concerns.append(f'NEAR_MATCH(dist=1): "{pkgname}" is one edit from X "{name}". ...')
elif dist == 2:
    notes.append(f'NEAR_MATCH(dist=2): ...')
```

Add a base class helper:

```python
def _lev_check(
    self,
    pkgname: str,
    candidates: list[str],
    label: str,
    concerns: list[str],
    notes: list[str],
) -> None:
    pkg_lower = pkgname.lower()
    for name in candidates:
        dist = shared.levenshtein(pkg_lower, name.lower())
        if dist == 1:
            concerns.append(
                f'NEAR_MATCH(dist=1): "{pkgname}" is one edit'
                f' from {label} "{name}". Classic typosquat pattern.')
        elif dist == 2:
            notes.append(
                f'NEAR_MATCH(dist=2): "{pkgname}" is two edits'
                f' from {label} "{name}".')
```

Each subclass `check_alternatives` then calls `self._lev_check(...)` for
each name set (stdlib/installed/builtins, then lockfile deps).

**Also:** The D2 prefix/suffix stripping block is structurally identical
across all three files (same loop logic, only the prefix/suffix list differs).
Move the loop to the base class; each subclass provides:

```python
def _name_strip_rules(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return ('python-', 'py-', 'pypi-'), ('-python', '-py')
```

**Files affected:** `analyzer_python.py:1280-1416`, `analyzer_ruby.py:1053-1175`,
`analyzer_js.py:1328-1462`

**Estimated net savings:** 50-65 lines across the three files.

**Pros:**
- Any fix or improvement to the distance logic applies to all ecosystems.
- Adding a 4th ecosystem gets the check for free: subclass provides the
  name lists and strip rules, base class does the rest.
- The exact/near/lockfile distinction stays in subclasses where
  ecosystem-specific context belongs.

**Cons:**
- The message text currently varies slightly per ecosystem (e.g.
  "stdlib module" vs "installed gem" vs "built-in"), so the `label`
  parameter must carry that. Slightly less tailored messages.
- Small increase in base class size (~25 lines).

**Verdict: Worth doing.**

---

## Proposal B: Template method for `reproducible_build`

**What:** All three `reproducible_build` methods share an identical skeleton:

1. Print header and sandbox name.
2. Return SKIPPED if no `work/source` dir.
3. Get runtime version (`python3 --version`, `ruby --version`,
   `npm --version`).
4. Locate the build manifest in the source clone.
5. Determine the container image tag from the runtime version.
6. Run `shared.run_sandboxed(...)` with the build command.
7. Find the built artifact in the output directory.
8. Unpack it, then call `shared.deep_source_comparison()` and
   `shared.finish_reproducible_build()`.

Steps 1, 2, 6, 8 are word-for-word identical. Steps 3-5, 7 differ only
in the specific command and filename.

Move the skeleton to the base class as a template method. Each subclass
provides three small hooks:

```python
def _get_runtime_version(self) -> str:       # e.g. run 'ruby --version'
def _locate_build_manifest(
    self, clone_dir: Path) -> Path | None:   # find *.gemspec / pyproject.toml
def _run_ecosystem_build(
    self,
    clone_dir: Path,
    built_dir: Path,
    sandbox: str,
    p: Printer,
) -> Path | None:                            # run build; return artifact path
```

**Files affected:** `analyzer_python.py:1526-1650`,
`analyzer_ruby.py:1222-1360`, `analyzer_js.py:1529-1655`

**Estimated net savings:** 60-80 lines across the three files.

**Pros:**
- The comparison and classification logic (`deep_source_comparison`,
  `finish_reproducible_build`, `classify_repro_diffs`) is in one place.
  A fix there automatically applies to all ecosystems.
- A new ecosystem analyzer gets reproducible-build support by implementing
  three small methods.

**Cons:**
- The hooks must cover enough variation. Python builds to a `.whl`, Ruby to
  a `.gem`, JS to a `.tgz`; each needs different unpacking inside
  `_run_ecosystem_build`. The hook is therefore not trivial.
- If a new ecosystem needs a step not in the skeleton (e.g., a two-phase
  build), the template becomes awkward. The current one-method-per-ecosystem
  approach is easier to diverge.

**Verdict: Worth doing, but implement the three hooks first as stubs and
verify the skeleton compiles cleanly before removing the per-ecosystem
copies.**

---

## Proposal C: Move `get_old_license` and `get_old_dep_lines` to base class

**What:** These methods exist in all three analyzers and are thin wrappers
that re-parse the old version's manifest. In all cases they:

1. Check that `old_unpacked_dir` exists.
2. Call the subclass manifest reader.
3. Extract license or dep lines from the result.

The base class already calls `read_manifest()` (abstract); it can provide
default implementations of `get_old_license` and `get_old_dep_lines` that
call `read_manifest()` on the old directory.

**Files affected:** `analyzer_python.py:799-845`,
`analyzer_ruby.py:614-660`, `analyzer_js.py:792-826`

**Estimated net savings:** 30-40 lines.

**Pros:**
- Three near-identical methods collapse to one.
- New ecosystems get them for free.

**Cons:**
- Ruby's `get_old_dep_lines` parses the gemspec differently from how
  `read_manifest` works (it calls `read_manifest` indirectly but with
  different fallback logic). Verify that the Ruby path works before
  removing the override.

**Verdict: Worth doing, but verify Ruby carefully.**

---

## Proposal D: Abstract `_name_normalization` for lockfile search

**What:** Python has `_detect_lockfile_format` + `_dep_in_lockfile`
(58 lines); JS has the same pair (33 lines). Ruby does not use this pattern.
The two implementations share:
- Format detection by filename.
- Name normalization before searching.
- Format-specific regex or JSON key search.

The format detection could move to the base class as a helper that takes
a `dict[str, str]` of `{filename_suffix: format_name}`, leaving only the
per-ecosystem regex patterns in the subclass.

**Files affected:** `analyzer_python.py:1116-1157`,
`analyzer_js.py:1153-1187`

**Estimated net savings:** 10-20 lines (modest; the format dispatch tables
are already small).

**Pros:** New ecosystem gets format detection for free by providing the
dispatch table.

**Cons:** Python and JS lockfile formats are sufficiently different that
the search patterns stay in each subclass anyway. The savings are small and
the abstraction adds indirection.

**Verdict: Low priority. Do only after A, B, C are done.**

---

## What was considered and rejected

**Unified download/unpack:** Previously decided against (Phase 2 notes).
Python's `unpack_archive` returns a `dist_type` string; JS returns a bool;
Ruby delegates to `gem unpack`. Incompatible signatures. Not revisited here.

**Registry data fetching:** JS `fetch_all_registry_data` is ~246 lines;
Python is ~151; Ruby is ~163. JS adds Sigstore provenance and publisher
velocity checks that the other two do not have. The common parts (age
extraction, license extraction, Printer formatting) are ~20-30 lines;
unifying them adds base-class complexity for modest per-file savings and
risks breaking the JS extras. Not recommended.

**`Patterns` class or `itertools.chain`:** Pattern lists are small (~20
items), already pre-compiled at module level where it matters. No benefit.

**Exceptions instead of `failures` list:** The `failures` list accumulates
non-fatal partial errors while analysis continues. Replacing it with
exceptions would require try/except around every individual step to preserve
this behavior, adding more lines than it removes.

**Composition over inheritance:** Would require introducing several new types
(`RegistryHandler`, `Downloader`, `PatternList`) and wiring them together.
The current inheritance model is well-understood and the subclass overrides
are already small. Not recommended.

---

## Summary

| Proposal | Net savings | Benefit to new ecosystems | Effort |
|---|---|---|---|
| A: Levenshtein helper + strip rules | 50-65 lines | High: typosquat check is free | Low |
| B: `reproducible_build` template | 60-80 lines | High: implement 3 small hooks | Medium |
| C: `get_old_license/dep_lines` to base | 30-40 lines | High: free | Low |
| D: Lockfile format dispatch | 10-20 lines | Low: search patterns still in subclass | Low |

Recommended order: C (safest, smallest), A, B, D.

Total expected reduction: ~140-200 lines from the analyzer files,
partially offset by ~50 lines added to the base class.
