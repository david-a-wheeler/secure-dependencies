# Simplify Data Handling: Consolidate to `signals.json`

## What We Are Changing From

`dep_review.py` currently runs deterministic analysis and produces two
parallel outputs:

1. **`signals.txt`** - a large human-readable plain-text report (~17 named
   sections) written via the `Printer` class (which auto-sanitizes output).
2. **`signals.json`** - a compact machine-readable file produced by
   serializing the `SignalReport` dataclass (20 flat scalar fields).

In addition, roughly 20 supporting `.txt` files are written to the work
directory by `dep_review.py` and the ecosystem analyzers:
`manifest-analysis.txt`, `license.txt`, `project-health.txt`,
`clone-status.txt`, `source-url.txt`, `extra-in-package.txt`,
`binary-files.txt`, `diff-semantic.txt`, `source-review.txt`,
`sandbox-detection.txt`, `reproducible-build.txt`, `transitive-deps.txt`,
`new-deps.txt`, `dep-lockfile-check.txt`, `dep-registry.txt`,
`provenance.txt`, `vulnerabilities.txt`, `oss-rebuild.txt`,
`badge-status.txt`, `alternatives.txt`, `package-hash.txt`,
`dist-type.txt`, `old-version-status.txt`, plus
`summary-scan-{LABEL}.txt` (one per scan label).

The tier 2 AI reads `signals.txt` as its primary input, then conditionally
reads up to 15 additional `.txt` files based on flags found in `signals.txt`.
This logic is captured in a complex conditional table in the analysis brief.

`dep_session.py` reads `signals.json` but must then invoke
`_parse_license_line()` and `_parse_health_line()` to decode compact
pipe-delimited strings like `"SPDX: MIT  |  OSI-approved: YES  |  Status: OK"`
that were designed for the text report rather than for machine consumption.

### Problems with the current approach

- Two representations of the same data that can drift out of sync.
- The `SignalReport` dataclass has only 20 flat fields; rich detail lives
  only in `signals.txt`, so machine consumers are second-class.
- Tier 2 has to track which of ~20 files to read under which conditions.
- `dep_session.py` needs fragile text parsers for data it generated itself.
- Adding a new signal requires updating `signals.txt` formatting, the
  `SignalReport` dataclass, and the parsers in `dep_session.py` - three
  separate places.

---

## What We Are Changing To

A single **`signals.json`** file that is both machine-readable and
human-readable (pretty-printed with `indent=2`, organized into named
sections). All the data currently scattered across 20+ `.txt` files is
consolidated into this one file.

**Tier 2 AI reads**: `signals.json` only. Tier 2 does not read
`install-scripts.txt` directly. When `signals.json["manifest"]["has_install_scripts"]`
is true, tier 2 will (in a future step) delegate reading of that file to
a tier 3 AI, whose structured verdict will be added back into
`signals.json` as an `install_scripts_review` section. For now, tier 2
sees only the flag and uses judgment based on the manifest metadata
already in `signals.json`.

**`--deeper` analysis**: reads the existing `signals.json`, adds new
top-level sections (`deeper`, `source_review`), and rewrites the file.
Python 3.7+ preserves dict insertion order, so the original sections
stay first and the deeper sections appear at the end - the natural
reading order.

**`dep_session.py`**: reads `signals.json` with `json.load()` and
accesses structured fields directly. No text parsing needed.

**`signals.txt`** and the `SignalReport` dataclass are eliminated.

---

## Target `signals.json` Schema

```json
{
  "meta": {
    "pkgname": "foo",
    "version": "1.0.0",
    "mode": "NEW",
    "old_version": null,
    "sha256": "abc...",
    "ecosystem": "rubygems",
    "timestamp": "2026-05-26T14:28:00Z"
  },
  "gate": {
    "risk_flags": ["SCAN_MATCHES(3)", "NATIVE_EXTENSION"],
    "positive_flags": ["MFA_ENFORCED", "SOURCE_CLONED"],
    "adversarial_gate": "CLEAR",
    "concern_level": "MEDIUM",
    "concern_count": 3,
    "concerns": [
      {"label": "scan_matches", "annotation": "3 dangerous pattern matches"},
      {"label": "native_extension", "annotation": "requires native build"}
    ]
  },
  "license": {
    "spdx": "MIT",
    "osi_approved": true,
    "status": "OK",
    "note": "none",
    "changed": false
  },
  "health": {
    "age_years": 5,
    "last_release_days": 30,
    "version_published_days": 2,
    "version_stability": "stable",
    "owner_count": 2,
    "scorecard": 7.5,
    "recent_commits_12mo": 45,
    "commit_trend": "stable",
    "security_policy": false,
    "known_vulnerabilities": 0,
    "health_concerns": [],
    "ecosystems": {"dependents": 1200, "critical": false}
  },
  "manifest": {
    "extensions": false,
    "executables": [],
    "has_install_scripts": true,
    "install_scripts_raw_bytes": 412,
    "install_scripts_stripped_bytes": 398,
    "post_install_msg": false,
    "dist_type": "sdist"
  },
  "clone": {
    "url": "https://github.com/foo/foo",
    "status": "OK",
    "version_tag": "v1.0.0",
    "commit_guessed": false,
    "source_likely_incompatible": false
  },
  "extra_files": {
    "count": 0,
    "paths": []
  },
  "binary_files": {
    "count": 0,
    "paths": []
  },
  "scans": {
    "adversarial":  {"count": 0, "paths": []},
    "dangerous":    {"count": 3, "paths": ["lib/client.rb:45"]},
    "todo_fixme":   {"count": 8, "density_pct": 0.4},
    "diff_danger":  {"count": 0, "paths": []}
  },
  "diff": {
    "lines": 45,
    "files_changed": 3,
    "review": {
      "assessment": "SAFE",
      "confidence": "HIGH",
      "suspicious_patterns": [],
      "changed_files": ["lib/foo.rb", "CHANGELOG.md"],
      "summary": "Minor refactor, no security-relevant changes."
    }
  },
  "transitive": {
    "total": 5,
    "not_in_lockfile": ["bar", "baz"],
    "registry": {
      "bar": {"downloads": 5000000, "first_seen": "2018-03-01"},
      "baz": {"downloads": 800000,  "first_seen": "2020-11-15"}
    }
  },
  "provenance": {
    "mfa": "enforced"
  },
  "vulnerabilities": {
    "count": 0,
    "cves": []
  },
  "oss_rebuild": {
    "signal_level": "POSITIVE",
    "summary": "Attested build matches published artifact."
  },
  "badge": {
    "level": "silver",
    "score": 85
  },
  "alternatives": {
    "check_run": true,
    "critical": false,
    "notes": []
  },
  "install_scripts_review": {
    "assessment": "SAFE",
    "suspicious_patterns": [],
    "summary": "Post-install hook echoes a welcome message; no network or shell exec."
  },
  "deeper": {
    "sandbox": "bwrap",
    "reproducible": "EXACTLY_REPRODUCIBLE",
    "code_diffs": 0,
    "source_review": {
      "assessment": "SAFE",
      "files_only_in_package": [],
      "suspicious_files": [],
      "summary": "No unexpected files."
    }
  }
}
```

The `diff` and `deeper` sections are omitted when not applicable (NEW mode
has no `diff`; basic analysis has no `deeper`). `--deeper` appends those
sections to the dict before rewriting. `install_scripts_review` is written
during basic analysis whenever install scripts exist and
`SECURE_DEPS_SANDBOX_AI` is set; omitted otherwise.

---

## What Needs Changing

### `scripts/analysis_shared.py`

- **Delete** `SignalReport` dataclass.
- **Keep** `Printer` class: still needed for `install-scripts.txt`
  (sanitizer version of attacker-controlled data) and
  `alternatives.txt`. Remove all other uses.
- Values going into `signals.json` that originate from attacker-controlled
  sources (file paths, package metadata strings) must be passed through
  `sanitize_line()` before insertion into the dict.

### `scripts/dep_review.py`

This is the largest change.

- **`write_signals(ctx, p)`**: rewrite to build and return a structured
  dict (the `signals.json` schema above) instead of writing `signals.txt`.
  Remove the `Printer` parameter `p`; remove all `p(...)` calls; remove all
  `Printer(work / 'X.txt')` blocks. Return the dict.
- **Final block** (currently writes `signals.txt` then `signals.json`):
  write only `signals.json` using `json.dumps(signals, indent=2)`.
- **`--deeper` pass**: at the start of the deeper analysis block, load the
  existing `signals.json`; add `signals['diff']['review']` (tier 3 diff
  result, if applicable) and `signals['deeper']` (sandbox, repro, source
  review); write back with `json.dumps(signals, indent=2)`. Use
  write-to-temp-then-rename for crash safety.
- **Remove** all remaining `Printer(work / 'X.txt')` calls for the ~15
  section files that are being consolidated (keep only `install-scripts.txt`
  and `alternatives.txt`).
- **Remove** `signals.txt` writing entirely.

### `scripts/dep_session.py`

- **`_parse_signals(path)`**: replace the entire function (~80 lines of
  text parsing plus JSON fast-path) with a simple JSON loader:
  ```python
  def _load_signals(work_dir: Path) -> dict:
      p = work_dir / 'signals.json'
      if not p.is_file():
          return {}
      try:
          return json.loads(p.read_text(encoding='utf-8'))
      except (json.JSONDecodeError, OSError):
          return {}
  ```
- **Delete** `_parse_license_line()` and `_parse_health_line()`: callers
  now do e.g. `sig.get('license', {}).get('spdx', 'unknown')`.
- **`cmd_pre_fill_assessment`**: update all field lookups to use the new
  structured paths (e.g. `signals['license']['spdx']` instead of
  `_parse_license_line(signals.get('license_line', ''))`).
- **`cmd_report`** and **`cmd_wrap_up`**: update field lookups similarly.
- All callers of the old `_parse_signals` return a flat dict of strings;
  update them to use the new nested dict. The most-used fields and their
  new paths:

  | Old flat key | New path |
  |---|---|
  | `sha256` | `sig['meta']['sha256']` |
  | `concern_level` | `sig['gate']['concern_level']` |
  | `concern_count` | `sig['gate']['concern_count']` |
  | `adversarial_gate` | `sig['gate']['adversarial_gate']` |
  | `risk_flags` | `sig['gate']['risk_flags']` (now a list) |
  | `positive_flags` | `sig['gate']['positive_flags']` (now a list) |
  | `mode` | `sig['meta']['mode']` |
  | `old_version` | `sig['meta']['old_version']` |
  | `license_line` (parsed) | `sig['license']` (already structured) |
  | `health_line` (parsed) | `sig['health']` (already structured) |
  | `clone_url` | `sig['clone']['url']` |
  | `clone_status` | `sig['clone']['status']` |
  | `extensions` | `sig['manifest']['extensions']` |
  | `executables` | `sig['manifest']['executables']` |
  | `install_hooks` | `sig['manifest']['has_install_scripts']` |
  | `new_transitive_deps` | `sig['transitive']['total']` |
  | `known_vulnerabilities` | `sig['health']['known_vulnerabilities']` |
  | `version_stability` | `sig['health']['version_stability']` |
  | `health_concerns` | `sig['health']['health_concerns']` |
  | `license_note` | `sig['license']['note']` |

### Ecosystem analyzers (`ruby_analyzer.py`, `python_analyzer.py`, `js_analyzer.py`)

- **`raw-install-scripts.txt`**: new; write the unmodified install
  script content here before sanitizing, following the existing
  `raw-*` convention. Read only by the tier 3 sandbox.
- **`install-scripts.txt`**: keep as-is (sanitized; safe for human
  browsing). Neither tier 2 nor tier 3 reads this; it exists for
  human inspection only.
- After writing both files, compute `install_scripts_raw_bytes` and
  `install_scripts_stripped_bytes` and pass them into the signals
  dict. If they differ, add an `install_scripts_adversarial_chars`
  concern to `gate.concerns`.
- **`alternatives.txt`**: keep for now; the alternatives check has its own
  report format that humans read. Add a summary `alternatives` section to
  `signals.json` (check run: bool, critical: bool, notes: list of str).
- **`package-hash.txt`**: eliminate; SHA256 is already in `meta.sha256`.
- **`dist-type.txt`** (Python): eliminate; move to `manifest.dist_type`.
- **`old-version-status.txt`**: eliminate; fold into `meta` section.

### Tier 3 install-scripts review (new, ~50 lines)

**Raw vs. stripped files.** The ecosystem analyzers currently write
only `install-scripts.txt` (sanitized: bidi controls, zero-width chars,
control sequences removed). Analyzing the sanitized version defeats the
purpose: the AI cannot see content the attacker deliberately hid using
those techniques. We need the tier 3 AI to see the raw, unmodified
content. The sanitized version remains for safe human browsing, and for
comparison to provide a signal of potentially-dangerous content.

Each ecosystem analyzer writes two files:
- `raw-install-scripts.txt` — completely unmodified content, following
  the existing `raw-*` naming convention for unprocessed attacker data.
- `install-scripts.txt` — sanitized version, unchanged from today.

The deterministic code then computes the size difference and records
it in `signals.json["manifest"]`:
- `install_scripts_raw_bytes`: int
- `install_scripts_stripped_bytes`: int

If the two sizes differ, the deterministic gate adds a concern: the
attacker used adversarial characters in their install script, which is
itself suspicious independent of what the AI finds. This concern is
recorded in `gate.concerns` like any other.

Add to `scripts/analysis_shared.py`:

- `INSTALL_SCRIPTS_REVIEW_PROMPT`: instructs tier 3 to review
  install-time hook scripts for malicious patterns (network calls,
  credential access, obfuscated payloads, shell exec unrelated to
  the package's stated purpose, hidden characters); return JSON only.
  The prompt notes that adversarial characters may be present and
  should themselves be flagged as suspicious.
- `INSTALL_SCRIPTS_REVIEW_SCHEMA`: `assessment` (SAFE | SUSPICIOUS |
  CRITICAL), `suspicious_patterns` (list of str), `summary` (str).
- `INSTALL_SCRIPTS_REVIEW_SKIPPED` and `INSTALL_SCRIPTS_REVIEW_FAILED`
  sentinel dicts.

Add to `scripts/dep_review.py`, in the manifest analysis block
(after both install-scripts files are written, before `signals.json`
is written):

```python
install_scripts_review_result = shared.INSTALL_SCRIPTS_REVIEW_SKIPPED
if has_install_scripts and shared.sandbox_ai_available():
    _raw_path = work / 'raw-install-scripts.txt'
    _script_text = _raw_path.read_text(encoding='utf-8', errors='replace')
    install_scripts_review_result = shared.run_ai_sandbox(
        _script_text,
        shared.INSTALL_SCRIPTS_REVIEW_PROMPT,
        shared.INSTALL_SCRIPTS_REVIEW_SCHEMA,
        shared.INSTALL_SCRIPTS_REVIEW_FAILED,
        shared.INSTALL_SCRIPTS_REVIEW_SKIPPED,
    )
```

The result is included in `signals.json["install_scripts_review"]`
when `has_install_scripts` is true. This runs during basic analysis
(not `--deeper`) because install hooks are always a concern.
The `INSTALL_SCRIPTS_REVIEW_SKIPPED` sentinel is written when
`SECURE_DEPS_SANDBOX_AI` is not set, so tier 2 always reads a
predictable structure.

Tier 2 reads `signals.json["install_scripts_review"]` as part of
its normal `signals.json` read. It never reads either install-scripts
file directly. The tier 3 sandbox is the only consumer of
`raw-install-scripts.txt`.

### `assets/assessment-template.md`

No structural changes needed. The pre-fill script reads different JSON
paths but substitutes the same template tokens.

### `references/package-analysis-brief.md`

- Replace the conditional file-reading table (15 rows, 8 condition rules)
  with: "Read `WORK_DIR/signals.json`. That is the only file to read."
- Remove the instruction to read `install-scripts.txt` directly. Tier 2
  sees `signals.json["manifest"]["has_install_scripts"]` as a boolean flag
  and uses that in its judgment; the actual script content is handled via
  tier 3 delegation (future work).
- Remove references to all eliminated `.txt` files.
- Update the Step 1 NEXT_ACTION example to show `signals.json` as the
  output to read.

### `scripts/tests/`

- **`test_file_parsing.py`**: update `TestParseAutoFindings` to test
  `_load_signals()` against a fixture `signals.json` with the new schema.
  Delete tests for `_parse_license_line()` and `_parse_health_line()`.
  Update or replace the `assessment.md` and `signals.txt` fixtures.
- **`test_integration.py`**: validate `signals.json` structure (check that
  expected top-level keys are present, `gate.concern_level` is valid, etc.)
  rather than parsing `signals.txt` content.
- Add a fixture `signals.json` with the new schema.

---

## Files Eliminated

| File | Replaced by |
|---|---|
| `signals.txt` | `signals.json` (IS the human-readable output) |
| `manifest-analysis.txt` | `signals.json["manifest"]` |
| `clone-status.txt` | `signals.json["clone"]` |
| `source-url.txt` | `signals.json["clone"]["url"]` |
| `license.txt` | `signals.json["license"]` |
| `project-health.txt` | `signals.json["health"]` |
| `extra-in-package.txt` | `signals.json["extra_files"]` |
| `binary-files.txt` | `signals.json["binary_files"]` |
| `diff-semantic.txt` | `signals.json["diff"]["review"]` |
| `source-review.txt` | `signals.json["deeper"]["source_review"]` |
| `sandbox-detection.txt` | `signals.json["deeper"]["sandbox"]` |
| `reproducible-build.txt` | `signals.json["deeper"]["reproducible"]` |
| `provenance.txt` | `signals.json["provenance"]` |
| `vulnerabilities.txt` | `signals.json["vulnerabilities"]` |
| `oss-rebuild.txt` | `signals.json["oss_rebuild"]` |
| `badge-status.txt` | `signals.json["badge"]` |
| `new-deps.txt` | `signals.json["transitive"]` |
| `dep-lockfile-check.txt` | `signals.json["transitive"]` |
| `dep-registry.txt` | `signals.json["transitive"]["registry"]` |
| `transitive-deps.txt` | `signals.json["transitive"]` |
| `summary-scan-{LABEL}.txt` | `signals.json["scans"][label]` |
| `package-hash.txt` | `signals.json["meta"]["sha256"]` |
| `dist-type.txt` | `signals.json["manifest"]["dist_type"]` |
| `old-version-status.txt` | `signals.json["meta"]` |

Files **kept**:
- `raw-install-scripts.txt` (unmodified; read only by tier 3 sandbox)
- `install-scripts.txt` (sanitized; human browsing only; no AI reads it)
- `alternatives.txt` (full human-readable alternatives report)
- `session-update.json` (tier 1 plumbing; tier 2 never reads)
- `verdict.json` (tier 2 output)
- `assessment.md` (tier 2 output)
- `raw-*` files (audit trail; nothing reads them)

---

## Implementation Order

1. **Define schema helpers** in `analysis_shared.py`: a `sanitize_for_json()`
   convenience wrapper (calls `sanitize_line` on string values in a dict
   recursively) so all dict values entering `signals.json` are clean.

2. **Add install-scripts tier 3 infrastructure** in `analysis_shared.py`:
   `INSTALL_SCRIPTS_REVIEW_PROMPT`, `INSTALL_SCRIPTS_REVIEW_SCHEMA`,
   and the two sentinel dicts. Mirrors the existing diff/source review
   pattern exactly.

3. **Rewrite `write_signals()`** in `dep_review.py`: build and return a
   structured dict (the `signals.json` schema above) instead of writing
   `signals.txt`. Drop the `Printer` parameter `p`; remove all `p(...)`
   calls and `Printer(work / 'X.txt')` blocks. Invoke the tier 3
   install-scripts review here (after `install-scripts.txt` is written)
   and include the result in the dict.

4. **Final block** in `dep_review.py`: write only `signals.json` using
   `json.dumps(signals, indent=2)`. Remove `signals.txt` write.

5. **Update `--deeper` block** in `dep_review.py`: load-merge-rewrite
   pattern; add `diff.review` and `deeper` sections to the loaded dict
   and rewrite using write-to-temp-then-rename.

6. **Update `dep_session.py`**: replace `_parse_signals` with
   `_load_signals`, delete `_parse_license_line` and `_parse_health_line`,
   update all callers to use new nested paths.

7. **Update ecosystem analyzers**: remove `package-hash.txt`,
   `dist-type.txt`, `old-version-status.txt` writes; fold values into the
   signals dict via existing `SignalContext` fields.

8. **Update the brief** (`references/package-analysis-brief.md`): replace
   the conditional file-reading table with "read `signals.json` only";
   note that `install_scripts_review` section contains the tier 3 verdict
   when install scripts are present.

9. **Update tests**: new fixture `signals.json` with full new schema;
   updated assertions in `test_file_parsing.py` and `test_integration.py`.

10. **Remove dead code**: `SignalReport` dataclass, `_parse_signals` text
    fallback, compact string encoding, all eliminated
    `Printer(work/'X.txt')` blocks.

---

## Verification

```bash
make test                        # all tests pass

# Basic analysis: one structured output file
python3 scripts/dep_review.py --from rubygems --basic --root . testgem 2.0.0
python3 -c "
import json
d = json.load(open('temp/dep-review/testgem-2.0.0/signals.json'))
print('sections:', list(d.keys()))
print('concern_level:', d['gate']['concern_level'])
print('license:', d['license']['spdx'])
"
ls temp/dep-review/testgem-2.0.0/*.txt
# only install-scripts.txt (if triggered) and alternatives.txt should remain

# Install-scripts tier 3 review (requires SECURE_DEPS_SANDBOX_AI=claude)
SECURE_DEPS_SANDBOX_AI=claude python3 scripts/dep_review.py \
    --from rubygems --basic --root . somegem-with-hooks 1.0.0
python3 -c "
import json
d = json.load(open('temp/dep-review/somegem-with-hooks-1.0.0/signals.json'))
m = d['manifest']
print('raw_bytes:', m.get('install_scripts_raw_bytes'))
print('stripped_bytes:', m.get('install_scripts_stripped_bytes'))
print('review:', d.get('install_scripts_review'))
"
# raw_bytes == stripped_bytes means no adversarial chars were stripped
# review should show assessment + summary from tier 3
ls temp/dep-review/somegem-with-hooks-1.0.0/raw-install-scripts.txt  # exists
ls temp/dep-review/somegem-with-hooks-1.0.0/install-scripts.txt      # exists (sanitized)

# --deeper: new sections appended at end
python3 scripts/dep_review.py --from rubygems --deeper --root . testgem 2.0.0
python3 -c "
import json
d = json.load(open('temp/dep-review/testgem-2.0.0/signals.json'))
print('keys after deeper:', list(d.keys()))
# deeper section must appear after all basic-analysis sections
"
```
