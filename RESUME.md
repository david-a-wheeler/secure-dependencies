# Resume Point

Branch: `shai-halud-more`  
Last commit: `1a6a8b6` "Generalize VCS/lockfile checks to all ecosystems"

## What was just completed

All of Idea Groups A-D from `docs/shai-halud-ideas.md` are now done:

- **Groups A-B** (install-script scanning, DANGEROUS_PATTERNS): earlier commits
- **Group C** (binary/staging-dir file-tree scan): commit `bb9adc6`
- **Group D** (VCS dep + lockfile foreign URL): commit `1a6a8b6`

Group D key decisions:
- Signal names unified across all ecosystems: `VCS_DEPENDENCY` (not
  `GIT_REF_DEPENDENCY`) and `LOCKFILE_FOREIGN_URL` (not `LOCKFILE_FOREIGN_RESOLVED`).
- All three ecosystems detect VCS deps: JS via `_RE_GIT_DEP` in `package.json`
  deps, Python via `_RE_PY_VCS_DEP` in `Requires-Dist` + `_RE_PY_VCS_DEP`
  in `poetry.lock`/`uv.lock`, Ruby via `_RE_GEMLOCK_GIT_SECTION` in
  `Gemfile.lock`.
- Private registry false-positive suppression: `self.registry_url` incorporated
  into trusted-host set in JS and Python lockfile checks.
- Shared constants added to `analysis_shared.py`: `VCS_SCHEMES_RE`,
  `VCS_HOSTNAMES_RE`, `COMMIT_HASH_RE`. Ecosystem patterns compose from these.

## What remains: Group E (Ideas 14-16)

These add network calls to `fetch_all_registry_data`. See
`docs/shai-halud-ideas.md` for full spec. Summary:

**Idea 14: Publisher velocity anomaly (`PUBLISHER_VELOCITY_ANOMALOUS`)**
- File: `analyzer_js.py`, `fetch_all_registry_data()`
- API: `GET https://registry.npmjs.org/-/v1/search?text=maintainer:<user>&size=250`
- Count packages whose `date` field is within the last 72 hours. Threshold: 10.
- Combine with account-age (from `time.created`): new account + high velocity = HIGH.
- One extra network call per analysis session.

**Idea 15: SLSA provenance issuer validation (`SIGSTORE_REPO_MISMATCH`)**
- File: `analyzer_js.py`, `fetch_all_registry_data()`
- API: `GET https://registry.npmjs.org/-/package/<encoded-name>/provenance`
- Compare `sourceRepositoryURI` against the declared `source_url` (already
  available from `_extract_source_url()`). Mismatch = forged provenance.
- Surface for AI review (not hard-fail); note if `workflowPath` looks ad-hoc.

**Idea 16: Repo campaign marker (`REPO_CAMPAIGN_MARKER`)**
- File: all three ecosystems' `fetch_all_registry_data()`
- API: `GET https://api.github.com/repos/<owner>/<repo>` (no auth needed for public)
- Check `description` for known campaign strings: `'niagA oG eW ereH :duluH-iahS'`,
  `'Sha1-Hulud'`, `'TeamPCP'`.
- Also check `GET .../contents/results` for a 200 response (credential staging dir).
- Rate limit: 60 req/hr unauthenticated; add `If-None-Match` ETag caching.
- `source_url` (already extracted) provides the `<owner>/<repo>` path.
- Cross-ecosystem: all three hooks can call the same GitHub API helper.

## Suggested next step

Start with Idea 16 (cheapest, highest signal-to-noise, and truly cross-ecosystem
since it uses a shared GitHub REST API call). Then Idea 15, then Idea 14.

Consider adding a shared helper `_github_repo_meta(source_url)` in
`analysis_shared.py` that all three ecosystems call, since the GitHub API
call and ETag caching logic is identical regardless of ecosystem.

## Key files

- `docs/shai-halud-ideas.md` -- full spec with implementation notes; status updated
- `scripts/analysis_shared.py` -- shared constants and helpers
- `scripts/analyzer_js.py` -- JS/npm ecosystem
- `scripts/analyzer_python.py` -- Python/PyPI ecosystem
- `scripts/analyzer_ruby.py` -- Ruby/RubyGems ecosystem
- `scripts/tests/` -- run with `python3 -m unittest discover tests -q`
