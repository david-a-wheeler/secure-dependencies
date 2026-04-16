# OSS Rebuild

[OSS Rebuild](https://oss-rebuild.dev/) is a Google project that verifies
whether open-source package releases are reproducible: it re-executes
the build and checks whether the artifact in the registry matches what
the source code produces. Results are published as signed in-toto/SLSA
attestations.

## Data access: no tool required

Attestations are stored in a public Google Cloud Storage (GCS) bucket named
`google-rebuild-attestations`. While they *supply* a go tool, it's also
possible to get the data directly without a GCP account,
`gcloud` CLI, or Go tool installation.
Everything is accessible via plain HTTPS using Google's
standard GCS JSON API.

### Download one attestation bundle

```
GET https://storage.googleapis.com/google-rebuild-attestations/{ecosystem}/{package}/{version}/{artifact}/rebuild.intoto.jsonl
```

Example (verified working):

```
https://storage.googleapis.com/google-rebuild-attestations/pypi/absl-py/2.0.0/absl_py-2.0.0-py3-none-any.whl/rebuild.intoto.jsonl
```

The response is a newline-delimited JSON file (`.jsonl`). Each line is a
base64-encoded in-toto envelope. A typical bundle contains two attestations:

- **Rebuild** (`Rebuild@v0.1`): documents the exact build procedure used
  (Docker image, Alpine version, build steps, source repo, timing, etc.)
- **ArtifactEquivalence** (`ArtifactEquivalence@v0.1`): records the
  comparison between the rebuilt artifact and the upstream registry release

### List versions of a package

Use `delimiter=/` to treat path separators as directory boundaries and get back
only the version-level prefixes rather than every file:

```
GET https://storage.googleapis.com/storage/v1/b/google-rebuild-attestations/o?prefix={ecosystem}/{package}/&delimiter=/
```

Example:

```
https://storage.googleapis.com/storage/v1/b/google-rebuild-attestations/o?prefix=pypi/absl-py/&delimiter=/
```

Response shape:

```json
{
  "kind": "storage#objects",
  "nextPageToken": "...",
  "prefixes": [
    "pypi/absl-py/1.3.0/",
    "pypi/absl-py/2.0.0/",
    "pypi/absl-py/2.2.2/"
  ]
}
```

Paginate with `&pageToken={nextPageToken}` until the response has no
`nextPageToken`.

### List artifact files within a version

Drop the `delimiter` parameter to get full object metadata for every file under a prefix:

```
GET https://storage.googleapis.com/storage/v1/b/google-rebuild-attestations/o?prefix={ecosystem}/{package}/{version}/
```

The `items` array in the response contains each object's `name`, `size`,
`md5Hash`, `updated`, and a `mediaLink` for direct download.

### Enumerate all ecosystems

```
GET https://storage.googleapis.com/storage/v1/b/google-rebuild-attestations/o?delimiter=/
```

Returns the top-level `prefixes` (e.g. `cratesio/`, `npm/`, `pypi/`).

## Always query; handle absence gracefully

The set of supported ecosystems will grow over time (RubyGems and Maven support
already exist in the codebase but have not yet been published). Rather than
maintaining a hard-coded allowlist, always attempt the lookup and treat an empty
response as "no data available."

The GCS API signals "no objects match this prefix" by returning a minimal body
with **no `items` and no `prefixes` keys**:

```json
{ "kind": "storage#objects" }
```

This is the same response whether the ecosystem has never been supported or
whether a specific package simply has no rebuild data yet. Code can therefore
use a single check:

```python
# Python example
import requests

def fetch_rebuild_versions(ecosystem: str, package: str) -> list[str]:
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        "google-rebuild-attestations/o"
    )
    versions = []
    page_token = None
    while True:
        params = {
            "prefix": f"{ecosystem}/{package}/",
            "delimiter": "/",
            "maxResults": 500,
        }
        if page_token:
            params["pageToken"] = page_token
        data = requests.get(url, params=params).json()
        for prefix in data.get("prefixes", []):
            # prefix looks like "pypi/absl-py/2.0.0/" - extract the version
            versions.append(prefix.rstrip("/").split("/")[-1])
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return versions  # empty list means no data for this ecosystem/package
```

If `versions` is empty, the package has no rebuild data yet. No special-casing
by ecosystem name is needed.

## Interpreting the verdict

**The presence of an ArtifactEquivalence attestation does not by itself mean the
rebuild succeeded.** Both successful and failed rebuilds are published to the
bucket. To determine the outcome, decode the base64 payload and inspect the
predicate:

- The `externalParameters.candidate` field gives the SHA-256 of the rebuilt
  artifact (after stabilization).
- The `externalParameters.target` field gives the SHA-256 of the upstream
  registry artifact (after stabilization).
- If the two hashes match, the rebuild succeeded (the package is reproducible).
- If they differ, the rebuild failed (the published artifact cannot be
  reproduced from source with the recorded procedure).

Before comparing, both artifacts go through a "stabilization" step that strips
non-deterministic content (embedded timestamps, etc.). The hashes in the
attestation are of the stabilized artifacts, not the raw downloads.

A successful rebuild is described by the OSS Rebuild project as "a mild positive
signal that a build was free from tampering." A failed rebuild is not
necessarily evidence of compromise; common causes include automation
limitations, legitimate build environment differences, and inherently
non-deterministic build processes.

## Update cadence and data freshness

OSS Rebuild is actively maintained (multiple commits per day as of 2026-04), but
the public bucket is not updated uniformly across ecosystems.

From sampling in April 2026:

| Ecosystem | Bulk run      | Incremental updates |
|-----------|--------------|---------------------|
| npm       | Dec 2025     | Yes, continuous (new releases within days; e.g. lodash 4.18.0 appeared 2026-03-31) |
| pypi      | Dec 2025 - Jan 2026 | Not observed; data appears frozen at ~2026-01-15 |
| cratesio  | Dec 2025     | Not observed         |

Coverage is also selective: not every package or version is present. For example,
`serde` (the most downloaded Rust crate) has no data, and `lodash 4.17.21` (the
most widely deployed npm version) is absent even though neighboring versions are
present.

**Old data is still useful.** A reproducibility result for a specific version
does not expire. If your dependency audit includes a version that was rebuilt in
December 2025, that attestation is still valid evidence about that release. The
data is most valuable for establishing that a version you are currently pinned to
was (or was not) reproducible at the time it was evaluated.

## Current ecosystem status (as of 2026-04)

| Ecosystem | Bucket data | Code in repo | Ecosystem identifier |
|-----------|-------------|--------------|----------------------|
| PyPI      | yes         | yes          | `pypi`               |
| npm       | yes         | yes          | `npm`                |
| crates.io | yes         | yes          | `cratesio` (no dot)  |
| RubyGems  | no          | yes (active) | `rubygems`           |
| Maven     | no          | yes (active) | `maven`              |
| Debian    | no          | yes          | `debian`             |

Note the `cratesio` identifier (no dot): it does not follow the registry domain
name `crates.io`.

All ecosystem identifier strings are defined as typed constants in
[`pkg/rebuild/rebuild/models.go`](https://github.com/google/oss-rebuild/blob/main/pkg/rebuild/rebuild/models.go),
which is also the authoritative source for any new ecosystems added in the future:

```go
const (
    NPM      Ecosystem = "npm"
    PyPI     Ecosystem = "pypi"
    CratesIO Ecosystem = "cratesio"
    Maven    Ecosystem = "maven"
    Debian   Ecosystem = "debian"
    RubyGems Ecosystem = "rubygems"
)
```

The constants serve dual purposes in the codebase: ecosystem selection and
storage path prefixes, which is why they map directly to the GCS bucket paths.

## Path structure summary

```
{ecosystem}/{package}/{version}/{artifact-filename}/rebuild.intoto.jsonl
```

## How we plan to use it

Our plan is to add this lookup in `basic analysis` - it takes almost no
tiem or effort to do the lookup. We'll always do the lookup, just in case
they've added the ecosystem we care about. There are various possible
outcomes:

* This ecosystem or package isn't in the datbase - say nothing as a signal,
  that would just be noise.
* We can only find an older version of the package - that can still give us
  information on what it was like, though it's less relevant.
* It reproduces - that means that if there is malicious code in the compiled
  version it's visible in the source, cutting off one kind of attack and
  giving us a small amount of confidence
* It doesn't reproduce, and it hasn't reproduced in the past or we don't
  know if it reproduced in the past - that's a mildly negative signal, say so.
  It MIGHT be okay, but there are some concerns, it might be wise for us to
  rebuild to check it further (in deeper analysis).
* It doesn't reproduce and it used to - that is VERY concerning. We DEFINITELY
  want to do deeper analysis.

## Further reading

- Home page and live demo: <https://oss-rebuild.dev/>
- Full documentation (storage layout, attestation format, trust model):
  <https://docs.oss-rebuild.dev/>
- Storage and access guide: <https://docs.oss-rebuild.dev/storage/>
- Source code: <https://github.com/google/oss-rebuild>
- GCS JSON API reference for listing objects:
  <https://cloud.google.com/storage/docs/json_api/v1/objects/list>
