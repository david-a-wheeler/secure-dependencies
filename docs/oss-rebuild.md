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

Because a package version can have multiple artifacts (e.g. a universal
wheel and a source distribution), the artifact filename is part of the
path. List the artifacts within a version first (see below) to discover
the exact filename, then construct the download URL:

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

**Presence of an ArtifactEquivalence attestation in a bundle means the rebuild
succeeded.** The service only publishes a bundle when the rebuild passes: if
neither an exact match nor a stabilized match is found, the process returns an
error before calling `PublishBundle`, so no attestation reaches the bucket.
(Source: `internal/api/apiservice/rebuild.go` in the OSS Rebuild repo.)

The practical implication: if a version appears in the bucket listing, it
passed. If it does not appear, it was either never attempted or failed (the
two are indistinguishable from the bucket alone).

### What the attestation stores

The `ArtifactEquivalence@v0.1` predicate records:

- `resolvedDependencies`: raw SHA-256 of the rebuilt artifact, and raw
  SHA-256 of the upstream artifact.
- `byproducts`: SHA-256 of the **stabilized upstream** artifact.
- `subject`: SHA-256 of the upstream artifact (same as resolvedDependencies).

The stabilized rebuild hash (the value actually compared for equivalence) is
used in-process but is not stored in the attestation. You cannot reproduce the
PASS/FAIL determination from the attestation data alone without re-running the
stabilization step. The presence of the attestation is the verdict.

Stabilization strips non-deterministic content (embedded timestamps, etc.)
before comparing rebuild and upstream. A build that does not match exactly may
still pass after stabilization; both cases produce an attestation.

A successful rebuild is described by the OSS Rebuild project as "a mild positive
signal that a build was free from tampering."

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

## Analysis strategy

Add this lookup to basic analysis - it takes almost no time or effort.
Always do the lookup regardless of ecosystem, just in case data has been
added for the ecosystem we care about.

### What "absent" means

Because the service only publishes attestations for builds that pass, an
absent version can mean either "never tested" or "tested and failed." The two
are indistinguishable from the bucket alone. Code must treat absence as
*unknown*, not as evidence of failure.

### Possible outcomes and their signals

* This ecosystem or package has no data: say nothing. Absence of data
  is not a signal; reporting it would just be noise.
  Otherwise (the rest of the cases below), report what we know and
  suggest what it might mean.
* We have data for the exact version we care about: the build reproduced
  (attestation present = PASS by design). That means any malicious code
  in the compiled version is also visible in the source, cutting off one
  class of supply chain attack and giving us a small amount of confidence.
* We have no data for the exact version, but we do have older versions
  that reproduced: that is a mildly positive signal. It tells us the
  project has a track record of reproducible builds: the maintainers care
  about it and the build tooling works. It does not confirm the current
  version is clean, but the prior versions at least were, and we have no
  evidence to the contrary. Worth noting, but not worth drawing a strong
  conclusion from.
* We have no data for the exact version and no data for other versions
  either: no signal either way. The package simply has not been evaluated.

### What about regressions?

In principle, "current version absent but older versions present" is
ambiguous: the current version might have been tested and failed (a
potential red flag) or simply not yet tested (no information). With the
current bucket layout there is no way to distinguish these cases. Treat
this as the MILD_POSITIVE case (positive track record) rather than sounding
a false alarm.

If the service ever adds explicit failure attestations, the NEGATIVE and
REGRESSION signals would become meaningful. The code retains those
signal_level values as a forward-compatibility hook.

### Multiple artifacts per version

A single package version can have more than one artifact (e.g. a
universal wheel and a source distribution, or wheels for different Python
versions). Always list the artifacts within a version to discover what is
available rather than guessing the filename.

When multiple artifacts exist, use this approach:

* If you know the exact artifact the user installed (e.g. from pip
  metadata), look up that artifact specifically.
* If you don't know the exact artifact, check all available ones. If any
  reproduce, report that as a positive signal. If none reproduce, report
  that as a negative signal.

### PyPI artifact coverage: current state and uncertainty

The current PyPI data covers only universal wheels (`py3-none-any.whl`).
Packages with C extensions (numpy, cryptography, pillow, etc.) are absent
from the bucket entirely - OSS Rebuild has not yet published data for
platform-specific wheels or source distributions. It is unclear how they
will handle these when they expand PyPI coverage: they might rebuild the
source distribution, each platform wheel, or only select artifacts.

The listing-based approach above will work correctly regardless of how
they resolve this: when they start publishing platform-specific wheels,
the version listing will return them and the per-artifact lookup will find
the right one.

### Coding for future ecosystems now

Since we always query and handle absence gracefully, any new ecosystem
that OSS Rebuild publishes will be picked up automatically with no code
changes. The listing approach discovers artifact names at runtime, so
unknown artifact filename conventions for new ecosystems (e.g. RubyGems
`.gem` files, Maven `.jar` files) are handled without special cases.

The only thing that could silently improve is the package name passed to
the lookup. PyPI normalizes package names (hyphens and underscores are
interchangeable, case is ignored), so normalize to lowercase with hyphens
when constructing PyPI paths - e.g. `Pillow` becomes `pillow`,
`my_package` becomes `my-package`. This matches what OSS Rebuild uses as
the path key.

## Further reading

- Home page and live demo: <https://oss-rebuild.dev/>
- Full documentation (storage layout, attestation format, trust model):
  <https://docs.oss-rebuild.dev/>
- Storage and access guide: <https://docs.oss-rebuild.dev/storage/>
- Source code: <https://github.com/google/oss-rebuild>
- GCS JSON API reference for listing objects:
  <https://cloud.google.com/storage/docs/json_api/v1/objects/list>
