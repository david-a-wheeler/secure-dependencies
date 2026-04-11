# JavaScript Ecosystem Reference

Reference for the `securely-update-dependencies` skill, JavaScript/Node.js details.
Covers npm, Yarn, and pnpm. All paths use `temp/dep-review/PKGNAME/` relative
to the project root.

## Detecting the Package Manager

| File | Tool |
|---|---|
| `package-lock.json` | npm |
| `yarn.lock` | Yarn (v1 or v2+) |
| `pnpm-lock.yaml` | pnpm |
| `bun.lockb` | Bun |

`package.json` is always present regardless of tool.

## Identifying Outdated Packages

```bash
# npm
npm outdated

# Yarn v1
yarn outdated

# Yarn v2+ (Berry)
yarn upgrade-interactive  # interactive; for CI: yarn outdated is unavailable, use npm-check

# pnpm
pnpm outdated

# CVE audit
npm audit            # npm
yarn audit           # Yarn v1
pnpm audit           # pnpm
```

`npm outdated` shows: Package / Current / Wanted / Latest / Location.
"Wanted" respects semver ranges in `package.json`; "Latest" ignores them.

## Reading the Locked Version

```bash
# package-lock.json v2/v3 (npm >= 7)
node -e "
const l = require('./package-lock.json');
const v = l.packages?.['node_modules/PKGNAME']?.version
       || l.dependencies?.PKGNAME?.version;
console.log(v || 'not found');
"

# yarn.lock (v1 format)
awk '/^"?PKGNAME@/{f=1} f && /^  version/{print; exit}' yarn.lock

# yarn.lock (v2+ / Berry, YAML-like)
awk '/^"PKGNAME@/{f=1} f && /version:/{print; exit}' yarn.lock

# pnpm-lock.yaml
awk '/^  \/PKGNAME\//{f=1} f && /version:/{print; exit}' pnpm-lock.yaml
```

## Downloading Without Installing

`npm pack PKGNAME@VERSION` downloads the package from the registry and creates
a `.tgz` tarball **without running any install scripts or lifecycle hooks**.
This is the correct safe download method.

```bash
mkdir -p temp/dep-review/PKGNAME/unpacked

# Download as tarball (no scripts run)
npm pack PKGNAME@VERSION \
  --pack-destination temp/dep-review/PKGNAME/

# Unpack
tar xf temp/dep-review/PKGNAME/*.tgz \
  -C temp/dep-review/PKGNAME/unpacked/ --strip-components=1
```

The unpacked directory corresponds to what would be installed under
`node_modules/PKGNAME/`; it always contains `package.json` at its root.

**Do not use** `npm install --ignore-scripts` for inspection purposes; it
still resolves and potentially downloads the full dependency graph, and
`--ignore-scripts` only suppresses lifecycle scripts, not all execution.

## Package.json Security Checklist

```bash
cat temp/dep-review/PKGNAME/unpacked/package.json
```

Focus on these fields:

| Field | What to look for |
|---|---|
| `scripts.preinstall` | Runs before install; any value is a red flag in a library |
| `scripts.install` | Runs during install (common for native addons); inspect what it does |
| `scripts.postinstall` | Runs after install (very common attack vector) |
| `bin` | Object/string mapping command names to scripts; adds executables to PATH |
| `dependencies` | Runtime dependencies: new entries or loosened semver ranges |
| `optionalDependencies` | Same concern as dependencies |
| `engines` | Sudden changes may indicate breaking behavior change |
| `main` / `exports` | Entry point: check that it is a `.js` file, not a binary |

Any non-empty `scripts.preinstall`, `scripts.install`, or `scripts.postinstall`
in a pure-JavaScript library (not a native addon) is suspicious. Read the
script value to understand what it does; do not run it.

## Native Addons

Packages using native code (N-API, nan, node-gyp) compile C/C++ at install time.
Indicators:
- `scripts.install` value contains `node-gyp rebuild` or `prebuild-install`
- `binding.gyp` file present in the unpacked directory
- `node_modules/PKGNAME/build/` directory in the tarball (pre-built binary)

If a native addon was added in an update that previously had none, inspect
the C/C++ source in the unpacked tarball carefully.

## Dangerous JavaScript Patterns (supplement to 3B blind scans)

Beyond blind scans, these patterns are worth checking with judgment
(not adversarial text; safe to read):

**Code execution:**
- `eval()`: immediate flag unless in a sandboxing library
- `new Function(...)`: equivalent to eval
- `vm.runInThisContext()`, `vm.runInNewContext()` with external string
- `require('child_process').exec()` / `execSync()` / `spawn()`

**Obfuscated execution:**
- `Buffer.from('...', 'base64').toString()` near eval or Function()
- Hex-encoded strings decoded and executed
- `require(variable)` where variable is constructed from external data

**Network at module load scope** (outside any function or export):
- `require('http').get(...)`, `require('https').get(...)`
- `fetch(...)` at top level (Node 18+)
- Any socket connection in the module's initialization code

**Credential harvesting:**
- `process.env.AWS_ACCESS_KEY_ID`, `process.env.GITHUB_TOKEN`, etc.
  accessed at module load time and sent over the network

**Dynamic require:**
- `require(process.env.SOME_VAR)`: load path from environment
- `require(userInput)`: path traversal / code injection

**Prototype pollution** (especially in utility libraries):
- Assignment to `Object.prototype`, `Array.prototype`, `Function.prototype`
- `__proto__` as an object key in merge/extend functions

## Comparing Versions

```bash
# Download old version with same safe method
npm pack PKGNAME@OLD_VERSION \
  --pack-destination temp/dep-review/PKGNAME/old-pkg/

mkdir -p temp/dep-review/PKGNAME/old/
tar xf temp/dep-review/PKGNAME/old-pkg/*.tgz \
  -C temp/dep-review/PKGNAME/old/ --strip-components=1

diff -rq \
  temp/dep-review/PKGNAME/old/ \
  temp/dep-review/PKGNAME/unpacked/ \
  --exclude="*.map"
```

## Provenance Check

```bash
# Full metadata for a specific version
npm info PKGNAME@VERSION

# Show maintainers, times, dist-tags
npm info PKGNAME maintainers
npm info PKGNAME time

# Verify package integrity (compares against registry checksum)
npm pack PKGNAME@VERSION --dry-run
```

Check for: changed `maintainers` list, changed `repository` or `homepage` URL,
unusual `time` entry for the version, changed `dist.integrity` compared to
what your lock file recorded.

**Lock file integrity**: npm's `package-lock.json` records `integrity` (SHA-512
hash) for every package. If a package at the same version has a different hash
than what was previously locked, treat it as CRITICAL:

```bash
# Extract recorded integrity from lock file
node -e "
const l = require('./package-lock.json');
const pkg = l.packages?.['node_modules/PKGNAME'];
console.log(pkg?.integrity);
"
```

## Applying Updates Safely

Update packages **by name and exact version**, not a blanket update:

```bash
# npm: installs exact version, updates package-lock.json
npm install PKGNAME@NEW_VERSION

# Yarn v1
yarn upgrade PKGNAME@NEW_VERSION

# Yarn v2+ (Berry)
yarn up PKGNAME@NEW_VERSION

# pnpm
pnpm update PKGNAME@NEW_VERSION
```

Re-run the audit after updating:

```bash
npm audit     # or yarn audit / pnpm audit
```

Commit `package-lock.json` (or `yarn.lock` / `pnpm-lock.yaml`) separately from
application code so the dependency update is independently auditable.

## Common False Positives

| Pattern | Legitimate use | Red flag |
|---|---|---|
| `scripts.postinstall` | Native addon compilation (`node-gyp rebuild`) | Downloading binaries, running curl/wget |
| `child_process` | Packages that wrap CLI tools | child_process calls at module load time |
| `eval` | Template engines, REPL implementations | `eval` of fetched or env-derived strings |
| `process.env` | Reading `NODE_ENV`, `PORT`, `DEBUG` | Reading cloud credential vars at load time |
| `bin` field | CLI tools (expected) | A library suddenly adding an executable |
| Dynamic `require` | Plugin systems with explicit user config | `require(process.env.SOME_VAR)` |
