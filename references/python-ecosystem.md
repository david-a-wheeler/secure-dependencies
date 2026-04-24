# Python Ecosystem Reference

Reference for the `securely-update-dependencies` skill, Python-specific details.
Covers pip, Poetry, and uv. All paths use `temp/dep-review/PKGNAME/` relative
to the project root.

## Detecting the Package Manager

Check which files are present to determine the active tool:

| File | Tool |
|---|---|
| `requirements.txt` | pip |
| `Pipfile` + `Pipfile.lock` | Pipenv |
| `pyproject.toml` + `poetry.lock` | Poetry |
| `pyproject.toml` + `uv.lock` | uv |
| `pyproject.toml` only | pip with PEP 517 |

A project may have multiple (e.g., `pyproject.toml` used by both uv and pip).
Use the lock file to determine what versions are actually pinned.

## Identifying Outdated Packages

```bash
# pip
python3 -m pip list --outdated

# Poetry
poetry show --outdated

# uv
uv pip list --outdated

# CVE audit (any of:)
pip-audit
safety check -r requirements.txt
```

## Reading the Locked Version

Each lock format is different:

```bash
# requirements.txt (pinned format: PKGNAME==1.2.3)
grep -i "^PKGNAME==" requirements.txt

# poetry.lock (TOML, find the name block then the version)
awk '/^name = "PKGNAME"/{f=1} f && /^version/{print; exit}' poetry.lock

# Pipfile.lock (JSON)
python3 -c "
import json
d = json.load(open('Pipfile.lock'))
pkg = d.get('default', {}).get('pkgname', {})  # key is lowercase
print(pkg.get('version', 'not found'))
"

# uv.lock (similar TOML structure to poetry.lock)
awk '/^name = "PKGNAME"/{f=1} f && /^version/{print; exit}' uv.lock
```

## Downloading Without Installing

`python3 -m pip download` fetches a package to disk without installing it.
`--prefer-binary` downloads a pre-built wheel when available, avoiding
any build-time code execution. `--no-deps` fetches only the named package.

```bash
mkdir -p temp/dep-review/PKGNAME/unpacked

python3 -m pip download PKGNAME==VERSION --no-deps --prefer-binary \
  -d temp/dep-review/PKGNAME/
```

**If a wheel (.whl) was downloaded** (preferred: a zip, no build execution):

```bash
unzip -q temp/dep-review/PKGNAME/PKGNAME*.whl \
  -d temp/dep-review/PKGNAME/unpacked/
```

**If a source distribution (.tar.gz) was downloaded** (fallback):

Note in the report that pip may have run `setup.py egg_info` or equivalent to
collect metadata during download, depending on the package's build backend.
Unpack with:

```bash
tar xf temp/dep-review/PKGNAME/PKGNAME*.tar.gz \
  -C temp/dep-review/PKGNAME/unpacked/ --strip-components=1
```

## Wheel Structure and Manifest (dist-info)

A wheel unpacks into a flat structure. Security-relevant files:

```
PKGNAME-VERSION.dist-info/
  METADATA          (package metadata: author, dependencies, description)
  RECORD            (list of every installed file with hashes)
  entry_points.txt  (scripts/commands installed to PATH, if any)
  WHEEL             (wheel format version info)
  top_level.txt     (top-level package names)
```

Check for:
- `entry_points.txt`: any `[console_scripts]` or `[gui_scripts]` entries
  add executables to the user's PATH on install
- New entries in `METADATA`'s `Requires-Dist` lines (new runtime dependencies)
- Loosened version pins in `Requires-Dist` (e.g., changed from `>=1.0,<2.0` to `>=1.0`)

## Source Distribution (sdist) Manifest

```
pyproject.toml or setup.cfg  (build configuration)
PKG-INFO                     (metadata, like METADATA in a wheel)
setup.py                     (legacy build script; if present, read carefully)
```

In `pyproject.toml`, check:
- `[build-system]` table: what runs at build time
- `[project.scripts]` and `[project.entry-points]`: executables added to PATH
- `[project.dependencies]`: runtime dependencies and their constraints

In `setup.py` (legacy), flag any top-level `os.system`, `subprocess`,
network calls, or `open()` writes that execute unconditionally.

## Dangerous Python Patterns (supplement to 3B blind scans)

Beyond what the blind scans cover, read these with human judgment
(they are not adversarial text, so reading them is safe):

**Unsafe deserialization:**
- `pickle.loads()` / `pickle.load()`: arbitrary code execution
- `yaml.load(data)` without `Loader=yaml.SafeLoader`: arbitrary code execution
- `marshal.loads()`: similar to pickle
- `shelve.open()` on external data

**Dynamic import and execution:**
- `importlib.import_module()` with a variable argument
- `__import__()` with external data
- `exec()` / `compile()` with non-literal strings
- `eval()` with non-literal strings

**Subprocess and shell:**
- `subprocess.run(..., shell=True)`: shell injection risk
- `os.system()`, `os.popen()`
- `commands.getoutput()` (deprecated but present in older packages)

**Network at import time** (module-level, outside any function):
- `urllib.request.urlopen()`, `requests.get()`, etc. at module scope
- Socket connections at module scope

## Comparing Versions

```bash
# Download old version with same safe approach
pip download PKGNAME==OLD_VERSION --no-deps --prefer-binary \
  -d temp/dep-review/PKGNAME/old-pkg/

mkdir -p temp/dep-review/PKGNAME/old/
unzip -q temp/dep-review/PKGNAME/old-pkg/PKGNAME*.whl \
  -d temp/dep-review/PKGNAME/old/ 2>/dev/null \
|| tar xf temp/dep-review/PKGNAME/old-pkg/PKGNAME*.tar.gz \
  -C temp/dep-review/PKGNAME/old/ --strip-components=1

diff -rq \
  temp/dep-review/PKGNAME/old/ \
  temp/dep-review/PKGNAME/unpacked/ \
  --exclude="*.pyc" --exclude="__pycache__"
```

## Provenance Check

```bash
# Show available versions and release dates
python3 -m pip index versions PKGNAME  # pip >= 21.2

# Show current metadata
python3 -m pip show PKGNAME

# PyPI JSON API (no auth required):
curl -s "https://pypi.org/pypi/PKGNAME/VERSION/json" | \
  python3 -c "
import json, sys
d = json.load(sys.stdin)
info = d['info']
print('Author:', info.get('author'))
print('Maintainer:', info.get('maintainer'))
print('Home page:', info.get('home_page'))
print('Project URLs:', info.get('project_urls'))
"
```

Check for: changed author/maintainer, changed homepage or repository URL,
unusual upload timestamp for the version.

## Applying Updates Safely

Update packages **by name**, never an unconstrained upgrade-all:

```bash
# pip: upgrade specific packages
python3 -m pip install --upgrade PKGNAME1 PKGNAME2

# Poetry: update specific packages and regenerate lock
poetry update PKGNAME1 PKGNAME2

# uv: upgrade specific packages
uv pip install --upgrade PKGNAME1 PKGNAME2
```

After updating, regenerate and commit the lock file separately from
application code changes.

## Common False Positives

| Pattern | Legitimate use | Red flag |
|---|---|---|
| `subprocess` | Wrapping CLI tools (git, imagemagick, etc.) | subprocess at import scope |
| `exec()` | Code generation, templating engines | `exec(base64.b64decode(...))` |
| `pickle` | ML model serialization from trusted source | `pickle.loads(data_from_network)` |
| `yaml.load` | Legacy code (safe if data is trusted) | `yaml.load` of user-uploaded content |
| `urllib` | Fetching remote resources (expected behavior) | Fetching at import time |
| `entry_points` | CLI tools, plugins (expected for tool packages) | Unexpected scripts in a library |
