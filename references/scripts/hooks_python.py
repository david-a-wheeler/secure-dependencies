#!/usr/bin/env python3
# hooks_python.py: Python language operations for the dependency analysis driver.
#
# Handles Python package formats (wheel .whl, source distribution .tar.gz)
# and the PyPI registry API. Used for --from pypi; can be reused for other
# Python package indices (DevPI, Artifactory, etc.) with a different registry
# entry in REGISTRY_TO_HOOKS pointing here.
#
# Called by dep_review.py; do not invoke directly.
# Each function accepts a `failures: list[str]` param and calls
# failures.append(...) on errors rather than raising exceptions.
#
# Python stdlib only; no third-party packages required.
# Requires Python 3.10+ (enforced by dep_review.py).

import json
import re
import tarfile
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
import analysis_shared as shared

# Pre-compiled pattern for PEP 427 name normalization (hyphens, underscores, dots).
# Used in multiple places; compiled once here to avoid repeated re.compile calls.
_NORM_RE = re.compile(r'[-_.]+')
_RE_REPRO_CODE = re.compile(r'^diff.*\.(py|pyx|pxd|c|h|cpp|rs|js)\b')
_RE_REPRO_META = re.compile(r'^diff.*(METADATA|RECORD|PKG-INFO|\.dist-info|setup\.py|pyproject\.toml)')

# ---------------------------------------------------------------------------
# Module-level constants read by the driver
# ---------------------------------------------------------------------------

ECOSYSTEM = 'python'

# Python projects use one of several lockfile formats. LOCKFILE_NAME is None
# so the driver skips the single-lockfile warning; LOCKFILE_NAMES lists the
# candidates. get_lockfile_path() returns the first one found.
LOCKFILE_NAME: str | None = None
LOCKFILE_NAMES: list[str] = ['uv.lock', 'poetry.lock', 'Pipfile.lock', 'requirements.txt']

# Name of the primary manifest file (extracted during analysis).
MANIFEST_FILE = 'pyproject-metadata.txt'

# Human-readable summary of what DANGEROUS_PATTERNS scans for.
DANGEROUS_WHAT = (
    'eval/exec variants, shell execution (os.system, subprocess with shell=True), '
    'obfuscated execution, unsafe deserialization (pickle, yaml.load, marshal), '
    'network calls at import scope, credential env-var access, home-dir writes, '
    'dynamic imports on external input, atexit/registration hooks'
)

DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    ('eval-exec',
     r'\b(?:eval|exec)\s*\('),
    ('shell-exec',
     r'\b(?:os\.system|os\.popen|commands\.getoutput)\s*\('),
    ('subprocess-shell',
     r'\bsubprocess\.(?:call|run|Popen|check_output|check_call)\b[^;#\n]*shell\s*=\s*True'),
    ('obfuscated-exec',
     r'(?:base64\.b64decode|codecs\.decode|zlib\.decompress)\b'
     r'(?:[^\n]{0,120})(?:eval|exec)\b'),
    ('pickle-load',
     r'\bpickle\.(?:load|loads|Unpickler)\b'),
    ('unsafe-yaml',
     r'\byaml\.load\s*\([^)]{0,200}(?<!\bLoader\s*=\s*yaml\.SafeLoader)(?<!\bLoader\s*=\s*yaml\.FullLoader)\b'),
    ('marshal-loads',
     r'\bmarshal\.(?:load|loads)\b'),
    ('network-at-load-scope',
     r'^\s*(?:urllib\.request\.|requests\.|http\.client\.|httpx\.|aiohttp\.|socket\.|ftplib\.|smtplib\.)'),
    ('credential-env-vars',
     r'os\.environ\s*(?:\[|\s*\.get\s*\()\s*["\']'
     r'[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_|GH_|GITHUB_|CI_|NPM_|PYPI_)'
     r'[A-Z_]*["\']'),
    ('home-or-shell-write',
     r'(?:open|io\.open|pathlib\.Path)\s*\([^)]*["\']'
     r'(?:~\/|\/home\/|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.ssh\/)'),
    ('dynamic-import',
     r'\b(?:importlib\.import_module|__import__)\s*\([^)]*'
     r'(?:request|user|input|argv|environ|getenv)\b'),
    ('atexit-hooks',
     r'^\s*(?:import\s+atexit\b|atexit\.register\s*\()'),
]

DIFF_PATTERNS: list[tuple[str, str]] = [
    ('diff-sql-injection',
     r'^\+.*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\b.*["\x27]\s*\+'),
    ('diff-cmd-injection',
     r'^\+.*(?:os\.system|subprocess\.(?:call|run|Popen)|shell\s*=\s*True)\s*[\(]'),
    ('diff-hardcoded-secrets',
     r'^\+.*(?:password|passwd|secret|api_key|token)\s*=\s*["\x27][^"\x27]{6,}["\x27]'),
    ('diff-eval',
     r'^\+.*(?:eval|exec)\s*\('),
    ('diff-pickle',
     r'^\+.*pickle\.(?:load|loads|Unpickler)\b'),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_dist_info(unpacked_dir: Path, pkgname: str) -> Path | None:
    """Find the .dist-info directory inside an unpacked wheel.

    Normalizes pkgname (PEP 427: hyphens become underscores, case-insensitive).

    >>> # Returns None for a nonexistent directory
    """
    if not unpacked_dir.is_dir():
        return None
    norm = _NORM_RE.sub('_', pkgname).lower()
    first_dist_info: Path | None = None
    for candidate in unpacked_dir.iterdir():
        if candidate.is_dir() and candidate.name.endswith('.dist-info'):
            if first_dist_info is None:
                first_dist_info = candidate
            cname = _NORM_RE.sub('_', candidate.name.split('-')[0]).lower()
            if cname == norm:
                return candidate
    return first_dist_info


def _parse_metadata(metadata_text: str) -> dict:
    """Parse an RFC 822-style METADATA or PKG-INFO file.

    Returns a dict where multi-valued headers (like Requires-Dist) are lists
    and single-valued headers are strings.

    >>> m = _parse_metadata('Name: foo\\nVersion: 1.0\\nRequires-Dist: bar\\nRequires-Dist: baz\\n')
    >>> m['Name']
    'foo'
    >>> m['Requires-Dist']
    ['bar', 'baz']
    """
    result: dict[str, str | list[str]] = {}
    multi_keys = {
        'Requires-Dist', 'Classifier', 'Project-URL', 'Provides-Extra',
        'Requires-External', 'Provides', 'Obsoletes', 'Requires',
    }
    for line in metadata_text.splitlines():
        if ':' not in line:
            continue
        # Stop at the long description separator
        if line.strip() == 'UNKNOWN' or line.startswith('        '):
            continue
        key, _, value = line.partition(':')
        key = key.strip()
        value = value.strip()
        if not key or ' ' in key:
            continue
        if key in multi_keys:
            lst = result.setdefault(key, [])
            if isinstance(lst, list):
                lst.append(value)
            else:
                result[key] = [str(lst), value]
        else:
            if key not in result:
                result[key] = value
    return result


def _extract_source_url_from_meta(meta: dict) -> str:
    """Extract source/homepage URL from parsed METADATA dict.

    Tries Project-URL: Source, Repository, Homepage in that order,
    then falls back to the Home-page header.

    >>> _extract_source_url_from_meta({'Project-URL': ['Source, https://github.com/foo/bar']})
    'https://github.com/foo/bar'
    >>> _extract_source_url_from_meta({'Home-page': 'https://example.com'})
    'https://example.com'
    >>> _extract_source_url_from_meta({})
    ''
    """
    project_urls = meta.get('Project-URL', [])
    if isinstance(project_urls, str):
        project_urls = [project_urls]
    # Priority: Source > Repository > Code > Homepage
    order = ('source', 'repository', 'code', 'homepage')
    by_label: dict[str, str] = {}
    for entry in project_urls:
        if ',' in entry:
            label, _, url = entry.partition(',')
            by_label[label.strip().lower()] = url.strip()
    for label in order:
        if label in by_label:
            return by_label[label]
    # Also check direct Project-URL entries
    hp = meta.get('Home-page', '') or meta.get('home-page', '')
    if isinstance(hp, list):
        hp = hp[0] if hp else ''
    return str(hp).strip()


def _extract_license_from_meta(meta: dict) -> str:
    """Extract raw license string from METADATA dict.

    Returns the License header value; falls back to extracting from
    Classifier: License :: OSI Approved :: <SPDX_ID> entries.

    >>> _extract_license_from_meta({'License': 'MIT'})
    'MIT'
    >>> _extract_license_from_meta({'Classifier': ['License :: OSI Approved :: MIT License']})
    'MIT License'
    >>> _extract_license_from_meta({})
    ''
    """
    lic = meta.get('License', '') or ''
    if isinstance(lic, list):
        lic = lic[0] if lic else ''
    lic = str(lic).strip()
    if lic and lic.upper() != 'UNKNOWN':
        return lic
    classifiers = meta.get('Classifier', [])
    if isinstance(classifiers, str):
        classifiers = [classifiers]
    for clf in classifiers:
        m = re.search(r'License\s*::\s*OSI Approved\s*::\s*(.+)', clf)
        if m:
            return m.group(1).strip()
        m2 = re.search(r'License\s*::\s*(.+)', clf)
        if m2:
            return m2.group(1).strip()
    return ''


def _unpack_pkg(
    pkg_file: Path,
    target_dir: Path,
    failures: list[str],
    failure_key: str,
) -> str:
    """Unpack a wheel (.whl) or sdist (.tar.gz/.zip) into target_dir.

    Returns a dist_type string: 'wheel', 'sdist', 'sdist-zip', or 'unknown'.
    Uses Python stdlib only (zipfile, tarfile).
    """
    name = pkg_file.name
    try:
        if pkg_file.suffix == '.whl' or name.endswith('.zip'):
            with zipfile.ZipFile(str(pkg_file), 'r') as zf:
                zf.extractall(str(target_dir))
            return 'wheel' if pkg_file.suffix == '.whl' else 'sdist-zip'
        if name.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
            with tarfile.open(str(pkg_file), 'r:*') as tf:
                members = []
                for m in tf.getmembers():
                    # Strip top-level directory (typically pkgname-version/)
                    parts = Path(m.name).parts
                    if len(parts) > 1:
                        m.name = '/'.join(parts[1:])
                        # Guard against path traversal
                        if '..' in Path(m.name).parts:
                            continue
                        members.append(m)
                tf.extractall(str(target_dir), members=members)
            return 'sdist'
    except Exception as exc:
        failures.append(f'{failure_key}: {exc}')
    return 'unknown'


def _get_pkg_file(directory: Path, pkgname: str, version: str) -> Path | None:
    """Find the downloaded package file (wheel preferred, then sdist)."""
    # Wheels use normalized names (hyphens to underscores, case-insensitive)
    norm = _NORM_RE.sub('_',pkgname)
    ver_norm = _NORM_RE.sub('_',version)
    # Search in order of preference: wheels first, then source dists
    for pattern in ('*.whl', '*.tar.gz', '*.tar.bz2', '*.tar.xz', '*.zip'):
        candidates = list(directory.glob(pattern))
        if len(candidates) == 1:
            return candidates[0]
        # Multiple candidates: pick one matching name+version
        for c in candidates:
            cname = _NORM_RE.sub('_',c.stem.split('-')[0]).lower()
            if cname == norm.lower():
                return c
        if candidates:
            return candidates[0]
    return None


# ---------------------------------------------------------------------------
# Public API: called by dep_review.py
# ---------------------------------------------------------------------------

def get_lockfile_path(project_root: Path) -> Path:
    """Return the path to the first existing Python lockfile.

    Tries uv.lock, poetry.lock, Pipfile.lock, requirements.txt in order.
    Falls back to requirements.txt if none found (path may not exist).
    """
    for name in LOCKFILE_NAMES:
        p = project_root / name
        if p.is_file():
            return p
    return project_root / 'requirements.txt'


def download_new(
    pkgname: str,
    version: str,
    work: Path,
    failures: list[str],
    registry_url: str | None = None,
) -> dict:
    """pip download --no-deps into work/, then unpack into work/unpacked/.

    Prefers wheels (--prefer-binary); falls back to sdist.
    Returns dict with keys: unpacked_dir (Path), sha256 (str),
    pkg_file (Path | None), dist_type (str).
    """
    unpacked_dir = work / 'unpacked'
    unpacked_dir.mkdir(parents=True, exist_ok=True)

    dl_cmd = [
        'pip', 'download',
        f'{pkgname}=={version}',
        '--no-deps',
        '--prefer-binary',
        '-d', str(work),
    ]
    if registry_url:
        dl_cmd += ['--index-url', registry_url]

    rc, _out, err = shared.run_cmd(dl_cmd, cwd=work, timeout=180)

    pkg_file = _get_pkg_file(work, pkgname, version)
    sha256 = ''
    dist_type = 'unknown'

    if pkg_file and pkg_file.is_file():
        sha256 = shared.sha256_file(pkg_file)
        (work / 'package-hash.txt').write_text(
            f'{sha256}  {pkg_file.name}\n', encoding='utf-8'
        )
        dist_type = _unpack_pkg(pkg_file, unpacked_dir, failures, 'unpack-new')
        if dist_type == 'unknown' and 'unpack-new' not in ' '.join(failures):
            failures.append('unpack-new')
    else:
        failures.append('pip-download-new')
        sanitized_err = shared.sanitize(err[:500]) if err else ''
        (work / 'package-hash.txt').write_text(
            f'ERROR: pip download failed\n{sanitized_err}\n', encoding='utf-8'
        )

    (work / 'dist-type.txt').write_text(f'DIST_TYPE: {dist_type}\n', encoding='utf-8')

    return {
        'unpacked_dir': unpacked_dir,
        'sha256': sha256,
        'pkg_file': pkg_file,
        'dist_type': dist_type,
    }


def read_manifest(
    pkgname: str,
    version: str,
    unpacked_dir: Path,
    work: Path,
    failures: list[str],
) -> dict:
    """Parse METADATA (wheel) or PKG-INFO (sdist); write manifest-analysis.txt.

    Returns dict with keys: source_url, extensions, executables,
    executables_list, post_install_msg, has_build_hooks, has_install_scripts,
    runtime_dep_lines, manifest_license_raw, manifest_text,
    manifest_extra_file, install_hook_context.
    """
    source_url = ''
    extensions = 'NO'
    executables = 'NO'
    executables_list = ''
    post_install_msg = 'NO'
    has_build_hooks = 'NO'
    manifest_license_raw = ''
    manifest_text = ''
    runtime_dep_lines: list[str] = []

    # Locate METADATA (wheel) or PKG-INFO (sdist)
    dist_info = _find_dist_info(unpacked_dir, pkgname) if unpacked_dir.is_dir() else None
    metadata_file: Path | None = None
    meta: dict = {}

    if dist_info and (dist_info / 'METADATA').is_file():
        metadata_file = dist_info / 'METADATA'
    elif unpacked_dir.is_dir() and (unpacked_dir / 'PKG-INFO').is_file():
        metadata_file = unpacked_dir / 'PKG-INFO'
    else:
        # Try searching one level deep for PKG-INFO
        for child in (unpacked_dir.iterdir() if unpacked_dir.is_dir() else []):
            if child.is_file() and child.name == 'PKG-INFO':
                metadata_file = child
                break

    if metadata_file and metadata_file.is_file():
        manifest_text = metadata_file.read_text(encoding='utf-8', errors='replace')
        # Copy to a canonical name for AI review
        dest_meta = work / 'pyproject-metadata.txt'
        if metadata_file != dest_meta:
            dest_meta.write_text(manifest_text, encoding='utf-8', errors='replace')
        meta = _parse_metadata(manifest_text)
    else:
        failures.append('metadata-missing')

    manifest_lines: list[str] = [f'=== Manifest analysis: {pkgname} {version} ===', '']

    # Read pyproject.toml once; reused for extensions, executables, and build-hook checks.
    ppt_text = ''
    if unpacked_dir.is_dir():
        ppt_path = unpacked_dir / 'pyproject.toml'
        if ppt_path.is_file():
            ppt_text = ppt_path.read_text(encoding='utf-8', errors='replace')

    # Check for C/Cython extensions: presence of .so/.pyd in unpacked wheel,
    # or ext_modules/cffi/Cython in pyproject.toml / setup.py / setup.cfg.
    if unpacked_dir.is_dir():
        native_exts = list(unpacked_dir.rglob('*.so')) + list(unpacked_dir.rglob('*.pyd'))
        if native_exts:
            extensions = 'YES'
    if extensions == 'NO' and unpacked_dir.is_dir():
        if ppt_text and re.search(r'(?i)ext_modules|cffi|Cython|cython|distutils\.extension', ppt_text):
            extensions = 'YES'
        if extensions == 'NO':
            for fname in ('setup.py', 'setup.cfg', 'meson.build'):
                fpath = unpacked_dir / fname
                if fpath.is_file():
                    txt = fpath.read_text(encoding='utf-8', errors='replace')
                    if re.search(r'(?i)ext_modules|cffi|Cython|cython|distutils\.extension', txt):
                        extensions = 'YES'
                        break
    manifest_lines.append(f'HAS_EXTENSIONS: {extensions}')

    # Check for entry points (executables installed to PATH)
    entry_points_file: Path | None = None
    if dist_info and (dist_info / 'entry_points.txt').is_file():
        entry_points_file = dist_info / 'entry_points.txt'
    elif unpacked_dir.is_dir():
        for candidate in unpacked_dir.rglob('entry_points.txt'):
            entry_points_file = candidate
            break

    if entry_points_file and entry_points_file.is_file():
        ep_text = entry_points_file.read_text(encoding='utf-8', errors='replace')
        if re.search(r'^\s*\[console_scripts\]', ep_text, re.MULTILINE):
            executables = 'YES'
            scripts = re.findall(r'^\s*(\S+)\s*=', ep_text, re.MULTILINE)
            executables_list = shared.sanitize(', '.join(scripts[:10]))
    # Also check pyproject.toml project.scripts
    if executables == 'NO' and ppt_text:
        if re.search(r'\[project\.scripts\]|\[project\.gui-scripts\]', ppt_text):
            executables = 'YES'
            scripts = re.findall(r'^\s*(\S+)\s*=', ppt_text, re.MULTILINE)
            executables_list = shared.sanitize(', '.join(scripts[:10]))
    manifest_lines.append(f'HAS_EXECUTABLES: {executables}')
    if executables == 'YES':
        manifest_lines.append(f'EXECUTABLES: {executables_list}')

    # Check for build hooks / install-time code:
    # setup.py with code beyond bare metadata; pyproject.toml build hooks;
    # RECORD present (wheel has one) is normal but setup.py is a risk signal.
    install_script_files: list[tuple[str, Path]] = []
    has_setup_py = False
    if unpacked_dir.is_dir():
        setup_py = unpacked_dir / 'setup.py'
        if setup_py.is_file():
            has_setup_py = True
            sp_text = setup_py.read_text(encoding='utf-8', errors='replace')
            # Flag if setup.py has code beyond simple setup() calls
            suspicious = bool(re.search(
                r'\b(?:os\.system|subprocess|urllib|requests|socket'
                r'|open\s*\(|exec\s*\(|eval\s*\(|__import__|importlib)\b',
                sp_text,
            ))
            if suspicious:
                has_build_hooks = 'YES'
                install_script_files.append(('setup.py', setup_py))
            elif has_setup_py:
                has_build_hooks = 'MAYBE'
        # pyproject.toml build-hooks (hatchling, meson-python, etc.)
        if ppt_text and re.search(r'\[tool\.hatch\.build\.hooks\]|build-backend\s*=', ppt_text):
            if has_build_hooks == 'NO':
                has_build_hooks = 'MAYBE'

    manifest_lines.append(f'HAS_BUILD_HOOKS: {has_build_hooks}')
    if has_setup_py:
        manifest_lines.append('SETUP_PY_PRESENT: YES')

    # Runtime dependencies
    manifest_lines.extend(['', 'RUNTIME_DEPS:'])
    requires_dist = meta.get('Requires-Dist', [])
    if isinstance(requires_dist, str):
        requires_dist = [requires_dist]
    runtime_dep_lines = [str(r) for r in requires_dist if r and '; extra ==' not in str(r)]
    if runtime_dep_lines:
        manifest_lines.extend(shared.sanitize(l) for l in runtime_dep_lines)
    else:
        manifest_lines.append('  (none declared)')

    # Python version requirement
    py_req = meta.get('Requires-Python', '')
    if py_req and isinstance(py_req, str):
        manifest_lines.extend(['', f'REQUIRES_PYTHON: {shared.sanitize(py_req)}'])

    # Homepage / source URL
    source_url = _extract_source_url_from_meta(meta)
    hp_display = shared.sanitize(source_url) if source_url else '(not found)'
    manifest_lines.extend(['', f'HOMEPAGE: {hp_display}'])

    # Authors
    author = meta.get('Author', '') or meta.get('Author-email', '')
    if isinstance(author, list):
        author = ', '.join(author)
    manifest_lines.append(f'AUTHOR: {shared.sanitize(str(author)[:200])}')

    # License
    manifest_license_raw = _extract_license_from_meta(meta)
    manifest_lines.extend([
        '',
        f'LICENSE_DECLARED: {shared.sanitize(manifest_license_raw) or "(not declared)"}',
    ])

    # Summary
    summary = meta.get('Summary', '')
    if isinstance(summary, list):
        summary = summary[0] if summary else ''
    if summary:
        manifest_lines.append(f'SUMMARY: {shared.sanitize(str(summary)[:300])}')

    manifest_lines.append('')
    (work / 'manifest-analysis.txt').write_text(
        '\n'.join(manifest_lines) + '\n', encoding='utf-8'
    )

    # Extract install-time scripts for AI review
    if install_script_files:
        script_lines: list[str] = [
            '=== Install-time scripts for AI review ===',
            '',
            'These files may execute code during pip install (sdist builds).',
            'Review each one for malicious or unexpected behavior.',
            '',
        ]
        for fname, fpath in install_script_files:
            raw = fpath.read_text(encoding='utf-8', errors='replace')
            script_lines.append(f'--- {fname} ---')
            script_lines.append(shared.sanitize(raw))
            script_lines.append('')
        (work / 'install-scripts.txt').write_text(
            '\n'.join(script_lines), encoding='utf-8'
        )

    has_install_scripts = bool(install_script_files)

    # Ecosystem-specific context for the driver's MANIFEST / INSTALL HOOKS section
    install_hook_context: list[str] = []
    if extensions == 'YES':
        install_hook_context.append(
            'Context: C/Cython extension modules detected. These are compiled at install '
            'time from source (for sdists) or pre-compiled (wheels). Verify that setup.py '
            'and any build scripts in the source are benign.'
        )
    if has_build_hooks == 'YES':
        install_hook_context.extend([
            'Context: setup.py contains suspicious code patterns (subprocess, network calls, '
            'exec/eval). These execute during "pip install" of a source distribution.',
            '  Review install-scripts.txt for the extracted setup.py content.',
        ])
    elif has_build_hooks == 'MAYBE':
        install_hook_context.append(
            'Context: setup.py is present and may execute code during sdist installation. '
            'Review install-scripts.txt if present, and confirm the build system is benign.'
        )

    return {
        'source_url': source_url,
        'extensions': extensions,
        'executables': executables,
        'executables_list': executables_list,
        'post_install_msg': post_install_msg,
        'has_build_hooks': has_build_hooks,
        'has_install_scripts': 'YES' if has_install_scripts else 'NO',
        'runtime_dep_lines': runtime_dep_lines,
        'manifest_license_raw': manifest_license_raw,
        'manifest_text': manifest_text,
        'manifest_extra_file': 'pyproject-metadata.txt',
        'install_hook_context': install_hook_context,
    }


def download_old(
    pkgname: str,
    old_ver: str,
    work: Path,
    failures: list[str],
    registry_url: str | None = None,
) -> dict:
    """Download the old version; unpack into work/old/.

    Checks the pip cache first; falls back to pip download.
    Returns dict with keys: ok (bool), source (str), unpacked_dir (Path).
    """
    old_dir = work / 'old'
    old_dir.mkdir(exist_ok=True)
    raw_old = work / 'raw-old-pkg'
    raw_old.mkdir(exist_ok=True)

    ok = False
    source = ''

    # Check pip cache
    rc_cache, cache_out, _ = shared.run_cmd(
        ['pip', 'cache', 'info'], timeout=10
    )
    cache_dir: Path | None = None
    if rc_cache == 0:
        for line in cache_out.splitlines():
            m = re.match(r'Location:\s*(.+)', line)
            if m:
                # pip cache wheels subdirectory
                wheels_dir = Path(m.group(1).strip()) / 'wheels'
                if wheels_dir.is_dir():
                    cache_dir = wheels_dir
                break

    pkg_file_cached: Path | None = None
    if cache_dir and cache_dir.is_dir():
        norm = _NORM_RE.sub('_',pkgname).lower()
        for whl in cache_dir.rglob('*.whl'):
            stem_parts = whl.stem.split('-')
            if (len(stem_parts) >= 2
                    and _NORM_RE.sub('_',stem_parts[0]).lower() == norm
                    and stem_parts[1] == old_ver):
                pkg_file_cached = whl
                break

    if pkg_file_cached:
        dist_type = _unpack_pkg(pkg_file_cached, old_dir, failures, 'unpack-old')
        if dist_type != 'unknown':
            ok = True
            source = 'pip-cache'
    else:
        dl_cmd = [
            'pip', 'download',
            f'{pkgname}=={old_ver}',
            '--no-deps',
            '--prefer-binary',
            '-d', str(raw_old),
        ]
        if registry_url:
            dl_cmd += ['--index-url', registry_url]
        rc_dl, _, _ = shared.run_cmd(dl_cmd, cwd=raw_old, timeout=180)
        if rc_dl == 0:
            pkg_file = _get_pkg_file(raw_old, pkgname, old_ver)
            if pkg_file and pkg_file.is_file():
                dist_type = _unpack_pkg(pkg_file, old_dir, failures, 'unpack-old')
                if dist_type != 'unknown':
                    ok = True
                    source = 'fetched'
                else:
                    failures.append('pip-download-old-unpack')
            else:
                failures.append('pip-download-old-file-missing')
        else:
            failures.append('pip-download-old')

    (work / 'old-version-status.txt').write_text(
        f'OLD_VERSION_SOURCE: {source or "unavailable"}\n', encoding='utf-8'
    )

    return {'ok': ok, 'source': source, 'unpacked_dir': old_dir}


def get_old_dep_lines(
    pkgname: str,
    old_ver: str,
    old_result: dict,
) -> list[str]:
    """Extract runtime Requires-Dist lines from the old version's METADATA.

    Returns list of Requires-Dist strings (without extras markers).
    """
    if not old_result.get('ok'):
        return []
    old_unpacked = old_result.get('unpacked_dir')
    if not old_unpacked or not Path(old_unpacked).is_dir():
        return []
    old_unpacked = Path(old_unpacked)
    dist_info = _find_dist_info(old_unpacked, pkgname)
    metadata_file = None
    if dist_info and (dist_info / 'METADATA').is_file():
        metadata_file = dist_info / 'METADATA'
    elif (old_unpacked / 'PKG-INFO').is_file():
        metadata_file = old_unpacked / 'PKG-INFO'
    if not metadata_file:
        return []
    meta = _parse_metadata(metadata_file.read_text(encoding='utf-8', errors='replace'))
    requires = meta.get('Requires-Dist', [])
    if isinstance(requires, str):
        requires = [requires]
    return [r for r in requires if r and '; extra ==' not in str(r)]


def get_old_license(
    pkgname: str,
    old_ver: str,
    old_unpacked_dir: Path,
) -> str | None:
    """Extract raw license string from old version METADATA.

    Returns the raw string or None if not found.
    """
    if not old_unpacked_dir or not Path(old_unpacked_dir).is_dir():
        return None
    old_unpacked_dir = Path(old_unpacked_dir)
    dist_info = _find_dist_info(old_unpacked_dir, pkgname)
    metadata_file = None
    if dist_info and (dist_info / 'METADATA').is_file():
        metadata_file = dist_info / 'METADATA'
    elif (old_unpacked_dir / 'PKG-INFO').is_file():
        metadata_file = old_unpacked_dir / 'PKG-INFO'
    if not metadata_file:
        return None
    meta = _parse_metadata(metadata_file.read_text(encoding='utf-8', errors='replace'))
    return _extract_license_from_meta(meta) or None


def fetch_all_registry_data(
    pkgname: str,
    version: str,
    work: Path,
    registry_url: str | None = None,
) -> dict:
    """Fetch PyPI JSON API: package info, version history, upload metadata.

    registry_url overrides the default pypi.org base URL for private indices.

    Writes: provenance.txt.
    Returns dict with keys: mfa_status, age_years_float, last_release_days,
    owner_count_int, version_stability, license_from_registry, ver_info_lines.
    """
    api_base = (registry_url.rstrip('/') if registry_url else 'https://pypi.org')
    mfa_status = 'unknown'
    age_years_float: float | None = None
    last_release_days: int | None = None
    owner_count_int: int | None = None
    version_stability = 'unknown'
    license_from_registry: list[str] = []
    ver_info_lines: list[str] = []

    prov_lines: list[str] = [f'=== Provenance: {pkgname} {version} ===', '']

    # Package-level JSON: info + releases
    pkg_data = shared.http_get(f'{api_base}/pypi/{pkgname}/json')
    if pkg_data:
        try:
            pkg_json = json.loads(pkg_data.decode('utf-8', errors='replace'))
            info = pkg_json.get('info', {})

            # Age: find the earliest release in the releases dict
            releases = pkg_json.get('releases', {})
            all_upload_times: list[str] = []
            for rel_files in releases.values():
                for f in (rel_files or []):
                    t = f.get('upload_time_iso_8601', '') or f.get('upload_time', '')
                    if t:
                        all_upload_times.append(t)
            if all_upload_times:
                all_upload_times.sort()
                age_days = shared.days_since(all_upload_times[0])
                if age_days is not None:
                    age_years_float = age_days / 365

            # Last release: find the most recent upload time
            if all_upload_times:
                last_release_days = shared.days_since(all_upload_times[-1])

            # Version stability
            ver_num = str(info.get('version', version))
            if re.search(r'(?i)(alpha|beta|rc|\.dev|\.post|a\d+|b\d+)', ver_num):
                version_stability = 'pre-release'
            elif ver_num.startswith('0.'):
                version_stability = 'pre-release'
            else:
                version_stability = 'stable'

            # License from registry info
            lic = info.get('license', '') or ''
            if lic and lic.upper() not in ('', 'UNKNOWN'):
                license_from_registry.append(str(lic))

            # Yanked status
            yanked = info.get('yanked', False)
            prov_lines.append(f'YANKED: {"YES" if yanked else "NO"}')
            if yanked:
                reason = shared.sanitize(str(info.get('yanked_reason', '')))
                prov_lines.append(f'YANKED_REASON: {reason}')
            prov_lines.append('')

            # Summary provenance info
            author = info.get('author', '') or ''
            maintainer = info.get('maintainer', '') or ''
            home = info.get('home_page', '') or ''
            prov_lines.extend([
                f'AUTHOR: {shared.sanitize(str(author)[:200])}',
                f'MAINTAINER: {shared.sanitize(str(maintainer)[:200])}',
                f'HOME_PAGE: {shared.sanitize(str(home)[:300])}',
                '',
            ])

        except (ValueError, KeyError, TypeError):
            prov_lines.append('REGISTRY_DATA: parse error')

    # Version-specific JSON
    ver_data = shared.http_get(f'{api_base}/pypi/{pkgname}/{version}/json')
    if ver_data:
        try:
            ver_json = json.loads(ver_data.decode('utf-8', errors='replace'))
            urls = ver_json.get('urls', [])
            ver_info_lines.append('VERSION_INFO (selected fields):')
            if urls:
                u = urls[0]
                for key in ('filename', 'upload_time_iso_8601', 'packagetype',
                            'python_version', 'requires_python', 'size'):
                    val = u.get(key, '')
                    ver_info_lines.append(f'  {key}: {shared.sanitize(str(val))[:200]}')
                sha = u.get('digests', {}).get('sha256', '')
                if sha:
                    ver_info_lines.append(f'  sha256: {shared.sanitize(sha)}')
        except (ValueError, KeyError, TypeError):
            ver_info_lines.append('VERSION_INFO: (parse error)')
    else:
        ver_info_lines.append('VERSION_INFO: (unavailable)')

    prov_lines.append('NOTE: PyPI does not expose per-package MFA status via API.')
    prov_lines.append('      MFA_REQUIRED is always "unknown" for PyPI packages.')
    prov_lines.extend(['', *ver_info_lines])

    (work / 'provenance.txt').write_text('\n'.join(prov_lines) + '\n', encoding='utf-8')

    return {
        'mfa_status': mfa_status,
        'age_years_float': age_years_float,
        'last_release_days': last_release_days,
        'owner_count_int': owner_count_int,
        'version_stability': version_stability,
        'license_from_registry': license_from_registry,
        'ver_info_lines': ver_info_lines,
    }


def get_license_candidates(manifest: dict, registry_data: dict) -> list[str]:
    """Delegate to the shared implementation in analysis_shared."""
    return shared.get_license_candidates(manifest, registry_data)


def check_lockfile(
    runtime_dep_lines: list[str],
    old_dep_lines: list[str],
    project_root: Path,
) -> dict:
    """Parse the project lockfile and compare new vs old runtime deps.

    Supports requirements.txt, poetry.lock, uv.lock, and Pipfile.lock.
    Returns dict with keys: added_deps, removed_deps, not_in_lockfile,
    and private keys _lockfile_lines, _dep_lines_new, _dep_lines_old.
    """
    dep_lines_new, dep_lines_old, added_deps, removed_deps = shared.compute_dep_diff(
        runtime_dep_lines, old_dep_lines
    )
    not_in_lockfile: list[str] = []

    # Find the lockfile (try all known formats)
    lockfile = get_lockfile_path(project_root)
    lockfile_lines: list[str] = ['=== Lockfile check ===']

    if lockfile.is_file() and dep_lines_new:
        lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
        lockfile_format = _detect_lockfile_format(lockfile.name)
        lockfile_lines.append(f'LOCKFILE: {lockfile.name} (format: {lockfile_format})')

        for dep_line in dep_lines_new:
            # Extract just the package name from "requests>=2.0,<3" etc.
            m_dep = re.match(r'([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)', dep_line.strip())
            if not m_dep:
                continue
            dep_name = m_dep.group(1)
            safe_dep = shared.sanitize(dep_name)
            norm_dep = _NORM_RE.sub('_',dep_name).lower()

            found = _dep_in_lockfile(dep_name, norm_dep, lf_text, lockfile_format)
            if found:
                lockfile_lines.append(f'IN_LOCKFILE: {safe_dep}')
            else:
                lockfile_lines.append(f'NOT_IN_LOCKFILE: {safe_dep}')
                not_in_lockfile.append(safe_dep)
    else:
        lockfile_lines.append('(no lockfile found or no deps to check)')

    return {
        'added_deps': added_deps,
        'removed_deps': removed_deps,
        'not_in_lockfile': not_in_lockfile,
        '_lockfile_lines': lockfile_lines,
        '_dep_lines_new': dep_lines_new,
        '_dep_lines_old': dep_lines_old,
    }


def _detect_lockfile_format(filename: str) -> str:
    """Return the lockfile format name for a given filename."""
    if filename == 'requirements.txt':
        return 'pip-requirements'
    if filename == 'poetry.lock':
        return 'poetry'
    if filename == 'uv.lock':
        return 'uv'
    if filename == 'Pipfile.lock':
        return 'pipenv'
    return 'unknown'


def _dep_in_lockfile(dep_name: str, norm_dep: str, lf_text: str, fmt: str) -> bool:
    """Return True if dep_name appears in the lockfile text for the given format."""
    if fmt == 'pip-requirements':
        # Look for "pkgname==" (pinned), "pkgname " or "pkgname[" (optional extras)
        return bool(re.search(
            rf'(?i)^{re.escape(dep_name)}\s*(?:==|>=|<=|!=|~=|\[|$)',
            lf_text, re.MULTILINE,
        ))
    if fmt in ('poetry', 'uv'):
        # TOML: name = "pkgname"
        return bool(re.search(
            rf'(?i)name\s*=\s*["\']' + re.escape(dep_name) + r'["\']',
            lf_text,
        ))
    if fmt == 'pipenv':
        # JSON: "pkgname": { ... }
        return bool(re.search(
            rf'(?i)"' + re.escape(dep_name) + r'"\s*:\s*\{{',
            lf_text,
        ))
    # Fallback: case-insensitive substring search on normalized name
    return bool(re.search(
        rf'(?i)\b{re.escape(norm_dep)}\b', lf_text,
    ))


def check_dep_registry(dep_name: str) -> dict:
    """PyPI JSON API lookup for a dep not in lockfile.

    Returns dict with keys: downloads, first_seen, homepage.
    """
    api_data = shared.http_get(f'https://pypi.org/pypi/{dep_name}/json')
    if api_data:
        try:
            info = json.loads(api_data.decode('utf-8', errors='replace'))
            pkg_info = info.get('info', {})
            releases = info.get('releases', {})
            # Total download count is not reliably exposed by the PyPI JSON API
            downloads = 'see pypistats.org'
            # Earliest release date
            all_times: list[str] = []
            for rel_files in releases.values():
                for f in (rel_files or []):
                    t = f.get('upload_time', '')
                    if t:
                        all_times.append(t)
            first_seen = 'unknown'
            if all_times:
                all_times.sort()
                date_m = re.search(r'\d{4}-\d{2}-\d{2}', all_times[0])
                first_seen = shared.sanitize(date_m.group() if date_m else 'unknown')
            home = pkg_info.get('home_page', '') or pkg_info.get('project_url', '') or ''
            return {
                'downloads': shared.sanitize(str(downloads))[:50],
                'first_seen': first_seen,
                'homepage': shared.sanitize(str(home))[:200],
            }
        except (ValueError, KeyError):
            pass
    return {'downloads': 'unavailable', 'first_seen': 'unavailable', 'homepage': 'unavailable'}


def get_transitive_deps(
    pkgname: str,
    version: str,
    lockfile_path: Path,
    work: Path,
) -> dict:
    """Fetch Requires-Dist from PyPI JSON API; compare against lockfile.

    This gives direct dependencies only (one level). A full transitive closure
    would require recursive PyPI API calls; that is deferred to a future
    enhancement.

    Writes: transitive-deps.txt, raw-transitive-deps.txt.
    Returns dict with keys: total (int), not_in_lockfile (list[str]).
    """
    # Fetch requires_dist from PyPI for the specific version
    api_data = shared.http_get(f'https://pypi.org/pypi/{pkgname}/{version}/json')
    requires_dist: list[str] = []
    raw_lines = []
    if api_data:
        try:
            ver_json = json.loads(api_data.decode('utf-8', errors='replace'))
            rd = ver_json.get('info', {}).get('requires_dist') or []
            if isinstance(rd, list):
                for r in rd:
                    if r and '; extra ==' not in str(r):
                        requires_dist.append(str(r))
                        raw_lines.append(str(r))
        except (ValueError, KeyError, TypeError):
            pass
    (work / 'raw-transitive-deps.txt').write_text('\n'.join(raw_lines), encoding='utf-8')

    # Normalize dep names for lockfile lookup
    all_deps: list[str] = []
    for req_line in requires_dist:
        m = re.match(r'([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)', req_line.strip())
        if m and m.group(1) != pkgname:
            all_deps.append(m.group(1))

    total = len(all_deps)
    lf_text = ''
    lf_format = 'unknown'
    if lockfile_path.is_file():
        lf_text = lockfile_path.read_text(encoding='utf-8', errors='replace')
        lf_format = _detect_lockfile_format(lockfile_path.name)

    transitive_new: list[str] = []
    for dep_name in all_deps:
        norm_dep = _NORM_RE.sub('_',dep_name).lower()
        if not _dep_in_lockfile(dep_name, norm_dep, lf_text, lf_format):
            transitive_new.append(dep_name)

    trans_lines = [
        f'=== Transitive dependency footprint: {pkgname} {version} ===',
        f'NOTE: shows direct (level-1) deps from PyPI metadata only.',
        f'TOTAL_DIRECT_DEPS: {total}',
        f'NEW_NOT_IN_LOCKFILE: {len(transitive_new)}',
        '',
        'NEW_PACKAGES (not in current lockfile):',
    ]
    (trans_lines.extend(f'  {shared.sanitize(d)}' for d in transitive_new)
     if transitive_new else trans_lines.append('  none'))
    (work / 'transitive-deps.txt').write_text('\n'.join(trans_lines) + '\n', encoding='utf-8')

    return {'total': total, 'not_in_lockfile': transitive_new}


def check_alternatives(
    pkgname: str,
    version: str,
    work: Path,
    project_root: Path,
    registry_url: str | None = None,
) -> dict:
    """Check for typosquat, slopsquat, and stdlib/builtins overlap signals.

    Three checks:
    A: Python stdlib module names; flag exact matches (dependency confusion)
        and near-matches (typosquat).
    B: Installed packages via 'pip list'; flag exact matches and near-matches.
    C: Project lockfile deps; flag near-matches.
    D: Structural heuristics: normalization (hyphens/underscores, python-/py- prefix).

    Writes: alternatives.txt to work dir.
    Returns dict with keys: concerns, notes, pkg_count, lockfile_count.
    """
    concerns: list[str] = []
    notes: list[str] = []
    pkg_lower = pkgname.lower()
    norm_pkg = _NORM_RE.sub('_',pkg_lower)

    # --- A: Python stdlib module names ---
    stdlib_names = _get_stdlib_names()

    for mod in stdlib_names:
        mod_lower = mod.lower()
        if mod_lower == pkg_lower or _NORM_RE.sub('_',mod_lower) == norm_pkg:
            concerns.append(
                f'EXACT_STDLIB_MATCH: "{pkgname}" matches Python stdlib module "{mod}". '
                'This is a strong dependency-confusion signal: the stdlib will shadow '
                'an external package of the same name in most Python contexts.'
            )
        else:
            dist = shared.levenshtein(pkg_lower, mod_lower)
            if dist == 1:
                concerns.append(
                    f'NEAR_MATCH(dist=1): "{pkgname}" is one edit from stdlib module "{mod}". '
                    'Classic typosquat pattern.'
                )
            elif dist == 2:
                notes.append(
                    f'NEAR_MATCH(dist=2): "{pkgname}" is two edits from stdlib module "{mod}".'
                )

    # --- B: Installed packages via pip list ---
    installed_names: list[str] = []
    rc_pip, pip_out, _ = shared.run_cmd(['pip', 'list', '--format=columns'], timeout=30)
    if rc_pip == 0:
        for line in pip_out.splitlines()[2:]:  # skip header rows
            parts = line.split()
            if parts:
                installed_names.append(parts[0])

    stdlib_lower = {m.lower() for m in stdlib_names}
    for pkg in installed_names:
        pkg_inst_lower = pkg.lower()
        if pkg_inst_lower in stdlib_lower:
            continue  # already checked in A
        if pkg_inst_lower == pkg_lower or _NORM_RE.sub('_',pkg_inst_lower) == norm_pkg:
            concerns.append(
                f'EXACT_INSTALLED_MATCH: "{pkgname}" matches already-installed package "{pkg}". '
                'Installing an external package with the same name as an existing installation '
                'could be a dependency-confusion or supply-chain attack.'
            )
        else:
            dist = shared.levenshtein(pkg_lower, pkg_inst_lower)
            if dist == 1:
                concerns.append(
                    f'NEAR_MATCH(dist=1): "{pkgname}" is one edit from installed package "{pkg}". '
                    'Classic typosquat pattern.'
                )
            elif dist == 2:
                notes.append(
                    f'NEAR_MATCH(dist=2): "{pkgname}" is two edits from installed package "{pkg}".'
                )

    # --- C: Project lockfile deps ---
    lockfile = get_lockfile_path(project_root)
    lockfile_names: list[str] = []
    if lockfile.is_file():
        lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
        lf_fmt = _detect_lockfile_format(lockfile.name)
        if lf_fmt == 'pip-requirements':
            for line in lf_text.splitlines():
                m = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)', line.strip())
                if m and not line.strip().startswith('#'):
                    lockfile_names.append(m.group(1))
        elif lf_fmt in ('poetry', 'uv'):
            for m in re.finditer(r'name\s*=\s*["\']([^"\']+)["\']', lf_text):
                lockfile_names.append(m.group(1))
        elif lf_fmt == 'pipenv':
            for m in re.finditer(r'"([A-Za-z0-9][A-Za-z0-9._-]*)"\s*:', lf_text):
                lockfile_names.append(m.group(1))

    installed_and_stdlib_lower = {p.lower() for p in installed_names} | stdlib_lower
    for dep in lockfile_names:
        dep_lower = dep.lower()
        if dep_lower in installed_and_stdlib_lower:
            continue  # already checked
        if dep_lower == pkg_lower or _NORM_RE.sub('_',dep_lower) == norm_pkg:
            concerns.append(
                f'EXACT_LOCKFILE_MATCH: "{pkgname}" matches existing lockfile dep "{dep}". '
                'This name is already in use in this project.'
            )
        else:
            dist = shared.levenshtein(pkg_lower, dep_lower)
            if dist == 1:
                concerns.append(
                    f'NEAR_LOCKFILE_MATCH(dist=1): "{pkgname}" is one edit from '
                    f'lockfile dep "{dep}". Possible targeted typosquat.'
                )
            elif dist == 2:
                notes.append(
                    f'NEAR_LOCKFILE_MATCH(dist=2): "{pkgname}" is two edits from '
                    f'lockfile dep "{dep}".'
                )

    # --- D: Structural heuristics ---
    # D1: hyphen/underscore normalization (PyPI treats these as equivalent)
    all_known_lower = {p.lower() for p in installed_names} | stdlib_lower | {d.lower() for d in lockfile_names}
    if norm_pkg != pkg_lower and norm_pkg in all_known_lower:
        concerns.append(
            f'NORMALIZATION_MATCH: "{pkgname}" normalizes to the same name as an existing '
            f'package/module ("{norm_pkg}"). PyPI normalizes hyphens, underscores, and dots; '
            'a package relying on this difference may be exploiting naming confusion.'
        )

    # D2: Python-specific prefix/suffix stripping
    strip_prefixes = ('python-', 'py-', 'pypi-')
    strip_suffixes = ('-python', '-py')
    for prefix in strip_prefixes:
        if pkg_lower.startswith(prefix):
            base = pkg_lower[len(prefix):]
            if base in all_known_lower:
                concerns.append(
                    f'PREFIX_SHADOW: "{pkgname}" appears to wrap existing package/module '
                    f'"{base}" (stripped prefix "{prefix}"). '
                    'Verify this wrapper is intentional.'
                )
    for suffix in strip_suffixes:
        if pkg_lower.endswith(suffix):
            base = pkg_lower[: -len(suffix)]
            if base in all_known_lower:
                concerns.append(
                    f'SUFFIX_SHADOW: "{pkgname}" appears to wrap existing package/module '
                    f'"{base}" (stripped suffix "{suffix}"). '
                    'Verify this wrapper is intentional.'
                )

    # --- Write report ---
    lines = [
        f'=== Alternatives check: {pkgname} {version} ===',
        f'Stdlib modules checked  : {len(stdlib_names)}',
        f'Installed pkgs checked  : {len(installed_names)}',
        f'Lockfile deps checked   : {len(lockfile_names)}',
        '',
    ]
    if concerns:
        lines.append(f'CONCERNS ({len(concerns)}):')
        for c in concerns:
            lines.append(f'  [!] {c}')
    else:
        lines.append('CONCERNS: none')
    lines.append('')
    if notes:
        lines.append(f'NOTES ({len(notes)}):')
        for n in notes:
            lines.append(f'  [-] {n}')
    else:
        lines.append('NOTES: none')

    work.mkdir(parents=True, exist_ok=True)
    (work / 'alternatives.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')

    return {
        'concerns': concerns,
        'notes': notes,
        'pkg_count': len(stdlib_names) + len(installed_names),
        'lockfile_count': len(lockfile_names),
    }


def _get_stdlib_names() -> list[str]:
    """Return a list of Python stdlib module names.

    Uses sys.stdlib_module_names (Python 3.10+) when available, with
    a curated fallback list covering the most commonly typosquatted names.
    """
    if hasattr(sys, 'stdlib_module_names'):
        return sorted(sys.stdlib_module_names)
    # Curated fallback: commonly targeted stdlib/builtin names
    return [
        'abc', 'ast', 'asyncio', 'base64', 'binascii', 'builtins',
        'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd', 'code',
        'codecs', 'codeop', 'colorsys', 'compileall', 'concurrent',
        'configparser', 'contextlib', 'copy', 'copyreg', 'csv',
        'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm',
        'decimal', 'difflib', 'dis', 'doctest', 'email', 'encodings',
        'enum', 'errno', 'faulthandler', 'filecmp', 'fileinput',
        'fnmatch', 'fractions', 'ftplib', 'functools', 'gc',
        'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip',
        'hashlib', 'heapq', 'hmac', 'html', 'http', 'idlelib',
        'imaplib', 'importlib', 'inspect', 'io', 'ipaddress',
        'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
        'locale', 'logging', 'lzma', 'mailbox', 'math', 'mimetypes',
        'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis',
        'nntplib', 'numbers', 'operator', 'optparse', 'os',
        'ossaudiodev', 'pathlib', 'pdb', 'pickle', 'pickletools',
        'pipes', 'pkgutil', 'platform', 'plistlib', 'poplib',
        'posix', 'posixpath', 'pprint', 'profile', 'pstats',
        'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc',
        'queue', 'quopri', 'random', 're', 'readline', 'reprlib',
        'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
        'selectors', 'shelve', 'shlex', 'shutil', 'signal',
        'site', 'smtplib', 'sndhdr', 'socket', 'socketserver',
        'spwd', 'sqlite3', 'ssl', 'stat', 'statistics', 'string',
        'stringprep', 'struct', 'subprocess', 'sunau', 'symtable',
        'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile',
        'telnetlib', 'tempfile', 'termios', 'test', 'textwrap',
        'threading', 'time', 'timeit', 'tkinter', 'token',
        'tokenize', 'tomllib', 'trace', 'traceback', 'tracemalloc',
        'tty', 'turtle', 'turtledemo', 'types', 'typing',
        'unicodedata', 'unittest', 'urllib', 'uu', 'uuid',
        'venv', 'warnings', 'wave', 'weakref', 'webbrowser',
        'wsgiref', 'xdrlib', 'xml', 'xmlrpc', 'zipapp',
        'zipfile', 'zipimport', 'zlib', 'zoneinfo',
    ]


def get_diff_excludes() -> list[str]:
    """Return glob patterns to exclude from diff (Python packaging artifacts)."""
    return ['*.pyc', '__pycache__', '*.egg-info', '*.dist-info', 'PKG-INFO']


def get_pkg_src_excludes() -> tuple[re.Pattern, re.Pattern]:
    """Return (pkg_excludes, src_excludes) compiled regex patterns.

    pkg_excludes: paths in the wheel/sdist to ignore during pkg-vs-source comparison.
    src_excludes: paths in the source clone to ignore.
    """
    pkg_ex = re.compile(
        r'^\.git/'
        r'|^LICEN[SC]E(?:\.[a-zA-Z]+)?$'
        r'|^COPYING(?:\.[a-zA-Z]+)?$'
        r'|\.dist-info/'
        r'|\.egg-info/'
        r'|__pycache__/'
        r'|\.pyc$'
        r'|^PKG-INFO$'
    )
    src_ex = re.compile(
        r'^\.git/'
        r'|__pycache__/'
        r'|\.pyc$'
        r'|\.egg-info/'
        r'|^docs?/'
        r'|^tests?/'
        r'|^\.tox/'
        r'|^\.nox/'
    )
    return pkg_ex, src_ex


def find_source_root(source_dir: Path) -> Path:
    """Return the subdirectory of source_dir containing the package source.

    For Python, the package is usually at the repo root or in a src/ layout.
    If a src/ directory contains a top-level package, use that.
    Otherwise return source_dir itself.
    """
    src_layout = source_dir / 'src'
    if src_layout.is_dir():
        # src/ layout: package is inside src/
        children = [c for c in src_layout.iterdir() if c.is_dir() and not c.name.startswith('.')]
        if children:
            return src_layout
    return source_dir


def get_deep_source_config() -> dict:
    """Return deep source comparison config for Python."""
    return {'primary_label': 'Python', 'primary_pattern': r'\.(py|pyx|pxd)$'}


def reproducible_build(
    pkgname: str,
    version: str,
    work: Path,
    sandbox: str,
) -> tuple[str, int, int]:
    """Attempt to build a wheel from source and compare with the distributed wheel.

    Uses 'python -m build --wheel --no-isolation' to build from the cloned source.
    Returns (repro_result, code_diffs, metadata_diffs).

    repro_result is one of:
      SKIPPED
      INCONCLUSIVE
      EXACTLY REPRODUCIBLE (sha256 match)
      EXACTLY REPRODUCIBLE (content match)
      FUNCTIONALLY EQUIVALENT (metadata-only diffs)
      UNEXPECTED DIFFERENCES
    """
    clone_dir = work / 'source'
    built_whl_dir = work / 'raw-built-whl'
    built_whl_dir.mkdir(exist_ok=True)

    lines: list[str] = [
        f'=== Reproducible build: {pkgname} {version} ===',
        f'Sandbox: {sandbox}',
        '',
    ]

    def finish(result: str, extra: list[str] | None = None) -> tuple[str, int, int]:
        lines.append(f'REPRODUCIBLE_BUILD: {result}')
        if extra:
            lines.extend(extra)
        (work / 'reproducible-build.txt').write_text(
            '\n'.join(lines) + '\n', encoding='utf-8'
        )
        return result, 0, 0

    if not clone_dir.is_dir():
        return finish('SKIPPED (no source clone)')

    rc_pv, pv_out, _ = shared.run_cmd(['python3', '--version'], timeout=10)
    python_ver = shared.sanitize(pv_out.strip()) if rc_pv == 0 else 'unknown'
    lines.append(f'PYTHON_VERSION: {python_ver}')

    # Locate pyproject.toml or setup.py in the clone
    build_root = clone_dir
    for candidate in (clone_dir / 'pyproject.toml', clone_dir / 'setup.py'):
        if candidate.is_file():
            build_root = clone_dir
            break
    else:
        # Try one level down
        for child in clone_dir.iterdir():
            if child.is_dir() and ((child / 'pyproject.toml').is_file()
                                   or (child / 'setup.py').is_file()):
                build_root = child
                break

    if not (build_root / 'pyproject.toml').is_file() and not (build_root / 'setup.py').is_file():
        return finish('SKIPPED (no pyproject.toml or setup.py in source)')

    lines.append(f'BUILD_ROOT: {shared.sanitize(str(build_root))}')
    build_log_path = work / 'raw-build-output.txt'
    build_ok = False

    build_cmd_base = [
        'python3', '-m', 'build', '--wheel', '--no-isolation',
        '--outdir', str(built_whl_dir),
        str(build_root),
    ]

    if sandbox == 'bwrap':
        bwrap_args = [
            'bwrap',
            '--ro-bind', str(build_root), '/src',
            '--bind', str(built_whl_dir), '/out',
            '--ro-bind', '/usr', '/usr',
            '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/etc', '/etc',
            '--tmpfs', '/tmp',
            '--proc', '/proc',
            '--dev', '/dev',
            '--unshare-net',
            '--die-with-parent',
            '--chdir', '/src',
        ]
        if Path('/lib64').is_dir():
            bwrap_args += ['--ro-bind', '/lib64', '/lib64']
        bwrap_args += ['python3', '-m', 'build', '--wheel', '--no-isolation', '--outdir', '/out']
        rc_b, b_out, b_err = shared.run_cmd(bwrap_args, timeout=300)
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = rc_b == 0

    elif sandbox in ('docker', 'podman'):
        rc_pv2, pv2_out, _ = shared.run_cmd(['python3', '-c', 'import sys; print(sys.version_info[:2])'], timeout=5)
        py_img_tag = '3'
        if rc_pv2 == 0:
            m = re.search(r'\((\d+),\s*(\d+)\)', pv2_out)
            if m:
                py_img_tag = f'{m.group(1)}.{m.group(2)}'
        rc_b, b_out, b_err = shared.run_cmd(
            [sandbox, 'run', '--rm',
             '--network', 'none',
             '-v', f'{build_root}:/src:ro',
             '-v', f'{built_whl_dir}:/out',
             f'python:{py_img_tag}',
             'sh', '-c',
             'pip install build --quiet && python -m build --wheel --no-isolation --outdir /out /src'],
            timeout=600,
        )
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = rc_b == 0

    else:
        # No sandbox or firejail: run directly
        rc_b, b_out, b_err = shared.run_cmd(build_cmd_base, cwd=build_root, timeout=300)
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = rc_b == 0

    lines.append(f'BUILD_STATUS: {"yes" if build_ok else "no"}')

    if not build_ok:
        return finish('INCONCLUSIVE (build failed)')

    built_whls = list(built_whl_dir.glob('*.whl'))
    if not built_whls:
        return finish('INCONCLUSIVE (no .whl produced)')
    built_whl = built_whls[0]

    built_sha = shared.sha256_file(built_whl)
    pkg_hash_file = work / 'package-hash.txt'
    dist_sha = ''
    if pkg_hash_file.is_file():
        first_line = pkg_hash_file.read_text(encoding='utf-8').splitlines()[0]
        dist_sha = first_line.split()[0] if first_line.split() else ''

    lines.append(f'BUILT_SHA256: {shared.sanitize(built_sha)}')
    lines.append(f'DISTRIBUTED_SHA256: {shared.sanitize(dist_sha or "UNKNOWN")}')

    if built_sha and built_sha == dist_sha:
        return finish('EXACTLY REPRODUCIBLE (sha256 match)')

    # Hashes differ: unpack both and compare contents
    built_unpacked = work / 'raw-built-unpacked'
    built_unpacked.mkdir(exist_ok=True)
    _unpack_pkg(built_whl, built_unpacked, [], 'repro-unpack')

    dist_unpacked = work / 'unpacked'
    if not dist_unpacked.is_dir():
        return finish('INCONCLUSIVE (hashes differ, no dist unpacked dir)')

    rc_diff, diff_out, _ = shared.run_cmd(
        ['diff', '-r', str(built_unpacked), str(dist_unpacked),
         '--exclude=*.pyc', '--exclude=__pycache__', '--exclude=RECORD'],
        timeout=60,
    )
    (work / 'raw-repro-diff.txt').write_text(diff_out, encoding='utf-8', errors='replace')

    diff_line_count = len(diff_out.splitlines())
    lines.append(f'CONTENT_DIFF_LINES: {diff_line_count}')

    if diff_line_count == 0:
        return finish('EXACTLY REPRODUCIBLE (content match)')

    differing: list[str] = []
    code_diffs = 0
    metadata_diffs = 0
    for line in diff_out.splitlines():
        if line.startswith('Only in') or line.startswith('diff '):
            differing.append(shared.sanitize(line))
        if _RE_REPRO_CODE.search(line):
            code_diffs += 1
        if _RE_REPRO_META.search(line):
            metadata_diffs += 1

    lines.append('DIFFERING_FILES (sanitized):')
    lines.extend(differing[:50])
    lines.append(f'CODE_FILE_DIFFS: {code_diffs}')
    lines.append(f'METADATA_FILE_DIFFS: {metadata_diffs}')

    if code_diffs > 0:
        extra = ['WARNING: code files differ (possible injected code; human review required)']
        result = 'UNEXPECTED DIFFERENCES'
    else:
        extra = []
        result = 'FUNCTIONALLY EQUIVALENT (metadata-only diffs)'

    lines.append(f'REPRODUCIBLE_BUILD: {result}')
    lines.extend(extra)
    (work / 'reproducible-build.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return result, code_diffs, metadata_diffs
