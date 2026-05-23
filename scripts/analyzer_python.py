#!/usr/bin/env python3
# analyzer_python.py: Python language operations for the dependency analysis driver.
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
import urllib.parse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
import analysis_shared as shared

# Pre-compiled pattern for PEP 427 name normalization (hyphens, underscores, dots).
# Used in multiple places; compiled once here to avoid repeated re.compile calls.
_NORM_RE = re.compile(r'[-_.]+')
_RE_REPRO_CODE = re.compile(r'^diff.*\.(py|pyx|pxd|c|h|cpp|rs|js)\b')
_RE_REPRO_META = re.compile(r'^diff.*(METADATA|RECORD|PKG-INFO|\.dist-info|setup\.py|pyproject\.toml)')

# VCS dependency detection (Idea 12 analog for Python).
# PEP 508 direct URL format: "package @ git+https://..." bypasses PyPI.
# Composed from shared.VCS_SCHEMES_RE and shared.VCS_HOSTNAMES_RE so that
# a new VCS transport added to analysis_shared.py propagates here.
_RE_PY_VCS_DEP = re.compile(
    r'@\s*(?:' + shared.VCS_SCHEMES_RE
    + r'|https?://(?:' + shared.VCS_HOSTNAMES_RE + r')/)',
    re.IGNORECASE,
)
# Commit hash: 7-40 hex chars after '@' (pip/uv URL) or '#' (fragment).
# Uses shared.COMMIT_HASH_RE so the range stays in sync with JS/Ruby.
_RE_PY_COMMIT_HASH = re.compile(
    r'[@#]' + shared.COMMIT_HASH_RE + r'(?:\s|$|[#/.])', re.IGNORECASE,
)
# Foreign URL in requirements.txt: lines starting with a VCS scheme or a
# non-PyPI http URL bypass the registry. Anchored to start of line (no MULTILINE;
# used with re.match on individual stripped lines).
_RE_PIP_FOREIGN_URL = re.compile(
    r'^(?:' + shared.VCS_SCHEMES_RE
    + r'|(?:https?|ftp)://(?!(?:files\.pythonhosted\.org|pypi\.org)/))',
    re.IGNORECASE,
)
# VCS source entries in poetry.lock (type = "git") and uv.lock
# (source = { git = "..." }). Both bypass PyPI entirely.
# Poetry uses a [package.source] section; uv uses an inline TOML table.
_RE_POETRY_GIT_SOURCE = re.compile(r'type\s*=\s*"git"', re.IGNORECASE)
_RE_POETRY_GIT_URL = re.compile(
    r'url\s*=\s*"([^"]{1,300})"', re.IGNORECASE)
_RE_POETRY_GIT_REF = re.compile(
    r'resolved_reference\s*=\s*"([0-9a-f]{7,64})"', re.IGNORECASE)
_RE_UV_GIT_SOURCE = re.compile(
    r'source\s*=\s*\{\s*git\s*=\s*"([^"]{1,300})"', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public API: called by dep_review.py
# ---------------------------------------------------------------------------

class PythonAnalyzer(shared.EcosystemAnalyzer):
    ECOSYSTEM = 'python'
    OSV_ECOSYSTEM = 'PyPI'
    OSS_REBUILD_ECOSYSTEM = 'pypi'
    NATIVE_BINARY_SUFFIXES: frozenset[str] = frozenset({'.so', '.pyd'})

    # Python projects use one of several lockfile formats. LOCKFILE_NAME is None
    # so the driver skips the single-lockfile warning; LOCKFILE_NAMES lists the
    # candidates. get_lockfile_path() returns the first one found.
    LOCKFILE_NAME: str | None = None
    LOCKFILE_NAMES: list[str] = ['uv.lock', 'poetry.lock', 'Pipfile.lock', 'requirements.txt']

    # Name of the primary manifest file (extracted during analysis).
    MANIFEST_FILE = 'pyproject-metadata.txt'

    # Human-readable summary of what DANGEROUS_PATTERNS scans for.
    # ReDoS prevention (CWE-400): all patterns use bounded quantifiers so that
    # worst-case PCRE backtracking is O(bound^2) rather than O(n^2) or worse.
    # Unbounded character-class repetitions ([^x]+, [^x]*) are capped with
    # {1,N} or {0,N}.  See AGENTS.md for the full policy.
    DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
        ('eval-exec',
         r'\b(?:eval|exec)\s*\(',
         'eval/exec variants'),
        ('shell-exec',
         r'\b(?:os\.system|os\.popen|commands\.getoutput)\s*\(',
         'shell execution (os.system, os.popen, commands.getoutput)'),
        ('subprocess-shell',
         r'\bsubprocess\.(?:call|run|Popen|check_output|check_call)\b[^;#\n]*shell\s*=\s*True',
         'subprocess with shell=True'),
        ('obfuscated-exec',
         r'(?:base64\.b64decode|codecs\.decode|zlib\.decompress)\b'
         r'(?:[^\n]{0,120})(?:eval|exec)\b',
         'obfuscated execution (base64/zlib decode into eval/exec)'),
        ('pickle-load',
         r'\bpickle\.(?:load|loads|Unpickler)\b',
         'unsafe deserialization via pickle'),
        # yaml.load without a safe Loader argument.
        # Variable-width lookbehinds are unsupported; use a lookahead instead.
        # [^)]{0,200} bounds backtracking in the lookahead (ReDoS: O(200^2) max).
        ('unsafe-yaml',
         r'\byaml\.load\s*\((?![^)]{0,200}\bLoader\s*=\s*yaml\.(?:SafeLoader|FullLoader|BaseLoader))',
         'unsafe YAML deserialization (yaml.load without SafeLoader)'),
        ('marshal-loads',
         r'\bmarshal\.(?:load|loads)\b',
         'unsafe deserialization via marshal'),
        ('network-at-load-scope',
         r'^\s*(?:urllib\.request\.|requests\.|http\.client\.|httpx\.|aiohttp\.|socket\.|ftplib\.|smtplib\.)',
         'network calls at import scope'),
        ('credential-env-vars',
         r'os\.environ\s*(?:\[|\s*\.get\s*\()\s*["\'][A-Z_]*(?:'
         + shared.CRED_KEYWORDS_RE + r')[A-Z_]*["\']',
         'credential environment variable access (AWS/cloud keys)'),
        # [^)]{0,200} rather than [^)]* to cap backtracking (ReDoS: O(200^2) max).
        ('home-or-shell-write',
         r'(?:open|io\.open|pathlib\.Path)\s*\([^)]{0,200}["\'](?:'
         + shared.HOME_PATHS_RE + r')',
         'home-dir or shell-config writes'),
        # [^)]{0,200} caps backtracking before the keyword alternatives.
        ('dynamic-import',
         r'\b(?:importlib\.import_module|__import__)\s*\([^)]{0,200}'
         r'(?:request|user|input|argv|environ|getenv)\b',
         'dynamic imports on external input (importlib/__import__ with user data)'),
        ('atexit-hooks',
         r'^\s*(?:import\s+atexit\b|atexit\.register\s*\()',
         'atexit/cleanup hook registration'),
        # Worm propagation: publishing to PyPI from inside an install hook.
        # Two twine forms: shell string "twine upload" and list ["twine","upload"].
        ('self-publish',
         r'\btwine\s+upload\b'
         r'|["\x27]twine["\x27][^)\n]{0,80}["\x27]upload["\x27]'
         r'|\bpoetry\s+publish\b'
         r'|\bflit\s+publish\b'
         r'|\bhatch\s+publish\b'
         r'|\bpython[^\n]{0,60}setup\.py[^\n]{0,40}\bupload\b',
         'self-publish worm propagation (twine/poetry/flit/hatch upload from install hook)'),
        # boto3 calls are not caught by network-at-load-scope (which checks urllib etc.).
        # Shared provider hostnames come from shared.CLOUD_SECRET_HOSTS_RE.
        ('cloud-secret-api',
         r'\bboto3\.client\s*\(\s*["\x27]secretsmanager["\x27]'
         r'|\bboto3\.client\s*\(\s*["\x27]ssm["\x27]'
         r'|google\.cloud\.secretmanager'
         r'|from\s+google\.cloud\s+import\s+secretmanager\b'
         r'|azure\.keyvault\.secrets\b'
         r'|' + shared.CLOUD_SECRET_HOSTS_RE,
         'cloud secret-manager API calls (boto3, GCP Secret Manager, Azure Key Vault)'),
        # (?:dict\s*\(\s*)? is a short optional prefix (no backtracking cascade)
        # that matches json.dumps(dict(os.environ)) as well as json.dumps(os.environ).
        ('env-enumeration',
         r'(?:json\.dumps|pprint\.pformat)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b',
         'bulk environment variable serialization (credential harvest)'),
        # [^)]{0,300} bounds backtracking to O(300) per anchor (safe).
        ('shadow-runtime',
         r'(?:subprocess\.(?:call|run|Popen|check_output|check_call)'
         r'|os\.(?:system|popen))\s*\([^)]{0,300}'
         r'\b' + shared.SHADOW_RUNTIME_NAMES_RE + r'\b',
         'shadow runtime invocation (bun/deno/pkgx spawned from source)'),
        # Python has requests/urllib; spawning curl/wget/nc is a strong
        # signal of a second-stage payload downloader.
        ('cross-lang-spawn',
         r'(?:subprocess\.(?:call|run|Popen|check_output|check_call)'
         r'|os\.(?:system|popen))\s*\([^)]{0,300}'
         r'\b' + shared.CROSS_LANG_TOOLS_RE + r'\b',
         'cross-language spawn (curl/wget/nc as second-stage downloader)'),
    ]

    # ReDoS prevention: diff lines start with ^\+ so they are anchored, but
    # .* before a keyword still causes O(n^2) backtracking on long lines.
    # [^\n]{0,500} caps worst-case to O(500^2).  Two .* on the same pattern
    # (keyword.*suffix) compounds to O(n^2) even for moderate line lengths;
    # bounding both fixes it.
    DIFF_PATTERNS: list[tuple[str, str]] = [
        # Two [^\n]{0,500} replace two .* to prevent the compounded O(n^2)
        # backtracking of keyword.*suffix when neither keyword nor suffix appears.
        ('diff-sql-injection',
         r'^\+[^\n]{0,500}\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\b[^\n]{0,500}["\x27]\s*\+'),
        ('diff-cmd-injection',
         r'^\+[^\n]{0,500}(?:os\.system|subprocess\.(?:call|run|Popen)|shell\s*=\s*True)\s*[\(]'),
        # [^"\x27]{6,200}: lower bound ensures a non-trivial value; upper bound
        # prevents O(n^2) backtracking when no closing quote follows.
        ('diff-hardcoded-secrets',
         r'^\+[^\n]{0,500}(?:password|passwd|secret|api_key|token)\s*=\s*["\x27][^"\x27]{6,200}["\x27]'),
        ('diff-eval',
         r'^\+[^\n]{0,500}(?:eval|exec)\s*\('),
        ('diff-pickle',
         r'^\+[^\n]{0,500}pickle\.(?:load|loads|Unpickler)\b'),
    ]

    # Size thresholds for setup.py.
    # Even numpy's historically large setup.py was under 1000 lines;
    # 40 KB or 1000 lines is extremely unusual for any legitimate package.
    SETUP_PY_WARN_BYTES: int = 40_000
    SETUP_PY_WARN_LINES: int = 1_000

    def extract_source_url(self, raw_data: object) -> str:
        """Extract source URL from a parsed METADATA dict.

        Tries Project-URL: Source, Repository, Homepage in that order,
        then falls back to the Home-page header.

        >>> PythonAnalyzer(None).extract_source_url({'Project-URL': ['Source, https://github.com/foo/bar']})
        'https://github.com/foo/bar'
        >>> PythonAnalyzer(None).extract_source_url({'Home-page': 'https://example.com'})
        'https://example.com'
        >>> PythonAnalyzer(None).extract_source_url({})
        ''
        """
        meta = raw_data if isinstance(raw_data, dict) else {}
        project_urls = meta.get('Project-URL', [])
        if isinstance(project_urls, str):
            project_urls = [project_urls]
        order = ('source', 'repository', 'code', 'homepage')
        by_label: dict[str, str] = {}
        for entry in project_urls:
            if ',' in entry:
                label, _, url = entry.partition(',')
                by_label[label.strip().lower()] = url.strip()
        for label in order:
            if label in by_label:
                return by_label[label]
        hp = meta.get('Home-page', '') or meta.get('home-page', '')
        if isinstance(hp, list):
            hp = hp[0] if hp else ''
        return str(hp).strip()

    def extract_license(self, raw_data: object) -> str:
        """Extract raw license string from a parsed METADATA dict.

        Returns the License header value; falls back to Classifier entries.

        >>> PythonAnalyzer(None).extract_license({'License': 'MIT'})
        'MIT'
        >>> PythonAnalyzer(None).extract_license({'Classifier': ['License :: OSI Approved :: MIT License']})
        'MIT License'
        >>> PythonAnalyzer(None).extract_license({})
        ''
        """
        meta = raw_data if isinstance(raw_data, dict) else {}
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

    def _find_dist_info(
        self, unpacked_dir: Path, pkgname: str,
    ) -> Path | None:
        """Find the .dist-info directory inside an unpacked wheel.

        Normalizes pkgname (PEP 427: hyphens become underscores,
        case-insensitive).
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

    def _parse_metadata(self, metadata_text: str) -> dict:
        """Parse an RFC 822-style METADATA or PKG-INFO file.

        Returns a dict where multi-valued headers (like Requires-Dist) are
        lists and single-valued headers are strings.

        >>> m = PythonAnalyzer(None)._parse_metadata('Name: foo\\nVersion: 1.0\\nRequires-Dist: bar\\nRequires-Dist: baz\\n')
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

    def _unpack_pkg(
        self,
        pkg_file: Path,
        target_dir: Path,
        failures: list[str],
        failure_key: str,
    ) -> str:
        """Unpack a wheel (.whl) or sdist (.tar.gz/.zip) into target_dir.

        Returns a dist_type string: 'wheel', 'sdist', 'sdist-zip', or
        'unknown'. Uses Python stdlib only (tarfile; zip via
        shared.extract_zip_securely).
        """
        name = pkg_file.name
        try:
            if pkg_file.suffix == '.whl' or name.endswith('.zip'):
                # extract_zip_securely enforces size limits, filters symlinks,
                # and checks paths during extraction (no race window).
                shared.extract_zip_securely(pkg_file, target_dir)
                return 'wheel' if pkg_file.suffix == '.whl' else 'sdist-zip'
            if name.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
                with tarfile.open(str(pkg_file), 'r:*') as tf:
                    members = []
                    for m in tf.getmembers():
                        parts = Path(m.name).parts
                        if len(parts) > 1:
                            m.name = '/'.join(parts[1:])
                            if '..' in Path(m.name).parts:
                                continue
                            members.append(m)
                    shared.tarfile_extractall_safe(tf, target_dir, members)
                # tarfile_extractall_safe already filters symlinks;
                # belt-and-suspenders.
                shared.remove_symlinks(target_dir)
                return 'sdist'
        except shared.ArchiveSecurityError as exc:
            # An ArchiveSecurityError (size limit, file count, path traversal,
            # or symlink in a zip) is a strong indicator of a malicious package.
            failures.append(f'SECURITY_VIOLATION:{failure_key}: {exc}')
        except Exception as exc:
            failures.append(f'{failure_key}: {exc}')
        return 'unknown'

    def _get_pkg_file(
        self, directory: Path, pkgname: str, version: str,
    ) -> Path | None:
        """Find the downloaded package file (wheel preferred, then sdist)."""
        norm = _NORM_RE.sub('_', pkgname)
        for pattern in ('*.whl', '*.tar.gz', '*.tar.bz2', '*.tar.xz', '*.zip'):
            candidates = list(directory.glob(pattern))
            if len(candidates) == 1:
                return candidates[0]
            for c in candidates:
                cname = _NORM_RE.sub('_', c.stem.split('-')[0]).lower()
                if cname == norm.lower():
                    return c
            if candidates:
                return candidates[0]
        return None

    def get_lockfile_path(self, project_root: Path) -> Path:
        """Return the path to the first existing Python lockfile.

        Tries uv.lock, poetry.lock, Pipfile.lock, requirements.txt in order.
        Falls back to requirements.txt if none found (path may not exist).
        """
        for name in self.LOCKFILE_NAMES:
            p = project_root / name
            if p.is_file():
                return p
        return project_root / 'requirements.txt'

    def download_new(
        self,
        pkgname: str,
        version: str,
        work: Path,
        failures: list[str],
    ) -> dict:
        """pip download --no-deps into work/, then unpack into work/unpacked/.

        Prefers wheels (--prefer-binary); falls back to sdist.
        Returns dict with keys: unpacked_dir (Path), sha256 (str),
        pkg_file (Path | None), dist_type (str).
        """
        unpacked_dir = work / 'unpacked'
        unpacked_dir.mkdir(parents=True, exist_ok=True)

        # Options before '--'; package spec after cannot be mistaken for a flag.
        dl_cmd = [
            'python3', '-m',
            'pip', 'download',
            '--no-deps',
            '--prefer-binary',
            '-d', str(work),
        ]
        if self.registry_url:
            dl_cmd += ['--index-url', self.registry_url]
        dl_cmd += ['--', f'{pkgname}=={version}']

        rc, _out, err = shared.run_cmd(dl_cmd, cwd=work, timeout=180)

        pkg_file = self._get_pkg_file(work, pkgname, version)
        sha256 = ''
        dist_type = 'unknown'

        if pkg_file and pkg_file.is_file():
            sha256 = shared.sha256_file(pkg_file)
            (work / 'package-hash.txt').write_text(
                f'{sha256}  {pkg_file.name}\n', encoding='utf-8'
            )
            dist_type = self._unpack_pkg(pkg_file, unpacked_dir, failures, 'unpack-new')
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
        self,
        pkgname: str,
        version: str,
        unpacked_dir: Path,
        work: Path,
        failures: list[str],
        p: 'shared.Printer',
    ) -> shared.PackageManifest:
        """Parse METADATA (wheel) or PKG-INFO (sdist); write manifest-analysis.txt."""
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
        dist_info = self._find_dist_info(unpacked_dir, pkgname) if unpacked_dir.is_dir() else None
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
            meta = self._parse_metadata(manifest_text)
        else:
            failures.append('metadata-missing')

        p(f'=== Manifest analysis: {pkgname} {version} ===')
        p('')

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
        p(f'HAS_EXTENSIONS: {extensions}')

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
                executables_list = shared.sanitize_line(', '.join(scripts[:10]))
        # Also check pyproject.toml project.scripts
        if executables == 'NO' and ppt_text:
            if re.search(r'\[project\.scripts\]|\[project\.gui-scripts\]', ppt_text):
                executables = 'YES'
                scripts = re.findall(r'^\s*(\S+)\s*=', ppt_text, re.MULTILINE)
                executables_list = shared.sanitize_line(', '.join(scripts[:10]))
        p(f'HAS_EXECUTABLES: {executables}')
        if executables == 'YES':
            p(f'EXECUTABLES: {executables_list}')

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
                _sp_size_warn = shared.report_install_script_size(
                    sp_text, 'setup.py', p,
                    self.SETUP_PY_WARN_BYTES, self.SETUP_PY_WARN_LINES,
                )
                if _sp_size_warn:
                    install_cmd_warnings.append(_sp_size_warn)
                if suspicious:
                    has_build_hooks = 'YES'
                    install_script_files.append(('setup.py', setup_py))
                elif has_setup_py:
                    has_build_hooks = 'MAYBE'
            # pyproject.toml build-hooks (hatchling, meson-python, etc.)
            if ppt_text and re.search(r'\[tool\.hatch\.build\.hooks\]|build-backend\s*=', ppt_text):
                if has_build_hooks == 'NO':
                    has_build_hooks = 'MAYBE'

        p(f'HAS_BUILD_HOOKS: {has_build_hooks}')
        if has_setup_py:
            p('SETUP_PY_PRESENT: YES')

        # Runtime dependencies
        p('')
        p('RUNTIME_DEPS:')
        requires_dist = meta.get('Requires-Dist', [])
        if isinstance(requires_dist, str):
            requires_dist = [requires_dist]
        runtime_dep_lines = [str(r) for r in requires_dist if r and '; extra ==' not in str(r)]
        if runtime_dep_lines:
            for rdl in runtime_dep_lines:
                p(shared.sanitize_line(rdl))
        else:
            p('  (none declared)')

        # VCS dependency check: URL-based deps in Requires-Dist bypass PyPI.
        install_cmd_warnings: list[str] = []
        _vcs_hash_deps: list[str] = []
        _vcs_named_deps: list[str] = []
        for rdl in runtime_dep_lines:
            if _RE_PY_VCS_DEP.search(rdl):
                _safe = shared.sanitize_line(rdl[:200])
                if _RE_PY_COMMIT_HASH.search(rdl):
                    _vcs_hash_deps.append(_safe)
                else:
                    _vcs_named_deps.append(_safe)
        for _s in _vcs_hash_deps:
            p(f'[!] VCS_DEPENDENCY (commit hash): {_s}')
        for _s in _vcs_named_deps:
            p(f'[!] VCS_DEPENDENCY (named ref): {_s}')
        if _vcs_hash_deps:
            install_cmd_warnings.append(
                'VCS_DEPENDENCY:Requires-Dist (commit hash)')
        if _vcs_named_deps:
            install_cmd_warnings.append(
                'VCS_DEPENDENCY:Requires-Dist (named ref)')

        # Python version requirement
        py_req = meta.get('Requires-Python', '')
        if py_req and isinstance(py_req, str):
            p('')
            p(f'REQUIRES_PYTHON: {shared.sanitize_line(py_req)}')

        # Homepage / source URL
        source_url = self.extract_source_url(meta)
        hp_display = shared.sanitize_line(source_url) if source_url else '(not found)'
        p('')
        p(f'HOMEPAGE: {hp_display}')

        # Authors
        author = meta.get('Author', '') or meta.get('Author-email', '')
        if isinstance(author, list):
            author = ', '.join(author)
        p(f'AUTHOR: {shared.sanitize_line(str(author)[:200])}')

        # License
        manifest_license_raw = self.extract_license(meta)
        p('')
        p(f'LICENSE_DECLARED: {shared.sanitize_line(manifest_license_raw) or "(not declared)"}')

        # Summary
        summary = meta.get('Summary', '')
        if isinstance(summary, list):
            summary = summary[0] if summary else ''
        if summary:
            p(f'SUMMARY: {shared.sanitize_line(str(summary)[:300])}')

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

        # Bundled IDE config directories (cross-ecosystem, #3).
        install_cmd_warnings.extend(
            shared.check_bundled_ide_dirs(unpacked_dir, p))

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

        return shared.PackageManifest(
            source_url=source_url,
            extensions=extensions,
            executables=executables,
            executables_list=executables_list,
            post_install_msg=post_install_msg,
            has_build_hooks=has_build_hooks,
            has_install_scripts='YES' if has_install_scripts else 'NO',
            runtime_dep_lines=runtime_dep_lines,
            manifest_license_raw=manifest_license_raw,
            manifest_text=manifest_text,
            manifest_extra_file='pyproject-metadata.txt',
            install_hook_context=install_hook_context,
            install_cmd_warnings=install_cmd_warnings,
        )

    def download_old(
        self,
        pkgname: str,
        old_ver: str,
        work: Path,
        failures: list[str],
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
            ['python3', '-m', 'pip', 'cache', 'info'], timeout=10
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
            dist_type = self._unpack_pkg(pkg_file_cached, old_dir, failures, 'unpack-old')
            if dist_type != 'unknown':
                ok = True
                source = 'pip-cache'
        else:
            dl_cmd = [
                'python3', '-m',
                'pip', 'download',
                '--no-deps',
                '--prefer-binary',
                '-d', str(raw_old),
            ]
            if self.registry_url:
                dl_cmd += ['--index-url', self.registry_url]
            dl_cmd += ['--', f'{pkgname}=={old_ver}']
            rc_dl, _, _ = shared.run_cmd(dl_cmd, cwd=raw_old, timeout=180)
            if rc_dl == 0:
                pkg_file = self._get_pkg_file(raw_old, pkgname, old_ver)
                if pkg_file and pkg_file.is_file():
                    dist_type = self._unpack_pkg(pkg_file, old_dir, failures, 'unpack-old')
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

    def _read_old_manifest(self, old_unpacked_dir: Path, pkgname: str) -> dict | None:
        dist_info = self._find_dist_info(old_unpacked_dir, pkgname)
        if dist_info and (dist_info / 'METADATA').is_file():
            metadata_file = dist_info / 'METADATA'
        elif (old_unpacked_dir / 'PKG-INFO').is_file():
            metadata_file = old_unpacked_dir / 'PKG-INFO'
        else:
            return None
        return self._parse_metadata(
            metadata_file.read_text(encoding='utf-8', errors='replace'))

    def _extract_old_dep_lines(self, old_unpacked_dir: Path, pkgname: str) -> list[str]:
        meta = self._read_old_manifest(old_unpacked_dir, pkgname)
        if meta is None:
            return []
        requires = meta.get('Requires-Dist', [])
        if isinstance(requires, str):
            requires = [requires]
        return [r for r in requires if r and '; extra ==' not in str(r)]

    def fetch_all_registry_data(
        self,
        pkgname: str,
        version: str,
        work: Path,
        p: 'shared.Printer',
        source_url: str = '',
    ) -> dict:
        """Fetch PyPI JSON API: package info, version history, upload metadata.

        self.registry_url overrides the default pypi.org base URL for private
        indices. Also checks GitHub repo metadata for Shai-Halud campaign
        markers when source_url is a GitHub URL (Idea 16).

        Writes: provenance.txt (via p).
        Returns dict with keys: mfa_status, age_years_float, last_release_days,
        owner_count_int, version_stability, license_from_registry, ver_info_lines.
        """
        api_base = (self.registry_url.rstrip('/') if self.registry_url else 'https://pypi.org')
        mfa_status = 'unknown'
        age_years_float: float | None = None
        last_release_days: int | None = None
        version_published_days: int | None = None
        owner_count_int: int | None = None
        version_stability = 'unknown'
        license_from_registry: list[str] = []
        ver_info_lines: list[str] = []

        p(f'=== Provenance: {pkgname} {version} ===')
        p('')

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
                    for rf in (rel_files or []):
                        t = rf.get('upload_time_iso_8601', '') or rf.get('upload_time', '')
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

                # Age of this specific version
                ver_files = releases.get(version, []) or []
                ver_upload_times = sorted(
                    t for rf in ver_files
                    for t in [
                        rf.get('upload_time_iso_8601', '')
                        or rf.get('upload_time', '')
                    ]
                    if t
                )
                if ver_upload_times:
                    version_published_days = shared.days_since(
                        ver_upload_times[0])

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
                p(f'YANKED: {"YES" if yanked else "NO"}')
                if yanked:
                    reason = shared.sanitize_line(str(info.get('yanked_reason', '')))
                    p(f'YANKED_REASON: {reason}')
                p('')

                ver_pub_str = (str(version_published_days)
                               if version_published_days is not None
                               else 'unknown')
                p(f'VERSION_PUBLISHED_DAYS_AGO: {ver_pub_str}')
                p('')

                # Summary provenance info
                author = info.get('author', '') or ''
                maintainer = info.get('maintainer', '') or ''
                home = info.get('home_page', '') or ''
                p(f'AUTHOR: {shared.sanitize_line(str(author)[:200])}')
                p(f'MAINTAINER: {shared.sanitize_line(str(maintainer)[:200])}')
                p(f'HOME_PAGE: {shared.sanitize_line(str(home)[:300])}')
                p('')

            except (ValueError, KeyError, TypeError):
                p('REGISTRY_DATA: parse error')

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
                        ver_info_lines.append(f'  {key}: {shared.sanitize_line(str(val))[:200]}')
                    sha = u.get('digests', {}).get('sha256', '')
                    if sha:
                        ver_info_lines.append(f'  sha256: {shared.sanitize_line(sha)}')
            except (ValueError, KeyError, TypeError):
                ver_info_lines.append('VERSION_INFO: (parse error)')
        else:
            ver_info_lines.append('VERSION_INFO: (unavailable)')

        p('NOTE: PyPI does not expose per-package MFA status via API.')
        p('      MFA_REQUIRED is always "unknown" for PyPI packages.')
        p('')
        for vline in ver_info_lines:
            p(vline)

        # Idea 16: GitHub repo campaign marker (cross-ecosystem shared helper).
        shared.emit_github_repo_meta(source_url, p)

        return {
            'mfa_status': mfa_status,
            'age_years_float': age_years_float,
            'last_release_days': last_release_days,
            'version_published_days': version_published_days,
            'owner_count_int': owner_count_int,
            'version_stability': version_stability,
            'license_from_registry': license_from_registry,
            'ver_info_lines': ver_info_lines,
        }

    def check_lockfile(
        self,
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
        lockfile = self.get_lockfile_path(project_root)
        lockfile_lines: list[str] = ['=== Lockfile check ===']

        if lockfile.is_file():
            lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
            lockfile_format = self._detect_lockfile_format(lockfile.name)
            lockfile_lines.append(
                f'LOCKFILE: {lockfile.name} (format: {lockfile_format})')

            if dep_lines_new:
                for dep_line in dep_lines_new:
                    # Extract just the package name from "requests>=2.0,<3".
                    m_dep = re.match(
                        r'([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)',
                        dep_line.strip())
                    if not m_dep:
                        continue
                    dep_name = m_dep.group(1)
                    safe_dep = shared.sanitize_line(dep_name)
                    norm_dep = _NORM_RE.sub('_', dep_name).lower()
                    found = self._dep_in_lockfile(
                        dep_name, norm_dep, lf_text, lockfile_format)
                    if found:
                        lockfile_lines.append(f'IN_LOCKFILE: {safe_dep}')
                    else:
                        lockfile_lines.append(f'NOT_IN_LOCKFILE: {safe_dep}')
                        not_in_lockfile.append(safe_dep)

            # Foreign URL check: non-PyPI lines in requirements.txt bypass
            # the registry (Idea 13 analog for Python). Runs regardless of
            # whether dep_lines_new is empty.
            # Foreign URL / VCS source checks. Runs regardless of
            # dep_lines_new so that pre-existing entries are also caught.
            if lockfile_format == 'pip-requirements':
                # Build the configured-registry host (if any) for
                # false-positive suppression (private registry users).
                _priv_host = ''
                if self.registry_url:
                    _priv_host = urllib.parse.urlparse(
                        self.registry_url).netloc.lower()
                for _line in lf_text.splitlines():
                    _stripped = _line.strip()
                    if _stripped and not _stripped.startswith('#'):
                        if _RE_PIP_FOREIGN_URL.match(_stripped):
                            if _priv_host and _priv_host in _stripped.lower():
                                continue
                            lockfile_lines.append(
                                f'[!] LOCKFILE_FOREIGN_URL: '
                                f'{shared.sanitize_line(_stripped[:200])}')

            elif lockfile_format == 'poetry':
                # poetry.lock: packages with [package.source] type = "git"
                # are VCS deps that bypass PyPI.
                for _sm in _RE_POETRY_GIT_SOURCE.finditer(lf_text):
                    # Back up to the start of the surrounding [[package]]
                    # block to extract the URL.
                    _block_start = lf_text.rfind('[[package]]', 0, _sm.start())
                    _block = lf_text[_block_start:_sm.end() + 300]
                    _url_m = _RE_POETRY_GIT_URL.search(_block)
                    _ref_m = _RE_POETRY_GIT_REF.search(_block)
                    _url = (shared.sanitize_line(_url_m.group(1)[:200])
                            if _url_m else '(unknown)')
                    if _ref_m:
                        lockfile_lines.append(
                            f'[!] VCS_DEPENDENCY (commit hash): {_url}'
                            f'@{shared.sanitize_line(_ref_m.group(1)[:64])}')
                    else:
                        lockfile_lines.append(
                            f'[!] VCS_DEPENDENCY (named ref): {_url}')

            elif lockfile_format == 'uv':
                # uv.lock: source = { git = "url?rev=..." } entries.
                for _um in _RE_UV_GIT_SOURCE.finditer(lf_text):
                    _raw_url = _um.group(1)
                    _safe_url = shared.sanitize_line(_raw_url[:200])
                    if '?rev=' in _raw_url or '#rev=' in _raw_url:
                        lockfile_lines.append(
                            f'[!] VCS_DEPENDENCY (commit hash): {_safe_url}')
                    else:
                        lockfile_lines.append(
                            f'[!] VCS_DEPENDENCY (named ref): {_safe_url}')
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

    LOCKFILE_FORMAT_MAP: dict[str, str] = {
        'requirements.txt': 'pip-requirements',
        'poetry.lock': 'poetry',
        'uv.lock': 'uv',
        'Pipfile.lock': 'pipenv',
    }

    def _dep_in_lockfile(self, dep_name: str, norm_dep: str, lf_text: str, fmt: str) -> bool:
        """Return True if dep_name appears in the lockfile text for the given format.

        PEP 503: package names are case-insensitive and treat hyphens, underscores,
        and dots as equivalent. All format-specific searches apply both the original
        name and the hyphen-normalized form to avoid false NOT_IN_LOCKFILE results.
        """
        # PEP 503 normalized form: hyphens everywhere, lowercase
        pep503 = _NORM_RE.sub('-', dep_name).lower()
        # Also try underscore form, since some lockfiles store it that way
        underscore_form = _NORM_RE.sub('_', dep_name).lower()

        def _any_match(pattern_template: str, flags: int = 0) -> bool:
            for variant in {dep_name, pep503, underscore_form}:
                if re.search(pattern_template.format(re.escape(variant)), lf_text, flags):
                    return True
            return False

        if fmt == 'pip-requirements':
            # Look for "pkgname==" (pinned), "pkgname " or "pkgname[" (optional extras)
            return _any_match(r'(?i)^{}\s*(?:==|>=|<=|!=|~=|\[|$)', re.MULTILINE)
        if fmt in ('poetry', 'uv'):
            # TOML: name = "pkgname"
            return _any_match(r'(?i)name\s*=\s*["\']{}["\']')
        if fmt == 'pipenv':
            # JSON: "pkgname": { ... }
            return _any_match(r'(?i)"{}"\s*:\s*\{{')
        # Fallback: case-insensitive substring search on normalized name
        return bool(re.search(rf'(?i)\b{re.escape(norm_dep)}\b', lf_text))

    def check_dep_registry(self, dep_name: str) -> dict:
        """PyPI JSON API lookup for a dep not in lockfile.

        self.registry_url overrides the default pypi.org base URL for private indices.
        Returns dict with keys: downloads, first_seen, homepage.
        """
        api_base = self.registry_url.rstrip('/') if self.registry_url else 'https://pypi.org'
        api_data = shared.http_get(f'{api_base}/pypi/{dep_name}/json')
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
                    first_seen = shared.sanitize_line(date_m.group() if date_m else 'unknown')
                home = pkg_info.get('home_page', '') or pkg_info.get('project_url', '') or ''
                return {
                    'downloads': shared.sanitize_line(str(downloads))[:50],
                    'first_seen': first_seen,
                    'homepage': shared.sanitize_line(str(home))[:200],
                }
            except (ValueError, KeyError):
                pass
        return {'downloads': 'unavailable', 'first_seen': 'unavailable', 'homepage': 'unavailable'}

    def get_transitive_deps(
        self,
        pkgname: str,
        version: str,
        lockfile_path: Path,
        work: Path,
        p: 'shared.Printer',
    ) -> dict:
        """Fetch Requires-Dist from PyPI JSON API; compare against lockfile.

        This gives direct dependencies only (one level). A full transitive closure
        would require recursive PyPI API calls; that is deferred to a future
        enhancement.

        Writes: transitive-deps.txt (via p), raw-transitive-deps.txt.
        Returns dict with keys: total (int), not_in_lockfile (list[str]).
        """
        # Fetch requires_dist from PyPI for the specific version
        api_base = (self.registry_url.rstrip('/') if self.registry_url else 'https://pypi.org')
        api_data = shared.http_get(f'{api_base}/pypi/{pkgname}/{version}/json')
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
            lf_format = self._detect_lockfile_format(lockfile_path.name)

        transitive_new: list[str] = []
        for dep_name in all_deps:
            norm_dep = _NORM_RE.sub('_',dep_name).lower()
            if not self._dep_in_lockfile(dep_name, norm_dep, lf_text, lf_format):
                transitive_new.append(dep_name)

        return shared.write_transitive_deps(
            work, pkgname, version, total, transitive_new, p,
            total_label='TOTAL_DIRECT_DEPS',
            note='shows direct (level-1) deps from PyPI metadata only.',
        )

    def check_alternatives(
        self,
        pkgname: str,
        version: str,
        work: Path,
        project_root: Path,
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
        norm_pkg = _NORM_RE.sub('_', pkg_lower)

        # --- A: Python stdlib module names ---
        stdlib_names = self._get_stdlib_names()
        stdlib_exact = {m for m in stdlib_names
                        if m.lower() == pkg_lower or _NORM_RE.sub('_', m.lower()) == norm_pkg}
        for mod in stdlib_exact:
            concerns.append(
                f'EXACT_STDLIB_MATCH: "{pkgname}" matches Python stdlib module "{mod}". '
                'This is a strong dependency-confusion signal: the stdlib will shadow '
                'an external package of the same name in most Python contexts.'
            )
        self._lev_check(pkgname, pkg_lower,
                        [m for m in stdlib_names if m not in stdlib_exact],
                        'stdlib module', concerns, notes)

        # --- B: Installed packages via pip list ---
        installed_names: list[str] = []
        rc_pip, pip_out, _ = shared.run_cmd(
            ['python3', '-m', 'pip', 'list', '--format=columns'], timeout=30)
        if rc_pip == 0:
            for line in pip_out.splitlines()[2:]:  # skip header rows
                parts = line.split()
                if parts:
                    installed_names.append(parts[0])

        stdlib_lower = {m.lower() for m in stdlib_names}
        non_stdlib = [p for p in installed_names if p.lower() not in stdlib_lower]
        inst_exact = {p for p in non_stdlib
                      if p.lower() == pkg_lower or _NORM_RE.sub('_', p.lower()) == norm_pkg}
        for pkg in inst_exact:
            concerns.append(
                f'EXACT_INSTALLED_MATCH: "{pkgname}" matches already-installed package "{pkg}". '
                'Installing an external package with the same name as an existing installation '
                'could be a dependency-confusion or supply-chain attack.'
            )
        self._lev_check(pkgname, pkg_lower,
                        [p for p in non_stdlib if p not in inst_exact],
                        'installed package', concerns, notes)

        # --- C: Project lockfile deps ---
        lockfile = self.get_lockfile_path(project_root)
        lockfile_names: list[str] = []
        if lockfile.is_file():
            lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
            lf_fmt = self._detect_lockfile_format(lockfile.name)
            if lf_fmt == 'pip-requirements':
                for line in lf_text.splitlines():
                    m = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)', line.strip())
                    if m and not line.strip().startswith('#'):
                        lockfile_names.append(m.group(1))
            elif lf_fmt in ('poetry', 'uv'):
                for m in re.finditer(r'name\s*=\s*["\']([^"\']+)["\']', lf_text):
                    lockfile_names.append(m.group(1))
            elif lf_fmt == 'pipenv':
                # Parse Pipfile.lock as JSON; package names are keys of "default" and "develop"
                # objects. Avoid simple regex which would match any JSON key including metadata
                # fields like "version", "index", "hashes", "_meta", etc.
                try:
                    pipfile_data = json.loads(lf_text)
                    for section in ('default', 'develop'):
                        for key in (pipfile_data.get(section) or {}).keys():
                            if key != '_meta':
                                lockfile_names.append(key)
                except (ValueError, TypeError):
                    # Fall back to conservative regex: only keys directly under default/develop
                    pass

        installed_and_stdlib_lower = {p.lower() for p in installed_names} | stdlib_lower
        new_lf_deps = [d for d in lockfile_names
                       if d.lower() not in installed_and_stdlib_lower]
        lf_exact = {d for d in new_lf_deps
                    if d.lower() == pkg_lower or _NORM_RE.sub('_', d.lower()) == norm_pkg}
        for dep in lf_exact:
            concerns.append(
                f'EXACT_LOCKFILE_MATCH: "{pkgname}" matches existing lockfile dep "{dep}". '
                'This name is already in use in this project.'
            )
        self._lev_check(pkgname, pkg_lower,
                        [d for d in new_lf_deps if d not in lf_exact],
                        'lockfile dep', concerns, notes)

        # --- D: Structural heuristics ---
        # D1: hyphen/underscore normalization (PyPI treats these as equivalent)
        all_known_lower = ({p.lower() for p in installed_names}
                           | stdlib_lower
                           | {d.lower() for d in lockfile_names})
        if norm_pkg != pkg_lower and norm_pkg in all_known_lower:
            concerns.append(
                f'NORMALIZATION_MATCH: "{pkgname}" normalizes to the same name as an existing '
                f'package/module ("{norm_pkg}"). PyPI normalizes hyphens, underscores, and dots; '
                'a package relying on this difference may be exploiting naming confusion.'
            )

        # D2: Python-specific prefix/suffix stripping
        self._check_strip_rules(pkgname, pkg_lower, all_known_lower,
                                ('python-', 'py-', 'pypi-'), ('-python', '-py'),
                                concerns)

        with shared.Printer(work / 'alternatives.txt') as _p_alt:
            return shared.write_alternatives(
                _p_alt, pkgname, version,
                {
                    'Stdlib modules checked': len(stdlib_names),
                    'Installed pkgs checked': len(installed_names),
                    'Lockfile deps checked': len(lockfile_names),
                },
                concerns, notes,
            )

    def _get_stdlib_names(self) -> list[str]:
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

    def get_diff_excludes(self) -> list[str]:
        """Return glob patterns to exclude from diff (Python packaging artifacts)."""
        return ['*.pyc', '__pycache__', '*.egg-info', '*.dist-info', 'PKG-INFO']

    def get_pkg_src_excludes(self) -> tuple[re.Pattern, re.Pattern]:
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

    def find_source_root(self, source_dir: Path) -> Path:
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

    def get_deep_source_config(self) -> dict:
        """Return deep source comparison config for Python."""
        return {'primary_label': 'Python', 'primary_pattern': r'\.(py|pyx|pxd)$'}

    REPRO_BUILT_DIR_SUFFIX = 'raw-built-whl'

    def _repro_setup(
        self, clone_dir: Path, work: Path, p: 'shared.Printer',
    ) -> 'Path | str':
        rc_pv, pv_out, _ = shared.run_cmd(['python3', '--version'], timeout=10)
        python_ver = (
            shared.sanitize_line(pv_out.strip()) if rc_pv == 0 else 'unknown')
        p(f'PYTHON_VERSION: {python_ver}')
        build_root = clone_dir
        for candidate in (clone_dir / 'pyproject.toml', clone_dir / 'setup.py'):
            if candidate.is_file():
                break
        else:
            for child in clone_dir.iterdir():
                if child.is_dir() and (
                    (child / 'pyproject.toml').is_file()
                    or (child / 'setup.py').is_file()
                ):
                    build_root = child
                    break
        if (not (build_root / 'pyproject.toml').is_file()
                and not (build_root / 'setup.py').is_file()):
            return 'SKIPPED (no pyproject.toml or setup.py in source)'
        p(f'BUILD_ROOT: {shared.sanitize_line(str(build_root))}')
        return build_root

    def _repro_run_build(
        self, build_root: Path, built_dir: Path, sandbox: str,
    ) -> 'tuple[int, str] | None':
        rc_pv2, pv2_out, _ = shared.run_cmd(
            ['python3', '-c', 'import sys; print(sys.version_info[:2])'],
            timeout=5,
        )
        py_img_tag = '3'
        if rc_pv2 == 0:
            m = re.search(r'\((\d+),\s*(\d+)\)', pv2_out)
            if m:
                py_img_tag = f'{m.group(1)}.{m.group(2)}'
        # python:X images don't pre-install 'build'; install it first.
        # container_allow_network=True is required for that pip install step.
        return shared.run_sandboxed(
            sandbox, build_root, built_dir,
            'python3 -m build --wheel --no-isolation --outdir {out} {src}',
            f'python:{py_img_tag}',
            container_shell_cmd=(
                'python3 -m pip install build --quiet'
                ' --disable-pip-version-check && '
                'python -m build --wheel --no-isolation --outdir {out} {src}'
            ),
            container_allow_network=True,
        )

    def _repro_compare(
        self,
        pkgname: str,
        version: str,
        built_dir: Path,
        work: Path,
        p: 'shared.Printer',
    ) -> tuple[str, int, int]:
        built_whls = list(built_dir.glob('*.whl'))
        if not built_whls:
            return shared.finish_reproducible_build(
                p, work, 'INCONCLUSIVE (no .whl produced)')
        built_whl = built_whls[0]
        built_sha = shared.sha256_file(built_whl)
        if (repro := shared.compare_repro_sha256(built_sha, work, p)) is not None:
            return repro
        built_unpacked = work / 'raw-built-unpacked'
        built_unpacked.mkdir(exist_ok=True)
        self._unpack_pkg(built_whl, built_unpacked, [], 'repro-unpack')
        dist_unpacked = work / 'unpacked'
        if not dist_unpacked.is_dir():
            return shared.finish_reproducible_build(
                p, work,
                'INCONCLUSIVE (hashes differ, no dist unpacked dir)')
        rc_diff, diff_out, _ = shared.run_cmd(
            ['diff', '-r', str(built_unpacked), str(dist_unpacked),
             '--exclude=*.pyc', '--exclude=__pycache__', '--exclude=RECORD'],
            timeout=60,
        )
        (work / 'raw-repro-diff.txt').write_text(
            diff_out, encoding='utf-8', errors='replace')
        diff_line_count = len(diff_out.splitlines())
        p(f'CONTENT_DIFF_LINES: {diff_line_count}')
        if diff_line_count == 0:
            return shared.finish_reproducible_build(
                p, work, 'EXACTLY REPRODUCIBLE (content match)')
        return shared.classify_repro_diffs(
            diff_out, p, work, _RE_REPRO_CODE, _RE_REPRO_META)


Analyzer = PythonAnalyzer   # used by dep_review.py for instantiation
