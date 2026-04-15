#!/usr/bin/env python3
# hooks_js.py: JavaScript/Node.js language operations for the dependency analysis driver.
#
# Handles the npm package format (download with npm pack, unpack tarball) and
# the npm registry API. Used for --from npm; can be reused for other
# npm-compatible registries (GitHub Packages, Verdaccio, Nexus, Artifactory, etc.)
# with a different registry entry in REGISTRY_TO_HOOKS pointing here.
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

# Pre-compiled patterns for reproducible-build diff classification.
_RE_REPRO_CODE = re.compile(r'^diff.*\.(js|mjs|cjs|ts|jsx|tsx)\b')
_RE_REPRO_META = re.compile(r'^diff.*(package\.json|package-lock\.json|\.npmignore|\.gitignore)')


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_license(pkg_json: dict) -> str:
    """Extract raw license string from a parsed package.json dict.

    Handles both string form ("MIT") and SPDX object form ({"type": "MIT"}).

    >>> _extract_license({"license": "MIT"})
    'MIT'
    >>> _extract_license({"license": {"type": "Apache-2.0"}})
    'Apache-2.0'
    >>> _extract_license({})
    ''
    """
    lic = pkg_json.get('license', '') or ''
    if isinstance(lic, dict):
        lic = lic.get('type', '') or ''
    return str(lic).strip()


def _extract_source_url(pkg_json: dict) -> str:
    """Extract source/repository URL from package.json.

    >>> _extract_source_url({"repository": {"url": "https://github.com/foo/bar"}})
    'https://github.com/foo/bar'
    >>> _extract_source_url({"repository": "https://github.com/foo/bar"})
    'https://github.com/foo/bar'
    >>> _extract_source_url({})
    ''
    """
    repo = pkg_json.get('repository', '') or ''
    if isinstance(repo, dict):
        url = repo.get('url', '') or ''
    elif isinstance(repo, str):
        url = repo
    else:
        url = ''
    url = re.sub(r'^git\+', '', str(url).strip())
    url = re.sub(r'^git://', 'https://', url)
    url = re.sub(r'\.git$', '', url).rstrip('/')
    return url


def _load_package_json(unpacked_dir: Path) -> dict:
    """Load and parse package.json from the unpacked directory; return {} on failure."""
    pkg_json_path = unpacked_dir / 'package.json'
    if not pkg_json_path.is_file():
        return {}
    try:
        return json.loads(pkg_json_path.read_text(encoding='utf-8', errors='replace'))
    except (ValueError, OSError):
        return {}


def _unpack_tgz(tgz_file: Path, target_dir: Path, failures: list[str], key: str) -> bool:
    """Unpack a .tgz, stripping the top-level 'package/' directory.

    npm tarballs always place files under a 'package/' top-level directory.
    Returns True on success.
    """
    try:
        with tarfile.open(str(tgz_file), 'r:gz') as tf:
            members = []
            for m in tf.getmembers():
                parts = Path(m.name).parts
                if len(parts) >= 2 and parts[0] == 'package':
                    m.name = '/'.join(parts[1:])
                elif len(parts) >= 2:
                    # Strip whatever the first-level directory is
                    m.name = '/'.join(parts[1:])
                else:
                    continue
                if not m.name or '..' in Path(m.name).parts:
                    continue
                members.append(m)
            tf.extractall(str(target_dir), members=members)
        return True
    except Exception as exc:
        failures.append(f'{key}: {exc}')
        return False


# ---------------------------------------------------------------------------
# Public API: called by dep_review.py
# ---------------------------------------------------------------------------

class Hooks(shared.EcosystemHooks):
    ECOSYSTEM = 'javascript'
    OSV_ECOSYSTEM = 'npm'

    # Multiple lockfile formats; LOCKFILE_NAME is None so the driver skips the
    # single-lockfile warning. LOCKFILE_NAMES lists candidates in priority order.
    LOCKFILE_NAME: str | None = None
    LOCKFILE_NAMES: list[str] = [
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
    ]

    MANIFEST_FILE = 'package-json.txt'

    DANGEROUS_WHAT = (
        'eval/new Function/vm execution, child_process execution, '
        'obfuscated execution (Buffer.from base64+eval, hex decode+eval), '
        'network calls at module load scope, credential env-var access '
        '(AWS/GitHub/cloud keys at load time), dynamic require on external input, '
        'prototype pollution (Object.prototype assignment, __proto__ assignment)'
    )

    DANGEROUS_PATTERNS: list[tuple[str, str]] = [
        ('eval-variants',
         r'\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:This|New)Context\s*\('),
        ('child-process-exec',
         r'\brequire\s*\(\s*["\x27]child_process["\x27]\s*\)'
         r'|child_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\('),
        ('obfuscated-exec',
         r'Buffer\.from\s*\([^)]{0,200}["\x27]base64["\x27][^)]{0,200}\)'
         r'(?:[^\n]{0,200})(?:eval|Function)\b'
         r'|(?:toString\s*\(\s*(?:16|8)\s*\)|fromCharCode)[^\n]{0,120}(?:eval|Function)\b'),
        ('network-at-load-scope',
         r'^\s*require\s*\(\s*["\x27](?:http|https|net|dgram|tls)["\x27]\s*\)'
         r'\.(?:get|request|connect|createServer|createConnection)\s*\('
         r'|^\s*fetch\s*\('),
        ('credential-env-vars',
         r'process\.env\s*(?:\.\s*|\[\s*["\x27])'
         r'(?:AWS_|GITHUB_|GH_|NPM_TOKEN|CI_|PYPI_|HEROKU_|VERCEL_|NETLIFY_)'
         r'[A-Z_]*'),
        ('dynamic-require',
         r'\brequire\s*\(\s*(?:process\.env\.|[^"\'`\)]{0,80}'
         r'(?:user|input|argv|env|request))'),
        ('prototype-pollution',
         r'Object\.prototype\s*\[["\x27][^\]]+["\x27]\s*='
         r'|__proto__\s*[=:]\s*\{'),
        ('module-load-socket',
         r'^\s*new\s+(?:net\.Socket|tls\.TLSSocket|dgram\.Socket)\s*\('),
    ]

    DIFF_PATTERNS: list[tuple[str, str]] = [
        ('diff-eval',
         r'^\+.*\beval\s*\(|^\+.*new\s+Function\s*\('),
        ('diff-cmd-injection',
         r'^\+.*child_process\.(?:exec|spawn|execSync|spawnSync)\s*\('),
        ('diff-hardcoded-secrets',
         r'^\+.*(?:password|passwd|secret|api_key|token|apikey)'
         r'\s*[=:]\s*["\x27][^"\x27]{6,}["\x27]'),
        ('diff-network-load',
         r'^\+\s*require\s*\(\s*["\x27](?:http|https)["\x27]\s*\)'
         r'\.(?:get|request)\s*\('),
        ('diff-prototype-pollution',
         r'^\+.*__proto__\s*[=:]\s*\{|^\+.*Object\.prototype\s*\['),
    ]

    def get_lockfile_path(self, project_root: Path) -> Path:
        """Return the path to the first existing JavaScript lockfile.

        Tries package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb in order.
        Falls back to package-lock.json if none found (path may not exist).
        """
        for name in self.LOCKFILE_NAMES:
            p = project_root / name
            if p.is_file():
                return p
        return project_root / 'package-lock.json'

    def download_new(
        self,
        pkgname: str,
        version: str,
        work: Path,
        failures: list[str],
    ) -> dict:
        """npm pack PKGNAME@VERSION into work/, then unpack into work/unpacked/.

        Uses npm pack which downloads the tarball without executing any install
        scripts or lifecycle hooks. Returns dict with keys: unpacked_dir (Path),
        sha256 (str), pkg_file (Path | None).
        """
        unpacked_dir = work / 'unpacked'
        unpacked_dir.mkdir(parents=True, exist_ok=True)

        pack_cmd = ['npm', 'pack', f'{pkgname}@{version}', '--pack-destination', str(work)]
        if self.registry_url:
            pack_cmd += ['--registry', self.registry_url]

        rc, _out, err = shared.run_cmd(pack_cmd, cwd=work, timeout=180)
        tgz_file: Path | None = None
        sha256 = ''

        if rc == 0:
            tgz_candidates = list(work.glob('*.tgz'))
            if tgz_candidates:
                tgz_file = max(tgz_candidates, key=lambda p: p.stat().st_mtime)
                sha256 = shared.sha256_file(tgz_file)
                (work / 'package-hash.txt').write_text(
                    f'{sha256}  {tgz_file.name}\n', encoding='utf-8'
                )
                if not _unpack_tgz(tgz_file, unpacked_dir, failures, 'unpack-new'):
                    failures.append('unpack-new-failed')
            else:
                failures.append('npm-pack-no-tgz')
                (work / 'package-hash.txt').write_text('ERROR: no .tgz produced\n', encoding='utf-8')
        else:
            failures.append('npm-pack-new')
            sanitized_err = shared.sanitize(err[:500]) if err else ''
            (work / 'package-hash.txt').write_text(
                f'ERROR: npm pack failed\n{sanitized_err}\n', encoding='utf-8'
            )

        return {
            'unpacked_dir': unpacked_dir,
            'sha256': sha256,
            'pkg_file': tgz_file,
        }

    def read_manifest(
        self,
        pkgname: str,
        version: str,
        unpacked_dir: Path,
        work: Path,
        failures: list[str],
    ) -> dict:
        """Parse package.json from the unpacked tarball; write manifest-analysis.txt.

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
        install_hook_context: list[str] = []

        manifest_lines: list[str] = [f'=== Manifest analysis: {pkgname} {version} ===', '']
        pkg_json: dict = {}

        if unpacked_dir.is_dir():
            pkg_json = _load_package_json(unpacked_dir)

        if pkg_json:
            manifest_text = json.dumps(pkg_json, indent=2, ensure_ascii=False)
            (work / 'package-json.txt').write_text(manifest_text, encoding='utf-8', errors='replace')

            # Native addons: binding.gyp present, or install script calls node-gyp/prebuild-install
            binding_gyp = (unpacked_dir / 'binding.gyp').is_file()
            scripts = pkg_json.get('scripts', {}) or {}
            preinstall_val = str(scripts.get('preinstall', '') or '').strip()
            install_val = str(scripts.get('install', '') or '').strip()
            postinstall_val = str(scripts.get('postinstall', '') or '').strip()

            is_native = binding_gyp or bool(
                re.search(r'node-gyp\s+rebuild|prebuild-install', install_val)
            )
            if is_native:
                extensions = 'YES'
                manifest_lines.append('HAS_EXTENSIONS: YES (native addon)')
            else:
                manifest_lines.append('HAS_EXTENSIONS: NO')

            # Executables (bin field)
            bin_field = pkg_json.get('bin', None)
            if bin_field:
                executables = 'YES'
                if isinstance(bin_field, dict):
                    executables_list = shared.sanitize(', '.join(list(bin_field.keys())[:10]))
                elif isinstance(bin_field, str):
                    executables_list = shared.sanitize(bin_field)
                manifest_lines.extend([
                    'HAS_EXECUTABLES: YES',
                    f'EXECUTABLES: {executables_list}',
                ])
            else:
                manifest_lines.append('HAS_EXECUTABLES: NO')

            # Lifecycle scripts: preinstall, install, postinstall
            install_script_content: list[tuple[str, str]] = []
            if preinstall_val:
                has_build_hooks = 'YES'
                manifest_lines.extend([
                    'HAS_PREINSTALL: YES',
                    f'  preinstall: {shared.sanitize(preinstall_val[:300])}',
                ])
                install_script_content.append(('preinstall', preinstall_val))
                post_install_msg = 'YES'
            if install_val and not is_native:
                has_build_hooks = 'YES'
                manifest_lines.extend([
                    'HAS_INSTALL_SCRIPT: YES',
                    f'  install: {shared.sanitize(install_val[:300])}',
                ])
                install_script_content.append(('install', install_val))
            elif is_native and install_val:
                manifest_lines.append(f'NATIVE_INSTALL_SCRIPT: {shared.sanitize(install_val[:300])}')
            if postinstall_val:
                has_build_hooks = 'YES'
                manifest_lines.extend([
                    'HAS_POSTINSTALL: YES',
                    f'  postinstall: {shared.sanitize(postinstall_val[:300])}',
                ])
                install_script_content.append(('postinstall', postinstall_val))
                post_install_msg = 'YES'
            if not (preinstall_val or install_val or postinstall_val):
                manifest_lines.append('HAS_BUILD_HOOKS: NO')

            # Runtime dependencies
            manifest_lines.extend(['', 'RUNTIME_DEPS:'])
            deps = pkg_json.get('dependencies', {}) or {}
            opt_deps = pkg_json.get('optionalDependencies', {}) or {}
            all_runtime = dict(deps)
            all_runtime.update(opt_deps)
            if all_runtime:
                for dep_name, dep_range in list(all_runtime.items())[:50]:
                    line = f'{dep_name}@{dep_range}'
                    runtime_dep_lines.append(line)
                    manifest_lines.append(f'  {shared.sanitize(line)}')
                if len(all_runtime) > 50:
                    manifest_lines.append(f'  ... and {len(all_runtime) - 50} more')
            else:
                manifest_lines.append('  (none)')

            source_url = _extract_source_url(pkg_json)
            hp_display = shared.sanitize(source_url) if source_url else '(not found)'
            manifest_lines.extend(['', f'HOMEPAGE: {hp_display}'])

            author = pkg_json.get('author', '') or ''
            if isinstance(author, dict):
                author = author.get('name', '') or ''
            manifest_lines.append(f'AUTHOR: {shared.sanitize(str(author)[:200])}')

            manifest_license_raw = _extract_license(pkg_json)
            manifest_lines.extend([
                '',
                f'LICENSE_DECLARED: {shared.sanitize(manifest_license_raw) or "(not declared)"}',
            ])

            desc = str(pkg_json.get('description', '') or '')[:300]
            if desc:
                manifest_lines.append(f'DESCRIPTION: {shared.sanitize(desc)}')

            main_field = pkg_json.get('main', '') or pkg_json.get('exports', '')
            if main_field:
                main_str = str(main_field) if not isinstance(main_field, dict) else '(exports map)'
                manifest_lines.append(f'MAIN: {shared.sanitize(main_str[:200])}')

            manifest_lines.append('')

            # Write install-time scripts for AI review
            if install_script_content:
                script_lines: list[str] = [
                    '=== Install-time scripts for AI review ===',
                    '',
                    'These lifecycle scripts execute during npm install.',
                    'Review each one for malicious or unexpected behavior.',
                    '',
                ]
                for hook_name, hook_val in install_script_content:
                    script_lines.append(f'--- {hook_name} ---')
                    script_lines.append(shared.sanitize(hook_val))
                    script_lines.append('')
                (work / 'install-scripts.txt').write_text(
                    '\n'.join(script_lines), encoding='utf-8'
                )

            if preinstall_val:
                install_hook_context.append(
                    'Context: preinstall script present. This runs BEFORE the package is '
                    'installed and can execute arbitrary code. Review install-scripts.txt carefully.'
                )
            if postinstall_val:
                install_hook_context.append(
                    'Context: postinstall script is present. This is the most common attack '
                    'vector for npm supply-chain attacks. Review install-scripts.txt carefully.'
                )
            if is_native and not (preinstall_val or postinstall_val):
                install_hook_context.append(
                    'Context: native addon (binding.gyp). The install script compiles C/C++ '
                    'at install time. This is expected for native addons (node-gyp rebuild).'
                )

        else:
            failures.append('package-json-missing')
            manifest_lines.append('ERROR: package.json not found in unpacked directory')

        (work / 'manifest-analysis.txt').write_text(
            '\n'.join(manifest_lines) + '\n', encoding='utf-8'
        )
        has_install_scripts = (work / 'install-scripts.txt').is_file()

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
            'manifest_extra_file': 'package-json.txt',
            'install_hook_context': install_hook_context,
        }

    def download_old(
        self,
        pkgname: str,
        old_ver: str,
        work: Path,
        failures: list[str],
    ) -> dict:
        """npm pack for the old version; unpack into work/old/.

        Returns dict with keys: ok (bool), source (str), unpacked_dir (Path).
        """
        old_dir = work / 'old'
        old_dir.mkdir(exist_ok=True)
        raw_old = work / 'raw-old-pkg'
        raw_old.mkdir(exist_ok=True)

        pack_cmd = ['npm', 'pack', f'{pkgname}@{old_ver}', '--pack-destination', str(raw_old)]
        if self.registry_url:
            pack_cmd += ['--registry', self.registry_url]

        rc, _, _ = shared.run_cmd(pack_cmd, cwd=raw_old, timeout=180)
        ok = False
        source = ''

        if rc == 0:
            tgz_candidates = list(raw_old.glob('*.tgz'))
            if tgz_candidates:
                tgz_file = max(tgz_candidates, key=lambda p: p.stat().st_mtime)
                if _unpack_tgz(tgz_file, old_dir, failures, 'unpack-old'):
                    ok = True
                    source = 'fetched'
                else:
                    failures.append('npm-pack-old-unpack')
            else:
                failures.append('npm-pack-old-no-tgz')
        else:
            failures.append('npm-pack-old')

        (work / 'old-version-status.txt').write_text(
            f'OLD_VERSION_SOURCE: {source or "unavailable"}\n', encoding='utf-8'
        )
        return {'ok': ok, 'source': source, 'unpacked_dir': old_dir}

    def get_old_license(
        self,
        pkgname: str,
        old_ver: str,
        old_unpacked_dir: Path,
    ) -> str | None:
        """Extract raw license from the old version's package.json."""
        if not old_unpacked_dir or not Path(old_unpacked_dir).is_dir():
            return None
        pkg_json = _load_package_json(Path(old_unpacked_dir))
        return _extract_license(pkg_json) or None

    def get_old_dep_lines(
        self,
        pkgname: str,
        old_ver: str,
        old_result: dict,
    ) -> list[str]:
        """Extract runtime dependency lines from the old version's package.json."""
        if not old_result.get('ok'):
            return []
        old_unpacked = old_result.get('unpacked_dir')
        if not old_unpacked or not Path(old_unpacked).is_dir():
            return []
        pkg_json = _load_package_json(Path(old_unpacked))
        deps = pkg_json.get('dependencies', {}) or {}
        opt_deps = pkg_json.get('optionalDependencies', {}) or {}
        all_runtime = dict(deps)
        all_runtime.update(opt_deps)
        return [f'{name}@{ver}' for name, ver in all_runtime.items()]

    def fetch_all_registry_data(
        self,
        pkgname: str,
        version: str,
        work: Path,
    ) -> dict:
        """Fetch npm registry API: full package metadata and version-specific data.

        Endpoint: registry.npmjs.org/{pkgname} (full doc) and
                  registry.npmjs.org/{pkgname}/{version} (version-specific).

        Writes: provenance.txt.
        Returns dict with keys: mfa_status, age_years_float, last_release_days,
        owner_count_int, version_stability, license_from_registry, ver_info_lines.
        """
        api_base = (
            self.registry_url.rstrip('/') if self.registry_url else 'https://registry.npmjs.org'
        )
        mfa_status = 'unknown'  # npm has no per-package MFA status via registry API
        age_years_float: float | None = None
        last_release_days: int | None = None
        owner_count_int: int | None = None
        version_stability = 'unknown'
        license_from_registry: list[str] = []
        ver_info_lines: list[str] = []

        prov_lines: list[str] = [f'=== Provenance: {pkgname} {version} ===', '']

        # Scoped packages (@scope/name) must be percent-encoded in the URL
        encoded_name = urllib.parse.quote(pkgname, safe='')

        # Full package document: maintainers, time history, versions object
        pkg_data = shared.http_get(f'{api_base}/{encoded_name}')
        if pkg_data:
            try:
                pkg_json = json.loads(pkg_data.decode('utf-8', errors='replace'))
                time_obj = pkg_json.get('time', {}) or {}

                created_str = str(time_obj.get('created', ''))
                age_days = shared.days_since(created_str)
                if age_days is not None:
                    age_years_float = age_days / 365

                ver_times = {
                    k: v for k, v in time_obj.items()
                    if k not in ('created', 'modified') and re.match(r'\d', k)
                }
                if ver_times:
                    last_release_days = shared.days_since(max(ver_times.values()))

                if re.search(r'(?i)(alpha|beta|rc|pre|dev|canary|next)', version) or \
                   version.startswith('0.'):
                    version_stability = 'pre-release'
                else:
                    version_stability = 'stable'

                maintainers = pkg_json.get('maintainers', []) or []
                if isinstance(maintainers, list):
                    owner_count_int = len(maintainers)
                    maint_names = [
                        shared.sanitize(
                            m.get('name', '') if isinstance(m, dict) else str(m)
                        )[:80]
                        for m in maintainers[:20]
                    ]
                    prov_lines.extend([
                        f'MAINTAINER_COUNT: {owner_count_int}',
                        f'MAINTAINERS: {", ".join(maint_names)}',
                        '',
                    ])

                # License from the specific version's entry in the versions object
                versions_obj = pkg_json.get('versions', {}) or {}
                target_ver = versions_obj.get(version, {}) or {}
                lic = target_ver.get('license', '') or ''
                if isinstance(lic, dict):
                    lic = lic.get('type', '') or ''
                if lic and str(lic).upper() not in ('', 'UNKNOWN'):
                    license_from_registry.append(str(lic))

                deprecated = target_ver.get('deprecated', '') or ''
                if deprecated:
                    prov_lines.extend([
                        'DEPRECATED: YES',
                        f'DEPRECATED_REASON: {shared.sanitize(str(deprecated)[:300])}',
                        '',
                    ])
                else:
                    prov_lines.extend(['DEPRECATED: NO', ''])

            except (ValueError, KeyError, TypeError):
                prov_lines.append('REGISTRY_DATA: parse error')

        # Version-specific endpoint: dist.integrity, dist.tarball, Sigstore signatures
        ver_data = shared.http_get(f'{api_base}/{encoded_name}/{version}')
        if ver_data:
            try:
                ver_json = json.loads(ver_data.decode('utf-8', errors='replace'))
                ver_info_lines.append('VERSION_INFO (selected fields):')
                dist = ver_json.get('dist', {}) or {}
                for key in ('version', '_npmUser', 'gitHead'):
                    val = ver_json.get(key, '')
                    if val:
                        ver_info_lines.append(f'  {key}: {shared.sanitize(str(val))[:200]}')
                for dist_key in ('integrity', 'shasum', 'tarball', 'fileCount', 'unpackedSize'):
                    val = dist.get(dist_key, '')
                    if val:
                        ver_info_lines.append(f'  dist.{dist_key}: {shared.sanitize(str(val))[:200]}')
                sigs = dist.get('signatures', [])
                if sigs:
                    ver_info_lines.append(
                        f'  dist.signatures: {len(sigs)} signature(s) present (Sigstore)'
                    )
                else:
                    ver_info_lines.append('  dist.signatures: none (not signed with Sigstore)')
            except (ValueError, KeyError, TypeError):
                ver_info_lines.append('VERSION_INFO: (parse error)')
        else:
            ver_info_lines.append('VERSION_INFO: (unavailable)')

        prov_lines.append('NOTE: npm does not expose per-package MFA status via the registry API.')
        prov_lines.append('      MFA_REQUIRED is always "unknown" for npm packages.')
        prov_lines.append('      Check dist.signatures above for Sigstore provenance attestation.')
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

    def check_lockfile(
        self,
        runtime_dep_lines: list[str],
        old_dep_lines: list[str],
        project_root: Path,
    ) -> dict:
        """Parse the project lockfile and compare new vs old runtime deps.

        Supports package-lock.json (npm v2/v3), yarn.lock (v1 and v2+/Berry),
        and pnpm-lock.yaml. Returns dict with keys: added_deps, removed_deps,
        not_in_lockfile, and private keys _lockfile_lines, _dep_lines_new,
        _dep_lines_old used by write_dep_files() in the driver.
        """
        dep_lines_new, dep_lines_old, added_deps, removed_deps = shared.compute_dep_diff(
            runtime_dep_lines, old_dep_lines
        )
        not_in_lockfile: list[str] = []

        lockfile = self.get_lockfile_path(project_root)
        lockfile_lines: list[str] = ['=== Lockfile check ===']

        if lockfile.is_file() and dep_lines_new:
            lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
            lockfile_format = self._detect_lockfile_format(lockfile.name)
            lockfile_lines.append(f'LOCKFILE: {lockfile.name} (format: {lockfile_format})')

            for dep_line in dep_lines_new:
                # Extract name from "pkgname@^version" or "@scope/name@version"
                m = re.match(r'^(@[^@]+|[^@]+)@', dep_line.strip())
                dep_name = m.group(1) if m else dep_line.strip()
                if not dep_name:
                    continue
                safe_dep = shared.sanitize(dep_name)
                if self._dep_in_lockfile(dep_name, lf_text, lockfile_format):
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

    def _detect_lockfile_format(self, filename: str) -> str:
        """Return the lockfile format name for a given filename."""
        if filename == 'package-lock.json':
            return 'npm'
        if filename == 'yarn.lock':
            return 'yarn'
        if filename == 'pnpm-lock.yaml':
            return 'pnpm'
        if filename == 'bun.lockb':
            return 'bun'
        return 'unknown'

    def _dep_in_lockfile(self, dep_name: str, lf_text: str, fmt: str) -> bool:
        """Return True if dep_name appears in the lockfile for the given format."""
        safe = re.escape(dep_name)
        if fmt == 'npm':
            # package-lock.json v2/v3: "node_modules/pkgname": { ...
            return bool(re.search(rf'"node_modules/{safe}"', lf_text))
        if fmt == 'yarn':
            # yarn.lock v1: pkgname@version: or "pkgname@version":
            # yarn.lock v2+ (Berry): pkgname@npm:version:
            return bool(re.search(
                rf'(?:^|\s|")["\']?{safe}@', lf_text, re.MULTILINE
            ))
        if fmt == 'pnpm':
            # pnpm-lock.yaml: "  /pkgname/version:" or "  pkgname@version:"
            return bool(re.search(
                rf'^\s+/?{safe}[@/]', lf_text, re.MULTILINE
            ))
        # Fallback: case-insensitive substring search
        return bool(re.search(rf'(?i)\b{safe}\b', lf_text))

    def check_dep_registry(self, dep_name: str) -> dict:
        """npm registry lookup for a dependency not in the lockfile.

        Returns dict with keys: downloads, first_seen, homepage.
        """
        api_base = (
            self.registry_url.rstrip('/') if self.registry_url else 'https://registry.npmjs.org'
        )
        encoded = urllib.parse.quote(dep_name, safe='')
        api_data = shared.http_get(f'{api_base}/{encoded}')
        if api_data:
            try:
                info = json.loads(api_data.decode('utf-8', errors='replace'))
                time_obj = info.get('time', {}) or {}
                created = str(time_obj.get('created', 'unknown'))
                date_m = re.search(r'\d{4}-\d{2}-\d{2}', created)
                homepage = info.get('homepage', '') or ''
                if not homepage:
                    repo = info.get('repository', {}) or {}
                    if isinstance(repo, dict):
                        homepage = repo.get('url', '') or ''
                return {
                    'downloads': f'see npmjs.com/package/{dep_name}',
                    'first_seen': shared.sanitize(date_m.group() if date_m else 'unknown'),
                    'homepage': shared.sanitize(str(homepage))[:200],
                }
            except (ValueError, KeyError, TypeError):
                pass
        return {'downloads': 'unavailable', 'first_seen': 'unavailable', 'homepage': 'unavailable'}

    def get_transitive_deps(
        self,
        pkgname: str,
        version: str,
        lockfile_path: Path,
        work: Path,
    ) -> dict:
        """Fetch direct runtime deps from the npm registry; compare against lockfile.

        Uses the registry API to get the package's dependencies object.
        Like the Python hook, this shows direct (level-1) deps only; full
        transitive closure would require recursive API calls.

        Writes: transitive-deps.txt, raw-transitive-deps.txt.
        Returns dict with keys: total (int), not_in_lockfile (list[str]).
        """
        api_base = (
            self.registry_url.rstrip('/') if self.registry_url else 'https://registry.npmjs.org'
        )
        encoded = urllib.parse.quote(pkgname, safe='')
        deps: list[str] = []
        raw_lines: list[str] = []

        ver_data = shared.http_get(f'{api_base}/{encoded}/{version}')
        if ver_data:
            try:
                ver_json = json.loads(ver_data.decode('utf-8', errors='replace'))
                all_deps = dict(ver_json.get('dependencies', {}) or {})
                all_deps.update(ver_json.get('optionalDependencies', {}) or {})
                for dep_name, dep_range in all_deps.items():
                    deps.append(dep_name)
                    raw_lines.append(f'{dep_name}@{dep_range}')
            except (ValueError, KeyError, TypeError):
                pass

        (work / 'raw-transitive-deps.txt').write_text('\n'.join(raw_lines), encoding='utf-8')

        total = len(deps)
        lf_text = ''
        lf_format = 'unknown'
        if lockfile_path.is_file():
            lf_text = lockfile_path.read_text(encoding='utf-8', errors='replace')
            lf_format = self._detect_lockfile_format(lockfile_path.name)

        transitive_new: list[str] = []
        for dep_name in deps:
            if not self._dep_in_lockfile(dep_name, lf_text, lf_format):
                transitive_new.append(dep_name)

        trans_lines = [
            f'=== Transitive dependency footprint: {pkgname} {version} ===',
            'NOTE: shows direct (level-1) runtime deps from the npm registry only.',
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
        self,
        pkgname: str,
        version: str,
        work: Path,
        project_root: Path,
    ) -> dict:
        """Check for typosquat, slopsquat, and Node.js built-in overlap signals.

        Three checks:
        A: Node.js built-in module names; flag exact matches (dependency confusion)
           and near-matches (typosquat).
        B: Project lockfile dependencies; flag near-matches.
        C: Structural heuristics: scope stripping, common JS wrapper
           prefix/suffix stripping.

        Writes: alternatives.txt to work dir.
        Returns dict with keys: concerns, notes, pkg_count, lockfile_count.
        """
        concerns: list[str] = []
        notes: list[str] = []
        pkg_lower = pkgname.lower()
        # For scoped packages like @scope/name, compare the 'name' part too
        bare_name = pkg_lower.lstrip('@').split('/')[-1] if '/' in pkg_lower else pkg_lower

        # --- A: Node.js built-in module names ---
        builtin_names = self._get_node_builtin_names()
        builtin_lower = {m.lower() for m in builtin_names}

        for mod in builtin_names:
            mod_lower = mod.lower()
            if mod_lower == bare_name or mod_lower == pkg_lower:
                concerns.append(
                    f'EXACT_BUILTIN_MATCH: "{pkgname}" matches Node.js built-in "{mod}". '
                    'Installing an external package with the same name as a built-in is a '
                    'strong dependency-confusion signal: the built-in will shadow the '
                    'external package in most Node.js contexts.'
                )
            else:
                dist = shared.levenshtein(bare_name, mod_lower)
                if dist == 1:
                    concerns.append(
                        f'NEAR_MATCH(dist=1): "{pkgname}" is one edit from built-in "{mod}". '
                        'Classic typosquat pattern.'
                    )
                elif dist == 2:
                    notes.append(
                        f'NEAR_MATCH(dist=2): "{pkgname}" is two edits from built-in "{mod}".'
                    )

        # --- B: Project lockfile deps ---
        lockfile = self.get_lockfile_path(project_root)
        lockfile_names: list[str] = []
        if lockfile.is_file():
            lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
            lf_fmt = self._detect_lockfile_format(lockfile.name)
            if lf_fmt == 'npm':
                for m in re.finditer(r'"node_modules/([^"]+)"', lf_text):
                    lockfile_names.append(m.group(1))
            elif lf_fmt == 'yarn':
                for m in re.finditer(r'^["\s]*([A-Za-z@][A-Za-z0-9@._/-]*)@', lf_text, re.MULTILINE):
                    lockfile_names.append(m.group(1).strip('"'))
            elif lf_fmt == 'pnpm':
                for m in re.finditer(r'^\s+/?([A-Za-z@][A-Za-z0-9@._/-]*)[@/]', lf_text, re.MULTILINE):
                    lockfile_names.append(m.group(1))

        # Deduplicate lockfile names while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for n in lockfile_names:
            nl = n.lower()
            if nl not in seen:
                seen.add(nl)
                deduped.append(n)
        lockfile_names = deduped

        for dep in lockfile_names:
            dep_lower = dep.lower()
            dep_bare = dep_lower.lstrip('@').split('/')[-1] if '/' in dep_lower else dep_lower
            if dep_lower in builtin_lower or dep_bare in builtin_lower:
                continue  # already checked in A
            if dep_lower == pkg_lower or dep_bare == bare_name:
                concerns.append(
                    f'EXACT_LOCKFILE_MATCH: "{pkgname}" matches existing lockfile dep "{dep}". '
                    'This name is already in use in this project.'
                )
            else:
                dist = shared.levenshtein(bare_name, dep_bare)
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

        # --- C: Structural heuristics ---
        all_known_bare = builtin_lower | {
            d.lower().lstrip('@').split('/')[-1] for d in lockfile_names
        }

        # C1: scope stripping - "@scope/name" vs "name"
        if pkgname.startswith('@') and '/' in pkgname:
            bare = pkgname.lstrip('@').split('/', 1)[1].lower()
            if bare in all_known_bare:
                concerns.append(
                    f'SCOPE_SHADOW: "{pkgname}" bare name "{bare}" matches an existing '
                    'package or built-in. A scoped package wrapping an unscoped one may '
                    'be a supply-chain attack or unnecessary indirection.'
                )

        # C2: common JS wrapper prefix/suffix stripping
        strip_prefixes = ('node-', 'js-', 'browser-')
        strip_suffixes = ('-js', '-node')
        for prefix in strip_prefixes:
            if bare_name.startswith(prefix):
                base = bare_name[len(prefix):]
                if base in all_known_bare:
                    concerns.append(
                        f'PREFIX_SHADOW: "{pkgname}" appears to wrap existing module/package '
                        f'"{base}" (stripped prefix "{prefix}"). '
                        'Verify this external wrapper is intentional.'
                    )
        for suffix in strip_suffixes:
            if bare_name.endswith(suffix):
                base = bare_name[: -len(suffix)]
                if base in all_known_bare:
                    concerns.append(
                        f'SUFFIX_SHADOW: "{pkgname}" appears to wrap existing module/package '
                        f'"{base}" (stripped suffix "{suffix}"). '
                        'Verify this external wrapper is intentional.'
                    )

        # --- Write report ---
        lines = [
            f'=== Alternatives check: {pkgname} {version} ===',
            f'Node.js built-ins checked: {len(builtin_names)}',
            f'Lockfile deps checked    : {len(lockfile_names)}',
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
            'pkg_count': len(builtin_names),
            'lockfile_count': len(lockfile_names),
        }

    def _get_node_builtin_names(self) -> list[str]:
        """Return a list of Node.js built-in module names (without 'node:' prefix).

        These are available without installation in any Node.js project.
        """
        return [
            'assert', 'async_hooks', 'buffer', 'child_process', 'cluster',
            'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel',
            'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https',
            'inspector', 'module', 'net', 'os', 'path', 'perf_hooks',
            'process', 'punycode', 'querystring', 'readline', 'repl',
            'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events',
            'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
        ]

    def get_diff_excludes(self) -> list[str]:
        """Return glob patterns to exclude from diff (JS packaging artifacts)."""
        return ['*.map', 'node_modules', '.yarn', '.pnp.cjs', '.pnp.loader.mjs']

    def get_pkg_src_excludes(self) -> tuple[re.Pattern, re.Pattern]:
        """Return (pkg_excludes, src_excludes) compiled regex patterns."""
        pkg_ex = re.compile(
            r'^\.git/'
            r'|^LICEN[SC]E(?:\.[a-zA-Z]+)?$'
            r'|^COPYING(?:\.[a-zA-Z]+)?$'
            r'|^node_modules/'
            r'|\.map$'
        )
        src_ex = re.compile(
            r'^\.git/'
            r'|^node_modules/'
            r'|^docs?/'
            r'|^tests?/'
            r'|^__tests__/'
            r'|^\.github/'
            r'|\.map$'
        )
        return pkg_ex, src_ex

    def find_source_root(self, source_dir: Path) -> Path:
        """Return the subdirectory of source_dir containing the package source.

        For npm packages, publishable content is usually at the repo root.
        Some monorepos put packages one level deep under packages/ or apps/.
        """
        if (source_dir / 'package.json').is_file():
            return source_dir
        for child in source_dir.iterdir():
            if child.is_dir() and (child / 'package.json').is_file():
                return child
        return source_dir

    def get_deep_source_config(self) -> dict:
        """Return deep source comparison config for JavaScript."""
        return {
            'primary_label': 'JavaScript',
            'primary_pattern': r'\.(js|mjs|cjs|ts|jsx|tsx)$',
        }

    def reproducible_build(
        self,
        pkgname: str,
        version: str,
        work: Path,
        sandbox: str,
    ) -> tuple[str, int, int]:
        """Attempt to reproduce the npm pack output from the source clone.

        Runs 'npm pack' in the cloned source and compares the resulting tarball
        contents against the distributed package. Note: npm tarballs are not
        bitwise-reproducible across machines due to embedded timestamps; this
        check therefore compares unpacked file contents rather than SHA256 hashes.

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
        built_tgz_dir = work / 'raw-built-tgz'
        built_tgz_dir.mkdir(exist_ok=True)

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

        rc_nv, nv_out, _ = shared.run_cmd(['npm', '--version'], timeout=10)
        npm_ver = shared.sanitize(nv_out.strip()) if rc_nv == 0 else 'unknown'
        lines.append(f'NPM_VERSION: {npm_ver}')

        # Find package.json in the source clone; check one level deep for monorepos
        pkg_json_path = clone_dir / 'package.json'
        if not pkg_json_path.is_file():
            for child in clone_dir.iterdir():
                if child.is_dir() and (child / 'package.json').is_file():
                    clone_dir = child
                    pkg_json_path = clone_dir / 'package.json'
                    break
        if not pkg_json_path.is_file():
            return finish('SKIPPED (no package.json in source)')

        lines.append(f'BUILD_ROOT: {shared.sanitize(str(clone_dir))}')
        build_log_path = work / 'raw-build-output.txt'
        build_ok = False

        if sandbox == 'bwrap':
            bwrap_args = [
                'bwrap',
                '--ro-bind', str(clone_dir), '/src',
                '--bind', str(built_tgz_dir), '/out',
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
            bwrap_args += ['npm', 'pack', '--pack-destination', '/out']
            rc_b, b_out, b_err = shared.run_cmd(bwrap_args, timeout=300)
            build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
            build_ok = (rc_b == 0)

        elif sandbox in ('docker', 'podman'):
            rc_nv2, nv2_out, _ = shared.run_cmd(['node', '--version'], timeout=5)
            node_tag = 'lts'
            if rc_nv2 == 0:
                m = re.match(r'v(\d+)', nv2_out.strip())
                if m:
                    node_tag = m.group(1)
            rc_b, b_out, b_err = shared.run_cmd(
                [sandbox, 'run', '--rm',
                 '--network', 'none',
                 '-v', f'{clone_dir}:/src:ro',
                 '-v', f'{built_tgz_dir}:/out',
                 f'node:{node_tag}',
                 'sh', '-c',
                 'cp -r /src /tmp/src && cd /tmp/src && '
                 'npm pack --pack-destination /out'],
                timeout=600,
            )
            build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
            build_ok = (rc_b == 0)

        elif sandbox == 'firejail':
            rc_b, b_out, b_err = shared.run_cmd(
                ['firejail', '--quiet', '--net=none',
                 f'--read-only={clone_dir}',
                 'npm', 'pack', '--pack-destination', str(built_tgz_dir)],
                cwd=clone_dir,
                timeout=300,
            )
            build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
            build_ok = (rc_b == 0)

        else:
            # No sandbox available: refuse to build unsandboxed
            return finish(
                'SKIPPED (no sandbox available: install bwrap, firejail, docker, or podman)'
            )

        lines.append(f'BUILD_STATUS: {"yes" if build_ok else "no"}')

        if not build_ok:
            return finish('INCONCLUSIVE (build failed)')

        built_tgzs = list(built_tgz_dir.glob('*.tgz'))
        if not built_tgzs:
            return finish('INCONCLUSIVE (no .tgz produced)')
        built_tgz = max(built_tgzs, key=lambda p: p.stat().st_mtime)

        built_sha = shared.sha256_file(built_tgz)
        pkg_hash_file = work / 'package-hash.txt'
        dist_sha = ''
        if pkg_hash_file.is_file():
            first_line = pkg_hash_file.read_text(encoding='utf-8').splitlines()[0]
            dist_sha = first_line.split()[0] if first_line.split() else ''

        lines.append(f'BUILT_SHA256: {shared.sanitize(built_sha)}')
        lines.append(f'DISTRIBUTED_SHA256: {shared.sanitize(dist_sha or "UNKNOWN")}')

        if built_sha and built_sha == dist_sha:
            return finish('EXACTLY REPRODUCIBLE (sha256 match)')

        # Hashes will nearly always differ (timestamps); compare unpacked contents
        built_unpacked = work / 'raw-built-unpacked'
        built_unpacked.mkdir(exist_ok=True)
        _unpack_tgz(built_tgz, built_unpacked, [], 'repro-unpack')

        dist_unpacked = work / 'unpacked'
        if not dist_unpacked.is_dir():
            return finish('INCONCLUSIVE (hashes differ, no dist unpacked dir)')

        rc_diff, diff_out, _ = shared.run_cmd(
            ['diff', '-r', str(built_unpacked), str(dist_unpacked), '--exclude=*.map'],
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
