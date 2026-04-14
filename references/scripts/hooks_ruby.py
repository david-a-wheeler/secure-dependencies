#!/usr/bin/env python3
# hooks_ruby.py: Ruby language operations for the dependency analysis driver.
#
# Handles the Ruby gem format (download, unpack, gemspec, Rakefile) and the
# rubygems.org registry API. Used for --from rubygems; can be reused for other
# Ruby gem registries (Gemfury, GitHub Packages, etc.) with a different registry
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
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import analysis_shared as shared

# ---------------------------------------------------------------------------
# Module-level constants read by the driver
# ---------------------------------------------------------------------------

ECOSYSTEM = 'ruby'
LOCKFILE_NAME = 'Gemfile.lock'

DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    ('eval-variants',
     r'\b(?:eval|instance_eval|class_eval|module_eval|binding\.eval)\s*[\(\{]'),
    ('shell-exec',
     r'\b(?:system|exec|spawn)\s*[\(\x60]|IO\.popen|Open3\.(?:popen|capture|pipeline)|%x\{|\x60'),
    ('obfuscated-exec',
     r'(?:Base64\.decode64|\.unpack\s*\(\s*["\x27]H\*|Zlib::Inflate|\.decode)\b'
     r'(?:[^\n]{0,120})(?:eval|instance_eval|class_eval|exec|system)\b'),
    ('marshal-load',       r'\bMarshal\.(?:load|restore)\b'),
    ('network-at-load-scope',
     r'^\s*(?:Net::HTTP|require\s+["\x27]open-uri["\x27]|URI\.open|Faraday\.new'
     r'|RestClient\.|HTTParty\.(?:get|post)|TCPSocket\.new|UDPSocket\.new)\b'),
    ('credential-env-vars',
     r'ENV\s*\[\s*["\x27][A-Z_]*'
     r'(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_|GH_|GITHUB_|CI_|NPM_|PYPI_|BUNDLE_)'
     r'[A-Z_]*["\x27]\s*\]'),
    ('home-or-shell-write',
     r'(?:File\.(?:write|open|binwrite)|IO\.write)\s*[^,]+'
     r'["\x27](?:~\/|\/home\/|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.ssh\/)'),
    ('dynamic-dispatch',
     r'\b(?:__send__|public_send|send)\s*\(\s*(?:params|request|user_input|ENV|ARGV|gets)\b'),
    ('at-exit-hooks',      r'^\s*at_exit\b'),
]

DIFF_PATTERNS: list[tuple[str, str]] = [
    ('diff-sql-injection',
     r'^\+.*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\b.*["\x27]\s*\+'),
    ('diff-cmd-injection',
     r'^\+.*(?:system|exec|spawn|popen|Open3)\s*\('),
    ('diff-hardcoded-secrets',
     r'^\+.*(?:password|passwd|secret|api_key|token)\s*=\s*["\x27][^"\x27]{6,}["\x27]'),
    ('diff-eval',
     r'^\+.*(?:eval|instance_eval|class_eval|module_eval)\s*[\(\{]'),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_source_url(gemspec_text: str) -> str:
    """Extract source/homepage URL from gemspec text.

    >>> _extract_source_url('s.source_code_uri = "https://github.com/foo/bar"')
    'https://github.com/foo/bar'
    >>> _extract_source_url('s.homepage = "https://example.com"')
    'https://example.com'
    >>> _extract_source_url('no url here')
    ''
    """
    m = re.search(
        r'(?:source_code_uri|homepage_uri|homepage)\s*=\s*["\']([^"\']+)', gemspec_text
    )
    return m.group(1).strip() if m else ''


def _extract_gemspec_license(gemspec_text: str) -> str:
    """Extract raw license string from gemspec text, or empty string.

    >>> _extract_gemspec_license('s.license = "MIT"')
    'MIT'
    >>> _extract_gemspec_license("s.licenses = ['Apache-2.0']")
    'Apache-2.0'
    >>> _extract_gemspec_license('no license here')
    ''
    """
    lic_match = re.search(r'\.licenses?\s*=\s*\[?["\']([^"\']+)["\']', gemspec_text)
    return lic_match.group(1).strip() if lic_match else ''


# ---------------------------------------------------------------------------
# Public API: called by dep_review.py
# ---------------------------------------------------------------------------

def download_new(
    pkgname: str,
    version: str,
    work: Path,
    failures: list[str],
    registry_url: str | None = None,
) -> dict:
    """gem fetch + gem unpack into work/unpacked/.

    Falls back to `gem specification` for gemspec if not present in unpacked dir.
    Returns dict with keys: unpacked_dir (Path), sha256 (str), gem_file (Path).
    """
    unpacked_dir_base = work / 'unpacked'
    unpacked_dir_base.mkdir(parents=True, exist_ok=True)

    gem_file = work / f'{pkgname}-{version}.gem'
    sha256 = ''

    fetch_cmd = ['gem', 'fetch', pkgname, '-v', version]
    if registry_url:
        fetch_cmd += ['--source', registry_url]
    rc, _, err = shared.run_cmd(fetch_cmd, cwd=work)
    if rc == 0 and gem_file.is_file():
        sha256 = shared.sha256_file(gem_file)
        (work / 'package-hash.txt').write_text(
            f'{sha256}  {pkgname}-{version}.gem\n', encoding='utf-8'
        )
        rc2, _, _ = shared.run_cmd(
            ['gem', 'unpack', str(gem_file), '--target', str(unpacked_dir_base)]
        )
        if rc2 != 0:
            failures.append('gem-unpack-new')
    else:
        failures.append('gem-fetch-new')
        (work / 'package-hash.txt').write_text('ERROR: gem fetch failed\n', encoding='utf-8')

    unpacked_dir = unpacked_dir_base / f'{pkgname}-{version}'

    # Fall back to `gem specification` for gemspec if not present in unpacked dir
    gemspec_file = unpacked_dir / f'{pkgname}.gemspec'
    if not gemspec_file.is_file() and gem_file.is_file():
        rc_spec, spec_out, _ = shared.run_cmd(
            ['gem', 'specification', str(gem_file), '--ruby']
        )
        if rc_spec == 0 and spec_out.strip():
            extracted = work / 'gemspec.txt'
            extracted.write_text(spec_out, encoding='utf-8', errors='replace')

    return {
        'unpacked_dir': unpacked_dir,
        'sha256': sha256,
        'gem_file': gem_file,
    }


def read_manifest(
    pkgname: str,
    version: str,
    unpacked_dir: Path,
    work: Path,
    failures: list[str],
) -> dict:
    """Parse gemspec; write manifest-analysis.txt and gemspec.txt.

    Returns dict with keys: source_url, extensions, executables,
    executables_list, post_install_msg, has_rakefile_tasks,
    runtime_dep_lines, gemspec_license_raw, gemspec_text.
    """
    extensions = 'NO'
    executables = 'NO'
    executables_list = ''
    post_install_msg = 'NO'
    has_rakefile_tasks = 'NO'
    gemspec_license_raw = ''
    source_url = ''
    gemspec_text = ''
    runtime_dep_lines: list[str] = []

    # Locate gemspec: prefer in-package file, fall back to extracted gemspec.txt
    gemspec_file = unpacked_dir / f'{pkgname}.gemspec'
    if not gemspec_file.is_file():
        extracted = work / 'gemspec.txt'
        if extracted.is_file():
            gemspec_file = extracted

    if gemspec_file.is_file():
        dest_gemspec = work / 'gemspec.txt'
        if gemspec_file != dest_gemspec:
            shutil.copy2(gemspec_file, dest_gemspec)
        gemspec_text = gemspec_file.read_text(encoding='utf-8', errors='replace')

        manifest_lines: list[str] = [f'=== Manifest analysis: {pkgname} {version} ===', '']

        if 'extensions' in gemspec_text:
            extensions = 'YES'
            manifest_lines.append('HAS_EXTENSIONS: YES')
        else:
            manifest_lines.append('HAS_EXTENSIONS: NO')

        exec_lines = [l for l in gemspec_text.splitlines() if 'executables' in l]
        if exec_lines:
            executables = 'YES'
            executables_list = shared.sanitize('; '.join(exec_lines[:3]))
            manifest_lines.extend(['HAS_EXECUTABLES: YES', f'EXECUTABLES_LINES: {executables_list}'])
        else:
            manifest_lines.append('HAS_EXECUTABLES: NO')

        if 'post_install_message' in gemspec_text:
            post_install_msg = 'YES'
            manifest_lines.append('HAS_POST_INSTALL_MESSAGE: YES')
        else:
            manifest_lines.append('HAS_POST_INSTALL_MESSAGE: NO')

        manifest_lines.append('')
        manifest_lines.append('RUNTIME_DEPS:')
        dep_lines = [
            l for l in gemspec_text.splitlines()
            if 'add_runtime_dependency' in l or
               ('add_dependency' in l and 'development' not in l)
        ]
        if dep_lines:
            runtime_dep_lines = dep_lines
            manifest_lines.extend(shared.sanitize(l) for l in dep_lines)
        else:
            manifest_lines.append('  (none)')

        manifest_lines.extend(['', 'DEV_DEPS:'])
        dev_lines = [l for l in gemspec_text.splitlines() if 'add_development_dependency' in l]
        (manifest_lines.extend(shared.sanitize(l) for l in dev_lines)
         if dev_lines else manifest_lines.append('  (none)'))

        hp_match = re.search(
            r'(?:homepage|source_code_uri|homepage_uri)\s*=\s*["\']([^"\']+)', gemspec_text
        )
        homepage_val = shared.sanitize(hp_match.group(1)) if hp_match else '(not found)'
        manifest_lines.extend(['', f'HOMEPAGE: {homepage_val}'])

        auth_match = re.search(r'authors?\s*=\s*([^\n]+)', gemspec_text)
        authors_val = shared.sanitize(auth_match.group(1)[:200]) if auth_match else '(not found)'
        manifest_lines.append(f'AUTHORS: {authors_val}')

        gemspec_license_raw = _extract_gemspec_license(gemspec_text)
        manifest_lines.extend(
            ['', f'LICENSE_DECLARED: {shared.sanitize(gemspec_license_raw) or "(not declared)"}']
        )

        manifest_lines.append('')
        rakefile = unpacked_dir / 'Rakefile'
        if rakefile.is_file():
            manifest_lines.append('RAKEFILE_PRESENT: YES')
            rake_text = rakefile.read_text(encoding='utf-8', errors='replace')
            if re.search(r'(?i)install|post_install', rake_text):
                has_rakefile_tasks = 'YES'
                manifest_lines.append('RAKEFILE_INSTALL_TASKS: YES')
            else:
                manifest_lines.append('RAKEFILE_INSTALL_TASKS: NO')
        else:
            manifest_lines.append('RAKEFILE_PRESENT: NO')

        (work / 'manifest-analysis.txt').write_text(
            '\n'.join(manifest_lines) + '\n', encoding='utf-8'
        )
        source_url = _extract_source_url(gemspec_text)

        # Collect install-time scripts for AI review when any install-time
        # code is present. These files run (or direct code that runs) during
        # gem install, so an AI reviewer must read them.
        install_script_files: list[tuple[str, Path]] = []
        if extensions == 'YES':
            for name in ('extconf.rb', 'Makefile.in', 'Makefile'):
                p = unpacked_dir / name
                if p.is_file():
                    install_script_files.append((name, p))
        if has_rakefile_tasks == 'YES' and rakefile.is_file():
            install_script_files.append(('Rakefile', rakefile))

        if install_script_files:
            script_lines: list[str] = [
                '=== Install-time scripts for AI review ===',
                '',
                'These files execute (or direct code that executes) during gem install.',
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
    else:
        failures.append('gemspec-missing')
        (work / 'manifest-analysis.txt').write_text('ERROR: gemspec not found\n', encoding='utf-8')

    has_install_scripts = (work / 'install-scripts.txt').is_file()
    return {
        'source_url': source_url,
        'extensions': extensions,
        'executables': executables,
        'executables_list': executables_list,
        'post_install_msg': post_install_msg,
        'has_rakefile_tasks': has_rakefile_tasks,
        'has_install_scripts': 'YES' if has_install_scripts else 'NO',
        'runtime_dep_lines': runtime_dep_lines,
        'gemspec_license_raw': gemspec_license_raw,
        'gemspec_text': gemspec_text,
    }


def download_old(
    pkgname: str,
    old_ver: str,
    work: Path,
    failures: list[str],
    registry_url: str | None = None,
) -> dict:
    """Download old version; check gem environment gemdir cache first, then gem fetch.

    Unpacks into work/old/.
    Returns dict with keys: ok (bool), source (str), unpacked_dir (Path).
    """
    old_dir_base = work / 'old'
    old_dir_base.mkdir(exist_ok=True)

    ok = False
    source = ''

    rc_gemdir, gemdir_out, _ = shared.run_cmd(['gem', 'environment', 'gemdir'])
    gemdir = gemdir_out.strip() if rc_gemdir == 0 else ''
    old_cached_gem = (
        Path(gemdir) / 'cache' / f'{pkgname}-{old_ver}.gem' if gemdir else None
    )

    if old_cached_gem and old_cached_gem.is_file():
        rc_up, _, _ = shared.run_cmd(
            ['gem', 'unpack', str(old_cached_gem), '--target', str(old_dir_base)]
        )
        if rc_up == 0:
            ok = True
            source = 'local-cache'
        else:
            failures.append('gem-unpack-old')
    else:
        raw_old_pkg = work / 'raw-old-pkg'
        raw_old_pkg.mkdir(exist_ok=True)
        fetch_cmd = ['gem', 'fetch', pkgname, '-v', old_ver]
        if registry_url:
            fetch_cmd += ['--source', registry_url]
        rc_fetch, _, _ = shared.run_cmd(fetch_cmd, cwd=raw_old_pkg)
        if rc_fetch == 0:
            old_gem = raw_old_pkg / f'{pkgname}-{old_ver}.gem'
            if old_gem.is_file():
                rc_up2, _, _ = shared.run_cmd(
                    ['gem', 'unpack', str(old_gem), '--target', str(old_dir_base)]
                )
                if rc_up2 == 0:
                    ok = True
                    source = 'fetched'
                else:
                    failures.append('gem-unpack-old')
            else:
                failures.append('gem-fetch-old')
        else:
            failures.append('gem-fetch-old')

    (work / 'old-version-status.txt').write_text(
        f'OLD_VERSION_SOURCE: {source or "unavailable"}\n', encoding='utf-8'
    )

    unpacked_dir = old_dir_base / f'{pkgname}-{old_ver}'
    return {'ok': ok, 'source': source, 'unpacked_dir': unpacked_dir}


def get_old_license(
    pkgname: str,
    old_ver: str,
    old_unpacked_dir: Path,
) -> str | None:
    """Extract raw license string from old version gemspec.

    Returns the raw string or None if not found.
    """
    if not old_unpacked_dir or not old_unpacked_dir.is_dir():
        return None
    old_gs_path = old_unpacked_dir / f'{pkgname}.gemspec'
    if not old_gs_path.is_file():
        return None
    old_gs_text = old_gs_path.read_text(encoding='utf-8', errors='replace')
    return _extract_gemspec_license(old_gs_text) or None


def fetch_all_registry_data(
    pkgname: str,
    version: str,
    work: Path,
    registry_url: str | None = None,
) -> dict:
    """Fetch RubyGems API: gems endpoint (MFA), versions endpoint (age/stability), owners.

    registry_url overrides the default rubygems.org base URL for private registries.
    Most private gem servers (Gemfury, Gemstash) implement the same /api/v1/ paths.

    Writes: provenance.txt, raw-owners.json.
    Returns dict with keys: mfa_status, age_years_float, last_release_days,
    owner_count_int, version_stability, license_from_registry, ver_info_lines.
    """
    api_base = (registry_url.rstrip('/') if registry_url else 'https://rubygems.org')
    mfa_status = 'unknown'
    age_years_float: float | None = None
    last_release_days: int | None = None
    owner_count_int: int | None = None
    version_stability = 'unknown'
    license_from_registry: list[str] = []
    ver_info_lines: list[str] = []

    prov_lines: list[str] = [f'=== Provenance: {pkgname} {version} ===', '']
    rc_gi, gi_out, _ = shared.run_cmd(['gem', 'info', pkgname, '-r'])
    prov_lines.extend(
        ['GEM_INFO:', shared.sanitize(gi_out[:2000]) if rc_gi == 0 else '(unavailable)', '']
    )

    # Gems endpoint: MFA
    # RubyGems stores MFA status in metadata.rubygems_mfa_required (a string "true"/"false")
    # rather than a top-level boolean field.
    api_gem_data = shared.http_get(f'{api_base}/api/v1/gems/{pkgname}.json')
    if api_gem_data:
        try:
            api_info = json.loads(api_gem_data.decode('utf-8', errors='replace'))
            # Try top-level boolean first (older API format), then metadata string
            mfa_val = api_info.get('mfa_required')
            if mfa_val is True:
                mfa_status = 'true'
            elif mfa_val is False:
                mfa_status = 'false'
            else:
                meta_mfa = api_info.get('metadata', {}).get('rubygems_mfa_required', '')
                if isinstance(meta_mfa, str) and meta_mfa.lower() == 'true':
                    mfa_status = 'true'
                elif isinstance(meta_mfa, str) and meta_mfa.lower() == 'false':
                    mfa_status = 'false'
        except (ValueError, KeyError):
            pass
    prov_lines.extend([f'MFA_REQUIRED: {shared.sanitize(mfa_status)}', ''])

    # Versions endpoint: age, stability, license
    ver_api_data_bytes = shared.http_get(f'{api_base}/api/v1/versions/{pkgname}.json')
    if ver_api_data_bytes:
        try:
            versions = json.loads(ver_api_data_bytes.decode('utf-8', errors='replace'))
            if isinstance(versions, list) and versions:
                oldest = versions[-1]
                newest = versions[0]

                first_date = str(oldest.get('created_at', ''))
                age_days_val = shared.days_since(first_date)
                if age_days_val is not None:
                    age_years_float = age_days_val / 365

                latest_date = str(
                    newest.get('latest_version_created_at', '') or newest.get('created_at', '')
                )
                last_release_days = shared.days_since(latest_date)

                ver_num = str(newest.get('number', version))
                if re.search(r'(?i)(alpha|beta|rc|pre|dev)', ver_num) or ver_num.startswith('0.'):
                    version_stability = 'pre-release'
                else:
                    version_stability = 'stable'

            # Find this specific version's data
            target_ver_info = next(
                (v for v in versions if isinstance(v, dict) and v.get('number') == version), None
            )
            if target_ver_info:
                ver_info_lines.append('VERSION_INFO (selected fields):')
                for key in ('number', 'created_at', 'authors', 'sha',
                            'ruby_version', 'rubygems_version', 'licenses'):
                    val = target_ver_info.get(key, '')
                    ver_info_lines.append(f'  {key}: {shared.sanitize(str(val))[:200]}')
                lic_field = target_ver_info.get('licenses')
                if isinstance(lic_field, list):
                    license_from_registry.extend(str(lc) for lc in lic_field if lc)
                elif lic_field:
                    license_from_registry.append(str(lic_field))
        except (ValueError, KeyError, TypeError):
            ver_info_lines.append('VERSION_INFO: (parse error)')
    else:
        ver_info_lines.append('VERSION_INFO: (unavailable)')

    prov_lines.extend(ver_info_lines)

    # Owners endpoint
    owners_data = shared.http_get(f'{api_base}/api/v1/owners/{pkgname}.json')
    if owners_data:
        (work / 'raw-owners.json').write_bytes(owners_data)
        try:
            owners = json.loads(owners_data.decode('utf-8', errors='replace'))
            if isinstance(owners, list):
                owner_count_int = len(owners)
        except (ValueError, TypeError):
            pass

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
    """Return deduplicated list of license candidates: gemspec first, then registry.

    Returns list of raw license strings.

    >>> get_license_candidates({'gemspec_license_raw': 'MIT'}, {'license_from_registry': ['Apache-2.0']})
    ['MIT', 'Apache-2.0']
    >>> get_license_candidates({'gemspec_license_raw': 'MIT'}, {'license_from_registry': ['MIT']})
    ['MIT']
    >>> get_license_candidates({}, {'license_from_registry': ['MIT']})
    ['MIT']
    >>> get_license_candidates({'gemspec_license_raw': ''}, {})
    []
    """
    candidates: list[str] = []
    if manifest.get('gemspec_license_raw'):
        candidates.append(manifest['gemspec_license_raw'])
    candidates.extend(registry_data.get('license_from_registry', []))
    # Deduplicate, preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for lc in candidates:
        if lc and lc not in seen:
            seen.add(lc)
            unique.append(lc)
    return unique


def check_lockfile(
    runtime_dep_lines: list[str],
    old_dep_lines: list[str],
    project_root: Path,
) -> dict:
    """Parse Gemfile.lock; compare new vs old runtime deps.

    Returns dict with keys: added_deps, removed_deps, not_in_lockfile,
    and private keys _lockfile_lines, _dep_lines_new, _dep_lines_old used
    by write_dep_files() in the driver to write new-deps.txt and
    dep-lockfile-check.txt. Does not write any files itself.
    """
    dep_lines_new = sorted(shared.sanitize(l) for l in runtime_dep_lines)
    dep_lines_old = sorted(shared.sanitize(l) for l in old_dep_lines)

    added_deps = sorted(set(dep_lines_new) - set(dep_lines_old))
    removed_deps = sorted(set(dep_lines_old) - set(dep_lines_new))
    not_in_lockfile: list[str] = []

    lockfile = project_root / LOCKFILE_NAME
    lockfile_lines: list[str] = ['=== Lockfile check ===']
    if lockfile.is_file() and dep_lines_new:
        lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
        for dep_line in dep_lines_new:
            m_dep = re.search(r"['\"]([a-z][a-z0-9_-]+)['\"]", dep_line)
            if not m_dep:
                continue
            dep_name = m_dep.group(1)
            safe_dep = shared.sanitize(dep_name)
            if re.search(rf'^    {re.escape(dep_name)} ', lf_text, re.MULTILINE):
                lockfile_lines.append(f'IN_LOCKFILE: {safe_dep}')
            else:
                lockfile_lines.append(f'NOT_IN_LOCKFILE: {safe_dep}')
                not_in_lockfile.append(safe_dep)
    else:
        lockfile_lines.append('(lockfile or dep list unavailable)')

    # The driver calls write_dep_files() to write the actual output files to work/.
    # This function returns the data; writing is deferred to the driver so that
    # the work directory path (which includes pkgname/version) is available.

    return {
        'added_deps': added_deps,
        'removed_deps': removed_deps,
        'not_in_lockfile': not_in_lockfile,
        '_lockfile_lines': lockfile_lines,
        '_dep_lines_new': dep_lines_new,
        '_dep_lines_old': dep_lines_old,
    }


def check_dep_registry(dep_name: str) -> dict:
    """RubyGems API lookup for a dep not in lockfile.

    Returns dict with keys: downloads, first_seen, homepage.
    """
    api_data = shared.http_get(f'https://rubygems.org/api/v1/gems/{dep_name}.json')
    if api_data:
        try:
            info = json.loads(api_data.decode('utf-8', errors='replace'))
            downloads = info.get('downloads', 'unknown')
            created = info.get('created_at', 'unknown')
            homepage_v = info.get('homepage_uri', 'unknown')
            date_m = re.search(r'\d{4}-\d{2}-\d{2}', str(created))
            return {
                'downloads': shared.sanitize(str(downloads))[:50],
                'first_seen': shared.sanitize(date_m.group() if date_m else 'unknown'),
                'homepage': shared.sanitize(str(homepage_v))[:200],
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
    """Run `gem dependency`; compare against lockfile.

    Writes: transitive-deps.txt, raw-transitive-deps.txt.
    Returns dict with keys: total (int), not_in_lockfile (list[str]).
    """
    rc_dep, dep_out, _ = shared.run_cmd(
        ['gem', 'dependency', pkgname, '-v', version, '--remote', '--pipe'],
        timeout=60,
    )
    (work / 'raw-transitive-deps.txt').write_text(dep_out, encoding='utf-8', errors='replace')

    all_transitive: list[str] = []
    for line in dep_out.splitlines():
        m_dep = re.match(r"gem\s+['\"]([a-z][a-z0-9_-]+)['\"]", line.strip())
        if m_dep:
            dep_name = m_dep.group(1)
            if dep_name != pkgname:
                all_transitive.append(dep_name)

    total = len(all_transitive)
    lf_text = ''
    if lockfile_path.is_file():
        lf_text = lockfile_path.read_text(encoding='utf-8', errors='replace')

    transitive_new: list[str] = []
    for dep_name in all_transitive:
        if not re.search(rf'^    {re.escape(dep_name)} ', lf_text, re.MULTILINE):
            transitive_new.append(dep_name)

    trans_lines = [
        f'=== Transitive dependency footprint: {pkgname} {version} ===',
        f'TOTAL_TRANSITIVE_DEPS: {total}',
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
    """Check for typosquat, slopsquat, and stdlib overlap signals.

    Three checks:
    A: Query 'gem list' for all installed/stdlib gems; flag exact matches and
        near-matches (edit distance <= 2). Because 'gem list' includes default
        and bundled gems, this covers the stdlib without a hardcoded list.
    C: Read Gemfile.lock for the project's direct deps; flag near-matches.
        Catches attacks targeting this project's specific dependency set.
    D: Structural heuristics: hyphen/underscore normalization, and stripping
        common Ruby-specific name prefixes/suffixes (ruby-, -rb, etc.) to see
        if what remains matches an installed gem.

    # TODO (Option B): Add registry search for top packages by download count
    #   to catch typosquats of popular packages not yet installed locally.
    #   Would call rubygems.org/api/v1/search.json?query=PKGNAME and compare
    #   edit distance + download counts of the top results.

    Writes: alternatives.txt to work dir.
    Returns dict with keys: concerns (list[str]), notes (list[str]),
      gem_count (int), lockfile_count (int).
    """
    concerns: list[str] = []
    notes: list[str] = []

    # --- A: Query runtime for all installed/stdlib gems ---
    gem_names: list[str] = []
    rc, out, _ = shared.run_cmd(['gem', 'list', '--no-versions'], timeout=30)
    if rc == 0:
        for line in out.splitlines():
            name = line.strip()
            if name:
                gem_names.append(name)

    pkg_lower = pkgname.lower()

    for gem in gem_names:
        gem_lower = gem.lower()
        if gem_lower == pkg_lower:
            concerns.append(
                f'EXACT_STDLIB_MATCH: "{pkgname}" matches installed/stdlib gem "{gem}". '
                'Installing an external gem with the same name as an already-available '
                'gem is a strong slopsquat signal.'
            )
        else:
            dist = shared.levenshtein(pkg_lower, gem_lower)
            if dist == 1:
                concerns.append(
                    f'NEAR_MATCH(dist=1): "{pkgname}" is one edit from installed gem "{gem}". '
                    'Classic typosquat pattern.'
                )
            elif dist == 2:
                notes.append(
                    f'NEAR_MATCH(dist=2): "{pkgname}" is two edits from installed gem "{gem}".'
                )

    # --- C: Read Gemfile.lock for project-specific deps ---
    lockfile = project_root / 'Gemfile.lock'
    lockfile_names: list[str] = []
    if lockfile.is_file():
        in_specs = False
        for line in lockfile.read_text(encoding='utf-8', errors='replace').splitlines():
            if line.strip() == 'specs:':
                in_specs = True
                continue
            if in_specs:
                # Gem entries are indented with exactly 4 spaces
                m = re.match(r'^    ([A-Za-z0-9_\-\.]+)\s', line)
                if m:
                    lockfile_names.append(m.group(1))
                elif line and not line[0].isspace():
                    in_specs = False  # end of specs block

    # Only flag lockfile matches not already caught by gem_names
    installed_lower = {g.lower() for g in gem_names}
    for dep in lockfile_names:
        dep_lower = dep.lower()
        if dep_lower in installed_lower:
            continue  # already checked in A
        if dep_lower == pkg_lower:
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
    # D1: hyphen/underscore normalization (ruby gems use both conventions)
    normalized = pkg_lower.replace('-', '_')
    if normalized != pkg_lower:
        for gem in gem_names:
            if gem.lower().replace('-', '_') == normalized and gem.lower() != pkg_lower:
                concerns.append(
                    f'NORMALIZATION_MATCH: "{pkgname}" normalizes to the same name as '
                    f'installed gem "{gem}" (hyphen/underscore difference). '
                    'Could be a naming-convention confusion attack.'
                )

    # D2: language prefix/suffix stripping
    # If stripping a Ruby-specific wrapper prefix/suffix reveals an installed gem name,
    # this package may be an unnecessary (or malicious) wrapper around stdlib.
    strip_prefixes = ('ruby-', 'rb-', 'gem-')
    strip_suffixes = ('-rb', '-ruby', '-gem')
    all_known_lower = {g.lower() for g in gem_names} | {d.lower() for d in lockfile_names}
    for prefix in strip_prefixes:
        if pkg_lower.startswith(prefix):
            base = pkg_lower[len(prefix):]
            if base in all_known_lower:
                concerns.append(
                    f'PREFIX_SHADOW: "{pkgname}" appears to wrap installed gem '
                    f'"{base}" (stripped prefix "{prefix}"). '
                    'Verify this external wrapper is intentional.'
                )
    for suffix in strip_suffixes:
        if pkg_lower.endswith(suffix):
            base = pkg_lower[: -len(suffix)]
            if base in all_known_lower:
                concerns.append(
                    f'SUFFIX_SHADOW: "{pkgname}" appears to wrap installed gem '
                    f'"{base}" (stripped suffix "{suffix}"). '
                    'Verify this external wrapper is intentional.'
                )

    # --- Write report ---
    lines = [
        f'=== Alternatives check: {pkgname} {version} ===',
        f'Installed/stdlib gems checked : {len(gem_names)}',
        f'Lockfile deps checked         : {len(lockfile_names)}',
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
        'gem_count': len(gem_names),
        'lockfile_count': len(lockfile_names),
    }


def get_diff_excludes() -> list[str]:
    """Returns list of glob patterns to exclude from diff."""
    return ['*.gem']


def get_pkg_src_excludes() -> tuple[re.Pattern, re.Pattern]:
    """Returns (pkg_excludes, src_excludes) compiled regex patterns.

    pkg_excludes: paths in the package to ignore during comparison (e.g.
      standard files always present in gems but not necessarily in the gem/
      subdirectory of a monorepo source).
    src_excludes: paths in the source clone to ignore.
    """
    # Gems always include a license file; in monorepos it lives at the repo root,
    # not inside the gem/ subdirectory, so exclude it from the "extra" check.
    # Note: pattern is applied to relative paths WITHOUT a leading "./" prefix.
    pkg_ex = re.compile(
        r'^\.git/'
        r'|^LICEN[SC]E(?:\.[a-zA-Z]+)?$'
        r'|^COPYING(?:\.[a-zA-Z]+)?$'
    )
    src_ex = re.compile(r'^\.git/')
    return pkg_ex, src_ex


def find_source_gem_root(source_dir: Path) -> Path:
    """Return the subdirectory of source_dir that contains the gem content.

    Some gem repos keep the gem in a ``gem/`` subdirectory (pagy, rails, etc.)
    rather than at the repo root. If a gemspec is found one level down, use
    that subdirectory; otherwise fall back to source_dir itself.
    """
    # Look for a direct subdirectory that contains a .gemspec file
    for candidate in source_dir.iterdir():
        if candidate.is_dir() and any(candidate.glob('*.gemspec')):
            return candidate
    return source_dir


def get_deep_source_config() -> dict:
    """Returns deep source comparison config for Ruby."""
    return {'primary_label': 'Ruby', 'primary_pattern': r'\.(rb)$'}


def reproducible_build(
    pkgname: str,
    version: str,
    work: Path,
    sandbox: str,
) -> tuple[str, int, int]:
    """Attempt to build gem from source and compare with distributed gem.

    Returns (repro_result, code_diffs, metadata_diffs).
    repro_result is one of:
      SKIPPED
      INCONCLUSIVE
      EXACTLY REPRODUCIBLE (sha256 match)
      EXACTLY REPRODUCIBLE (content match)
      FUNCTIONALLY EQUIVALENT (metadata-only diffs)
      UNEXPECTED DIFFERENCES
    """
    import hashlib

    clone_dir = work / 'source'
    built_gem_dir = work / 'raw-built-gem'
    built_gem_dir.mkdir(exist_ok=True)

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

    rc_rv, rv_out, _ = shared.run_cmd(['ruby', '--version'], timeout=10)
    ruby_ver = shared.sanitize(rv_out.strip()) if rc_rv == 0 else 'unknown'
    lines.append(f'RUBY_VERSION: {ruby_ver}')

    gemspec_candidates = list(clone_dir.rglob('*.gemspec'))
    if not gemspec_candidates:
        return finish('SKIPPED (no gemspec in source)')
    source_gemspec = str(gemspec_candidates[0])
    lines.append(f'SOURCE_GEMSPEC: {shared.sanitize(source_gemspec)}')

    build_ok = False
    build_log_path = work / 'raw-build-output.txt'

    if sandbox == 'bwrap':
        bwrap_args = [
            'bwrap',
            '--ro-bind', str(clone_dir), '/src',
            '--bind', str(built_gem_dir), '/out',
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
        bwrap_args += ['gem', 'build', source_gemspec, '--output', '/out/']
        rc_b, b_out, b_err = shared.run_cmd(bwrap_args, timeout=300)
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    elif sandbox == 'firejail':
        rc_b, b_out, b_err = shared.run_cmd(
            ['firejail', '--quiet', '--net=none',
             f'--read-only={clone_dir}',
             'gem', 'build', source_gemspec, '--output', f'{built_gem_dir}/'],
            timeout=300,
        )
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    elif sandbox in ('docker', 'podman'):
        rc_rv2, rv2_out, _ = shared.run_cmd(['ruby', '-e', 'puts RUBY_VERSION'], timeout=5)
        ruby_img_tag = rv2_out.strip() if rc_rv2 == 0 else '3'
        parts = ruby_img_tag.split('.')
        ruby_img_tag = '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]

        rc_b, b_out, b_err = shared.run_cmd(
            [sandbox, 'run', '--rm',
             '--network', 'none',
             '-v', f'{clone_dir}:/src:ro',
             '-v', f'{built_gem_dir}:/out',
             f'ruby:{ruby_img_tag}',
             'sh', '-c',
             'git config --global --add safe.directory /tmp/src 2>/dev/null; '
             'cp -r /src /tmp/src && cd /tmp/src && '
             'gem build *.gemspec && '
             'cp *.gem /out/'],
            timeout=600,
        )
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    else:
        # No sandbox; run directly (lower assurance)
        rc_b, b_out, b_err = shared.run_cmd(
            ['gem', 'build', source_gemspec, '--output', f'{built_gem_dir}/'],
            cwd=clone_dir,
            timeout=300,
        )
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    lines.append(f'BUILD_STATUS: {"yes" if build_ok else "no"}')

    if not build_ok:
        return finish('INCONCLUSIVE (build failed)')

    built_gems = list(built_gem_dir.glob('*.gem'))
    if not built_gems:
        return finish('INCONCLUSIVE (no .gem produced)')
    built_gem = built_gems[0]

    def sha256_file(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    built_sha = sha256_file(built_gem)
    pkg_hash_file = work / 'package-hash.txt'
    dist_sha = ''
    if pkg_hash_file.is_file():
        first_line = pkg_hash_file.read_text(encoding='utf-8').splitlines()[0]
        dist_sha = first_line.split()[0] if first_line.split() else ''

    lines.append(f'BUILT_SHA256: {shared.sanitize(built_sha)}')
    lines.append(f'DISTRIBUTED_SHA256: {shared.sanitize(dist_sha or "UNKNOWN")}')

    if built_sha and built_sha == dist_sha:
        return finish('EXACTLY REPRODUCIBLE (sha256 match)')

    # Hashes differ; unpack and compare contents
    built_unpacked_parent = work / 'raw-built-unpacked'
    built_unpacked_parent.mkdir(exist_ok=True)
    shared.run_cmd(
        ['gem', 'unpack', str(built_gem), '--target', str(built_unpacked_parent)],
        timeout=60,
    )

    built_unpacked = built_unpacked_parent / f'{pkgname}-{version}'
    if not built_unpacked.is_dir():
        built_unpacked = built_unpacked_parent

    dist_unpacked = work / 'unpacked' / f'{pkgname}-{version}'
    if not dist_unpacked.is_dir():
        return finish('INCONCLUSIVE (hashes differ, no dist unpacked dir)')

    rc_diff, diff_out, _ = shared.run_cmd(
        ['diff', '-r', str(built_unpacked), str(dist_unpacked), '--exclude=*.gem'],
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
        if re.search(r'^diff.*\.(rb|c|h|java|py|js|sh)\b', line):
            code_diffs += 1
        if re.search(r'^diff.*(\.gemspec|metadata|RECORD|METADATA|Gemfile)', line):
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
