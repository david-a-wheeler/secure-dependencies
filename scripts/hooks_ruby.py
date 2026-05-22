#!/usr/bin/env python3
# hooks_ruby.py: Ruby language operations for the dependency analysis driver.
#
# Handles the Ruby gem format (download, unpack, gemspec, Rakefile) and the
# rubygems.org registry API. Used for --from rubygems; can be reused for other
# Ruby gem registries (Gemfury, GitHub Packages, etc.) with a different
# registry entry in REGISTRY_TO_HOOKS pointing here.
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

# Pre-compiled patterns for reproducible-build diff classification.
# Used in reproducible_build(); compiled once here to avoid repeated calls.
_RE_REPRO_CODE = re.compile(r'^diff.*\.(rb|c|h|cpp|rs|js|sh)\b')
_RE_REPRO_META = re.compile(r'^diff.*(\.gemspec|metadata|RECORD|METADATA|Gemfile)')

# VCS dependency detection (Idea 12 analog for Ruby).
# Gemfile.lock marks git-sourced gems with a "GIT" section; the "revision:"
# line contains the pinned commit hash. A raw commit hash is HIGH risk
# (unauditable pinned point); a branch-only reference is MEDIUM.
# _RE_GEMLOCK_REVISION uses shared.COMMIT_HASH_RE for the hex char range.
_RE_GEMLOCK_GIT_SECTION = re.compile(
    r'^GIT\n((?:[ \t][^\n]*\n)+)', re.MULTILINE,
)
_RE_GEMLOCK_REVISION = re.compile(
    r'^\s+revision:\s+(' + shared.COMMIT_HASH_RE + r')\s*$', re.MULTILINE,
)
_RE_GEMLOCK_REMOTE = re.compile(r'^\s+remote:\s+(\S+)', re.MULTILINE)
_RE_GEMLOCK_SPECS = re.compile(r'^\s{4}(\S+)\s+\(', re.MULTILINE)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_source_url(gemspec_text: str) -> str:
    """Extract source/homepage URL from gemspec text.

    Tries in priority order for source_code_uri, then homepage_uri:
      1. Hash-rocket metadata hash  ("source_code_uri" => "URL")
      2. Subscript assignment       (metadata['source_code_uri'] = 'URL')
      3. Top-level assignment       (s.source_code_uri = "URL")
    Then falls back to s.homepage = "URL".

    >>> _extract_source_url("s.metadata['source_code_uri'] = 'https://github.com/foo/bar'")
    'https://github.com/foo/bar'
    >>> _extract_source_url('"source_code_uri" => "https://github.com/foo/bar"')
    'https://github.com/foo/bar'
    >>> _extract_source_url('s.source_code_uri = "https://github.com/foo/bar"')
    'https://github.com/foo/bar'
    >>> _extract_source_url('s.homepage = "https://example.com"')
    'https://example.com'
    >>> _extract_source_url('no url here')
    ''
    """
    for key in ('source_code_uri', 'homepage_uri'):
        ek = re.escape(key)
        # Format 1: hash rocket  ("source_code_uri" => "URL")
        m = re.search(
            rf'["\']' + ek + r'["\']\s*=>\s*["\']([^"\']+)',
            gemspec_text)
        if m:
            return m.group(1).strip().rstrip('/')
        # Format 2: subscript assignment (metadata['source_code_uri'] = 'URL')
        m = re.search(
            r"metadata\[(['\"])" + ek + r"\1\]\s*=\s*['\"]([^'\"]+)",
            gemspec_text)
        if m:
            return m.group(2).strip().rstrip('/')
    # Format 3: top-level assignment
    # (s.source_code_uri = "URL" or s.homepage_uri = "URL")
    m = re.search(
        r'(?:source_code_uri|homepage_uri)\s*=\s*["\']([^"\']+)',
        gemspec_text)
    if m:
        return m.group(1).strip()
    # Last resort: s.homepage = "URL"
    m = re.search(r'homepage\s*=\s*["\']([^"\']+)', gemspec_text)
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
    lic_match = re.search(
        r'\.licenses?\s*=\s*\[?["\']([^"\']+)["\']', gemspec_text)
    return lic_match.group(1).strip() if lic_match else ''


# Size thresholds for Ruby install scripts, keyed by filename.
# extconf.rb: nokogiri is ~500 lines; > 1000 lines is extremely unusual.
# Rakefile: complex gems rarely exceed 300 install-related lines;
#   the whole Rakefile is checked, so 500 lines is the threshold.
# 'default' covers any other install-time file (Makefile.in, etc.).
_INSTALL_SCRIPT_WARN: dict[str, tuple[int, int]] = {
    'extconf.rb': (40_000, 1_000),
    'Rakefile':   (20_000,   500),
    'default':    (20_000,   500),
}


# ---------------------------------------------------------------------------
# Public API: called by dep_review.py
# ---------------------------------------------------------------------------

class Hooks(shared.EcosystemHooks):
    ECOSYSTEM = 'ruby'
    LOCKFILE_NAME = 'Gemfile.lock'
    OSV_ECOSYSTEM = 'RubyGems'
    OSS_REBUILD_ECOSYSTEM = 'rubygems'
    NATIVE_BINARY_SUFFIXES: frozenset[str] = frozenset({'.so', '.bundle'})

    # Name of the primary manifest file (copied to work dir during analysis).
    MANIFEST_FILE = 'gemspec.txt'

    # Human-readable summary of what DANGEROUS_PATTERNS scans for.
    DANGEROUS_WHAT = (
        'eval/exec variants, shell execution, obfuscated execution, '
        'Marshal.load, '
        'network at load scope, credential env-var access, home-dir writes, '
        'dynamic dispatch on external input, at_exit hooks, '
        'self-publish (worm propagation), IDE config writes, cloud secret-manager API calls, '
        'shadow runtimes (bun/deno/pkgx spawned from source), '
        'cross-language spawn (curl/wget/nc as second-stage loaders)'
    )

    # ReDoS prevention (CWE-400): all patterns use bounded quantifiers so that
    # worst-case PCRE backtracking is O(bound^2) rather than O(n^2) or worse.
    # Unbounded character-class repetitions ([^x]+, [^x]*) are capped with
    # {1,N} or {0,N}.  See AGENTS.md for the full policy.
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
         r'ENV\s*\[\s*["\x27][A-Z_]*(?:'
         + shared.CRED_KEYWORDS_RE + r'|BUNDLE_)[A-Z_]*["\x27]\s*\]'),
        # [^,]{1,200} rather than [^,]+ to cap backtracking when no quote
        # follows many non-comma characters (ReDoS: O(200^2) not O(n^2)).
        ('home-or-shell-write',
         r'(?:File\.(?:write|open|binwrite)|IO\.write)\s*[^,]{1,200}["\x27](?:'
         + shared.HOME_PATHS_RE + r')'),
        ('dynamic-dispatch',
         r'\b(?:__send__|public_send|send)\s*\(\s*(?:params|request|user_input|ENV|ARGV|gets)\b'),
        ('at-exit-hooks',      r'^\s*at_exit\b'),
        # Worm propagation: publishing to RubyGems from inside an install hook.
        ('self-publish',
         r'\bgem\s+push\b'),
        # Persistence: writing to IDE or AI-tool config directories.
        ('ide-config-write', shared.IDE_CONFIG_PATHS_RE),
        # Credential harvesting via cloud secret-manager SDKs or direct API calls.
        # Aws::SecretsManager is not caught by network-at-load-scope (which checks
        # Net::HTTP and similar, not the AWS SDK).
        # Shared provider hostnames come from shared.CLOUD_SECRET_HOSTS_RE.
        ('cloud-secret-api',
         r'\bAws::SecretsManager::Client\b'
         r'|\bAws::SSM::Client\b'
         r'|' + shared.CLOUD_SECRET_HOSTS_RE),
        # Bulk env-var serialization: harvest pattern that converts the entire
        # ENV hash to JSON or an Array of pairs.  ENV.to_h is excluded (very
        # common for subprocess env copies); ENV.to_a and JSON serialization
        # are the unambiguous bulk-collect forms.
        ('env-enumeration',
         r'JSON\.(?:dump|generate)\s*\(\s*ENV\b'
         r'|ENV\.to_a\b'),
        # Mini Shai-Hulud campaign: backdoor install path, LaunchAgent name,
        # and dead-man's-switch script. No legitimate use in package code.
        ('mini-shai-hulud-paths', shared.MINI_SHAI_HULUD_PATHS_RE),
        # Exfiltration relay services and known campaign C2 domains.
        ('exfil-relay-domain', shared.EXFIL_RELAY_DOMAINS_RE),
        # Shadow runtimes: system/exec/spawn invoking bun/deno/pkgx etc.
        # Extremely unusual in Ruby source; no legitimate published-gem use case.
        ('shadow-runtime',
         r'(?:system|exec|spawn|IO\.popen)\s*\([^)]{0,300}'
         r'\b' + shared.SHADOW_RUNTIME_NAMES_RE + r'\b'),
        # Cross-language spawn: Ruby invoking curl/wget/nc.
        # Ruby has Net::HTTP/Faraday; spawning curl/wget/nc is a strong
        # signal of a second-stage payload downloader.
        ('cross-lang-spawn',
         r'(?:system|exec|spawn|IO\.popen)\s*\([^)]{0,300}'
         r'\b' + shared.CROSS_LANG_TOOLS_RE + r'\b'),
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
         r'^\+[^\n]{0,500}(?:system|exec|spawn|popen|Open3)\s*\('),
        # [^"\x27]{6,200}: lower bound ensures a non-trivial value; upper bound
        # prevents O(n^2) backtracking when no closing quote follows.
        ('diff-hardcoded-secrets',
         r'^\+[^\n]{0,500}(?:password|passwd|secret|api_key|token)\s*=\s*["\x27][^"\x27]{6,200}["\x27]'),
        ('diff-eval',
         r'^\+[^\n]{0,500}(?:eval|instance_eval|class_eval|module_eval)\s*[\(\{]'),
    ]

    def get_lockfile_path(self, project_root: Path) -> Path:
        """Return the path to the Ruby lockfile (Gemfile.lock)."""
        return project_root / self.LOCKFILE_NAME

    def download_new(
        self,
        pkgname: str,
        version: str,
        work: Path,
        failures: list[str],
    ) -> dict:
        """gem fetch + gem unpack into work/unpacked/.

        Falls back to `gem specification` for gemspec if not present
        in the unpacked dir.
        Returns dict with keys: unpacked_dir (Path), sha256 (str),
        pkg_file (Path).
        """
        unpacked_dir_base = work / 'unpacked'
        unpacked_dir_base.mkdir(parents=True, exist_ok=True)

        gem_file = work / f'{pkgname}-{version}.gem'
        sha256 = ''

        # Options before '--'; pkgname after cannot be mistaken for a flag.
        # Defense-in-depth: _DEP_NAME_RE already prevents leading '-', but
        # explicit '--' is portable and works even if that check is bypassed.
        fetch_cmd = ['gem', 'fetch', '-v', version]
        if self.registry_url:
            fetch_cmd += ['--source', self.registry_url]
        fetch_cmd += ['--', pkgname]
        rc, _, err = shared.run_cmd(fetch_cmd, cwd=work)

        # gem fetch may download a platform-specific gem
        # (e.g. ffi-1.17.4-x86_64-linux-gnu.gem) instead of the generic name.
        # If the exact name is missing, find the actual file.
        if rc == 0 and not gem_file.is_file():
            candidates = sorted(work.glob(f'{pkgname}-{version}-*.gem'))
            if candidates:
                gem_file = candidates[0]

        if rc == 0 and gem_file.is_file():
            sha256 = shared.sha256_file(gem_file)
            (work / 'package-hash.txt').write_text(
                f'{sha256}  {gem_file.name}\n', encoding='utf-8'
            )
            rc2, _, _ = shared.run_cmd(
                ['gem', 'unpack', '--target', str(unpacked_dir_base),
                 '--', str(gem_file)]
            )
            if rc2 != 0:
                failures.append('gem-unpack-new')
        else:
            failures.append('gem-fetch-new')
            (work / 'package-hash.txt').write_text(
                'ERROR: gem fetch failed\n', encoding='utf-8')

        unpacked_dir = unpacked_dir_base / f'{pkgname}-{version}'
        # Platform-specific gems unpack to e.g. ffi-1.17.4-x86_64-linux-gnu/
        if not unpacked_dir.is_dir():
            candidates = sorted(
                unpacked_dir_base.glob(f'{pkgname}-{version}-*'))
            if candidates:
                unpacked_dir = candidates[0]

        # Remove symlinks gem unpack may have preserved from the archive.
        # Malicious gems can embed symlinks pointing to host paths outside
        # the package (e.g. /etc/passwd). remove_symlinks is called on
        # every ecosystem but is the primary defense here since gem unpack
        # is a system tool with no Python-level symlink filtering.
        if unpacked_dir.is_dir():
            _n = shared.remove_symlinks(unpacked_dir)
            if _n:
                # Symlinks in gem archives are a strong attack signal: legitimate
                # gems do not contain symlinks pointing outside the package tree.
                failures.append(
                    f'SECURITY_VIOLATION:symlinks-in-gem({_n} symlinks removed)'
                )

        # Fall back to `gem specification` for gemspec if not present
        # in the unpacked dir
        gemspec_file = unpacked_dir / f'{pkgname}.gemspec'
        if not gemspec_file.is_file() and gem_file.is_file():
            rc_spec, spec_out, _ = shared.run_cmd(
                ['gem', 'specification', '--ruby', '--', str(gem_file)]
            )
            if rc_spec == 0 and spec_out.strip():
                extracted = work / 'gemspec.txt'
                extracted.write_text(
                    spec_out, encoding='utf-8', errors='replace')

        return {
            'unpacked_dir': unpacked_dir,
            'sha256': sha256,
            'pkg_file': gem_file,
        }

    def read_manifest(
        self,
        pkgname: str,
        version: str,
        unpacked_dir: Path,
        work: Path,
        failures: list[str],
        p: 'shared.Printer',
    ) -> dict:
        """Parse gemspec; write manifest-analysis.txt and gemspec.txt.

        Returns dict with keys: source_url, extensions, executables,
        executables_list, post_install_msg, runtime_dep_lines,
        manifest_license_raw, manifest_text, manifest_extra_file,
        has_build_hooks, has_install_scripts, install_hook_context.
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
        install_cmd_warnings: list[str] = []

        # Locate gemspec: prefer in-package file, fall back to
        # extracted gemspec.txt
        gemspec_file = unpacked_dir / f'{pkgname}.gemspec'
        if not gemspec_file.is_file():
            extracted = work / 'gemspec.txt'
            if extracted.is_file():
                gemspec_file = extracted

        if gemspec_file.is_file():
            dest_gemspec = work / 'gemspec.txt'
            if gemspec_file != dest_gemspec:
                shutil.copy2(gemspec_file, dest_gemspec)
            gemspec_text = gemspec_file.read_text(
                encoding='utf-8', errors='replace')

            p(f'=== Manifest analysis: {pkgname} {version} ===')
            p('')

            if 'extensions' in gemspec_text:
                extensions = 'YES'
                p('HAS_EXTENSIONS: YES')
            else:
                p('HAS_EXTENSIONS: NO')

            exec_lines = [
                el for el in gemspec_text.splitlines()
                if 'executables' in el]
            if exec_lines:
                executables = 'YES'
                executables_list = shared.sanitize_line(
                    '; '.join(exec_lines[:3]))
                p('HAS_EXECUTABLES: YES')
                p(f'EXECUTABLES_LINES: {executables_list}')
            else:
                p('HAS_EXECUTABLES: NO')

            if 'post_install_message' in gemspec_text:
                post_install_msg = 'YES'
                p('HAS_POST_INSTALL_MESSAGE: YES')
            else:
                p('HAS_POST_INSTALL_MESSAGE: NO')

            p('')
            p('RUNTIME_DEPS:')
            dep_lines = [
                dl for dl in gemspec_text.splitlines()
                if 'add_runtime_dependency' in dl or
                   ('add_dependency' in dl and 'development' not in dl)
            ]
            if dep_lines:
                runtime_dep_lines = dep_lines
                for dl in dep_lines:
                    p(shared.sanitize_line(dl))
            else:
                p('  (none)')

            p('')
            p('DEV_DEPS:')
            dev_lines = [
                dl for dl in gemspec_text.splitlines()
                if 'add_development_dependency' in dl]
            if dev_lines:
                for dl in dev_lines:
                    p(shared.sanitize_line(dl))
            else:
                p('  (none)')

            hp_match = re.search(
                r'(?:homepage|source_code_uri|homepage_uri)\s*=\s*["\']([^"\']+)', gemspec_text
            )
            homepage_val = (
                shared.sanitize_line(hp_match.group(1))
                if hp_match else '(not found)')
            p('')
            p(f'HOMEPAGE: {homepage_val}')

            auth_match = re.search(r'authors?\s*=\s*([^\n]+)', gemspec_text)
            authors_val = (
                shared.sanitize_line(auth_match.group(1)[:200])
                if auth_match else '(not found)')
            p(f'AUTHORS: {authors_val}')

            gemspec_license_raw = _extract_gemspec_license(gemspec_text)
            p('')
            lic_decl = (
                shared.sanitize_line(gemspec_license_raw)
                or '(not declared)')
            p(f'LICENSE_DECLARED: {lic_decl}')

            p('')
            rakefile = unpacked_dir / 'Rakefile'
            if rakefile.is_file():
                p('RAKEFILE_PRESENT: YES')
                rake_text = rakefile.read_text(
                    encoding='utf-8', errors='replace')
                if re.search(r'(?i)install|post_install', rake_text):
                    has_rakefile_tasks = 'YES'
                    p('RAKEFILE_INSTALL_TASKS: YES')
                else:
                    p('RAKEFILE_INSTALL_TASKS: NO')
            else:
                p('RAKEFILE_PRESENT: NO')

            source_url = _extract_source_url(gemspec_text)

            # Collect install-time scripts for AI review when any
            # install-time code is present. These files run (or direct
            # code that runs) during gem install, so an AI reviewer
            # must read them.
            install_script_files: list[tuple[str, Path]] = []
            if extensions == 'YES':
                for name in ('extconf.rb', 'Makefile.in', 'Makefile'):
                    script_fp = unpacked_dir / name
                    if script_fp.is_file():
                        install_script_files.append((name, script_fp))
            if has_rakefile_tasks == 'YES' and rakefile.is_file():
                install_script_files.append(('Rakefile', rakefile))

            if install_script_files:
                script_lines: list[str] = [
                    '=== Install-time scripts for AI review ===',
                    '',
                    'These files execute (or direct code that executes)'
                    ' during gem install.',
                    'Review each one for malicious or unexpected behavior.',
                    '',
                ]
                for fname, fpath in install_script_files:
                    raw = fpath.read_text(encoding='utf-8', errors='replace')
                    warn_b, warn_l = _INSTALL_SCRIPT_WARN.get(
                        fname, _INSTALL_SCRIPT_WARN['default'])
                    _sz_warn = shared.report_install_script_size(
                        raw, fname, p, warn_b, warn_l)
                    if _sz_warn:
                        install_cmd_warnings.append(_sz_warn)
                    script_lines.append(f'--- {fname} ---')
                    script_lines.append(shared.sanitize_line(raw))
                    script_lines.append('')
                (work / 'install-scripts.txt').write_text(
                    '\n'.join(script_lines), encoding='utf-8'
                )
        else:
            failures.append('gemspec-missing')
            p('ERROR: gemspec not found')

        has_install_scripts = (work / 'install-scripts.txt').is_file()

        # Bundled IDE config directories (cross-ecosystem, #3).
        install_cmd_warnings.extend(
            shared.check_bundled_ide_dirs(unpacked_dir, p))

        # Build ecosystem-specific context for the driver's MANIFEST
        # / INSTALL HOOKS section
        install_hook_context: list[str] = []
        if extensions == 'YES':
            install_hook_context.extend([
                'Context: Compiled code runs during gem install.'
                ' The build process can execute',
                '  arbitrary code. Verify extconf.rb and Makefile'
                ' in the source are benign.',
            ])
        if has_rakefile_tasks == 'YES':
            install_hook_context.extend([
                'Context: Rakefile install tasks were found.'
                ' These execute during gem install.',
                '  Review install-scripts.txt for malicious'
                ' or unexpected behavior.',
            ])

        return {
            'source_url': source_url,
            'extensions': extensions,
            'executables': executables,
            'executables_list': executables_list,
            'post_install_msg': post_install_msg,
            'has_build_hooks': has_rakefile_tasks,
            'has_install_scripts': 'YES' if has_install_scripts else 'NO',
            'runtime_dep_lines': runtime_dep_lines,
            'manifest_license_raw': gemspec_license_raw,
            'manifest_text': gemspec_text,
            'manifest_extra_file': 'gemspec.txt',
            'install_hook_context': install_hook_context,
            'install_cmd_warnings': install_cmd_warnings,
        }

    def download_old(
        self,
        pkgname: str,
        old_ver: str,
        work: Path,
        failures: list[str],
    ) -> dict:
        """Download old version; check gem environment gemdir cache
        first, then gem fetch.

        Unpacks into work/old/.
        Returns dict with keys: ok (bool), source (str), unpacked_dir (Path).
        """
        old_dir_base = work / 'old'
        old_dir_base.mkdir(exist_ok=True)

        ok = False
        source = ''

        rc_gemdir, gemdir_out, _ = shared.run_cmd(
            ['gem', 'environment', 'gemdir'])
        gemdir = gemdir_out.strip() if rc_gemdir == 0 else ''
        cache_dir = Path(gemdir) / 'cache' if gemdir else None

        # Check local gem cache; platform-specific gems are named
        # e.g. ffi-1.17.3-x86_64-linux-gnu.gem
        old_cached_gem = None
        if cache_dir:
            exact = cache_dir / f'{pkgname}-{old_ver}.gem'
            if exact.is_file():
                old_cached_gem = exact
            else:
                candidates = sorted(
                    cache_dir.glob(f'{pkgname}-{old_ver}-*.gem'))
                if candidates:
                    old_cached_gem = candidates[0]

        if old_cached_gem and old_cached_gem.is_file():
            rc_up, _, _ = shared.run_cmd(
                ['gem', 'unpack', '--target', str(old_dir_base),
                 '--', str(old_cached_gem)]
            )
            if rc_up == 0:
                ok = True
                source = 'local-cache'
            else:
                failures.append('gem-unpack-old')
        else:
            raw_old_pkg = work / 'raw-old-pkg'
            raw_old_pkg.mkdir(exist_ok=True)
            fetch_cmd = ['gem', 'fetch', '-v', old_ver]
            if self.registry_url:
                fetch_cmd += ['--source', self.registry_url]
            fetch_cmd += ['--', pkgname]
            rc_fetch, _, _ = shared.run_cmd(fetch_cmd, cwd=raw_old_pkg)
            if rc_fetch == 0:
                old_gem = raw_old_pkg / f'{pkgname}-{old_ver}.gem'
                # Platform-specific gem may have a longer name
                if not old_gem.is_file():
                    candidates = sorted(
                        raw_old_pkg.glob(f'{pkgname}-{old_ver}-*.gem'))
                    if candidates:
                        old_gem = candidates[0]
                if old_gem.is_file():
                    rc_up2, _, _ = shared.run_cmd(
                        ['gem', 'unpack', '--target', str(old_dir_base),
                         '--', str(old_gem)]
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

        # Remove symlinks from whichever path populated old_dir_base.
        _n_old = shared.remove_symlinks(old_dir_base)
        if _n_old:
            failures.append(
                f'SECURITY_VIOLATION:symlinks-in-old-gem({_n_old} symlinks removed)'
            )
        (work / 'old-version-status.txt').write_text(
            f'OLD_VERSION_SOURCE: {source or "unavailable"}\n',
            encoding='utf-8'
        )

        unpacked_dir = old_dir_base / f'{pkgname}-{old_ver}'
        # Platform-specific gem unpacks to a directory
        # with the platform suffix
        if not unpacked_dir.is_dir():
            candidates = sorted(old_dir_base.glob(f'{pkgname}-{old_ver}-*'))
            if candidates:
                unpacked_dir = candidates[0]
        return {'ok': ok, 'source': source, 'unpacked_dir': unpacked_dir}

    def get_old_license(
        self,
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
        old_gs_text = old_gs_path.read_text(
            encoding='utf-8', errors='replace')
        return _extract_gemspec_license(old_gs_text) or None

    def get_old_dep_lines(
        self,
        pkgname: str,
        old_ver: str,
        old_result: dict,
    ) -> list[str]:
        """Extract runtime dependency lines from the old version's gemspec.

        Returns list of raw lines containing add_runtime_dependency
        or add_dependency.
        """
        if not old_result.get('ok'):
            return []
        old_unpacked_dir = old_result.get('unpacked_dir')
        if not old_unpacked_dir or not Path(old_unpacked_dir).is_dir():
            return []
        old_gs_path = Path(old_unpacked_dir) / f'{pkgname}.gemspec'
        if not old_gs_path.is_file():
            return []
        old_gs_text = old_gs_path.read_text(
            encoding='utf-8', errors='replace')
        return [
            l for l in old_gs_text.splitlines()
            if 'add_runtime_dependency' in l or
               ('add_dependency' in l and 'development' not in l)
        ]

    def fetch_all_registry_data(
        self,
        pkgname: str,
        version: str,
        work: Path,
        p: 'shared.Printer',
        source_url: str = '',
    ) -> dict:
        """Fetch RubyGems API: gems endpoint (MFA), versions endpoint
        (age/stability), owners. Also checks GitHub repo metadata for
        Shai-Halud campaign markers when source_url is a GitHub URL (Idea 16).

        self.registry_url overrides the default rubygems.org base URL
        for private registries. Most private gem servers (Gemfury,
        Gemstash) implement the same /api/v1/ paths.

        Writes: provenance.txt, raw-owners.json.
        Returns dict with keys: mfa_status, age_years_float,
        last_release_days, owner_count_int, version_stability,
        license_from_registry, ver_info_lines.
        """
        api_base = (
            self.registry_url.rstrip('/') if self.registry_url
            else 'https://rubygems.org')
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
        rc_gi, gi_out, _ = shared.run_cmd(['gem', 'info', '-r', '--', pkgname])
        p('GEM_INFO:')
        p(shared.sanitize(gi_out[:2000]) if rc_gi == 0 else '(unavailable)')
        p('')

        # Gems endpoint: MFA
        # RubyGems stores MFA status in
        # metadata.rubygems_mfa_required (a string "true"/"false")
        # rather than a top-level boolean field.
        api_gem_data = shared.http_get(
            f'{api_base}/api/v1/gems/{pkgname}.json')
        if api_gem_data:
            try:
                api_info = json.loads(
                    api_gem_data.decode('utf-8', errors='replace'))
                # Try top-level boolean first (older API format),
                # then metadata string
                mfa_val = api_info.get('mfa_required')
                if mfa_val is True:
                    mfa_status = 'true'
                elif mfa_val is False:
                    mfa_status = 'false'
                else:
                    meta_mfa = (
                        api_info.get('metadata', {})
                        .get('rubygems_mfa_required', ''))
                    if (isinstance(meta_mfa, str)
                            and meta_mfa.lower() == 'true'):
                        mfa_status = 'true'
                    elif (isinstance(meta_mfa, str)
                              and meta_mfa.lower() == 'false'):
                        mfa_status = 'false'
            except (ValueError, KeyError):
                pass
        p(f'MFA_REQUIRED: {shared.sanitize_line(mfa_status)}')
        p('')

        # Versions endpoint: age, stability, license
        ver_api_data_bytes = shared.http_get(
            f'{api_base}/api/v1/versions/{pkgname}.json')
        if ver_api_data_bytes:
            try:
                versions = json.loads(
                    ver_api_data_bytes.decode('utf-8', errors='replace'))
                if isinstance(versions, list) and versions:
                    oldest = versions[-1]
                    newest = versions[0]

                    first_date = str(oldest.get('created_at', ''))
                    age_days_val = shared.days_since(first_date)
                    if age_days_val is not None:
                        age_years_float = age_days_val / 365

                    latest_date = str(
                        newest.get('latest_version_created_at', '')
                        or newest.get('created_at', '')
                    )
                    last_release_days = shared.days_since(latest_date)

                    ver_num = str(newest.get('number', version))
                    if (re.search(r'(?i)(alpha|beta|rc|pre|dev)', ver_num)
                            or ver_num.startswith('0.')):
                        version_stability = 'pre-release'
                    else:
                        version_stability = 'stable'

                # Find this specific version's data
                target_ver_info = next(
                    (v for v in versions
                     if isinstance(v, dict) and v.get('number') == version),
                    None
                )
                if target_ver_info:
                    ver_created = str(target_ver_info.get('created_at', ''))
                    version_published_days = shared.days_since(ver_created)
                    ver_info_lines.append('VERSION_INFO (selected fields):')
                    for key in ('number', 'created_at', 'authors',
                                'sha', 'ruby_version',
                                'rubygems_version', 'licenses'):
                        val = target_ver_info.get(key, '')
                        val_str = shared.sanitize_line(str(val))[:200]
                        ver_info_lines.append(f'  {key}: {val_str}')
                    ver_pub_str = (str(version_published_days)
                                   if version_published_days is not None
                                   else 'unknown')
                    ver_info_lines.append(
                        f'  version_published_days_ago: {ver_pub_str}')
                    lic_field = target_ver_info.get('licenses')
                    if isinstance(lic_field, list):
                        license_from_registry.extend(
                            str(lc) for lc in lic_field if lc)
                    elif lic_field:
                        license_from_registry.append(str(lic_field))
            except (ValueError, KeyError, TypeError):
                ver_info_lines.append('VERSION_INFO: (parse error)')
        else:
            ver_info_lines.append('VERSION_INFO: (unavailable)')

        for vline in ver_info_lines:
            p(vline)

        # Owners endpoint
        owners_data = shared.http_get(
            f'{api_base}/api/v1/owners/{pkgname}.json')
        if owners_data:
            (work / 'raw-owners.json').write_bytes(owners_data)
            try:
                owners = json.loads(
                    owners_data.decode('utf-8', errors='replace'))
                if isinstance(owners, list):
                    owner_count_int = len(owners)
            except (ValueError, TypeError):
                pass

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
        """Parse Gemfile.lock; compare new vs old runtime deps.

        Returns dict with keys: added_deps, removed_deps, not_in_lockfile,
        and private keys _lockfile_lines, _dep_lines_new, _dep_lines_old used
        by write_dep_files() in the driver to write new-deps.txt and
        dep-lockfile-check.txt. Does not write any files itself.
        """
        (dep_lines_new, dep_lines_old,
         added_deps, removed_deps) = shared.compute_dep_diff(
            runtime_dep_lines, old_dep_lines
        )
        not_in_lockfile: list[str] = []

        lockfile = project_root / self.LOCKFILE_NAME
        lockfile_lines: list[str] = ['=== Lockfile check ===']
        if lockfile.is_file():
            lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
            lockfile_lines.append(
                f'LOCKFILE: {self.LOCKFILE_NAME} (format: bundler)')

            if dep_lines_new:
                for dep_line in dep_lines_new:
                    m_dep = re.search(
                        r"['\"]([a-z][a-z0-9_-]+)['\"]", dep_line)
                    if not m_dep:
                        continue
                    dep_name = m_dep.group(1)
                    safe_dep = shared.sanitize_line(dep_name)
                    if re.search(
                            rf'^    {re.escape(dep_name)} ',
                            lf_text, re.MULTILINE):
                        lockfile_lines.append(f'IN_LOCKFILE: {safe_dep}')
                    else:
                        lockfile_lines.append(f'NOT_IN_LOCKFILE: {safe_dep}')
                        not_in_lockfile.append(safe_dep)

            # VCS dependency check: GIT sections in Gemfile.lock mean deps
            # are resolved from VCS instead of RubyGems (Idea 12 analog).
            # Runs regardless of dep_lines_new.
            for _git_block in _RE_GEMLOCK_GIT_SECTION.finditer(lf_text):
                _block_text = _git_block.group(0)
                _remote_m = _RE_GEMLOCK_REMOTE.search(_block_text)
                _remote = (shared.sanitize_line(_remote_m.group(1)[:200])
                           if _remote_m else '(unknown)')
                _rev_m = _RE_GEMLOCK_REVISION.search(_block_text)
                _specs = [
                    shared.sanitize_line(m.group(1)[:80])
                    for m in _RE_GEMLOCK_SPECS.finditer(_block_text)
                ]
                _gems = ', '.join(_specs[:5]) if _specs else '(unknown)'
                if _rev_m:
                    _rev = shared.sanitize_line(_rev_m.group(1))
                    lockfile_lines.append(
                        f'[!] VCS_DEPENDENCY (commit hash): {_gems}'
                        f' from {_remote}@{_rev}')
                else:
                    lockfile_lines.append(
                        f'[!] VCS_DEPENDENCY (named ref): {_gems}'
                        f' from {_remote}')
        else:
            lockfile_lines.append('(lockfile or dep list unavailable)')

        # The driver calls write_dep_files() to write the actual output
        # files to work/. This function returns the data; writing is
        # deferred to the driver so that the work directory path
        # (which includes pkgname/version) is available.

        return {
            'added_deps': added_deps,
            'removed_deps': removed_deps,
            'not_in_lockfile': not_in_lockfile,
            '_lockfile_lines': lockfile_lines,
            '_dep_lines_new': dep_lines_new,
            '_dep_lines_old': dep_lines_old,
        }

    def check_dep_registry(self, dep_name: str) -> dict:
        """RubyGems API lookup for a dep not in lockfile.

        self.registry_url overrides the default rubygems.org base URL
        for private registries.
        Returns dict with keys: downloads, first_seen, homepage.
        """
        api_base = (
            self.registry_url.rstrip('/') if self.registry_url
            else 'https://rubygems.org')
        api_data = shared.http_get(f'{api_base}/api/v1/gems/{dep_name}.json')
        if api_data:
            try:
                info = json.loads(api_data.decode('utf-8', errors='replace'))
                downloads = info.get('downloads', 'unknown')
                created = info.get('created_at', 'unknown')
                homepage_v = info.get('homepage_uri', 'unknown')
                date_m = re.search(r'\d{4}-\d{2}-\d{2}', str(created))
                return {
                    'downloads': shared.sanitize_line(str(downloads))[:50],
                    'first_seen': shared.sanitize_line(
                        date_m.group() if date_m else 'unknown'),
                    'homepage': shared.sanitize_line(str(homepage_v))[:200],
                }
            except (ValueError, KeyError):
                pass
        return {
            'downloads': 'unavailable',
            'first_seen': 'unavailable',
            'homepage': 'unavailable',
        }

    def get_source_url_from_registry(self, pkgname: str) -> str:
        """Query RubyGems API for the source repository URL.

        Returns source_code_uri if it points to github.com; falls back to
        homepage_uri on the same condition.  Returns '' if neither is found
        or if the network call fails.  Called by dep_review.py as a fallback
        when the gemspec is unavailable (e.g. platform-specific gem fetch).

        >>> # integration: real network call, not tested in unit suite
        """
        api_base = (
            self.registry_url.rstrip('/') if self.registry_url
            else 'https://rubygems.org')
        api_data = shared.http_get(f'{api_base}/api/v1/gems/{pkgname}.json')
        if not api_data:
            return ''
        try:
            info = json.loads(api_data.decode('utf-8', errors='replace'))
            for key in ('source_code_uri', 'homepage_uri'):
                url = str(info.get(key, '') or '').strip().rstrip('/')
                if url and 'github.com' in url:
                    return url
        except (ValueError, KeyError):
            pass
        return ''

    def get_transitive_deps(
        self,
        pkgname: str,
        version: str,
        lockfile_path: Path,
        work: Path,
        p: 'shared.Printer',
    ) -> dict:
        """Run `gem dependency`; compare against lockfile.

        Writes: transitive-deps.txt (via p), raw-transitive-deps.txt.
        Returns dict with keys: total (int), not_in_lockfile (list[str]).
        """
        rc_dep, dep_out, _ = shared.run_cmd(
            ['gem', 'dependency', '-v', version, '--remote', '--pipe',
             '--', pkgname],
            timeout=60,
        )
        (work / 'raw-transitive-deps.txt').write_text(
            dep_out, encoding='utf-8', errors='replace')

        all_transitive: list[str] = []
        for line in dep_out.splitlines():
            m_dep = re.match(
                r"gem\s+['\"]([a-z][a-z0-9_-]+)['\"]", line.strip())
            if m_dep:
                dep_name = m_dep.group(1)
                if dep_name != pkgname:
                    all_transitive.append(dep_name)

        total = len(all_transitive)
        lf_text = ''
        if lockfile_path.is_file():
            lf_text = lockfile_path.read_text(
                encoding='utf-8', errors='replace')

        transitive_new: list[str] = []
        for dep_name in all_transitive:
            if not re.search(
                    rf'^    {re.escape(dep_name)} ',
                    lf_text, re.MULTILINE):
                transitive_new.append(dep_name)

        return shared.write_transitive_deps(
            work, pkgname, version, total, transitive_new, p)

    def check_alternatives(
        self,
        pkgname: str,
        version: str,
        work: Path,
        project_root: Path,
    ) -> dict:
        """Check for typosquat, slopsquat, and stdlib overlap signals.

        Three checks:
        A: Query 'gem list' for all installed/stdlib gems; flag exact
            matches and near-matches (edit distance <= 2). Because
            'gem list' includes default and bundled gems, this covers
            the stdlib without a hardcoded list.
        C: Read Gemfile.lock for the project's direct deps; flag near-matches.
            Catches attacks targeting this project's specific dependency set.
        D: Structural heuristics: hyphen/underscore normalization, and
            stripping common Ruby-specific name prefixes/suffixes
            (ruby-, -rb, etc.) to see if what remains matches an
            installed gem.

        # TODO (Option B): Add registry search for top packages by
        #   download count to catch typosquats of popular packages
        #   not yet installed locally.
        #   Would call rubygems.org/api/v1/search.json?query=PKGNAME
        #   and compare edit distance + download counts of top results.

        Writes: alternatives.txt to work dir.
        Returns dict with keys: concerns (list[str]), notes (list[str]),
          pkg_count (int), lockfile_count (int).
        """
        concerns: list[str] = []
        notes: list[str] = []

        # --- A: Query runtime for all installed/stdlib gems ---
        gem_names: list[str] = []
        rc, out, _ = shared.run_cmd(
            ['gem', 'list', '--no-versions'], timeout=30)
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
                    f'EXACT_STDLIB_MATCH: "{pkgname}" matches'
                    f' installed/stdlib gem "{gem}". '
                    'Installing an external gem with the same name'
                    ' as an already-available '
                    'gem is a strong slopsquat signal.'
                )
            else:
                dist = shared.levenshtein(pkg_lower, gem_lower)
                if dist == 1:
                    concerns.append(
                        f'NEAR_MATCH(dist=1): "{pkgname}" is one'
                        f' edit from installed gem "{gem}". '
                        'Classic typosquat pattern.'
                    )
                elif dist == 2:
                    notes.append(
                        f'NEAR_MATCH(dist=2): "{pkgname}" is two'
                        f' edits from installed gem "{gem}".'
                    )

        # --- C: Read Gemfile.lock for project-specific deps ---
        lockfile = project_root / 'Gemfile.lock'
        lockfile_names: list[str] = []
        if lockfile.is_file():
            in_specs = False
            for line in lockfile.read_text(
                    encoding='utf-8', errors='replace').splitlines():
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
                    f'EXACT_LOCKFILE_MATCH: "{pkgname}" matches'
                    f' existing lockfile dep "{dep}". '
                    'This name is already in use in this project.'
                )
            else:
                dist = shared.levenshtein(pkg_lower, dep_lower)
                if dist == 1:
                    concerns.append(
                        f'NEAR_LOCKFILE_MATCH(dist=1): "{pkgname}"'
                        f' is one edit from '
                        f'lockfile dep "{dep}". Possible targeted typosquat.'
                    )
                elif dist == 2:
                    notes.append(
                        f'NEAR_LOCKFILE_MATCH(dist=2): "{pkgname}"'
                        f' is two edits from lockfile dep "{dep}".'
                    )

        # --- D: Structural heuristics ---
        # D1: hyphen/underscore normalization (ruby gems use both conventions)
        normalized = pkg_lower.replace('-', '_')
        if normalized != pkg_lower:
            for gem in gem_names:
                if (gem.lower().replace('-', '_') == normalized
                        and gem.lower() != pkg_lower):
                    concerns.append(
                        f'NORMALIZATION_MATCH: "{pkgname}" normalizes'
                        f' to the same name as installed gem "{gem}"'
                        ' (hyphen/underscore difference).'
                        ' Could be a naming-convention confusion attack.'
                    )

        # D2: language prefix/suffix stripping
        # If stripping a Ruby-specific wrapper prefix/suffix reveals
        # an installed gem name, this package may be an unnecessary
        # (or malicious) wrapper around stdlib.
        strip_prefixes = ('ruby-', 'rb-', 'gem-')
        strip_suffixes = ('-rb', '-ruby', '-gem')
        all_known_lower = (
            {g.lower() for g in gem_names}
            | {d.lower() for d in lockfile_names})
        for prefix in strip_prefixes:
            if pkg_lower.startswith(prefix):
                base = pkg_lower[len(prefix):]
                if base in all_known_lower:
                    concerns.append(
                        f'PREFIX_SHADOW: "{pkgname}" appears to'
                        f' wrap installed gem "{base}"'
                        f' (stripped prefix "{prefix}").'
                        ' Verify this external wrapper is intentional.'
                    )
        for suffix in strip_suffixes:
            if pkg_lower.endswith(suffix):
                base = pkg_lower[: -len(suffix)]
                if base in all_known_lower:
                    concerns.append(
                        f'SUFFIX_SHADOW: "{pkgname}" appears to'
                        f' wrap installed gem "{base}"'
                        f' (stripped suffix "{suffix}").'
                        ' Verify this external wrapper is intentional.'
                    )

        with shared.Printer(work / 'alternatives.txt') as _p_alt:
            return shared.write_alternatives(
                _p_alt, pkgname, version,
                {
                    'Installed/stdlib gems checked': len(gem_names),
                    'Lockfile deps checked': len(lockfile_names),
                },
                concerns, notes,
            )

    def get_diff_excludes(self) -> list[str]:
        """Returns list of glob patterns to exclude from diff."""
        return ['*.gem']

    def get_pkg_src_excludes(self) -> tuple[re.Pattern, re.Pattern]:
        """Returns (pkg_excludes, src_excludes) compiled regex patterns.

        pkg_excludes: paths in the package to ignore during comparison (e.g.
          standard files always present in gems but not necessarily in
          the gem/
          subdirectory of a monorepo source).
        src_excludes: paths in the source clone to ignore.
        """
        # Gems always include a license file; in monorepos it lives at
        # the repo root, not inside the gem/ subdirectory, so exclude
        # it from the "extra" check.
        # Note: pattern is applied to relative paths WITHOUT a
        # leading "./" prefix.
        pkg_ex = re.compile(
            r'^\.git/'
            r'|^LICEN[SC]E(?:\.[a-zA-Z]+)?$'
            r'|^COPYING(?:\.[a-zA-Z]+)?$'
        )
        src_ex = re.compile(r'^\.git/')
        return pkg_ex, src_ex

    def find_source_root(self, source_dir: Path) -> Path:
        """Return the subdirectory of source_dir that contains the
        gem content.

        Some gem repos keep the gem in a ``gem/`` subdirectory
        (pagy, rails, etc.) rather than at the repo root. If a gemspec
        is found one level down, use that subdirectory; otherwise fall
        back to source_dir itself.
        """
        # Look for a direct subdirectory that contains a .gemspec file
        for candidate in source_dir.iterdir():
            if candidate.is_dir() and any(candidate.glob('*.gemspec')):
                return candidate
        return source_dir

    def get_deep_source_config(self) -> dict:
        """Returns deep source comparison config for Ruby."""
        return {'primary_label': 'Ruby', 'primary_pattern': r'\.(rb)$'}

    def reproducible_build(
        self,
        pkgname: str,
        version: str,
        work: Path,
        sandbox: str,
        p: 'shared.Printer',
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
        clone_dir = work / 'source'
        built_gem_dir = work / 'raw-built-gem'
        built_gem_dir.mkdir(exist_ok=True)

        p(f'=== Reproducible build: {pkgname} {version} ===')
        p(f'Sandbox: {sandbox}')
        p('')

        if not clone_dir.is_dir():
            return shared.finish_reproducible_build(
                p, work, 'SKIPPED (no source clone)')

        rc_rv, rv_out, _ = shared.run_cmd(['ruby', '--version'], timeout=10)
        ruby_ver = (
            shared.sanitize_line(rv_out.strip())
            if rc_rv == 0 else 'unknown')
        p(f'RUBY_VERSION: {ruby_ver}')

        gemspec_candidates = list(clone_dir.rglob('*.gemspec'))
        if not gemspec_candidates:
            return shared.finish_reproducible_build(
                p, work, 'SKIPPED (no gemspec in source)')
        source_gemspec = gemspec_candidates[0].relative_to(clone_dir)
        p(f'SOURCE_GEMSPEC: {shared.sanitize_line(str(source_gemspec))}')

        build_log_path = work / 'raw-build-output.txt'

        rc_rv2, rv2_out, _ = shared.run_cmd(
            ['ruby', '-e', 'puts RUBY_VERSION'], timeout=5)
        ruby_img_tag = rv2_out.strip() if rc_rv2 == 0 else '3'
        parts = ruby_img_tag.split('.')
        ruby_img_tag = '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]

        # Shell injection defense: two separate paths, neither uses
        # source_gemspec in a shell string.
        #   bwrap/firejail: cmd= list is exec'd directly (no shell), so a
        #     gemspec path like "$(evil).gemspec" is a literal filename
        #     argument to gem build, not a shell command.
        #   docker/podman: container_shell_cmd is a hardcoded string that
        #     uses "*.gemspec" (a shell glob), independent of the discovered
        #     filename entirely.
        build_result = shared.run_sandboxed(
            sandbox, clone_dir, built_gem_dir,
            '',  # shell_cmd unused for bwrap/firejail; cmd= used instead
            f'ruby:{ruby_img_tag}',
            cmd=['gem', 'build', '{src}/' + str(source_gemspec),
                 '--output', '{out}/'],
            container_shell_cmd=(
                'git config --global --add'
                ' safe.directory /tmp/src 2>/dev/null; '
                'cp -r {src} /tmp/src && cd /tmp/src && '
                'gem build *.gemspec && cp *.gem {out}/'
            ),
        )
        if build_result is None:
            return shared.finish_reproducible_build(
                p, work,
                'SKIPPED (no sandbox available:'
                ' install bwrap, firejail, docker, or podman)',
            )
        rc_b, combined = build_result
        build_log_path.write_text(
            combined, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

        p(f'BUILD_STATUS: {"yes" if build_ok else "no"}')

        if not build_ok:
            return shared.finish_reproducible_build(
                p, work, 'INCONCLUSIVE (build failed)')

        built_gems = list(built_gem_dir.glob('*.gem'))
        if not built_gems:
            return shared.finish_reproducible_build(
                p, work, 'INCONCLUSIVE (no .gem produced)')
        built_gem = built_gems[0]

        built_sha = shared.sha256_file(built_gem)
        repro = shared.compare_repro_sha256(built_sha, work, p)
        if repro is not None:
            return repro

        # Hashes differ; unpack and compare contents
        built_unpacked_parent = work / 'raw-built-unpacked'
        built_unpacked_parent.mkdir(exist_ok=True)
        shared.run_cmd(
            ['gem', 'unpack', str(built_gem),
             '--target', str(built_unpacked_parent)],
            timeout=60,
        )

        built_unpacked = built_unpacked_parent / f'{pkgname}-{version}'
        if not built_unpacked.is_dir():
            built_unpacked = built_unpacked_parent

        dist_unpacked = work / 'unpacked' / f'{pkgname}-{version}'
        if not dist_unpacked.is_dir():
            return shared.finish_reproducible_build(
                p, work,
                'INCONCLUSIVE (hashes differ, no dist unpacked dir)')

        rc_diff, diff_out, _ = shared.run_cmd(
            ['diff', '-r', str(built_unpacked), str(dist_unpacked),
             '--exclude=*.gem'],
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
