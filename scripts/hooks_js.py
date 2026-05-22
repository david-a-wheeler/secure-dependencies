#!/usr/bin/env python3
# hooks_js.py: JavaScript/Node.js language operations for the
# dependency analysis driver.
#
# Handles the npm package format (download with npm pack, unpack tarball) and
# the npm registry API. Used for --from npm; can be reused for other
# npm-compatible registries (GitHub Packages, Verdaccio, Nexus,
# Artifactory, etc.)
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
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
import analysis_shared as shared

# Pre-compiled patterns for reproducible-build diff classification.
_RE_REPRO_CODE = re.compile(r'^diff.*\.(js|mjs|cjs|ts|jsx|tsx)\b')
_RE_REPRO_META = re.compile(
    r'^diff.*(package\.json|package-lock\.json|\.npmignore|\.gitignore)')

# VCS dependency detection (Idea 12 for JS).
# Matches dep specs that pull directly from a VCS host instead of the registry.
# Composed from shared.VCS_SCHEMES_RE so coverage stays in sync with other
# ecosystems when new VCS transports or hosting aliases are added there.
_RE_GIT_DEP = re.compile(
    r'^(?:github:|gitlab:|bitbucket:|' + shared.VCS_SCHEMES_RE + r')',
    re.IGNORECASE,
)
# Commit hash: 7-40 hex chars after '#' fragment in a VCS URL.
# Uses shared.COMMIT_HASH_RE so the range stays in sync with Python/Ruby.
_RE_COMMIT_HASH = re.compile(
    r'#' + shared.COMMIT_HASH_RE + r'$', re.IGNORECASE)

# VCS/lockfile foreign URL detection (Ideas 12-13 for JS).
# _RE_GIT_DEP uses shared.VCS_SCHEMES_RE and shared.VCS_HOSTNAMES_RE.
# _RE_LOCKFILE_RESOLVED matches "resolved" fields in package-lock.json;
# foreign hosts (not in _TRUSTED_REGISTRY_HOSTS or self.registry_url) are
# flagged as LOCKFILE_FOREIGN_URL -- the same signal used by Python/Ruby.
_RE_LOCKFILE_RESOLVED = re.compile(
    r'"resolved"\s*:\s*"(https?://[^"]{1,300})"'
)
_TRUSTED_REGISTRY_HOSTS: frozenset[str] = frozenset({
    'registry.npmjs.org',
    'registry.yarnpkg.com',
})

# npm package name allowlist: letters, digits, '.', '-', '_', '/', '@'.
# Scoped names start with '@' (e.g. @scope/name). Max 214 chars (npm spec).
# Rejects names containing ';', '$', backticks, spaces, '..', or other
# shell-special characters before they reach LLM-visible command strings.
_NPM_NAME_RE = re.compile(r'^[@A-Za-z0-9][A-Za-z0-9._/-]{0,213}$')

# Install-script command checks: applied against the preinstall/install/
# postinstall command strings from package.json (not against JS source files).
# Each entry is (signal_name, compiled_pattern).
# ReDoS prevention: all patterns use anchored word boundaries or bounded
# character classes; no nested unbounded quantifiers.
_INSTALL_CMD_CHECKS: list[tuple[str, re.Pattern[str]]] = [
    # Shai-Halud pattern: bootstrap a secondary JS runtime to evade npm policy.
    # bun/deno/pkgx are rarely legitimate in install hooks; high suspicion.
    # bunx is Bun's npx equivalent and equally suspicious here.
    ('INSTALL_BOOTSTRAP_RUNTIME', re.compile(
        r'\b(?:bun|deno|pkgx)\s+(?:run\s+)?[\w./]{1,120}\.(?:js|ts|mjs|cjs)\b'
        r'|\bbunx\s+[\w@/-]{1,120}\b'
        r'|\bsetup_bun\.js\b'
        r'|\bbun_environment\.js\b',
        re.IGNORECASE,
    )),
    # ts-node/tsx are common TypeScript runners used in legitimate build scripts
    # (e.g. ts-node scripts/build.ts), so they get a separate lower-urgency
    # signal rather than being grouped with bun/deno above.
    ('INSTALL_TSRUNNER_IN_HOOK', re.compile(
        r'\b(?:tsx|ts-node)\s+(?:run\s+)?[\w./]{1,120}\.(?:ts|mjs|cjs)\b',
        re.IGNORECASE,
    )),
    # Worm propagation: publish other packages during install.
    # Near-zero false-positive rate; rare legitimate cases (monorepo tooling)
    # warrant human confirmation rather than auto-rejection.
    # Known false positive: a string like 'echo run npm publish to release'
    # will match because the pattern fires on the substring, not a shell parse.
    # Practical risk is low since install scripts rarely echo publishing docs.
    ('INSTALL_SELF_PUBLISH', re.compile(
        r'\bnpm\s+(?:publish|unpublish|deprecate)\b'
        r'|\b(?:pnpm|yarn)\s+publish\b'
        r'|\bnpm\s+(?:token|adduser)\b'
        r'|\bnpm\s+set\s+registry\b',
        re.IGNORECASE,
    )),
    # Persistence: write to IDE or AI-tool config directories.
    ('INSTALL_IDE_CONFIG_WRITE', re.compile(
        r'(?:\.vscode|\.idea|\.claude|\.cursor)[/\\]'
        r'(?:tasks|settings|extensions|launch)\.json\b'
        r'|\.config[/\\](?:claude|copilot|cursor|codeium)[/\\]',
        re.IGNORECASE,
    )),
    # Persistence: write to shell startup files.
    # Require a write operator (>> or tee) to avoid false positives from
    # packages that echo instructions like 'Add this to your ~/.bashrc'.
    ('INSTALL_SHELL_CONFIG_WRITE', re.compile(
        r'>>\s*(?:~|\$\{?HOME\}?)[^\n]{0,60}\.(?:bashrc|zshrc|profile|bash_profile)\b'
        r'|\btee\s+(?:-a\s+)?(?:~|\$\{?HOME\}?)[^\n]{0,60}\.(?:bashrc|zshrc|profile|bash_profile)\b',
        re.IGNORECASE,
    )),
    # Dead-man's-switch: destructive wipe commands.
    ('INSTALL_DESTRUCTIVE_WIPE', re.compile(
        r'\bdel\s+/[FQS]'
        r'|\brm\s+-[rf]{1,3}\s+(?:[~/]|\$\{?HOME\}?)'
        r'|\bshred\s+-[uvzn]{1,6}'
        r'|\bcipher\s+/W:'
        r'|\bdd\s+if=/dev/zero\s+of=',
        re.IGNORECASE,
    )),
    # Credential harvesting via CLI tools (not env var reads).
    # Note: detecting "gh auth token" in package source does NOT require
    # the gh CLI to be installed on the reviewer's machine; we are scanning
    # the malicious package's code, not invoking gh ourselves.
    ('INSTALL_CREDENTIAL_CLI', re.compile(
        r'\bgh\s+auth\s+(?:token|status)\b'
        r'|\bgit\s+config\s+--get\b[^\n]{0,80}credential'
        r'|\bnpm\s+token\s+(?:list|create)\b'
        r'|\baws\s+configure\s+(?:get|list)\b'
        r'|\bgcloud\s+auth\s+print-access-token\b'
        r'|\baz\s+account\s+get-access-token\b'
        r'|\bcat\s+[^\n]{0,40}\.npmrc\b'
        r'|\bcat\s+[^\n]{0,40}\.netrc\b',
        re.IGNORECASE,
    )),
    # Credential harvesting via direct cloud secret-manager API calls.
    ('INSTALL_CLOUD_SECRET_API', re.compile(
        r'secretsmanager\.[a-z0-9-]{1,50}\.amazonaws\.com'
        r'|ssm\.[a-z0-9-]{1,50}\.amazonaws\.com'
        r'|secretmanager\.googleapis\.com'
        r'|kms\.[a-z0-9-]{1,50}\.amazonaws\.com'
        r'|vault\.azure\.net',
        re.IGNORECASE,
    )),
]

# Size thresholds for install hook command strings (combined preinstall +
# install + postinstall). Inline hook commands in package.json are almost
# always a short shell invocation; 10 KB or 50 lines is extremely unusual
# even for the most complex legitimate packages.
_INSTALL_HOOK_WARN_BYTES = 10_000
_INSTALL_HOOK_WARN_LINES = 50


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
    """Load and parse package.json from the unpacked directory.

    Returns {} on failure.
    """
    pkg_json_path = unpacked_dir / 'package.json'
    if not pkg_json_path.is_file():
        return {}
    try:
        return json.loads(
            pkg_json_path.read_text(encoding='utf-8', errors='replace'))
    except (ValueError, OSError):
        return {}


def _unpack_tgz(
    tgz_file: Path, target_dir: Path,
    failures: list[str], key: str,
) -> bool:
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
            shared.tarfile_extractall_safe(tf, target_dir, members)
        # Belt-and-suspenders: tarfile_extractall_safe already filters
        # symlinks at the member level; this catches any edge cases.
        shared.remove_symlinks(target_dir)
        return True
    except shared.ArchiveSecurityError as exc:
        # An ArchiveSecurityError is a strong indicator of a malicious package:
        # legitimate npm packages do not contain tar bombs or traversal payloads.
        failures.append(f'SECURITY_VIOLATION:{key}: {exc}')
        return False
    except Exception as exc:
        failures.append(f'{key}: {exc}')
        return False


# ---------------------------------------------------------------------------
# Idea 14-16 helpers: registry and provenance API checks
# ---------------------------------------------------------------------------



def _slsa_signer_repo(attest: dict) -> tuple[str, str]:
    """Extract (signer_repo_url, workflow_path) from one SLSA attestation.

    Handles two provenance predicate formats:
      SLSA v1  (predicateType .../provenance/v1):
        predicate.buildDefinition.externalParameters.workflow.{repository,path}
      SLSA v0.2 (predicateType .../provenance/v0.2):
        predicate.materials[0].uri  (git+https://github.com/owner/repo@ref)
    Returns ('', '') when no usable URI is found.
    """
    predicate = attest.get('predicate', {}) or {}

    # SLSA v1 path
    workflow = (
        predicate
        .get('buildDefinition', {})
        .get('externalParameters', {})
        .get('workflow', {})
    )
    if isinstance(workflow, dict):
        repo = str(workflow.get('repository', '') or '')
        if repo:
            return repo, str(workflow.get('path', '') or '')

    # SLSA v0.2 path: materials[0].uri contains "git+https://...@ref"
    materials = predicate.get('materials', []) or []
    if materials and isinstance(materials[0], dict):
        uri = str(materials[0].get('uri', '') or '')
        if uri.startswith('git+'):
            # Strip git+ prefix and @ref suffix to get bare repo URL.
            repo = re.sub(r'^git\+', '', uri)
            repo = re.sub(r'@[^@]{0,200}$', '', repo)
            if repo:
                return repo, ''

    return '', ''


def _norm_repo_url(url: str) -> str:
    """Normalise a source/signer repo URL for comparison.

    Strips scheme prefix, git+ transport prefix, .git suffix, and trailing
    slash, then lowercases. Two URLs that differ only in these ways refer
    to the same repo.
    """
    url = re.sub(r'^git\+', '', url.strip().lower().rstrip('/'))
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^ssh://git@', '', url)
    url = re.sub(r'^git@([^:]+):', r'\1/', url)
    url = re.sub(r'\.git$', '', url)
    return url


def _check_slsa_provenance(
    api_base: str, encoded_name: str, source_url: str, p: 'shared.Printer',
) -> None:
    """Idea 15: compare SLSA provenance signer repo against declared source.

    Fetches the npm provenance attestation and checks whether the signing
    repository matches the package's declared source URL. A mismatch
    is the Shai-Halud OIDC-token-theft signature (the signature appears
    cryptographically valid but was produced by a different repo's workflow).
    """
    p('')
    p('=== SLSA provenance ===')
    prov_url = f'{api_base}/-/package/{encoded_name}/provenance'
    prov_data = shared.http_get(prov_url)
    if not prov_data:
        p('SLSA_PROVENANCE: none (package not published with --provenance)')
        return
    try:
        prov_json = json.loads(prov_data.decode('utf-8', errors='replace'))
    except ValueError:
        p('SLSA_PROVENANCE: parse error')
        return

    attestations = prov_json.get('attestations', []) or []
    if not attestations:
        p('SLSA_PROVENANCE: none (no attestations in registry response)')
        return

    signer_repo, workflow_path = '', ''
    for attest in attestations:
        signer_repo, workflow_path = _slsa_signer_repo(attest)
        if signer_repo:
            break

    if not signer_repo:
        p('SLSA_PROVENANCE: present but signer repository URI not found')
        return

    p(f'SLSA_SIGNER_REPO: {shared.sanitize_line(signer_repo[:300])}')
    if workflow_path:
        p(f'SLSA_WORKFLOW_PATH: {shared.sanitize_line(workflow_path[:200])}')

    if not source_url:
        p('SIGSTORE_REPO_MISMATCH: N/A (no declared source URL to compare)')
        return

    if _norm_repo_url(signer_repo) != _norm_repo_url(source_url):
        p('SIGSTORE_REPO_MISMATCH: YES')
        p(f'  declared: {shared.sanitize_line(source_url[:300])}')
        p(f'  signer:   {shared.sanitize_line(signer_repo[:300])}')
        p('  NOTE: surface for human review; monorepos may sign from a')
        p('  parent repo. A mismatch combined with other signals is HIGH.')
    else:
        p('SIGSTORE_REPO_MISMATCH: NO')


# npm username allowlist: letters, digits, hyphens, underscores, dots.
# Used before constructing search API URLs (command-injection prevention).
_RE_NPM_USER = re.compile(r'^[A-Za-z0-9._-]{1,80}$')
# 72 hours in seconds; packages published more recently than this count
# toward the velocity total.
_VELOCITY_WINDOW_SECS = 72 * 3600
# Packages published within 72 hours by a single user to qualify as anomalous.
_VELOCITY_THRESHOLD = 10
# Publisher tenure in days below which they are considered a "new" publisher.
_NEW_PUBLISHER_DAYS = 90


def _parse_npm_date(date_str: str) -> 'datetime | None':
    """Parse an ISO-8601 date string (with or without trailing Z/offset).

    Returns a timezone-aware datetime or None on failure.
    """
    try:
        clean = date_str.rstrip('Z').split('+')[0].split('.')[0]
        return datetime.fromisoformat(clean).replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def _check_publisher_velocity(
    api_base: str,
    npm_user_name: str,
    p: 'shared.Printer',
) -> None:
    """Idea 14: detect anomalous publish velocity for this package's publisher.

    Queries the npm search API for all packages maintained by the publisher,
    counts those published in the last 72 hours, and emits
    PUBLISHER_VELOCITY_ANOMALOUS if the count exceeds the threshold.

    Severity is HIGH when the publisher is also new (their oldest maintained
    package is less than _NEW_PUBLISHER_DAYS days old); MEDIUM otherwise.
    This uses the oldest package date from the search results as a proxy for
    publisher tenure, since npm does not expose direct account creation dates.
    """
    if not npm_user_name or not _RE_NPM_USER.match(npm_user_name):
        return
    if 'registry.npmjs.org' not in api_base:
        return

    p('')
    p(f'=== Publisher velocity: {shared.sanitize_line(npm_user_name)} ===')

    search_url = (
        'https://registry.npmjs.org/-/v1/search'
        f'?text=maintainer:{urllib.parse.quote(npm_user_name, safe="")}'
        '&size=250'
    )
    search_data = shared.http_get(search_url, timeout=20)
    if not search_data:
        p('PUBLISHER_VELOCITY: (search API unavailable)')
        return

    try:
        search_json = json.loads(search_data.decode('utf-8', errors='replace'))
    except ValueError:
        p('PUBLISHER_VELOCITY: (parse error)')
        return

    now = datetime.now(timezone.utc)
    recent_count = 0
    oldest_dt: 'datetime | None' = None
    objects = search_json.get('objects', []) or []
    for obj in objects:
        pkg = obj.get('package', {}) or {}
        date_str = str(pkg.get('date', '') or '')
        if not date_str:
            continue
        pub_dt = _parse_npm_date(date_str)
        if pub_dt is None:
            continue
        age_secs = (now - pub_dt).total_seconds()
        if 0 <= age_secs <= _VELOCITY_WINDOW_SECS:
            recent_count += 1
        if oldest_dt is None or pub_dt < oldest_dt:
            oldest_dt = pub_dt

    total_count = len(objects)
    p(f'PUBLISHER_TOTAL_PACKAGES: {total_count}')
    p(f'PUBLISHER_RECENT_72H: {recent_count}')

    if recent_count >= _VELOCITY_THRESHOLD:
        tenure_days = (
            int((now - oldest_dt).total_seconds() / 86400)
            if oldest_dt else None
        )
        is_new = tenure_days is not None and tenure_days < _NEW_PUBLISHER_DAYS
        severity = 'HIGH' if is_new else 'MEDIUM'
        p(f'PUBLISHER_VELOCITY_ANOMALOUS: YES ({severity})')
        p(f'  {recent_count} packages published in last 72h '
          f'(threshold: {_VELOCITY_THRESHOLD})')
        if is_new:
            p(f'  Publisher tenure: {tenure_days} days '
              f'(<{_NEW_PUBLISHER_DAYS} days; new publisher + high velocity = HIGH)')
        elif tenure_days is not None:
            p(f'  Publisher tenure: {tenure_days} days '
              f'(consider: may be a high-volume CI pipeline such as a monorepo)')
    else:
        p('PUBLISHER_VELOCITY_ANOMALOUS: NO')


# ---------------------------------------------------------------------------
# Public API: called by dep_review.py
# ---------------------------------------------------------------------------

class Hooks(shared.EcosystemHooks):
    ECOSYSTEM = 'javascript'
    OSV_ECOSYSTEM = 'npm'
    OSS_REBUILD_ECOSYSTEM = 'npm'
    NATIVE_BINARY_SUFFIXES: frozenset[str] = frozenset({'.node'})

    # Multiple lockfile formats; LOCKFILE_NAME is None so the driver skips the
    # single-lockfile warning. LOCKFILE_NAMES lists candidates in
    # priority order.
    LOCKFILE_NAME: str | None = None
    LOCKFILE_NAMES: list[str] = [
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
    ]

    MANIFEST_FILE = 'package-json.txt'

    DANGEROUS_WHAT = (
        'eval/new Function/vm execution, child_process execution, '
        'obfuscated execution (Buffer.from base64+eval, hex decode+eval), '
        'network calls at module load scope, credential env-var access '
        '(AWS/GitHub/cloud keys at load time), '
        'dynamic require on external input, '
        'prototype pollution '
        '(Object.prototype assignment, __proto__ assignment), '
        'home-dir writes, IDE config writes, cloud secret-manager API calls, '
        'shadow runtimes (bun/deno/pkgx spawned from source), '
        'cross-language spawn (python/curl/wget/nc as second-stage loaders)'
    )

    # ReDoS prevention (CWE-400): all patterns use bounded quantifiers so that
    # worst-case PCRE backtracking is O(bound^2) rather than O(n^2) or worse.
    # Unbounded character-class repetitions ([^x]+, [^x]*) are capped with
    # {1,N} or {0,N}.  See AGENTS.md for the full policy.
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
        # NPM_TOKEN is covered by NPM_ + [A-Z_]* from CRED_KEYWORDS_RE.
        ('credential-env-vars',
         r'process\.env\s*(?:\.\s*|\[\s*["\x27])(?:'
         + shared.CRED_KEYWORDS_RE + r'|HEROKU_|VERCEL_|NETLIFY_)[A-Z_]*'),
        ('dynamic-require',
         r'\brequire\s*\(\s*(?:process\.env\.|[^"\'`\)]{0,80}'
         r'(?:user|input|argv|env|request))'),
        # [^\]]{1,200} rather than [^\]]+ to cap backtracking when no closing
        # quote is found (ReDoS: O(200^2) worst case, not O(n^2)).
        ('prototype-pollution',
         r'Object\.prototype\s*\[["\x27][^\]]{1,200}["\x27]\s*='
         r'|__proto__\s*[=:]\s*\{'),
        ('module-load-socket',
         r'^\s*new\s+(?:net\.Socket|tls\.TLSSocket|dgram\.Socket)\s*\('),
        # Persistence: writing to home-dir or shell-config paths.
        # fs.open() is included because callers often follow with a write.
        ('home-or-shell-write',
         r'fs\.(?:writeFile(?:Sync)?|appendFile(?:Sync)?|open(?:Sync)?)\s*\([^,)]{0,100}["\x27](?:'
         + shared.HOME_PATHS_RE + r')'),
        # Persistence: writing to IDE or AI-tool config directories.
        ('ide-config-write', shared.IDE_CONFIG_PATHS_RE),
        # Credential harvesting via cloud secret-manager SDKs or direct API calls.
        # AWS SDK v3 require() calls are not caught by network-at-load-scope.
        # Shared provider hostnames come from shared.CLOUD_SECRET_HOSTS_RE.
        ('cloud-secret-api',
         r'require\s*\(\s*["\x27]@aws-sdk/client-secrets-manager["\x27]'
         r'|require\s*\(\s*["\x27]@aws-sdk/client-ssm["\x27]'
         r'|new\s+SecretsManagerClient\s*\('
         r'|new\s+SSMClient\s*\('
         r'|require\s*\(\s*["\x27]@google-cloud/secret-manager["\x27]'
         r'|require\s*\(\s*["\x27]@azure/keyvault-secrets["\x27]'
         r'|' + shared.CLOUD_SECRET_HOSTS_RE),
        # Bulk env-var collection: harvest pattern that serializes or iterates
        # all of process.env at once.  The existing credential-env-vars pattern
        # catches named prefixes; this catches the bulk-collect variant worms
        # use to avoid known-prefix detection.  \w{1,40} bounds the loop var.
        ('env-enumeration',
         r'(?:JSON\.stringify|Object\.(?:keys|values|entries|assign|fromEntries))'
         r'\s*\(\s*process\.env\s*\)'
         r'|for\s*\(\s*(?:const|let|var)\s+\w{1,40}\s+(?:in|of)\s+process\.env\s*\)'),
        # Mini Shai-Hulud campaign: backdoor install path, LaunchAgent name,
        # and dead-man's-switch script. No legitimate use in package code.
        ('mini-shai-hulud-paths', shared.MINI_SHAI_HULUD_PATHS_RE),
        # Exfiltration relay services and known campaign C2 domains.
        # Shared domain list from analysis_shared; no ecosystem-specific additions.
        ('exfil-relay-domain', shared.EXFIL_RELAY_DOMAINS_RE),
        # Shadow runtimes: exec/spawn invoking bun/deno/pkgx/tsx/ts-node.
        # These are covered in install hooks by _INSTALL_CMD_CHECKS; this
        # pattern catches the same runtimes in broader source-file scans.
        # [^)]{0,300} bounds backtracking to O(300) per anchor (safe).
        ('shadow-runtime',
         r'(?:exec(?:Sync|File(?:Sync)?)?|spawn(?:Sync)?)\s*\([^)]{0,300}'
         r'\b' + shared.SHADOW_RUNTIME_NAMES_RE + r'\b'),
        # Cross-language spawn: JS invoking python/curl/wget/nc.
        # A JS package that spawns these tools is almost certainly a second-stage
        # payload downloader or data exfiltration step.
        ('cross-lang-spawn',
         r'(?:exec(?:Sync|File(?:Sync)?)?|spawn(?:Sync)?)\s*\([^)]{0,300}'
         r'\b' + shared.CROSS_LANG_TOOLS_RE + r'\b'),
    ]

    # ReDoS prevention: diff lines start with ^\+ so they are anchored, but
    # .* before a keyword still causes O(n^2) backtracking on long lines such
    # as minified JS (the whole file may be a single line).  [^\n]{0,500}
    # caps worst-case to O(500^2).  Two .* on the same pattern (keyword.*suffix)
    # compounds to O(n^2) even for moderate line lengths; bounding both fixes it.
    DIFF_PATTERNS: list[tuple[str, str]] = [
        ('diff-eval',
         r'^\+[^\n]{0,500}\beval\s*\(|^\+[^\n]{0,500}new\s+Function\s*\('),
        ('diff-cmd-injection',
         r'^\+[^\n]{0,500}child_process\.(?:exec|spawn|execSync|spawnSync)\s*\('),
        # [^"\x27]{6,200}: lower bound ensures it is a non-trivial value;
        # upper bound prevents O(n^2) backtracking when no closing quote follows.
        ('diff-hardcoded-secrets',
         r'^\+[^\n]{0,500}(?:password|passwd|secret|api_key|token|apikey)'
         r'\s*[=:]\s*["\x27][^"\x27]{6,200}["\x27]'),
        ('diff-network-load',
         r'^\+\s*require\s*\(\s*["\x27](?:http|https)["\x27]\s*\)'
         r'\.(?:get|request)\s*\('),
        ('diff-prototype-pollution',
         r'^\+[^\n]{0,500}__proto__\s*[=:]\s*\{|^\+[^\n]{0,500}Object\.prototype\s*\['),
    ]

    def get_lockfile_path(self, project_root: Path) -> Path:
        """Return the path to the first existing JavaScript lockfile.

        Tries package-lock.json, yarn.lock, pnpm-lock.yaml,
        bun.lockb in order.
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
        """npm pack PKGNAME@VERSION into work/, then unpack into
        work/unpacked/.

        Uses npm pack which downloads the tarball without executing
        any install scripts or lifecycle hooks. Returns dict with
        keys: unpacked_dir (Path), sha256 (str), pkg_file (Path | None).
        """
        unpacked_dir = work / 'unpacked'
        unpacked_dir.mkdir(parents=True, exist_ok=True)

        # Options before '--'; package spec after cannot be mistaken for a flag.
        pack_cmd = ['npm', 'pack', '--pack-destination', str(work)]
        if self.registry_url:
            pack_cmd += ['--registry', self.registry_url]
        pack_cmd += ['--', f'{pkgname}@{version}']

        rc, _out, err = shared.run_cmd(pack_cmd, cwd=work, timeout=180)
        tgz_file: Path | None = None
        sha256 = ''

        if rc == 0:
            tgz_candidates = list(work.glob('*.tgz'))
            if tgz_candidates:
                tgz_file = max(
                    tgz_candidates, key=lambda p: p.stat().st_mtime)
                sha256 = shared.sha256_file(tgz_file)
                (work / 'package-hash.txt').write_text(
                    f'{sha256}  {tgz_file.name}\n', encoding='utf-8'
                )
                if not _unpack_tgz(
                        tgz_file, unpacked_dir, failures, 'unpack-new'):
                    failures.append('unpack-new-failed')
            else:
                failures.append('npm-pack-no-tgz')
                (work / 'package-hash.txt').write_text(
                    'ERROR: no .tgz produced\n', encoding='utf-8')
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
        p: 'shared.Printer',
    ) -> dict:
        """Parse package.json from the unpacked tarball; write
        manifest-analysis.txt.

        Returns dict with keys: source_url, extensions, executables,
        executables_list, post_install_msg, has_build_hooks,
        has_install_scripts, runtime_dep_lines, manifest_license_raw,
        manifest_text, manifest_extra_file, install_hook_context,
        install_cmd_warnings.
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
        install_cmd_warnings: list[str] = []

        p(f'=== Manifest analysis: {pkgname} {version} ===')
        p('')
        pkg_json: dict = {}

        if unpacked_dir.is_dir():
            pkg_json = _load_package_json(unpacked_dir)

        if pkg_json:
            manifest_text = json.dumps(pkg_json, indent=2, ensure_ascii=False)
            (work / 'package-json.txt').write_text(
                manifest_text, encoding='utf-8', errors='replace')

            # Native addons: binding.gyp present, or install script
            # calls node-gyp/prebuild-install
            binding_gyp = (unpacked_dir / 'binding.gyp').is_file()
            scripts = pkg_json.get('scripts', {}) or {}
            preinstall_val = str(scripts.get('preinstall', '') or '').strip()
            install_val = str(scripts.get('install', '') or '').strip()
            postinstall_val = str(
                scripts.get('postinstall', '') or '').strip()

            is_native = binding_gyp or bool(
                re.search(r'node-gyp\s+rebuild|prebuild-install', install_val)
            )
            if is_native:
                extensions = 'YES'
                p('HAS_EXTENSIONS: YES (native addon)')
            else:
                p('HAS_EXTENSIONS: NO')

            # Executables (bin field)
            bin_field = pkg_json.get('bin', None)
            if bin_field:
                executables = 'YES'
                if isinstance(bin_field, dict):
                    executables_list = shared.sanitize_line(
                        ', '.join(list(bin_field.keys())[:10]))
                elif isinstance(bin_field, str):
                    executables_list = shared.sanitize_line(bin_field)
                p('HAS_EXECUTABLES: YES')
                p(f'EXECUTABLES: {executables_list}')
            else:
                p('HAS_EXECUTABLES: NO')

            # Lifecycle scripts: preinstall, install, postinstall
            install_script_content: list[tuple[str, str]] = []
            if preinstall_val:
                has_build_hooks = 'YES'
                p('HAS_PREINSTALL: YES')
                p(f'  preinstall: '
                  f'{shared.sanitize_line(preinstall_val[:300])}')
                install_script_content.append(('preinstall', preinstall_val))
                post_install_msg = 'YES'
            if install_val and not is_native:
                has_build_hooks = 'YES'
                p('HAS_INSTALL_SCRIPT: YES')
                p(f'  install: {shared.sanitize_line(install_val[:300])}')
                install_script_content.append(('install', install_val))
            elif is_native and install_val:
                p(f'NATIVE_INSTALL_SCRIPT: '
                  f'{shared.sanitize_line(install_val[:300])}')
            if postinstall_val:
                has_build_hooks = 'YES'
                p('HAS_POSTINSTALL: YES')
                p(f'  postinstall: '
                  f'{shared.sanitize_line(postinstall_val[:300])}')
                install_script_content.append(
                    ('postinstall', postinstall_val))
                post_install_msg = 'YES'
            if not (preinstall_val or install_val or postinstall_val):
                p('HAS_BUILD_HOOKS: NO')

            # Install-command security checks: scan lifecycle script command
            # strings for attack patterns.  Each signal fires at most once even
            # if the pattern matches in more than one hook.
            _install_hooks = [
                ('preinstall', preinstall_val),
                ('install', install_val),
                ('postinstall', postinstall_val),
            ]
            for _sig_name, _pat in _INSTALL_CMD_CHECKS:
                for _hook_name, _hook_val in _install_hooks:
                    if _hook_val and _pat.search(_hook_val):
                        _short = shared.sanitize_line(_hook_val[:120])
                        p(f'[!] {_sig_name}: detected in {_hook_name}: {_short}')
                        install_hook_context.append(
                            f'CRITICAL: {_sig_name} detected in {_hook_name} '
                            f'script ({_short}). Supply chain attack indicator.'
                        )
                        install_cmd_warnings.append(
                            f'{_sig_name}:{_hook_name}')
                        break  # report each signal once only

            # Install hook size check (combined inline hook content).
            # Inline hook strings > 10 KB or > 50 lines are extremely unusual;
            # attackers sometimes embed base64-encoded payloads directly here.
            _hook_combined = '\n'.join(
                v for _, v in install_script_content if v)
            if _hook_combined:
                _size_warn = shared.report_install_script_size(
                    _hook_combined, 'install hooks (combined)',
                    p, _INSTALL_HOOK_WARN_BYTES, _INSTALL_HOOK_WARN_LINES,
                )
                if _size_warn:
                    install_cmd_warnings.append(_size_warn)
                    install_hook_context.append(
                        f'CRITICAL: {_size_warn.split(":", 1)[1]}'
                        ' install hook content is unusually large.'
                        ' Review for embedded payloads.'
                    )

            # Runtime dependencies
            p('')
            p('RUNTIME_DEPS:')
            deps = pkg_json.get('dependencies', {}) or {}
            opt_deps = pkg_json.get('optionalDependencies', {}) or {}
            all_runtime = dict(deps)
            all_runtime.update(opt_deps)
            if all_runtime:
                for dep_name, dep_range in list(all_runtime.items())[:50]:
                    dep_line = f'{dep_name}@{dep_range}'
                    runtime_dep_lines.append(dep_line)
                    p(f'  {shared.sanitize_line(dep_line)}')
                if len(all_runtime) > 50:
                    p(f'  ... and {len(all_runtime) - 50} more')
            else:
                p('  (none)')

            # Git-reference dependency check: deps resolved from VCS refs
            # bypass the registry entirely. Separate by severity: raw commit
            # hashes are HIGH (unauditable pinned point); named refs MEDIUM.
            _git_hash_deps: list[str] = []
            _git_named_deps: list[str] = []
            for _dep_name, _dep_spec in all_runtime.items():
                if not isinstance(_dep_spec, str):
                    continue
                if _RE_GIT_DEP.match(_dep_spec):
                    _safe = shared.sanitize_line(
                        f'{_dep_name}@{_dep_spec}'[:200])
                    if _RE_COMMIT_HASH.search(_dep_spec):
                        _git_hash_deps.append(_safe)
                    else:
                        _git_named_deps.append(_safe)
            for _s in _git_hash_deps:
                p(f'[!] VCS_DEPENDENCY (commit hash): {_s}')
            for _s in _git_named_deps:
                p(f'[!] VCS_DEPENDENCY (named ref): {_s}')
            if _git_hash_deps:
                install_cmd_warnings.append(
                    'VCS_DEPENDENCY:package.json (commit hash)')
            if _git_named_deps:
                install_cmd_warnings.append(
                    'VCS_DEPENDENCY:package.json (named ref)')

            source_url = _extract_source_url(pkg_json)
            hp_display = (
                shared.sanitize_line(source_url) if source_url
                else '(not found)')
            p('')
            p(f'HOMEPAGE: {hp_display}')

            author = pkg_json.get('author', '') or ''
            if isinstance(author, dict):
                author = author.get('name', '') or ''
            p(f'AUTHOR: {shared.sanitize_line(str(author)[:200])}')

            manifest_license_raw = _extract_license(pkg_json)
            p('')
            lic_str = (
                shared.sanitize_line(manifest_license_raw)
                or '(not declared)')
            p(f'LICENSE_DECLARED: {lic_str}')

            desc = str(pkg_json.get('description', '') or '')[:300]
            if desc:
                p(f'DESCRIPTION: {shared.sanitize_line(desc)}')

            main_field = (
                pkg_json.get('main', '') or pkg_json.get('exports', ''))
            if main_field:
                main_str = (
                    str(main_field)
                    if not isinstance(main_field, dict)
                    else '(exports map)')
                p(f'MAIN: {shared.sanitize_line(main_str[:200])}')

            p('')

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
                    script_lines.append(shared.sanitize_line(hook_val))
                    script_lines.append('')
                (work / 'install-scripts.txt').write_text(
                    '\n'.join(script_lines), encoding='utf-8'
                )

            if preinstall_val:
                install_hook_context.append(
                    'Context: preinstall script present. This runs '
                    'BEFORE the package is '
                    'installed and can execute arbitrary code. '
                    'Review install-scripts.txt carefully.'
                )
            if postinstall_val:
                install_hook_context.append(
                    'Context: postinstall script is present. '
                    'This is the most common attack '
                    'vector for npm supply-chain attacks. '
                    'Review install-scripts.txt carefully.'
                )
            if is_native and not (preinstall_val or postinstall_val):
                install_hook_context.append(
                    'Context: native addon (binding.gyp). '
                    'The install script compiles C/C++ '
                    'at install time. This is expected for '
                    'native addons (node-gyp rebuild).'
                )

        else:
            failures.append('package-json-missing')
            p('ERROR: package.json not found in unpacked directory')

        has_install_scripts = (work / 'install-scripts.txt').is_file()

        # Bundled IDE config directories (cross-ecosystem, #3).
        install_cmd_warnings.extend(
            shared.check_bundled_ide_dirs(unpacked_dir, p))

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
            'install_cmd_warnings': install_cmd_warnings,
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

        pack_cmd = ['npm', 'pack', '--pack-destination', str(raw_old)]
        if self.registry_url:
            pack_cmd += ['--registry', self.registry_url]
        pack_cmd += ['--', f'{pkgname}@{old_ver}']

        rc, _, _ = shared.run_cmd(pack_cmd, cwd=raw_old, timeout=180)
        ok = False
        source = ''

        if rc == 0:
            tgz_candidates = list(raw_old.glob('*.tgz'))
            if tgz_candidates:
                tgz_file = max(
                    tgz_candidates, key=lambda p: p.stat().st_mtime)
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
            f'OLD_VERSION_SOURCE: {source or "unavailable"}\n',
            encoding='utf-8',
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
        """Extract runtime dependency lines from the old version's
        package.json."""
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
        p: 'shared.Printer',
        source_url: str = '',
    ) -> dict:
        """Fetch npm registry API: full package metadata and
        version-specific data.

        Endpoint: registry.npmjs.org/{pkgname} (full doc) and
                  registry.npmjs.org/{pkgname}/{version} (version-specific).
        Also checks:
          - GitHub repo metadata for Shai-Halud campaign markers (Idea 16).
          - npm provenance API for SLSA signer/repo mismatch (Idea 15).
          - npm search API for publisher velocity anomaly (Idea 14).

        Writes: provenance.txt (via p).
        Returns dict with keys: mfa_status, age_years_float,
        last_release_days, owner_count_int, version_stability,
        license_from_registry, ver_info_lines.
        """
        api_base = (
            self.registry_url.rstrip('/')
            if self.registry_url
            else 'https://registry.npmjs.org'
        )
        # npm has no per-package MFA status via registry API
        mfa_status = 'unknown'
        age_years_float: float | None = None
        last_release_days: int | None = None
        version_published_days: int | None = None
        owner_count_int: int | None = None
        version_stability = 'unknown'
        license_from_registry: list[str] = []
        ver_info_lines: list[str] = []
        npm_user_name: str = ''   # publisher of this specific version (Idea 14)

        p(f'=== Provenance: {pkgname} {version} ===')
        p('')

        # Scoped packages (@scope/name) must be percent-encoded in the URL
        encoded_name = urllib.parse.quote(pkgname, safe='')

        # Full package document: maintainers, time history, versions object
        pkg_data = shared.http_get(f'{api_base}/{encoded_name}')
        if pkg_data:
            try:
                pkg_json = json.loads(
                    pkg_data.decode('utf-8', errors='replace'))
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
                    last_release_days = shared.days_since(
                        max(ver_times.values()))
                ver_ts = ver_times.get(version)
                if ver_ts:
                    version_published_days = shared.days_since(ver_ts)

                if (re.search(
                        r'(?i)(alpha|beta|rc|pre|dev|canary|next)',
                        version)
                        or version.startswith('0.')):
                    version_stability = 'pre-release'
                else:
                    version_stability = 'stable'

                maintainers = pkg_json.get('maintainers', []) or []
                if isinstance(maintainers, list):
                    owner_count_int = len(maintainers)
                    maint_names = [
                        shared.sanitize_line(
                            m.get('name', '')
                            if isinstance(m, dict) else str(m)
                        )[:80]
                        for m in maintainers[:20]
                    ]
                    p(f'MAINTAINER_COUNT: {owner_count_int}')
                    p(f'MAINTAINERS: {", ".join(maint_names)}')
                    p('')

                # License from the specific version's entry in the
                # versions object
                versions_obj = pkg_json.get('versions', {}) or {}
                target_ver = versions_obj.get(version, {}) or {}
                lic = target_ver.get('license', '') or ''
                if isinstance(lic, dict):
                    lic = lic.get('type', '') or ''
                if lic and str(lic).upper() not in ('', 'UNKNOWN'):
                    license_from_registry.append(str(lic))

                deprecated = target_ver.get('deprecated', '') or ''
                if deprecated:
                    p('DEPRECATED: YES')
                    p(f'DEPRECATED_REASON: '
                      f'{shared.sanitize_line(str(deprecated)[:300])}')
                    p('')
                else:
                    p('DEPRECATED: NO')
                    p('')

                ver_pub_str = (str(version_published_days)
                               if version_published_days is not None
                               else 'unknown')
                p(f'VERSION_PUBLISHED_DAYS_AGO: {ver_pub_str}')
                p('')

            except (ValueError, KeyError, TypeError):
                p('REGISTRY_DATA: parse error')

        # Version-specific endpoint: dist.integrity, dist.tarball,
        # Sigstore signatures
        ver_data = shared.http_get(f'{api_base}/{encoded_name}/{version}')
        if ver_data:
            try:
                ver_json = json.loads(
                    ver_data.decode('utf-8', errors='replace'))
                ver_info_lines.append('VERSION_INFO (selected fields):')
                dist = ver_json.get('dist', {}) or {}
                npm_user_raw = ver_json.get('_npmUser', '')
                if isinstance(npm_user_raw, dict):
                    npm_user_name = str(npm_user_raw.get('name', ''))
                elif isinstance(npm_user_raw, str):
                    npm_user_name = npm_user_raw
                for key in ('version', '_npmUser', 'gitHead'):
                    val = ver_json.get(key, '')
                    if val:
                        ver_info_lines.append(
                            f'  {key}: '
                            f'{shared.sanitize_line(str(val))[:200]}')
                for dist_key in (
                        'integrity', 'shasum', 'tarball',
                        'fileCount', 'unpackedSize'):
                    val = dist.get(dist_key, '')
                    if val:
                        ver_info_lines.append(
                            f'  dist.{dist_key}: '
                            f'{shared.sanitize_line(str(val))[:200]}')
                sigs = dist.get('signatures', [])
                if sigs:
                    ver_info_lines.append(
                        f'  dist.signatures: {len(sigs)}'
                        f' signature(s) present (Sigstore)'
                    )
                else:
                    ver_info_lines.append(
                        '  dist.signatures: none (not signed with Sigstore)')
            except (ValueError, KeyError, TypeError):
                ver_info_lines.append('VERSION_INFO: (parse error)')
        else:
            ver_info_lines.append('VERSION_INFO: (unavailable)')

        p('NOTE: npm does not expose per-package MFA status '
          'via the registry API.')
        p('      MFA_REQUIRED is always "unknown" for npm packages.')
        p('      Check dist.signatures above for Sigstore '
          'provenance attestation.')
        p('')
        for vline in ver_info_lines:
            p(vline)

        # Idea 16: GitHub repo campaign marker (cross-ecosystem shared helper).
        shared.emit_github_repo_meta(source_url, p)

        # Idea 15: SLSA provenance signer/repo mismatch (JS only).
        # npm exposes provenance attestations without external tooling.
        _check_slsa_provenance(api_base, encoded_name, source_url, p)

        # Idea 14: Publisher velocity anomaly (JS only).
        # A publisher who pushed many packages in the last 72 hours is a
        # strong account-takeover or worm indicator.
        _check_publisher_velocity(api_base, npm_user_name, p)

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

        Supports package-lock.json (npm v2/v3), yarn.lock (v1 and v2+/Berry),
        and pnpm-lock.yaml. Returns dict with keys: added_deps, removed_deps,
        not_in_lockfile, and private keys _lockfile_lines, _dep_lines_new,
        _dep_lines_old used by write_dep_files() in the driver.
        """
        (dep_lines_new, dep_lines_old,
         added_deps, removed_deps) = shared.compute_dep_diff(
            runtime_dep_lines, old_dep_lines
        )
        not_in_lockfile: list[str] = []

        lockfile = self.get_lockfile_path(project_root)
        lockfile_lines: list[str] = ['=== Lockfile check ===']

        if lockfile.is_file():
            lf_text = lockfile.read_text(encoding='utf-8', errors='replace')
            lockfile_format = self._detect_lockfile_format(lockfile.name)
            lockfile_lines.append(
                f'LOCKFILE: {lockfile.name} (format: {lockfile_format})')

            if dep_lines_new:
                for dep_line in dep_lines_new:
                    # Extract name from "pkgname@^version"
                    # or "@scope/name@version"
                    m = re.match(r'^(@[^@]+|[^@]+)@', dep_line.strip())
                    dep_name = m.group(1) if m else dep_line.strip()
                    if not dep_name or not _NPM_NAME_RE.match(dep_name):
                        continue
                    safe_dep = shared.sanitize_line(dep_name)
                    if self._dep_in_lockfile(dep_name, lf_text, lockfile_format):
                        lockfile_lines.append(f'IN_LOCKFILE: {safe_dep}')
                    else:
                        lockfile_lines.append(f'NOT_IN_LOCKFILE: {safe_dep}')
                        not_in_lockfile.append(safe_dep)

            # Foreign resolved URL check (npm format only).
            # package-lock.json v2/v3 "resolved" fields should all point to
            # the npm registry (or the configured private registry); any other
            # host is a potential supply-chain injection.
            # Deduplicated and capped to avoid noise.
            if lockfile_format == 'npm':
                _trusted = set(_TRUSTED_REGISTRY_HOSTS)
                if self.registry_url:
                    _rh = urllib.parse.urlparse(
                        self.registry_url).netloc.lower()
                    if _rh:
                        _trusted.add(_rh)
                _foreign_urls: list[str] = []
                _seen_foreign: set[str] = set()
                for _m in _RE_LOCKFILE_RESOLVED.finditer(lf_text):
                    _url = _m.group(1)
                    _is_trusted = any(f'//{h}/' in _url for h in _trusted)
                    if not _is_trusted and _url not in _seen_foreign:
                        _seen_foreign.add(_url)
                        _foreign_urls.append(_url)
                for _furl in _foreign_urls[:10]:
                    lockfile_lines.append(
                        f'[!] LOCKFILE_FOREIGN_URL: '
                        f'{shared.sanitize_line(_furl[:200])}')
                if len(_foreign_urls) > 10:
                    lockfile_lines.append(
                        f'  ... and {len(_foreign_urls) - 10} more'
                        f' foreign resolved URLs')
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

    def _dep_in_lockfile(
        self, dep_name: str, lf_text: str, fmt: str,
    ) -> bool:
        """Return True if dep_name appears in the lockfile for
        the given format."""
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
            self.registry_url.rstrip('/')
            if self.registry_url
            else 'https://registry.npmjs.org'
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
                    'first_seen': shared.sanitize_line(
                        date_m.group() if date_m else 'unknown'),
                    'homepage': shared.sanitize_line(str(homepage))[:200],
                }
            except (ValueError, KeyError, TypeError):
                pass
        return {
            'downloads': 'unavailable',
            'first_seen': 'unavailable',
            'homepage': 'unavailable',
        }

    def get_transitive_deps(
        self,
        pkgname: str,
        version: str,
        lockfile_path: Path,
        work: Path,
        p: 'shared.Printer',
    ) -> dict:
        """Fetch direct runtime deps from the npm registry; compare
        against lockfile.

        Uses the registry API to get the package's dependencies object.
        Like the Python hook, this shows direct (level-1) deps only; full
        transitive closure would require recursive API calls.

        Writes: transitive-deps.txt, raw-transitive-deps.txt.
        Returns dict with keys: total (int), not_in_lockfile (list[str]).
        """
        api_base = (
            self.registry_url.rstrip('/')
            if self.registry_url
            else 'https://registry.npmjs.org'
        )
        encoded = urllib.parse.quote(pkgname, safe='')
        deps: list[str] = []
        raw_lines: list[str] = []

        ver_data = shared.http_get(f'{api_base}/{encoded}/{version}')
        if ver_data:
            try:
                ver_json = json.loads(
                    ver_data.decode('utf-8', errors='replace'))
                all_deps = dict(ver_json.get('dependencies', {}) or {})
                all_deps.update(
                    ver_json.get('optionalDependencies', {}) or {})
                for dep_name, dep_range in all_deps.items():
                    if (not isinstance(dep_name, str)
                            or not _NPM_NAME_RE.match(dep_name)):
                        raw_lines.append(
                            f'REJECTED: '
                            f'{shared.sanitize_line(str(dep_name)[:200])}')
                        continue
                    deps.append(dep_name)
                    raw_lines.append(f'{dep_name}@{dep_range}')
            except (ValueError, KeyError, TypeError):
                pass

        (work / 'raw-transitive-deps.txt').write_text(
            '\n'.join(raw_lines), encoding='utf-8')

        total = len(deps)
        lf_text = ''
        lf_format = 'unknown'
        if lockfile_path.is_file():
            lf_text = lockfile_path.read_text(
                encoding='utf-8', errors='replace')
            lf_format = self._detect_lockfile_format(lockfile_path.name)

        transitive_new: list[str] = []
        for dep_name in deps:
            if not self._dep_in_lockfile(dep_name, lf_text, lf_format):
                transitive_new.append(dep_name)

        return shared.write_transitive_deps(
            work, pkgname, version, total, transitive_new, p,
            total_label='TOTAL_DIRECT_DEPS',
            note=(
                'shows direct (level-1) runtime deps '
                'from the npm registry only.'),
        )

    def check_alternatives(
        self,
        pkgname: str,
        version: str,
        work: Path,
        project_root: Path,
    ) -> dict:
        """Check for typosquat, slopsquat, and Node.js built-in
        overlap signals.

        Three checks:
        A: Node.js built-in module names; flag exact matches
           (dependency confusion) and near-matches (typosquat).
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
        bare_name = (
            pkg_lower.lstrip('@').split('/')[-1]
            if '/' in pkg_lower else pkg_lower)

        # --- A: Node.js built-in module names ---
        builtin_names = self._get_node_builtin_names()
        builtin_lower = {m.lower() for m in builtin_names}

        for mod in builtin_names:
            mod_lower = mod.lower()
            if mod_lower == bare_name or mod_lower == pkg_lower:
                concerns.append(
                    f'EXACT_BUILTIN_MATCH: "{pkgname}" matches '
                    f'Node.js built-in "{mod}". '
                    'Installing an external package with the same '
                    'name as a built-in is a '
                    'strong dependency-confusion signal: '
                    'the built-in will shadow the '
                    'external package in most Node.js contexts.'
                )
            else:
                dist = shared.levenshtein(bare_name, mod_lower)
                if dist == 1:
                    concerns.append(
                        f'NEAR_MATCH(dist=1): "{pkgname}" is one edit'
                        f' from built-in "{mod}". '
                        'Classic typosquat pattern.'
                    )
                elif dist == 2:
                    notes.append(
                        f'NEAR_MATCH(dist=2): "{pkgname}" is two edits'
                        f' from built-in "{mod}".'
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
                for m in re.finditer(
                        r'^["\s]*([A-Za-z@][A-Za-z0-9@._/-]*)@',
                        lf_text, re.MULTILINE):
                    lockfile_names.append(m.group(1).strip('"'))
            elif lf_fmt == 'pnpm':
                for m in re.finditer(
                        r'^\s+/?([A-Za-z@][A-Za-z0-9@._/-]*)[@/]',
                        lf_text, re.MULTILINE):
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
            dep_bare = (
                dep_lower.lstrip('@').split('/')[-1]
                if '/' in dep_lower else dep_lower)
            if dep_lower in builtin_lower or dep_bare in builtin_lower:
                continue  # already checked in A
            if dep_lower == pkg_lower or dep_bare == bare_name:
                concerns.append(
                    f'EXACT_LOCKFILE_MATCH: "{pkgname}" matches '
                    f'existing lockfile dep "{dep}". '
                    'This name is already in use in this project.'
                )
            else:
                dist = shared.levenshtein(bare_name, dep_bare)
                if dist == 1:
                    concerns.append(
                        f'NEAR_LOCKFILE_MATCH(dist=1): "{pkgname}" is'
                        f' one edit from '
                        f'lockfile dep "{dep}". Possible targeted typosquat.'
                    )
                elif dist == 2:
                    notes.append(
                        f'NEAR_LOCKFILE_MATCH(dist=2): "{pkgname}" is'
                        f' two edits from '
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
                    f'SCOPE_SHADOW: "{pkgname}" bare name "{bare}" '
                    'matches an existing '
                    'package or built-in. A scoped package '
                    'wrapping an unscoped one may '
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
                        f'PREFIX_SHADOW: "{pkgname}" appears to wrap '
                        f'existing module/package '
                        f'"{base}" (stripped prefix "{prefix}"). '
                        'Verify this external wrapper is intentional.'
                    )
        for suffix in strip_suffixes:
            if bare_name.endswith(suffix):
                base = bare_name[: -len(suffix)]
                if base in all_known_bare:
                    concerns.append(
                        f'SUFFIX_SHADOW: "{pkgname}" appears to wrap '
                        f'existing module/package '
                        f'"{base}" (stripped suffix "{suffix}"). '
                        'Verify this external wrapper is intentional.'
                    )

        with shared.Printer(work / 'alternatives.txt') as _p_alt:
            return shared.write_alternatives(
                _p_alt, pkgname, version,
                {
                    'Node.js built-ins checked': len(builtin_names),
                    'Lockfile deps checked': len(lockfile_names),
                },
                concerns, notes,
            )

    def _get_node_builtin_names(self) -> list[str]:
        """Return a list of Node.js built-in module names
        (without 'node:' prefix).

        These are available without installation in any Node.js project.
        """
        return [
            'assert', 'async_hooks', 'buffer', 'child_process', 'cluster',
            'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel',
            'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https',
            'inspector', 'module', 'net', 'os', 'path', 'perf_hooks',
            'process', 'punycode', 'querystring', 'readline', 'repl',
            'stream', 'string_decoder', 'sys', 'timers', 'tls',
            'trace_events',
            'tty', 'url', 'util', 'v8', 'vm', 'wasi',
            'worker_threads', 'zlib',
        ]

    def get_diff_excludes(self) -> list[str]:
        """Return glob patterns to exclude from diff (JS packaging
        artifacts)."""
        return [
            '*.map', 'node_modules', '.yarn', '.pnp.cjs', '.pnp.loader.mjs',
        ]

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
        """Return the subdirectory of source_dir containing the
        package source.

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
        p: 'shared.Printer',
    ) -> tuple[str, int, int]:
        """Attempt to reproduce the npm pack output from the source clone.

        Runs 'npm pack' in the cloned source and compares the resulting
        tarball contents against the distributed package. Note: npm tarballs
        are not bitwise-reproducible across machines due to embedded
        timestamps; this check therefore compares unpacked file contents
        rather than SHA256 hashes.

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

        p(f'=== Reproducible build: {pkgname} {version} ===')
        p(f'Sandbox: {sandbox}')
        p('')

        if not clone_dir.is_dir():
            return shared.finish_reproducible_build(
                p, work, 'SKIPPED (no source clone)')

        rc_nv, nv_out, _ = shared.run_cmd(['npm', '--version'], timeout=10)
        npm_ver = (
            shared.sanitize_line(nv_out.strip()) if rc_nv == 0
            else 'unknown')
        p(f'NPM_VERSION: {npm_ver}')

        # Find package.json in the source clone; check one level deep
        # for monorepos
        pkg_json_path = clone_dir / 'package.json'
        if not pkg_json_path.is_file():
            for child in clone_dir.iterdir():
                if child.is_dir() and (child / 'package.json').is_file():
                    clone_dir = child
                    pkg_json_path = clone_dir / 'package.json'
                    break
        if not pkg_json_path.is_file():
            return shared.finish_reproducible_build(
                p, work, 'SKIPPED (no package.json in source)')

        p(f'BUILD_ROOT: {shared.sanitize_line(str(clone_dir))}')
        build_log_path = work / 'raw-build-output.txt'

        rc_nv2, nv2_out, _ = shared.run_cmd(['node', '--version'], timeout=5)
        node_tag = 'lts'
        if rc_nv2 == 0:
            m = re.match(r'v(\d+)', nv2_out.strip())
            if m:
                node_tag = m.group(1)

        build_result = shared.run_sandboxed(
            sandbox, clone_dir, built_tgz_dir,
            'cd {src} && npm pack --pack-destination {out}',
            f'node:{node_tag}',
            container_shell_cmd=(
                'cp -r {src} /tmp/src && cd /tmp/src'
                ' && npm pack --pack-destination {out}'
            ),
            firejail_cwd=clone_dir,
        )
        if build_result is None:
            return shared.finish_reproducible_build(
                p, work,
                'SKIPPED (no sandbox available: install bwrap, '
                'firejail, docker, or podman)',
            )
        rc_b, combined = build_result
        build_log_path.write_text(
            combined, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

        p(f'BUILD_STATUS: {"yes" if build_ok else "no"}')

        if not build_ok:
            return shared.finish_reproducible_build(
                p, work, 'INCONCLUSIVE (build failed)')

        built_tgzs = list(built_tgz_dir.glob('*.tgz'))
        if not built_tgzs:
            return shared.finish_reproducible_build(
                p, work, 'INCONCLUSIVE (no .tgz produced)')
        built_tgz = max(built_tgzs, key=lambda tgz: tgz.stat().st_mtime)

        built_sha = shared.sha256_file(built_tgz)
        if (repro := shared.compare_repro_sha256(built_sha, work, p)) is not None:
            return repro

        # Hashes will nearly always differ (timestamps); compare unpacked contents
        built_unpacked = work / 'raw-built-unpacked'
        built_unpacked.mkdir(exist_ok=True)
        _unpack_tgz(built_tgz, built_unpacked, [], 'repro-unpack')

        dist_unpacked = work / 'unpacked'
        if not dist_unpacked.is_dir():
            return shared.finish_reproducible_build(p, work, 'INCONCLUSIVE (hashes differ, no dist unpacked dir)')

        rc_diff, diff_out, _ = shared.run_cmd(
            ['diff', '-r', str(built_unpacked), str(dist_unpacked), '--exclude=*.map'],
            timeout=60,
        )
        (work / 'raw-repro-diff.txt').write_text(diff_out, encoding='utf-8', errors='replace')

        diff_line_count = len(diff_out.splitlines())
        p(f'CONTENT_DIFF_LINES: {diff_line_count}')

        if diff_line_count == 0:
            return shared.finish_reproducible_build(p, work, 'EXACTLY REPRODUCIBLE (content match)')

        return shared.classify_repro_diffs(diff_out, p, work, _RE_REPRO_CODE, _RE_REPRO_META)
