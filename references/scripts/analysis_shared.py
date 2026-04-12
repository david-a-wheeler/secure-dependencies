#!/usr/bin/env python3
# analysis_shared.py — Cross-ecosystem helpers for dependency security analysis.
#
# Import this from ecosystem-specific scripts:
#   import sys
#   sys.path.insert(0, str(Path(__file__).parent))
#   import analysis_shared as shared
#
# Provides universal helpers and cross-ecosystem analysis steps. Everything
# here operates on a repo URL, a downloaded directory tree, or data that is
# registry-agnostic (license identifiers, OpenSSF badge, Scorecard, git tags,
# file comparisons, health thresholds, sandbox detection).
#
# Ecosystem-specific code stays in the calling script:
#   - Package download and unpack (gem fetch, pip download, npm pack)
#   - Manifest parsing (gemspec, dist-info, package.json)
#   - Registry API calls (rubygems.org, pypi.org, registry.npmjs.org)
#   - Dangerous-code scan patterns (language-specific eval/exec/shell idioms)
#   - Diff scan patterns (language-specific injection patterns)
#   - Lockfile parsing (Gemfile.lock, requirements.txt, package-lock.json)
#   - Reproducible build (ecosystem-specific build commands)
#
# Python stdlib only — no third-party packages required.

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# OSI-approved SPDX license identifiers (representative list).
# Source: https://opensource.org/licenses/
# ---------------------------------------------------------------------------

OSI_APPROVED: frozenset[str] = frozenset({
    '0BSD', 'AFL-3.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
    'Apache-2.0', 'Artistic-2.0', 'BSD-2-Clause', 'BSD-3-Clause',
    'BSL-1.0', 'CDDL-1.0', 'CECILL-2.1', 'EPL-1.0', 'EPL-2.0',
    'EUPL-1.2', 'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
    'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later', 'ISC', 'LGPL-2.0',
    'LGPL-2.0-only', 'LGPL-2.0-or-later', 'LGPL-2.1', 'LGPL-2.1-only',
    'LGPL-2.1-or-later', 'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
    'MIT', 'MIT-0', 'MPL-2.0', 'MS-PL', 'MS-RL', 'MulanPSL-2.0',
    'NCSA', 'OSL-3.0', 'PSF-2.0', 'Python-2.0', 'Ruby', 'Unlicense',
    'UPL-1.0', 'W3C', 'Zlib',
})

# Common license strings that aren't canonical SPDX — map to canonical form
_LICENSE_ALIASES: dict[str, str] = {
    'apache 2.0': 'Apache-2.0',
    'apache2': 'Apache-2.0',
    'apache license 2.0': 'Apache-2.0',
    'apache license, version 2.0': 'Apache-2.0',
    'bsd': 'BSD-3-Clause',
    'bsd-2': 'BSD-2-Clause',
    'bsd-3': 'BSD-3-Clause',
    'gplv2': 'GPL-2.0-or-later',
    'gplv3': 'GPL-3.0-or-later',
    'gpl2': 'GPL-2.0-or-later',
    'gpl3': 'GPL-3.0-or-later',
    'lgplv2': 'LGPL-2.1-or-later',
    'lgpl': 'LGPL-2.1-or-later',
    'mpl2': 'MPL-2.0',
    'new bsd': 'BSD-3-Clause',
    'simplified bsd': 'BSD-2-Clause',
    '2-clause bsd': 'BSD-2-Clause',
    '3-clause bsd': 'BSD-3-Clause',
}


def normalize_license(raw: str) -> str:
    """Return canonical SPDX id; fall back to the stripped original."""
    stripped = raw.strip().rstrip('.')
    lower = stripped.lower()
    if lower in _LICENSE_ALIASES:
        return _LICENSE_ALIASES[lower]
    return stripped


def license_osi_status(identifier: str) -> tuple[str, str]:
    """Return (normalized_spdx_id, 'YES'|'NO')."""
    norm = normalize_license(identifier)
    if norm in OSI_APPROVED:
        return norm, 'YES'
    base = re.sub(r'-(only|or-later)$', '', norm)
    if base in OSI_APPROVED:
        return norm, 'YES'
    if norm:
        return norm, 'NO'
    return 'MISSING', 'NO'


def evaluate_license(
    candidates: list[str],
    old_license: str | None = None,
) -> dict[str, object]:
    """Evaluate license candidates; return structured result dict.

    Args:
        candidates: license strings from the package manifest/registry,
                    newest-first; first entry is treated as the primary.
        old_license: raw license string from the previous version
                     (UPDATE mode only); None skips change detection.

    Returns dict with keys:
        spdx (str), osi (str), status (str), note (str), changed (bool)
    """
    license_spdx = 'MISSING'
    license_osi = 'NO'
    license_status = 'CRITICAL'
    license_note = (
        'No license declared. No legal basis for security audits or external '
        'contributions; strong predictor of long-term abandonment and unpatched CVEs.'
    )
    license_changed = False

    if candidates:
        norm, osi = license_osi_status(candidates[0])
        license_spdx = norm
        license_osi = osi
        if osi == 'YES':
            license_status = 'OK'
            license_note = 'OSI-approved license; external security review legally permitted.'
        else:
            license_status = 'CONCERN'
            license_note = (
                f'License "{norm}" is not OSI-approved. External researchers cannot '
                'legally audit or fix security issues; community cannot fork to '
                'continue security maintenance if the project is abandoned.'
            )

    if old_license is not None and old_license and candidates:
        current_raw = candidates[0]
        if old_license.strip() != current_raw.strip():
            license_changed = True
            license_note += f' [!] License changed: "{old_license}" -> "{current_raw}"'
            if license_status == 'OK':
                license_status = 'CONCERN'

    return {
        'spdx': license_spdx,
        'osi': license_osi,
        'status': license_status,
        'note': license_note,
        'changed': license_changed,
    }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def sanitize(text: str) -> str:
    """Replace C0/C1 control chars with '?'.

    Strips bidi controls and zero-width chars used for visual spoofing or
    prompt injection before any text reaches the AI.
    """
    result = []
    for ch in text:
        cp = ord(ch)
        if (0x00 <= cp <= 0x1F) or (0x7F <= cp <= 0x9F):
            result.append('?')
        else:
            result.append(ch)
    return ''.join(result)


def run_cmd(
    args: list[str],
    cwd: str | Path | None = None,
    timeout: int = 120,
    capture: bool = True,
) -> tuple[int, str, str]:
    """Run a subprocess; return (returncode, stdout, stderr). Never raises."""
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout or '', result.stderr or ''
    except subprocess.TimeoutExpired:
        return 1, '', f'TIMEOUT after {timeout}s'
    except FileNotFoundError:
        return 1, '', f'command not found: {args[0]}'
    except Exception as exc:  # noqa: BLE001
        return 1, '', str(exc)


def sha256_file(path: Path) -> str:
    """Return hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def blind_scan(label: str, pattern: str, target: Path, work: Path) -> int:
    """Run grep; save raw matches (DO NOT read); write sanitized summary.

    Returns number of matching lines.
    """
    raw_file = work / f'raw-scan-{label}.txt'
    summary_file = work / f'summary-scan-{label}.txt'

    rc, stdout, stderr = run_cmd(['grep', '-rnP', pattern, str(target)], timeout=60)
    raw_content = stdout + (stderr if rc > 1 else '')
    raw_file.write_text(raw_content, encoding='utf-8', errors='replace')

    count = len([line for line in raw_content.splitlines() if line])
    summary_lines = [f'label={label}', f'match_count={count}']
    if count > 0:
        summary_lines.append('files_with_matches:')
        seen: set[str] = set()
        for line in raw_content.splitlines():
            if ':' in line:
                fname = line.split(':', 1)[0]
                if fname not in seen:
                    seen.add(fname)
                    summary_lines.append(sanitize(fname))
    summary_file.write_text('\n'.join(summary_lines) + '\n', encoding='utf-8')
    return count


def http_get(url: str, timeout: int = 15) -> bytes | None:
    """Fetch a URL; return bytes or None on error."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read()
    except Exception:  # noqa: BLE001
        return None


def days_since(date_str: str) -> int | None:
    """Parse an ISO-8601 date string and return days elapsed, or None."""
    try:
        m = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
        if not m:
            return None
        dt = datetime.strptime(m.group(1), '%Y-%m-%d').replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, OverflowError):
        return None


def cmd_available(name: str) -> bool:
    """Return True if `name` is found on PATH."""
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# Adversarial scan patterns — language-agnostic; apply to every ecosystem.
# DANGEROUS_PATTERNS (language-specific eval/exec/etc.) live in each
# ecosystem script because the idioms differ across languages.
# ---------------------------------------------------------------------------

ADVERSARIAL_PATTERNS: list[tuple[str, str]] = [
    ('bidi-controls',
     r'[\u202a-\u202e\u2066-\u2069\u200e\u200f]'),
    ('zero-width-chars',
     r'[\u200b-\u200d\ufeff\u00ad\u2060]'),
    ('non-ascii-in-identifiers',
     r'[a-zA-Z0-9_][\x80-\xFF]+[a-zA-Z0-9_]'),
    ('prompt-injection',
     r'(?i)(?:disregard\s+(?:prior|previous|earlier|above)\s+(?:instructions?|rules?|constraints?)'
     r'|you\s+(?:must|should|shall|are\s+required\s+to)\s+(?:approve|skip|allow|install|bypass|ignore)'
     r'|new\s+(?:directives?|instructions?)\s*:'
     r'|(?:as|being)\s+an?\s+(?:AI|LLM|assistant|language\s+model)\b)'),
    ('long-lines', r'.{480,}'),
]


# ---------------------------------------------------------------------------
# Source repository clone
# ---------------------------------------------------------------------------

def clone_source_repo(
    source_url: str,
    pkgname: str,
    new_ver: str,
    work: Path,
) -> tuple[bool, str]:
    """Shallow-clone the upstream source at the version tag.

    Writes: source-url.txt, clone-status.txt, raw-git-clone-output.txt.
    Returns: (clone_ok, version_tag).
    """
    (work / 'source-url.txt').write_text(sanitize(source_url) + '\n', encoding='utf-8')

    clone_lines: list[str] = []
    clone_ok = False
    version_tag = ''

    if not source_url:
        clone_lines.append('CLONE_STATUS: SKIPPED (no source URL)')
        (work / 'clone-status.txt').write_text('\n'.join(clone_lines) + '\n', encoding='utf-8')
        return False, ''

    # Find a matching version tag via ls-remote (no clone needed)
    rc_ls, ls_out, _ = run_cmd(['git', 'ls-remote', '--tags', source_url], timeout=30)
    tag = ''
    if rc_ls == 0:
        escaped_ver = re.escape(new_ver)
        for line in ls_out.splitlines():
            m_tag = re.search(r'refs/tags/([^\^]+)', line)
            if not m_tag:
                continue
            candidate = m_tag.group(1)
            if re.search(
                rf'(?:v?|{re.escape(pkgname)}[-_]?){escaped_ver}(?:[^0-9]|$)',
                candidate, re.IGNORECASE,
            ):
                tag = candidate
                break
        if not tag:
            # Broader fallback: any tag ending with the version string
            for line in ls_out.splitlines():
                m_tag = re.search(r'refs/tags/([^\^]+)', line)
                if m_tag and re.search(rf'{escaped_ver}$', m_tag.group(1)):
                    tag = m_tag.group(1)
                    break

    if not tag:
        clone_lines.extend([
            'CLONE_STATUS: SKIPPED (no matching version tag)',
            f'SOURCE_URL: {sanitize(source_url)}',
        ])
    else:
        version_tag = tag
        clone_lines.extend([
            f'VERSION_TAG: {sanitize(tag)}',
            f'SOURCE_URL: {sanitize(source_url)}',
        ])
        source_dir = work / 'source'
        rc_clone, _, clone_err = run_cmd(
            ['git', 'clone', '--depth', '1', '--branch', tag, source_url, str(source_dir)],
            timeout=120,
        )
        (work / 'raw-git-clone-output.txt').write_text(
            clone_err, encoding='utf-8', errors='replace'
        )
        if rc_clone == 0:
            clone_lines.append('CLONE_STATUS: OK')
            clone_ok = True
        else:
            clone_lines.append('CLONE_STATUS: FAILED')

    (work / 'clone-status.txt').write_text('\n'.join(clone_lines) + '\n', encoding='utf-8')
    return clone_ok, version_tag


# ---------------------------------------------------------------------------
# OpenSSF Best Practices Badge
# ---------------------------------------------------------------------------

def lookup_openssf_badge(
    source_url: str,
    pkgname: str,
    work: Path,
) -> dict[str, object]:
    """Query bestpractices.dev for a badge given the package's source URL.

    Writes: badge-status.txt, raw-badge-search.json, raw-badge-data.json.
    Returns dict with keys: found (bool), id (str), level (str),
    tiered (str), baseline_tiered (str).
    """
    result: dict[str, object] = {
        'found': False, 'id': '', 'level': '', 'tiered': '', 'baseline_tiered': '',
    }

    if source_url:
        encoded_url = urllib.parse.quote(source_url, safe='')
        search_data = http_get(f'https://www.bestpractices.dev/projects.json?url={encoded_url}')
        if search_data is not None:
            (work / 'raw-badge-search.json').write_bytes(search_data)
            try:
                projects = json.loads(search_data.decode('utf-8', errors='replace'))
                if isinstance(projects, list) and projects:
                    pid = int(projects[0].get('id', 0))
                    if pid > 0:
                        result['id'] = str(pid)
            except (ValueError, KeyError, TypeError):
                pass

        if result['id']:
            detail_data = http_get(
                f'https://www.bestpractices.dev/projects/{result["id"]}.json'
            )
            if detail_data is not None:
                (work / 'raw-badge-data.json').write_bytes(detail_data)
                try:
                    d = json.loads(detail_data.decode('utf-8', errors='replace'))
                    result['found'] = True
                    raw_level = str(d.get('badge_level', ''))
                    result['level'] = re.sub(r'[^a-z0-9_\-]', '', raw_level)[:32] or 'in_progress'
                    tp = d.get('tiered_percentage')
                    if isinstance(tp, (int, float)):
                        result['tiered'] = str(int(tp))
                    btp = d.get('baseline_tiered_percentage')
                    if isinstance(btp, (int, float)):
                        result['baseline_tiered'] = str(int(btp))
                except (ValueError, KeyError, TypeError):
                    result['found'] = False

    badge_lines = [
        f'=== OpenSSF Best Practices Badge: {pkgname} ===',
        f'SOURCE_URL_QUERIED: {sanitize(source_url)}',
        f'BADGE_FOUND: {"yes" if result["found"] else "no"}',
    ]
    if result['found']:
        badge_lines.extend([
            f'BADGE_PROJECT_ID: {sanitize(str(result["id"]))}',
            f'BADGE_LEVEL (metal): {sanitize(str(result["level"]))}',
        ])
        if result['tiered']:
            badge_lines.append(
                f'METAL_TIERED_PERCENTAGE: {result["tiered"]}'
                ' (passing=100, silver=200, gold=300)'
            )
        if result['baseline_tiered']:
            badge_lines.append(
                f'BASELINE_TIERED_PERCENTAGE: {result["baseline_tiered"]}'
                ' (baseline_1=100, baseline_2=200, baseline_3=300)'
            )
    (work / 'badge-status.txt').write_text('\n'.join(badge_lines) + '\n', encoding='utf-8')
    return result


# ---------------------------------------------------------------------------
# OpenSSF Scorecard
# ---------------------------------------------------------------------------

def lookup_scorecard(source_url: str, work: Path) -> str:
    """Query securityscorecards.dev given the source repo URL.

    Writes: raw-scorecard.json (if found).
    Returns: scorecard score string like '7.2/10', or 'not found'.
    """
    if not source_url or 'github.com' not in source_url:
        return 'not found'

    m_gh = re.search(r'github\.com[/:]([^/]+)/([^/\.#?]+)', source_url)
    if not m_gh:
        return 'not found'

    gh_owner = m_gh.group(1)
    gh_repo = m_gh.group(2)
    scorecard_data = http_get(
        f'https://api.securityscorecards.dev/projects/github.com/{gh_owner}/{gh_repo}',
        timeout=20,
    )
    if not scorecard_data:
        return 'not found'

    (work / 'raw-scorecard.json').write_bytes(scorecard_data)
    try:
        sc = json.loads(scorecard_data.decode('utf-8', errors='replace'))
        sc_score = sc.get('score')
        if sc_score is not None:
            return f'{float(sc_score):.1f}/10'
    except (ValueError, KeyError, TypeError):
        pass
    return 'not found'


# ---------------------------------------------------------------------------
# Package vs source comparison
# ---------------------------------------------------------------------------

def compare_pkg_vs_source(
    unpacked_dir: Path,
    source_dir: Path,
    work: Path,
    pkg_excludes: re.Pattern[str],
    src_excludes: re.Pattern[str],
) -> int:
    """Compare distributed package file tree vs source repo.

    Writes: extra-in-package.txt, raw-pkg-paths.txt, raw-src-paths.txt,
            raw-extra-in-package.txt.
    Returns: number of extra files (in package but not in source).
    """
    if not unpacked_dir.is_dir() or not source_dir.is_dir():
        (work / 'extra-in-package.txt').write_text(
            'EXTRA_FILES_IN_PACKAGE: N/A (no clone)\n', encoding='utf-8'
        )
        return 0

    def collect_paths(base: Path, excludes: re.Pattern[str]) -> list[str]:
        paths = []
        for p in base.rglob('*'):
            if not p.is_file():
                continue
            rel = str(p.relative_to(base))
            if not excludes.search(rel):
                paths.append('./' + rel)
        return sorted(paths)

    pkg_paths = collect_paths(unpacked_dir, pkg_excludes)
    src_paths = collect_paths(source_dir, src_excludes)
    extra = sorted(set(pkg_paths) - set(src_paths))

    (work / 'raw-pkg-paths.txt').write_text('\n'.join(pkg_paths) + '\n', encoding='utf-8')
    (work / 'raw-src-paths.txt').write_text('\n'.join(src_paths) + '\n', encoding='utf-8')
    (work / 'raw-extra-in-package.txt').write_text('\n'.join(extra) + '\n', encoding='utf-8')

    (work / 'extra-in-package.txt').write_text(
        '\n'.join([
            f'EXTRA_FILES_IN_PACKAGE: {len(extra)}',
            '(files in distributed package but absent from source repo)',
            'Expected extras: METADATA, RECORD, PKG-INFO, .gemspec, Gemfile.lock, dist-info/',
            '',
        ] + [sanitize(p) for p in extra]) + '\n',
        encoding='utf-8',
    )
    return len(extra)


# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------

def detect_binary_files(unpacked_dir: Path, work: Path) -> int:
    """Find non-text files in the unpacked package.

    Writes: binary-files.txt, raw-binary-in-package.txt.
    Returns: count of binary files found.
    """
    if not unpacked_dir.is_dir():
        (work / 'binary-files.txt').write_text(
            'BINARY_FILES_IN_PACKAGE: N/A\n', encoding='utf-8'
        )
        return 0

    text_indicators = re.compile(
        r'ASCII|UTF|JSON|XML|text|script|empty|directory|\.pyc:|\.pyo:'
    )
    raw_lines: list[str] = []
    for fp in unpacked_dir.rglob('*'):
        if not fp.is_file():
            continue
        rc_f, fout, _ = run_cmd(['file', str(fp)], timeout=10)
        if rc_f == 0 and fout.strip() and not text_indicators.search(fout):
            raw_lines.append(fout.rstrip())

    (work / 'raw-binary-in-package.txt').write_text(
        '\n'.join(raw_lines) + '\n', encoding='utf-8'
    )
    (work / 'binary-files.txt').write_text(
        '\n'.join(
            [f'BINARY_FILES_IN_PACKAGE: {len(raw_lines)}', '']
            + [sanitize(line) for line in raw_lines]
        ) + '\n',
        encoding='utf-8',
    )
    return len(raw_lines)


# ---------------------------------------------------------------------------
# Version diff
# ---------------------------------------------------------------------------

def compute_diff(
    old_dir: Path,
    new_dir: Path,
    work: Path,
    excludes: list[str] | None = None,
) -> tuple[int, str]:
    """Run diff -r between old and new unpacked directories.

    Writes: raw-diff-full.txt, diff-filenames.txt.
    Returns: (total_diff_lines, sanitized_changed_files_text).
    The raw diff is intentionally not returned — callers must not read it.
    """
    if not old_dir.is_dir() or not new_dir.is_dir():
        (work / 'raw-diff-full.txt').write_text('', encoding='utf-8')
        (work / 'diff-filenames.txt').write_text(
            'DIFF: N/A (old or new directory missing)\n', encoding='utf-8'
        )
        return 0, ''

    exclude_args: list[str] = []
    for pat in (excludes or []):
        exclude_args += ['--exclude', pat]

    rc_diff, diff_out, _ = run_cmd(
        ['diff', '-r', str(old_dir), str(new_dir)] + exclude_args,
        timeout=60,
    )
    (work / 'raw-diff-full.txt').write_text(diff_out, encoding='utf-8', errors='replace')
    diff_lines = len(diff_out.splitlines())

    file_headers = [
        line for line in diff_out.splitlines()
        if line.startswith('Only in') or line.startswith('diff ')
    ]
    changed_files_text = '\n'.join(sanitize(line) for line in file_headers)
    (work / 'diff-filenames.txt').write_text(
        '\n'.join([
            f'DIFF_TOTAL_LINES: {diff_lines}', '',
            'Changed/added/removed files (sanitized filenames only):',
        ] + [sanitize(line) for line in file_headers]) + '\n',
        encoding='utf-8',
    )
    return diff_lines, changed_files_text


# ---------------------------------------------------------------------------
# Project health concerns
# ---------------------------------------------------------------------------

def compute_health_concerns(
    last_release_days: int | None,
    age_years: float | None,
    owner_count: int | None,
    scorecard_score: str,
    version_stability: str,
) -> list[str]:
    """Return a list of human-readable health concern strings.

    All thresholds here are ecosystem-agnostic:
      - No release in >18 months → likely unmaintained
      - Package age <6 months → immature / high abandonment risk
      - Single owner → no succession plan
      - Scorecard <4.0/10 → multiple security practice failures
      - Pre-release version → security guarantees rarely made
    """
    concerns: list[str] = []

    if last_release_days is not None and last_release_days > 548:  # ~18 months
        concerns.append(
            f'no release in {last_release_days} days (>18 months — likely unmaintained)'
        )

    if age_years is not None and age_years < 0.5:
        concerns.append('package is less than 6 months old')

    if owner_count == 1:
        concerns.append('single owner (no succession plan)')

    if scorecard_score != 'not found':
        try:
            sc_val = float(scorecard_score.split('/')[0])
            if sc_val < 4.0:
                concerns.append(f'OpenSSF Scorecard {scorecard_score} (<4.0)')
        except (ValueError, IndexError):
            pass

    if version_stability == 'pre-release':
        concerns.append('version is pre-release (security guarantees rarely made)')

    return concerns


# ---------------------------------------------------------------------------
# Sandbox detection (used by deeper-analysis scripts)
# ---------------------------------------------------------------------------

def detect_sandbox(work: Path) -> str:
    """Probe available sandbox tools; write sandbox-detection.txt.

    Returns the name of the selected sandbox tool ('bwrap', 'firejail',
    'nsjail', 'docker', 'podman'), or 'none'.
    """
    lines: list[str] = ['=== Sandbox availability ===']
    selected = 'none'

    if cmd_available('bwrap'):
        rc_ver, ver_out, _ = run_cmd(['bwrap', '--version'], timeout=5)
        ver = ver_out.strip() or 'version unknown'
        rc_probe, _, _ = run_cmd(
            ['bwrap',
             '--ro-bind', '/usr', '/usr',
             '--tmpfs', '/tmp',
             '--proc', '/proc',
             '--dev', '/dev',
             'true'],
            timeout=10,
        )
        if rc_probe == 0:
            lines.append(f'AVAILABLE: bwrap ({ver})')
            if selected == 'none':
                selected = 'bwrap'
        else:
            lines.append(
                f'UNAVAILABLE: bwrap ({ver}) — probe failed'
                ' (unprivileged userns likely disabled)'
            )

    if cmd_available('firejail'):
        rc_ver, ver_out, _ = run_cmd(['firejail', '--version'], timeout=5)
        ver = ver_out.splitlines()[0] if ver_out.strip() else 'version unknown'
        lines.append(f'AVAILABLE: firejail ({ver})')
        if selected == 'none':
            selected = 'firejail'

    if cmd_available('nsjail'):
        lines.append('AVAILABLE: nsjail')
        if selected == 'none':
            selected = 'nsjail'

    if cmd_available('docker'):
        rc_info, _, _ = run_cmd(['docker', 'info'], timeout=15)
        if rc_info == 0:
            lines.append('AVAILABLE: docker')
            if selected == 'none':
                selected = 'docker'

    if cmd_available('podman'):
        lines.append('AVAILABLE: podman')
        if selected == 'none':
            selected = 'podman'

    if selected == 'none':
        lines.append('AVAILABLE: none (build will run unsandboxed — lower assurance)')

    lines.extend(['', f'SELECTED_SANDBOX: {selected}'])
    (work / 'sandbox-detection.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return selected


# ---------------------------------------------------------------------------
# Deep source comparison (used by deeper-analysis scripts)
# ---------------------------------------------------------------------------

def deep_source_comparison(
    pkgname: str,
    new_ver: str,
    work: Path,
    primary_label: str,
    primary_pattern: str,
    native_pattern: str = r'\.(c|h|cpp)$',
) -> None:
    """Compare package file tree vs source; write source-deep-diff.txt.

    Args:
        pkgname: package name (for header lines).
        new_ver: version being analysed.
        work: working directory (must contain unpacked/ and source/).
        primary_label: human-readable name for the primary code language,
                       e.g. 'Ruby', 'Python', 'JavaScript'.
        primary_pattern: regex matching primary-language source files,
                         e.g. r'\\.(rb)$' for Ruby, r'\\.(py)$' for Python.
        native_pattern: regex matching compiled-extension source files
                        (C/C++ by default); pass '' to skip.
    """
    clone_dir = work / 'source'
    dist_unpacked = work / 'unpacked' / f'{pkgname}-{new_ver}'

    lines: list[str] = [
        f'=== Deep source vs. package: {pkgname} {new_ver} ===',
        '',
    ]

    if not clone_dir.is_dir() or not dist_unpacked.is_dir():
        lines.append('DEEP_COMPARISON: SKIPPED (source or unpacked dir missing)')
        (work / 'source-deep-diff.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return

    def relative_files(base: Path, pattern: str) -> set[str]:
        results: set[str] = set()
        pat = re.compile(pattern)
        for p in base.rglob('*'):
            if p.is_file():
                rel = './' + str(p.relative_to(base))
                if pat.search(rel):
                    results.add(rel)
        return results

    # Primary language files in package but NOT in source (highest concern)
    primary_pkg = relative_files(dist_unpacked, primary_pattern)
    primary_src = relative_files(clone_dir, primary_pattern)
    primary_extra = sorted(primary_pkg - primary_src)
    lines.append(f'{primary_label} source files in package but NOT in source (highest concern):')
    for p in primary_extra[:30]:
        lines.append(sanitize(p))
    lines.append('(end)')

    # Native extension files in package but NOT in source
    if native_pattern:
        lines.append('')
        native_pkg = relative_files(dist_unpacked, native_pattern)
        native_src = relative_files(clone_dir, native_pattern)
        native_extra = sorted(native_pkg - native_src)
        lines.append('C/C++ extension files in package but NOT in source:')
        for p in native_extra[:20]:
            lines.append(sanitize(p))
        lines.append('(end)')

    # Binary files vs source counterpart
    lines.extend(['', 'Binary files in package vs source counterpart:'])
    text_indicators = re.compile(
        r'ASCII|UTF|JSON|XML|text|script|empty|directory'
    )
    count = 0
    for pkg_file in dist_unpacked.rglob('*'):
        if not pkg_file.is_file():
            continue
        rc_f, fout, _ = run_cmd(['file', str(pkg_file)], timeout=10)
        if rc_f != 0 or not fout.strip() or text_indicators.search(fout):
            continue
        rel = './' + str(pkg_file.relative_to(dist_unpacked))
        src_counterpart = clone_dir / rel.lstrip('./')
        tag = '[source present]' if src_counterpart.is_file() else '[NO SOURCE COUNTERPART]'
        lines.append(sanitize(fout.rstrip()) + f' {tag}')
        count += 1
        if count >= 20:
            break
    lines.append('(end)')

    lines.extend(['', 'DEEP_COMPARISON: COMPLETE'])
    (work / 'source-deep-diff.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
