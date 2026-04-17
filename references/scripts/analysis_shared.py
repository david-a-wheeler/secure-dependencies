#!/usr/bin/env python3
# analysis_shared.py: Cross-ecosystem helpers for dependency security analysis.
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
# Python stdlib only; no third-party packages required.

import base64
import hashlib
import json
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
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

# Common license strings that aren't canonical SPDX; map to canonical form
_LICENSE_ALIASES: dict[str, str] = {
    'apache 2.0': 'Apache-2.0',
    'apache2': 'Apache-2.0',
    'apache license 2.0': 'Apache-2.0',
    'apache license, version 2.0': 'Apache-2.0',
    'bsd': 'BSD-3-Clause',
    'bsd-2': 'BSD-2-Clause',
    'bsd-3': 'BSD-3-Clause',
    'gplv2': 'GPL-2.0-only',
    'gplv2+': 'GPL-2.0-or-later',
    'gplv3': 'GPL-3.0-only',
    'gplv3+': 'GPL-3.0-or-later',
    'gpl2': 'GPL-2.0-only',
    'gpl2+': 'GPL-2.0-or-later',
    'gpl3': 'GPL-3.0-only',
    'gpl3+': 'GPL-3.0-or-later',
    'lgplv2': 'LGPL-2.1-or-later',
    'lgpl': 'LGPL-2.1-or-later',
    'mpl2': 'MPL-2.0',
    'new bsd': 'BSD-3-Clause',
    'simplified bsd': 'BSD-2-Clause',
    '2-clause bsd': 'BSD-2-Clause',
    '3-clause bsd': 'BSD-3-Clause',
}


def normalize_license(raw: str) -> str:
    """Return canonical SPDX id; fall back to the stripped original.

    >>> normalize_license('MIT')
    'MIT'
    >>> normalize_license('MIT.')
    'MIT'
    >>> normalize_license('apache 2.0')
    'Apache-2.0'
    >>> normalize_license('  gplv3  ')
    'GPL-3.0-only'
    >>> normalize_license('gplv3+')
    'GPL-3.0-or-later'
    """
    stripped = raw.strip().rstrip('.')
    lower = stripped.lower()
    if lower in _LICENSE_ALIASES:
        return _LICENSE_ALIASES[lower]
    return stripped


def license_osi_status(identifier: str) -> tuple[str, str]:
    """Return (normalized_spdx_id, 'YES'|'NO').

    >>> license_osi_status('MIT')
    ('MIT', 'YES')
    >>> license_osi_status('apache 2.0')
    ('Apache-2.0', 'YES')
    >>> license_osi_status('Proprietary')
    ('Proprietary', 'NO')
    >>> license_osi_status('')
    ('MISSING', 'NO')
    """
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
# Cross-ecosystem manifest helpers
# ---------------------------------------------------------------------------

def get_license_candidates(manifest: dict, registry_data: dict) -> list[str]:
    """Return deduplicated license candidates: manifest_license_raw first, then registry.

    Reads 'manifest_license_raw' from the manifest dict (the canonical key set by
    all ecosystem hooks) and appends any 'license_from_registry' entries from the
    registry data dict. Deduplicates while preserving order.

    >>> get_license_candidates({'manifest_license_raw': 'MIT'}, {'license_from_registry': ['Apache-2.0']})
    ['MIT', 'Apache-2.0']
    >>> get_license_candidates({'manifest_license_raw': 'MIT'}, {'license_from_registry': ['MIT']})
    ['MIT']
    >>> get_license_candidates({}, {'license_from_registry': ['MIT']})
    ['MIT']
    >>> get_license_candidates({'manifest_license_raw': ''}, {})
    []
    """
    candidates: list[str] = []
    raw = manifest.get('manifest_license_raw', '')
    if raw:
        candidates.append(str(raw))
    candidates.extend(str(lc) for lc in registry_data.get('license_from_registry', []) if lc)
    seen: set[str] = set()
    unique: list[str] = []
    for lc in candidates:
        if lc and lc not in seen:
            seen.add(lc)
            unique.append(lc)
    return unique


def compute_dep_diff(
    runtime_dep_lines: list[str],
    old_dep_lines: list[str],
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Compute sorted dep lists and added/removed sets from new and old dep lines.

    Returns (dep_lines_new, dep_lines_old, added_deps, removed_deps).
    All returned lists are sorted. Sanitizes each line with sanitize().

    >>> new, old, added, removed = compute_dep_diff(['b', 'a'], ['a', 'c'])
    >>> new
    ['a', 'b']
    >>> added
    ['b']
    >>> removed
    ['c']
    """
    dep_lines_new = sorted(sanitize(l) for l in runtime_dep_lines)
    dep_lines_old = sorted(sanitize(l) for l in old_dep_lines)
    added_deps = sorted(set(dep_lines_new) - set(dep_lines_old))
    removed_deps = sorted(set(dep_lines_old) - set(dep_lines_new))
    return dep_lines_new, dep_lines_old, added_deps, removed_deps


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Return the Levenshtein edit distance between two strings.

    >>> levenshtein('', '')
    0
    >>> levenshtein('abc', 'abc')
    0
    >>> levenshtein('abc', 'ab')
    1
    >>> levenshtein('kitten', 'sitting')
    3
    """
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def sanitize(text: str) -> str:
    """Replace C0/C1 control chars with '?'.

    Strips bidi controls and zero-width chars used for visual spoofing or
    prompt injection before any text reaches the AI.

    >>> sanitize('hello')
    'hello'
    >>> sanitize('hel\\x01lo')
    'hel?lo'
    >>> sanitize('tab\\there')
    'tab?here'
    >>> sanitize('del\\x7fchar')
    'del?char'
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


def count_source_lines(unpacked_dir: Path) -> int:
    """Count non-blank lines across all text files in unpacked_dir.

    Used to compute TODO/FIXME density as a percentage of total source.
    Binary files are skipped (same heuristic as blind_scan: any null byte
    in the first 8 KB is treated as binary).
    """
    total = 0
    for path in unpacked_dir.rglob('*'):
        if not path.is_file():
            continue
        try:
            chunk = path.read_bytes()[:8192]
            if b'\x00' in chunk:
                continue  # binary file
            text = path.read_text(encoding='utf-8', errors='replace')
            total += sum(1 for ln in text.splitlines() if ln.strip())
        except OSError:
            continue
    return total


def blind_scan(
    label: str,
    pattern: str,
    target: Path,
    work: Path,
    include_globs: list[str] | None = None,
) -> int:
    """Run grep; save raw matches (DO NOT read); write sanitized summary.

    include_globs: if given, passed as --include=GLOB to restrict which files
    are scanned (e.g. ['*.rb', '*.py'] to scan only source files).

    Returns number of matching lines.
    """
    raw_file = work / f'raw-scan-{label}.txt'
    summary_file = work / f'summary-scan-{label}.txt'

    cmd = ['grep', '-rnP', pattern]
    for glob in (include_globs or []):
        cmd += [f'--include={glob}']
    cmd.append(str(target))
    rc, stdout, stderr = run_cmd(cmd, timeout=60)

    if rc > 1:
        # grep error (rc==2+): pattern failure or other error (not a match result)
        err_msg = sanitize(stderr.strip())
        raw_file.write_text(f'GREP_ERROR: {stderr}', encoding='utf-8', errors='replace')
        summary_file.write_text(
            f'label={label}\nmatch_count=0\nGREP_ERROR: {err_msg}\n', encoding='utf-8'
        )
        return 0

    # rc==0 means matches found; rc==1 means no matches; both are normal grep exits
    raw_file.write_text(stdout, encoding='utf-8', errors='replace')
    count = len([line for line in stdout.splitlines() if line])
    summary_lines = [f'label={label}', f'match_count={count}']
    if count > 0:
        summary_lines.append('files_with_matches:')
        seen: set[str] = set()
        for line in stdout.splitlines():
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


def http_post(url: str, data: bytes, content_type: str = 'application/json', timeout: int = 15) -> bytes | None:
    """POST data to url; return response bytes or None on error."""
    req = urllib.request.Request(url, data=data, headers={'Content-Type': content_type})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
# Adversarial scan patterns: language-agnostic; apply to every ecosystem.
# DANGEROUS_PATTERNS (language-specific eval/exec/etc.) live in each
# ecosystem script because the idioms differ across languages.
# ---------------------------------------------------------------------------

ADVERSARIAL_PATTERNS: list[tuple[str, str]] = [
    ('bidi-controls',
     '[\u202a-\u202e\u2066-\u2069\u200e\u200f]'),
    ('zero-width-chars',
     '[\u200b-\u200d\ufeff\u00ad\u2060]'),
    ('non-ascii-in-identifiers',
     r'[a-zA-Z0-9_][\x80-\xFF]+[a-zA-Z0-9_]'),
    ('prompt-injection',
     r'(?i)(?:disregard\s+(?:prior|previous|earlier|above)\s+(?:instructions?|rules?|constraints?)'
     r'|you\s+(?:must|should|shall|are\s+required\s+to)\s+(?:approve|skip|allow|install|bypass|ignore)'
     r'|new\s+(?:directives?|instructions?)\s*:'
     r'|(?:as|being)\s+an?\s+(?:AI|LLM|assistant|language\s+model)\b)'),
    # 1000+ spaces/tabs followed by a non-whitespace character: content hidden
    # after padding that won't be visible in most editors or diff views.
    ('whitespace-hiding', r'[ \t]{1000,}[^ \t\r\n]'),
]

# Labels that trigger ADVERSARIAL_GATE: ABORT.  These represent unambiguous
# active attacks with no legitimate use in package code:
#   - bidi controls can visually reverse or hide code to deceive reviewers
#   - zero-width chars inject invisible content into identifiers
#   - prompt-injection text directly targets AI reviewers
#   - whitespace-hiding hides content after 1000+ spaces, invisible in editors
#
# non-ascii-in-identifiers is NOT in this set: accented characters and
# non-Latin scripts are common in documentation, comments, and string literals
# of internationalised packages.  A hit there is flagged for AI review but
# does not abort the gate. Only homoglyph attacks in actual code identifiers
# are esp. dangerous, and distinguishing those requires human/AI judgment.
ADVERSARIAL_ABORT_LABELS: frozenset[str] = frozenset({
    'bidi-controls',
    'zero-width-chars',
    'prompt-injection',
    'whitespace-hiding',
})

# Source-code file globs used to scope bidi/zero-width scans.
# Bidi controls are legitimate in documentation and natural-language text
# (RTL scripts: Arabic, Hebrew, etc.).  They are only dangerous in source
# code files where the Trojan Source attack can visually reverse code logic.
# Scanning only these extensions avoids false positives in .md/.txt/etc.
CODE_FILE_GLOBS: list[str] = [
    '*.rb', '*.rake', '*.gemspec',
    '*.py', '*.pyw',
    '*.js', '*.mjs', '*.cjs', '*.ts', '*.tsx', '*.jsx',
    '*.c', '*.cc', '*.cpp', '*.cxx', '*.h', '*.hh', '*.hpp',
    '*.go', '*.rs', '*.java', '*.kt', '*.swift', '*.cs',
    '*.php', '*.sh', '*.bash', '*.zsh', '*.pl', '*.pm',
]

# Labels whose scans should be restricted to CODE_FILE_GLOBS.
# bidi-controls and zero-width-chars are only dangerous inside source code;
# seeing them in a README or .txt is normal for RTL-language content.
ADVERSARIAL_CODE_ONLY_LABELS: frozenset[str] = frozenset({
    'bidi-controls',
    'zero-width-chars',
})

# TODO/FIXME comment patterns: flag incomplete or rushed code.
# Matches are NOT counted in SCAN_MATCHES risk flags (they are never
# adversarial on their own), but count and density are surfaced to the
# reviewer so the AI sub-agent can judge whether the codebase looks
# incomplete or hastily developed.
TODO_PATTERNS: list[tuple[str, str]] = [
    ('todo-fixme', r'(?i)#\s*(?:TODO|FIXME|HACK|XXX)\b'),
]


# ---------------------------------------------------------------------------
# Source repository clone
# ---------------------------------------------------------------------------

def clone_source_repo(
    source_url: str,
    pkgname: str,
    new_ver: str,
    work: Path,
) -> tuple[bool, str, bool, bool]:
    """Shallow-clone the upstream source at the version tag.

    Writes: source-url.txt, clone-status.txt, raw-git-clone-output.txt.
    Returns: (clone_ok, version_tag, commit_guessed, source_likely_incompatible).
      clone_ok:                  True if a usable clone exists in work/source/
      version_tag:               matched tag string, or 'GUESSED:<sha>', or ''
      commit_guessed:            True when the commit was inferred from history
      source_likely_incompatible: True when source_url is known and clone was
                                 attempted but no tag or guessable commit was
                                 found; the distributed package cannot be matched
                                 to any specific commit and is HIGH RISK. May be
                                 benign (unpinned build tooling) but is suspicious.
    """
    (work / 'source-url.txt').write_text(sanitize(source_url) + '\n', encoding='utf-8')

    clone_lines: list[str] = []
    clone_ok = False
    version_tag = ''
    commit_guessed = False
    source_likely_incompatible = False

    if not source_url:
        clone_lines.append('CLONE_STATUS: SKIPPED (no source URL)')
        (work / 'clone-status.txt').write_text('\n'.join(clone_lines) + '\n', encoding='utf-8')
        return False, '', False, False

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
        # No version tag found. Attempt to locate the release commit by scanning
        # recent history for a commit message that mentions the version string.
        clone_lines.append(f'SOURCE_URL: {sanitize(source_url)}')
        clone_lines.append('NO_TAG: no matching version tag found in repository')
        source_dir = work / 'source'
        guessed_sha = ''
        commits: list[tuple[str, str, str]] = []  # (sha, date, subject)

        if source_dir.exists() and any(source_dir.iterdir()):
            clone_err_text = 'Reused existing clone from previous run.\n'
        else:
            source_dir.mkdir(parents=True, exist_ok=True)
            rc_shallow, _, clone_err_text = run_cmd(
                ['git', 'clone', '--depth', '20', source_url, str(source_dir)],
                timeout=120,
            )
            if rc_shallow != 0:
                clone_err_text = clone_err_text or 'git clone failed'
        (work / 'raw-git-clone-output.txt').write_text(
            clone_err_text, encoding='utf-8', errors='replace'
        )

        # Parse recent commit log: hash, author-date (ISO), subject
        rc_log, log_out, _ = run_cmd(
            ['git', '-C', str(source_dir), 'log', '--format=%H\t%ai\t%s', '-20'],
            timeout=15,
        )
        if rc_log == 0:
            for log_line in log_out.splitlines():
                parts = log_line.split('\t', 2)
                if len(parts) == 3:
                    commits.append((parts[0], parts[1], parts[2]))

        # Search for a commit whose subject mentions the version number
        ver_pat = re.compile(
            rf'(?:version|release|bump|tag)[^0-9]*{re.escape(new_ver)}|{re.escape(new_ver)}',
            re.IGNORECASE,
        )
        guessed_idx = -1
        for i, (sha, _date, subject) in enumerate(commits):
            if ver_pat.search(subject):
                guessed_sha = sha
                guessed_idx = i
                break

        if guessed_sha:
            # Check out exactly that commit so pkg-vs-source comparison works
            run_cmd(['git', '-C', str(source_dir), 'checkout', guessed_sha], timeout=15)
            commit_guessed = True
            clone_ok = True
            version_tag = f'GUESSED:{guessed_sha}'

            # Show ±2 commits around the guessed one so the AI can see context
            start = max(0, guessed_idx - 2)
            end = min(len(commits), guessed_idx + 3)
            nearby: list[str] = []
            for j in range(start, end):
                sha, date, subject = commits[j]
                marker = '>>>' if j == guessed_idx else '   '
                nearby.append(
                    f'  {marker} {sha[:12]}  {date[:19]}  {sanitize(subject)}'
                )

            clone_lines.extend([
                f'CLONE_STATUS: GUESSED (commit inferred from history, no version tag)',
                f'GUESSED_COMMIT: {guessed_sha}',
                'NEARBY_COMMITS (>>> = guessed commit):',
            ] + nearby + [
                'WARNING: Commit was inferred by matching commit message text, not a',
                '  cryptographically-anchored version tag. The AI reviewer MUST explicitly',
                '  flag this uncertainty in the analysis report and ask the human to verify.',
            ])
        else:
            clone_lines.append('CLONE_STATUS: SKIPPED (no matching tag or commit message found)')
            clone_lines.extend([
                'HIGH_RISK: Source repository identified but published version cannot be matched',
                '  to any commit or tag. The distributed package may not correspond to the',
                '  listed source repository at all.',
                'NOTE: This may be benign (e.g., the project does not use tags, or build tooling',
                '  was updated and is not pinned), but it is suspicious and warrants explicit',
                '  human review before installation.',
            ])
            source_likely_incompatible = True
            if commits:
                clone_lines.append('RECENT_COMMITS (for manual inspection):')
                for sha, date, subject in commits[:5]:
                    clone_lines.append(
                        f'  {sha[:12]}  {date[:19]}  {sanitize(subject)}'
                    )
    else:
        version_tag = tag
        clone_lines.extend([
            f'VERSION_TAG: {sanitize(tag)}',
            f'SOURCE_URL: {sanitize(source_url)}',
        ])
        source_dir = work / 'source'
        if source_dir.exists() and any(source_dir.iterdir()):
            # Already cloned in a previous run; reuse existing checkout
            (work / 'raw-git-clone-output.txt').write_text(
                'Reused existing clone from previous run.\n', encoding='utf-8'
            )
            clone_lines.append('CLONE_STATUS: OK (reused)')
            clone_ok = True
        else:
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
    return clone_ok, version_tag, commit_guessed, source_likely_incompatible


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
# Scorecard sub-checks
# ---------------------------------------------------------------------------

def parse_scorecard_checks(work: Path) -> dict[str, float]:
    """Parse individual check scores from raw-scorecard.json.

    Returns dict mapping check name to score (0-10), or {} if unavailable.
    """
    sc_path = work / 'raw-scorecard.json'
    if not sc_path.is_file():
        return {}
    try:
        data = json.loads(sc_path.read_text(encoding='utf-8', errors='replace'))
        return {
            c['name']: float(c['score'])
            for c in data.get('checks', [])
            if 'name' in c and 'score' in c
        }
    except (ValueError, KeyError, TypeError):
        return {}


# ---------------------------------------------------------------------------
# Commit activity
# ---------------------------------------------------------------------------

def count_recent_commits(source_dir: Path, work: Path) -> dict | None:
    """Collect commit-activity statistics for the cloned source repo.

    Fetches all commit timestamps from the last 12 months in a single git
    call, then buckets them into twelve 30-day windows and computes a trend
    signal.

    Returns None if source_dir is not a git repo or git fails.
    Returns a dict with:
      total   (int): total commits in the last 12 months
      buckets (list[int]): 12 ints, most-recent-first; buckets[0] is 0-30
                           days ago, buckets[1] is 31-60 days ago, etc.
      trend   (str): one of 'increasing', 'decreasing', 'stable',
                     'recently_started', 'recently_stopped', 'inactive',
                     or 'insufficient_data' (fewer than 3 months of data)

    Writes: recent-commits.txt
    """
    import time as _time

    if not (source_dir / '.git').is_dir():
        return None

    # Fetch Unix timestamps of all commits in the last 365 days.
    rc, stdout, _ = run_cmd(
        ['git', '-C', str(source_dir), 'log',
         '--format=%cd', '--date=unix', '--since=365.days.ago'],
        timeout=30,
    )
    if rc != 0:
        return None

    now = _time.time()
    timestamps = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            try:
                timestamps.append(float(line))
            except ValueError:
                pass

    # Bucket into 12 x 30-day windows (buckets[0] = most recent 0-30 days).
    buckets: list[int] = [0] * 12
    for ts in timestamps:
        age_days = (now - ts) / 86400.0
        idx = int(age_days // 30)
        if 0 <= idx < 12:
            buckets[idx] += 1

    total = sum(buckets)

    # Trend: compare recent half (months 1-6) vs older half (months 7-12).
    recent_half = sum(buckets[0:6])
    older_half  = sum(buckets[6:12])

    months_with_data = sum(1 for b in buckets if b > 0)
    if months_with_data < 3:
        trend = 'insufficient_data'
    elif total == 0:
        trend = 'inactive'
    elif older_half == 0 and recent_half > 0:
        trend = 'recently_started'
    elif recent_half == 0 and older_half > 0:
        trend = 'recently_stopped'
    elif recent_half > older_half * 1.5:
        trend = 'increasing'
    elif older_half > recent_half * 1.5:
        trend = 'decreasing'
    else:
        trend = 'stable'

    # Write human-readable summary.
    lines = ['=== Commit activity (last 12 months) ===', '']
    lines.append(f'TOTAL_12MO: {total}')
    lines.append(f'TREND: {trend}')
    lines.append('')
    lines.append('Monthly buckets (most recent first):')
    for i, count in enumerate(buckets):
        start_days = i * 30
        end_days = start_days + 29
        lines.append(f'  {start_days:3d}-{end_days:3d} days ago: {count:4d} commits')
    (work / 'recent-commits.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')

    return {'total': total, 'buckets': buckets, 'trend': trend}


# ---------------------------------------------------------------------------
# Known vulnerability lookup (OSV)
# ---------------------------------------------------------------------------

def lookup_vulnerabilities(pkgname: str, version: str, osv_ecosystem: str, work: Path) -> dict:
    """Query the OSV database for known vulnerabilities affecting pkgname version.

    Writes: vulnerabilities.txt
    Returns dict with:
      count (int): total number of matching vulnerabilities
      vulns (list[dict]): each entry has 'id', 'summary', 'severity'
    """
    body = json.dumps({
        'package': {'name': pkgname, 'ecosystem': osv_ecosystem},
        'version': version,
    }).encode()
    raw = http_post('https://api.osv.dev/v1/query', body)
    lines = [f'=== Known vulnerabilities: {pkgname} {version} ===', '']
    vulns: list[dict] = []
    if raw:
        try:
            data = json.loads(raw.decode('utf-8', errors='replace'))
            for v in data.get('vulns', []):
                vid = v.get('id', 'unknown')
                summary = v.get('summary', '')
                severity = ''
                for s in v.get('severity', []):
                    if s.get('type') == 'CVSS_V3':
                        severity = s.get('score', '')
                        break
                vulns.append({'id': vid, 'summary': summary, 'severity': severity})
        except (ValueError, KeyError):
            pass
    if vulns:
        lines.append(f'VULNERABILITY_COUNT: {len(vulns)}')
        lines.append('')
        for v in vulns:
            lines.append(f'  {v["id"]}  severity={v["severity"] or "unknown"}')
            if v['summary']:
                lines.append(f'    {v["summary"]}')
    else:
        lines.append('VULNERABILITY_COUNT: 0')
        lines.append('No known vulnerabilities found in OSV database.')
    (work / 'vulnerabilities.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return {'count': len(vulns), 'vulns': vulns}


# ---------------------------------------------------------------------------
# Security policy (SECURITY.md)
# ---------------------------------------------------------------------------

def check_security_policy(source_dir: Path, work: Path) -> bool:
    """Check whether the source repo contains a SECURITY.md file.

    Checks: SECURITY.md, .github/SECURITY.md, docs/SECURITY.md
    Writes: security-policy.txt
    Returns True if found.
    """
    candidates = [
        source_dir / 'SECURITY.md',
        source_dir / '.github' / 'SECURITY.md',
        source_dir / 'docs' / 'SECURITY.md',
    ]
    found_path = next((p for p in candidates if p.is_file()), None)
    lines = ['=== Security policy ===', '']
    if found_path:
        rel = found_path.relative_to(source_dir)
        lines.append(f'SECURITY_POLICY_FOUND: YES ({rel})')
        lines.append('Context: Project has a SECURITY.md vulnerability disclosure policy.')
    else:
        lines.append('SECURITY_POLICY_FOUND: NO')
        lines.append('Context: No SECURITY.md found. Vulnerability reporting process is unclear.')
    (work / 'security-policy.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return found_path is not None


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

# Magic-byte signatures for precompiled executable formats.
# Each entry is (prefix_bytes, human_readable_format_name).
# Only formats that should never appear in a source package without
# a corresponding build recipe are listed here.
_EXEC_MAGIC: list[tuple[bytes, str]] = [
    (b'\x7fELF',           'ELF (Linux/Unix executable or shared library)'),
    (b'MZ',                'PE (Windows .exe / .dll / .com)'),
    (b'\xce\xfa\xed\xfe',  'Mach-O 32-bit little-endian (macOS)'),
    (b'\xcf\xfa\xed\xfe',  'Mach-O 64-bit little-endian (macOS)'),
    (b'\xfe\xed\xfa\xce',  'Mach-O 32-bit big-endian (macOS)'),
    (b'\xfe\xed\xfa\xcf',  'Mach-O 64-bit big-endian (macOS)'),
    (b'\xca\xfe\xba\xbe',  'Mach-O fat binary or Java .class'),
    (b'\x00asm',           'WebAssembly binary (.wasm)'),
]
_EXEC_HEADER_LEN: int = max(len(magic) for magic, _ in _EXEC_MAGIC)

# Extensions that reliably indicate compiled executables even when the file
# format uses a container (like zip) that would be too broad to match by magic.
# .exe is redundant with MZ magic but included as belt-and-suspenders.
_EXEC_EXTENSIONS: dict[str, str] = {
    '.exe': 'PE executable (Windows)',
    '.jar': 'Java archive (compiled bytecode)',
    '.war': 'Java Web Archive (compiled bytecode)',
    '.ear': 'Java Enterprise Archive (compiled bytecode)',
    '.aar': 'Android Archive (compiled bytecode)',
}


def detect_binary_files(unpacked_dir: Path, work: Path) -> int:
    """Find precompiled executable files in the unpacked package.

    Detection uses file extension first (for zip-container formats like .jar
    that cannot be identified by magic bytes), then falls back to magic-byte
    prefix matching. Detects ELF, PE (Windows), Mach-O, WebAssembly, Java
    .class files, and Java archives (.jar/.war/.ear/.aar). PNG, JPEG, zip,
    gzip, and other non-executable binaries are intentionally NOT flagged.

    Writes: binary-files.txt, raw-binary-in-package.txt.
    Returns: count of embedded executables found.
    """
    if not unpacked_dir.is_dir():
        (work / 'binary-files.txt').write_text(
            'EMBEDDED_EXECUTABLES: N/A\n', encoding='utf-8'
        )
        return 0

    hits: list[str] = []
    for fp in sorted(unpacked_dir.rglob('*')):
        if not fp.is_file() or fp.is_symlink():
            continue
        rel = sanitize(str(fp.relative_to(unpacked_dir)))
        fmt = ''

        # Check by file extension first (catches zip-container formats like .jar)
        ext_fmt = _EXEC_EXTENSIONS.get(fp.suffix.lower())
        if ext_fmt:
            fmt = ext_fmt
        else:
            # Check magic bytes
            try:
                header = fp.read_bytes()[:_EXEC_HEADER_LEN]
            except OSError:
                continue
            for magic, magic_fmt in _EXEC_MAGIC:
                if header.startswith(magic):
                    fmt = magic_fmt
                    break

        if fmt:
            hits.append(f'{rel}: {fmt}')

    (work / 'raw-binary-in-package.txt').write_text(
        '\n'.join(hits) + '\n', encoding='utf-8'
    )
    (work / 'binary-files.txt').write_text(
        '\n'.join(
            [f'EMBEDDED_EXECUTABLES: {len(hits)}', '']
            + hits
        ) + '\n',
        encoding='utf-8',
    )
    return len(hits)


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
    The raw diff is intentionally not returned; callers must not read it.
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

    # Extract short relative filenames for human-readable display.
    # diff header: "diff -r [--exclude ...] OLD_PATH NEW_PATH"
    # Only-in:     "Only in DIR: FILENAME"
    old_prefix = str(old_dir).rstrip('/') + '/'
    new_prefix = str(new_dir).rstrip('/') + '/'
    short_names: list[str] = []
    for line in file_headers:
        if line.startswith('diff '):
            parts = line.split()
            # Last token is the new path; second-to-last is the old path
            old_path = parts[-2] if len(parts) >= 2 else ''
            rel = old_path.removeprefix(old_prefix) if old_path.startswith(old_prefix) else old_path
            short_names.append(sanitize(rel))
        elif line.startswith('Only in '):
            # "Only in /path/dir: filename"
            rest = line[len('Only in '):]
            if ': ' in rest:
                dir_part, fname = rest.split(': ', 1)
                dir_part = dir_part.rstrip('/')
                full = dir_part + '/' + fname
                if full.startswith(old_prefix):
                    short_names.append(sanitize(full.removeprefix(old_prefix)) + ' (removed)')
                elif full.startswith(new_prefix):
                    short_names.append(sanitize(full.removeprefix(new_prefix)) + ' (added)')
                else:
                    short_names.append(sanitize(full))
            else:
                short_names.append(sanitize(line))
        else:
            short_names.append(sanitize(line))

    changed_files_text = '\n'.join(short_names)
    (work / 'diff-filenames.txt').write_text(
        '\n'.join([
            f'DIFF_TOTAL_LINES: {diff_lines}', '',
            'Changed/added/removed files (relative paths):',
        ] + short_names) + '\n',
        encoding='utf-8',
    )
    return diff_lines, changed_files_text


def git_diff_between_tags(
    source_dir: Path,
    source_url: str,
    old_ver: str,
    new_ver: str,
    pkgname: str,
    work: Path,
) -> tuple[int, str]:
    """Diff old→new using the already-cloned source repo (fallback when old gem unavailable).

    Locates the old version tag via ls-remote, fetches it into the existing
    shallow clone, then runs ``git diff OLD_TAG..HEAD``.

    Writes: raw-diff-full.txt, diff-filenames.txt.
    Returns: (total_diff_lines, sanitized_changed_files_text), or (0, '') on failure.
    """
    if not source_dir.is_dir():
        return 0, ''

    # Find old version tag with the same matching logic as clone_source_repo.
    rc_ls, ls_out, _ = run_cmd(['git', 'ls-remote', '--tags', source_url], timeout=30)
    old_tag = ''
    if rc_ls == 0:
        escaped_old = re.escape(old_ver)
        for line in ls_out.splitlines():
            m = re.search(r'refs/tags/([^\^]+)', line)
            if not m:
                continue
            candidate = m.group(1)
            if re.search(
                rf'(?:v?|{re.escape(pkgname)}[-_]?){escaped_old}(?:[^0-9]|$)',
                candidate, re.IGNORECASE,
            ):
                old_tag = candidate
                break
        if not old_tag:
            for line in ls_out.splitlines():
                m = re.search(r'refs/tags/([^\^]+)', line)
                if m and re.search(rf'{escaped_old}$', m.group(1)):
                    old_tag = m.group(1)
                    break

    if not old_tag:
        (work / 'diff-filenames.txt').write_text(
            f'DIFF: N/A (old version tag for {sanitize(old_ver)} not found in source repo)\n',
            encoding='utf-8',
        )
        (work / 'raw-diff-full.txt').write_text('', encoding='utf-8')
        return 0, ''

    # Fetch the old tag into the existing shallow clone.
    rc_fetch, _, _ = run_cmd(
        ['git', '-C', str(source_dir), 'fetch', '--depth', '1', 'origin',
         f'refs/tags/{old_tag}:refs/tags/{old_tag}'],
        timeout=60,
    )
    if rc_fetch != 0:
        (work / 'diff-filenames.txt').write_text(
            f'DIFF: N/A (could not fetch old tag {sanitize(old_tag)} into clone)\n',
            encoding='utf-8',
        )
        (work / 'raw-diff-full.txt').write_text('', encoding='utf-8')
        return 0, ''

    # Full diff output for scan/AI review (written to raw- file; never returned to caller).
    rc_diff, diff_out, _ = run_cmd(
        ['git', '-C', str(source_dir), 'diff', f'{old_tag}..HEAD'],
        timeout=60,
    )
    (work / 'raw-diff-full.txt').write_text(diff_out, encoding='utf-8', errors='replace')
    diff_lines = len(diff_out.splitlines())

    # File-level summary via --name-status (safe to surface to AI).
    rc_names, names_out, _ = run_cmd(
        ['git', '-C', str(source_dir), 'diff', '--name-status', f'{old_tag}..HEAD'],
        timeout=30,
    )
    short_names: list[str] = []
    if rc_names == 0:
        for line in names_out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) == 2:
                status, fname = parts[0].strip(), sanitize(parts[1].strip())
                if status == 'D':
                    short_names.append(f'{fname} (removed)')
                elif status == 'A':
                    short_names.append(f'{fname} (added)')
                else:
                    short_names.append(fname)

    changed_files_text = '\n'.join(short_names)
    (work / 'diff-filenames.txt').write_text(
        '\n'.join([
            f'DIFF_TOTAL_LINES: {diff_lines}',
            f'DIFF_SOURCE: git diff {sanitize(old_tag)}..HEAD (source repo; old gem unavailable)',
            '',
            'Changed/added/removed files (relative paths):',
        ] + short_names) + '\n',
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
    recent_commits: int | None = None,
    known_vulns: int = 0,
) -> list[str]:
    """Return a list of human-readable health concern strings.

    All thresholds here are ecosystem-agnostic:
      - No release in >18 months: likely unmaintained
      - Package age <6 months: immature / high abandonment risk
      - Single owner: no succession plan
      - Scorecard <4.0/10: multiple security practice failures
      - Pre-release version: security guarantees rarely made

    >>> compute_health_concerns(None, None, None, 'not found', 'stable')
    []
    >>> compute_health_concerns(600, None, None, 'not found', 'stable')
    ['no release in 600 days (>18 months; likely unmaintained)']
    >>> compute_health_concerns(None, 0.3, None, 'not found', 'stable')
    ['package is less than 6 months old']
    >>> compute_health_concerns(None, None, 1, 'not found', 'stable')
    ['single owner (no succession plan)']
    >>> compute_health_concerns(None, None, None, '3.5/10', 'stable')
    ['OpenSSF Scorecard 3.5/10 (<4.0)']
    >>> compute_health_concerns(None, None, None, 'not found', 'pre-release')
    ['version is pre-release (security guarantees rarely made)']
    >>> compute_health_concerns(None, None, None, 'not found', 'stable', recent_commits=0)
    ['no commits in last 12 months (activity may have ceased)']
    >>> compute_health_concerns(None, None, None, 'not found', 'stable', known_vulns=2)
    ['2 known vulnerabilities in OSV database']
    """
    concerns: list[str] = []

    if last_release_days is not None and last_release_days > 548:  # ~18 months
        concerns.append(
            f'no release in {last_release_days} days (>18 months; likely unmaintained)'
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

    if recent_commits == 0:
        concerns.append('no commits in last 12 months (activity may have ceased)')

    if known_vulns > 0:
        vuln_word = 'vulnerability' if known_vulns == 1 else 'vulnerabilities'
        concerns.append(f'{known_vulns} known {vuln_word} in OSV database')

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
                f'UNAVAILABLE: bwrap ({ver}): probe failed'
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
        lines.append(
            'AVAILABLE: none -- reproducible build SKIPPED (no sandbox tool found; '
            'install bwrap, firejail, docker, or podman to enable)'
        )

    lines.extend(['', f'SELECTED_SANDBOX: {selected}'])
    (work / 'sandbox-detection.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return selected


# ---------------------------------------------------------------------------
# Sandboxed build helper
# ---------------------------------------------------------------------------

def run_sandboxed(
    sandbox: str,
    src_dir: Path,
    out_dir: Path,
    shell_cmd: str,
    container_image: str,
    *,
    container_shell_cmd: str | None = None,
    container_allow_network: bool = False,
    firejail_cwd: Path | None = None,
    timeout: int = 300,
    container_timeout: int = 600,
) -> tuple[int, str] | None:
    """Run one or more commands inside a sandbox; return (returncode, combined_output).

    Returns None when sandbox == 'none', signalling the caller should emit SKIPPED.

    shell_cmd is a shell command string that may chain multiple commands with &&
    or ; as needed. Use the literal placeholders {src} and {out} for the
    source directory (read-only) and output directory respectively.  The
    function substitutes the correct paths for each sandbox type before
    execution, so a single shell_cmd works for bwrap, firejail, and containers.

    Example:
        run_sandboxed(
            sandbox, src, out,
            shell_cmd='cd {src} && npm install && npm test && npm pack --pack-destination {out}',
            container_image='node:20',
        )

    Parameters:
        sandbox: 'bwrap', 'firejail', 'docker', 'podman', or 'none'
        src_dir: read-only source tree on the host
        out_dir: writable output directory on the host
        shell_cmd: shell command with {src} and {out} placeholders; used for
            bwrap and firejail (substituted with /src//out and real paths resp.)
        container_image: Docker/Podman image (e.g. 'ruby:3.2', 'node:20')
        container_shell_cmd: override shell_cmd for Docker/Podman only; useful
            when the container needs extra setup steps (e.g. pip install build)
            before the main build command; same {src}/{out} substitution applies
        container_allow_network: allow network in the container (default False)
        firejail_cwd: working directory for firejail (default: src_dir)
        timeout: seconds allowed for bwrap/firejail
        container_timeout: seconds allowed for Docker/Podman
    """
    if sandbox == 'bwrap':
        script = shell_cmd.format(src='/src', out='/out')
        args = [
            'bwrap',
            '--ro-bind', str(src_dir), '/src',
            '--bind', str(out_dir), '/out',
            '--ro-bind', '/usr', '/usr',
            '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/etc', '/etc',
            '--symlink', 'usr/bin', '/bin',
            '--tmpfs', '/tmp',
            '--proc', '/proc',
            '--dev', '/dev',
            '--unshare-net',
            '--die-with-parent',
            '--chdir', '/src',
        ]
        if Path('/lib64').is_dir():
            args += ['--ro-bind', '/lib64', '/lib64']
        args += ['/usr/bin/sh', '-c', script]
        rc, out, err = run_cmd(args, timeout=timeout)
        return rc, out + err

    if sandbox == 'firejail':
        script = shell_cmd.format(src=str(src_dir), out=str(out_dir))
        cwd = firejail_cwd or src_dir
        args = [
            'firejail', '--quiet', '--net=none',
            f'--read-only={src_dir}',
            'sh', '-c', script,
        ]
        rc, out, err = run_cmd(args, cwd=cwd, timeout=timeout)
        return rc, out + err

    if sandbox in ('docker', 'podman'):
        raw = container_shell_cmd if container_shell_cmd is not None else shell_cmd
        script = raw.format(src='/src', out='/out')
        args = [sandbox, 'run', '--rm']
        if not container_allow_network:
            args += ['--network', 'none']
        args += [
            '-v', f'{src_dir}:/src:ro',
            '-v', f'{out_dir}:/out',
            container_image,
            'sh', '-c', script,
        ]
        rc, out, err = run_cmd(args, timeout=container_timeout)
        return rc, out + err

    return None  # sandbox == 'none'


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


# ---------------------------------------------------------------------------
# Reproducible-build helpers (used by all ecosystem hooks)
# ---------------------------------------------------------------------------

def finish_reproducible_build(
    lines: list,
    work: Path,
    result: str,
    extra: list | None = None,
) -> tuple:
    """Append result, write reproducible-build.txt, return (result, 0, 0).

    The trailing zeros are placeholder diff counts for early-exit paths where
    no diff was performed. Use classify_repro_diffs for paths that do a diff.
    """
    lines.append(f'REPRODUCIBLE_BUILD: {result}')
    if extra:
        lines.extend(extra)
    (work / 'reproducible-build.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return result, 0, 0


def compare_repro_sha256(
    built_sha: str,
    work: Path,
    lines: list,
) -> tuple | None:
    """Read package-hash.txt, append SHA256 lines, and check for an exact match.

    Returns a finished result tuple if the built and distributed hashes match,
    or None if they differ (caller should proceed to content comparison).
    """
    pkg_hash_file = work / 'package-hash.txt'
    dist_sha = ''
    if pkg_hash_file.is_file():
        first_line = pkg_hash_file.read_text(encoding='utf-8').splitlines()[0]
        dist_sha = first_line.split()[0] if first_line.split() else ''
    lines.append(f'BUILT_SHA256: {sanitize(built_sha)}')
    lines.append(f'DISTRIBUTED_SHA256: {sanitize(dist_sha or "UNKNOWN")}')
    if built_sha and built_sha == dist_sha:
        return finish_reproducible_build(lines, work, 'EXACTLY REPRODUCIBLE (sha256 match)')
    return None


def classify_repro_diffs(
    diff_out: str,
    lines: list,
    work: Path,
    re_code: 're.Pattern',
    re_meta: 're.Pattern',
) -> tuple:
    """Classify diff output into code vs metadata changes, write report, return result tuple.

    re_code and re_meta are ecosystem-specific compiled patterns passed by the caller.
    Returns (result_str, code_diffs, metadata_diffs).
    """
    differing: list = []
    code_diffs = 0
    metadata_diffs = 0
    for line in diff_out.splitlines():
        if line.startswith('Only in') or line.startswith('diff '):
            differing.append(sanitize(line))
        if re_code.search(line):
            code_diffs += 1
        if re_meta.search(line):
            metadata_diffs += 1
    lines.append('DIFFERING_FILES (sanitized):')
    lines.extend(differing[:50])
    lines.append(f'CODE_FILE_DIFFS: {code_diffs}')
    lines.append(f'METADATA_FILE_DIFFS: {metadata_diffs}')
    if code_diffs > 0:
        result = 'UNEXPECTED DIFFERENCES'
        extra: list | None = ['WARNING: code files differ (possible injected code; human review required)']
    else:
        result = 'FUNCTIONALLY EQUIVALENT (metadata-only diffs)'
        extra = None
    return finish_reproducible_build(lines, work, result, extra)


def write_transitive_deps(
    work: Path,
    pkgname: str,
    version: str,
    total: int,
    new_deps: list,
    *,
    total_label: str = 'TOTAL_TRANSITIVE_DEPS',
    note: str = '',
) -> dict:
    """Write transitive-deps.txt and return the standard result dict."""
    trans_lines = [f'=== Transitive dependency footprint: {pkgname} {version} ===']
    if note:
        trans_lines.append(f'NOTE: {note}')
    trans_lines += [
        f'{total_label}: {total}',
        f'NEW_NOT_IN_LOCKFILE: {len(new_deps)}',
        '',
        'NEW_PACKAGES (not in current lockfile):',
    ]
    if new_deps:
        trans_lines.extend(f'  {sanitize(d)}' for d in new_deps)
    else:
        trans_lines.append('  none')
    (work / 'transitive-deps.txt').write_text('\n'.join(trans_lines) + '\n', encoding='utf-8')
    return {'total': total, 'not_in_lockfile': new_deps}


def write_alternatives(
    work: Path,
    pkgname: str,
    version: str,
    section_labels: dict,
    concerns: list,
    notes: list,
) -> dict:
    """Write alternatives.txt and return the standard result dict.

    section_labels maps a human-readable label to its count, e.g.:
        {'Installed gems checked': 45, 'Lockfile deps checked': 12}
    These lines appear verbatim in the report header.
    pkg_count in the return dict is the sum of all non-lockfile section counts.
    """
    lines = [f'=== Alternatives check: {pkgname} {version} ===']
    for label, count in section_labels.items():
        lines.append(f'{label}: {count}')
    lines.append('')
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
    lockfile_count = sum(
        v for k, v in section_labels.items() if 'lockfile' in k.lower()
    )
    pkg_count = sum(
        v for k, v in section_labels.items() if 'lockfile' not in k.lower()
    )
    return {
        'concerns': concerns,
        'notes': notes,
        'pkg_count': pkg_count,
        'lockfile_count': lockfile_count,
    }


# ---------------------------------------------------------------------------
# Ecosyste.ms cross-ecosystem package metadata
# ---------------------------------------------------------------------------

ECOSYSTEMS_REGISTRY_MAP: dict[str, str] = {
    'rubygems': 'rubygems.org',
    'pypi':     'pypi.org',
    'npm':      'npmjs.org',
}

ECOSYSTEMS_EMAIL_FILE: Path = (
    Path.home() / '.config' / 'secure-dependencies' / 'ecosystems-email.txt'
)


def ecosystems_email() -> str:
    """Return the stored contact email for the ecosyste.ms polite pool.

    Returns '' if the file is missing (never configured) or empty (opted out).
    """
    try:
        return ECOSYSTEMS_EMAIL_FILE.read_text(encoding='utf-8').strip()
    except FileNotFoundError:
        return ''


def save_ecosystems_email(email: str) -> None:
    """Write email (or '' for opt-out) to the config file.

    Creates parent directories if needed.
    """
    ECOSYSTEMS_EMAIL_FILE.parent.mkdir(parents=True, exist_ok=True)
    content = email.strip()
    ECOSYSTEMS_EMAIL_FILE.write_text(
        content + '\n' if content else '', encoding='utf-8',
    )


def lookup_ecosystems_package(registry_key: str, pkgname: str,
                              work: Path | None = None) -> dict:
    """Query packages.ecosyste.ms for cross-ecosystem package metadata.

    Uses the stored email (if any) to opt into the polite rate-limit pool via
    the From header and a mailto= query parameter, as documented at
    https://ecosyste.ms/api.

    Writes: raw-ecosystems.json to work (if work is provided and request succeeds).

    Returns a dict with these keys on success:
      dependent_packages_count  int | None
      dependent_repos_count     int | None
      critical                  bool | None   (True = widely-depended-on package)
      status                    str | None    ('deprecated', 'archived', or None)
      rankings_average          float | None  (lower percentile = more popular)

    Returns {'rate_limited': True} on HTTP 429.
    Returns {} if the registry is not in ECOSYSTEMS_REGISTRY_MAP or the
    request fails for any other reason.
    """
    eco_registry = ECOSYSTEMS_REGISTRY_MAP.get(registry_key)
    if not eco_registry:
        return {}

    email = ecosystems_email()
    url = (
        'https://packages.ecosyste.ms/api/v1/registries/'
        f'{urllib.parse.quote(eco_registry, safe="")}/packages/'
        f'{urllib.parse.quote(pkgname, safe="")}'
    )
    if email:
        url += f'?mailto={urllib.parse.quote(email)}'

    headers: dict[str, str] = {
        'User-Agent': 'secure-dependencies/1 (dependency security review)',
    }
    if email:
        headers['From'] = email

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            raw = resp.read()
        data = json.loads(raw.decode('utf-8', errors='replace'))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return {'rate_limited': True}
        return {}
    except Exception:  # noqa: BLE001
        return {}

    if work is not None:
        (work / 'raw-ecosystems.json').write_bytes(raw)

    rankings = data.get('rankings') or {}
    return {
        'dependent_packages_count': data.get('dependent_packages_count'),
        'dependent_repos_count':    data.get('dependent_repos_count'),
        'critical':                 data.get('critical'),
        'status':                   data.get('status'),
        'rankings_average':         rankings.get('average'),
    }


# ---------------------------------------------------------------------------
# OSS Rebuild reproducibility lookup
# ---------------------------------------------------------------------------

_OSS_REBUILD_BUCKET = 'google-rebuild-attestations'
_OSS_REBUILD_BASE_URL = 'https://storage.googleapis.com'
_OSS_REBUILD_API_URL = f'{_OSS_REBUILD_BASE_URL}/storage/v1/b/{_OSS_REBUILD_BUCKET}/o'

# Fallback: maps OSV ecosystem name -> OSS Rebuild bucket identifier.
# Primary source is hooks.OSS_REBUILD_ECOSYSTEM; this table covers any hook
# that pre-dates this feature or that leaves the attribute as an empty string.
# Identifiers from pkg/rebuild/rebuild/models.go in google/oss-rebuild.
_OSS_REBUILD_ECOSYSTEM_FALLBACK: dict[str, str] = {
    'PyPI':      'pypi',
    'npm':       'npm',
    'RubyGems':  'rubygems',
    'crates.io': 'cratesio',
    'Maven':     'maven',
    'Debian':    'debian',
}


def _oss_rebuild_pkg_key(ecosystem: str, pkgname: str) -> str:
    """Return the package name as used in the OSS Rebuild GCS path.

    PyPI normalizes package names to lowercase with hyphens (underscores and
    periods are interchangeable with hyphens and case is ignored).
    Other ecosystems use the name as-is.

    >>> _oss_rebuild_pkg_key('pypi', 'Pillow')
    'pillow'
    >>> _oss_rebuild_pkg_key('pypi', 'my_package')
    'my-package'
    >>> _oss_rebuild_pkg_key('pypi', 'My.Package')
    'my-package'
    >>> _oss_rebuild_pkg_key('npm', 'lodash')
    'lodash'
    >>> _oss_rebuild_pkg_key('rubygems', 'rails')
    'rails'
    """
    if ecosystem == 'pypi':
        return re.sub(r'[-_.]+', '-', pkgname).lower()
    return pkgname


def _oss_rebuild_list_versions(ecosystem: str, pkg_key: str) -> list[str]:
    """Return sorted list of versions available in the OSS Rebuild bucket.

    Uses the GCS JSON API with delimiter to enumerate version-level prefixes.
    Returns [] if no data exists (unknown ecosystem, unknown package, or
    transient network failure).

    Try it:
        python3 -c "
        import sys; sys.path.insert(0, 'references/scripts')
        import analysis_shared as s
        print(s._oss_rebuild_list_versions('pypi', 'absl-py'))
        "
    """
    versions: list[str] = []
    page_token: str | None = None
    prefix = f'{ecosystem}/{pkg_key}/'
    while True:
        # safe="" encodes everything including '/', which is correct here:
        # the prefix is a query parameter value and GCS decodes it fully
        # before matching, so %2F is equivalent to a literal slash in the
        # object namespace.  In particular, scoped npm names like
        # @angular/core must have their '/' encoded so it is not mistaken
        # for a URL path separator.
        url = (
            f'{_OSS_REBUILD_API_URL}?'
            f'prefix={urllib.parse.quote(prefix, safe="")}'
            f'&delimiter=%2F&maxResults=500'
        )
        if page_token:
            url += f'&pageToken={urllib.parse.quote(page_token, safe="")}'
        raw = http_get(url, timeout=15)
        if not raw:
            break
        try:
            data = json.loads(raw)
        except (ValueError, KeyError):
            break
        for p in data.get('prefixes', []):
            # p looks like "pypi/requests/2.32.3/"
            ver = p.rstrip('/').split('/')[-1]
            if ver:
                versions.append(ver)
        page_token = data.get('nextPageToken')
        if not page_token:
            break
    return sorted(versions)


def _oss_rebuild_list_artifacts(ecosystem: str, pkg_key: str, version: str) -> list[str]:
    """Return artifact names available for a specific version.

    Each artifact is the directory segment between version and rebuild.intoto.jsonl,
    e.g. 'requests-2.32.3-py3-none-any.whl'. Returns [] if none found.

    Try it:
        python3 -c "
        import sys; sys.path.insert(0, 'references/scripts')
        import analysis_shared as s
        print(s._oss_rebuild_list_artifacts('pypi', 'absl-py', '2.0.0'))
        "
    """
    artifacts: list[str] = []
    prefix = f'{ecosystem}/{pkg_key}/{version}/'
    # safe="" for the same reason as in _oss_rebuild_list_versions: the
    # prefix is a query parameter, so all characters including '/' must be
    # percent-encoded so GCS treats them as part of the value, not the URL.
    url = (
        f'{_OSS_REBUILD_API_URL}?'
        f'prefix={urllib.parse.quote(prefix, safe="")}'
        f'&maxResults=50'
    )
    raw = http_get(url, timeout=15)
    if not raw:
        return artifacts
    try:
        data = json.loads(raw)
    except (ValueError, KeyError):
        return artifacts
    for item in data.get('items', []):
        name = item.get('name', '')
        # Strip the version prefix and take the next path component.
        # This handles pkg_key values that contain '/' (e.g. scoped npm
        # packages like @angular/core) where fixed-index splitting breaks.
        # name: "pypi/requests/2.32.3/requests-2.32.3-py3-none-any.whl/rebuild.intoto.jsonl"
        # name: "npm/@angular/core/19.0.0/angular-core-19.0.0.tgz/rebuild.intoto.jsonl"
        remainder = name.removeprefix(prefix)
        artifact = remainder.split('/')[0]
        if artifact:
            artifacts.append(artifact)
    return artifacts


def _oss_rebuild_fetch_verdict(
    ecosystem: str, pkg_key: str, version: str, artifact: str,
) -> str | None:
    """Fetch one attestation bundle and return 'PASS', 'FAIL', or None.

    Try it:
        python3 -c "
        import sys; sys.path.insert(0, 'references/scripts')
        import analysis_shared as s
        print(s._oss_rebuild_fetch_verdict(
            'pypi', 'absl-py', '2.0.0', 'absl_py-2.0.0-py3-none-any.whl'))
        "


    OSS Rebuild only publishes an attestation bundle when the rebuild
    succeeds (source: internal/api/apiservice/rebuild.go, which returns
    FailedPrecondition before calling PublishBundle if neither exactMatch
    nor stabilizedMatch).  So the verdict rule is:

        ArtifactEquivalence attestation present in bundle  ->  PASS
        Bundle present but no ArtifactEquivalence           ->  FAIL (guard
            against a future format change where failures get attestations)
        Bundle absent or unparseable                        ->  None

    Note: the attestation stores the raw rebuild hash and the stabilized
    upstream hash, but NOT the stabilized rebuild hash.  The in-process
    comparison (rb.StabilizedHash == up.StabilizedHash) cannot be
    reproduced from the attestation data alone, which is why presence
    of the attestation is the correct signal, not any hash comparison.
    """
    # This is a direct-download URL, not a query parameter, so path
    # structure matters.  safe="/" for pkg_key preserves any '/' within
    # the name as a literal URL path separator (e.g. scoped npm packages
    # like @angular/core become ...npm/@angular/core/...).  Using safe=""
    # here would encode '/' as '%2F'; HTTP servers (including GCS) do NOT
    # decode %2F back to '/' in paths, so the request would 404.
    # version and artifact never contain '/' so safe="" is fine for those.
    url = (
        f'{_OSS_REBUILD_BASE_URL}/{_OSS_REBUILD_BUCKET}/'
        f'{ecosystem}/{urllib.parse.quote(pkg_key, safe="/")}/'
        f'{urllib.parse.quote(version, safe="")}/'
        f'{urllib.parse.quote(artifact, safe="")}/rebuild.intoto.jsonl'
    )
    raw = http_get(url, timeout=15)
    if not raw:
        return None
    bundle_found = False
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            envelope = json.loads(line)
            payload_b64 = envelope.get('payload', '')
            if not payload_b64:
                continue
            payload = json.loads(
                base64.b64decode(payload_b64).decode('utf-8', errors='replace')
            )
            bundle_found = True
            pred = payload.get('predicate', {})
            build_def = pred.get('buildDefinition', {})
            if 'ArtifactEquivalence' in build_def.get('buildType', ''):
                return 'PASS'
        except Exception:  # noqa: BLE001
            continue
    # Bundle was readable but contained no ArtifactEquivalence attestation.
    # This should not happen with the current service, but guard against it.
    return 'FAIL' if bundle_found else None


def _oss_rebuild_version_verdict(
    ecosystem: str, pkg_key: str, version: str,
) -> str | None:
    """Get the overall verdict for a package version across all its artifacts.

    Returns 'PASS' if any artifact has an ArtifactEquivalence attestation,
    'FAIL' if bundles exist but none contain ArtifactEquivalence, or None
    if no verdict could be determined.

    In practice with current OSS Rebuild data, versions only appear in the
    bucket when they passed, so a listed version will virtually always return
    'PASS' here.  The FAIL path exists as a guard against future format
    changes where failures might also get attestation bundles.

    We use "any PASS = PASS" because a single reproduced artifact is a
    positive signal; a FAIL on one artifact format may just be a tooling gap.
    """
    artifacts = _oss_rebuild_list_artifacts(ecosystem, pkg_key, version)
    if not artifacts:
        return None
    verdicts = [
        v for v in (
            _oss_rebuild_fetch_verdict(ecosystem, pkg_key, version, a)
            for a in artifacts
        )
        if v is not None
    ]
    if not verdicts:
        return None
    return 'PASS' if any(v == 'PASS' for v in verdicts) else 'FAIL'


def _oss_rebuild_sample_other_versions(
    ecosystem: str, pkg_key: str, all_versions: list[str], exclude: str,
) -> tuple[bool, bool]:
    """Check a spread sample of versions (excluding `exclude`) for pass/fail.

    Samples up to 3 versions spread across the list (first, middle, last).
    Returns (any_pass, any_fail).
    """
    others = [v for v in all_versions if v != exclude]
    if not others:
        return False, False
    if len(others) == 1:
        sample = others[:]
    else:
        idxs = sorted({0, len(others) // 2, len(others) - 1})
        sample = [others[i] for i in idxs]
    verdicts = [_oss_rebuild_version_verdict(ecosystem, pkg_key, v) for v in sample]
    return (
        any(v == 'PASS' for v in verdicts),
        any(v == 'FAIL' for v in verdicts),
    )


def lookup_oss_rebuild(
    oss_rebuild_ecosystem: str,
    pkgname: str,
    version: str,
    work: Path | None = None,
) -> dict:
    """Query OSS Rebuild for reproducibility data on pkgname@version.

    Always performs the lookup regardless of ecosystem; returns gracefully
    with signal_level='NONE' if no data exists.  An absent version in the
    bucket means unknown, not failed.

    See docs/oss-rebuild.md for background on the data source, update cadence,
    coverage gaps, and how to interpret the signals.

    work: directory for output files.  If None, a temporary directory is used
    and oss-rebuild.txt is printed to stdout on return.

    Writes: oss-rebuild.txt

    Returns dict with keys:
        available     (bool): any data exists for this package
        exact_found   (bool): data for this exact version is in the bucket
        exact_verdict (str | None): 'PASS', 'FAIL', or None
        older_found   (bool): data for other versions exists
        older_any_pass (bool): at least one sampled older version passed
        older_any_fail (bool): at least one sampled older version failed
        signal        (str): human-readable one-line summary
        signal_level  (str): 'NONE' | 'MILD_POSITIVE' | 'POSITIVE'
                             | 'MILD_NEGATIVE' | 'NEGATIVE' | 'REGRESSION'

    Quick invocation (no work dir needed):
        python3 -c "
        import sys; sys.path.insert(0, 'references/scripts')
        import analysis_shared as shared
        shared.lookup_oss_rebuild('pypi', 'absl-py', '2.0.0')
        "

    Or via __main__ (from the references/scripts directory):
        python3 analysis_shared.py pypi absl-py 2.0.0
    """
    import tempfile as _tempfile
    _tmpdir = None
    if work is None:
        _tmpdir = _tempfile.TemporaryDirectory()
        work = Path(_tmpdir.name)
    result: dict = {
        'available': False,
        'exact_found': False,
        'exact_verdict': None,
        'older_found': False,
        'older_any_pass': False,
        'older_any_fail': False,
        'signal': 'No OSS Rebuild data for this ecosystem/package.',
        'signal_level': 'NONE',
    }
    lines: list[str] = [
        f'=== OSS Rebuild reproducibility: {pkgname} {version} ===',
        '',
        'OSS Rebuild independently rebuilds packages and checks whether the',
        'result matches the artifact published to the registry.  See docs/oss-rebuild.md.',
        '',
    ]

    if not oss_rebuild_ecosystem:
        lines.append('OSS_REBUILD: SKIPPED (no ecosystem identifier)')
        (work / 'oss-rebuild.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return result

    pkg_key = _oss_rebuild_pkg_key(oss_rebuild_ecosystem, pkgname)
    lines.append(f'ECOSYSTEM  : {oss_rebuild_ecosystem}')
    lines.append(f'PACKAGE_KEY: {pkg_key}')
    lines.append(f'VERSION    : {version}')
    lines.append('')

    # Step 1: list all versions in the bucket for this package.
    all_versions = _oss_rebuild_list_versions(oss_rebuild_ecosystem, pkg_key)
    lines.append(f'VERSIONS_IN_BUCKET: {len(all_versions)}')
    if all_versions:
        shown = all_versions[:20]
        lines.append('  ' + '  '.join(shown) + ('  ...' if len(all_versions) > 20 else ''))
    lines.append('')

    if not all_versions:
        lines.append('OSS_REBUILD: NO_DATA')
        lines.append(
            'No data for this package.  Either the ecosystem is not yet covered or '
            'this package was not included in the bulk run.'
        )
        (work / 'oss-rebuild.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return result

    result['available'] = True
    exact_found = version in all_versions
    result['exact_found'] = exact_found
    result['older_found'] = len(all_versions) > (1 if exact_found else 0)

    # Step 2: check exact version verdict.
    if exact_found:
        exact_verdict = _oss_rebuild_version_verdict(oss_rebuild_ecosystem, pkg_key, version)
        result['exact_verdict'] = exact_verdict
        lines.append(f'EXACT_VERSION_VERDICT: {exact_verdict or "UNDETERMINED"}')
    else:
        lines.append('EXACT_VERSION_VERDICT: NOT_IN_BUCKET (absent = unknown, not failed)')

    # Step 3: sample other versions for track record / regression check.
    if result['older_found']:
        older_any_pass, older_any_fail = _oss_rebuild_sample_other_versions(
            oss_rebuild_ecosystem, pkg_key, all_versions, version,
        )
        result['older_any_pass'] = older_any_pass
        result['older_any_fail'] = older_any_fail
        track = []
        if older_any_pass:
            track.append('some pass')
        if older_any_fail:
            track.append('some fail')
        lines.append(f'OTHER_VERSIONS_SAMPLE: {", ".join(track) or "all undetermined"}')
    lines.append('')

    # Step 4: determine signal.
    ev = result['exact_verdict']
    if exact_found and ev == 'PASS':
        result['signal_level'] = 'POSITIVE'
        result['signal'] = (
            f'Version {version} REPRODUCED. '
            'Any malicious code in the compiled artifact is also visible in the source; '
            'one attack vector is closed.'
        )
    elif exact_found and ev == 'FAIL' and result['older_any_pass']:
        result['signal_level'] = 'REGRESSION'
        result['signal'] = (
            f'Version {version} FAILED to reproduce, but older versions DID. '
            'This regression is a classic supply chain attack pattern. '
            'Deeper analysis strongly recommended.'
        )
    elif exact_found and ev == 'FAIL':
        result['signal_level'] = 'NEGATIVE'
        result['signal'] = (
            f'Version {version} FAILED to reproduce. '
            'Build environment differences are a common non-malicious cause. '
            'Mildly negative; consider deeper analysis.'
        )
    elif not exact_found and result['older_any_pass']:
        result['signal_level'] = 'MILD_POSITIVE'
        result['signal'] = (
            f'Version {version} not yet evaluated by OSS Rebuild, '
            'but other versions reproduce. '
            'Mildly positive track record; does not confirm this version is clean.'
        )
    elif not exact_found and result['older_any_fail']:
        result['signal_level'] = 'MILD_NEGATIVE'
        result['signal'] = (
            f'Version {version} not yet evaluated by OSS Rebuild; '
            'other versions also do not reproduce. '
            'Project does not prioritize reproducible builds.'
        )
    # else: data exists but all verdicts undetermined -> leave NONE

    lines.append(f'SIGNAL_LEVEL: {result["signal_level"]}')
    lines.append(f'SIGNAL: {result["signal"]}')
    txt = '\n'.join(lines) + '\n'
    (work / 'oss-rebuild.txt').write_text(txt, encoding='utf-8')
    if _tmpdir is not None:
        print(txt, end='')
        _tmpdir.cleanup()
    return result


# ---------------------------------------------------------------------------
# Ecosystem hooks contract
# ---------------------------------------------------------------------------

class EcosystemHooks(ABC):
    """Abstract base class for ecosystem-specific analysis hooks.

    Subclass this in each hooks_<ecosystem>.py module. Instantiate with the
    registry URL (if using a private registry) and call methods directly.

    Required class attributes (set as class-level variables in each subclass):
        ECOSYSTEM            Short name, e.g. 'ruby', 'python'.
        LOCKFILE_NAME        Single lockfile filename, or None if the ecosystem
                             uses multiple formats (see LOCKFILE_NAMES).
        MANIFEST_FILE        Canonical manifest filename written to the work dir.
        DANGEROUS_WHAT       Human-readable description of DANGEROUS_PATTERNS.
        DANGEROUS_PATTERNS   list[tuple[str, str]] of (label, regex) pairs.
        DIFF_PATTERNS        list[tuple[str, str]] of (label, regex) pairs.
    """

    ECOSYSTEM: str
    LOCKFILE_NAME: str | None
    MANIFEST_FILE: str
    DANGEROUS_WHAT: str
    DANGEROUS_PATTERNS: list[tuple[str, str]]
    DIFF_PATTERNS: list[tuple[str, str]]
    OSV_ECOSYSTEM: str
    OSS_REBUILD_ECOSYSTEM: str

    def __init__(self, registry_url: str | None = None) -> None:
        self.registry_url = registry_url

    @abstractmethod
    def get_lockfile_path(self, project_root: Path) -> Path: ...

    @abstractmethod
    def download_new(
        self, pkgname: str, version: str, work: Path, failures: list[str],
    ) -> dict: ...

    @abstractmethod
    def read_manifest(
        self, pkgname: str, version: str, unpacked_dir: Path,
        work: Path, failures: list[str],
    ) -> dict: ...

    @abstractmethod
    def download_old(
        self, pkgname: str, old_ver: str, work: Path, failures: list[str],
    ) -> dict: ...

    @abstractmethod
    def get_old_license(
        self, pkgname: str, old_ver: str, old_unpacked_dir: Path,
    ) -> str | None: ...

    @abstractmethod
    def get_old_dep_lines(
        self, pkgname: str, old_ver: str, old_result: dict,
    ) -> list[str]: ...

    @abstractmethod
    def fetch_all_registry_data(
        self, pkgname: str, version: str, work: Path,
    ) -> dict: ...

    @abstractmethod
    def check_lockfile(
        self, runtime_dep_lines: list[str], old_dep_lines: list[str],
        project_root: Path,
    ) -> dict: ...

    @abstractmethod
    def check_dep_registry(self, dep_name: str) -> dict: ...

    @abstractmethod
    def get_transitive_deps(
        self, pkgname: str, version: str, lockfile_path: Path, work: Path,
    ) -> dict: ...

    @abstractmethod
    def check_alternatives(
        self, pkgname: str, version: str, work: Path, project_root: Path,
    ) -> dict: ...

    @abstractmethod
    def get_diff_excludes(self) -> list[str]: ...

    @abstractmethod
    def get_pkg_src_excludes(self) -> tuple[re.Pattern, re.Pattern]: ...

    @abstractmethod
    def find_source_root(self, source_dir: Path) -> Path: ...

    @abstractmethod
    def get_deep_source_config(self) -> dict: ...

    @abstractmethod
    def reproducible_build(
        self, pkgname: str, version: str, work: Path, sandbox: str,
    ) -> tuple[str, int, int]: ...


# ---------------------------------------------------------------------------
# Library-import usage examples
# ---------------------------------------------------------------------------
# analysis_shared.py is a library; use dep_review.py for dependency analysis.
#
# To try individual functions from a Python REPL or one-liner:
#
#   from references.scripts.analysis_shared import lookup_oss_rebuild
#   lookup_oss_rebuild('pypi', 'absl-py', '2.0.0')
#
# Or from the references/scripts directory:
#
#   python3 -c "from analysis_shared import lookup_oss_rebuild; lookup_oss_rebuild('pypi','absl-py','2.0.0')"
#   python3 -c "from analysis_shared import lookup_oss_rebuild; lookup_oss_rebuild('npm','lodash','4.18.1')"
#
# lookup_oss_rebuild prints oss-rebuild.txt to stdout when no work dir is given.
if __name__ == '__main__':
    import sys as _sys
    print(
        'analysis_shared.py is a library, not a standalone script.\n'
        'For dependency analysis, use: dep_review.py\n'
        '\n'
        'To try a function interactively:\n'
        '  python3 -c "from analysis_shared import lookup_oss_rebuild;'
        " lookup_oss_rebuild('pypi','absl-py','2.0.0')\"",
        file=_sys.stderr,
    )
    _sys.exit(1)
