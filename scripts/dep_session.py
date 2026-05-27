#!/usr/bin/env python3
# dep_session.py: BFS queue and state manager for dependency analysis sessions.
#
# Requires Python 3.10+.
#
# This script tracks the analysis queue, analyzed packages, depth threshold,
# and CRITICAL propagation so the orchestrating AI never has to maintain state.
# The AI's only job is: make security judgments, write assessment.md
# and verdict.json, call "dep_session.py complete" with its verdict.
#
# Subcommands:
#   init              Create a new session from the project lockfile.
#   complete          Mark a package analyzed; enqueue new transitive deps; print NEXT_ACTION.
#   resolve           Resolve unknown version for a queued package, then print NEXT_ACTION.
#   confirm-depth     User confirmed the large-footprint warning; continue.
#   abort             Mark session aborted with a reason.
#   status            Print current state and NEXT_ACTION without changing anything.
#   deeper-done       Mark a MEDIUM-risk package as having completed --deeper analysis.
#   generate-manifest Regenerate the install manifest from current session state.
#   env-check         Check for optional install-probe tools; suggest any missing ones.
#   ecosystem-detect  Detect ecosystems in project root; check analyzer availability.
#   diff-packages     Compare lockfile versions between git states; print changed packages.
#   report            Generate Phase 3 summary cards from all analyzed packages.
#   wrap-up           Generate the session report file.
#   record-install    Append an installation record to the session report.
#   vuln-audit        Run the ecosystem's vulnerability auditor; format two-group output.
#   follow-on         Bucket remaining outdated packages into A/B/C/D.
#   health-scan       Fetch health metadata for all installed packages; print triage table.
#
# Workflow:
#   dep_session.py init --from REGISTRY --root DIR [--update N O N] [--new N V]
#   → prints NEXT_ACTION: ANALYZE with the exact dep_review.py command to run
#
#   (sub-agent runs dep_review.py --session FILE ... ; makes security judgment;
#    writes assessment.md and verdict.json)
#
#   dep_session.py complete SESSION PKGNAME VERSION RECOMMENDATION RISK
#   → updates session, enqueues newly discovered deps, prints NEXT_ACTION
#
#   (repeat until NEXT_ACTION: SESSION_COMPLETE)
#
# Python stdlib only; no third-party packages required.
# Requires Python 3.10+ (enforced by dep_review.py; dep_session.py follows suit).

import sys

if sys.version_info < (3, 10):
    sys.exit(f'dep_session.py requires Python 3.10 or later (running {sys.version})')

import argparse
import json
import os
import re
import secrets
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import analysis_shared as shared

SESSION_VERSION = 1
DEPTH_THRESHOLD = 10
VALID_RECOMMENDATIONS = frozenset({
    'APPROVE', 'APPROVE_WITH_CAUTION', 'REVIEW_MANUALLY', 'DO_NOT_INSTALL',
})

# Defense-in-depth: reject any queued dep name that contains shell-special
# characters, regardless of which ecosystem hook produced it. This catches
# malformed names that slip past ecosystem-level validation or a hook bug.
# Covers npm, PyPI, RubyGems, Maven (group:artifact), and CPAN (Foo::Bar).
# ':' is not a shell metacharacter in argument position, so it is safe to allow.
# Shell injection is not a risk: all subprocess calls use list form (never
# shell=True), so special chars cannot inject into commands. Path traversal
# via '/' is separately neutralized by safe_dir_component.
# All subprocess calls that take a package name or version also use '--'
# to explicitly terminate option processing, providing defense-in-depth
# that is portable across platforms and independent of this regex.
_DEP_NAME_RE = re.compile(r'^[@A-Za-z0-9][A-Za-z0-9._/:-]{0,213}$')
# Allows semver, pre-release (+/-/alpha/beta), and build metadata.
# Excludes spaces, '--', and other text that could confuse arg parsers.
_RE_SAFE_VER = re.compile(r'^[0-9][A-Za-z0-9._+\-]{0,100}$')
VALID_RISKS = frozenset({'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})

# Shell command to install approved packages, per ecosystem.
# {packages} is replaced with a space-separated list of package names.
ECOSYSTEM_INSTALL_CMD: dict[str, str] = {
    'rubygems': 'bundle update {packages}',
    'pypi':     'python3 -m pip install --upgrade {packages}',
    'npm':      'npm update {packages}',
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _pkg_key(name: str, version: str | None) -> str:
    """Return a lowercase 'name@version' key for use in session dicts.

    >>> _pkg_key('Foo', '1.0')
    'foo@1.0'
    >>> _pkg_key('Bar', None)
    'bar@?'
    """
    return f'{name.lower()}@{version or "?"}'


def load_session(path: Path) -> dict:
    """Load and validate a session file; exit with a message on any error.

    Exits if the file is missing, not valid JSON, or carries a different
    SESSION_VERSION than this tool expects (prevents silent mis-parses when
    the schema changes between releases).
    """
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        sys.exit(f'Session file not found: {path}')
    except json.JSONDecodeError as e:
        sys.exit(f'Session file is not valid JSON ({path}): {e}')
    if data.get('session_version') != SESSION_VERSION:
        sys.exit(
            f'Session version mismatch: file has {data.get("session_version")!r}, '
            f'expected {SESSION_VERSION}'
        )
    return data


def save_session(path: Path, session: dict) -> None:
    """Write session dict to path as indented JSON (overwrites any existing file)."""
    path.write_text(json.dumps(session, indent=2) + '\n', encoding='utf-8')


# ---------------------------------------------------------------------------
# Lockfile baseline reader
# ---------------------------------------------------------------------------

def _read_lockfile_baseline(root: Path, registry: str) -> list[str]:
    """Return lowercase package names already present in the project lockfile.

    These are treated as "already accepted" and skipped during BFS.
    """
    # Ruby: Gemfile.lock
    if registry == 'rubygems':
        lockfile = root / 'Gemfile.lock'
        if lockfile.is_file():
            names: list[str] = []
            in_specs = False
            for line in lockfile.read_text(encoding='utf-8', errors='replace').splitlines():
                if line.strip() == 'specs:':
                    in_specs = True
                    continue
                if in_specs:
                    m = re.match(r'^    ([A-Za-z0-9_\-\.]+)\s', line)
                    if m:
                        names.append(m.group(1).lower())
                    elif line and not line[0].isspace():
                        in_specs = False  # end of this specs block; keep scanning for more
            return names

    # Python: uv.lock / poetry.lock (TOML [[package]] sections), then requirements.txt
    if registry == 'pypi':
        for lockname in ('uv.lock', 'poetry.lock'):
            lockfile = root / lockname
            if lockfile.is_file():
                names: list[str] = []
                for line in lockfile.read_text(encoding='utf-8', errors='replace').splitlines():
                    m = re.match(r'^name\s*=\s*"([A-Za-z0-9._-]{1,200})"', line)
                    if m:
                        names.append(re.sub(r'[-_.]+', '-', m.group(1)).lower())
                return names
        req = root / 'requirements.txt'
        if req.is_file():
            names = []
            for line in req.read_text(encoding='utf-8', errors='replace').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]{0,199})', line)
                if m:
                    names.append(re.sub(r'[-_.]+', '-', m.group(1)).lower())
            return names

    # JavaScript: package-lock.json (v2/v3 'packages' or v1 'dependencies')
    if registry == 'npm':
        lockfile = root / 'package-lock.json'
        if lockfile.is_file():
            try:
                data = json.loads(lockfile.read_text(encoding='utf-8', errors='replace'))
                names = []
                pkg_map: dict = data.get('packages', {})
                if pkg_map:
                    # v2/v3: keys are paths like "node_modules/foo" or
                    # "node_modules/@scope/bar"; skip nested and the root ""
                    for key in pkg_map:
                        if not key.startswith('node_modules/'):
                            continue
                        pkg = key[len('node_modules/'):]
                        # Nested dep path: "node_modules/foo/node_modules/bar"
                        tail = pkg.lstrip('@')
                        if '/' in tail:
                            continue
                        names.append(pkg.lower())
                else:
                    for key in data.get('dependencies', {}):
                        names.append(key.lower())
                return names
            except (json.JSONDecodeError, ValueError):
                pass
        yarn = root / 'yarn.lock'
        if yarn.is_file():
            names = []
            for line in yarn.read_text(encoding='utf-8', errors='replace').splitlines():
                # Entry header: "foo@^1.0", "foo@^1.0, foo@^1.1":, or @scope/pkg@ver:
                m = re.match(r'^"?(@?[A-Za-z0-9][A-Za-z0-9._/-]{0,213})@', line)
                if m and line.rstrip().endswith(':'):
                    names.append(m.group(1).lower())
            return names

    return []


# ---------------------------------------------------------------------------
# Version resolution (network, stdlib only)
# ---------------------------------------------------------------------------

def _fetch_version_json(url: str) -> dict:
    """Fetch a registry JSON endpoint; return parsed dict or raise on error."""
    req = urllib.request.Request(url, headers={'User-Agent': 'dep_session/1 (security-review)'})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        return json.loads(resp.read().decode('utf-8', errors='replace'))


def _resolve_rubygems(name: str, registry_url: str | None) -> str | None:
    base = (registry_url or 'https://rubygems.org').rstrip('/')
    try:
        data = _fetch_version_json(f'{base}/api/v1/gems/{name}.json')
        v = str(data.get('version', '')).strip()
        return v or None
    except Exception:
        return None


def _resolve_pypi(name: str, registry_url: str | None) -> str | None:
    base = (registry_url or 'https://pypi.org').rstrip('/')
    try:
        data = _fetch_version_json(f'{base}/pypi/{name}/json')
        v = str(data.get('info', {}).get('version', '')).strip()
        return v or None
    except Exception:
        return None


def _resolve_npm(name: str, registry_url: str | None) -> str | None:
    base = (registry_url or 'https://registry.npmjs.org').rstrip('/')
    # Scoped packages (@scope/name) include '/' in the URL path; the npm
    # registry API accepts them unencoded (e.g. /@scope/name/latest).
    try:
        data = _fetch_version_json(f'{base}/{name}/latest')
        v = str(data.get('version', '')).strip()
        return v or None
    except Exception:
        return None


def resolve_version(name: str, registry: str, registry_url: str | None = None) -> str | None:
    """Query the registry for the current published version of a package."""
    if registry == 'rubygems':
        return _resolve_rubygems(name, registry_url)
    if registry == 'pypi':
        return _resolve_pypi(name, registry_url)
    if registry == 'npm':
        return _resolve_npm(name, registry_url)
    return None


# ---------------------------------------------------------------------------
# NEXT_ACTION printer
# ---------------------------------------------------------------------------

def generate_manifest(session: dict, session_path: Path) -> Path:
    """Generate the human-review install manifest and return its path.

    - APPROVE / LOW or MEDIUM(deeper done): active install line
    - REVIEW_MANUALLY / HIGH: commented-out line with explanation
    - DO_NOT_INSTALL / CRITICAL: omitted (session should be aborted already)
    - MEDIUM needing deeper: commented-out with note to run deeper first
    """
    root = Path(session['project_root'])
    registry = session['registry']
    analyzed: dict = session.get('analyzed', {})
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')

    install_cmd_tpl = ECOSYSTEM_INSTALL_CMD.get(registry, 'install {packages}')

    lines: list[str] = []
    lines.append(f'# Dependency install manifest: {today}')
    lines.append('# Generated by dep_session.py after AI security analysis.')
    lines.append('#')
    lines.append('# HUMAN REVIEW REQUIRED before running the install command:')
    lines.append('#   - Read the AI recommendation and risk for each package.')
    lines.append('#   - cat any assessment.md listed below for full detail.')
    lines.append('#   - Remove a package from the install command if you do not approve it.')
    lines.append('#   - This file, once committed, is the record of human approval.')
    lines.append('#')

    approved_names: list[str] = []
    detail_lines: list[str] = []
    flagged_lines: list[str] = []

    for key, v in analyzed.items():
        name = v['name']
        version = v['version']
        rec = v.get('recommendation', 'UNKNOWN')
        risk = v.get('risk', 'UNKNOWN')
        deeper_needed = v.get('deeper_needed', False)
        deeper_done = v.get('deeper_done', False)
        itc = ' [INSTALL-TIME CODE: verify extconf.rb/setup.py]' if v.get('install_time_code') else ''
        report_path = f'temp/dep-review/{shared.safe_dir_component(name, version)}/assessment.md'

        if rec == 'DO_NOT_INSTALL' or risk == 'CRITICAL':
            flagged_lines.append(f'#   {name} {version}  OMITTED: {rec} / {risk} risk (DO NOT install)')
            continue

        if risk == 'HIGH' or rec == 'REVIEW_MANUALLY':
            flagged_lines.append(f'#   {name} {version}  HIGH RISK / {rec}: human review required before approving')
            flagged_lines.append(f'#     Detail: {report_path}')
            detail_lines.append(f'#   {name} {version}  recommend {rec} / {risk} risk{itc}')
            detail_lines.append(f'#     Detail: {report_path}')
            continue

        if deeper_needed and not deeper_done:
            flagged_lines.append(f'#   {name} {version}  MEDIUM risk: --deeper analysis required before approving')
            flagged_lines.append(f'#     Run: python3 temp/dep-review/scripts/dep_review.py --from {registry} --deeper --root . {name} {version}')
            flagged_lines.append(f'#     Then: python3 temp/dep-review/scripts/dep_session.py deeper-done temp/dep-review/session.json {name} {version}')
            continue

        # Approved: LOW (or MEDIUM after deeper)
        approved_names.append(name)
        detail_lines.append(f'#   {name} {version}  recommend {rec} / {risk} risk{itc}')
        detail_lines.append(f'#     Detail: {report_path}')

    lines.append('# AI recommendations:')
    lines.extend(detail_lines)
    if flagged_lines:
        lines.append('#')
        lines.append('# Packages requiring additional human review (excluded from install command):')
        lines.extend(flagged_lines)
    lines.append('#')

    if approved_names:
        pkg_str = ' '.join(approved_names)
        install_cmd = install_cmd_tpl.format(packages=pkg_str)
        lines.append('# Run this command to install approved packages:')
        lines.append(install_cmd)
    else:
        lines.append('# No packages are ready to install yet.')
        lines.append('# Resolve flagged packages above, then re-run: dep_session.py generate-manifest')

    manifest_path = root / 'temp' / 'dep-review' / 'install-manifest.txt'
    manifest_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return manifest_path


def print_next_action(session: dict, session_path: Path) -> None:
    """Print the machine-readable NEXT_ACTION block.

    The orchestrating agent reads this after every dep_session.py call and
    follows the instruction exactly; no state tracking required on its part.
    """
    # Scripts live wherever this file lives; use that path directly.
    scripts = Path(__file__).parent.resolve()
    try:
        scripts_rel = scripts.relative_to(Path.cwd())
    except ValueError:
        scripts_rel = scripts
    try:
        session_rel = session_path.relative_to(Path.cwd())
    except ValueError:
        session_rel = session_path
    registry = session['registry']
    ru = session.get('registry_url')
    registry_url_flag = f' --registry-url {ru}' if ru else ''
    _tok = session.get('next_action_token')
    _tok_part = f'/{_tok}' if _tok else ''

    analyzed: dict = session.get('analyzed', {})
    queue: list[dict] = session.get('queue', [])
    new_count: int = session.get('total_new_to_lockfile', 0)
    threshold: int = session.get('depth_threshold', DEPTH_THRESHOLD)
    depth_confirmed: bool = session.get('depth_confirmed', False)

    print()
    print('=== SESSION STATUS ===')
    print(f'Analyzed        : {len(analyzed)} package(s)')
    print(f'Queued          : {len(queue)} package(s)')
    print(f'New to lockfile : {new_count} (confirmation threshold: {threshold})')
    critical_count = sum(1 for v in analyzed.values() if v.get('risk') == 'CRITICAL')
    if critical_count:
        print(f'CRITICAL        : {critical_count} finding(s)')
    print()

    # --- ABORTED ---
    if session.get('aborted'):
        print(f'=== NEXT_ACTION{_tok_part}: ABORTED_CRITICAL ===')
        print(f'Reason: {shared.sanitize_line(session.get("abort_reason", "unknown"))}')
        print()
        print('DO NOT install ANY package in this session, including the package')
        print('that introduced the problematic dependency.')
        print('Report all findings to the user immediately.')
        return

    # --- DEEPER ANALYSIS REQUIRED for a just-completed MEDIUM package ---
    # Check if the most recently analyzed package needs --deeper before we proceed.
    deeper_pending = [
        v for v in analyzed.values()
        if v.get('deeper_needed') and not v.get('deeper_done')
    ]
    if deeper_pending:
        v = deeper_pending[0]  # handle one at a time
        name = v['name']
        version = v['version']
        registry = session['registry']
        ru = session.get('registry_url')
        registry_url_flag = f' --registry-url {ru}' if ru else ''
        sname = shared.sanitize_line(name)
        sversion = shared.sanitize_line(version)
        _droot = Path(session['project_root'])
        _dwork = _droot / 'temp' / 'dep-review' / shared.safe_dir_component(name, version)
        try:
            _dwork_rel = _dwork.relative_to(Path.cwd())
        except ValueError:
            _dwork_rel = _dwork
        print(f'=== NEXT_ACTION{_tok_part}: RUN_DEEPER ===')
        print(f'Package  : {sname} {sversion}')
        print(f'Work dir : {_dwork_rel}')
        print('Reason   : MEDIUM risk requires reproducible-build verification before approval.')
        print()
        print('Step 1: run deeper analysis:')
        print(f'  python3 {scripts_rel}/dep_review.py'
              f' --from {registry}{registry_url_flag} --deeper --root . {sname} {sversion}')
        print()
        print('Step 2: read updated signals, update assessment and verdict:')
        print(f'  Read  : {_dwork_rel}/signals.json (see deeper_analysis section)')
        print(f'  Update: {_dwork_rel}/assessment.md (fill deeper-analysis [TODO] placeholders)')
        print(f'  Update: {_dwork_rel}/verdict.json (revise if verdict changes)')
        print()
        print('Step 3: record deeper result:')
        print(f'  python3 {scripts_rel}/dep_session.py deeper-done {session_rel} {sname} {sversion}')
        return

    # --- COMPLETE ---
    if not queue:
        bad = [k for k, v in analyzed.items() if v.get('recommendation') == 'DO_NOT_INSTALL']
        print(f'=== NEXT_ACTION{_tok_part}: SESSION_COMPLETE ===')
        if bad:
            print(f'WARNING: {len(bad)} package(s) flagged DO_NOT_INSTALL:')
            for k in bad:
                v = analyzed[k]
                print(f'  {k}: recommend {v.get("recommendation")} / {v.get("risk")} risk')
            print()
            print('Do NOT proceed to Phase 4 (install) without resolving these.')
        else:
            print('All packages analyzed. No blocking findings.')
        print()
        print('Full results:')
        for key, v in analyzed.items():
            itc = ' [INSTALL-TIME CODE]' if v.get('install_time_code') else ''
            deeper_note = ' [DEEPER DONE]' if v.get('deeper_done') else (
                          ' [DEEPER NEEDED]' if v.get('deeper_needed') else '')
            print(f'  {key}: recommend {v.get("recommendation", "UNKNOWN")} / '
                  f'{v.get("risk", "UNKNOWN")} risk{itc}{deeper_note}')
        print()
        manifest_path = generate_manifest(session, session_path)
        print(f'Install manifest : {manifest_path}')
        print()
        print('Next steps:')
        print('  1. Review the manifest (cat the file above).')
        print('  2. cat any assessment.md files you want to inspect.')
        print('  3. Edit the manifest to remove any packages you do not approve.')
        print('  4. Run the install command at the bottom of the manifest.')
        print('  5. Commit the manifest and lockfile changes together.')
        return

    # --- DEPTH CONFIRMATION NEEDED ---
    if new_count > threshold and not depth_confirmed:
        baseline = set(session.get('lockfile_baseline', []))
        print(f'=== NEXT_ACTION{_tok_part}: CONFIRM_DEPTH ===')
        print(f'New packages not in original lockfile: {new_count} (threshold: {threshold})')
        print()
        print('Newly discovered packages (analyzed + queued):')
        for v in analyzed.values():
            if v['name'].lower() not in baseline:
                print(f'  [done]   {shared.sanitize_line(v["name"])} {shared.sanitize_line(v["version"])} '
                      f'recommend {v.get("recommendation", "?")} / {v.get("risk", "?")} risk'
                      f' via {shared.sanitize_line(v.get("introduced_by", "?"))}')
        for entry in queue:
            if entry['name'].lower() not in baseline:
                print(f'  [queued] {shared.sanitize_line(entry["name"])} {shared.sanitize_line(entry.get("version", "?"))} '
                      f'via {shared.sanitize_line(entry.get("introduced_by", "?"))}')
        print()
        print('TELL USER:')
        print(f'  "This dependency set has introduced {new_count} packages not currently')
        print('  in your lockfile. That is a large transitive footprint and a risk signal.')
        print('  Continue analyzing all of them, or stop and reconsider the root dependency?"')
        print()
        print(f'If user says continue : python3 {scripts_rel}/dep_session.py confirm-depth {session_rel}')
        print(f'If user says stop     : python3 {scripts_rel}/dep_session.py abort {session_rel} "user declined large footprint"')
        return

    # --- NEXT PACKAGE ---
    next_pkg = queue[0]
    name = next_pkg['name']
    version = next_pkg.get('version')
    old_version = next_pkg.get('old_version')
    mode = next_pkg.get('mode', 'NEW')
    introduced_by = next_pkg.get('introduced_by', 'user request')

    # --- VERSION UNKNOWN ---
    if version is None:
        sname = shared.sanitize_line(name)
        print(f'=== NEXT_ACTION{_tok_part}: RESOLVE_VERSION ===')
        print(f'Package      : {sname}')
        print(f'Mode         : {mode}')
        print(f'Introduced by: {shared.sanitize_line(introduced_by)}')
        print('Version      : UNKNOWN (registry lookup required)')
        print()
        print(f'Run: python3 {scripts_rel}/dep_session.py resolve {session_rel} {sname}')
        print('(This will query the registry, update the session, and print the next command.)')
        return

    # --- ANALYZE ---
    sname = shared.sanitize_line(name)
    sversion = shared.sanitize_line(version)
    mode_flags = '--alternatives --basic' if mode == 'NEW' else '--basic'
    old_flag = f' --old {old_version}' if old_version else ''
    # --session is omitted: dep_review.py defaults to ROOT/temp/dep-review/session.json
    cmd = (
        f'python3 {scripts_rel}/dep_review.py'
        f' --from {registry}{registry_url_flag}'
        f' {mode_flags}{old_flag}'
        f' --root .'
        f' {sname} {sversion}'
    )

    _aroot = Path(session['project_root'])
    _awork = _aroot / 'temp' / 'dep-review' / shared.safe_dir_component(name, version)
    try:
        _awork_rel = _awork.relative_to(Path.cwd())
    except ValueError:
        _awork_rel = _awork
    print(f'=== NEXT_ACTION{_tok_part}: ANALYZE ===')
    print(f'Package      : {sname}')
    print(f'Version      : {sversion}')
    print(f'Mode         : {mode}' + (f' (was {old_version})' if old_version else ''))
    print(f'Introduced by: {shared.sanitize_line(introduced_by)}')
    print(f'Work dir     : {_awork_rel}')
    print()
    print('Step 1: run analysis:')
    print(f'  {cmd}')
    print()
    print('Step 2: pre-fill assessment.md, fill judgment, write verdict.json')
    prefill_cmd = (
        f'python3 {scripts_rel}/dep_session.py pre-fill-assessment'
        f' --session {session_rel} -- {sname} {sversion}'
    )
    print(f'  {prefill_cmd}')
    print(f'  Creates: {_awork_rel}/assessment.md'
          f'  (open it; fill every [TODO: ...] placeholder)')
    print(f'  Write  : {_awork_rel}/verdict.json'
          f'  (summary, risk_increasing, risk_decreasing)')
    print()
    print('Step 3: record verdict:')
    _token_flag = f' --token {_tok}' if _tok else ''
    print(f'  python3 {scripts_rel}/dep_session.py complete{_token_flag} -- {session_rel} \\')
    print(f'    {sname} {sversion} RECOMMENDATION RISK')
    print()
    print('  RECOMMENDATION: APPROVE | APPROVE_WITH_CAUTION | REVIEW_MANUALLY | DO_NOT_INSTALL')
    print('  RISK          : LOW | MEDIUM | HIGH | CRITICAL')


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    session_path = (Path(args.session).resolve() if args.session
                    else root / 'temp' / 'dep-review' / 'session.json')
    session_path.parent.mkdir(parents=True, exist_ok=True)

    registry = args.registry
    registry_url = getattr(args, 'registry_url', None)
    if registry_url and not registry_url.startswith('https://'):
        sys.exit('--registry-url must use https://')

    baseline = _read_lockfile_baseline(root, registry)

    queue: list[dict] = []
    for item in (args.update or []):
        name, old_ver, new_ver = item
        queue.append({
            'name': name, 'version': new_ver, 'old_version': old_ver,
            'mode': 'UPDATE', 'introduced_by': 'user request',
        })
    for item in (args.new or []):
        name, version = item
        queue.append({
            'name': name, 'version': version, 'old_version': None,
            'mode': 'NEW', 'introduced_by': 'user request',
        })

    if not queue:
        sys.exit('No packages queued. Use --update NAME OLD NEW or --new NAME VERSION.')

    session: dict = {
        'session_version': SESSION_VERSION,
        'created_at': _now(),
        'registry': registry,
        'registry_url': registry_url,
        'project_root': str(root),
        'lockfile_baseline': baseline,
        'queue': queue,
        'analyzed': {},
        'total_new_to_lockfile': 0,
        'depth_threshold': DEPTH_THRESHOLD,
        'depth_confirmed': False,
        'aborted': False,
        'abort_reason': None,
        # Mitigates instruction-mimicry attacks: a malicious package cannot
        # forge a valid NEXT_ACTION/{token}: ... line without knowing this
        # value. The `complete --token` argument enforces this at the script
        # level (see cmd_complete), independent of AI judgment.
        'next_action_token': secrets.token_hex(8),
    }
    save_session(session_path, session)
    print(f'Session created : {session_path}')
    print(f'Lockfile baseline : {len(baseline)} packages')
    print(f'Initial queue     : {len(queue)} package(s)')
    print_next_action(session, session_path)


def cmd_complete(args: argparse.Namespace) -> None:
    session_path = Path(args.session).resolve()
    session = load_session(session_path)

    name = args.pkgname
    version = args.version
    recommendation = args.recommendation.upper()
    risk = args.risk.upper()

    if recommendation not in VALID_RECOMMENDATIONS:
        sys.exit(f'Invalid RECOMMENDATION: {recommendation!r}\n'
                 f'Must be one of: {", ".join(sorted(VALID_RECOMMENDATIONS))}')
    if risk not in VALID_RISKS:
        sys.exit(f'Invalid RISK: {risk!r}\n'
                 f'Must be one of: {", ".join(sorted(VALID_RISKS))}')

    # Token verification: prevents malicious package content from embedding
    # fake `complete` calls that a sub-agent might execute blindly. The token
    # is unknown to content inside the reviewed package.
    _expected_token = session.get('next_action_token')
    _provided_token = getattr(args, 'token', None)
    if _expected_token:
        if not _provided_token:
            sys.exit(
                'This session requires --token TOKEN.\n'
                'Use the token from the === NEXT_ACTION/TOKEN: ... === line.'
            )
        if _provided_token != _expected_token:
            sys.exit(
                'Token mismatch: provided token does not match session.\n'
                'Use the token from the === NEXT_ACTION/TOKEN: ... === line.'
            )

    key = _pkg_key(name, version)

    # Read session-update.json written by dep_review.py --session
    root = Path(session['project_root'])
    work = root / 'temp' / 'dep-review' / shared.safe_dir_component(name, version)
    # Enforce adversarial gate deterministically: if dep_review.py flagged
    # adversarial content, override whatever the sub-agent submitted.
    # This means a compromised sub-agent cannot approve a package that the
    # deterministic gate already rejected, regardless of what it returns.
    _abort_flag = work / 'adversarial-abort.flag'
    if _abort_flag.exists():
        if recommendation != 'DO_NOT_INSTALL' or risk != 'CRITICAL':
            print(
                f'WARNING: adversarial gate was triggered for {name} {version}. '
                f'Sub-agent verdict ({recommendation}/{risk}) overridden to '
                f'DO_NOT_INSTALL/CRITICAL.',
                file=sys.stderr,
            )
        recommendation = 'DO_NOT_INSTALL'
        risk = 'CRITICAL'
    update_file = work / 'session-update.json'
    new_dep_names: list[str] = []
    alternatives_critical = False
    install_time_code = False
    install_time_code_reason = ''
    concern_level = 'NONE'

    if update_file.is_file():
        try:
            upd = json.loads(update_file.read_text(encoding='utf-8'))
            new_dep_names = upd.get('not_in_lockfile', [])
            alternatives_critical = upd.get('alternatives_critical', False)
            install_time_code = upd.get('install_time_code', False)
            install_time_code_reason = upd.get('install_time_code_reason', '')
            concern_level = upd.get('concern_level', 'NONE')
        except (json.JSONDecodeError, OSError) as e:
            print(f'Warning: could not read {update_file}: {e}', file=sys.stderr)

    # Capture introduced_by and mode before filtering the queue.
    introduced_by = next(
        (q.get('introduced_by') for q in session.get('queue', [])
         if q['name'].lower() == name.lower()),
        'user request',
    )
    pkg_mode = next(
        (q.get('mode') for q in session.get('queue', [])
         if q['name'].lower() == name.lower()),
        'NEW',
    )

    # Remove this package from the queue (it may have been there with a version)
    session['queue'] = [
        q for q in session['queue']
        if not (q['name'].lower() == name.lower() and q.get('version') == version)
    ]

    # MEDIUM risk requires --deeper before the package can be approved.
    # HIGH concern_level also triggers deeper if the sub-agent didn't already
    # run it (evidenced by sandbox-detection.txt, which --deeper always writes).
    deeper_already_run = (work / 'sandbox-detection.txt').is_file()
    deeper_needed = (risk == 'MEDIUM') or (
        concern_level == 'HIGH' and not deeper_already_run
    )

    # Record the result
    analyzed_entry = {
        'name': name,
        'version': version,
        'mode': pkg_mode,
        'recommendation': recommendation,
        'risk': risk,
        'deeper_needed': deeper_needed,
        'deeper_done': False,
        'install_time_code': install_time_code,
        'install_time_code_reason': install_time_code_reason,
        'introduced_by': introduced_by,
        'analyzed_at': _now(),
    }
    session['analyzed'][key] = analyzed_entry

    # CRITICAL propagation: abort the whole session
    if risk == 'CRITICAL' or alternatives_critical:
        reason_parts = []
        if alternatives_critical:
            reason_parts.append('alternatives check detected high-confidence attack pattern')
        if risk == 'CRITICAL':
            reason_parts.append(f'risk assessment CRITICAL for {name} {version}')
        session['aborted'] = True
        session['abort_reason'] = '; '.join(reason_parts)
        save_session(session_path, session)
        print_next_action(session, session_path)
        return

    # Enqueue newly discovered transitive deps (BFS expansion)
    baseline = set(session.get('lockfile_baseline', []))
    analyzed_names = {k.split('@')[0] for k in session['analyzed']}
    queued_names = {q['name'].lower() for q in session['queue']}

    for dep_name in new_dep_names:
        if not isinstance(dep_name, str) or not _DEP_NAME_RE.match(dep_name):
            print(f'Warning: skipping malformed dep name: {shared.sanitize_line(str(dep_name)[:200])}', file=sys.stderr)
            continue
        dep_lower = dep_name.lower()
        if dep_lower in baseline or dep_lower in analyzed_names or dep_lower in queued_names:
            continue  # already known; cycle guard

        # Resolve current version from registry
        resolved = resolve_version(dep_name, session['registry'], session.get('registry_url'))

        session['queue'].append({
            'name': dep_name,
            'version': resolved,        # None if registry unreachable; handled by RESOLVE_VERSION
            'old_version': None,
            'mode': 'NEW',
            'introduced_by': f'{name} {version}',
        })
        session['total_new_to_lockfile'] = session.get('total_new_to_lockfile', 0) + 1
        queued_names.add(dep_lower)

    save_session(session_path, session)

    if not (work / 'assessment.md').is_file():
        print(f'Warning: no assessment.md found in {work}', file=sys.stderr)

    print_next_action(session, session_path)


def cmd_resolve(args: argparse.Namespace) -> None:
    """Resolve an unknown version for a queued dep, then print NEXT_ACTION."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    name = args.pkgname

    resolved = resolve_version(name, session['registry'], session.get('registry_url'))
    if not resolved:
        sys.exit(
            f'Could not resolve version for {name!r} from {session["registry"]}.\n'
            'Check network access or supply the version manually by editing the session file.'
        )

    matched = False
    for entry in session['queue']:
        if entry['name'].lower() == name.lower() and entry.get('version') is None:
            entry['version'] = resolved
            matched = True
            break

    if not matched:
        sys.exit(f'{name!r} not found in queue with an unknown version.')

    save_session(session_path, session)
    print(f'Resolved: {name} → {resolved}')
    print_next_action(session, session_path)


def cmd_confirm_depth(args: argparse.Namespace) -> None:
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    session['depth_confirmed'] = True
    save_session(session_path, session)
    print('Depth confirmation recorded. Resuming analysis.')
    print_next_action(session, session_path)


def cmd_abort(args: argparse.Namespace) -> None:
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    session['aborted'] = True
    session['abort_reason'] = args.reason
    save_session(session_path, session)
    print_next_action(session, session_path)


def cmd_status(args: argparse.Namespace) -> None:
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    print(f'Session : {session_path}')
    print(f'Created : {session.get("created_at")}')
    print(f'Registry: {session["registry"]}')
    print(f'Root    : {session["project_root"]}')
    print_next_action(session, session_path)


def cmd_deeper_done(args: argparse.Namespace) -> None:
    """Mark a MEDIUM-risk package as having completed --deeper analysis."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    name = args.pkgname
    version = args.version
    key = _pkg_key(name, version)

    entry = session['analyzed'].get(key)
    if not entry:
        sys.exit(f'{key!r} not found in analyzed packages. Has it been completed yet?')
    if not entry.get('deeper_needed'):
        sys.exit(f'{key!r} does not have deeper_needed set. Was it a MEDIUM risk package?')

    entry['deeper_done'] = True
    save_session(session_path, session)
    print(f'Recorded deeper analysis done for {name} {version}.')
    print_next_action(session, session_path)


def cmd_generate_manifest(args: argparse.Namespace) -> None:
    """Regenerate the install manifest on demand."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    manifest_path = generate_manifest(session, session_path)
    print(f'Install manifest written: {manifest_path}')


# ---------------------------------------------------------------------------
# Environment / tool check
# ---------------------------------------------------------------------------

def _which(cmd: str) -> bool:
    """Return True if cmd is on PATH."""
    import shutil
    return shutil.which(cmd) is not None


def cmd_env_check(_args: argparse.Namespace) -> None:  # noqa: C901
    """Check for optional tools that improve install-probe analysis.

    Prints a structured report and, for any tool that is missing but would
    meaningfully improve the analysis, prints an INSTALL_SUGGESTION line so
    the AI can relay it to the user.

    Exit codes:
      0  all install-probe tools found (best backend available)
      1  some tools missing (degraded or no install-probe available)
    """
    print('=== ORIENTATION REMINDER ===')
    print()
    print('BEFORE CONTINUING: confirm you completed SKILL.md Step 0 (orient the user).')
    print('Step 0 requires you to have, as your own text output (not inside a tool call):')
    print('  1. Named the detected mode (UPDATE / NEW / CURRENT) in plain language')
    print('  2. Listed the Phase 1 steps and explained what each one does')
    print('  3. Stated that nothing will be installed until the user confirms in Phase 3')
    print('  4. Received explicit confirmation from the user to proceed')
    print()
    print('If you have NOT done Step 0: stop now, output the orientation to the user,')
    print('and wait for their confirmation before running any further commands.')
    print()
    print('If you HAVE done Step 0 and the user confirmed: continue below.')
    print()

    found: dict[str, bool] = {
        'strace':            _which('strace'),
        'bwrap':             _which('bwrap'),
        'docker':            _which('docker'),
        'runsc':             _which('runsc'),          # gVisor kernel
        'package-analysis':  _which('package-analysis'),
    }

    # Determine install-probe backend
    if found['package-analysis'] and found['docker']:
        backend = 'package-analysis'
        backend_note = 'best: gVisor isolation + structured output'
    elif found['bwrap'] and found['strace']:
        backend = 'bwrap+strace'
        backend_note = 'good: namespace isolation + syscall tracing'
    elif found['strace']:
        backend = 'strace-only'
        backend_note = 'limited: syscall tracing, no filesystem isolation'
    else:
        backend = 'none'
        backend_note = '--install-probe unavailable'

    print('=== INSTALL-PROBE ENVIRONMENT CHECK ===')
    print()
    print('Tool availability:')
    for tool, ok in found.items():
        status = 'found' if ok else 'NOT FOUND'
        print(f'  {tool:<22} {status}')

    print()
    print(f'INSTALL_PROBE_BACKEND: {backend}  ({backend_note})')

    # Suggest missing tools that would meaningfully improve the backend
    suggestions: list[tuple[str, str, str]] = []  # (tool, reason, install_hint)

    if not found['package-analysis'] or not found['docker']:
        if backend != 'package-analysis':
            suggestions.append((
                'ossf/package-analysis + Docker',
                'provides gVisor-sandboxed install with structured behavioral output; '
                'detects network calls, file writes, and credential access better than strace alone',
                'Install Docker (https://docs.docker.com/get-docker/), then:\n'
                '    go install github.com/ossf/package-analysis/cmd/package-analysis@latest\n'
                '  or download a pre-built binary from the releases page.',
            ))

    if not found['bwrap'] and backend not in ('package-analysis', 'bwrap+strace'):
        suggestions.append((
            'bubblewrap (bwrap)',
            'lightweight Linux namespace sandbox; needed for bwrap+strace backend',
            'apt install bubblewrap  # Debian/Ubuntu\n'
            '    dnf install bubblewrap  # Fedora/RHEL',
        ))

    if not found['strace'] and backend == 'none':
        suggestions.append((
            'strace',
            'syscall tracer; minimum requirement for any install-probe monitoring',
            'apt install strace  # Debian/Ubuntu\n'
            '    dnf install strace  # Fedora/RHEL',
        ))

    if suggestions:
        print()
        print('Optional tools not installed that would improve install-probe analysis:')
        for tool, reason, hint in suggestions:
            print()
            print(f'  [{tool}]')
            print(f'  Why: {reason}')
            print(f'  How: {hint}')
        print()
        print('SUGGESTION: Ask the user if they would like to install the above tool(s)')
        print('  before proceeding. If yes, install and re-run env-check to confirm.')
        print('  If no, proceed; install-probe will use the available backend.')

    # AI sandbox section
    import shutil as _shutil_ai
    print()
    print('=== AI SANDBOX ===')
    sandbox_ai_val = os.environ.get('SECURE_DEPS_SANDBOX_AI', '')
    if sandbox_ai_val:
        print(f'SECURE_DEPS_SANDBOX_AI: {sandbox_ai_val}')
    else:
        print('SECURE_DEPS_SANDBOX_AI: NOT SET')
    claude_path = _shutil_ai.which('claude')
    gh_path = _shutil_ai.which('gh')
    print(f'claude CLI: {claude_path if claude_path else "NOT FOUND"}')
    print(f'gh (Copilot CLI): {gh_path if gh_path else "NOT FOUND"}')

    if not sandbox_ai_val and claude_path:
        print()
        print('SUGGESTION: export SECURE_DEPS_SANDBOX_AI=claude')
        print('  (enables sandboxed AI review of diffs and filenames; strongly recommended')
        print('  for --deeper and UPDATE mode analysis)')
    elif sandbox_ai_val:
        _ai_cli_map = {'claude': 'claude', 'copilot': 'gh'}
        _expected_cli = _ai_cli_map.get(sandbox_ai_val.strip().lower())
        if _expected_cli is None:
            print()
            print(f'WARNING: SECURE_DEPS_SANDBOX_AI={sandbox_ai_val!r} is not a recognised backend.')
            print('  Known values: claude, copilot. Tier 3 AI review will be skipped.')
        elif not _shutil_ai.which(_expected_cli):
            print()
            print(f'WARNING: SECURE_DEPS_SANDBOX_AI={sandbox_ai_val} but {_expected_cli} CLI not found in PATH.')
            print('  Tier 3 AI review will be skipped.')

    if suggestions:
        sys.exit(1)
    else:
        print()
        print('All recommended tools present. install-probe is fully operational.')
        sys.exit(0)


# ---------------------------------------------------------------------------
# Utility subcommands: report, wrap-up, vuln-audit, follow-on, health-scan
# ---------------------------------------------------------------------------

# Lockfile indicator files per ecosystem: shared by multiple subcommands.
ECOSYSTEM_INDICATOR_FILES: dict[str, list[str]] = {
    'rubygems': ['Gemfile.lock'],
    'pypi':     ['requirements.txt', 'pyproject.toml', 'poetry.lock', 'uv.lock', 'Pipfile.lock'],
    'npm':      ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
}

# Analyzer script file for each ecosystem.
ECOSYSTEM_ANALYZER_FILES: dict[str, str] = {
    'rubygems': 'ruby_analyzer.py',
    'pypi':     'python_analyzer.py',
    'npm':      'js_analyzer.py',
}


def _detect_ecosystems(root: Path) -> list[str]:
    """Return list of ecosystem names whose lockfile indicators exist under root."""
    return [eco for eco, files in ECOSYSTEM_INDICATOR_FILES.items()
            if any((root / f).is_file() for f in files)]


def cmd_ecosystem_detect(args: argparse.Namespace) -> None:
    """Detect ecosystems in root and report analyzer availability.

    Prints one line per detected ecosystem showing its status. Exits with
    code 1 if any detected ecosystem is missing an analyzer, so callers
    can use the exit code as a quick check without parsing text.
    """
    root = Path(args.root).resolve()
    scripts_dir = Path(__file__).parent
    detected = _detect_ecosystems(root)

    print(f'=== ECOSYSTEM DETECTION: {root} ===')
    print()

    if not detected:
        print('NONE_DETECTED: no known lockfile indicator files found.')
        return

    all_ok = True
    for eco in detected:
        analyzer_file = ECOSYSTEM_ANALYZER_FILES.get(eco, '')
        if not analyzer_file:
            status = 'MISSING (no analyzer file known for this ecosystem)'
            all_ok = False
        elif (scripts_dir / analyzer_file).is_file():
            status = f'OK ({analyzer_file})'
        else:
            status = f'MISSING ({analyzer_file} not found)'
            all_ok = False
        print(f'{eco}: DETECTED  analyzer={status}')

    print()
    n = len(detected)
    if all_ok:
        print(f'SUMMARY: {n} ecosystem(s) detected; all analyzers present.')
    else:
        print(
            f'SUMMARY: {n} ecosystem(s) detected; '
            'one or more are missing an analyzer -- see MISSING lines above.',
        )
        sys.exit(1)


# Ordered lockfiles to try per ecosystem for version diff (first existing wins).
ECOSYSTEM_LOCKFILES_ORDERED: dict[str, list[str]] = {
    'rubygems': ['Gemfile.lock'],
    'pypi':     ['uv.lock', 'poetry.lock', 'Pipfile.lock', 'requirements.txt'],
    'npm':      ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
}


def _git_show_file(repo_root: Path, ref: str, filepath: str) -> str | None:
    """Return text content of filepath at git ref, or None if absent.

    Uses `git show REF:FILEPATH` object syntax; no shell expansion of ref or path.
    """
    # `REF:FILEPATH` is a git object reference, not a path; do not add '--'.
    result = subprocess.run(  # noqa: S603
        ['git', 'show', f'{ref}:{filepath}'],
        cwd=str(repo_root), capture_output=True, text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _parse_gemfile_lock_versions(content: str) -> dict[str, str]:
    """Return {lowercase_name: version} for all gems in Gemfile.lock specs sections.

    Top-level gems (4-space indent with a bare version) are included; sub-dep
    constraint lines (6-space indent or constraint syntax like ``= 7.0.0``) are
    excluded because their version field starts with a letter, not a digit.

    >>> _parse_gemfile_lock_versions('GEM\\n  specs:\\n    rails (7.0.0)\\n      railties (= 7.0.0)\\n    rake (13.0.6)\\n')
    {'rails': '7.0.0', 'rake': '13.0.6'}
    >>> _parse_gemfile_lock_versions('')
    {}
    """
    pkgs: dict[str, str] = {}
    in_specs = False
    for line in content.splitlines():
        if line.strip() == 'specs:':
            in_specs = True
            continue
        if in_specs:
            # 4-space indent = top-level gem entry; version starts with digit.
            m = re.match(
                r'^    ([A-Za-z0-9][A-Za-z0-9_\-\.]{0,200}) '
                r'\(([0-9][A-Za-z0-9._\-]{0,50})\)$',
                line,
            )
            if m:
                pkgs[m.group(1).lower()] = m.group(2)
            elif line and not line[0].isspace():
                in_specs = False
    return pkgs


def _parse_toml_lock_versions(content: str) -> dict[str, str]:
    """Return {normalized_name: version} from a poetry.lock or uv.lock file.

    >>> _parse_toml_lock_versions('[[package]]\\nname = "requests"\\nversion = "2.28.1"\\n')
    {'requests': '2.28.1'}
    >>> _parse_toml_lock_versions('[[package]]\\nname = "Flask"\\nversion = "2.3.0"\\n')
    {'flask': '2.3.0'}
    >>> _parse_toml_lock_versions('')
    {}
    """
    pkgs: dict[str, str] = {}
    current_name: str | None = None
    in_pkg = False
    for line in content.splitlines():
        if line.strip() == '[[package]]':
            in_pkg = True
            current_name = None
            continue
        if not in_pkg:
            continue
        m_name = re.match(r'^name\s*=\s*"([A-Za-z0-9][A-Za-z0-9._-]{0,200})"', line)
        if m_name:
            current_name = re.sub(r'[-_.]+', '-', m_name.group(1)).lower()
            continue
        # Tightened from [^"] to exclude spaces and flag-like text.
        m_ver = re.match(r'^version\s*=\s*"([0-9][A-Za-z0-9._+\-]{0,100})"', line)
        if m_ver and current_name:
            pkgs[current_name] = m_ver.group(1)
            in_pkg = False
            current_name = None
    return pkgs


def _parse_requirements_txt_versions(content: str) -> dict[str, str]:
    """Return {normalized_name: version} for pinned (==) entries in requirements.txt.

    Unpinned constraints (>=, ~=, etc.) are silently ignored because they do
    not give a definitive old/new version for a diff.

    >>> _parse_requirements_txt_versions('requests==2.28.1\\nflask>=2.0\\n# comment\\n')
    {'requests': '2.28.1'}
    >>> _parse_requirements_txt_versions('Django==4.2.0\\n')
    {'django': '4.2.0'}
    """
    pkgs: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]{0,200})==([^;\s,]{1,100})', line)
        if m:
            name = re.sub(r'[-_.]+', '-', m.group(1)).lower()
            pkgs[name] = m.group(2)
    return pkgs


def _parse_pipfile_lock_versions(content: str) -> dict[str, str]:
    """Return {normalized_name: version} from a Pipfile.lock JSON file.

    >>> _parse_pipfile_lock_versions('{"default": {"requests": {"version": "==2.28.1"}}, "develop": {"pytest": {"version": "==7.2.0"}}}')
    {'requests': '2.28.1', 'pytest': '7.2.0'}
    >>> _parse_pipfile_lock_versions('not json')
    {}
    """
    pkgs: dict[str, str] = {}
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return pkgs
    for section in ('default', 'develop'):
        for pkg_name, info in data.get(section, {}).items():
            if not isinstance(info, dict):
                continue
            ver = info.get('version', '')
            if not (isinstance(ver, str) and ver.startswith('==')):
                continue
            name = re.sub(r'[-_.]+', '-', pkg_name).lower()
            version = ver[2:]
            # JSON keys and values are unstructured; validate before accepting.
            if _DEP_NAME_RE.match(name) and _RE_SAFE_VER.match(version):
                pkgs[name] = version
    return pkgs


def _parse_package_lock_json_versions(content: str) -> dict[str, str]:
    """Return {name: version} from a package-lock.json (v1/v2/v3) file.

    Nested deps (e.g. ``node_modules/foo/node_modules/bar``) are excluded.

    >>> _parse_package_lock_json_versions('{"packages": {"node_modules/lodash": {"version": "4.17.21"}, "node_modules/a/node_modules/b": {"version": "1.0.0"}}}')
    {'lodash': '4.17.21'}
    >>> _parse_package_lock_json_versions('not json')
    {}
    """
    pkgs: dict[str, str] = {}
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return pkgs
    pkg_map: dict = data.get('packages', {})
    if pkg_map:
        for key, info in pkg_map.items():
            if not key.startswith('node_modules/'):
                continue
            pkg = key[len('node_modules/'):]
            # Allow "@scope/name" (scoped, one '/') but skip nested paths.
            parts = pkg.split('/')
            if pkg.startswith('@') and len(parts) == 2:
                pass  # valid scoped package
            elif len(parts) == 1:
                pass  # valid unscoped package
            else:
                continue  # nested dep path
            ver = info.get('version', '') if isinstance(info, dict) else ''
            name = pkg.lower()
            # JSON values are unstructured; validate before accepting.
            if ver and _DEP_NAME_RE.match(name) and _RE_SAFE_VER.match(ver):
                pkgs[name] = ver
    else:
        for name, info in data.get('dependencies', {}).items():
            ver = info.get('version', '') if isinstance(info, dict) else ''
            name = name.lower()
            if ver and _DEP_NAME_RE.match(name) and _RE_SAFE_VER.match(ver):
                pkgs[name] = ver
    return pkgs


def _parse_yarn_lock_versions(content: str) -> dict[str, str]:
    """Return {name: version} from a yarn.lock file.

    Handles multiple constraints for the same package on one header line, and
    scoped packages (``@scope/pkg@constraint``).

    >>> _parse_yarn_lock_versions('# yarn lockfile v1\\n\\nlodash@^4.17.20, lodash@^4.17.21:\\n  version "4.17.21"\\n')
    {'lodash': '4.17.21'}
    >>> _parse_yarn_lock_versions('"@scope/pkg@^1.0.0":\\n  version "1.0.0"\\n')
    {'@scope/pkg': '1.0.0'}
    """
    pkgs: dict[str, str] = {}
    current_names: list[str] = []
    for line in content.splitlines():
        if not line or line.startswith('#'):
            continue
        if not line[0].isspace() and line.rstrip().endswith(':'):
            header = line.rstrip()[:-1]
            current_names = []
            for part in header.split(','):
                part = part.strip().strip('"')
                # Name is everything before the last '@' (handles @scope/pkg@ver).
                at = part.rfind('@')
                if at > 0:
                    name = part[:at].lower()
                    if name not in current_names and _DEP_NAME_RE.match(name):
                        current_names.append(name)
        elif current_names:
            # Tightened from [^"] to exclude spaces and flag-like text.
            m = re.match(r'^\s+version\s+"([0-9][A-Za-z0-9._+\-]{0,100})"', line)
            if m:
                ver = m.group(1)
                for name in current_names:
                    pkgs[name] = ver
                current_names = []
    return pkgs


def _parse_pnpm_lock_versions(content: str) -> dict[str, str]:
    """Return {name: version} from a pnpm-lock.yaml file (v6 and v9 formats).

    v6 uses ``/name/version:`` keys; v9 uses ``name@version:`` keys.

    >>> _parse_pnpm_lock_versions('packages:\\n  /lodash/4.17.21:\\n    resolution: {}\\n')
    {'lodash': '4.17.21'}
    >>> _parse_pnpm_lock_versions("packages:\\n  lodash@4.17.21:\\n    resolution: {}\\n")
    {'lodash': '4.17.21'}
    """
    pkgs: dict[str, str] = {}
    in_packages = False
    for line in content.splitlines():
        if line.rstrip() == 'packages:':
            in_packages = True
            continue
        if in_packages:
            if line and not line[0].isspace():
                in_packages = False
                continue
            # v6 format: /name/version: or /@scope/name/version:
            m = re.match(
                r'^\s+/?(@?[A-Za-z0-9][A-Za-z0-9._/-]{0,200})/([0-9][^/:]{0,50}):',
                line,
            )
            if m:
                pkgs[m.group(1).lstrip('/').lower()] = m.group(2)
                continue
            # v9 format: name@version: or '@scope/pkg@version':
            m2 = re.match(
                r"^\s+'?(@?[A-Za-z0-9][A-Za-z0-9._/-]{0,200})@([^:' ]{1,50})'?:",
                line,
            )
            if m2:
                pkgs[m2.group(1).lower()] = m2.group(2)
    return pkgs


def _parse_lockfile_versions(lockfile_name: str, content: str) -> dict[str, str]:
    """Dispatch to the right parser based on lockfile filename."""
    if lockfile_name == 'Gemfile.lock':
        return _parse_gemfile_lock_versions(content)
    if lockfile_name in ('uv.lock', 'poetry.lock'):
        return _parse_toml_lock_versions(content)
    if lockfile_name == 'Pipfile.lock':
        return _parse_pipfile_lock_versions(content)
    if lockfile_name == 'requirements.txt':
        return _parse_requirements_txt_versions(content)
    if lockfile_name == 'package-lock.json':
        return _parse_package_lock_json_versions(content)
    if lockfile_name == 'yarn.lock':
        return _parse_yarn_lock_versions(content)
    if lockfile_name == 'pnpm-lock.yaml':
        return _parse_pnpm_lock_versions(content)
    return {}


def cmd_diff_packages(args: argparse.Namespace) -> None:
    """Compare lockfile versions between two git states; print changed packages.

    For each ecosystem with changes, prints:
        REGISTRY: <name>  (lockfile: <filename>)
        --update <pkg> <old_ver> <new_ver>
        --new <pkg> <new_ver>

    These lines can be passed directly to `dep_session.py init`.
    Exits with code 1 if no git repo is found or no ecosystems are detected.
    """
    root = Path(args.root).resolve()
    since = getattr(args, 'since', None) or 'HEAD~1'

    ecosystems = _detect_ecosystems(root)
    if not ecosystems:
        print('NO_ECOSYSTEMS: no lockfile indicator files found.')
        sys.exit(1)

    print(f'=== DIFF PACKAGES: {root} (since {since}) ===')
    print()

    total_updates = 0
    total_new = 0
    active_registries = 0

    for eco in ecosystems:
        lockfile_candidates = ECOSYSTEM_LOCKFILES_ORDERED.get(eco, [])
        lockfile_used: str | None = None
        current_pkgs: dict[str, str] = {}
        old_pkgs: dict[str, str] = {}

        for lf_name in lockfile_candidates:
            if not (root / lf_name).is_file():
                continue
            lockfile_used = lf_name
            current_content = (root / lf_name).read_text(encoding='utf-8', errors='replace')
            current_pkgs = _parse_lockfile_versions(lf_name, current_content)
            old_content = _git_show_file(root, since, lf_name)
            old_pkgs = (_parse_lockfile_versions(lf_name, old_content)
                        if old_content else {})
            break

        if lockfile_used is None:
            continue

        updates: list[tuple[str, str, str]] = []
        news: list[tuple[str, str]] = []

        for name, new_ver in sorted(current_pkgs.items()):
            # Defense-in-depth: re-validate before printing even though parsers
            # already filter; lockfile content is developer-controlled, not
            # attacker-controlled, but guard against parser bugs.
            if not _DEP_NAME_RE.match(name) or not _RE_SAFE_VER.match(new_ver):
                continue
            old_ver = old_pkgs.get(name)
            if old_ver is None:
                news.append((name, new_ver))
            elif old_ver != new_ver:
                if not _RE_SAFE_VER.match(old_ver):
                    continue
                updates.append((name, old_ver, new_ver))

        if not updates and not news:
            continue

        print(f'REGISTRY: {eco}  (lockfile: {lockfile_used})')
        for name, old_ver, new_ver in updates:
            print(f'--update {shared.sanitize_line(name)} '
                  f'{shared.sanitize_line(old_ver)} {shared.sanitize_line(new_ver)}')
        for name, new_ver in news:
            print(f'--new {shared.sanitize_line(name)} {shared.sanitize_line(new_ver)}')
        print()

        total_updates += len(updates)
        total_new += len(news)
        active_registries += 1

    if active_registries == 0:
        print('NO_CHANGES: no package version differences found.')
    else:
        total = total_updates + total_new
        print(
            f'SUMMARY: {total} change(s) detected '
            f'({total_updates} update(s), {total_new} new) '
            f'across {active_registries} registry(ies) with changes.',
        )


def _run_cmd(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run cmd in cwd; return (returncode, stdout, stderr). Never raises."""
    try:
        result = subprocess.run(  # noqa: S603
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=120,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, '', f'Command not found: {cmd[0]}'
    except subprocess.TimeoutExpired:
        return -2, '', f'Command timed out: {" ".join(cmd)}'
    except OSError as e:
        return -3, '', str(e)


def _load_signals(work_dir: Path) -> dict:
    """Load signals.json from work_dir; return {} if missing or invalid."""
    path = work_dir / 'signals.json'
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {}


def _read_verdict(work_dir: Path) -> dict[str, str]:
    """Read verdict.json written by tier 2; return defaults if absent."""
    defaults: dict[str, str] = {
        'summary': '', 'risk_increasing': '', 'risk_decreasing': '',
    }
    vpath = work_dir / 'verdict.json'
    if not vpath.is_file():
        return dict(defaults)
    try:
        data = json.loads(vpath.read_text(encoding='utf-8'))
        result = dict(defaults)
        for k in defaults:
            if k in data and data[k] is not None:
                result[k] = str(data[k])
        return result
    except (json.JSONDecodeError, OSError):
        return dict(defaults)


def cmd_report(args: argparse.Namespace) -> None:
    """Generate Phase 3 summary cards from analyzed packages in this session."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    root = Path(session['project_root'])
    analyzed: dict = session.get('analyzed', {})

    if not analyzed:
        print('No packages have been analyzed yet in this session.')
        return

    registry = session['registry']
    print('=== DEPENDENCY REVIEW REPORT ===')
    print(f'Ecosystem: {registry}  |  Packages analyzed: {len(analyzed)}')
    print()

    for _key, v in analyzed.items():
        name = v['name']
        version = v['version']
        rec = v.get('recommendation', 'UNKNOWN')
        risk = v.get('risk', 'UNKNOWN')
        work_dir = root / 'temp' / 'dep-review' / shared.safe_dir_component(name, version)
        sig = _load_signals(work_dir)
        verdict = _read_verdict(work_dir)

        meta = sig.get('meta', {})
        gate_d = sig.get('gate', {})
        lic_d = sig.get('license', {})
        health_d = sig.get('health', {})
        manifest_d = sig.get('manifest', {})
        repo_d = sig.get('source_repository', {})
        trans_d = sig.get('transitive_dependencies', {})

        pkg_mode = meta.get('analysis_mode', 'UNKNOWN')
        old_ver = meta.get('old_version') or ''
        sha = (meta.get('sha256') or '(not found)').split()[0]
        gate = gate_d.get('adversarial_gate', 'UNKNOWN')
        concern_count = str(gate_d.get('concern_count', '?'))
        concern_level = gate_d.get('concern_level', '?')
        pos_flags = gate_d.get('positive_flags', [])
        mfa = 'YES' if 'MFA_ENFORCED' in pos_flags else 'NO'
        extensions = 'YES' if manifest_d.get('has_native_extensions') else 'NO'
        executables = 'YES' if manifest_d.get('executables_list') else 'NO'
        spdx = lic_d.get('spdx_expression', 'unknown')
        osi_bool = lic_d.get('osi_approved')
        osi_str = 'YES' if osi_bool is True else 'NO' if osi_bool is False else '?'
        lic_status = lic_d.get('status', '')
        license_line = (
            f'SPDX: {spdx}  |  OSI-approved: {osi_str}  |  Status: {lic_status}'
        )
        age_years = health_d.get('age_years')
        age_str = f'{age_years:.1f} yr' if age_years is not None else 'unknown'
        last_rel = health_d.get('last_release_days')
        last_rel_str = f'{last_rel} days ago' if last_rel is not None else 'unknown'
        owner_count = health_d.get('owner_count')
        owners_str = str(owner_count) if owner_count is not None else 'unknown'
        scorecard = health_d.get('openssf_scorecard_score')
        scorecard_str = f'{scorecard}/10' if scorecard is not None else 'unknown'
        health_line = (
            f'Age: {age_str}  |  Last release: {last_rel_str}'
            f'  |  Owners: {owners_str}  |  Scorecard: {scorecard_str}'
        )
        clone_status = repo_d.get('status', 'UNKNOWN')
        clone_url = repo_d.get('source_url', '')
        clone_display = (
            f'OK ({clone_url})' if clone_status.upper().startswith('OK') and clone_url
            else clone_status
        )
        not_in_lock = trans_d.get('not_in_lockfile', [])
        new_trans = (
            str(len(not_in_lock)) if pkg_mode != 'UPDATE' else 'N/A'
        )
        report_path = f'temp/dep-review/{shared.safe_dir_component(name, version)}/assessment.md'
        summary = verdict['summary'] or f'(see {report_path})'

        version_str = f'{old_ver} → {version}' if old_ver else version
        print(f'## {name} {version_str}: {rec} / {risk} risk')
        print()
        print(f'Summary: {summary}')
        print()
        print(f'SHA256: {sha}')
        print(f'MFA: {mfa}   Extensions: {extensions}   Executables: {executables}')
        print(f'License: {license_line}')
        print(f'Project health: {health_line}')
        if pkg_mode not in ('UPDATE', 'UNKNOWN'):
            print(f'New transitive deps: {new_trans}')
        print(f'Adversarial gate: {gate}  |  Concern level: {concern_level} ({concern_count} areas)')
        print(f'Source clone: {clone_display}')
        print()
        print(f'Full report: {report_path}')
        print()
        print('---')
        print()

    flagged = [v for v in analyzed.values()
               if v.get('recommendation') in ('REVIEW_MANUALLY', 'DO_NOT_INSTALL')]

    if session.get('aborted'):
        abort_reason = session.get('abort_reason', 'unknown reason')
        print(f'SESSION ABORTED: {abort_reason}')
        print('Do not install anything in this session.')
        print('SUGGESTED_NEXT: Run wrap-up to generate a record of the '
              'aborted session, then inform the user installation is not '
              'permitted.')
        print(f'  Run: dep_session.py wrap-up {session_path}')
        return

    if flagged:
        fnames = ', '.join(v['name'] for v in flagged)
        print(f'SUGGESTED_NEXT: {len(flagged)} package(s) flagged ({fnames}); '
              'review analysis reports before proceeding to wrap-up.')
    print('SUGGESTED_NEXT: Run wrap-up to generate the full session report, '
          'then present the report path and wait for the user to review it '
          'before asking about installation.')
    print(f'  Run: dep_session.py wrap-up {session_path}')


def _next_report_path(dep_review_dir: Path, today: str) -> Path:
    """Return the next available report-YYYY-MM-DD-SEQ.md path."""
    existing = []
    for f in dep_review_dir.glob(f'report-{today}-*.md'):
        m = re.match(r'report-\d{4}-\d{2}-\d{2}-(\d+)\.md', f.name)
        if m:
            existing.append(int(m.group(1)))
    seq = max(existing) + 1 if existing else 1
    return dep_review_dir / f'report-{today}-{seq}.md'


def cmd_wrap_up(args: argparse.Namespace) -> None:
    """Generate the session report file."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    root = Path(session['project_root'])
    registry = session['registry']
    analyzed: dict = session.get('analyzed', {})

    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    dep_review_dir = root / 'temp' / 'dep-review'
    dep_review_dir.mkdir(parents=True, exist_ok=True)
    out_path = _next_report_path(dep_review_dir, today)

    # Risk sort order: CRITICAL first, then HIGH, MEDIUM, LOW, unknown
    _risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    # Collect per-package data
    pkg_data: list[dict] = []
    for _key, v in analyzed.items():
        name = v['name']
        version = v['version']
        rec = v.get('recommendation', 'pending')
        risk = v.get('risk', 'unknown')
        work_dir = root / 'temp' / 'dep-review' / shared.safe_dir_component(name, version)
        sig = _load_signals(work_dir)
        verdict = _read_verdict(work_dir)

        old_ver = sig.get('meta', {}).get('old_version') or ''
        lic_d = sig.get('license', {})
        spdx = lic_d.get('spdx_expression', 'unknown')
        osi_bool = lic_d.get('osi_approved')
        osi = (
            'approved' if osi_bool is True
            else 'not approved' if osi_bool is False
            else 'unknown'
        )
        lic_status = lic_d.get('status', 'unknown')

        lic_display = spdx
        if lic_status and lic_status not in ('unknown',):
            lic_display = f'{spdx} ({lic_status})'

        # Version display using ->
        if old_ver and old_ver != version:
            ver_display = f'{old_ver} -> {version}'
        else:
            ver_display = version

        assessment_rel = (
            f'{shared.safe_dir_component(name, version)}/assessment.md'
        )

        pkg_data.append({
            'name': name,
            'version': version,
            'ver_display': ver_display,
            'rec': rec,
            'risk': risk,
            'ecosystem': registry,
            'lic_display': lic_display,
            'spdx': spdx,
            'osi': osi,
            'lic_status': lic_status,
            'risk_increasing': verdict['risk_increasing'],
            'risk_decreasing': verdict['risk_decreasing'],
            'summary': verdict['summary'],
            'assessment_rel': assessment_rel,
            'sort_key': _risk_order.get(risk.upper(), 4),
        })

    # Sort by risk (CRITICAL first)
    pkg_data.sort(key=lambda x: x['sort_key'])

    # Derive session mode from analyzed entries; sessions have no top-level mode field.
    _modes = {v.get('mode', 'NEW') for v in analyzed.values()}
    if 'UPDATE' in _modes and len(_modes) > 1:
        _session_mode = 'MIXED'
    elif 'UPDATE' in _modes:
        _session_mode = 'UPDATE'
    elif _modes:
        _session_mode = next(iter(_modes))
    else:
        _session_mode = 'UNKNOWN'

    rel_session = 'temp/dep-review/session.json'

    lines: list[str] = [
        '# Dependency Security Report',
        '',
        f'**Date:** {today}',
        f'**Mode:** {_session_mode}',
        f'**Project root:** {root}',
        f'**Packages reviewed:** {len(pkg_data)}',
        f'**Session:** {rel_session}',
        '',
        '> This report is generated automatically by the secure-dependencies skill and supports',
        '> due diligence review of dependency changes. It is not a substitute for human judgment.',
        '> Review the linked per-package assessments before approving any installation.',
        '',
        '## Results Summary',
        '',
        '| Package | Version | Ecosystem | Risk | Recommendation | License |',
        '|---|---|---|---|---|---|',
    ]

    for p in pkg_data:
        lines.append(
            f'| {p["name"]} | {p["ver_display"]} | {p["ecosystem"]} '
            f'| {p["risk"]} | {p["rec"]} | {p["lic_display"]} |'
        )

    lines += ['', '## Per-Package Findings', '']

    for p in pkg_data:
        lines.append(f'### {p["name"]} {p["ver_display"]}')
        lines.append('')
        lines.append(f'**Risk:** {p["risk"]}')
        lines.append(f'**Recommendation:** {p["rec"]}')
        # License line
        lic_detail = p["spdx"]
        if p["osi"] and p["osi"] not in ('unknown',):
            lic_detail += f', OSI {p["osi"]}'
        if p["lic_status"] and p["lic_status"] not in ('unknown',):
            lic_detail += f' ({p["lic_status"]})'
        lines.append(f'**License:** {lic_detail}')
        lines.append('')
        lines.append('**Risk factors:**')
        ri = p['risk_increasing'] or 'none'
        rd = p['risk_decreasing'] or 'none'
        lines.append(f'- Increasing: {ri}')
        lines.append(f'- Decreasing: {rd}')
        lines.append('')
        if p['summary']:
            lines.append(f'**Summary:** {p["summary"]}')
            lines.append('')
        lines.append(f'[Full assessment]({p["assessment_rel"]})')
        lines.append('')
        lines.append('---')
        lines.append('')

    lines += [f'*Generated by `dep_session.py wrap-up` at {_now()}*']

    out_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    session['report_path'] = str(out_path)
    save_session(session_path, session)
    print(f'Report written: {out_path}')

    gitignore = root / '.gitignore'
    if gitignore.is_file():
        gi = gitignore.read_text(encoding='utf-8', errors='replace')
        if 'temp/' not in gi and 'temp/*' not in gi:
            print('REMINDER: Add "temp/" to .gitignore to avoid committing analysis artifacts.')
    else:
        print('REMINDER: Create .gitignore with "temp/" to avoid committing analysis artifacts.')


def cmd_pre_fill_assessment(args: argparse.Namespace) -> None:
    """Write a pre-filled assessment.md to the package work directory.

    Reads signals.json and substitutes all factual fields into the
    assessment template, leaving [TODO: ...] placeholders for the AI
    to fill in.  Tier 2 runs this after dep_review.py, before writing
    the narrative.
    """
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    root = Path(session['project_root'])
    registry = session['registry']

    name = args.pkgname
    version = args.version

    work = root / 'temp' / 'dep-review' / shared.safe_dir_component(
        name, version
    )
    sig = _load_signals(work)
    meta = sig.get('meta', {})
    gate_d = sig.get('gate', {})
    lic_d = sig.get('license', {})
    health_d = sig.get('health', {})
    manifest_d = sig.get('manifest', {})
    repo_d = sig.get('source_repository', {})
    trans_d = sig.get('transitive_dependencies', {})

    sha256 = meta.get('sha256', 'UNKNOWN')
    mode = meta.get('analysis_mode', 'UNKNOWN')
    old_version = meta.get('old_version') or ''
    version_display = f'{old_version} -> {version}' if old_version else version

    spdx = lic_d.get('spdx_expression', 'unknown')
    osi_bool = lic_d.get('osi_approved')
    osi_approved = 'YES' if osi_bool is True else 'NO' if osi_bool is False else 'unknown'
    license_status = lic_d.get('status', 'unknown')

    age_years = health_d.get('age_years')
    health_age = f'{age_years:.1f} yr' if age_years is not None else 'unknown'
    last_rel_days = health_d.get('last_release_days')
    health_last_release = (
        f'{last_rel_days} days ago' if last_rel_days is not None else 'unknown'
    )
    owner_count = health_d.get('owner_count')
    health_owners = str(owner_count) if owner_count is not None else 'unknown'
    scorecard = health_d.get('openssf_scorecard_score')
    health_scorecard = f'{scorecard}/10' if scorecard is not None else 'unknown'

    clone_url = repo_d.get('source_url', 'not found')
    clone_status = repo_d.get('status', 'UNKNOWN')
    extensions = 'YES' if manifest_d.get('has_native_extensions') else 'NO'
    executables = 'YES' if manifest_d.get('executables') else 'NO'
    not_in_lock = trans_d.get('not_in_lockfile', [])
    transitive_total = str(len(not_in_lock)) if isinstance(not_in_lock, list) else '0'
    concern_level = gate_d.get('concern_level', 'NONE')
    risk_flags_list = gate_d.get('risk_flags', [])
    risk_flags = ' '.join(risk_flags_list) if risk_flags_list else 'NONE'
    pos_flags = gate_d.get('positive_flags', [])
    mfa_status = (
        'MFA_ENFORCED' if 'MFA_ENFORCED' in pos_flags else 'NOT_ENFORCED'
    )

    health_version_stability = health_d.get('version_stability', 'unknown')
    vuln_count = health_d.get('known_vulnerability_count')
    health_known_vulns = str(vuln_count) if vuln_count is not None else 'unknown'
    health_concerns_raw = health_d.get('health_concerns', [])
    if isinstance(health_concerns_raw, list):
        health_concerns = ', '.join(
            c.get('concern', str(c)) if isinstance(c, dict) else str(c)
            for c in health_concerns_raw
        ) or 'none'
    else:
        health_concerns = str(health_concerns_raw) or 'none'
    install_hooks = 'YES' if manifest_d.get('has_install_scripts') else 'NO'

    license_note_raw = lic_d.get('note', '')
    if license_status == 'OK':
        license_note = 'none'
    elif license_note_raw:
        license_note = license_note_raw
    else:
        license_note = (
            '[TODO: explain security implications; missing license means'
            ' no legal basis for external audits and predicts abandonment'
            ' and unpatched vulnerabilities]'
        )

    template_path = (
        Path(__file__).parent.parent / 'assets' / 'assessment-template.md'
    )
    if not template_path.is_file():
        sys.exit(f'Template not found: {template_path}')
    content = template_path.read_text(encoding='utf-8')

    substitutions = {
        'PKGNAME':                  shared.sanitize_line(name),
        'VERSION_DISPLAY':          shared.sanitize_line(version_display),
        'MODE':                     mode,
        'ECOSYSTEM':                registry,
        'WORK_DIR':                 str(work),
        'SHA256':                   sha256,
        'SPDX':                     spdx,
        'OSI_APPROVED':             osi_approved,
        'LICENSE_STATUS':           license_status,
        'LICENSE_NOTE':             license_note,
        'HEALTH_AGE':               health_age,
        'HEALTH_LAST_RELEASE':      health_last_release,
        'HEALTH_VERSION_STABILITY': health_version_stability,
        'HEALTH_OWNERS':            health_owners,
        'HEALTH_SCORECARD':         health_scorecard,
        'HEALTH_KNOWN_VULNS':       health_known_vulns,
        'HEALTH_CONCERNS':          health_concerns,
        'CLONE_URL':                clone_url,
        'CLONE_STATUS':             clone_status,
        'EXTENSIONS':               extensions,
        'EXECUTABLES':              executables,
        'INSTALL_TIME_HOOKS':       install_hooks,
        'TRANSITIVE_TOTAL':         transitive_total,
        'MFA_STATUS':               mfa_status,
        'RISK_FLAGS':               risk_flags,
        'CONCERN_LEVEL':            concern_level,
    }
    for key, value in substitutions.items():
        content = content.replace(f'{{{key}}}', value)

    work.mkdir(parents=True, exist_ok=True)
    out_path = work / 'assessment.md'
    out_path.write_text(content, encoding='utf-8')
    print(f'Pre-filled: {out_path}')


def cmd_record_install(args: argparse.Namespace) -> None:
    """Append an installation record section to the session report."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)

    report_path_str = session.get('report_path', '')
    if not report_path_str:
        print('No report path in session. Run wrap-up before record-install.')
        return
    report_path = Path(report_path_str)
    if not report_path.exists():
        print(f'Report file not found: {report_path}')
        print('Nothing to update.')
        return

    existing = report_path.read_text(encoding='utf-8')
    heading = ('## Additional Installation Record'
               if '## Installation Record' in existing
               else '## Installation Record')

    def _md_cell(s: str) -> str:
        return s.replace('|', r'\|').replace('\n', ' ')

    now = _now()
    lines: list[str] = [
        '',
        heading,
        '',
        f'**Installed at:** {now}',
        '',
        '| Package | Version |',
        '|---|---|',
    ]
    for name, version in args.package:
        lines.append(f'| {_md_cell(name)} | {_md_cell(version)} |')
    lines += ['', f'*Recorded by `dep_session.py record-install` at {now}*', '']

    with report_path.open('a', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'Installation record appended to: {report_path}')


# ---------------------------------------------------------------------------
# Vulnerability audit subcommand
# ---------------------------------------------------------------------------

# Primary auditor commands per ecosystem
_VULN_CMDS: dict[str, list[str]] = {
    'rubygems': ['bundle', 'audit', 'check', '--update'],
    'pypi':     ['pip-audit'],
    'npm':      ['npm', 'audit', '--json'],
}
# Fallback if primary not available
_VULN_FALLBACK: dict[str, list[str] | None] = {
    'rubygems': None,
    'pypi':     ['safety', 'check'],
    'npm':      None,
}
# Outdated-package check commands per ecosystem
_OUTDATED_CMDS: dict[str, list[str]] = {
    'rubygems': ['bundle', 'outdated', '--strict'],
    'pypi':     ['python3', '-m', 'pip', 'list', '--outdated', '--format=columns'],
    'npm':      ['npm', 'outdated'],
}


def _format_bundler_audit(output: str) -> None:
    vuln_entries: list[str] = []
    cur: dict[str, str] = {}
    for line in output.splitlines():
        s = line.strip()
        if s.startswith('Name:'):
            cur = {'name': s[5:].strip()}
        elif s.startswith('Version:') and cur:
            cur['version'] = s[8:].strip()
        elif s.startswith('Advisory:') and cur:
            cur['advisory'] = s[9:].strip()
        elif s.startswith('Criticality:') and cur:
            cur['severity'] = s[12:].strip()
        elif s.startswith('Title:') and cur:
            cur['title'] = s[6:].strip()
        elif s.startswith('Solution:') and cur:
            cur['solution'] = s[9:].strip()
            vuln_entries.append(
                f'  {cur.get("name","?")} {cur.get("version","?")}  '
                f'[{cur.get("advisory","?")}]  Severity: {cur.get("severity","?")}  '
                f'Fix: {cur.get("solution","?")}  {cur.get("title","")}'
            )
            cur = {}
    if vuln_entries:
        print('Group 1: KNOWN VULNERABILITIES (act first)')
        for ln in vuln_entries:
            print(ln)
    else:
        print('Group 1: No known vulnerabilities found.')


def _format_pip_audit(stdout: str, rc: int, tool: str) -> None:
    if tool == 'pip-audit':
        vuln_lines: list[str] = []
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2].startswith(('CVE-', 'GHSA-', 'PYSEC-')):
                vuln_lines.append(f'  {parts[0]} {parts[1]}  [{parts[2]}]')
        if vuln_lines:
            print('Group 1: KNOWN VULNERABILITIES (act first)')
            for ln in vuln_lines:
                print(ln)
        else:
            print('Group 1: No known vulnerabilities found.')
    else:
        if rc != 0 and stdout.strip():
            print('Group 1: KNOWN VULNERABILITIES (act first)')
            print(stdout.rstrip())
        else:
            print('Group 1: No known vulnerabilities found.')


def _format_npm_audit(stdout: str, rc: int) -> None:
    vuln_lines: list[str] = []
    try:
        data = json.loads(stdout)
        for pkg_name, info in data.get('vulnerabilities', {}).items():
            sev = info.get('severity', '?')
            via = info.get('via', [])
            advisories = [v.get('url', '') for v in via if isinstance(v, dict) and v.get('url')]
            fix = 'fix available' if info.get('fixAvailable') else 'no fix yet'
            adv = f'  {advisories[0]}' if advisories else ''
            vuln_lines.append(f'  {pkg_name}  Severity: {sev}  {fix}{adv}')
    except (json.JSONDecodeError, AttributeError):
        if rc != 0 and stdout.strip():
            print('Group 1: KNOWN VULNERABILITIES (raw output; JSON parse failed):')
            print(stdout[:2000])
            return
    if vuln_lines:
        print('Group 1: KNOWN VULNERABILITIES (act first)')
        for ln in vuln_lines:
            print(ln)
    else:
        print('Group 1: No known vulnerabilities found.')


def cmd_vuln_audit(args: argparse.Namespace) -> None:  # noqa: C901
    """Detect ecosystem, run vulnerability auditor, format output in two groups."""
    import shutil as _shutil
    root = Path(args.root).resolve()
    ecosystems = args.ecosystems if getattr(args, 'ecosystems', None) else _detect_ecosystems(root)
    if not ecosystems:
        print('No recognized lockfile found in project root.')
        print('Looked for: Gemfile.lock, requirements.txt, pyproject.toml, package-lock.json …')
        sys.exit(1)

    for eco in ecosystems:
        cmd_list = _VULN_CMDS.get(eco, [])
        if not cmd_list:
            continue

        tool_name = cmd_list[0]
        if not _shutil.which(cmd_list[0]):
            fallback = _VULN_FALLBACK.get(eco)
            if fallback and _shutil.which(fallback[0]):
                cmd_list = fallback
                tool_name = cmd_list[0]
            else:
                print(f'[{eco}] Auditor not installed: {cmd_list[0]}')
                if eco == 'rubygems':
                    print('  Install: gem install bundler-audit')
                elif eco == 'pypi':
                    print('  Install: python3 -m pip install pip-audit   (or: pip install safety)')
                elif eco == 'npm':
                    print('  npm audit is bundled with npm; check your npm installation.')
                print('  Proceeding without vulnerability audit for this ecosystem.')
                continue

        print(f'=== VULNERABILITY AUDIT: {eco.upper()} (via {tool_name}) ===')
        print()
        rc, stdout, stderr = _run_cmd(cmd_list, root)

        if rc == -1:
            print(f'ERROR: {tool_name} not found on PATH.')
            continue

        if eco == 'rubygems':
            _format_bundler_audit(stdout + stderr)
        elif eco == 'pypi':
            _format_pip_audit(stdout, rc, tool_name)
        elif eco == 'npm':
            _format_npm_audit(stdout, rc)

        print()
        outdated_cmd = _OUTDATED_CMDS.get(eco, [])
        if outdated_cmd and _shutil.which(outdated_cmd[0]):
            print('Group 2: OTHER OUTDATED PACKAGES')
            rc2, out2, _ = _run_cmd(outdated_cmd, root)
            if out2.strip():
                print(out2.rstrip())
            else:
                print('  All packages are up to date.')
        print()


# ---------------------------------------------------------------------------
# Follow-on subcommand
# ---------------------------------------------------------------------------

def cmd_follow_on(args: argparse.Namespace) -> None:  # noqa: C901
    """Bucket remaining outdated packages into A/B/C/D after a session."""
    import shutil as _shutil
    root = Path(args.root).resolve()
    ecosystems = ([args.registry] if getattr(args, 'registry', None)
                  else _detect_ecosystems(root))

    session_flagged: set[str] = set()
    if getattr(args, 'session', None):
        try:
            s = load_session(Path(args.session).resolve())
            for v in s.get('analyzed', {}).values():
                if v.get('recommendation') in ('REVIEW_MANUALLY', 'DO_NOT_INSTALL'):
                    session_flagged.add(v['name'].lower())
        except SystemExit:
            pass

    if not ecosystems:
        print('No recognized lockfile found. Specify --from or run from the project root.')
        sys.exit(1)

    for eco in ecosystems:
        outdated_cmd = _OUTDATED_CMDS.get(eco, [])
        if not outdated_cmd or not _shutil.which(outdated_cmd[0]):
            tool = outdated_cmd[0] if outdated_cmd else '(none)'
            print(f'[{eco}] Cannot run outdated check ({tool} not found).')
            continue

        print(f'=== FOLLOW-ON UPDATE PLAN: {eco.upper()} ===')
        print()
        rc, stdout, _ = _run_cmd(outdated_cmd, root)
        if not stdout.strip():
            print('All packages are up to date.')
            print()
            continue

        bucket_a: list[str] = []   # available within constraints
        bucket_b: list[str] = []   # likely blocked by constraint
        bucket_c: list[str] = []   # flagged this session

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith(('package', '---', 'gem ', 'npm ')):
                continue
            name_guess = stripped.split()[0].lower().rstrip('@').strip('*')
            if name_guess in session_flagged:
                bucket_c.append(f'  {stripped}  [flagged this session]')
            elif '~>' in stripped or '>=' in stripped or 'Gemfile requirement' in stripped:
                # Heuristic: line contains a constraint indicator
                bucket_b.append(f'  {stripped}  [constraint may block update]')
            else:
                bucket_a.append(f'  {stripped}')

        def _print_bucket(label: str, items: list[str]) -> None:
            print(label)
            if items:
                for ln in items:
                    print(ln)
            else:
                print('  (none)')
            print()

        _print_bucket('Bucket A: available within current constraints:', bucket_a)
        _print_bucket('Bucket B: may be blocked by version constraints:', bucket_b)
        _print_bucket('Bucket C: deferred/flagged this session:', bucket_c)
        print('Bucket D: all other installed packages: already at latest version.')
        print()
        print('NOTE: Run `dep_session.py vuln-audit --root .` to identify [VULNERABILITY]')
        print('      packages in Bucket B before relaxing any constraints.')
        print()


# ---------------------------------------------------------------------------
# Health-scan subcommand
# ---------------------------------------------------------------------------

# Minimal set of common OSI-approved SPDX identifiers (upper-case for comparison).
_OSI_LICENSES: frozenset[str] = frozenset({
    'MIT', 'APACHE-2.0', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE',
    'GPL-2.0', 'GPL-2.0-ONLY', 'GPL-2.0-OR-LATER',
    'GPL-3.0', 'GPL-3.0-ONLY', 'GPL-3.0-OR-LATER',
    'LGPL-2.0', 'LGPL-2.1', 'LGPL-2.1-ONLY', 'LGPL-2.1-OR-LATER',
    'LGPL-3.0', 'LGPL-3.0-ONLY', 'LGPL-3.0-OR-LATER',
    'MPL-2.0', 'ISC', 'EUPL-1.2', 'AGPL-3.0', 'AGPL-3.0-ONLY', 'AGPL-3.0-OR-LATER',
    'EPL-2.0', 'CC0-1.0', 'UNLICENSE', 'ARTISTIC-2.0', 'RUBY',
    'PSF-2.0', 'PYTHON-2.0',
})
_STALE_THRESHOLD_DAYS = 548   # ~18 months
_SCORECARD_THRESHOLD  = 4.0


def _query_pkg_metadata(name: str, registry: str,
                         registry_url: str | None) -> dict:
    """Fetch license and last-release-days from the registry. Returns {} on failure."""
    result: dict = {'license': None, 'last_release_days': None}
    try:
        if registry == 'rubygems':
            base = (registry_url or 'https://rubygems.org').rstrip('/')
            data = _fetch_version_json(f'{base}/api/v1/gems/{name}.json')
            lic = data.get('licenses') or data.get('license_links', '')
            result['license'] = ', '.join(lic) if isinstance(lic, list) else (lic or None)
            ts_str = data.get('version_created_at') or data.get('created_at', '')
            result['last_release_days'] = shared.days_since(ts_str)

        elif registry == 'pypi':
            base = (registry_url or 'https://pypi.org').rstrip('/')
            data = _fetch_version_json(f'{base}/pypi/{name}/json')
            result['license'] = data.get('info', {}).get('license') or None
            latest = data.get('info', {}).get('version', '')
            files = data.get('releases', {}).get(latest, [])
            if files:
                ts_str = files[-1].get('upload_time_iso_8601') or files[-1].get('upload_time', '')
                result['last_release_days'] = shared.days_since(ts_str)

        elif registry == 'npm':
            base = (registry_url or 'https://registry.npmjs.org').rstrip('/')
            data = _fetch_version_json(f'{base}/{name}')
            latest = data.get('dist-tags', {}).get('latest', '')
            lic = (data.get('versions', {}).get(latest, {}).get('license')
                   or data.get('license'))
            result['license'] = str(lic) if lic else None
            result['last_release_days'] = shared.days_since(
                data.get('time', {}).get(latest, ''))

    except Exception:  # noqa: BLE001
        pass
    return result


def _list_installed_names(root: Path, registry: str) -> list[str]:
    """Return a list of installed package names for the ecosystem."""
    if registry == 'rubygems':
        lf = root / 'Gemfile.lock'
        if not lf.is_file():
            return []
        names: list[str] = []
        in_specs = False
        for line in lf.read_text(encoding='utf-8', errors='replace').splitlines():
            if line.strip() == 'specs:':
                in_specs = True
                continue
            if in_specs:
                m = re.match(r'^    ([A-Za-z0-9_\-\.]+)\s', line)
                if m:
                    names.append(m.group(1))
                elif line and not line[0].isspace():
                    in_specs = False
        return names
    elif registry == 'pypi':
        import shutil as _shutil
        if _shutil.which('pip') or _shutil.which('pip3'):
            rc, out, _ = _run_cmd(['python3', '-m', 'pip', 'list', '--format=columns'], root)
            names = []
            for line in out.splitlines():
                parts = line.split()
                if (parts and not parts[0].lower().startswith('package')
                        and not parts[0].startswith('-')):
                    names.append(parts[0])
            return names
    elif registry == 'npm':
        import shutil as _shutil
        if _shutil.which('npm'):
            rc, out, _ = _run_cmd(['npm', 'list', '--depth=0', '--json'], root)
            try:
                return list(json.loads(out).get('dependencies', {}).keys())
            except (json.JSONDecodeError, AttributeError):
                pass
    return []


def cmd_configure_email(args: argparse.Namespace) -> None:
    """Save or clear the ecosyste.ms contact email for the polite rate-limit pool."""
    if getattr(args, 'no_email', False):
        shared.save_ecosystems_email('')
        print('Opted out: no email will be sent to ecosyste.ms.')
        print(f'Config file: {shared.ECOSYSTEMS_EMAIL_FILE}')
        print('To undo, run: dep_session.py configure-email YOUR_EMAIL')
    else:
        email = (args.email or '').strip()
        if not email or '@' not in email:
            import sys as _sys
            _sys.exit(f'Invalid email address: {email!r}  (provide a valid address or use --no-email)')
        shared.save_ecosystems_email(email)
        print(f'Saved email: {email}')
        print(f'Config file: {shared.ECOSYSTEMS_EMAIL_FILE}')
        print('Future requests to packages.ecosyste.ms will use the polite pool.')


def cmd_health_scan(args: argparse.Namespace) -> None:
    """Fetch health metadata for all installed packages and print an annotated triage table."""
    root = Path(args.root).resolve()
    registry = args.registry
    registry_url = getattr(args, 'registry_url', None)

    packages = _list_installed_names(root, registry)
    if not packages:
        print(f'No installed packages found for {registry} in {root}')
        sys.exit(1)

    print(f'=== HEALTH SCAN RESULTS: {registry.upper()} ({len(packages)} packages) ===')
    print()
    print('Fetching metadata from registry... (may take a moment for large projects)')
    print()

    rate_limited_ecosystems = False
    W_PKG, W_LIC, W_REL, W_DEPS, W_SC, W_CONC = 24, 20, 20, 18, 10, 38

    def _hr() -> str:
        return (f'+{"-"*(W_PKG+2)}+{"-"*(W_LIC+2)}+{"-"*(W_REL+2)}'
                f'+{"-"*(W_DEPS+2)}+{"-"*(W_SC+2)}+{"-"*(W_CONC+2)}+')

    def _row(p: str, li: str, rel: str, deps: str, sc: str, co: str) -> str:
        return (f'| {p:<{W_PKG}} | {li:<{W_LIC}} | {rel:<{W_REL}}'
                f' | {deps:<{W_DEPS}} | {sc:<{W_SC}} | {co:<{W_CONC}} |')

    print(_hr())
    print(_row('Package', 'License', 'Last Release', 'Dependents', 'Scorecard', 'Concerns'))
    print(_hr())

    flagged: list[tuple[str, list[str]]] = []
    for pkg_name in packages:
        meta = _query_pkg_metadata(pkg_name, registry, registry_url)
        lic = (meta.get('license') or 'MISSING')
        days = meta.get('last_release_days')
        rel_str = (f'{days} days ago*' if days is not None and days > _STALE_THRESHOLD_DAYS
                   else f'{days} days ago' if days is not None else 'unknown')
        sc_str = 'N/A'  # scorecard not fetched in basic scan; requires deps.dev call

        eco_data: dict = {}
        if not rate_limited_ecosystems:
            eco_data = shared.lookup_ecosystems_package(registry, pkg_name)
            if eco_data.get('rate_limited'):
                rate_limited_ecosystems = True
                eco_data = {}
        dep_pkgs = eco_data.get('dependent_packages_count')
        dep_repos = eco_data.get('dependent_repos_count')
        deps_str = (
            f'{dep_pkgs}p / {dep_repos}r'
            if dep_pkgs is not None and dep_repos is not None
            else 'N/A'
        )
        eco_status = eco_data.get('status') or ''

        concerns: list[str] = []
        lic_upper = lic.upper()
        if lic_upper in ('MISSING', 'NONE', 'UNKNOWN', ''):
            concerns.append('LICENSE_MISSING')
            lic_display = 'MISSING*'
        elif lic_upper not in _OSI_LICENSES:
            concerns.append('LICENSE_NON_OSI')
            lic_display = f'{lic[:W_LIC-1]}*'
        else:
            lic_display = lic[:W_LIC]
        if days is not None and days > _STALE_THRESHOLD_DAYS:
            concerns.append(f'STALE ({days}d > {_STALE_THRESHOLD_DAYS}d threshold)')
        if eco_status in ('deprecated', 'archived'):
            concerns.append(f'ECOSYSTEMS_{eco_status.upper()}')

        conc_str = (', '.join(concerns) if concerns else 'none')

        print(_row(pkg_name[:W_PKG], lic_display[:W_LIC], rel_str[:W_REL],
                   deps_str[:W_DEPS], sc_str[:W_SC], conc_str[:W_CONC]))
        if concerns:
            flagged.append((pkg_name, concerns))

    print(_hr())
    print('* exceeds threshold or concern')
    print()

    if rate_limited_ecosystems:
        print()
        print('NOTE: packages.ecosyste.ms rate limited (HTTP 429); dependent counts unavailable.')
        print('  To use the polite pool: dep_session.py configure-email YOUR_EMAIL')
        print('  To opt out:             dep_session.py configure-email --no-email')
        print()

    if flagged:
        print(f'FLAGGED_PACKAGES: {len(flagged)} of {len(packages)}')
        for name, concerns in flagged:
            for c in concerns:
                print(f'  {name}: {c}')
        print()
        print('SUGGESTED_NEXT: Which flagged packages would you like to deep-dive?')
        print(f'  Run: dep_session.py init --from {registry} --root . --new NAME VERSION')
    else:
        print('No health concerns detected.')


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog='dep_session.py',
        description=(
            'BFS queue manager for dep_review.py dependency analysis sessions.\n'
            'Tracks queue state so the orchestrating AI never has to.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # init
    p_init = sub.add_parser('init', help='Create a new session.')
    p_init.add_argument('--from', dest='registry', required=True,
                        metavar='REGISTRY', help='rubygems | pypi | npm')
    p_init.add_argument('--root', required=True, metavar='DIR',
                        help='Project root directory')
    p_init.add_argument('--session', metavar='FILE',
                        help='Session file path (default: ROOT/temp/dep-review/session.json)')
    p_init.add_argument('--registry-url', metavar='URL',
                        help='Override registry base URL (https:// required)')
    p_init.add_argument('--update', nargs=3, action='append',
                        metavar=('NAME', 'OLD_VER', 'NEW_VER'),
                        help='Queue a version update (repeatable)')
    p_init.add_argument('--new', nargs=2, action='append',
                        metavar=('NAME', 'VERSION'),
                        help='Queue a new dependency (repeatable)')

    # complete
    p_complete = sub.add_parser('complete',
                                help='Mark a package analyzed; update queue; print NEXT_ACTION.')
    p_complete.add_argument('session', metavar='SESSION_FILE')
    p_complete.add_argument('pkgname')
    p_complete.add_argument('version')
    p_complete.add_argument('recommendation',
                            metavar='RECOMMENDATION',
                            help='APPROVE | APPROVE_WITH_CAUTION | REVIEW_MANUALLY | DO_NOT_INSTALL')
    p_complete.add_argument('risk', metavar='RISK',
                            help='LOW | MEDIUM | HIGH | CRITICAL')
    p_complete.add_argument('--token', metavar='TOKEN',
                            help='next_action_token from the NEXT_ACTION line '
                                 '(required when the session has one)')

    # resolve
    p_resolve = sub.add_parser('resolve',
                               help='Resolve unknown version for a queued dep; print NEXT_ACTION.')
    p_resolve.add_argument('session', metavar='SESSION_FILE')
    p_resolve.add_argument('pkgname')

    # confirm-depth
    p_cd = sub.add_parser('confirm-depth',
                          help='User confirmed large transitive footprint; continue.')
    p_cd.add_argument('session', metavar='SESSION_FILE')

    # abort
    p_abort = sub.add_parser('abort', help='Mark session aborted.')
    p_abort.add_argument('session', metavar='SESSION_FILE')
    p_abort.add_argument('reason', help='Human-readable reason for aborting')

    # status
    p_status = sub.add_parser('status', help='Print session state and NEXT_ACTION.')
    p_status.add_argument('session', metavar='SESSION_FILE')

    # deeper-done
    p_deeper = sub.add_parser(
        'deeper-done',
        help='Mark a MEDIUM-risk package as having completed --deeper analysis.',
    )
    p_deeper.add_argument('session', metavar='SESSION_FILE')
    p_deeper.add_argument('pkgname')
    p_deeper.add_argument('version')

    # generate-manifest
    p_manifest = sub.add_parser(
        'generate-manifest',
        help='Regenerate the install manifest from current session state.',
    )
    p_manifest.add_argument('session', metavar='SESSION_FILE')

    # env-check
    sub.add_parser(
        'env-check',
        help='Check for optional tools that improve --install-probe analysis. '
             'Run once at the start of each session.',
    )

    # report
    p_report = sub.add_parser(
        'report',
        help='Generate Phase 3 summary cards from analyzed packages in the session.',
    )
    p_report.add_argument('session', metavar='SESSION_FILE')

    # wrap-up
    p_wrapup = sub.add_parser(
        'wrap-up',
        help='Generate the session report file.',
    )
    p_wrapup.add_argument('session', metavar='SESSION_FILE')

    # record-install
    p_recinstall = sub.add_parser(
        'record-install',
        help='Append an installation record to the session report.',
    )
    p_recinstall.add_argument('session', metavar='SESSION_FILE')
    p_recinstall.add_argument(
        '--package', nargs=2, metavar=('NAME', 'VERSION'),
        action='append', required=True,
        help='Package installed (repeat for each package)',
    )

    # vuln-audit
    p_vuln = sub.add_parser(
        'vuln-audit',
        help='Detect ecosystem, run vulnerability auditor, format results in two groups.',
    )
    p_vuln.add_argument('--root', required=True, metavar='DIR',
                        help='Project root directory')
    p_vuln.add_argument('--ecosystems', nargs='+', metavar='ECO',
                        help='Override auto-detected ecosystem(s): rubygems | pypi | npm')

    # follow-on
    p_followon = sub.add_parser(
        'follow-on',
        help='Bucket remaining outdated packages into A/B/C/D after a session.',
    )
    p_followon.add_argument('--root', required=True, metavar='DIR',
                            help='Project root directory')
    p_followon.add_argument('--from', dest='registry', metavar='REGISTRY',
                            help='rubygems | pypi | npm (auto-detected if omitted)')
    p_followon.add_argument('--session', metavar='SESSION_FILE',
                            help='Session file to identify packages flagged this session')

    # configure-email
    p_cfg_email = sub.add_parser(
        'configure-email',
        help='Save contact email for the ecosyste.ms polite rate-limit pool.',
    )
    p_cfg_email.add_argument(
        'email',
        nargs='?',
        default='',
        metavar='EMAIL',
        help='Your email address (omit with --no-email to opt out)',
    )
    p_cfg_email.add_argument(
        '--no-email',
        action='store_true',
        help='Opt out: no email sent; suppresses future RATE_LIMITED warnings',
    )

    # diff-packages
    p_diffpkg = sub.add_parser(
        'diff-packages',
        help='Compare lockfile versions between git states; print changed packages.',
    )
    p_diffpkg.add_argument('--root', required=True, metavar='DIR',
                           help='Project root directory (must be a git repo)')
    p_diffpkg.add_argument('--since', metavar='REF', default='HEAD~1',
                           help='Git ref to compare against (default: HEAD~1)')

    # ecosystem-detect
    p_ecodetect = sub.add_parser(
        'ecosystem-detect',
        help='Detect ecosystems in the project root and check analyzer availability.',
    )
    p_ecodetect.add_argument('--root', required=True, metavar='DIR',
                             help='Project root directory')

    # pre-fill-assessment
    p_prefill = sub.add_parser(
        'pre-fill-assessment',
        help='Write a pre-filled assessment.md to the package work directory.',
    )
    p_prefill.add_argument('--session', required=True, metavar='FILE',
                           help='Session file path')
    p_prefill.add_argument('pkgname')
    p_prefill.add_argument('version')

    # health-scan
    p_health = sub.add_parser(
        'health-scan',
        help='Fetch health metadata for all installed packages and print a triage table.',
    )
    p_health.add_argument('--root', required=True, metavar='DIR',
                          help='Project root directory')
    p_health.add_argument('--from', dest='registry', required=True,
                          metavar='REGISTRY', help='rubygems | pypi | npm')
    p_health.add_argument('--registry-url', metavar='URL',
                          help='Override registry base URL (https:// required)')

    args = parser.parse_args()
    dispatch = {
        'init':              cmd_init,
        'complete':          cmd_complete,
        'resolve':           cmd_resolve,
        'confirm-depth':     cmd_confirm_depth,
        'abort':             cmd_abort,
        'status':            cmd_status,
        'deeper-done':       cmd_deeper_done,
        'generate-manifest': cmd_generate_manifest,
        'env-check':         cmd_env_check,
        'ecosystem-detect':  cmd_ecosystem_detect,
        'diff-packages':     cmd_diff_packages,
        'report':            cmd_report,
        'wrap-up':              cmd_wrap_up,
        'pre-fill-assessment':  cmd_pre_fill_assessment,
        'record-install':       cmd_record_install,
        'vuln-audit':        cmd_vuln_audit,
        'follow-on':         cmd_follow_on,
        'health-scan':       cmd_health_scan,
        'configure-email':   cmd_configure_email,
    }
    dispatch[args.command](args)


if __name__ == '__main__':
    main()
