#!/usr/bin/env python3
# dep_session.py: BFS queue and state manager for dependency analysis sessions.
#
# Requires Python 3.10+.
#
# This script tracks the analysis queue, analyzed packages, depth threshold,
# and CRITICAL propagation so the orchestrating AI never has to maintain state.
# The AI's only job is: make security judgments, write assessment.txt,
# call "dep_session.py complete" with its verdict.
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
#   report            Generate Phase 3 summary cards from all analyzed packages.
#   wrap-up           Generate the session progress file.
#   vuln-audit        Run the ecosystem's vulnerability auditor; format two-group output.
#   follow-on         Bucket remaining outdated packages into A/B/C/D.
#   health-scan       Fetch health metadata for all installed packages; print triage table.
#
# Workflow:
#   dep_session.py init --from REGISTRY --root DIR [--update N O N] [--new N V]
#   → prints NEXT_ACTION: ANALYZE with the exact dep_review.py command to run
#
#   (sub-agent runs dep_review.py --session FILE ... ; makes security judgment;
#    writes assessment.txt)
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
import re
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
VALID_RISKS = frozenset({'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})

# Shell command to install approved packages, per ecosystem.
# {packages} is replaced with a space-separated list of package names.
ECOSYSTEM_INSTALL_CMD: dict[str, str] = {
    'rubygems': 'bundle update {packages}',
    'pypi':     'pip install --upgrade {packages}',
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

    # TODO: Python (requirements.txt, poetry.lock, uv.lock)
    # TODO: JavaScript (package-lock.json, yarn.lock)
    return []


# ---------------------------------------------------------------------------
# Version resolution (network, stdlib only)
# ---------------------------------------------------------------------------

def _resolve_rubygems(name: str, registry_url: str | None) -> str | None:
    base = (registry_url or 'https://rubygems.org').rstrip('/')
    url = f'{base}/api/v1/gems/{name}.json'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'dep_session/1 (security-review)'})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            data = json.loads(resp.read().decode('utf-8', errors='replace'))
            v = str(data.get('version', '')).strip()
            return v or None
    except Exception:
        return None


def resolve_version(name: str, registry: str, registry_url: str | None = None) -> str | None:
    """Query the registry for the current published version of a package."""
    if registry == 'rubygems':
        return _resolve_rubygems(name, registry_url)
    # TODO: pypi, npm
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
    lines.append('#   - cat any assessment.txt listed below for full detail.')
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
        report_path = f'temp/dep-review/{name}-{version}/assessment.txt'

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
    root = Path(session['project_root'])
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
        print('=== NEXT_ACTION: ABORTED_CRITICAL ===')
        print(f'Reason: {session.get("abort_reason", "unknown")}')
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
        print('=== NEXT_ACTION: RUN_DEEPER ===')
        print(f'Package  : {name} {version}')
        print(f'Reason   : MEDIUM risk requires reproducible-build verification before approval.')
        print()
        print('Step 1: run deeper analysis:')
        print(f'  python3 {scripts_rel}/dep_review.py'
              f' --from {registry}{registry_url_flag} --deeper --root . {name} {version}')
        print()
        print('Step 2: read the updated signals.txt (deeper section), make judgment.')
        print()
        print('Step 3: record deeper result:')
        print(f'  python3 {scripts_rel}/dep_session.py deeper-done {session_rel} {name} {version}')
        return

    # --- COMPLETE ---
    if not queue:
        bad = [k for k, v in analyzed.items() if v.get('recommendation') == 'DO_NOT_INSTALL']
        print('=== NEXT_ACTION: SESSION_COMPLETE ===')
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
        print('  2. cat any assessment.txt files you want to inspect.')
        print('  3. Edit the manifest to remove any packages you do not approve.')
        print('  4. Run the install command at the bottom of the manifest.')
        print('  5. Commit the manifest and lockfile changes together.')
        return

    # --- DEPTH CONFIRMATION NEEDED ---
    if new_count > threshold and not depth_confirmed:
        baseline = set(session.get('lockfile_baseline', []))
        print('=== NEXT_ACTION: CONFIRM_DEPTH ===')
        print(f'New packages not in original lockfile: {new_count} (threshold: {threshold})')
        print()
        print('Newly discovered packages (analyzed + queued):')
        for v in analyzed.values():
            if v['name'].lower() not in baseline:
                print(f'  [done]   {v["name"]} {v["version"]} '
                      f'recommend {v.get("recommendation", "?")} / {v.get("risk", "?")} risk'
                      f' via {v.get("introduced_by", "?")}')
        for entry in queue:
            if entry['name'].lower() not in baseline:
                print(f'  [queued] {entry["name"]} {entry.get("version", "?")} '
                      f'via {entry.get("introduced_by", "?")}')
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
        print('=== NEXT_ACTION: RESOLVE_VERSION ===')
        print(f'Package      : {name}')
        print(f'Mode         : {mode}')
        print(f'Introduced by: {introduced_by}')
        print(f'Version      : UNKNOWN (registry lookup required)')
        print()
        print(f'Run: python3 {scripts_rel}/dep_session.py resolve {session_rel} {name}')
        print('(This will query the registry, update the session, and print the next command.)')
        return

    # --- ANALYZE ---
    mode_flags = '--alternatives --basic' if mode == 'NEW' else '--basic'
    old_flag = f' --old {old_version}' if old_version else ''
    # --session is omitted: dep_review.py defaults to ROOT/temp/dep-review/session.json
    cmd = (
        f'python3 {scripts_rel}/dep_review.py'
        f' --from {registry}{registry_url_flag}'
        f' {mode_flags}{old_flag}'
        f' --root .'
        f' {name} {version}'
    )

    print('=== NEXT_ACTION: ANALYZE ===')
    print(f'Package      : {name}')
    print(f'Version      : {version}')
    print(f'Mode         : {mode}' + (f' (was {old_version})' if old_version else ''))
    print(f'Introduced by: {introduced_by}')
    print()
    print(f'Step 1: run analysis:')
    print(f'  {cmd}')
    print()
    print(f'Step 2: read output, make security judgment, write assessment.txt')
    print()
    print(f'Step 3: record verdict:')
    print(f'  python3 {scripts_rel}/dep_session.py complete {session_rel} \\')
    print(f'    {name} {version} RECOMMENDATION RISK')
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

    key = _pkg_key(name, version)

    # Read session-update.json written by dep_review.py --session
    root = Path(session['project_root'])
    work = root / 'temp' / 'dep-review' / f'{name}-{version}'
    update_file = work / 'session-update.json'
    new_dep_names: list[str] = []
    alternatives_critical = False
    install_time_code = False
    install_time_code_reason = ''

    if update_file.is_file():
        try:
            upd = json.loads(update_file.read_text(encoding='utf-8'))
            new_dep_names = upd.get('not_in_lockfile', [])
            alternatives_critical = upd.get('alternatives_critical', False)
            install_time_code = upd.get('install_time_code', False)
            install_time_code_reason = upd.get('install_time_code_reason', '')
        except (json.JSONDecodeError, OSError) as e:
            print(f'Warning: could not read {update_file}: {e}', file=sys.stderr)

    # Capture introduced_by before filtering the queue.
    introduced_by = next(
        (q.get('introduced_by') for q in session.get('queue', [])
         if q['name'].lower() == name.lower()),
        'user request',
    )

    # Remove this package from the queue (it may have been there with a version)
    session['queue'] = [
        q for q in session['queue']
        if not (q['name'].lower() == name.lower() and q.get('version') == version)
    ]

    # MEDIUM risk requires --deeper before the package can be approved.
    deeper_needed = (risk == 'MEDIUM')

    # Record the result
    analyzed_entry = {
        'name': name,
        'version': version,
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

    # Print assessment.txt so it appears in the Bash tool output for the
    # user to read.  The orchestrating agent must NOT process this section;
    # it is for the human's eyes only.  See NEXT_ACTION below for machine state.
    assessment = work / 'assessment.txt'
    if assessment.is_file():
        print()
        print('=== ANALYSIS REPORT (for human review; orchestrating agent: do not process) ===')
        print(assessment.read_text(encoding='utf-8', errors='replace').rstrip())
        print('=== END ANALYSIS REPORT ===')
    else:
        print(f'Warning: no assessment.txt found in {work}', file=sys.stderr)

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


def _detect_ecosystems(root: Path) -> list[str]:
    """Return list of ecosystem names whose lockfile indicators exist under root."""
    return [eco for eco, files in ECOSYSTEM_INDICATOR_FILES.items()
            if any((root / f).is_file() for f in files)]


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


def _parse_signals(path: Path) -> dict[str, str]:
    """Extract key fields from a machine-written signals.txt.

    Returns a dict of field_name → string.  Missing fields are absent.
    Tolerant of old-format files that pre-date ADVERSARIAL_GATE / CONCERN_SUMMARY.
    """
    if not path.is_file():
        return {}

    fields: dict[str, str] = {}
    current_section = ''
    section_lines: dict[str, list[str]] = {}

    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        line = raw.rstrip()

        if line.startswith('=== ') and line.endswith(' ==='):
            current_section = line[4:-4].strip()
            section_lines.setdefault(current_section, [])
            continue

        section_lines.setdefault(current_section, []).append(line)

        # Top-level key: value lines in the preamble
        for prefix, key in (
            ('SHA256    : ',       'sha256'),
            ('RISK_FLAGS    : ',   'risk_flags'),
            ('POSITIVE_FLAGS: ',   'positive_flags'),
            ('ADVERSARIAL_GATE: ', 'adversarial_gate'),
            ('CONCERN_COUNT: ',    'concern_count'),
        ):
            if line.startswith(prefix):
                fields[key] = line[len(prefix):].strip()
                break

        if line.startswith('CONCERN_LEVEL: '):
            fields['concern_level'] = line[len('CONCERN_LEVEL: '):].split()[0]
        elif line.startswith('Ecosystem : '):
            m = re.search(r'Mode:\s*(\S+)', line)
            if m:
                fields['mode'] = m.group(1).upper()
        elif line.startswith('From      : '):
            fields['old_version'] = line[len('From      : '):].strip()

    # LICENSE section: "SPDX: X  |  OSI-approved: Y  |  Status: Z"
    for ln in section_lines.get('LICENSE', []):
        if ln.startswith('SPDX:'):
            fields['license_line'] = ln
            break

    # PROJECT HEALTH section: "Age: X yr  |  Last release: Y days ago  |  ..."
    for ln in section_lines.get('PROJECT HEALTH', []):
        if ln.startswith('Age:'):
            fields['health_line'] = ln
            break

    # SOURCE REPOSITORY section
    for ln in section_lines.get('SOURCE REPOSITORY', []):
        if ln.startswith('URL  :'):
            fields['clone_url'] = ln[len('URL  :'):].strip()
        elif ln.startswith('Clone:'):
            fields['clone_status'] = ln[len('Clone:'):].strip()

    # MANIFEST / INSTALL HOOKS section
    for ln in section_lines.get('MANIFEST / INSTALL HOOKS', []):
        if ln.startswith('Native extensions'):
            fields['extensions'] = 'YES' if 'YES' in ln else 'NO'
        elif ln.startswith('Executables added to PATH'):
            fields['executables'] = 'YES' if 'YES' in ln else 'NO'

    # new_transitive_deps from CONCERN_SUMMARY (lives in the preamble, section key '')
    in_concern = False
    for ln in section_lines.get('', []):
        stripped = ln.strip()
        if stripped == 'CONCERN_SUMMARY:':
            in_concern = True
            continue
        if in_concern:
            if stripped.startswith('new_transitive_deps'):
                val = stripped.split(':', 1)[1].strip() if ':' in stripped else ''
                fields['new_transitive_deps'] = val.split()[0] if val else ''
            if stripped.startswith('CONCERN_') or (stripped and not ln.startswith(' ')):
                in_concern = False

    return fields


def _parse_assessment_summary(path: Path) -> str:
    """Extract the SUMMARY: paragraph from an AI-written assessment.txt."""
    if not path.is_file():
        return '(assessment.txt not found)'
    summary_lines: list[str] = []
    in_summary = False
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if line.startswith('SUMMARY:'):
            in_summary = True
            rest = line[len('SUMMARY:'):].strip()
            if rest:
                summary_lines.append(rest)
            continue
        if in_summary:
            if re.match(r'^[A-Z_]+:', line) and not line.startswith(' '):
                break
            summary_lines.append(line.strip())
    text = ' '.join(p for p in summary_lines if p)
    return text or '(no SUMMARY in assessment.txt)'


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
        work_dir = root / 'temp' / 'dep-review' / f'{name}-{version}'
        af = _parse_signals(work_dir / 'signals.txt')
        summary = _parse_assessment_summary(work_dir / 'assessment.txt')

        pkg_mode = af.get('mode', 'UNKNOWN')
        old_ver = af.get('old_version', '')
        sha = af.get('sha256', '(not found)').split()[0]
        gate = af.get('adversarial_gate', 'UNKNOWN')
        concern_count = af.get('concern_count', '?')
        concern_level = af.get('concern_level', '?')
        mfa = 'YES' if 'MFA_ENFORCED' in af.get('positive_flags', '') else 'NO'
        extensions = af.get('extensions', '?')
        executables = af.get('executables', '?')
        license_line = af.get('license_line', '(see license.txt)')
        health_line = af.get('health_line', '(see project-health.txt)')
        clone_status = af.get('clone_status', 'UNKNOWN')
        clone_url = af.get('clone_url', '')
        clone_display = (f'OK ({clone_url})' if clone_status.upper().startswith('OK') and clone_url
                         else clone_status)
        new_trans = af.get('new_transitive_deps', 'N/A' if pkg_mode == 'UPDATE' else '?')
        report_path = f'temp/dep-review/{name}-{version}/assessment.txt'

        version_str = f'{old_ver} → {version}' if old_ver else version
        print(f'## {name} {version_str}: {rec} / {risk} risk')
        print()
        print(f'Summary: {summary}')
        print()
        print(f'SHA256: {sha}')
        print(f'MFA: {mfa}   Extensions: {extensions}   Executables: {executables}')
        print(f'License: {license_line}')
        print(f'Project health: {health_line}')
        if pkg_mode not in ('UPDATE',):
            print(f'New transitive deps: {new_trans}')
        print(f'Adversarial gate: {gate}  |  Concern level: {concern_level} ({concern_count} areas)')
        print(f'Source clone: {clone_display}')
        print()
        print(f'Full report: {report_path}')
        print()
        print('---')
        print()

    approved = [v for v in analyzed.values()
                if v.get('recommendation') in ('APPROVE', 'APPROVE_WITH_CAUTION')
                and (not v.get('deeper_needed') or v.get('deeper_done'))]
    flagged = [v for v in analyzed.values()
               if v.get('recommendation') in ('REVIEW_MANUALLY', 'DO_NOT_INSTALL')]

    if approved:
        names = ', '.join(v['name'] for v in approved)
        print(f'SUGGESTED_NEXT: Shall I install the approved packages ({names})?')
        print(f'  Run: dep_session.py generate-manifest {session_path}')
    if flagged:
        fnames = ', '.join(v['name'] for v in flagged)
        print(f'SUGGESTED_NEXT: {len(flagged)} package(s) flagged ({fnames}); '
              'review analysis reports before proceeding.')


def cmd_wrap_up(args: argparse.Namespace) -> None:
    """Generate (or append to) the session progress file."""
    session_path = Path(args.session).resolve()
    session = load_session(session_path)
    root = Path(session['project_root'])
    registry = session['registry']
    analyzed: dict = session.get('analyzed', {})

    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    hour = datetime.now(timezone.utc).strftime('%H')
    base_path = root / 'temp' / 'dep-review' / f'progress-{today}.md'
    out_path = (root / 'temp' / 'dep-review' / f'progress-{today}T{hour}.md'
                if base_path.is_file() else base_path)

    col_w = 24
    lines: list[str] = [
        f'# Dependency Session: {today}',
        f'Ecosystem: {registry}',
        f'Session: {session_path}',
        '',
        '## Vulnerability audit',
        '(run `dep_session.py vuln-audit --root .` and paste summary here)',
        '',
        '## Packages analyzed',
        '',
        '| Package | Mode | From → To | SHA256 (first 12) | License | Status | Report |',
        '|---------|------|-----------|-------------------|---------|--------|--------|',
    ]

    for _key, v in analyzed.items():
        name = v['name']
        version = v['version']
        rec = v.get('recommendation', 'pending')
        risk = v.get('risk', '')
        work_dir = root / 'temp' / 'dep-review' / f'{name}-{version}'
        af = _parse_signals(work_dir / 'signals.txt')
        pkg_mode = af.get('mode', '?')
        old_ver = af.get('old_version', '')
        sha = af.get('sha256', '?').split()[0][:12]
        lic_raw = af.get('license_line', '?')
        spdx = lic_raw.split('|')[0].replace('SPDX:', '').strip() if '|' in lic_raw else lic_raw
        ver_str = f'{old_ver} → {version}' if old_ver else version
        status = f'{rec} / {risk}' if risk else rec
        rep_rel = f'temp/dep-review/{name}-{version}/assessment.txt'
        lines.append(
            f'| {name} | {pkg_mode} | {ver_str} | {sha} | {spdx} | {status} | '
            f'[report]({rep_rel}) |'
        )

    lines += ['', f'*Generated by `dep_session.py wrap-up` at {_now()}*']

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Progress file written: {out_path}')

    gitignore = root / '.gitignore'
    if gitignore.is_file():
        gi = gitignore.read_text(encoding='utf-8', errors='replace')
        if 'temp/' not in gi and 'temp/*' not in gi:
            print('REMINDER: Add "temp/" to .gitignore to avoid committing analysis artifacts.')
    else:
        print('REMINDER: Create .gitignore with "temp/" to avoid committing analysis artifacts.')


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
    'pypi':     ['pip', 'list', '--outdated', '--format=columns'],
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
                    print('  Install: pip install pip-audit   (or: pip install safety)')
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
            url = f'{base}/api/v1/gems/{name}.json'
            req = urllib.request.Request(
                url, headers={'User-Agent': 'dep_session/1 (security-review)'},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                data = json.loads(resp.read().decode('utf-8', errors='replace'))
            lic = data.get('licenses') or data.get('license_links', '')
            result['license'] = ', '.join(lic) if isinstance(lic, list) else (lic or None)
            ts_str = data.get('version_created_at') or data.get('created_at')
            if ts_str:
                ts = ts_str.rstrip('Z').split('.')[0]
                dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                result['last_release_days'] = (datetime.now(timezone.utc) - dt).days

        elif registry == 'pypi':
            base = (registry_url or 'https://pypi.org').rstrip('/')
            url = f'{base}/pypi/{name}/json'
            req = urllib.request.Request(
                url, headers={'User-Agent': 'dep_session/1 (security-review)'},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                data = json.loads(resp.read().decode('utf-8', errors='replace'))
            result['license'] = data.get('info', {}).get('license') or None
            latest = data.get('info', {}).get('version', '')
            files = data.get('releases', {}).get(latest, [])
            if files:
                ts_str = files[-1].get('upload_time_iso_8601') or files[-1].get('upload_time', '')
                if ts_str:
                    ts = ts_str.rstrip('Z').split('.')[0]
                    dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                    result['last_release_days'] = (datetime.now(timezone.utc) - dt).days

        elif registry == 'npm':
            base = (registry_url or 'https://registry.npmjs.org').rstrip('/')
            url = f'{base}/{name}'
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'dep_session/1 (security-review)',
                         'Accept': 'application/json'},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                data = json.loads(resp.read().decode('utf-8', errors='replace'))
            latest = data.get('dist-tags', {}).get('latest', '')
            lic = (data.get('versions', {}).get(latest, {}).get('license')
                   or data.get('license'))
            result['license'] = str(lic) if lic else None
            ts_str = data.get('time', {}).get(latest, '')
            if ts_str:
                ts = ts_str.rstrip('Z').split('.')[0]
                dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                result['last_release_days'] = (datetime.now(timezone.utc) - dt).days

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
        if _shutil.which('pip'):
            rc, out, _ = _run_cmd(['pip', 'list', '--format=columns'], root)
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
            concerns.append(f'LICENSE_NON_OSI')
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
        help='Generate (or append to) the session progress file.',
    )
    p_wrapup.add_argument('session', metavar='SESSION_FILE')

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
        'report':            cmd_report,
        'wrap-up':           cmd_wrap_up,
        'vuln-audit':        cmd_vuln_audit,
        'follow-on':         cmd_follow_on,
        'health-scan':       cmd_health_scan,
        'configure-email':   cmd_configure_email,
    }
    dispatch[args.command](args)


if __name__ == '__main__':
    main()
