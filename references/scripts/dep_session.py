#!/usr/bin/env python3
# dep_session.py — BFS queue and state manager for dependency analysis sessions.
#
# Requires Python 3.10+.
#
# This script tracks the analysis queue, analyzed packages, depth threshold,
# and CRITICAL propagation so the orchestrating AI never has to maintain state.
# The AI's only job is: make security judgments, write analysis-report.txt,
# call "dep_session.py complete" with its verdict.
#
# Subcommands:
#   init          Create a new session from the project lockfile.
#   complete      Mark a package analyzed; enqueue new transitive deps; print NEXT_ACTION.
#   resolve       Resolve unknown version for a queued package, then print NEXT_ACTION.
#   confirm-depth User confirmed the large-footprint warning; continue.
#   abort         Mark session aborted with a reason.
#   status        Print current state and NEXT_ACTION without changing anything.
#
# Workflow:
#   dep_session.py init --from REGISTRY --root DIR [--update N O N] [--new N V]
#   → prints NEXT_ACTION: ANALYZE with the exact dep_review.py command to run
#
#   (sub-agent runs dep_review.py --session FILE ... ; makes security judgment;
#    writes analysis-report.txt)
#
#   dep_session.py complete SESSION PKGNAME VERSION RECOMMENDATION RISK
#   → updates session, enqueues newly discovered deps, prints NEXT_ACTION
#
#   (repeat until NEXT_ACTION: SESSION_COMPLETE)
#
# Python stdlib only — no third-party packages required.
# Requires Python 3.10+ (enforced by dep_review.py; dep_session.py follows suit).

import sys

if sys.version_info < (3, 10):
    sys.exit(f'dep_session.py requires Python 3.10 or later (running {sys.version})')

import argparse
import json
import re
import shutil
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SESSION_VERSION = 1
DEPTH_THRESHOLD = 10
VALID_RECOMMENDATIONS = frozenset({
    'APPROVE', 'APPROVE_WITH_CAUTION', 'REVIEW_MANUALLY', 'DO_NOT_INSTALL',
})
VALID_RISKS = frozenset({'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _pkg_key(name: str, version: str | None) -> str:
    return f'{name.lower()}@{version or "?"}'


def load_session(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        sys.exit(f'Session file not found: {path}')
    except json.JSONDecodeError as e:
        sys.exit(f'Session file is not valid JSON — {path}: {e}')
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

def print_next_action(session: dict, session_path: Path) -> None:
    """Print the machine-readable NEXT_ACTION block.

    The orchestrating agent reads this after every dep_session.py call and
    follows the instruction exactly — no state tracking required on its part.
    """
    root = Path(session['project_root'])
    # Use paths relative to project root so commands stay short.
    # dep_session.py copies scripts to temp/dep-review/scripts/ at init time.
    scripts = Path(session['scripts_dir'])
    try:
        scripts_rel = scripts.relative_to(root)
    except ValueError:
        scripts_rel = scripts  # fallback: scripts not under root (e.g. older session)
    try:
        session_rel = session_path.relative_to(root)
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

    # --- COMPLETE ---
    if not queue:
        bad = [k for k, v in analyzed.items() if v.get('recommendation') == 'DO_NOT_INSTALL']
        print('=== NEXT_ACTION: SESSION_COMPLETE ===')
        if bad:
            print(f'WARNING: {len(bad)} package(s) flagged DO_NOT_INSTALL:')
            for k in bad:
                v = analyzed[k]
                print(f'  {k}: {v.get("recommendation")} / risk={v.get("risk")}')
            print()
            print('Do NOT proceed to Phase 4 (install) without resolving these.')
        else:
            print('All packages analyzed. No blocking findings.')
            print('Proceed to Phase 3: present report cards and get user approval.')
        print()
        print('Full results:')
        for key, v in analyzed.items():
            itc = ' [INSTALL-TIME CODE]' if v.get('install_time_code') else ''
            print(f'  {key}: {v.get("recommendation", "UNKNOWN")} / '
                  f'risk={v.get("risk", "UNKNOWN")}{itc}')
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
                      f'— {v.get("recommendation", "?")} via {v.get("introduced_by", "?")}')
        for entry in queue:
            if entry['name'].lower() not in baseline:
                print(f'  [queued] {entry["name"]} {entry.get("version", "?")} '
                      f'— via {entry.get("introduced_by", "?")}')
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
        print(f'Version      : UNKNOWN — registry lookup required')
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
    print(f'Step 1 — run analysis:')
    print(f'  {cmd}')
    print()
    print(f'Step 2 — read output, make security judgment, write analysis-report.txt')
    print()
    print(f'Step 3 — record verdict:')
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
    scripts_src = Path(__file__).parent.resolve()
    session_path = (Path(args.session).resolve() if args.session
                    else root / 'temp' / 'dep-review' / 'session.json')
    session_path.parent.mkdir(parents=True, exist_ok=True)

    # Copy scripts into the project so all subsequent commands use short local paths.
    local_scripts = root / 'temp' / 'dep-review' / 'scripts'
    local_scripts.mkdir(parents=True, exist_ok=True)
    for src_file in scripts_src.glob('*.py'):
        dest = local_scripts / src_file.name
        if not dest.exists() or src_file.stat().st_mtime > dest.stat().st_mtime:
            shutil.copy2(src_file, dest)
    scripts_dir = local_scripts

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
        'scripts_dir': str(scripts_dir),
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

    # Remove this package from the queue (it may have been there with a version)
    session['queue'] = [
        q for q in session['queue']
        if not (q['name'].lower() == name.lower() and q.get('version') == version)
    ]

    # Record the result
    analyzed_entry = {
        'name': name,
        'version': version,
        'recommendation': recommendation,
        'risk': risk,
        'install_time_code': install_time_code,
        'install_time_code_reason': install_time_code_reason,
        'introduced_by': next(
            (q.get('introduced_by') for q in session.get('queue', [])
             if q['name'].lower() == name.lower()),
            'user request',
        ),
        'analyzed_at': _now(),
    }
    session['analyzed'][key] = analyzed_entry

    # CRITICAL propagation — abort the whole session
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
            continue  # already known — cycle guard

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
        print('  If no, proceed — install-probe will use the available backend.')
        sys.exit(1)
    else:
        print()
        print('All recommended tools present. install-probe is fully operational.')
        sys.exit(0)


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

    # env-check
    sub.add_parser(
        'env-check',
        help='Check for optional tools that improve --install-probe analysis. '
             'Run once at the start of each session.',
    )

    args = parser.parse_args()
    dispatch = {
        'init': cmd_init,
        'complete': cmd_complete,
        'resolve': cmd_resolve,
        'confirm-depth': cmd_confirm_depth,
        'abort': cmd_abort,
        'status': cmd_status,
        'env-check': cmd_env_check,
    }
    dispatch[args.command](args)


if __name__ == '__main__':
    main()
