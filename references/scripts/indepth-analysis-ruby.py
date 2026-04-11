#!/usr/bin/env python3
# indepth-analysis-ruby.py — Reproducible-build and deep source analysis.
#
# Run AFTER basic-analysis-ruby.py for the same PKGNAME/NEW_VERSION.
# Usage: python3 indepth-analysis-ruby.py PKGNAME OLD_VERSION NEW_VERSION PROJECT_ROOT
#
# Prints a summary of what was done to stdout.
# Capture with: python3 ... | tee -a PROJECT_ROOT/temp/PKGNAME-NEW_VERSION/run-log.txt
#
# Safe output files added by this script:
#   sandbox-detection.txt   — which sandbox tool is available
#   reproducible-build.txt  — whether a locally-built gem matches distributed
#   source-deep-diff.txt    — deeper source-vs-package file comparison
#
# DO NOT read: raw-repro-diff.txt, raw-build-output.txt (adversarial risk)
#
# Python stdlib only — no third-party packages required.

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sanitize(text: str) -> str:
    """Replace C0/C1 control chars (U+0000-U+001F, U+007F-U+009F) with '?'."""
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
    timeout: int = 300,
    capture: bool = True,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess; return (returncode, stdout, stderr).

    Never raises on non-zero exit — callers check returncode themselves.
    """
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=capture,
            text=True,
            timeout=timeout,
            env=env,
        )
        return result.returncode, result.stdout or '', result.stderr or ''
    except subprocess.TimeoutExpired:
        return 1, '', f'TIMEOUT after {timeout}s'
    except FileNotFoundError:
        return 1, '', f'command not found: {args[0]}'
    except Exception as exc:  # noqa: BLE001
        return 1, '', str(exc)


def cmd_available(name: str) -> bool:
    """Return True if `name` is found on PATH."""
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# Step A: Sandbox detection
# ---------------------------------------------------------------------------

def detect_sandbox(work: Path) -> str:
    """Probe available sandbox tools; write sandbox-detection.txt.

    Returns the name of the selected sandbox tool, or 'none'.
    """
    lines: list[str] = ['=== Sandbox availability ===']
    selected = 'none'

    # bwrap — probe with a no-op; unprivileged user namespaces may be disabled
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
        ver = (ver_out.splitlines()[0] if ver_out.strip() else 'version unknown')
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

    lines.append('')
    lines.append(f'SELECTED_SANDBOX: {selected}')
    (work / 'sandbox-detection.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return selected


# ---------------------------------------------------------------------------
# Step B: Reproducible build
# ---------------------------------------------------------------------------

def reproducible_build(
    pkgname: str,
    new_ver: str,
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
    clone_dir = work / 'source'
    built_gem_dir = work / 'raw-built-gem'
    built_gem_dir.mkdir(exist_ok=True)

    lines: list[str] = [
        f'=== Reproducible build: {pkgname} {new_ver} ===',
        f'Sandbox: {sandbox}',
        '',
    ]

    def finish(result: str, extra: list[str] | None = None) -> tuple[str, int, int]:
        lines.append(f'REPRODUCIBLE_BUILD: {result}')
        if extra:
            lines.extend(extra)
        (work / 'reproducible-build.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return result, 0, 0

    if not clone_dir.is_dir():
        return finish('SKIPPED (no source clone)')

    # Find Ruby version
    rc_rv, rv_out, _ = run_cmd(['ruby', '--version'], timeout=10)
    ruby_ver = sanitize(rv_out.strip()) if rc_rv == 0 else 'unknown'
    lines.append(f'RUBY_VERSION: {ruby_ver}')

    # Find gemspec in source
    gemspec_candidates = list(clone_dir.rglob('*.gemspec'))
    if not gemspec_candidates:
        return finish('SKIPPED (no gemspec in source)')
    source_gemspec = str(gemspec_candidates[0])
    lines.append(f'SOURCE_GEMSPEC: {sanitize(source_gemspec)}')

    # Build the gem with the selected sandbox
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
        rc_b, b_out, b_err = run_cmd(bwrap_args, timeout=300)
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    elif sandbox == 'firejail':
        rc_b, b_out, b_err = run_cmd(
            ['firejail', '--quiet', '--net=none',
             f'--read-only={clone_dir}',
             'gem', 'build', source_gemspec, '--output', f'{built_gem_dir}/'],
            timeout=300,
        )
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    elif sandbox in ('docker', 'podman'):
        # Determine ruby image tag from installed ruby version
        rc_rv2, rv2_out, _ = run_cmd(['ruby', '-e', 'puts RUBY_VERSION'], timeout=5)
        ruby_img_tag = rv2_out.strip() if rc_rv2 == 0 else '3'
        # Use major.minor only
        parts = ruby_img_tag.split('.')
        ruby_img_tag = '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]

        # Build in /tmp/src (writable) to avoid:
        #   - EISDIR: gem build --output requires a file path, not a directory
        #   - dubious ownership: git rejects host-owned files in root container
        rc_b, b_out, b_err = run_cmd(
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
        # No sandbox — run directly
        rc_b, b_out, b_err = run_cmd(
            ['gem', 'build', source_gemspec, '--output', f'{built_gem_dir}/'],
            cwd=clone_dir,
            timeout=300,
        )
        build_log_path.write_text(b_out + b_err, encoding='utf-8', errors='replace')
        build_ok = (rc_b == 0)

    lines.append(f'BUILD_STATUS: {"yes" if build_ok else "no"}')

    if not build_ok:
        return finish('INCONCLUSIVE (build failed)')

    # Find the built gem
    built_gems = list(built_gem_dir.glob('*.gem'))
    if not built_gems:
        return finish('INCONCLUSIVE (no .gem produced)')
    built_gem = built_gems[0]

    # Compare SHA256 hashes
    import hashlib
    def sha256_file(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    built_sha = sha256_file(built_gem)
    # Read distributed SHA from package-hash.txt written by basic analysis
    pkg_hash_file = work / 'package-hash.txt'
    dist_sha = ''
    if pkg_hash_file.is_file():
        first_line = pkg_hash_file.read_text(encoding='utf-8').splitlines()[0]
        dist_sha = first_line.split()[0] if first_line.split() else ''

    lines.append(f'BUILT_SHA256: {sanitize(built_sha)}')
    lines.append(f'DISTRIBUTED_SHA256: {sanitize(dist_sha or "UNKNOWN")}')

    if built_sha and built_sha == dist_sha:
        return finish('EXACTLY REPRODUCIBLE (sha256 match)')

    # Hashes differ — unpack built gem and compare contents
    built_unpacked_parent = work / 'raw-built-unpacked'
    built_unpacked_parent.mkdir(exist_ok=True)
    run_cmd(['gem', 'unpack', str(built_gem), '--target', str(built_unpacked_parent)], timeout=60)

    built_unpacked = built_unpacked_parent / f'{pkgname}-{new_ver}'
    if not built_unpacked.is_dir():
        built_unpacked = built_unpacked_parent  # fallback

    dist_unpacked = work / 'unpacked' / f'{pkgname}-{new_ver}'
    if not dist_unpacked.is_dir():
        return finish('INCONCLUSIVE (hashes differ, no dist unpacked dir)')

    rc_diff, diff_out, _ = run_cmd(
        ['diff', '-r', str(built_unpacked), str(dist_unpacked), '--exclude=*.gem'],
        timeout=60,
    )
    (work / 'raw-repro-diff.txt').write_text(diff_out, encoding='utf-8', errors='replace')

    diff_line_count = len(diff_out.splitlines())
    lines.append(f'CONTENT_DIFF_LINES: {diff_line_count}')

    if diff_line_count == 0:
        return finish('EXACTLY REPRODUCIBLE (content match)')

    # Analyse what differs
    differing: list[str] = []
    code_diffs = 0
    metadata_diffs = 0
    for line in diff_out.splitlines():
        if line.startswith('Only in') or line.startswith('diff '):
            differing.append(sanitize(line))
        if re.search(r'^diff.*\.(rb|c|h|java|py|js|sh)\b', line):
            code_diffs += 1
        if re.search(r'^diff.*(\.gemspec|metadata|RECORD|METADATA|Gemfile)', line):
            metadata_diffs += 1

    lines.append('DIFFERING_FILES (sanitized):')
    lines.extend(differing[:50])
    lines.append(f'CODE_FILE_DIFFS: {code_diffs}')
    lines.append(f'METADATA_FILE_DIFFS: {metadata_diffs}')

    if code_diffs > 0:
        extra = ['WARNING: code files differ — possible injected code; human review required']
        result = 'UNEXPECTED DIFFERENCES'
    else:
        extra = []
        result = 'FUNCTIONALLY EQUIVALENT (metadata-only diffs)'

    lines.append(f'REPRODUCIBLE_BUILD: {result}')
    lines.extend(extra)
    (work / 'reproducible-build.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return result, code_diffs, metadata_diffs


# ---------------------------------------------------------------------------
# Step C: Deep source comparison
# ---------------------------------------------------------------------------

def deep_source_comparison(pkgname: str, new_ver: str, work: Path) -> None:
    """Compare package file tree vs source repo tree; write source-deep-diff.txt."""
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

    def relative_files(base: Path, pattern: str | None = None) -> set[str]:
        results = set()
        for p in base.rglob('*'):
            if not p.is_file():
                continue
            rel = './' + str(p.relative_to(base))
            if pattern is None or re.search(pattern, rel):
                results.add(rel)
        return results

    # Ruby/script files in package but NOT in source (highest concern)
    rb_pkg = relative_files(dist_unpacked, r'\.(rb)$')
    rb_src = relative_files(clone_dir, r'\.(rb)$')
    rb_extra = sorted(rb_pkg - rb_src)
    lines.append('Ruby/script files in package but NOT in source (highest concern):')
    for p in rb_extra[:30]:
        lines.append(sanitize(p))
    lines.append('(end)')

    # C/C++ files in package but NOT in source
    lines.append('')
    c_pkg = relative_files(dist_unpacked, r'\.(c|h|cpp)$')
    c_src = relative_files(clone_dir, r'\.(c|h|cpp)$')
    c_extra = sorted(c_pkg - c_src)
    lines.append('C/C++ files in package but NOT in source:')
    for p in c_extra[:20]:
        lines.append(sanitize(p))
    lines.append('(end)')

    # Binary files in package vs source counterpart
    lines.append('')
    lines.append('Binary files in package vs source counterpart:')
    text_indicators = re.compile(
        r'ASCII|UTF|JSON|XML|text|script|empty|directory'
    )
    count = 0
    all_pkg_files = [p for p in dist_unpacked.rglob('*') if p.is_file()]
    for pkg_file in all_pkg_files:
        rc_f, fout, _ = run_cmd(['file', str(pkg_file)], timeout=10)
        if rc_f != 0 or not fout.strip():
            continue
        if text_indicators.search(fout):
            continue
        rel = './' + str(pkg_file.relative_to(dist_unpacked))
        src_counterpart = clone_dir / rel.lstrip('./')
        tag = '[source present]' if src_counterpart.is_file() else '[NO SOURCE COUNTERPART]'
        lines.append(sanitize(fout.rstrip()) + f' {tag}')
        count += 1
        if count >= 20:
            break
    lines.append('(end)')

    lines.append('')
    lines.append('DEEP_COMPARISON: COMPLETE')
    (work / 'source-deep-diff.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) != 5:
        print(
            'Usage: indepth-analysis-ruby.py PKGNAME OLD_VERSION NEW_VERSION PROJECT_ROOT',
            file=sys.stderr,
        )
        sys.exit(1)

    pkgname, old_ver, new_ver, project_root = sys.argv[1:]
    root = Path(project_root).resolve()
    work = root / 'temp' / f'{pkgname}-{new_ver}'

    if not work.is_dir():
        print(f'ERROR: work directory not found: {work}', file=sys.stderr)
        print('Run basic-analysis-ruby.py first.', file=sys.stderr)
        sys.exit(1)

    start_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print('============================================================')
    print(' indepth-analysis-ruby.py')
    print(f' Package : {pkgname}')
    print(f' Update  : {old_ver} -> {new_ver}')
    print(f' Started : {start_time}')
    print('============================================================')
    print()

    # -----------------------------------------------------------------------
    # Step A: Sandbox detection
    # -----------------------------------------------------------------------
    print('--- Step A: Sandbox detection ---')
    sandbox = detect_sandbox(work)
    print(f'  Selected sandbox: {sandbox}')

    # -----------------------------------------------------------------------
    # Step B: Reproducible build
    # -----------------------------------------------------------------------
    print()
    print('--- Step B: Reproducible build ---')
    repro_result, code_diffs, metadata_diffs = reproducible_build(
        pkgname, new_ver, work, sandbox
    )
    print(f'  Reproducible build: {repro_result}')
    print(f'  Code diffs: {code_diffs}  Metadata diffs: {metadata_diffs}')

    # -----------------------------------------------------------------------
    # Step C: Deep source comparison
    # -----------------------------------------------------------------------
    print()
    print('--- Step C: Deep source comparison ---')
    deep_source_comparison(pkgname, new_ver, work)
    print('  Deep comparison saved to source-deep-diff.txt')

    # -----------------------------------------------------------------------
    # Append in-depth addendum to verdict.txt
    # -----------------------------------------------------------------------
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    verdict_file = work / 'verdict.txt'
    addendum_lines = [
        '',
        f'=== IN-DEPTH ADDENDUM ({timestamp}) ===',
        f'SANDBOX: {sandbox}',
        f'REPRODUCIBLE_BUILD: {repro_result}',
        f'CODE_DIFFS: {code_diffs}',
        f'METADATA_DIFFS: {metadata_diffs}',
        '',
        'Additional safe files: sandbox-detection.txt, reproducible-build.txt,'
        ' source-deep-diff.txt',
        'Additional unsafe files: raw-repro-diff.txt, raw-build-output.txt',
    ]
    with open(verdict_file, 'a', encoding='utf-8') as f:
        f.write('\n'.join(addendum_lines) + '\n')

    # -----------------------------------------------------------------------
    # Final summary to stdout
    # -----------------------------------------------------------------------
    print()
    print('============================================================')
    print(f' IN-DEPTH SUMMARY: {pkgname} {old_ver} -> {new_ver}')
    print('============================================================')
    print()
    print(f'Sandbox used       : {sandbox}')
    print(f'Reproducible build : {repro_result}')
    if code_diffs > 0:
        print(f'  [!] CODE FILES DIFFER: {code_diffs} files — human review needed')
    if metadata_diffs > 0:
        print(f'  Metadata-only diffs: {metadata_diffs} files (expected)')
    print()
    print('Updated verdict.txt with in-depth results.')
    print(f'Output directory: {work}')
    print()
    finished = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f'Finished: {finished}')
    print('============================================================')


if __name__ == '__main__':
    main()
