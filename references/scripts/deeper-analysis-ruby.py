#!/usr/bin/env python3
# deeper-analysis-ruby.py — Reproducible-build and deeper source analysis for Ruby.
#
# Run AFTER basic-analysis-ruby.py for the same PKGNAME/NEW_VERSION.
# Usage: python3 deeper-analysis-ruby.py PKGNAME OLD_VERSION NEW_VERSION PROJECT_ROOT
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

import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import analysis_shared as shared


# ---------------------------------------------------------------------------
# Reproducible build — Ruby-specific (uses gem build)
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
        # No sandbox — run directly (lower assurance)
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

    # Hashes differ — unpack and compare contents
    built_unpacked_parent = work / 'raw-built-unpacked'
    built_unpacked_parent.mkdir(exist_ok=True)
    shared.run_cmd(
        ['gem', 'unpack', str(built_gem), '--target', str(built_unpacked_parent)],
        timeout=60,
    )

    built_unpacked = built_unpacked_parent / f'{pkgname}-{new_ver}'
    if not built_unpacked.is_dir():
        built_unpacked = built_unpacked_parent

    dist_unpacked = work / 'unpacked' / f'{pkgname}-{new_ver}'
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
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) != 5:
        print(
            'Usage: deeper-analysis-ruby.py PKGNAME OLD_VERSION NEW_VERSION PROJECT_ROOT',
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
    print(' deeper-analysis-ruby.py')
    print(f' Package : {pkgname}')
    print(f' Update  : {old_ver} -> {new_ver}')
    print(f' Started : {start_time}')
    print('============================================================')
    print()

    # -----------------------------------------------------------------------
    # Sandbox detection
    # -----------------------------------------------------------------------
    print('--- Sandbox detection ---')
    sandbox = shared.detect_sandbox(work)
    print(f'  Selected sandbox: {sandbox}')

    # -----------------------------------------------------------------------
    # Reproducible build
    # -----------------------------------------------------------------------
    print()
    print('--- Reproducible build ---')
    repro_result, code_diffs, metadata_diffs = reproducible_build(
        pkgname, new_ver, work, sandbox
    )
    print(f'  Reproducible build: {repro_result}')
    print(f'  Code diffs: {code_diffs}  Metadata diffs: {metadata_diffs}')

    # -----------------------------------------------------------------------
    # Deep source comparison
    # -----------------------------------------------------------------------
    print()
    print('--- Deep source comparison ---')
    shared.deep_source_comparison(
        pkgname, new_ver, work,
        primary_label='Ruby',
        primary_pattern=r'\.(rb)$',
    )
    print('  Deep comparison saved to source-deep-diff.txt')

    # -----------------------------------------------------------------------
    # Append addendum to verdict.txt
    # -----------------------------------------------------------------------
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    verdict_file = work / 'verdict.txt'
    addendum_lines = [
        '',
        f'=== DEEPER ANALYSIS ADDENDUM ({timestamp}) ===',
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
    print(f' DEEPER ANALYSIS SUMMARY: {pkgname} {old_ver} -> {new_ver}')
    print('============================================================')
    print()
    print(f'Sandbox used       : {sandbox}')
    print(f'Reproducible build : {repro_result}')
    if code_diffs > 0:
        print(f'  [!] CODE FILES DIFFER: {code_diffs} files — human review needed')
    if metadata_diffs > 0:
        print(f'  Metadata-only diffs: {metadata_diffs} files (expected)')
    print()
    print('Updated verdict.txt with deeper analysis results.')
    print(f'Output directory: {work}')
    print()
    finished = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f'Finished: {finished}')
    print('============================================================')


if __name__ == '__main__':
    main()
