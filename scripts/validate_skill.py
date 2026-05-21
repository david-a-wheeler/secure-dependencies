#!/usr/bin/env python3
"""Validate SKILL.md frontmatter against Agent Skills spec requirements."""
import re
import sys
from pathlib import Path

SKILL_FILE = Path(__file__).parent.parent / 'SKILL.md'
EXPECTED_NAME = 'secure-dependencies'
MAX_NAME_LEN = 64
MAX_DESC_CHARS = 1024
BODY_LINE_WARN = 500
NAME_PAT = re.compile(r'^[a-z][a-z0-9-]*$')


def parse_frontmatter(path):
    lines = Path(path).read_text().splitlines()
    if not lines or lines[0].rstrip() != '---':
        raise ValueError('File does not start with ---')
    try:
        end = next(i for i, ln in enumerate(lines[1:], 1)
                   if ln.rstrip() == '---')
    except StopIteration:
        raise ValueError('No closing --- found')
    return lines[1:end], lines[end + 1:]


def get_field(fm_lines, key):
    """Return text content of a top-level YAML field, or None if absent."""
    start = None
    for i, line in enumerate(fm_lines):
        if re.match(rf'^{re.escape(key)}:\s*', line):
            start = i
            break
    if start is None:
        return None
    after_colon = fm_lines[start].split(':', 1)[1].strip()
    if after_colon and after_colon not in ('|', '>', '|-', '>-', '|+', '>+'):
        return after_colon
    content = []
    for line in fm_lines[start + 1:]:
        if line and not line[0].isspace():
            break
        content.append(line.strip())
    return '\n'.join(content).strip()


def main():
    errors = []
    warnings = []

    try:
        fm_lines, body_lines = parse_frontmatter(SKILL_FILE)
    except ValueError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)

    if len(body_lines) > BODY_LINE_WARN:
        warnings.append(
            f'body is {len(body_lines)} lines '
            f'(spec recommends fewer than {BODY_LINE_WARN})'
        )

    for line in fm_lines:
        if re.match(r'^version:\s', line) or line.rstrip() == 'version:':
            errors.append(
                "bare top-level 'version:' key found; "
                "move it inside 'metadata:'"
            )
            break

    name = get_field(fm_lines, 'name')
    if name is None:
        errors.append("'name' field is missing or empty")
    else:
        if not NAME_PAT.match(name):
            errors.append(
                f"name '{name}' must be lowercase letters, "
                f"digits, and hyphens only"
            )
        elif name.endswith('-'):
            errors.append(f"name '{name}' must not end with a hyphen")
        elif '--' in name:
            errors.append(
                f"name '{name}' must not contain consecutive hyphens"
            )
        if len(name) > MAX_NAME_LEN:
            errors.append(f"name is {len(name)} chars (max {MAX_NAME_LEN})")
        if name != EXPECTED_NAME:
            errors.append(
                f"name '{name}' must match directory name '{EXPECTED_NAME}'"
            )

    lic = get_field(fm_lines, 'license')
    if not lic:
        errors.append("'license' field is missing or empty")

    desc = get_field(fm_lines, 'description')
    if desc is None:
        errors.append("'description' field is missing")
    elif not desc:
        errors.append("'description' field is empty")
    elif len(desc) > MAX_DESC_CHARS:
        errors.append(
            f"description is {len(desc)} chars (max {MAX_DESC_CHARS})"
        )

    for w in warnings:
        print(f'WARNING: {w}')
    for e in errors:
        print(f'ERROR: {e}', file=sys.stderr)
    if errors:
        sys.exit(1)
    if not warnings:
        print('SKILL.md frontmatter: OK')


if __name__ == '__main__':
    main()
