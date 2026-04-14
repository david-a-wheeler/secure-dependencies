#!/usr/bin/env python3
# fetch_json.py: Download a URL, extract specific JSON fields, and print sanitized values.
#
# Usage: python3 fetch_json.py URL KEY [KEY ...]
#   URL  : HTTPS URL to fetch (must start with https://)
#   KEY  : dot-path into the JSON, e.g. "name" or "metadata.rubygems_mfa_required"
#
# Output: one "KEY: value" line per key requested. Values are sanitized to
#         remove control characters, bidi overrides, and zero-width chars that
#         could be used for adversarial manipulation.
#
# Security design:
#   - Only HTTPS allowed (prevents HTTP downgrade / redirect attacks)
#   - Response capped at 1 MB to avoid memory exhaustion
#   - Values are sanitized: C0/C1 controls, bidi controls, zero-width chars
#     replaced with '?'
#   - Only the specific keys requested are extracted; the rest is discarded
#   - Python stdlib only; no third-party execution

from __future__ import annotations

import json
import re
import sys
import urllib.request
import urllib.error

MAX_BYTES = 1_048_576  # 1 MB cap

_SANITIZE_RE = re.compile(
    r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f'     # C0/C1 controls (keep \t \n \r)
    r'\u202a-\u202e\u2066-\u2069\u200e\u200f'       # bidi controls
    r'\u200b-\u200d\ufeff\u00ad\u2060]'             # zero-width / soft-hyphen
)


def sanitize(text: str) -> str:
    """Replace adversarial control characters with '?'."""
    return _SANITIZE_RE.sub('?', str(text))


def get_nested(data: object, dotpath: str) -> object:
    """Walk dot-separated keys into a nested dict/list structure."""
    keys = dotpath.split('.')
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (IndexError, ValueError):
                return None
        else:
            return None
    return current


def fetch_json(url: str) -> object:
    """Fetch URL (HTTPS only) and parse as JSON. Returns parsed object."""
    if not url.startswith('https://'):
        raise ValueError(f'Only HTTPS URLs are allowed, got: {url!r}')
    req = urllib.request.Request(url, headers={'User-Agent': 'fetch_json/1.0 (security-review)'})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read(MAX_BYTES)
    return json.loads(raw.decode('utf-8', errors='replace'))


def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: python3 fetch_json.py URL KEY [KEY ...]', file=sys.stderr)
        print('  KEY may use dot notation: metadata.rubygems_mfa_required', file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]
    keys = sys.argv[2:]

    try:
        data = fetch_json(url)
    except urllib.error.HTTPError as exc:
        print(f'HTTP {exc.code}: {exc.reason}', file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(1)

    for key in keys:
        value = get_nested(data, key)
        if value is None:
            print(f'{key}: (not found)')
        elif isinstance(value, (dict, list)):
            # Compact single-line JSON for nested structures
            as_str = json.dumps(value, ensure_ascii=False)
            print(f'{key}: {sanitize(as_str)}')
        else:
            print(f'{key}: {sanitize(str(value))}')


if __name__ == '__main__':
    main()
