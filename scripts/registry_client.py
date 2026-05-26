#!/usr/bin/env python3
# registry_client.py: HTTP primitives and GitHub API helpers for dep_review.py.
#
# Contains all functions that make outbound network calls so that
# analysis_shared.py can import them, and tests can replace them with
# fixtures without monkey-patching urllib directly.
#
# Python stdlib only; no third-party packages required.

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# 10 MB cap: prevents memory exhaustion from oversized registry responses.
_HTTP_MAX_BYTES = 10_485_760


# ---------------------------------------------------------------------------
# HTTP primitives
# ---------------------------------------------------------------------------

def http_get(url: str, timeout: int = 15) -> bytes | None:
    """Fetch a URL; return bytes or None on error."""
    if not url.startswith('https://'):
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read(_HTTP_MAX_BYTES)
    except Exception:  # noqa: BLE001
        return None


def http_get_with_headers(
    url: str,
    headers: dict[str, str],
    timeout: int = 15,
) -> bytes:
    """Fetch a URL with custom headers; return bytes on success.

    Raises urllib.error.HTTPError on HTTP error responses (including 429),
    so callers can distinguish rate-limiting from connection failures.
    Raises urllib.error.URLError on connection errors.
    """
    if not url.startswith('https://'):
        raise ValueError(f'Only https:// URLs are allowed: {url!r}')
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(_HTTP_MAX_BYTES)


def http_post(
    url: str,
    data: bytes,
    content_type: str = 'application/json',
    timeout: int = 15,
) -> bytes | None:
    """POST data to url; return response bytes or None on error."""
    if not url.startswith('https://'):
        return None
    req = urllib.request.Request(url, data=data, headers={'Content-Type': content_type})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(_HTTP_MAX_BYTES)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# GitHub REST API helper
# ---------------------------------------------------------------------------

# ETag cache: maps URL to (etag, response_body). Prevents re-fetching
# unchanged repo metadata within a single analysis session, keeping
# unauthenticated usage within the 60 req/hr rate limit.
_github_etag_cache: dict[str, tuple[str, bytes]] = {}

# Matches owner/repo in github.com URLs or git@github.com:owner/repo URLs.
# {1,100} bounds prevent ReDoS on adversarial source_url values.
_RE_GITHUB_REPO = re.compile(
    r'github\.com[/:]([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})'
)


def _github_api_get(url: str, timeout: int = 15) -> bytes | None:
    """Fetch a GitHub API URL with ETag caching; return bytes or None.

    Sends If-None-Match with a cached ETag when available; on HTTP 304
    returns the cached body without counting as a new request. On success
    stores the new ETag for future calls.
    """
    if not url.startswith('https://'):
        return None
    headers: dict[str, str] = {'Accept': 'application/vnd.github+json'}
    cached = _github_etag_cache.get(url)
    if cached:
        etag, _ = cached
        headers['If-None-Match'] = etag
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(_HTTP_MAX_BYTES)
            new_etag = resp.headers.get('ETag', '')
            if new_etag:
                _github_etag_cache[url] = (new_etag, body)
            return body
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and cached:
            return cached[1]
        return None
    except Exception:  # noqa: BLE001
        return None


def github_repo_meta(source_url: str) -> dict | None:
    """Fetch GitHub repo metadata for a source URL.

    Uses two GitHub REST API calls (repo metadata + contents/results);
    both use ETag caching to stay within the 60 req/hr rate limit.

    Returns dict with keys:
      owner (str), repo (str), description (str), has_results_dir (bool)
    or None if source_url is not a GitHub URL or the metadata request fails.
    """
    m = _RE_GITHUB_REPO.search(source_url)
    if not m:
        return None
    owner = m.group(1)
    repo = re.sub(r'\.git$', '', m.group(2))

    meta_url = f'https://api.github.com/repos/{owner}/{repo}'
    meta_data = _github_api_get(meta_url)
    if not meta_data:
        return None
    try:
        meta_json = json.loads(meta_data.decode('utf-8', errors='replace'))
    except ValueError:
        return None

    description = str(meta_json.get('description', '') or '')

    # Check for results/ credential-staging directory.
    # GitHub returns a JSON array for a directory listing (200) and a
    # JSON object for errors (404 -> None from _github_api_get).
    contents_url = (
        f'https://api.github.com/repos/{owner}/{repo}/contents/results'
    )
    contents_data = _github_api_get(contents_url)
    has_results_dir = False
    if contents_data:
        try:
            has_results_dir = isinstance(
                json.loads(contents_data.decode('utf-8', errors='replace')),
                list,
            )
        except ValueError:
            pass

    return {
        'owner': owner,
        'repo': repo,
        'description': description,
        'has_results_dir': has_results_dir,
    }
