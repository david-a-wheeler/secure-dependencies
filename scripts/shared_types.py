#!/usr/bin/env python3
# shared_types.py: Core data classes for dependency security analysis.
#
# Kept separate from analysis_shared.py so that ecosystem analyzers and
# tests can import the type contracts without pulling in the full
# network and scanning machinery.
#
# Python stdlib only; no third-party packages required.

from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Manifest data object
# ---------------------------------------------------------------------------

@dataclass
class PackageManifest:
    """Typed result from EcosystemAnalyzer.read_manifest().

    All fields have safe defaults so a partially-populated instance is valid.
    String 'YES'/'NO' fields match the established signal vocabulary used
    throughout write_signals() and the AI prompt.
    """
    source_url: str = ''
    extensions: str = 'NO'
    executables: str = 'NO'
    executables_list: str = ''
    post_install_msg: str = 'NO'
    has_build_hooks: str = 'NO'
    has_install_scripts: str = 'NO'
    manifest_license_raw: str = ''
    manifest_text: str = ''
    manifest_extra_file: str = ''
    runtime_dep_lines: list[str] = field(default_factory=list)
    install_hook_context: list[str] = field(default_factory=list)
    install_cmd_warnings: list[str] = field(default_factory=list)
    dangerous_what: str = ''


# ---------------------------------------------------------------------------
# Signal context object
# ---------------------------------------------------------------------------

@dataclass
class SignalContext:
    """All inputs to write_signals(), bundled so the call site is stable.

    Adding a new signal requires adding one field here and one reference
    inside write_signals(); the call site itself does not change.
    """
    # Package identity
    work: Path
    pkgname: str
    old_ver: str
    new_ver: str
    diff_mode: bool
    ecosystem: str
    # Archive
    sha256: str
    # Manifest
    manifest: PackageManifest
    # Scans
    scan_details: list[tuple[str, int]]
    total_matches: int
    diff_scan_details: list[tuple[str, int]]
    diff_scan_matches: int
    source_lines: int
    # Source clone
    clone_ok: bool
    version_tag: str
    commit_guessed: bool
    source_url: str
    source_likely_incompatible: bool
    # Registry
    registry: dict
    badge: dict
    scorecard: str
    health_concerns: list[str]
    # Package content
    extra_files: int
    binary_files: int
    # Diff (update mode)
    diff_lines: int
    changed_files: str
    # Analysis results
    license_result: dict
    dep_result: dict
    dep_registry: dict
    transitive: dict
    deeper_result: dict
    failures: list[str]
    # Mode flags
    deeper: bool
    deeper_mode: bool = False
    install_probe: bool = False
    install_probe_mode: bool = False
    # Optional results
    vuln_result: dict | None = None
    has_security_policy: bool | None = None
    scorecard_checks: dict | None = None
    recent_commits: int | None = None
    commit_activity: dict | None = None
    ecosystems_data: dict | None = None
    oss_rebuild_result: dict | None = None
    diff_semantic_result: dict | None = None
    source_review_result: dict | None = None


# ---------------------------------------------------------------------------
# Signal report object
# ---------------------------------------------------------------------------

@dataclass
class SignalReport:
    """Machine-readable summary written as signals.json alongside signals.txt.

    Fields mirror what _parse_signals() in dep_session.py extracts from
    the text file, but are typed and authoritative. dep_session.py reads
    signals.json when present rather than parsing text.
    """
    sha256: str = ''
    risk_flags: str = 'NONE'
    positive_flags: str = 'NONE'
    adversarial_gate: str = 'CLEAR'
    concern_count: int = 0
    concern_level: str = 'NONE'
    mode: str = ''
    old_version: str = ''
    license_line: str = ''
    health_line: str = ''
    clone_url: str = ''
    clone_status: str = ''
    extensions: str = 'NO'
    executables: str = 'NO'
    new_transitive_deps: str = ''
