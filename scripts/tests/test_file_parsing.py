"""Tests for file-parsing functions that require fixture files."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import dep_session

FIXTURES = Path(__file__).parent / 'fixtures'


_signals_cache: dict | None = None


def _signals() -> dict:
    """Return parsed fields from the shared signals fixture (cached)."""
    global _signals_cache
    if _signals_cache is None:
        # signals.json is present alongside signals.txt, so JSON path is used.
        _signals_cache = dep_session._parse_signals(FIXTURES / 'signals.txt')
    return _signals_cache


class TestParseAutoFindings(unittest.TestCase):

    def test_top_level_fields(self):
        f = _signals()
        self.assertEqual(f['sha256'], 'abc123def456')
        self.assertEqual(f['adversarial_gate'], 'PASS')
        self.assertEqual(f['risk_flags'], 'NATIVE_EXTENSION')
        self.assertEqual(f['concern_count'], '2')
        self.assertEqual(f['concern_level'], 'MEDIUM')

    def test_concern_summary_transitive_deps(self):
        self.assertEqual(_signals()['new_transitive_deps'], '3')

    def test_section_license(self):
        self.assertIn('MIT', _signals()['license_line'])

    def test_section_source_repository(self):
        f = _signals()
        self.assertEqual(f['clone_url'], 'https://github.com/example/pkg')
        self.assertEqual(f['clone_status'], 'OK')

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(
            dep_session._parse_signals(Path('/no/such/file.txt')), {})

    def test_text_fallback_when_no_json(self):
        """Text parsing is used when only signals.txt exists (no signals.json)."""
        with tempfile.TemporaryDirectory() as tmp:
            txt = Path(tmp) / 'signals.txt'
            txt.write_text(
                (FIXTURES / 'signals.txt').read_text(encoding='utf-8'),
                encoding='utf-8',
            )
            f = dep_session._parse_signals(txt)
        self.assertEqual(f['sha256'], 'abc123def456')
        self.assertEqual(f['risk_flags'], 'NATIVE_EXTENSION')
        self.assertIn('MIT', f['license_line'])
        self.assertEqual(f['clone_url'], 'https://github.com/example/pkg')


class TestReadVerdict(unittest.TestCase):

    def test_reads_summary_from_verdict_json(self):
        verdict = dep_session._read_verdict(FIXTURES)
        self.assertIn('good', verdict['summary'])
        self.assertIn('well-maintained', verdict['summary'])

    def test_reads_risk_factors(self):
        verdict = dep_session._read_verdict(FIXTURES)
        self.assertEqual(verdict['risk_increasing'], 'none')
        self.assertIn('MFA', verdict['risk_decreasing'])

    def test_missing_dir_returns_empty_defaults(self):
        verdict = dep_session._read_verdict(Path('/no/such/dir'))
        self.assertEqual(verdict['summary'], '')
        self.assertEqual(verdict['risk_increasing'], '')
        self.assertEqual(verdict['risk_decreasing'], '')


class TestParseLockfileVersions(unittest.TestCase):
    """Unit tests for the lockfile version parsers used by diff-packages."""

    def test_gemfile_lock_versions(self):
        content = (FIXTURES / 'Gemfile.lock').read_text()
        pkgs = dep_session._parse_gemfile_lock_versions(content)
        self.assertEqual(pkgs.get('rack'), '3.0.0')
        self.assertEqual(pkgs.get('rails'), '7.0.0')
        self.assertEqual(pkgs.get('activesupport'), '7.0.0')
        # Sub-dep constraint lines (= 7.0.0) must not be included as versions
        self.assertNotIn('railties', pkgs)

    def test_toml_lock_versions(self):
        content = """\
[[package]]
name = "requests"
version = "2.28.1"
description = "HTTP library"

[[package]]
name = "Flask"
version = "2.3.0"
"""
        pkgs = dep_session._parse_toml_lock_versions(content)
        self.assertEqual(pkgs.get('requests'), '2.28.1')
        self.assertEqual(pkgs.get('flask'), '2.3.0')

    def test_requirements_txt_versions(self):
        content = "requests==2.28.1\nflask>=2.0\ndjango~=4.2\n"
        pkgs = dep_session._parse_requirements_txt_versions(content)
        self.assertEqual(pkgs.get('requests'), '2.28.1')
        self.assertNotIn('flask', pkgs)   # range, not pin
        self.assertNotIn('django', pkgs)  # range, not pin

    def test_pipfile_lock_versions(self):
        content = (
            '{"default": {"requests": {"version": "==2.28.1"}},'
            ' "develop": {"pytest": {"version": "==7.2.0"}}}'
        )
        pkgs = dep_session._parse_pipfile_lock_versions(content)
        self.assertEqual(pkgs.get('requests'), '2.28.1')
        self.assertEqual(pkgs.get('pytest'), '7.2.0')

    def test_package_lock_json_versions_v3(self):
        content = (
            '{"lockfileVersion":3,"packages":{'
            '"":{},'
            '"node_modules/lodash":{"version":"4.17.21"},'
            '"node_modules/@scope/pkg":{"version":"1.0.0"},'
            '"node_modules/lodash/node_modules/deep":{"version":"0.1.0"}'
            '}}'
        )
        pkgs = dep_session._parse_package_lock_json_versions(content)
        self.assertEqual(pkgs.get('lodash'), '4.17.21')
        self.assertEqual(pkgs.get('@scope/pkg'), '1.0.0')
        self.assertNotIn('deep', pkgs)   # nested dep, skipped

    def test_yarn_lock_versions(self):
        content = """\
# yarn lockfile v1

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash"

"@scope/pkg@^1.0.0":
  version "1.0.0"
"""
        pkgs = dep_session._parse_yarn_lock_versions(content)
        self.assertEqual(pkgs.get('lodash'), '4.17.21')
        self.assertEqual(pkgs.get('@scope/pkg'), '1.0.0')

    def test_pnpm_lock_v6(self):
        content = """\
lockfileVersion: '6.0'

packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-xxx}
  /@scope/pkg/1.0.0:
    resolution: {integrity: sha512-yyy}
"""
        pkgs = dep_session._parse_pnpm_lock_versions(content)
        self.assertEqual(pkgs.get('lodash'), '4.17.21')
        self.assertEqual(pkgs.get('@scope/pkg'), '1.0.0')


class TestReadLockfileBaseline(unittest.TestCase):

    def test_rubygems_extracts_top_level_gems(self):
        names = dep_session._read_lockfile_baseline(FIXTURES, 'rubygems')
        self.assertIn('rack', names)
        self.assertIn('rails', names)
        self.assertIn('activesupport', names)

    def test_rubygems_excludes_sub_dependency_lines(self):
        # Sub-deps (6-space indent) should not appear as separate entries
        names = dep_session._read_lockfile_baseline(FIXTURES, 'rubygems')
        # 'railties' only appears as a sub-dep of rails (6-space), not as a
        # standalone gem in our fixture, so it must not be in the baseline.
        self.assertNotIn('railties', names)

    def test_non_rubygems_returns_empty(self):
        for registry in ('pypi', 'npm'):
            with self.subTest(registry=registry):
                self.assertEqual(
                    dep_session._read_lockfile_baseline(FIXTURES, registry),
                    [])
