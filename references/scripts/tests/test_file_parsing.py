"""Tests for file-parsing functions that require fixture files."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import dep_session

FIXTURES = Path(__file__).parent / 'fixtures'


def _findings():
    """Return parsed fields from the shared auto-findings fixture (cached)."""
    if not hasattr(_findings, '_cache'):
        _findings._cache = dep_session._parse_auto_findings(FIXTURES / 'auto-findings.txt')
    return _findings._cache


class TestParseAutoFindings(unittest.TestCase):

    def test_top_level_fields(self):
        f = _findings()
        self.assertEqual(f['sha256'], 'abc123def456')
        self.assertEqual(f['adversarial_gate'], 'PASS')
        self.assertEqual(f['risk_flags'], 'NATIVE_EXTENSION')
        self.assertEqual(f['concern_count'], '2')
        self.assertEqual(f['concern_level'], 'MEDIUM')

    def test_concern_summary_transitive_deps(self):
        self.assertEqual(_findings()['new_transitive_deps'], '3')

    def test_section_license(self):
        self.assertIn('MIT', _findings()['license_line'])

    def test_section_source_repository(self):
        f = _findings()
        self.assertEqual(f['clone_url'], 'https://github.com/example/pkg')
        self.assertEqual(f['clone_status'], 'OK')

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(dep_session._parse_auto_findings(Path('/no/such/file.txt')), {})


class TestParseReportSummary(unittest.TestCase):

    def test_extracts_summary_text(self):
        summary = dep_session._parse_report_summary(FIXTURES / 'analysis-report.txt')
        self.assertIn('good', summary)
        self.assertIn('well-maintained', summary)

    def test_missing_file_returns_fallback(self):
        result = dep_session._parse_report_summary(Path('/no/such/file.txt'))
        self.assertEqual(result, '(analysis-report.txt not found)')


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
                self.assertEqual(dep_session._read_lockfile_baseline(FIXTURES, registry), [])
