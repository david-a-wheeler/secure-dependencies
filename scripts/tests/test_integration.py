"""Integration tests for the full run_analysis() pipeline.

These tests run the complete analysis pipeline against minimal fixture
packages, replacing only network calls (registry_client.*) and subprocess
git operations (clone_source_repo). Everything else (manifest parsing,
scanning, license evaluation, health checks, and signals writing)
uns for real.

The primary goal is to catch type mismatches and logic errors that only
surface when the full pipeline runs end-to-end, such as the
PackageManifest/dict mismatch that previously crashed
dep_review.py --basic at the license step.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

import analysis_shared
import registry_client
from dep_review import run_analysis
from python_analyzer import PythonAnalyzer
from ruby_analyzer import RubyAnalyzer
from js_analyzer import JavaScriptAnalyzer


# ---------------------------------------------------------------------------
# Stub HTTP responses
# ---------------------------------------------------------------------------

def _stub_http_get(url: str, timeout: int = 15) -> bytes | None:
    """Return minimal valid JSON for each external service, None otherwise."""
    if 'bestpractices.dev' in url:
        return json.dumps({'projects': []}).encode()
    if 'api.securityscorecards.dev' in url:
        return json.dumps({'score': 7.0, 'checks': []}).encode()
    if 'oss-rebuild.appspot.com' in url or 'oss-rebuild' in url:
        return None
    return None


def _stub_http_post(url: str, data: bytes, **kwargs: object) -> bytes | None:
    """Return an empty vulnerability list for OSV queries."""
    if 'osv.dev' in url:
        return json.dumps({'vulns': []}).encode()
    return None


_NO_CLONE = (False, '', False, False)


# ---------------------------------------------------------------------------
# Fixture analyzer base: overrides all network/subprocess/download methods
# ---------------------------------------------------------------------------

class _FixtureAnalyzerMixin:
    """Override download and registry methods with fixture data.

    Subclass alongside a real EcosystemAnalyzer to replace every method
    that touches the network or runs ecosystem CLI tools.
    """

    def _make_unpacked_dir(
        self, work: Path, pkgname: str, version: str,
    ) -> Path:
        """Create a minimal unpacked package directory for scanning."""
        raise NotImplementedError

    def download_new(
        self, pkgname: str, version: str, work: Path, failures: list,
    ) -> dict:
        unpacked_dir = self._make_unpacked_dir(work, pkgname, version)
        return {
            'ok': True,
            'unpacked_dir': unpacked_dir,
            'sha256': 'a' * 64,
            'pkg_file': None,
            'dist_type': 'fixture',
        }

    def download_old(self, pkgname: str, old_ver: str, work: Path, failures: list) -> dict:
        return {'ok': False}

    def fetch_all_registry_data(
        self, pkgname: str, version: str, work: Path, p: object,
        source_url: str = '',
    ) -> dict:
        return {'license_from_registry': ['MIT']}

    def check_lockfile(
        self, runtime_dep_lines: list, old_dep_lines: list, project_root: Path,
    ) -> dict:
        return {'in_lockfile': [], 'not_in_lockfile': []}

    def check_dep_registry(self, dep_name: str) -> dict:
        return {}

    def get_transitive_deps(
        self, pkgname: str, version: str, lockfile_path: Path,
        work: Path, p: object,
    ) -> dict:
        return {'total': 0, 'new': 0, 'deps': []}

    def check_alternatives(
        self, pkgname: str, version: str, work: Path, project_root: Path,
    ) -> dict:
        return {'concerns': [], 'notes': []}


class FixturePythonAnalyzer(_FixtureAnalyzerMixin, PythonAnalyzer):
    def _make_unpacked_dir(self, work: Path, pkgname: str, version: str) -> Path:
        unpacked = work / 'unpacked'
        unpacked.mkdir(parents=True, exist_ok=True)
        dist_info = unpacked / f'{pkgname}-{version}.dist-info'
        dist_info.mkdir()
        (dist_info / 'METADATA').write_text(
            f'Metadata-Version: 2.1\n'
            f'Name: {pkgname}\n'
            f'Version: {version}\n'
            f'License: MIT\n'
            f'Home-page: https://github.com/example/{pkgname}\n',
            encoding='utf-8',
        )
        (unpacked / f'{pkgname}.py').write_text(f'# {pkgname}\n', encoding='utf-8')
        return unpacked


class FixtureRubyAnalyzer(_FixtureAnalyzerMixin, RubyAnalyzer):
    def _make_unpacked_dir(self, work: Path, pkgname: str, version: str) -> Path:
        unpacked = work / 'unpacked'
        unpacked.mkdir(parents=True, exist_ok=True)
        (unpacked / f'{pkgname}.gemspec').write_text(
            f'Gem::Specification.new do |s|\n'
            f'  s.name = "{pkgname}"\n'
            f'  s.version = "{version}"\n'
            f'  s.license = "MIT"\n'
            f'  s.homepage = "https://github.com/example/{pkgname}"\n'
            f'end\n',
            encoding='utf-8',
        )
        (unpacked / 'lib' ).mkdir()
        (unpacked / 'lib' / f'{pkgname}.rb').write_text(f'# {pkgname}\n', encoding='utf-8')
        return unpacked


class FixtureJavaScriptAnalyzer(_FixtureAnalyzerMixin, JavaScriptAnalyzer):
    def _make_unpacked_dir(self, work: Path, pkgname: str, version: str) -> Path:
        unpacked = work / 'unpacked'
        unpacked.mkdir(parents=True, exist_ok=True)
        (unpacked / 'package.json').write_text(
            json.dumps({
                'name': pkgname,
                'version': version,
                'license': 'MIT',
                'repository': {'type': 'git', 'url': f'https://github.com/example/{pkgname}'},
            }),
            encoding='utf-8',
        )
        (unpacked / 'index.js').write_text(f'// {pkgname}\n', encoding='utf-8')
        return unpacked


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestRunAnalysisIntegration(unittest.TestCase):
    """run_analysis() completes end-to-end for each ecosystem."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _work(self, label: str) -> Path:
        work = self.root / 'temp' / 'dep-review' / label
        work.mkdir(parents=True)
        return work

    def _run(self, analyzer: object, pkgname: str, version: str) -> bool:
        """Call run_analysis with all network/subprocess stubs active."""
        work = self._work(f'{pkgname}-{version}')
        with (
            mock.patch.object(registry_client, 'http_get', _stub_http_get),
            mock.patch.object(registry_client, 'http_post', _stub_http_post),
            mock.patch.object(registry_client, 'http_get_with_headers', return_value=b'{}'),
            mock.patch.object(registry_client, '_github_api_get', return_value=None),
            mock.patch.object(analysis_shared, 'clone_source_repo', return_value=_NO_CLONE),
        ):
            return run_analysis(
                analyzer=analyzer,
                pkgname=pkgname,
                old_ver='none',
                new_ver=version,
                root=self.root,
                work=work,
                diff_mode=False,
                deeper=False,
            )

    def _check_outputs(self, pkgname: str, version: str) -> dict:
        work = self.root / 'temp' / 'dep-review' / f'{pkgname}-{version}'
        self.assertTrue(
            (work / 'signals.txt').exists(),
            'signals.txt must be written by run_analysis()',
        )
        self.assertTrue(
            (work / 'signals.json').exists(),
            'signals.json must be written by run_analysis()',
        )
        with open(work / 'signals.json', encoding='utf-8') as f:
            report = json.load(f)
        self.assertIn('risk_flags', report)
        self.assertIn('sha256', report)
        return report

    def test_python_basic_completes(self) -> None:
        aborted = self._run(FixturePythonAnalyzer(), 'testpkg', '1.0.0')
        self.assertFalse(aborted)
        report = self._check_outputs('testpkg', '1.0.0')
        self.assertEqual(report.get('adversarial_gate'), 'CLEAR')

    def test_ruby_basic_completes(self) -> None:
        aborted = self._run(FixtureRubyAnalyzer(), 'testgem', '2.0.0')
        self.assertFalse(aborted)
        self._check_outputs('testgem', '2.0.0')

    def test_javascript_basic_completes(self) -> None:
        aborted = self._run(FixtureJavaScriptAnalyzer(), 'testpkg', '3.0.0')
        self.assertFalse(aborted)
        self._check_outputs('testpkg', '3.0.0')

    def test_license_present_in_report(self) -> None:
        """License field from manifest reaches signals.json without type errors."""
        aborted = self._run(FixturePythonAnalyzer(), 'licensedpkg', '1.0.0')
        self.assertFalse(aborted)
        report = self._check_outputs('licensedpkg', '1.0.0')
        self.assertIn('license_line', report)
        self.assertIn('MIT', report['license_line'])
