"""Wire doctest examples from all script modules into unittest discovery."""
import doctest
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import analysis_shared
import dep_review
import dep_session
import fetch_json
import hooks_ruby


def load_tests(loader, tests, ignore):
    for mod in (analysis_shared, fetch_json, dep_review, dep_session, hooks_ruby):
        tests.addTests(doctest.DocTestSuite(mod))
    return tests
