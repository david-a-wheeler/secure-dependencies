"""Wire doctest examples from all script modules into unittest discovery."""
import doctest
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import analysis_shared
import shared_types
import ruby_analyzer
import python_analyzer
import js_analyzer
import dep_review
import dep_session
import fetch_json


def load_tests(loader, tests, ignore):
    for mod in (shared_types, analysis_shared, fetch_json, dep_review, dep_session,
                ruby_analyzer, python_analyzer, js_analyzer):
        tests.addTests(doctest.DocTestSuite(mod))
    return tests
