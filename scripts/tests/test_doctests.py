"""Wire doctest examples from all script modules into unittest discovery."""
import doctest
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import analysis_shared
import analyzer_js
import analyzer_python
import analyzer_ruby
import dep_review
import dep_session
import fetch_json


def load_tests(loader, tests, ignore):
    for mod in (analysis_shared, fetch_json, dep_review, dep_session,
                analyzer_ruby, analyzer_python, analyzer_js):
        tests.addTests(doctest.DocTestSuite(mod))
    return tests
