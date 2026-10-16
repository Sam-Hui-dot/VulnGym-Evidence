from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vulngym_agent.repository import ReadOnlyGitRepository
from vulngym_agent.trace_inspector import inspect_trace

from .git_fixture import create_fix_history


class TraceInspectorTests(unittest.TestCase):
    def test_finds_direct_cross_file_symbol_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _fixed = create_fix_history(root)
            result = inspect_trace(
                ReadOnlyGitRepository(root),
                vulnerable,
                [
                    {"file": "src/app.py", "line": 2, "code": "return handle(request)"},
                    {"file": "src/core.py", "line": 2, "code": "return run(value)"},
                ],
            )
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["edges"][0]["status"], "direct_symbol_call")
        self.assertEqual(result["edges"][0]["symbols"], ["handle"])

    def test_reports_reverse_order_inside_one_function(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _fixed = create_fix_history(root)
            result = inspect_trace(
                ReadOnlyGitRepository(root),
                vulnerable,
                [
                    {"file": "src/app.py", "line": 2, "code": "return handle(request)"},
                    {"file": "src/app.py", "line": 1, "code": "def endpoint(request):"},
                ],
            )
        self.assertEqual(result["edges"][0]["status"], "same_function_reverse")


if __name__ == "__main__":
    unittest.main()
