from __future__ import annotations

import copy
import unittest

from vulngym_agent.history import history_difference_fields

from .helpers import valid_record


class HistoryTests(unittest.TestCase):
    def test_ignores_desc_only_edits(self) -> None:
        old = valid_record()
        reference = copy.deepcopy(old)
        reference["entry_point"]["desc"] = "better explanation"
        self.assertEqual(history_difference_fields(old, reference), [])

    def test_reports_priority_leaf_fields_and_trace(self) -> None:
        old = valid_record()
        reference = copy.deepcopy(old)
        reference["entry_point"]["line"] = 11
        reference["critical_operation"]["code"] = "safe_run(value)"
        reference["trace"] = list(reversed(reference["trace"]))
        self.assertEqual(
            history_difference_fields(old, reference),
            ["entry_point.line", "critical_operation.code", "trace"],
        )


if __name__ == "__main__":
    unittest.main()

