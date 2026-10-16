from __future__ import annotations

import unittest

from vulngym_agent.models import Verdict
from vulngym_agent.schema import line_span, validate_schema

from .helpers import valid_record


class SchemaTests(unittest.TestCase):
    def test_valid_record_has_no_incorrect_checks(self) -> None:
        checks = validate_schema(valid_record())
        self.assertTrue(checks)
        self.assertFalse([check for check in checks if check.verdict is Verdict.INCORRECT])

    def test_line_span_accepts_current_schema_forms(self) -> None:
        self.assertEqual(line_span(7), (7, 7))
        self.assertEqual(line_span("7-9"), (7, 9))
        self.assertIsNone(line_span(0))
        self.assertIsNone(line_span("9-7"))
        self.assertIsNone(line_span(True))

    def test_invalid_commit_is_reported(self) -> None:
        record = valid_record()
        record["commit"] = "ABC"
        checks = validate_schema(record)
        failures = {check.field for check in checks if check.verdict is Verdict.INCORRECT}
        self.assertIn("commit.format", failures)


if __name__ == "__main__":
    unittest.main()

