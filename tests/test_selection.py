from __future__ import annotations

import unittest

from vulngym_agent.selection import select_records

from .helpers import valid_record


class SelectionTests(unittest.TestCase):
    def test_preserves_requested_order(self) -> None:
        first = valid_record("entry-00001")
        second = valid_record("entry-00002")
        selected = select_records([first, second], ["entry-00002", "entry-00001"])
        self.assertEqual([record["entry_id"] for record in selected], ["entry-00002", "entry-00001"])

    def test_rejects_missing_entry(self) -> None:
        with self.assertRaisesRegex(ValueError, "absent"):
            select_records([valid_record()], ["entry-99999"])


if __name__ == "__main__":
    unittest.main()

