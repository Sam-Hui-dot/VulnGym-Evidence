from __future__ import annotations

import unittest

from vulngym_agent.benchmark import build_repo_holdout_mutations

from .helpers import valid_record


class BenchmarkTests(unittest.TestCase):
    def test_repo_holdout_mutations_use_cross_repository_donors(self) -> None:
        first = valid_record("entry-00001", "https://github.com/acme/one")
        second = valid_record("entry-00002", "https://github.com/acme/two")
        second["entry_point"] = {"file": "other/input.py", "line": 8, "code": "receive(data)"}
        second["critical_operation"] = {"file": "other/sink.py", "line": 19, "code": "execute(data)"}

        candidates, manifest = build_repo_holdout_mutations([first, second])

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0]["entry_point"], second["entry_point"])
        self.assertEqual(candidates[1]["critical_operation"], first["critical_operation"])
        self.assertEqual(manifest[0]["target_fields"], ["entry_point"])
        self.assertNotIn("VULNGYM_MUTATED", str(candidates))

    def test_repo_holdout_mutations_require_distinct_repositories(self) -> None:
        first = valid_record("entry-00001")
        second = valid_record("entry-00002")
        with self.assertRaisesRegex(ValueError, "different repository"):
            build_repo_holdout_mutations([first, second])


if __name__ == "__main__":
    unittest.main()
