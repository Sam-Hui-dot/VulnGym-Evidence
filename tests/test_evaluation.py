from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vulngym_agent.evaluation import evaluate_audits
from vulngym_agent.jsonl import write_jsonl


class EvaluationTests(unittest.TestCase):
    def test_scores_case_and_field_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.jsonl"
            audits = root / "audits.jsonl"
            write_jsonl(
                manifest,
                [
                    {"case_id": "clean", "expected_incorrect_fields": []},
                    {"case_id": "bad", "expected_incorrect_fields": ["entry_point.file"]},
                ],
            )
            write_jsonl(
                audits,
                [
                    {"case_id": "clean", "overall_verdict": "correct", "checks": []},
                    {
                        "case_id": "bad",
                        "overall_verdict": "incorrect",
                        "checks": [{"field": "entry_point.source", "verdict": "incorrect"}],
                    },
                ],
            )
            result = evaluate_audits(audits, manifest)
            self.assertEqual(result["metrics"]["invalid_case_recall"], 1.0)
            self.assertEqual(result["metrics"]["field_error_recall"], 1.0)
            self.assertEqual(result["metrics"]["clean_case_accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main()

