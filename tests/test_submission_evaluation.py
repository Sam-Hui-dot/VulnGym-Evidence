from __future__ import annotations

import unittest

from vulngym_agent.submission import SUBMISSION_FIELDS
from vulngym_agent.submission_evaluation import evaluate_submission_reports


def report(case_id: str, statuses: dict[str, str]) -> dict:
    return {
        "case_id": case_id,
        "entry_id": case_id,
        "fields": {
            field: {
                "status": statuses.get(field, "correct"),
                "confidence": 0.9,
                "evidence": "fixture evidence",
            }
            for field in SUBMISSION_FIELDS
        },
    }


class SubmissionEvaluationTests(unittest.TestCase):
    def test_scores_all_fields_precision_recall_and_exact_match(self) -> None:
        clean_labels = {field: "correct" for field in SUBMISSION_FIELDS}
        error_labels = dict(clean_labels, trace="incorrect")
        reference = [
            {"case_id": "clean", "labels": clean_labels},
            {"case_id": "error", "labels": error_labels},
        ]
        reports = [
            report("clean", {"entry_point": "incorrect"}),
            report("error", {"trace": "incorrect"}),
        ]

        result = evaluate_submission_reports(reports, reference)

        self.assertEqual(result["metrics"]["accuracy"], 15 / 16)
        self.assertEqual(result["metrics"]["incorrect_precision"], 0.5)
        self.assertEqual(result["metrics"]["incorrect_recall"], 1.0)
        self.assertEqual(result["metrics"]["incorrect_f1"], 2 / 3)
        self.assertEqual(result["metrics"]["case_exact_match"], 0.5)
        self.assertEqual(result["metrics"]["evidence_coverage"], 1.0)

    def test_missing_report_is_counted_in_denominator(self) -> None:
        reference = [
            {"case_id": "missing", "labels": {field: "correct" for field in SUBMISSION_FIELDS}}
        ]
        result = evaluate_submission_reports([], reference)
        self.assertEqual(result["metrics"]["accuracy"], 0.0)
        self.assertEqual(result["metrics"]["missing_predictions"], 8)


if __name__ == "__main__":
    unittest.main()
