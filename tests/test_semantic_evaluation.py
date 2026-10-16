from __future__ import annotations

import unittest

from vulngym_agent.semantic_contract import SEMANTIC_FIELDS
from vulngym_agent.semantic_evaluation import evaluate_semantic_results

from .test_semantic_runner import judgment


class SemanticEvaluationTests(unittest.TestCase):
    def test_scores_judge_critic_change_and_high_confidence_error(self) -> None:
        judge = judgment()
        final = judgment()
        judge["field_results"][0]["verdict"] = "incorrect"
        judge["field_results"][0]["confidence"] = 0.9
        judge["overall_verdict"] = "incorrect"
        row = {
            "entry_id": "entry-00001",
            "judgment": judge,
            "final_judgment": final,
        }
        gold = [{"entry_id": "entry-00001", "labels": {field: "correct" for field in SEMANTIC_FIELDS}}]

        result = evaluate_semantic_results([row], gold)

        expected_judge_accuracy = (len(SEMANTIC_FIELDS) - 1) / len(SEMANTIC_FIELDS)
        self.assertEqual(result["judge"]["accuracy"], expected_judge_accuracy)
        self.assertEqual(result["final"]["accuracy"], 1.0)
        self.assertAlmostEqual(result["critic_accuracy_delta"], 1 / len(SEMANTIC_FIELDS))
        self.assertEqual(len(result["judge"]["high_confidence_errors"]), 1)

    def test_penalizes_missing_result_and_rejects_incomplete_gold(self) -> None:
        gold = [{"case_id": "missing", "labels": {field: "correct" for field in SEMANTIC_FIELDS}}]
        result = evaluate_semantic_results([], gold)
        self.assertEqual(result["final"]["accuracy"], 0.0)
        self.assertEqual(result["final"]["missing_predictions"], len(SEMANTIC_FIELDS))

        with self.assertRaises(ValueError):
            evaluate_semantic_results([], [{"case_id": "bad", "labels": {"entry_point": "correct"}}])


if __name__ == "__main__":
    unittest.main()
