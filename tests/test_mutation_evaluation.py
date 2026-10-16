from __future__ import annotations

import unittest

from vulngym_agent.mutation_evaluation import compare_mutation_detection
from vulngym_agent.semantic_contract import SEMANTIC_FIELDS


def judgment(target: str, target_verdict: str) -> dict:
    return {
        "field_results": [
            {
                "field": field,
                "verdict": target_verdict if field == target else "uncertain",
                "confidence": 0.9,
            }
            for field in SEMANTIC_FIELDS
        ]
    }


class MutationEvaluationTests(unittest.TestCase):
    def test_comparison_scores_only_target_fields(self) -> None:
        manifest = [
            {
                "case_id": "case-1",
                "mutation": "donor_entry_point",
                "target_fields": ["entry_point"],
            }
        ]
        bare = [{"case_id": "case-1", "final_judgment": judgment("entry_point", "correct")}]
        agent = [
            {
                "case_id": "case-1",
                "judgment": judgment("entry_point", "uncertain"),
                "final_judgment": judgment("entry_point", "incorrect"),
            }
        ]

        result = compare_mutation_detection(manifest, bare, agent)

        self.assertEqual(result["bare_record"]["target_detection_recall"], 0.0)
        self.assertEqual(result["evidence_judge"]["target_detection_recall"], 0.0)
        self.assertEqual(result["evidence_judge_critic"]["target_detection_recall"], 1.0)
        self.assertEqual(result["bare_record"]["target_labels"], 1)


if __name__ == "__main__":
    unittest.main()
