from __future__ import annotations

import unittest

from vulngym_agent.semantic_report import summarize_semantic_results

from .test_semantic_runner import judgment


class SemanticReportTests(unittest.TestCase):
    def test_summarizes_usage_and_judge_critic_changes(self) -> None:
        judge = judgment()
        final = judgment()
        final["field_results"][0]["verdict"] = "uncertain"
        final["overall_verdict"] = "uncertain"
        row = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "status": "completed",
            "judgment": judge,
            "final_judgment": final,
            "judge_seconds": 2.0,
            "critic_seconds": 3.0,
            "judge_provider_metadata": {
                "usage": {"input_tokens": 100, "cached_input_tokens": 80, "output_tokens": 10}
            },
            "critic_provider_metadata": {
                "usage": {"input_tokens": 120, "cached_input_tokens": 100, "output_tokens": 12}
            },
        }
        report = summarize_semantic_results([row])
        summary = report["summary"]
        self.assertEqual(summary["successful_cases"], 1)
        self.assertEqual(summary["judge_critic_changed_cases"], 1)
        self.assertEqual(summary["usage"]["input_tokens"], 220)
        self.assertEqual(summary["calls_with_usage"], 2)
        self.assertEqual(report["cases"][0]["judge_critic_changed_fields"], ["entry_point"])

    def test_normalizes_chat_completion_usage_names(self) -> None:
        row = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "status": "completed",
            "judgment": judgment(),
            "final_judgment": judgment(),
            "judge_seconds": 1.0,
            "judge_provider_metadata": {
                "usage": {"prompt_tokens": 400, "completion_tokens": 50, "total_tokens": 450}
            },
        }
        summary = summarize_semantic_results([row])["summary"]
        self.assertEqual(summary["usage"]["input_tokens"], 400)
        self.assertEqual(summary["usage"]["output_tokens"], 50)


if __name__ == "__main__":
    unittest.main()
