from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from vulngym_agent.systemic_analysis import analyze_systemic_patterns, write_systemic_analysis


def run(case: str, *, gap: str | None = None, verdict: str = "incorrect") -> dict:
    gaps = []
    if gap:
        gaps.append({"code": gap, "reason": "fixture gap", "next_action": "fixture action", "severity": "warning"})
    return {
        "entry_id": case,
        "evidence_gaps": gaps,
        "submission_report": {
            "fields": {
                "commit": {
                    "status": verdict,
                    "confidence": 0.9,
                    "evidence": "candidate does not match explicitly declared vulnerable commits",
                }
            }
        },
        "semantic_result": {"judgment": {"field_results": []}, "final_judgment": {"field_results": []}},
    }


class SystemicAnalysisTests(unittest.TestCase):
    def test_reports_only_repeated_evidence_backed_patterns(self) -> None:
        report = analyze_systemic_patterns(
            [
                run("case-1", gap="fix_patch_unresolved"),
                run("case-2", gap="fix_patch_unresolved"),
                run("case-3", gap="advisory_missing", verdict="correct"),
            ]
        )
        codes = {item["code"] for item in report["patterns"]}
        self.assertIn("fix_patch_unresolved", codes)
        self.assertIn("commit_provenance_mismatch", codes)
        self.assertNotIn("advisory_missing", codes)
        self.assertTrue(all(item["status"] == "repeated_signal_not_proven_root_cause" for item in report["patterns"]))

    def test_writes_machine_and_human_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report = write_systemic_analysis(output, [run("case-1"), run("case-2")])
            self.assertEqual(report["cases"], 2)
            self.assertTrue((output / "systemic-analysis.json").is_file())
            self.assertIn("批次系统性错误分析", (output / "systemic-analysis.md").read_text(encoding="utf-8"))

    def test_rejects_single_occurrence_threshold(self) -> None:
        with self.assertRaises(ValueError):
            analyze_systemic_patterns([], minimum_occurrences=1)


if __name__ == "__main__":
    unittest.main()
