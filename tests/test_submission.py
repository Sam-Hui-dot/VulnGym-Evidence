from __future__ import annotations

import unittest

from vulngym_agent.submission import SUBMISSION_FIELDS, build_submission_report, validate_submission_report

from .test_semantic_runner import judgment


def packet() -> dict:
    return {
        "entry_id": "entry-00001",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "candidate_record": {
            "entry_id": "entry-00001",
            "report_id": "GHSA-AAAA-BBBB-CCCC",
        },
        "deterministic_audit": {
            "evidence": [
                {
                    "field": "commit.repository_object",
                    "verdict": "correct",
                    "confidence": 0.99,
                    "reason": "commit object exists",
                    "evidence_id": "deterministic:1",
                },
                {
                    "field": "entry_point.source",
                    "verdict": "correct",
                    "confidence": 0.99,
                    "reason": "source agrees",
                    "evidence_id": "deterministic:2",
                },
            ]
        },
    }


class SubmissionTests(unittest.TestCase):
    def test_formats_semantic_fields_and_abstains_on_unverified_commit(self) -> None:
        result = {"final_judgment": judgment()}
        report = build_submission_report(packet(), result)
        self.assertEqual(set(report["fields"]), set(SUBMISSION_FIELDS))
        self.assertEqual(report["fields"]["entry_point"]["status"], "correct")
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")
        self.assertEqual(report["fields"]["vuln_title"]["status"], "correct")
        self.assertEqual(report["verdict"], "uncertain")
        self.assertEqual(validate_submission_report(report), [])

    def test_deterministic_failure_overrides_semantic_judgment(self) -> None:
        broken = packet()
        broken["deterministic_audit"]["evidence"].append(
            {
                "field": "entry_point.source",
                "verdict": "incorrect",
                "confidence": 0.98,
                "reason": "declared code is absent",
                "evidence_id": "deterministic:3",
            }
        )
        report = build_submission_report(broken, {"final_judgment": judgment()})
        self.assertEqual(report["fields"]["entry_point"]["status"], "incorrect")
        self.assertEqual(report["verdict"], "incorrect")
        self.assertEqual(validate_submission_report(report), [])

    def test_unique_source_drift_proposes_a_safe_line_correction(self) -> None:
        broken = packet()
        broken["candidate_record"]["entry_point"] = {
            "file": "src/app.py",
            "line": 10,
            "code": "handle(request)",
        }
        broken["deterministic_audit"]["evidence"].append(
            {
                "field": "entry_point.source_location",
                "verdict": "incorrect",
                "confidence": 0.98,
                "reason": "the code exists uniquely in the declared file, but the declared location does not identify it",
                "evidence_id": "deterministic:3",
                "evidence": [
                    {
                        "tool": "source_search",
                        "target": "src/app.py",
                        "observation": "match_status=drifted; declared=10-10; matched=15-15; handle(request)",
                    }
                ],
            }
        )
        report = build_submission_report(broken, {"final_judgment": judgment()})
        correction = report["fields"]["entry_point"]["suggested_correction"]
        self.assertIn('"line": 15', correction)

    def test_preserves_actionable_semantic_correction(self) -> None:
        semantic = judgment()
        semantic["field_results"][0]["verdict"] = "incorrect"
        semantic["field_results"][0]["correction"] = {"proposed_value": "use the HTTP handler as entry point"}
        semantic["overall_verdict"] = "incorrect"
        report = build_submission_report(packet(), {"final_judgment": semantic})
        self.assertEqual(
            report["fields"]["entry_point"]["suggested_correction"],
            "use the HTTP handler as entry point",
        )

    def test_uses_explicit_advisory_evidence_for_ids_title_and_vulnerable_commit(self) -> None:
        value = packet()
        value["candidate_record"].update(
            vuln_ids=["CVE-2026-12345", "GHSA-AAAA-BBBB-CCCC"],
            vuln_title="Example vulnerability",
            commit="a" * 40,
        )
        value["advisory_analysis"] = {
            "status": "matched",
            "documents": [
                {
                    "evidence_id": "advisory:fixture",
                    "identifiers": ["CVE-2026-12345", "GHSA-AAAA-BBBB-CCCC"],
                    "title": "Example vulnerability",
                    "vulnerable_commits": ["a" * 40],
                }
            ],
        }
        report = build_submission_report(value, {"final_judgment": judgment()})
        self.assertEqual(report["fields"]["vuln_ids"]["status"], "correct")
        self.assertEqual(report["fields"]["vuln_title"]["status"], "correct")
        self.assertEqual(report["fields"]["commit"]["status"], "correct")

    def test_non_identical_advisory_title_uses_semantic_verdict(self) -> None:
        value = packet()
        value["candidate_record"]["vuln_title"] = "Example RCE in parser"
        value["advisory_analysis"] = {
            "status": "matched",
            "documents": [{"evidence_id": "advisory:fixture", "title": "Parser remote code execution"}],
        }
        report = build_submission_report(value, {"final_judgment": judgment("advisory:fixture")})
        self.assertEqual(report["fields"]["vuln_title"]["status"], "correct")
        self.assertEqual(report["fields"]["vuln_title"]["confidence"], 0.8)

    def test_selected_patch_with_strong_provenance_verifies_commit(self) -> None:
        value = packet()
        value["candidate_record"]["commit"] = "a" * 40
        value["patch_analysis"] = {
            "status": "selected",
            "vulnerable_commit": "a" * 40,
            "selected_fix_commit": "b" * 40,
            "selection_basis": "explicit fix-map hint",
            "selection_confidence": 0.99,
            "provenance_status": "verified",
            "provenance_basis": "trusted explicit fix-map, Git ancestry, and inspectable source diff",
            "diff": "diff --git a/file b/file\n-old\n+new",
        }
        report = build_submission_report(value, {"final_judgment": judgment()})
        self.assertEqual(report["fields"]["commit"]["status"], "correct")
        self.assertIn("patch:selected_diff", report["fields"]["commit"]["evidence"])

    def test_weak_patch_guess_does_not_verify_commit(self) -> None:
        value = packet()
        value["candidate_record"]["commit"] = "a" * 40
        value["patch_analysis"] = {
            "status": "selected",
            "vulnerable_commit": "a" * 40,
            "selected_fix_commit": "b" * 40,
            "selection_basis": "heuristic overlap",
            "selection_confidence": 0.65,
            "provenance_status": "supported",
            "provenance_basis": "heuristic patch signals without an authoritative commit role",
            "diff": "diff --git a/file b/file\n-old\n+new",
        }
        report = build_submission_report(value, {"final_judgment": judgment()})
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")

    def test_high_confidence_without_verified_provenance_does_not_verify_commit(self) -> None:
        value = packet()
        value["candidate_record"]["commit"] = "a" * 40
        value["patch_analysis"] = {
            "status": "selected",
            "vulnerable_commit": "a" * 40,
            "selected_fix_commit": "b" * 40,
            "selection_basis": "only direct child reachable from local refs",
            "selection_confidence": 0.99,
            "provenance_status": "weak",
            "provenance_basis": "Git topology without advisory role or related source change",
            "diff": "diff --git a/README.md b/README.md\n-old\n+new",
        }
        report = build_submission_report(value, {"final_judgment": judgment()})
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")

    def test_known_advisory_ids_make_empty_candidate_ids_incorrect(self) -> None:
        value = packet()
        value["candidate_record"]["vuln_ids"] = []
        value["advisory_analysis"] = {
            "status": "matched",
            "documents": [
                {
                    "evidence_id": "advisory:fixture",
                    "identifiers": ["CVE-2026-12345", "GHSA-AAAA-BBBB-CCCC"],
                }
            ],
        }
        report = build_submission_report(value, {"final_judgment": judgment("advisory:fixture")})
        self.assertEqual(report["fields"]["vuln_ids"]["status"], "incorrect")


if __name__ == "__main__":
    unittest.main()
