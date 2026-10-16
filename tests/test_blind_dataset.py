from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from vulngym_agent.blind_dataset import build_blind_dataset

from .helpers import valid_record


class BlindDatasetTests(unittest.TestCase):
    def test_materializes_complete_clean_and_history_references(self) -> None:
        clean = valid_record("entry-clean", "https://github.com/new/clean")
        corrected = valid_record("entry-history", "https://github.com/new/history")
        older = copy.deepcopy(corrected)
        older["entry_point"] = {"file": "old.py", "line": 1, "code": "old(request)"}
        older["trace"] = [older["entry_point"], older["critical_operation"]]
        rows = {"v0.1.4": [clean, corrected], "v0.1.1": [older]}
        selection = {
            "evaluation_id": "fixture",
            "reference_ref": "v0.1.4",
            "cases": [
                {"case_id": "clean", "entry_id": "entry-clean", "kind": "clean", "expected_changed_fields": []},
                {
                    "case_id": "history",
                    "entry_id": "entry-history",
                    "kind": "history_revision",
                    "candidate_ref": "v0.1.1",
                    "expected_changed_fields": [
                        "entry_point.file",
                        "entry_point.line",
                        "entry_point.code",
                        "trace",
                    ],
                },
            ],
        }

        with patch("vulngym_agent.blind_dataset.read_jsonl_at_ref", side_effect=lambda _repo, ref: rows[ref]):
            candidates, reference, review, manifest = build_blind_dataset(Path("fixture"), selection)

        self.assertEqual(manifest["counts"]["cases"], 2)
        self.assertEqual(manifest["counts"]["labels"], 16)
        self.assertEqual(reference[0]["labels"]["trace"], "correct")
        self.assertEqual(reference[1]["labels"]["entry_point"], "incorrect")
        self.assertEqual(reference[1]["labels"]["trace"], "incorrect")
        self.assertEqual(reference[1]["labels"]["commit"], "correct")
        self.assertEqual(candidates[1]["_case_id"], "history")
        self.assertEqual(review[1]["review_status"], "pending")

    def test_uses_complete_reviewed_labels_and_freezes_only_reviewed_cases(self) -> None:
        row = valid_record(repo_url="https://github.com/new/repo")
        reviewed = {
            "entry_point": "correct",
            "critical_operation": "correct",
            "vuln_category_l1": "uncertain",
            "vuln_category_l2": "uncertain",
            "vuln_title": "correct",
            "vuln_ids": "incorrect",
            "commit": "correct",
            "trace": "correct",
        }
        selection = {
            "evaluation_id": "fixture",
            "selection_status": "frozen",
            "reference_ref": "v0.1.4",
            "cases": [{
                "case_id": "reviewed",
                "entry_id": row["entry_id"],
                "kind": "clean",
                "review": {
                    "status": "reviewed",
                    "reviewer": "fixture reviewer",
                    "labels": reviewed,
                    "notes": {"basis": "fixture evidence"},
                },
            }],
        }
        with patch("vulngym_agent.blind_dataset.read_jsonl_at_ref", return_value=[row]):
            _, reference, review, manifest = build_blind_dataset(Path("fixture"), selection)

        self.assertEqual(reference[0]["labels"], reviewed)
        self.assertEqual(review[0]["provisional_labels"]["vuln_ids"], "correct")
        self.assertEqual(review[0]["review_status"], "reviewed")
        self.assertEqual(manifest["counts"]["reviewed_cases"], 1)
        self.assertEqual(manifest["counts"]["label_verdicts"]["uncertain"], 2)

    def test_rejects_frozen_selection_with_pending_review(self) -> None:
        row = valid_record(repo_url="https://github.com/new/repo")
        selection = {
            "evaluation_id": "fixture",
            "selection_status": "frozen",
            "reference_ref": "v0.1.4",
            "cases": [{"case_id": "pending", "entry_id": row["entry_id"], "kind": "clean"}],
        }
        with patch("vulngym_agent.blind_dataset.read_jsonl_at_ref", return_value=[row]):
            with self.assertRaisesRegex(ValueError, "unreviewed cases"):
                build_blind_dataset(Path("fixture"), selection)

    def test_rejects_development_repository_leakage(self) -> None:
        row = valid_record(repo_url="https://github.com/used/repo")
        selection = {
            "evaluation_id": "fixture",
            "reference_ref": "v0.1.4",
            "excluded_development_repositories": ["https://github.com/used/repo"],
            "cases": [{"case_id": "leak", "entry_id": row["entry_id"], "kind": "clean"}],
        }
        with patch("vulngym_agent.blind_dataset.read_jsonl_at_ref", return_value=[row]):
            with self.assertRaisesRegex(ValueError, "development repository leaked"):
                build_blind_dataset(Path("fixture"), selection)

    def test_rejects_development_report_leakage(self) -> None:
        row = valid_record(repo_url="https://github.com/new/repo")
        selection = {
            "evaluation_id": "fixture",
            "reference_ref": "v0.1.4",
            "excluded_development_report_ids": [row["report_id"].lower()],
            "cases": [{"case_id": "leak", "entry_id": row["entry_id"], "kind": "clean"}],
        }
        with patch("vulngym_agent.blind_dataset.read_jsonl_at_ref", return_value=[row]):
            with self.assertRaisesRegex(ValueError, "development report leaked"):
                build_blind_dataset(Path("fixture"), selection)


if __name__ == "__main__":
    unittest.main()
