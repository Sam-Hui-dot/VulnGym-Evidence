from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from vulngym_agent.advisory import normalize_advisory
from vulngym_agent.repository_index import RepositoryResolution, RepositoryResolver
from vulngym_agent.workflow import evidence_gaps, preflight_plan, run_validation_record

from .git_fixture import create_fix_history
from .helpers import valid_record
from .test_semantic_runner import FakeProvider


class WorkflowTests(unittest.TestCase):
    def test_runs_complete_validation_workflow_and_reflects_on_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            vulnerable, _fixed = create_fix_history(repository)
            record = valid_record()
            record.update(
                _case_id="case-1",
                commit=vulnerable,
                report_id="GHSA-2345-6789-CFGH",
                source_link="https://github.com/advisories/GHSA-2345-6789-CFGH",
                vuln_ids=["CVE-2026-12345", "GHSA-2345-6789-CFGH"],
            )
            record["entry_point"] = {"file": "src/app.py", "line": 2, "code": "return handle(request)"}
            record["critical_operation"] = {"file": "src/core.py", "line": 2, "code": "return run(value)"}
            record["trace"] = [record["entry_point"], record["critical_operation"]]
            advisory = normalize_advisory(
                {
                    "source_link": record["source_link"],
                    "identifiers": record["vuln_ids"],
                    "title": record["vuln_title"],
                    "vulnerable_commits": [vulnerable],
                },
                source="fixture",
            )
            provider = FakeProvider()
            result = run_validation_record(
                record,
                resolver=RepositoryResolver(),
                provider=provider,
                explicit_repository=repository,
                advisory_documents=[advisory],
            )

        self.assertEqual(result["semantic_result"]["status"], "completed")
        self.assertEqual(result["submission_report"]["verdict"], "correct")
        self.assertTrue(result["reflection"]["ready_for_human_review"])
        self.assertEqual(
            provider.tasks,
            ["vulngym_t1_semantic_judge", "vulngym_t1_semantic_critic"],
        )
        self.assertEqual(result["plan"][-1]["status"], "completed")
        self.assertTrue(all("decision" in step and "reason" in step for step in result["plan"]))

    def test_preflight_skips_tools_without_required_resources(self) -> None:
        record = valid_record()
        plan = preflight_plan(
            record,
            resolution=RepositoryResolution(
                repo_url=record["repo_url"],
                status="missing",
                path=None,
                origin=None,
                reason="fixture",
            ),
            advisory_available=False,
            use_critic=False,
        )
        decisions = {step["step"]: step["decision"] for step in plan}
        self.assertEqual(decisions["inspect_fix_patch"], "skip")
        self.assertEqual(decisions["inspect_trace"], "skip")
        self.assertEqual(decisions["read_advisory"], "skip")
        self.assertEqual(decisions["seek_counterevidence"], "skip")

    def test_gap_planner_names_missing_resources(self) -> None:
        packet = {
            "repository": {"status": "missing"},
            "source_contexts": [{"field": "entry_point", "status": "missing"}],
            "patch_analysis": {"status": "not_found"},
            "trace_analysis": {"edges": [{"status": "unresolved"}]},
            "advisory_analysis": {"documents": []},
            "taxonomy_analysis": {"documents": []},
        }
        self.assertEqual(
            {item["code"] for item in evidence_gaps(packet)},
            {
                "repository_missing",
                "source_context_incomplete",
                "advisory_missing",
                "fix_patch_unresolved",
                "trace_edges_unproven",
                "taxonomy_missing",
            },
        )


if __name__ == "__main__":
    unittest.main()
