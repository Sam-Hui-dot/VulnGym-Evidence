from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from vulngym_agent.readable_report import render_reports, write_readable_reports
from vulngym_agent.submission import SUBMISSION_FIELDS


def example_run():
    return {
        "workflow_version": "0.1.0",
        "entry_id": "entry-00080",
        "evidence_packet": {
            "packet_version": "0.7.0",
            "candidate_record": {"vuln_title": "Example", "trace": [{"code": "<script>alert(1)</script>"}]},
            "source_contexts": [{"evidence_id": "source:entry_point", "numbered_source": "1 | <script>alert(1)</script>"}],
        },
        "semantic_result": {"status": "completed", "provider": "fixture", "judge_provider_metadata": {"resolved_model": "fixture-v1", "requested_reasoning_effort": "high", "api_key": "secret-not-for-report"}},
        "submission_report": {
            "entry_id": "entry-00080", "report_id": "GHSA-78H3-63C4-5FQC", "verdict": "uncertain", "summary": "fixture",
            "fields": {f: {"status": "uncertain", "confidence": 0.0, "evidence": "insufficient source:entry_point", "suggested_correction": "<img src=x onerror=alert(1)>"} for f in SUBMISSION_FIELDS},
        },
        "evidence_gaps": [{"code": "fixture", "reason": "missing evidence"}],
    }


class ReadableReportTests(unittest.TestCase):
    def test_renders_eight_fields_versions_and_links_without_mutating_verdicts(self):
        row = example_run()
        original = copy.deepcopy(row)
        md, page = render_reports([row])
        self.assertEqual(row, original)
        for field in SUBMISSION_FIELDS:
            self.assertIn(field, md)
            self.assertIn(field, page)
        self.assertIn('href="#case-1-ev-', page)
        self.assertIn("0.7.0", page)
        self.assertIn("fixture-v1", page)
        self.assertIn("semantic_status", md)
        self.assertIn("requested_reasoning_effort", md)
        self.assertIn("一页总览", md)
        self.assertIn("置信度 0%", md)
        self.assertIn("summary-grid", page)
        self.assertIn("原记录主张", page)
        self.assertNotIn("secret-not-for-report", md + page)

    def test_escapes_untrusted_html_and_uses_no_active_content(self):
        md, page = render_reports([example_run()])
        self.assertNotIn("<script>", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Content-Security-Policy", page)
        self.assertIn("    insufficient", md)

    def test_rejects_invalid_submission(self):
        row = example_run()
        row["submission_report"]["fields"].pop("commit")
        with self.assertRaises(ValueError):
            render_reports([row])

    def test_batch_anchors_are_unique_and_files_are_written(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_readable_reports(output, [example_run(), example_run()])
            page = (output / "report.html").read_text(encoding="utf-8")
            self.assertIn('id="case-1-ev-', page)
            self.assertIn('id="case-2-ev-', page)
            self.assertTrue((output / "report.md").is_file())
            self.assertFalse(list(output.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
