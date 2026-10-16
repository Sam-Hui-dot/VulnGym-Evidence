from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vulngym_agent.advisory import advisory_evidence, load_advisory_cache, normalize_advisory


class AdvisoryTests(unittest.TestCase):
    def test_normalizes_ghsa_and_matches_by_identifier(self) -> None:
        document = normalize_advisory(
            {
                "ghsa_id": "GHSA-2345-6789-CFGH",
                "cve_id": "CVE-2026-12345",
                "summary": "Example vulnerability",
                "references": [{"url": "https://github.com/acme/project/commit/abcdef1234567890"}],
                "facts": ["User-controlled input reaches a process execution sink."],
                "weaknesses": ["CWE-78"],
                "affected_versions": ["< 1.2.3"],
                "patched_versions": ["1.2.3"],
            },
            source="fixture.json",
        )
        evidence = advisory_evidence(
            {"report_id": "GHSA-2345-6789-CFGH", "vuln_ids": ["CVE-2026-12345"]},
            [document],
        )
        self.assertEqual(evidence["status"], "matched")
        self.assertEqual(evidence["documents"][0]["referenced_commits"], ["abcdef1234567890"])
        self.assertFalse(evidence["documents"][0]["vulnerable_commits"])
        self.assertFalse(evidence["documents"][0]["fixed_commits"])
        self.assertFalse(evidence["documents"][0]["supporting_fix_commits"])
        self.assertEqual(
            evidence["documents"][0]["facts"],
            ["User-controlled input reaches a process execution sink."],
        )
        self.assertEqual(evidence["documents"][0]["weaknesses"], ["CWE-78"])
        self.assertEqual(evidence["documents"][0]["affected_versions"], ["< 1.2.3"])
        self.assertEqual(evidence["documents"][0]["patched_versions"], ["1.2.3"])

    def test_loads_jsonl_and_preserves_explicit_commit_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisories.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "id": "CVE-2026-12345",
                        "vulnerable_commits": ["a" * 40],
                        "fixed_commits": ["b" * 40],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            documents = load_advisory_cache([path])
        self.assertEqual(documents[0]["vulnerable_commits"], ["a" * 40])
        self.assertEqual(documents[0]["fixed_commits"], ["b" * 40])

    def test_extracts_explicit_markdown_commit_roles_without_promoting_references(self) -> None:
        main_fix = "b" * 40
        supporting_fix = "c" * 40
        reference_only = "d" * 40
        document = normalize_advisory(
            {
                "id": "CVE-2026-12345",
                "references": [{"url": f"https://github.com/acme/project/commit/{reference_only}"}],
                "facts": [
                    "## Fix Commit(s)\n\n"
                    f"- {main_fix} (primary fix)\n\n"
                    "Defense-in-depth / supporting fixes:\n\n"
                    f"- {supporting_fix} (runtime guard)"
                ],
            },
            source="fixture.json",
        )
        self.assertEqual(document["fixed_commits"], [main_fix])
        self.assertEqual(document["supporting_fix_commits"], [supporting_fix])
        self.assertEqual(document["referenced_commits"], [reference_only])
        self.assertNotIn(reference_only, document["fixed_commits"])
        self.assertNotIn(reference_only, document["supporting_fix_commits"])


if __name__ == "__main__":
    unittest.main()
