from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vulngym_agent.advisory import normalize_advisory
from vulngym_agent.evidence import build_evidence_packet, packet_evidence_ids
from vulngym_agent.patch_inspector import inspect_patch
from vulngym_agent.repository import ReadOnlyGitRepository
from vulngym_agent.repository_index import RepositoryResolution
from vulngym_agent.semantic_contract import SEMANTIC_FIELDS, build_critic_request, build_judge_request, validate_semantic_output
from vulngym_agent.submission import build_submission_report

from .git_fixture import create_fix_history, git
from .helpers import valid_record


class EvidenceTests(unittest.TestCase):
    def _record(self, vulnerable: str) -> dict:
        record = valid_record()
        record["commit"] = vulnerable
        record["entry_point"] = {"file": "src/app.py", "line": 2, "code": "    return handle(request)"}
        record["critical_operation"] = {"file": "src/core.py", "line": 2, "code": "    return run(value)"}
        record["trace"] = [record["entry_point"], record["critical_operation"]]
        return record

    def test_patch_and_packet_capture_source_and_fix_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, fixed = create_fix_history(root)
            record = self._record(vulnerable)
            repository = ReadOnlyGitRepository(root)

            patch = inspect_patch(repository, record)
            self.assertEqual(patch["status"], "selected")
            self.assertEqual(patch["selected_fix_commit"], fixed)
            self.assertIn("sanitize(value)", patch["diff"])
            self.assertIn("src/core.py", patch["candidates"][0]["overlap_files"])

            resolution = RepositoryResolution(
                repo_url=record["repo_url"],
                status="resolved",
                path=root,
                origin="https://github.com/acme/example.git",
                reason="test fixture",
            )
            packet = build_evidence_packet(record, resolution=resolution, context_lines=1)
            available = [item for item in packet["source_contexts"] if item["status"] == "available"]
            self.assertEqual(len(available), 4)
            self.assertIn("patch:selected_diff", packet_evidence_ids(packet))
            self.assertEqual(packet["trace_analysis"]["status"], "available")
            self.assertIn("trace_edge:0-1", packet_evidence_ids(packet))
            self.assertEqual(packet["advisory_analysis"]["status"], "missing")
            self.assertEqual(packet["packet_version"], "0.11.0")
            contexts = {item["field"]: item for item in available}
            self.assertEqual(contexts["entry_point"]["context_after_lines"], 1)
            self.assertEqual(contexts["critical_operation"]["context_after_lines"], 40)
            self.assertNotIn("judge_request", packet)

    def test_same_file_called_helper_definition_is_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _ = create_fix_history(root)
            (root / "src" / "app.py").write_text(
                "def authorize(user):\n    return user == 'admin'\n\n"
                "def endpoint(request):\n    if not authorize(request.user):\n        return None\n    return handle(request)\n",
                encoding="utf-8",
            )
            git(root, "add", "src/app.py")
            git(root, "commit", "-q", "--amend", "--no-edit")
            vulnerable = git(root, "rev-parse", "HEAD")
            record = self._record(vulnerable)
            record["entry_point"] = {"file": "src/app.py", "line": 4, "code": "def endpoint(request):"}
            resolution = self._resolution(root, record["repo_url"])
            packet = build_evidence_packet(record, resolution=resolution, context_lines=4)
        helpers = {item["helper"]: item for item in packet["helper_contexts"]}
        self.assertIn("authorize", helpers)
        self.assertIn("return user == 'admin'", helpers["authorize"]["numbered_source"])
        self.assertIn(helpers["authorize"]["evidence_id"], packet_evidence_ids(packet))

    def test_one_hop_relative_import_helper_definition_is_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _ = create_fix_history(root)
            (root / "src" / "app.ts").write_text(
                "import { authorize } from './authz.js';\n\n"
                "export async function endpoint(req) {\n"
                "  if (!authorize(req.user)) return null;\n"
                "  return handle(req);\n}\n",
                encoding="utf-8",
            )
            (root / "src" / "authz.ts").write_text(
                "export function authorize(user) {\n  return user.role === 'admin';\n}\n",
                encoding="utf-8",
            )
            git(root, "add", "src/app.ts", "src/authz.ts")
            git(root, "commit", "-q", "--amend", "--no-edit")
            vulnerable = git(root, "rev-parse", "HEAD")
            record = self._record(vulnerable)
            record["entry_point"] = {"file": "src/app.ts", "line": 3, "code": "export async function endpoint(req) {"}
            packet = build_evidence_packet(record, resolution=self._resolution(root, record["repo_url"]), context_lines=4)
        helpers = {item["helper"]: item for item in packet["helper_contexts"]}
        self.assertEqual(helpers["authorize"]["scope"], "cross_file_one_hop")
        self.assertEqual(helpers["authorize"]["file"], "src/authz.ts")
        self.assertIn("user.role === 'admin'", helpers["authorize"]["numbered_source"])

    def test_ambiguous_cross_file_helper_definition_is_not_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _ = create_fix_history(root)
            (root / "src" / "app.ts").write_text("export function endpoint(req) { return authorize(req.user); }\n", encoding="utf-8")
            (root / "src" / "a.ts").write_text("export function authorize(user) { return true; }\n", encoding="utf-8")
            (root / "src" / "b.ts").write_text("export function authorize(user) { return false; }\n", encoding="utf-8")
            git(root, "add", "src/app.ts", "src/a.ts", "src/b.ts")
            git(root, "commit", "-q", "--amend", "--no-edit")
            vulnerable = git(root, "rev-parse", "HEAD")
            record = self._record(vulnerable)
            record["entry_point"] = {"file": "src/app.ts", "line": 1, "code": "export function endpoint(req) { return authorize(req.user); }"}
            packet = build_evidence_packet(record, resolution=self._resolution(root, record["repo_url"]), context_lines=1)
        self.assertNotIn("authorize", {item["helper"] for item in packet["helper_contexts"]})

    def _create_unrelated_child(self, root: Path, *files: str) -> tuple[str, str]:
        vulnerable, _ = create_fix_history(root)
        git(root, "reset", "--hard", "-q", vulnerable)
        for file_name in files:
            path = root / file_name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("updated metadata\n", encoding="utf-8")
            git(root, "add", file_name)
        git(root, "commit", "-q", "-m", "chore: update release metadata")
        return vulnerable, git(root, "rev-parse", "HEAD")

    def _resolution(self, root: Path, repo_url: str) -> RepositoryResolution:
        return RepositoryResolution(repo_url, "resolved", root, "https://github.com/acme/example.git", "fixture")

    def test_only_unrelated_readme_child_is_weak_and_commit_abstains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _ = self._create_unrelated_child(root, "README.md")
            record = self._record(vulnerable)
            packet = build_evidence_packet(record, resolution=self._resolution(root, record["repo_url"]))
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "weak")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")

    def test_only_lockfile_and_appcast_child_is_weak_and_commit_abstains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _ = self._create_unrelated_child(root, "pnpm-lock.yaml", "appcast.xml")
            record = self._record(vulnerable)
            packet = build_evidence_packet(record, resolution=self._resolution(root, record["repo_url"]))
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "weak")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")

    def test_advisory_explicit_fix_with_related_source_diff_verifies_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, fixed = create_fix_history(root)
            record = self._record(vulnerable)
            advisory = normalize_advisory(
                {
                    "id": record["vuln_ids"][0],
                    "facts": [f"## Fix Commit(s)\n\n- {fixed} (security validation)"],
                },
                source="fixture",
            )
            packet = build_evidence_packet(
                record,
                resolution=self._resolution(root, record["repo_url"]),
                advisory_documents=[advisory],
            )
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "verified")
        self.assertEqual(packet["patch_analysis"]["candidates"][0]["advisory_role"], "fixed")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "correct")

    def test_advisory_fix_can_be_a_later_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, direct_child = create_fix_history(root)
            (root / "src" / "core.py").write_text(
                "def handle(value):\n    validated = strict_sanitize(value)\n    return run(validated)\n",
                encoding="utf-8",
            )
            git(root, "add", "src/core.py")
            git(root, "commit", "-q", "-m", "security: complete validation hardening")
            later_fix = git(root, "rev-parse", "HEAD")
            self.assertNotEqual(direct_child, later_fix)
            record = self._record(vulnerable)
            advisory = normalize_advisory(
                {
                    "id": record["vuln_ids"][0],
                    "facts": [f"## Fix Commit(s)\n\n- {later_fix} (complete remediation)"],
                },
                source="fixture",
            )
            packet = build_evidence_packet(
                record,
                resolution=self._resolution(root, record["repo_url"]),
                advisory_documents=[advisory],
            )
        self.assertEqual(packet["patch_analysis"]["selected_fix_commit"], later_fix)
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "verified")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "correct")

    def test_advisory_fix_without_candidate_ancestry_does_not_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, _ = create_fix_history(root)
            git(root, "checkout", "-q", "--orphan", "unrelated-fix")
            git(root, "rm", "-q", "-rf", ".")
            (root / "src").mkdir(exist_ok=True)
            (root / "src" / "core.py").write_text(
                "def handle(value):\n    return run(sanitize(value))\n",
                encoding="utf-8",
            )
            git(root, "add", "src/core.py")
            git(root, "commit", "-q", "-m", "security fix on unrelated history")
            unrelated = git(root, "rev-parse", "HEAD")
            record = self._record(vulnerable)
            advisory = normalize_advisory(
                {
                    "id": record["vuln_ids"][0],
                    "facts": [f"## Fix Commit(s)\n\n- {unrelated} (unrelated history)"],
                },
                source="fixture",
            )
            packet = build_evidence_packet(
                record,
                resolution=self._resolution(root, record["repo_url"]),
                advisory_documents=[advisory],
            )
        self.assertNotEqual(packet["patch_analysis"]["provenance_status"], "verified")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")

    def test_reference_only_commit_is_not_promoted_even_with_source_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, fixed = create_fix_history(root)
            record = self._record(vulnerable)
            advisory = normalize_advisory(
                {
                    "id": record["vuln_ids"][0],
                    "references": [f"https://github.com/acme/example/commit/{fixed}"],
                },
                source="fixture",
            )
            packet = build_evidence_packet(
                record,
                resolution=self._resolution(root, record["repo_url"]),
                advisory_documents=[advisory],
            )
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "supported")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "uncertain")

    def test_advisory_supporting_fix_with_path_migration_verifies_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "-q")
            git(root, "config", "user.name", "VulnGym Test")
            git(root, "config", "user.email", "vulngym-test@example.invalid")
            old_path = root / "extensions" / "service" / "src" / "webhook.ts"
            old_path.parent.mkdir(parents=True)
            old_path.write_text("export function start(secret) { return listen(secret); }\n", encoding="utf-8")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "vulnerable webhook")
            vulnerable = git(root, "rev-parse", "HEAD")
            new_path = root / "src" / "service" / "webhook.ts"
            new_path.parent.mkdir(parents=True)
            git(root, "mv", "extensions/service/src/webhook.ts", "src/service/webhook.ts")
            new_path.write_text(
                "export function start(secret) { if (!secret) throw new Error('required'); return listen(secret); }\n",
                encoding="utf-8",
            )
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "fix: require webhook secret")
            fixed = git(root, "rev-parse", "HEAD")
            record = valid_record()
            record["commit"] = vulnerable
            record["entry_point"] = {"file": "extensions/service/src/webhook.ts", "line": 1, "code": "export function start(secret) { return listen(secret); }"}
            record["critical_operation"] = dict(record["entry_point"])
            record["trace"] = [dict(record["entry_point"]), dict(record["critical_operation"])]
            advisory = normalize_advisory(
                {
                    "id": record["vuln_ids"][0],
                    "facts": [f"Defense-in-depth / supporting fixes:\n\n- {fixed} (runtime guard)"],
                },
                source="fixture",
            )
            packet = build_evidence_packet(
                record,
                resolution=self._resolution(root, record["repo_url"]),
                advisory_documents=[advisory],
            )
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "verified")
        self.assertEqual(packet["patch_analysis"]["candidates"][0]["advisory_role"], "supporting_fix")
        self.assertTrue(
            any(path.endswith("webhook.ts") for path in packet["patch_analysis"]["path_relationship"]["basename_only"])
        )
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "correct")

    def test_explicit_fix_map_with_source_diff_verifies_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable, fixed = create_fix_history(root)
            record = self._record(vulnerable)
            packet = build_evidence_packet(
                record,
                resolution=self._resolution(root, record["repo_url"]),
                explicit_fix_commit=fixed,
            )
        self.assertEqual(packet["patch_analysis"]["provenance_status"], "verified")
        report = build_submission_report(packet, None)
        self.assertEqual(report["fields"]["commit"]["status"], "correct")

    def test_packet_exposes_matched_advisory_as_citable_evidence(self) -> None:
        record = valid_record()
        document = {
            "advisory_key": record["report_id"],
            "identifiers": [record["report_id"], *record["vuln_ids"]],
            "title": record["vuln_title"],
            "references": [record["source_link"]],
            "referenced_commits": [],
            "vulnerable_commits": [record["commit"]],
            "fixed_commits": [],
            "source": "fixture",
            "source_sha256": "a" * 64,
        }
        resolution = RepositoryResolution(record["repo_url"], "missing", None, None, "fixture")
        packet = build_evidence_packet(record, resolution=resolution, advisory_documents=[document])
        evidence_id = packet["advisory_analysis"]["documents"][0]["evidence_id"]
        self.assertIn(evidence_id, packet_evidence_ids(packet))

    def test_packet_exposes_known_business_logic_taxonomy_as_citable_evidence(self) -> None:
        record = valid_record()
        record["vuln_category_l1"] = "业务逻辑"
        record["vuln_category_l2"] = "BL-AGENT-CAPABILITY(AI/Agent能力边界绕过)"
        resolution = RepositoryResolution(record["repo_url"], "missing", None, None, "fixture")

        packet = build_evidence_packet(record, resolution=resolution)

        self.assertEqual(packet["taxonomy_analysis"]["status"], "matched")
        evidence_ids = packet_evidence_ids(packet)
        self.assertIn("taxonomy:vulngym-v0.1.4:l1:business-logic", evidence_ids)
        self.assertIn("taxonomy:vulngym-v0.1.4:l2:bl-agent-capability", evidence_ids)

    def test_packet_cross_checks_missing_authentication_against_authorization_label(self) -> None:
        record = valid_record()
        record["vuln_category_l1"] = "业务逻辑"
        record["vuln_category_l2"] = "BL-AUTHZ-MISSING(授权缺失)"
        document = {
            "advisory_key": record["report_id"],
            "identifiers": [record["report_id"]],
            "title": "Missing authentication on critical endpoint",
            "references": [record["source_link"]],
            "referenced_commits": [],
            "vulnerable_commits": [],
            "fixed_commits": [],
            "facts": ["The endpoint has no authentication dependency."],
            "weaknesses": ["CWE-306"],
            "affected_versions": [],
            "patched_versions": [],
            "source": "fixture",
            "source_sha256": "b" * 64,
        }
        resolution = RepositoryResolution(record["repo_url"], "missing", None, None, "fixture")

        packet = build_evidence_packet(record, resolution=resolution, advisory_documents=[document])

        cross_checks = [
            item
            for item in packet["taxonomy_analysis"]["documents"]
            if item.get("cross_check") == "semantic_conflict"
        ]
        self.assertEqual({item["field"] for item in cross_checks}, {"vuln_category_l1", "vuln_category_l2"})
        self.assertTrue({item["evidence_id"] for item in cross_checks} <= packet_evidence_ids(packet))

    def test_packet_exposes_observed_non_business_taxonomy_pair(self) -> None:
        record = valid_record()
        record["vuln_category_l1"] = "命令注入"
        record["vuln_category_l2"] = "OS命令注入"
        resolution = RepositoryResolution(record["repo_url"], "missing", None, None, "fixture")

        packet = build_evidence_packet(record, resolution=resolution)

        self.assertEqual(packet["taxonomy_analysis"]["status"], "matched")
        documents = packet["taxonomy_analysis"]["documents"]
        self.assertEqual({item["field"] for item in documents}, {"vuln_category_l1", "vuln_category_l2"})
        self.assertTrue(all(item["evidence_id"] in packet_evidence_ids(packet) for item in documents))

    def test_semantic_contract_rejects_unknown_evidence(self) -> None:
        packet = {"case_id": "case", "entry_id": "entry-00001"}
        request = build_judge_request(packet)
        self.assertEqual(request["task"], "vulngym_t1_semantic_judge")
        self.assertEqual(request["prompt_metadata"]["prompt_id"], "vulngym.t1.semantic.judge")
        self.assertEqual(request["prompt_metadata"]["version"], "1.7.0")
        self.assertEqual(len(request["prompt_metadata"]["sha256"]), 64)
        self.assertEqual(request["valid_evidence_ids"], [])

        judgment = {
            "case_id": "case",
            "entry_id": "entry-00001",
            "field_results": [
                {
                    "field": field,
                    "verdict": "correct",
                    "confidence": 0.9,
                    "reason": "supported",
                    "evidence_refs": ["unknown:evidence"],
                    "correction": None,
                }
                for field in SEMANTIC_FIELDS
            ],
            "overall_verdict": "correct",
            "overall_confidence": 0.9,
            "self_check": {
                "looked_for_counterevidence": True,
                "unresolved_questions": [],
                "unsupported_claims_removed": True,
            },
        }
        validation = validate_semantic_output(judgment, {"source:entry_point"})
        self.assertFalse(validation.valid)
        self.assertTrue(any("unknown evidence" in error for error in validation.errors))
        critic_request = build_critic_request(packet, judgment)
        self.assertEqual(critic_request["task"], "vulngym_t1_semantic_critic")
        self.assertEqual(critic_request["prompt_metadata"]["prompt_id"], "vulngym.t1.semantic.critic")
        self.assertEqual(critic_request["valid_evidence_ids"], [])


if __name__ == "__main__":
    unittest.main()
