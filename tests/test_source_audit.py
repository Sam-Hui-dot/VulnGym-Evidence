from __future__ import annotations

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulngym_agent.engine import AuditEngine
from vulngym_agent.models import Verdict

from .helpers import valid_record


class SourceAuditTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def test_reads_commit_and_detects_tampered_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "def endpoint(request):\n    return handle(request)\n",
                encoding="utf-8",
            )
            (root / "src" / "core.py").write_text(
                "def handle(value):\n    return run(value)\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.py", "src/core.py")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {"file": "src/app.py", "line": 2, "code": "    return handle(request)"}
            record["critical_operation"] = {"file": "src/core.py", "line": 2, "code": "    return run(value)"}
            record["trace"] = []

            engine = AuditEngine(root)
            clean = engine.audit(record)
            source_failures = [
                check for check in clean.checks
                if check.field.endswith(".source") and check.verdict is Verdict.INCORRECT
            ]
            self.assertFalse(source_failures)
            self.assertTrue(
                any(
                    check.field == "commit.repository_object" and check.verdict is Verdict.CORRECT
                    for check in clean.checks
                )
            )

            tampered = copy.deepcopy(record)
            tampered["critical_operation"]["code"] = "return execute_untrusted(value)"
            result = engine.audit(tampered)
            self.assertEqual(result.overall_verdict, Verdict.INCORRECT)
            self.assertTrue(
                any(
                    check.field == "critical_operation.source" and check.verdict is Verdict.INCORRECT
                    for check in result.checks
                )
            )

    def test_nearby_line_drift_is_not_automatically_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "def endpoint(request):\n    marker = True\n    return handle(request)\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.py")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {"file": "src/app.py", "line": 2, "code": "    return handle(request)"}
            record["critical_operation"] = {"file": "src/app.py", "line": 3, "code": "    return handle(request)"}
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            drift = next(check for check in result.checks if check.field == "entry_point.source_location")
            self.assertEqual(drift.verdict, Verdict.INCORRECT)
            self.assertIn("match_status=drifted", drift.evidence[0].observation)

    def test_integer_line_is_start_of_multiline_snippet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "def endpoint(request):\n    value = load(request)\n    return handle(value)\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.py")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {
                "file": "src/app.py",
                "line": 2,
                "code": "    value = load(request)\n    return handle(value)",
            }
            record["critical_operation"] = {"file": "src/app.py", "line": 3, "code": "    return handle(value)"}
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            entry = next(check for check in result.checks if check.field == "entry_point.source")
            self.assertEqual(entry.verdict, Verdict.CORRECT)
            self.assertIn(":2-3", entry.evidence[0].target)

    def test_ellipsis_summary_does_not_create_deterministic_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "def endpoint(\n    request,\n    token,\n):\n    return handle(request)\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.py")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {
                "file": "src/app.py",
                "line": 1,
                "code": "def endpoint(\n    request,\n    ...",
            }
            record["critical_operation"] = {"file": "src/app.py", "line": 5, "code": "    return handle(request)"}
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            entry = next(check for check in result.checks if check.field == "entry_point.source_summary")
            self.assertEqual(entry.verdict, Verdict.UNCERTAIN)
            self.assertIn("match_status=summary_placeholder", entry.evidence[0].observation)

    def test_matching_multiline_start_with_summarized_body_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "def endpoint(request):\n    value = normalize(request)\n    return handle(value)\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.py")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {
                "file": "src/app.py",
                "line": 1,
                "code": "def endpoint(request):\n    return handle(request)",
            }
            record["critical_operation"] = {"file": "src/app.py", "line": 3, "code": "    return handle(value)"}
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            entry = next(check for check in result.checks if check.field == "entry_point.source_content")
            self.assertEqual(entry.verdict, Verdict.UNCERTAIN)
            self.assertIn("match_status=anchored_summary", entry.evidence[0].observation)

    def test_trailing_explanatory_annotation_does_not_fail_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.ts").write_text(
                'const url = "https://example.invalid/api";\nrun(value);\n',
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.ts")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {
                "file": "src/app.ts",
                "line": 1,
                "code": 'const url = "https://example.invalid/api"; // explanatory note',
            }
            record["critical_operation"] = {
                "file": "src/app.ts",
                "line": 2,
                "code": "run(value); // security impact explanation",
            }
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            source_checks = [
                check for check in result.checks
                if check.field in {"entry_point.source", "critical_operation.source"}
            ]
            self.assertEqual([check.verdict for check in source_checks], [Verdict.CORRECT, Verdict.CORRECT])
            self.assertTrue(all("annotated_exact" in check.evidence[0].observation for check in source_checks))

    def test_compressed_single_line_source_is_deferred_to_semantic_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.ts").write_text(
                "const stream = createReadStream(path, {\n  flags: SAFE_FLAGS,\n});\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.ts")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {
                "file": "src/app.ts",
                "line": 1,
                "code": "const stream = createReadStream(path, { flags: SAFE_FLAGS }); // summary",
            }
            record["critical_operation"] = {"file": "src/app.ts", "line": 1, "code": "wrong()"}
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            entry = next(check for check in result.checks if check.field == "entry_point.source_content")
            self.assertEqual(entry.verdict, Verdict.UNCERTAIN)
            self.assertIn("match_status=anchored_summary", entry.evidence[0].observation)

    def test_multiple_matches_are_reported_as_ambiguous_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "VulnGym Test")
            self._git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "handle(request)\nplaceholder()\nhandle(request)\n",
                encoding="utf-8",
            )
            self._git(root, "add", "src/app.py")
            self._git(root, "commit", "-q", "-m", "fixture")
            commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["commit"] = commit
            record["entry_point"] = {"file": "src/app.py", "line": 2, "code": "handle(request)"}
            record["critical_operation"] = {"file": "src/app.py", "line": 1, "code": "handle(request)"}
            record["trace"] = []

            result = AuditEngine(root).audit(record)
            ambiguous = next(check for check in result.checks if check.field == "entry_point.source_location")
            self.assertEqual(ambiguous.verdict, Verdict.INCORRECT)
            self.assertIn("match_status=ambiguous", ambiguous.evidence[0].observation)


if __name__ == "__main__":
    unittest.main()
