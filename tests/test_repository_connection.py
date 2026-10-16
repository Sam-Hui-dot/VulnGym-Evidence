"""Local checkout selection, origin checks and immutable revision handling."""
import shutil
import json
import subprocess
import tempfile
from pathlib import Path
import unittest

from vulngym_evidence.runtime import connect_repository
from vulngym_evidence.workflow import verify_request


@unittest.skipUnless(shutil.which("git"), "Git is required")
class RepositoryConnectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "project with spaces"
        self.path.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("remote", "add", "origin", "https://github.com/example/project.git")
        (self.path / "code.py").write_text("VALUE = 1\n", encoding="utf-8")
        self.git("add", "code.py")
        self.git("commit", "--quiet", "-m", "first")
        self.commit = self.git("rev-parse", "HEAD")
        self.git("tag", "v1")

    def tearDown(self):
        self.directory.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.path), *args],
                                       stderr=subprocess.PIPE, text=True).strip()

    def value(self, **overrides):
        return {"local_path": str(self.path), "repo_url": "", "revision": "HEAD", **overrides}

    def test_detects_origin_and_pins_tag_without_changing_checkout_or_worktree(self):
        (self.path / "code.py").write_text("VALUE = 999\n", encoding="utf-8")
        before = self.git("status", "--porcelain")
        state, path = connect_repository(self.value(revision="v1"))
        self.assertTrue(state["ready"])
        self.assertEqual(state["repo_url"], "https://github.com/example/project")
        self.assertEqual(state["reviewed_commit"], self.commit)
        self.assertEqual(path, self.path.resolve())
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.commit)

    def test_rejects_a_different_project_even_when_commit_exists(self):
        with self.assertRaisesRegex(ValueError, "origin 不一致"):
            connect_repository(self.value(repo_url="https://github.com/other/project"))

    def test_missing_revision_explains_local_history_without_fetching(self):
        with self.assertRaisesRegex(ValueError, "本地没有找到这个版本"):
            connect_repository(self.value(revision="missing-version"))

    def test_source_zip_relative_path_and_option_like_revision_are_rejected(self):
        plain = self.path.parent / "source-zip"
        plain.mkdir()
        for value in (self.value(local_path=str(plain)), self.value(local_path="relative"),
                      self.value(revision="--help"), self.value(revision="HEAD:code.py")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                connect_repository(value)

    def test_no_origin_requires_explicit_https_identity(self):
        self.git("remote", "remove", "origin")
        with self.assertRaisesRegex(ValueError, "未找到远程来源"):
            connect_repository(self.value())
        state, _ = connect_repository(self.value(repo_url="https://github.com/example/project"))
        self.assertTrue(state["ready"])
        self.assertEqual(state["repository"]["status"], "resolved_without_origin")

    def test_revision_resolution_does_not_expand_beyond_a_commit(self):
        state, _ = connect_repository(self.value(local_path='"' + str(self.path) + '"', revision=self.commit))
        self.assertEqual(state["reviewed_commit"], self.commit)
        for value in (None, {**self.value(), "extra": True}, self.value(revision=[])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                connect_repository(value)

    def test_git_origin_credentials_are_not_copied_into_status_or_exported_evidence(self):
        self.git("remote", "set-url", "origin", "https://fixture-secret@github.com/example/project.git")
        state, path = connect_repository(self.value())
        self.assertNotIn("fixture-secret", json.dumps(state))
        value = {"schema_version": "1.0", "case_id": "credential-redaction", "repo_url": state["repo_url"],
                 "reviewed_commit": state["reviewed_commit"], "claims": [{"claim_id": "location",
                 "kind": "source_location", "text": "所列代码与引用一致。",
                 "node": {"file": "code.py", "line": 1, "code": "VALUE = 1"}}]}
        result = verify_request(value, repository=path, provider=None)
        self.assertNotIn("fixture-secret", json.dumps(result))
        self.assertEqual(result["results"][0]["verdict"], "supported")
        with self.assertRaises(ValueError):
            connect_repository(self.value(repo_url="https://fixture-secret@github.com/example/project"))
