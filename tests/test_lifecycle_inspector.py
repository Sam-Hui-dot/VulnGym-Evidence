from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vulngym_agent.lifecycle_inspector import inspect_critical_lifecycle
from vulngym_agent.repository import ReadOnlyGitRepository

from .git_fixture import git


class LifecycleInspectorTests(unittest.TestCase):
    def test_reports_constructor_and_later_activation_without_deciding_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "-q")
            git(root, "config", "user.name", "VulnGym Test")
            git(root, "config", "user.email", "vulngym-test@example.invalid")
            (root / "client.go").write_text(
                "package fixture\n"
                "func NewWrapper(opts Options) (*Wrapper, error) {\n"
                "    client, err := sdk.NewClient(opts)\n"
                "    return &Wrapper{client: client}, err\n"
                "}\n"
                "func (w *Wrapper) Connect(ctx Context) error {\n"
                "    return w.client.Start(ctx)\n"
                "}\n",
                encoding="utf-8",
            )
            git(root, "add", "client.go")
            git(root, "commit", "-q", "-m", "fixture")
            commit = git(root, "rev-parse", "HEAD")

            result = inspect_critical_lifecycle(
                ReadOnlyGitRepository(root),
                commit,
                {"file": "client.go", "line": 3, "code": "client, err := sdk.NewClient(opts)"},
            )

            self.assertEqual(result["status"], "available")
            self.assertEqual(result["constructor_like_calls"], ["sdk.NewClient"])
            self.assertIn(
                "w.client.Start",
                [item["call"] for item in result["downstream_activation_calls"]],
            )
            self.assertNotIn(
                "Connect",
                [item["call"] for item in result["downstream_activation_calls"]],
            )
            self.assertNotIn("verdict", result)


if __name__ == "__main__":
    unittest.main()
