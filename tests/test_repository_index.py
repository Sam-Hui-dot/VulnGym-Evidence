from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vulngym_agent.repository_index import RepositoryResolver, build_repository_index, normalize_repo_url

from .git_fixture import create_fix_history
from .helpers import valid_record


class RepositoryIndexTests(unittest.TestCase):
    def test_normalizes_https_and_ssh_origins(self) -> None:
        expected = "https://github.com/acme/example"
        self.assertEqual(normalize_repo_url("https://github.com/acme/example.git/"), expected)
        self.assertEqual(normalize_repo_url("git@github.com:acme/example.git"), expected)

    def test_resolves_owner_repo_layout_and_checks_commits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "acme" / "example"
            repository.mkdir(parents=True)
            vulnerable, _fixed = create_fix_history(repository)
            record = valid_record()
            record["commit"] = vulnerable

            resolver = RepositoryResolver(roots=[root])
            resolution = resolver.resolve(record["repo_url"])
            self.assertEqual(resolution.status, "resolved")
            self.assertEqual(resolution.path, repository.resolve())

            index = build_repository_index([record], resolver)
            self.assertEqual(index["summary"]["repositories"], 1)
            self.assertEqual(index["summary"]["resolved"], 1)
            self.assertEqual(index["summary"]["missing_commits"], 0)
            self.assertEqual(index["summary"]["unchecked_commits"], 0)

    def test_unresolved_repository_marks_commits_unchecked(self) -> None:
        record = valid_record()
        index = build_repository_index([record], RepositoryResolver())
        self.assertEqual(index["summary"]["missing"], 1)
        self.assertEqual(index["summary"]["missing_commits"], 0)
        self.assertEqual(index["summary"]["unchecked_commits"], 1)


if __name__ == "__main__":
    unittest.main()
