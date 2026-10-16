from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class RepositoryError(RuntimeError):
    pass


def normalize_repo_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts or "\x00" in normalized:
        raise RepositoryError(f"unsafe repository path: {value!r}")
    return path.as_posix()


@dataclass(frozen=True)
class ReadOnlyGitRepository:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", self.root.resolve())
        if not (self.root / ".git").exists():
            raise RepositoryError(f"not a Git repository: {self.root}")

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-c", f"safe.directory={self.root}", "-C", str(self.root), *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def _commit(value: str) -> str:
        if not COMMIT_RE.fullmatch(value):
            raise RepositoryError(f"invalid commit SHA: {value!r}")
        return value

    def has_commit(self, commit: str) -> bool:
        sha = self._commit(commit)
        completed = self._run("cat-file", "-e", f"{sha}^{{commit}}")
        return completed.returncode == 0

    def read_file(self, commit: str, file_path: str) -> str:
        sha = self._commit(commit)
        normalized_path = normalize_repo_path(file_path)
        completed = self._run("show", f"{sha}:{normalized_path}")
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RepositoryError(error or f"cannot read {normalized_path} at {sha}")
        return completed.stdout.decode("utf-8", errors="replace")

    def list_files(self, commit: str) -> list[str]:
        """List tracked files at one commit without checking out or executing it."""
        sha = self._commit(commit)
        completed = self._run("ls-tree", "-r", "--name-only", sha)
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RepositoryError(error or f"cannot list files at {sha}")
        return [
            normalize_repo_path(line)
            for line in completed.stdout.decode("utf-8", errors="replace").splitlines()
            if line
        ]

    def remote_origin(self) -> str | None:
        completed = self._run("config", "--get", "remote.origin.url")
        if completed.returncode != 0:
            return None
        value = completed.stdout.decode("utf-8", errors="replace").strip()
        return value or None

    def direct_children(self, commit: str) -> list[str]:
        sha = self._commit(commit)
        completed = self._run("rev-list", "--all", "--children")
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RepositoryError(error or "cannot enumerate commit graph")
        for raw_line in completed.stdout.decode("ascii", errors="replace").splitlines():
            parts = raw_line.split()
            if parts and parts[0] == sha:
                return [value for value in parts[1:] if COMMIT_RE.fullmatch(value)]
        return []

    def is_ancestor(self, base: str, target: str) -> bool:
        base_sha, target_sha = self._commit(base), self._commit(target)
        completed = self._run("merge-base", "--is-ancestor", base_sha, target_sha)
        if completed.returncode == 0:
            return True
        if completed.returncode == 1:
            return False
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RepositoryError(error or f"cannot compare ancestry for {base_sha}..{target_sha}")

    def commit_subject(self, commit: str) -> str:
        sha = self._commit(commit)
        completed = self._run("show", "-s", "--format=%s", sha)
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RepositoryError(error or f"cannot read commit subject for {sha}")
        return completed.stdout.decode("utf-8", errors="replace").strip()

    def changed_files(self, base: str, target: str) -> list[str]:
        base_sha, target_sha = self._commit(base), self._commit(target)
        completed = self._run("diff", "--name-only", base_sha, target_sha, "--")
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RepositoryError(error or f"cannot diff {base_sha}..{target_sha}")
        return [line for line in completed.stdout.decode("utf-8", errors="replace").splitlines() if line]

    def diff(
        self,
        base: str,
        target: str,
        *,
        files: Iterable[str] = (),
        unified: int = 3,
    ) -> str:
        if unified < 0 or unified > 100:
            raise RepositoryError("unified context must be between 0 and 100")
        base_sha, target_sha = self._commit(base), self._commit(target)
        normalized_files = [normalize_repo_path(value) for value in files]
        completed = self._run(
            "diff",
            "--no-ext-diff",
            f"--unified={unified}",
            base_sha,
            target_sha,
            "--",
            *normalized_files,
        )
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RepositoryError(error or f"cannot diff {base_sha}..{target_sha}")
        return completed.stdout.decode("utf-8", errors="replace")
