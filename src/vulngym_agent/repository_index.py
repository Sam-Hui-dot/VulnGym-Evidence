from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from .repository import ReadOnlyGitRepository, RepositoryError


SCP_GITHUB_RE = re.compile(r"^(?:git@|ssh://git@)github\.com[:/](.+?)(?:\.git)?$")


def normalize_repo_url(value: str) -> str:
    if not isinstance(value, str):
        return ""
    raw = value.strip()
    scp_match = SCP_GITHUB_RE.fullmatch(raw)
    if scp_match:
        path = scp_match.group(1)
    else:
        parsed = urlparse(raw)
        if parsed.hostname is None or parsed.hostname.lower() != "github.com":
            return raw.rstrip("/").removesuffix(".git")
        path = parsed.path.strip("/")
    path = path.removesuffix(".git")
    parts = path.split("/")
    if len(parts) < 2:
        return ""
    return f"https://github.com/{parts[0]}/{parts[1]}"


def repo_owner_name(repo_url: str) -> tuple[str, str] | None:
    normalized = normalize_repo_url(repo_url)
    prefix = "https://github.com/"
    if not normalized.startswith(prefix):
        return None
    parts = normalized[len(prefix) :].split("/")
    return (parts[0], parts[1]) if len(parts) == 2 and all(parts) else None


def load_repository_map(path: Path | None) -> dict[str, Path]:
    if path is None:
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("repository map must be a JSON object of repo_url -> local path")
    result: dict[str, Path] = {}
    for repo_url, local_path in value.items():
        if not isinstance(repo_url, str) or not isinstance(local_path, str):
            raise ValueError("repository map keys and values must be strings")
        result[normalize_repo_url(repo_url)] = Path(local_path).expanduser()
    return result


@dataclass(frozen=True)
class RepositoryResolution:
    repo_url: str
    status: str
    path: Path | None
    origin: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_url": self.repo_url,
            "status": self.status,
            "path": str(self.path) if self.path else None,
            # Export the matched identity, never credentials from Git configuration.
            "origin": self.repo_url if self.origin else None,
            "reason": self.reason,
        }


class RepositoryResolver:
    def __init__(self, *, roots: Iterable[Path] = (), mapping: dict[str, Path] | None = None) -> None:
        self.roots = tuple(Path(root).expanduser().resolve() for root in roots)
        self.mapping = {normalize_repo_url(key): Path(value).expanduser() for key, value in (mapping or {}).items()}

    def _candidates(self, repo_url: str) -> list[Path]:
        normalized = normalize_repo_url(repo_url)
        owner_name = repo_owner_name(normalized)
        candidates: list[Path] = []
        if normalized in self.mapping:
            candidates.append(self.mapping[normalized])
        if owner_name:
            owner, name = owner_name
            for root in self.roots:
                candidates.extend((root / owner / name, root / name, root / f"{owner}__{name}"))
        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            resolved = candidate.resolve()
            key = str(resolved)
            if key not in seen:
                seen.add(key)
                unique.append(resolved)
        return unique

    def resolve(self, repo_url: str) -> RepositoryResolution:
        normalized = normalize_repo_url(repo_url)
        candidates = self._candidates(normalized)
        existing_non_repositories: list[Path] = []
        for candidate in candidates:
            if not candidate.exists():
                continue
            try:
                repository = ReadOnlyGitRepository(candidate)
            except RepositoryError:
                existing_non_repositories.append(candidate)
                continue
            origin = repository.remote_origin()
            normalized_origin = normalize_repo_url(origin) if origin else ""
            if origin and normalized_origin != normalized:
                continue
            return RepositoryResolution(
                repo_url=normalized,
                status="resolved" if origin else "resolved_without_origin",
                path=candidate,
                origin=origin,
                reason="matched local Git repository" if origin else "local Git repository has no remote.origin.url",
            )

        reason = "no candidate path exists"
        if existing_non_repositories:
            reason = "candidate path exists but is not a Git repository"
        elif candidates:
            reason = "expected one of: " + ", ".join(str(path) for path in candidates)
        return RepositoryResolution(normalized, "missing", None, None, reason)


def build_repository_index(
    records: list[dict[str, Any]],
    resolver: RepositoryResolver,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        repo_url = normalize_repo_url(record.get("repo_url", ""))
        if repo_url:
            grouped[repo_url].append(record)

    repositories: list[dict[str, Any]] = []
    for repo_url, rows in sorted(grouped.items()):
        resolution = resolver.resolve(repo_url)
        commits = sorted({row.get("commit") for row in rows if isinstance(row.get("commit"), str)})
        missing_commits: list[str] = []
        unchecked_commits: list[str] = []
        if resolution.path:
            repository = ReadOnlyGitRepository(resolution.path)
            for commit in commits:
                try:
                    if not repository.has_commit(commit):
                        missing_commits.append(commit)
                except RepositoryError:
                    missing_commits.append(commit)
        else:
            unchecked_commits = commits
        repositories.append(
            {
                **resolution.to_dict(),
                "projects": sorted({row.get("project") for row in rows if isinstance(row.get("project"), str)}),
                "entries": len(rows),
                "reports": len({row.get("report_id") for row in rows}),
                "required_commits": commits,
                "missing_commits": missing_commits,
                "unchecked_commits": unchecked_commits,
            }
        )

    return {
        "summary": {
            "repositories": len(repositories),
            "resolved": sum(row["status"].startswith("resolved") for row in repositories),
            "missing": sum(row["status"] == "missing" for row in repositories),
            "entries": sum(row["entries"] for row in repositories),
            "reports": len({record.get("report_id") for record in records}),
            "required_commits": sum(len(row["required_commits"]) for row in repositories),
            "missing_commits": sum(len(row["missing_commits"]) for row in repositories),
            "unchecked_commits": sum(len(row["unchecked_commits"]) for row in repositories),
        },
        "repositories": repositories,
    }


def write_repository_index(path: Path, index: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
