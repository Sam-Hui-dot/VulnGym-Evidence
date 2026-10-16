from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable

from .repository import ReadOnlyGitRepository, RepositoryError


FIX_KEYWORDS = (
    "fix",
    "security",
    "vulnerability",
    "cve-",
    "ghsa-",
    "sanitize",
    "validation",
    "permission",
    "auth",
    "escape",
)

SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".scala", ".sh",
    ".sol", ".swift", ".ts", ".tsx", ".vue",
}

def candidate_files(record: dict[str, Any]) -> set[str]:
    files: set[str] = set()
    for field in ("entry_point", "critical_operation"):
        node = record.get(field)
        if isinstance(node, dict) and isinstance(node.get("file"), str):
            files.add(node["file"])
    trace = record.get("trace")
    if isinstance(trace, list):
        for node in trace:
            if isinstance(node, dict) and isinstance(node.get("file"), str):
                files.add(node["file"])
    return files


@dataclass(frozen=True)
class FixCandidate:
    commit: str
    subject: str
    changed_files: tuple[str, ...]
    overlap_files: tuple[str, ...]
    score: int
    is_direct_child: bool
    advisory_role: str | None
    has_candidate_ancestry: bool
    related_source_files: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _score_candidate(subject: str, overlap_files: list[str]) -> int:
    lowered = subject.lower()
    return len(overlap_files) * 4 + sum(1 for keyword in FIX_KEYWORDS if keyword in lowered)


def _commit_matches(candidate: str, declared: str) -> bool:
    left, right = candidate.lower(), declared.lower()
    return left.startswith(right) or right.startswith(left)


def _advisory_role(commit: str, documents: Iterable[dict[str, Any]]) -> tuple[str | None, list[str]]:
    matches: list[tuple[str, str]] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        evidence_id = document.get("evidence_id")
        if not isinstance(evidence_id, str):
            evidence_id = "advisory:unidentified"
        for field, role in (("fixed_commits", "fixed"), ("supporting_fix_commits", "supporting_fix")):
            values = document.get(field, [])
            if isinstance(values, list) and any(
                isinstance(value, str) and _commit_matches(commit, value) for value in values
            ):
                matches.append((role, evidence_id))
    if not matches:
        return None, []
    role = "fixed" if any(item[0] == "fixed" for item in matches) else "supporting_fix"
    return role, list(dict.fromkeys(item[1] for item in matches))


def _advisory_fix_commits(documents: Iterable[dict[str, Any]]) -> list[str]:
    commits: list[str] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        for field in ("fixed_commits", "supporting_fix_commits"):
            values = document.get(field, [])
            if isinstance(values, list):
                commits.extend(value for value in values if isinstance(value, str))
    return list(dict.fromkeys(commits))


def _source_files(paths: Iterable[str]) -> list[str]:
    return sorted(
        {
            path
            for path in paths
            if PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES
        }
    )


def _path_relationship(target_files: set[str], changed_files: Iterable[str]) -> dict[str, list[str]]:
    changed = set(changed_files)
    exact = sorted(target_files & changed)
    basename = sorted(
        changed_path
        for changed_path in changed - set(exact)
        if any(PurePosixPath(changed_path).name == PurePosixPath(target).name for target in target_files)
    )
    return {"exact": exact, "basename_only": basename}


def inspect_patch(
    repository: ReadOnlyGitRepository,
    record: dict[str, Any],
    *,
    explicit_fix_commit: str | None = None,
    advisory_documents: Iterable[dict[str, Any]] = (),
    max_candidates: int = 5,
    max_diff_chars: int = 16000,
) -> dict[str, Any]:
    vulnerable_commit = record.get("commit")
    if not isinstance(vulnerable_commit, str):
        return {"status": "unavailable", "reason": "record has no valid vulnerable commit", "candidates": []}
    if not repository.has_commit(vulnerable_commit):
        return {"status": "unavailable", "reason": "vulnerable commit is missing locally", "candidates": []}

    direct_children = repository.direct_children(vulnerable_commit)
    advisory_documents = tuple(advisory_documents)
    commits = list(direct_children)
    for advisory_commit in reversed(_advisory_fix_commits(advisory_documents)):
        if advisory_commit not in commits:
            commits.insert(0, advisory_commit)
    if explicit_fix_commit and explicit_fix_commit not in commits:
        commits.insert(0, explicit_fix_commit)

    target_files = candidate_files(record)
    candidates: list[FixCandidate] = []
    errors: list[str] = []
    for commit in commits:
        try:
            if not repository.has_commit(commit):
                errors.append(f"candidate fix commit is missing: {commit}")
                continue
            subject = repository.commit_subject(commit)
            changed = repository.changed_files(vulnerable_commit, commit)
            has_candidate_ancestry = repository.is_ancestor(vulnerable_commit, commit)
        except RepositoryError as exc:
            errors.append(f"{commit}: {exc}")
            continue
        overlap = sorted(target_files.intersection(changed))
        advisory_role, _ = _advisory_role(commit, advisory_documents)
        candidates.append(
            FixCandidate(
                commit=commit,
                subject=subject,
                changed_files=tuple(changed),
                overlap_files=tuple(overlap),
                score=_score_candidate(subject, overlap),
                is_direct_child=commit in direct_children,
                advisory_role=advisory_role,
                has_candidate_ancestry=has_candidate_ancestry,
                related_source_files=tuple(_source_files(changed)),
            )
        )

    candidates.sort(
        key=lambda candidate: (
            candidate.commit != explicit_fix_commit,
            not (
                candidate.advisory_role in {"fixed", "supporting_fix"}
                and candidate.has_candidate_ancestry
                and candidate.related_source_files
            ),
            candidate.advisory_role not in {"fixed", "supporting_fix"},
            -candidate.score,
            candidate.commit,
        )
    )
    candidates = candidates[:max_candidates]

    selected: FixCandidate | None = None
    selection_basis = ""
    selection_confidence = 0.0
    if explicit_fix_commit:
        selected = next((candidate for candidate in candidates if candidate.commit == explicit_fix_commit), None)
        if selected:
            selection_basis = "explicit fix-map hint"
            selection_confidence = 0.99
    elif any(candidate.advisory_role in {"fixed", "supporting_fix"} for candidate in candidates):
        selected = next(candidate for candidate in candidates if candidate.advisory_role in {"fixed", "supporting_fix"})
        selection_basis = f"official advisory {selected.advisory_role.replace('_', ' ')}"
        selection_confidence = 0.95 if selected.advisory_role == "fixed" else 0.9
    elif len(candidates) == 1:
        selected = candidates[0]
        selection_basis = "only direct child reachable from local refs"
        selection_confidence = 0.75
    elif candidates:
        first = candidates[0]
        second_score = candidates[1].score if len(candidates) > 1 else -1
        if first.overlap_files and first.score >= second_score + 4:
            selected = first
            selection_basis = "highest-ranked direct child with unique candidate-file overlap"
            selection_confidence = 0.65

    diff_text: str | None = None
    diff_truncated = False
    if selected:
        files = selected.overlap_files or selected.related_source_files[:8] or selected.changed_files[:8]
        try:
            diff_text = repository.diff(vulnerable_commit, selected.commit, files=files, unified=5)
            if len(diff_text) > max_diff_chars:
                diff_text = diff_text[: max_diff_chars - 1] + "…"
                diff_truncated = True
        except RepositoryError as exc:
            errors.append(f"cannot read selected diff: {exc}")

    provenance_status = "weak"
    provenance_basis = "no selected candidate provides vulnerability provenance"
    provenance_evidence_ids: list[str] = []
    related_source_files: list[str] = []
    path_relationship = {"exact": [], "basename_only": []}
    if selected:
        related_source_files = list(selected.related_source_files)
        path_relationship = _path_relationship(target_files, selected.changed_files)
        advisory_role, provenance_evidence_ids = _advisory_role(selected.commit, advisory_documents)
        has_ancestry = selected.has_candidate_ancestry
        inspectable_source_diff = bool(diff_text and diff_text.strip() and related_source_files)
        if explicit_fix_commit and selected.commit == explicit_fix_commit and has_ancestry and inspectable_source_diff:
            provenance_status = "verified"
            provenance_basis = "trusted explicit fix-map, Git ancestry, and inspectable source diff"
        elif advisory_role and has_ancestry and inspectable_source_diff:
            provenance_status = "verified"
            provenance_basis = f"official advisory {advisory_role.replace('_', ' ')}, Git ancestry, and inspectable source diff"
        elif selected.overlap_files or selected.score > 0 or related_source_files:
            provenance_status = "supported"
            provenance_basis = "heuristic patch signals without an authoritative commit role"
        else:
            provenance_basis = "Git topology without advisory role or related source change"

    status = "selected" if selected else ("ambiguous" if candidates else "not_found")
    return {
        "status": status,
        "vulnerable_commit": vulnerable_commit,
        "candidate_files": sorted(target_files),
        "direct_child_count": len(direct_children),
        "candidates": [candidate.to_dict() for candidate in candidates],
        "selected_fix_commit": selected.commit if selected else None,
        "selection_basis": selection_basis or None,
        "selection_confidence": selection_confidence,
        "provenance_status": provenance_status,
        "provenance_basis": provenance_basis,
        "provenance_evidence_ids": provenance_evidence_ids,
        "related_source_files": related_source_files,
        "path_relationship": path_relationship,
        "diff": diff_text,
        "diff_truncated": diff_truncated,
        "errors": errors,
    }
