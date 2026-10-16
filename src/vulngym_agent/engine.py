from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import AuditResult, CheckResult, Evidence, Verdict
from .repository import ReadOnlyGitRepository, RepositoryError
from .schema import COMMIT_RE, validate_schema
from .source import inspect_node


SEMANTIC_FIELDS = (
    "entry_point.semantic_role",
    "critical_operation.semantic_role",
    "vuln_category_l1.semantic_value",
    "vuln_category_l2.semantic_value",
    "trace.semantic_continuity",
)


class AuditEngine:
    def __init__(self, repository: Path | None = None) -> None:
        self.repository_path = repository
        self.repository: ReadOnlyGitRepository | None = None
        self.repository_error: str | None = None
        if repository is not None:
            try:
                self.repository = ReadOnlyGitRepository(repository)
            except RepositoryError as exc:
                self.repository_error = str(exc)

    def plan(self) -> tuple[str, ...]:
        steps = ["validate_schema", "resolve_repository"]
        if self.repository_path is not None:
            steps.extend(("inspect_git_objects", "verify_source_locations"))
        steps.extend(("defer_semantic_judgment", "reflect"))
        return tuple(steps)

    def audit(self, record: dict[str, Any]) -> AuditResult:
        checks = validate_schema(record)
        checks.extend(self._inspect_repository(record))
        checks.extend(self._semantic_placeholders())
        overall, confidence = self._reflect(checks)
        return AuditResult(
            case_id=record.get("_case_id") if isinstance(record.get("_case_id"), str) else None,
            entry_id=record.get("entry_id") if isinstance(record.get("entry_id"), str) else None,
            report_id=record.get("report_id") if isinstance(record.get("report_id"), str) else None,
            overall_verdict=overall,
            confidence=confidence,
            plan=self.plan(),
            checks=tuple(checks),
        )

    def _inspect_repository(self, record: dict[str, Any]) -> list[CheckResult]:
        if self.repository_path is None:
            return [
                CheckResult(
                    field="$source_repository",
                    verdict=Verdict.UNCERTAIN,
                    confidence=0.0,
                    reason="no local upstream repository was supplied; source facts were not guessed",
                    evidence=(Evidence("repository_resolver", "--repository", "not provided"),),
                )
            ]
        if self.repository is None:
            return [
                CheckResult(
                    field="$source_repository",
                    verdict=Verdict.INCORRECT,
                    confidence=1.0,
                    reason="the supplied repository cannot be inspected",
                    evidence=(Evidence("repository_resolver", str(self.repository_path), self.repository_error or "unknown error"),),
                )
            ]

        commit = record.get("commit")
        if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
            return []
        try:
            has_commit = self.repository.has_commit(commit)
        except RepositoryError as exc:
            return [
                CheckResult(
                    field="commit.repository_object",
                    verdict=Verdict.INCORRECT,
                    confidence=0.99,
                    reason="the commit could not be inspected",
                    evidence=(Evidence("git_cat_file", commit, str(exc)),),
                )
            ]

        if not has_commit:
            return [
                CheckResult(
                    field="commit.repository_object",
                    verdict=Verdict.INCORRECT,
                    confidence=0.99,
                    reason="the declared commit does not exist in the supplied repository",
                    evidence=(Evidence("git_cat_file", commit, "missing commit object"),),
                )
            ]

        checks = [
            CheckResult(
                field="commit.repository_object",
                verdict=Verdict.CORRECT,
                confidence=0.99,
                reason="the declared vulnerable commit exists locally",
                evidence=(Evidence("git_cat_file", commit, "commit object exists"),),
            )
        ]
        checks.extend(
            inspect_node(
                self.repository,
                commit,
                record.get("entry_point"),
                "entry_point",
            )
        )
        checks.extend(
            inspect_node(
                self.repository,
                commit,
                record.get("critical_operation"),
                "critical_operation",
            )
        )
        trace = record.get("trace")
        if isinstance(trace, list):
            for index, node in enumerate(trace):
                checks.extend(
                    inspect_node(
                        self.repository,
                        commit,
                        node,
                        f"trace[{index}]",
                    )
                )
        return checks

    @staticmethod
    def _semantic_placeholders() -> list[CheckResult]:
        return [
            CheckResult(
                field=field,
                verdict=Verdict.UNCERTAIN,
                confidence=0.0,
                reason="semantic judge is not connected in WP1; no unsupported conclusion is emitted",
                evidence=(Evidence("semantic_judge", field, "pending WP3"),),
            )
            for field in SEMANTIC_FIELDS
        ]

    @staticmethod
    def _reflect(checks: list[CheckResult]) -> tuple[Verdict, float]:
        incorrect = [check for check in checks if check.verdict is Verdict.INCORRECT]
        if incorrect:
            return Verdict.INCORRECT, max(check.confidence for check in incorrect)
        uncertain = [check for check in checks if check.verdict is Verdict.UNCERTAIN]
        if uncertain:
            known_confidences = [check.confidence for check in checks if check.verdict is Verdict.CORRECT]
            confidence = min(0.5, sum(known_confidences) / len(known_confidences)) if known_confidences else 0.0
            return Verdict.UNCERTAIN, confidence
        confidence = min((check.confidence for check in checks), default=0.0)
        return Verdict.CORRECT, confidence
