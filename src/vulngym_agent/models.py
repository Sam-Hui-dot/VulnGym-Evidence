from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class Evidence:
    tool: str
    target: str
    observation: str


@dataclass(frozen=True)
class CheckResult:
    field: str
    verdict: Verdict
    confidence: float
    reason: str
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass(frozen=True)
class AuditResult:
    case_id: str | None
    entry_id: str | None
    report_id: str | None
    overall_verdict: Verdict
    confidence: float
    plan: tuple[str, ...]
    checks: tuple[CheckResult, ...]

    def to_dict(self) -> dict[str, Any]:
        counts = {verdict.value: 0 for verdict in Verdict}
        for check in self.checks:
            counts[check.verdict.value] += 1
        return {
            "case_id": self.case_id,
            "entry_id": self.entry_id,
            "report_id": self.report_id,
            "overall_verdict": self.overall_verdict.value,
            "confidence": round(self.confidence, 4),
            "plan": list(self.plan),
            "summary": counts,
            "checks": [check.to_dict() for check in self.checks],
        }
