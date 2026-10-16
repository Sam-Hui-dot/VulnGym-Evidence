from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .semantic_contract import SEMANTIC_FIELDS


TOKEN_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)


def _field_verdicts(judgment: Any) -> dict[str, str]:
    if not isinstance(judgment, dict) or not isinstance(judgment.get("field_results"), list):
        return {}
    verdicts: dict[str, str] = {}
    for result in judgment["field_results"]:
        if not isinstance(result, dict):
            continue
        field = result.get("field")
        verdict = result.get("verdict")
        if field in SEMANTIC_FIELDS and verdict in {"correct", "incorrect", "uncertain"}:
            verdicts[field] = verdict
    return verdicts


def _usage(row: dict[str, Any], stage: str) -> dict[str, int] | None:
    metadata = row.get(f"{stage}_provider_metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("usage"), dict):
        return None
    usage = metadata["usage"]
    normalized: dict[str, int] = {}
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens"),
        "output_tokens": ("output_tokens", "completion_tokens"),
        "cached_input_tokens": ("cached_input_tokens",),
        "reasoning_output_tokens": ("reasoning_output_tokens",),
    }
    for field in TOKEN_FIELDS:
        value = next((usage.get(name) for name in aliases[field] if name in usage), 0)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            normalized[field] = value
    return normalized


def summarize_semantic_results(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    latest: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for index, row in enumerate(rows):
        entry_id = row.get("entry_id")
        key = str(entry_id) if entry_id is not None else f"__row_{index}"
        if key not in latest:
            order.append(key)
        latest[key] = row

    statuses: Counter[str] = Counter()
    overall_verdicts: Counter[str] = Counter()
    field_verdicts: dict[str, Counter[str]] = {field: Counter() for field in SEMANTIC_FIELDS}
    token_totals = {field: 0 for field in TOKEN_FIELDS}
    calls_with_usage = 0
    calls_without_usage = 0
    total_seconds = 0.0
    cases: list[dict[str, Any]] = []

    for key in order:
        row = latest[key]
        status = str(row.get("status", "missing"))
        statuses[status] += 1
        judgment = row.get("judgment")
        final_judgment = row.get("final_judgment")
        judge_fields = _field_verdicts(judgment)
        final_fields = _field_verdicts(final_judgment)
        changed_fields = [
            field
            for field in SEMANTIC_FIELDS
            if field in judge_fields and field in final_fields and judge_fields[field] != final_fields[field]
        ]

        overall = final_judgment.get("overall_verdict") if isinstance(final_judgment, dict) else None
        if overall in {"correct", "incorrect", "uncertain"}:
            overall_verdicts[overall] += 1
        for field, verdict in final_fields.items():
            field_verdicts[field][verdict] += 1

        case_seconds = 0.0
        case_usage = {field: 0 for field in TOKEN_FIELDS}
        for stage in ("judge", "critic"):
            seconds = row.get(f"{stage}_seconds")
            if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds >= 0:
                case_seconds += float(seconds)
            usage = _usage(row, stage)
            stage_ran = f"{stage}_seconds" in row
            if usage is not None:
                calls_with_usage += 1
                for field, value in usage.items():
                    token_totals[field] += value
                    case_usage[field] += value
            elif stage_ran:
                calls_without_usage += 1
        total_seconds += case_seconds

        cases.append(
            {
                "case_id": row.get("case_id"),
                "entry_id": row.get("entry_id"),
                "status": status,
                "judge_overall_verdict": judgment.get("overall_verdict") if isinstance(judgment, dict) else None,
                "final_overall_verdict": overall,
                "judge_critic_changed_fields": changed_fields,
                "seconds": round(case_seconds, 6),
                "usage": case_usage,
            }
        )

    successful_statuses = {
        "completed",
        "completed_with_repair",
        "completed_without_critic",
        "completed_without_critic_with_repair",
    }
    return {
        "summary": {
            "cases": len(cases),
            "successful_cases": sum(count for status, count in statuses.items() if status in successful_statuses),
            "statuses": dict(sorted(statuses.items())),
            "overall_verdicts": dict(sorted(overall_verdicts.items())),
            "field_verdicts": {
                field: dict(sorted(field_verdicts[field].items()))
                for field in SEMANTIC_FIELDS
            },
            "judge_critic_changed_cases": sum(bool(case["judge_critic_changed_fields"]) for case in cases),
            "calls_with_usage": calls_with_usage,
            "calls_without_usage": calls_without_usage,
            "total_seconds": round(total_seconds, 6),
            "usage": token_totals,
        },
        "cases": cases,
    }


def write_semantic_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
