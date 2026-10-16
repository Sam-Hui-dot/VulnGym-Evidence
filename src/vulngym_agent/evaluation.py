from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .jsonl import read_jsonl


def _covers(actual: str, expected: str) -> bool:
    if actual == expected or actual.startswith(expected + ".") or expected.startswith(actual + "."):
        return True
    parent = expected.rsplit(".", 1)[0] if "." in expected else expected
    return actual == parent + ".source"


def evaluate_audits(audit_path: Path, manifest_path: Path) -> dict[str, Any]:
    audits = {row.get("case_id"): row for _, row in read_jsonl(audit_path) if row.get("case_id")}
    labels = {row.get("case_id"): row for _, row in read_jsonl(manifest_path) if row.get("case_id")}
    missing = sorted(set(labels) - set(audits))
    unexpected = sorted(set(audits) - set(labels))

    invalid_cases = 0
    detected_invalid = 0
    clean_cases = 0
    clean_called_correct = 0
    abstentions = 0
    expected_errors = 0
    detected_errors = 0

    for case_id, label in labels.items():
        audit = audits.get(case_id)
        if audit is None:
            continue
        predicted = audit.get("overall_verdict")
        if predicted == "uncertain":
            abstentions += 1
        expected_invalid_fields = label.get("expected_incorrect_fields", [])
        if expected_invalid_fields:
            invalid_cases += 1
            if predicted == "incorrect":
                detected_invalid += 1
            actual_fields = [
                check.get("field", "")
                for check in audit.get("checks", [])
                if check.get("verdict") == "incorrect"
            ]
            expected_errors += len(expected_invalid_fields)
            detected_errors += sum(
                any(_covers(actual, expected) for actual in actual_fields)
                for expected in expected_invalid_fields
            )
        else:
            clean_cases += 1
            if predicted == "correct":
                clean_called_correct += 1

    evaluated = len(labels) - len(missing)
    return {
        "totals": {
            "manifest_cases": len(labels),
            "evaluated_cases": evaluated,
            "missing_audits": len(missing),
            "unexpected_audits": len(unexpected),
            "invalid_cases": invalid_cases,
            "clean_cases": clean_cases,
        },
        "metrics": {
            "invalid_case_recall": detected_invalid / invalid_cases if invalid_cases else 0.0,
            "field_error_recall": detected_errors / expected_errors if expected_errors else 0.0,
            "clean_case_accuracy": clean_called_correct / clean_cases if clean_cases else 0.0,
            "abstention_rate": abstentions / evaluated if evaluated else 0.0,
        },
        "missing_case_ids": missing,
        "unexpected_case_ids": unexpected,
    }


def write_evaluation(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)

