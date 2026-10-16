from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .submission import SUBMISSION_FIELDS, VERDICTS


def _case_key(row: dict[str, Any]) -> str | None:
    for field in ("case_id", "entry_id"):
        value = row.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _validate_reference(row: dict[str, Any]) -> tuple[str, dict[str, str]]:
    key = _case_key(row)
    if key is None:
        raise ValueError("reference row must contain case_id or entry_id")
    labels = row.get("labels")
    if not isinstance(labels, dict) or set(labels) != set(SUBMISSION_FIELDS):
        raise ValueError(f"reference row {key} must label all eight T1 fields")
    for field, verdict in labels.items():
        if verdict not in VERDICTS:
            raise ValueError(f"reference row {key} has invalid {field} verdict: {verdict!r}")
    return key, labels


def evaluate_submission_reports(
    reports: Iterable[dict[str, Any]],
    reference: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    reference_rows: dict[str, dict[str, str]] = {}
    for row in reference:
        key, labels = _validate_reference(row)
        if key in reference_rows:
            raise ValueError(f"duplicate reference key: {key}")
        reference_rows[key] = labels

    report_rows: dict[str, dict[str, Any]] = {}
    for row in reports:
        key = _case_key(row)
        if key is not None:
            report_rows[key] = row

    confusion = {
        field: {
            expected: Counter({predicted: 0 for predicted in sorted(VERDICTS)})
            for expected in sorted(VERDICTS)
        }
        for field in SUBMISSION_FIELDS
    }
    total = len(reference_rows) * len(SUBMISSION_FIELDS)
    predictions = correct = abstentions = 0
    expected_incorrect = predicted_incorrect = true_incorrect = 0
    complete_cases = exact_cases = evidence_items = 0
    high_confidence_errors: list[dict[str, Any]] = []

    for key, labels in reference_rows.items():
        fields = report_rows.get(key, {}).get("fields")
        if not isinstance(fields, dict):
            fields = {}
        case_complete = all(
            isinstance(fields.get(field), dict) and fields[field].get("status") in VERDICTS
            for field in SUBMISSION_FIELDS
        )
        case_exact = case_complete
        if case_complete:
            complete_cases += 1
        for field in SUBMISSION_FIELDS:
            expected = labels[field]
            if expected == "incorrect":
                expected_incorrect += 1
            item = fields.get(field)
            if not isinstance(item, dict) or item.get("status") not in VERDICTS:
                case_exact = False
                continue
            predictions += 1
            predicted = item["status"]
            confusion[field][expected][predicted] += 1
            if isinstance(item.get("evidence"), str) and item["evidence"].strip():
                evidence_items += 1
            if predicted == expected:
                correct += 1
            else:
                case_exact = False
                confidence = item.get("confidence")
                if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and confidence >= 0.8:
                    high_confidence_errors.append(
                        {
                            "case_id": key,
                            "field": field,
                            "expected": expected,
                            "predicted": predicted,
                            "confidence": confidence,
                        }
                    )
            if predicted == "uncertain":
                abstentions += 1
            if predicted == "incorrect":
                predicted_incorrect += 1
                if expected == "incorrect":
                    true_incorrect += 1
        if case_exact:
            exact_cases += 1

    precision = _ratio(true_incorrect, predicted_incorrect)
    recall = _ratio(true_incorrect, expected_incorrect)
    f1 = None
    if isinstance(precision, float) and isinstance(recall, float):
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    by_field: dict[str, Any] = {}
    for field in SUBMISSION_FIELDS:
        matrix = confusion[field]
        observed = sum(sum(row.values()) for row in matrix.values())
        exact = sum(matrix[value][value] for value in VERDICTS)
        field_abstentions = sum(matrix[value]["uncertain"] for value in VERDICTS)
        by_field[field] = {
            "accuracy": _ratio(exact, len(reference_rows)),
            "observed_accuracy": _ratio(exact, observed),
            "abstention_rate": _ratio(field_abstentions, observed),
            "missing_predictions": len(reference_rows) - observed,
            "confusion": {expected: dict(matrix[expected]) for expected in sorted(VERDICTS)},
        }

    return {
        "totals": {
            "reference_cases": len(reference_rows),
            "report_cases": len(report_rows),
            "labels": total,
            "predictions": predictions,
            "complete_cases": complete_cases,
            "missing_result_keys": sorted(set(reference_rows) - set(report_rows)),
            "unexpected_result_keys": sorted(set(report_rows) - set(reference_rows)),
        },
        "metrics": {
            "accuracy": _ratio(correct, total),
            "observed_accuracy": _ratio(correct, predictions),
            "incorrect_precision": precision,
            "incorrect_recall": recall,
            "incorrect_f1": f1,
            "abstention_rate": _ratio(abstentions, predictions),
            "case_exact_match": _ratio(exact_cases, len(reference_rows)),
            "evidence_coverage": _ratio(evidence_items, predictions),
            "missing_predictions": total - predictions,
        },
        "high_confidence_errors": high_confidence_errors,
        "by_field": by_field,
    }


def write_submission_evaluation(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
