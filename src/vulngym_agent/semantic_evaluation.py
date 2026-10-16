from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .semantic_contract import SEMANTIC_FIELDS


VERDICTS = ("correct", "incorrect", "uncertain")


def _case_key(row: dict[str, Any]) -> str | None:
    for field in ("case_id", "entry_id"):
        value = row.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _validate_gold(row: dict[str, Any]) -> tuple[str, dict[str, str]]:
    key = _case_key(row)
    if key is None:
        raise ValueError("gold row must contain a non-empty case_id or entry_id")
    labels = row.get("labels")
    if not isinstance(labels, dict) or set(labels) != set(SEMANTIC_FIELDS):
        raise ValueError(f"gold row {key} must label each semantic field exactly once")
    for field, verdict in labels.items():
        if verdict not in VERDICTS:
            raise ValueError(f"gold row {key} has invalid {field} verdict: {verdict!r}")
    return key, labels


def _field_results(judgment: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(judgment, dict) or not isinstance(judgment.get("field_results"), list):
        return {}
    results: dict[str, dict[str, Any]] = {}
    for item in judgment["field_results"]:
        if not isinstance(item, dict):
            continue
        field = item.get("field")
        verdict = item.get("verdict")
        if field in SEMANTIC_FIELDS and verdict in VERDICTS and field not in results:
            results[field] = item
    return results


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _score_stage(
    stage: str,
    gold_rows: dict[str, dict[str, str]],
    result_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    confusion = {
        field: {expected: Counter({predicted: 0 for predicted in VERDICTS}) for expected in VERDICTS}
        for field in SEMANTIC_FIELDS
    }
    total_labels = len(gold_rows) * len(SEMANTIC_FIELDS)
    predictions = 0
    exact = 0
    abstentions = 0
    expected_incorrect = 0
    predicted_incorrect = 0
    true_incorrect = 0
    exact_cases = 0
    complete_cases = 0
    high_confidence_errors: list[dict[str, Any]] = []

    for key, labels in gold_rows.items():
        result = result_rows.get(key, {})
        fields = _field_results(result.get(stage))
        case_complete = len(fields) == len(SEMANTIC_FIELDS)
        case_exact = case_complete
        if case_complete:
            complete_cases += 1
        for field in SEMANTIC_FIELDS:
            expected = labels[field]
            if expected == "incorrect":
                expected_incorrect += 1
            predicted_item = fields.get(field)
            if predicted_item is None:
                case_exact = False
                continue
            predictions += 1
            predicted = predicted_item["verdict"]
            confusion[field][expected][predicted] += 1
            if predicted == expected:
                exact += 1
            else:
                case_exact = False
                confidence = predicted_item.get("confidence")
                if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and confidence >= 0.8:
                    high_confidence_errors.append(
                        {
                            "key": key,
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

    by_field: dict[str, Any] = {}
    for field in SEMANTIC_FIELDS:
        field_confusion = confusion[field]
        field_total = sum(sum(predictions.values()) for predictions in field_confusion.values())
        field_exact = sum(field_confusion[verdict][verdict] for verdict in VERDICTS)
        field_abstentions = sum(field_confusion[expected]["uncertain"] for expected in VERDICTS)
        by_field[field] = {
            "accuracy": _ratio(field_exact, len(gold_rows)),
            "observed_accuracy": _ratio(field_exact, field_total),
            "abstention_rate": _ratio(field_abstentions, field_total),
            "missing_predictions": len(gold_rows) - field_total,
            "confusion": {
                expected: dict(field_confusion[expected])
                for expected in VERDICTS
            },
        }

    return {
        "gold_cases": len(gold_rows),
        "complete_cases": complete_cases,
        "case_exact_match": _ratio(exact_cases, len(gold_rows)),
        "labels": total_labels,
        "predictions": predictions,
        "missing_predictions": total_labels - predictions,
        "accuracy": _ratio(exact, total_labels),
        "observed_accuracy": _ratio(exact, predictions),
        "abstention_rate": _ratio(abstentions, predictions),
        "incorrect_precision": _ratio(true_incorrect, predicted_incorrect),
        "incorrect_recall": _ratio(true_incorrect, expected_incorrect),
        "high_confidence_errors": high_confidence_errors,
        "by_field": by_field,
    }


def evaluate_semantic_results(
    semantic_rows: Iterable[dict[str, Any]],
    gold: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    gold_rows: dict[str, dict[str, str]] = {}
    for row in gold:
        key, labels = _validate_gold(row)
        if key in gold_rows:
            raise ValueError(f"duplicate gold key: {key}")
        gold_rows[key] = labels

    result_rows: dict[str, dict[str, Any]] = {}
    for row in semantic_rows:
        key = _case_key(row)
        if key is not None:
            result_rows[key] = row

    judge = _score_stage("judgment", gold_rows, result_rows)
    final = _score_stage("final_judgment", gold_rows, result_rows)
    judge_accuracy = judge["accuracy"]
    final_accuracy = final["accuracy"]
    critic_delta = (
        final_accuracy - judge_accuracy
        if isinstance(judge_accuracy, float) and isinstance(final_accuracy, float)
        else None
    )
    return {
        "totals": {
            "gold_cases": len(gold_rows),
            "result_cases": len(result_rows),
            "missing_result_keys": sorted(set(gold_rows) - set(result_rows)),
            "unexpected_result_keys": sorted(set(result_rows) - set(gold_rows)),
        },
        "judge": judge,
        "final": final,
        "critic_accuracy_delta": critic_delta,
    }


def write_semantic_evaluation(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
