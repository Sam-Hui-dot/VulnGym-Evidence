from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


def _case_key(row: dict[str, Any]) -> str | None:
    value = row.get("case_id")
    return value if isinstance(value, str) and value else None


def _field_verdicts(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("field_results"), list):
        return {}
    return {
        item["field"]: item
        for item in value["field_results"]
        if isinstance(item, dict) and isinstance(item.get("field"), str) and isinstance(item.get("verdict"), str)
    }


def _score(rows: dict[str, dict[str, Any]], manifest: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    counts = Counter()
    by_mutation: dict[str, Counter] = {}
    high_confidence_misses: list[dict[str, Any]] = []
    completed_cases = 0
    models: set[str] = set()
    for item in manifest:
        key = item["case_id"]
        row = rows.get(key, {})
        fields = _field_verdicts(row.get(stage))
        if fields:
            completed_cases += 1
        metadata = row.get("provider_metadata") or row.get("judge_provider_metadata")
        if isinstance(metadata, dict):
            model = metadata.get("resolved_model") or metadata.get("requested_model")
            if isinstance(model, str):
                models.add(model)
        mutation_counts = by_mutation.setdefault(item["mutation"], Counter())
        for field in item["target_fields"]:
            counts["targets"] += 1
            mutation_counts["targets"] += 1
            prediction = fields.get(field)
            if prediction is None:
                counts["missing"] += 1
                mutation_counts["missing"] += 1
                continue
            verdict = prediction["verdict"]
            counts[verdict] += 1
            mutation_counts[verdict] += 1
            if verdict == "incorrect":
                counts["detected"] += 1
                mutation_counts["detected"] += 1
            else:
                confidence = prediction.get("confidence")
                if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and confidence >= 0.8:
                    high_confidence_misses.append(
                        {"case_id": key, "field": field, "predicted": verdict, "confidence": confidence}
                    )
    total = counts["targets"]
    return {
        "cases": len(manifest),
        "completed_cases": completed_cases,
        "target_labels": total,
        "detected": counts["detected"],
        "target_detection_recall": counts["detected"] / total if total else None,
        "uncertain_rate": counts["uncertain"] / total if total else None,
        "missed_as_correct": counts["correct"],
        "missing_predictions": counts["missing"],
        "models": sorted(models),
        "high_confidence_misses": high_confidence_misses,
        "by_mutation": {
            mutation: {
                "targets": values["targets"],
                "detected": values["detected"],
                "uncertain": values["uncertain"],
                "missed_as_correct": values["correct"],
                "missing": values["missing"],
            }
            for mutation, values in sorted(by_mutation.items())
        },
    }


def compare_mutation_detection(
    manifest: Iterable[dict[str, Any]],
    bare_rows: Iterable[dict[str, Any]],
    agent_rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    labels = list(manifest)
    bare = {key: row for row in bare_rows if (key := _case_key(row)) is not None}
    agent = {key: row for row in agent_rows if (key := _case_key(row)) is not None}
    return {
        "evaluation_policy": "Only intentionally mutated target fields are scored; untouched fields are not treated as gold.",
        "bare_record": _score(bare, labels, "final_judgment"),
        "evidence_judge": _score(agent, labels, "judgment"),
        "evidence_judge_critic": _score(agent, labels, "final_judgment"),
    }
