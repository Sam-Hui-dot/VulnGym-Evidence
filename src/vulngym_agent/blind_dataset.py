from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .data_factory import canonical_sha256
from .history import history_difference_fields, read_jsonl_at_ref
from .jsonl import write_jsonl
from .submission import SUBMISSION_FIELDS


BLIND_DATASET_VERSION = "0.3.0"
REVIEW_VERDICTS = {"correct", "incorrect", "uncertain"}


def _rows_by_id(repository: Path, ref: str) -> dict[str, dict[str, Any]]:
    return {
        str(row["entry_id"]): row
        for row in read_jsonl_at_ref(repository, ref)
        if isinstance(row.get("entry_id"), str)
    }


def _top_level_fields(fields: list[str]) -> list[str]:
    return list(dict.fromkeys(field.split(".", 1)[0] for field in fields))


def _labels_for(changed_fields: list[str]) -> dict[str, str]:
    changed = set(_top_level_fields(changed_fields))
    return {
        field: "incorrect" if field in changed else "correct"
        for field in SUBMISSION_FIELDS
    }


def _review_for(item: dict[str, Any]) -> tuple[dict[str, str] | None, str | None, Any]:
    review = item.get("review")
    if review is None:
        return None, None, None
    if not isinstance(review, dict):
        raise ValueError("case review must be an object")
    if review.get("status") != "reviewed":
        raise ValueError("case review.status must be 'reviewed'")
    labels = review.get("labels")
    if not isinstance(labels, dict) or set(labels) != set(SUBMISSION_FIELDS):
        raise ValueError("case review.labels must contain exactly the eight T1 fields")
    invalid = {field: verdict for field, verdict in labels.items() if verdict not in REVIEW_VERDICTS}
    if invalid:
        raise ValueError(f"case review contains invalid verdicts: {invalid!r}")
    reviewer = review.get("reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError("case review.reviewer must be a non-empty string")
    notes = review.get("notes")
    if not isinstance(notes, (str, dict, list)):
        raise ValueError("case review.notes must be text, an object, or a list")
    return dict(labels), reviewer.strip(), copy.deepcopy(notes)


def build_blind_dataset(
    repository: Path,
    selection: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Materialize a frozen clean/history benchmark from published VulnGym refs.

    The selection must be committed before any model run.  Historical candidates
    start from the trusted reference row and replace only fields that differ in
    the older published ref, so every one of the eight T1 fields receives a
    dataset-derived label instead of scoring only the mutated field.
    """
    evaluation_id = selection.get("evaluation_id")
    reference_ref = selection.get("reference_ref")
    cases = selection.get("cases")
    if not isinstance(evaluation_id, str) or not evaluation_id:
        raise ValueError("selection.evaluation_id must be a non-empty string")
    if not isinstance(reference_ref, str) or not reference_ref:
        raise ValueError("selection.reference_ref must be a non-empty string")
    if not isinstance(cases, list) or not cases:
        raise ValueError("selection.cases must be a non-empty list")

    reference_rows = _rows_by_id(repository, reference_ref)
    rows_by_ref: dict[str, dict[str, dict[str, Any]]] = {reference_ref: reference_rows}
    excluded_ids = set(selection.get("excluded_development_entry_ids", []))
    excluded_report_ids = {
        str(value).upper()
        for value in selection.get("excluded_development_report_ids", [])
    }
    excluded_repositories = {
        str(value).lower().rstrip("/")
        for value in selection.get("excluded_development_repositories", [])
    }

    candidates: list[dict[str, Any]] = []
    reference: list[dict[str, Any]] = []
    review_queue: list[dict[str, Any]] = []
    manifest_cases: list[dict[str, Any]] = []
    seen_case_ids: set[str] = set()
    seen_entry_ids: set[str] = set()

    for item in cases:
        if not isinstance(item, dict):
            raise ValueError("each selection case must be an object")
        case_id = item.get("case_id")
        entry_id = item.get("entry_id")
        kind = item.get("kind")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("case_id must be a non-empty string")
        if case_id in seen_case_ids:
            raise ValueError(f"duplicate case_id: {case_id}")
        if not isinstance(entry_id, str) or entry_id not in reference_rows:
            raise ValueError(f"unknown reference entry_id: {entry_id!r}")
        if entry_id in seen_entry_ids:
            raise ValueError(f"duplicate entry_id would make result matching ambiguous: {entry_id}")
        if entry_id in excluded_ids:
            raise ValueError(f"development entry leaked into blind selection: {entry_id}")

        trusted = reference_rows[entry_id]
        report_id = str(trusted.get("report_id") or "")
        if report_id.upper() in excluded_report_ids:
            raise ValueError(f"development report leaked into blind selection: {report_id}")
        repo_url = str(trusted.get("repo_url") or "")
        if repo_url.lower().rstrip("/") in excluded_repositories:
            raise ValueError(f"development repository leaked into blind selection: {repo_url}")
        if trusted.get("verify") != 1:
            raise ValueError(f"reference row is not human-verified at {reference_ref}: {entry_id}")

        candidate = copy.deepcopy(trusted)
        changed_fields: list[str] = []
        candidate_ref = reference_ref
        if kind == "history_revision":
            candidate_ref = item.get("candidate_ref")
            if not isinstance(candidate_ref, str) or not candidate_ref:
                raise ValueError(f"history case {case_id} is missing candidate_ref")
            if candidate_ref not in rows_by_ref:
                rows_by_ref[candidate_ref] = _rows_by_id(repository, candidate_ref)
            older = rows_by_ref[candidate_ref].get(entry_id)
            if older is None:
                raise ValueError(f"{entry_id} is absent from {candidate_ref}")
            changed_fields = history_difference_fields(older, trusted)
            if not changed_fields:
                raise ValueError(f"history case has no scored revision: {case_id}")
            for field in _top_level_fields(changed_fields):
                if field in older:
                    candidate[field] = copy.deepcopy(older[field])
                else:
                    candidate.pop(field, None)
        elif kind != "clean":
            raise ValueError(f"unsupported blind case kind: {kind!r}")

        expected = item.get("expected_changed_fields")
        if expected is not None and sorted(expected) != sorted(changed_fields):
            raise ValueError(
                f"frozen changed fields drifted for {case_id}: "
                f"expected {expected!r}, got {changed_fields!r}"
            )

        candidate["_case_id"] = case_id
        provisional_labels = _labels_for(changed_fields)
        reviewed_labels, reviewer, review_notes = _review_for(item)
        labels = reviewed_labels or provisional_labels
        review_status = "reviewed" if reviewed_labels is not None else "pending"
        candidate_hash = canonical_sha256(candidate)
        trusted_hash = canonical_sha256(trusted)
        reference_row = {
            "case_id": case_id,
            "entry_id": entry_id,
            "labels": labels,
            "provenance": {
                "kind": kind,
                "candidate_ref": candidate_ref,
                "reference_ref": reference_ref,
                "changed_fields": changed_fields,
                "reference_verify": trusted.get("verify"),
                "status": (
                    "evidence-reviewed reference"
                    if reviewed_labels is not None
                    else "dataset-derived provisional reference; human review required"
                ),
                "reviewer": reviewer,
            },
        }
        manifest_row = {
            "case_id": case_id,
            "entry_id": entry_id,
            "repo_url": repo_url,
            "report_id": trusted.get("report_id"),
            "kind": kind,
            "candidate_ref": candidate_ref,
            "reference_ref": reference_ref,
            "changed_fields": changed_fields,
            "candidate_sha256": candidate_hash,
            "reference_sha256": trusted_hash,
            "review_status": review_status,
        }
        review_row = {
            **manifest_row,
            "labels": labels,
            "candidate_fields": {
                field: copy.deepcopy(candidate.get(field))
                for field in SUBMISSION_FIELDS
            },
            "reference_fields": {
                field: copy.deepcopy(trusted.get(field))
                for field in SUBMISSION_FIELDS
            },
            "provisional_labels": provisional_labels,
            "review_status": review_status,
            "reviewer": reviewer,
            "review_notes": review_notes if review_notes is not None else "",
        }
        candidates.append(candidate)
        reference.append(reference_row)
        review_queue.append(review_row)
        manifest_cases.append(manifest_row)
        seen_case_ids.add(case_id)
        seen_entry_ids.add(entry_id)

    selection_hash = canonical_sha256(selection)
    if selection.get("selection_status") == "frozen":
        pending = [item["case_id"] for item in manifest_cases if item["review_status"] != "reviewed"]
        if pending:
            raise ValueError(f"frozen blind selection contains unreviewed cases: {pending!r}")
    label_counts = {
        verdict: sum(row["labels"][field] == verdict for row in reference for field in SUBMISSION_FIELDS)
        for verdict in sorted(REVIEW_VERDICTS)
    }
    manifest = {
        "evaluation_id": evaluation_id,
        "dataset_version": BLIND_DATASET_VERSION,
        "selection_sha256": selection_hash,
        "reference_ref": reference_ref,
        "cases": manifest_cases,
        "counts": {
            "cases": len(manifest_cases),
            "clean": sum(item["kind"] == "clean" for item in manifest_cases),
            "history_revision": sum(item["kind"] == "history_revision" for item in manifest_cases),
            "repositories": len({item["repo_url"] for item in manifest_cases}),
            "labels": len(manifest_cases) * len(SUBMISSION_FIELDS),
            "reviewed_cases": sum(item["review_status"] == "reviewed" for item in manifest_cases),
            "label_verdicts": label_counts,
        },
        "policy": selection.get("policy", {}),
    }
    return candidates, reference, review_queue, manifest


def write_blind_dataset(
    output_dir: Path,
    *,
    candidates: list[dict[str, Any]],
    reference: list[dict[str, Any]],
    review_queue: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / "candidates.jsonl", candidates)
    write_jsonl(output_dir / "reference.jsonl", reference)
    write_jsonl(output_dir / "review-queue.jsonl", review_queue)
    temporary = output_dir / "manifest.json.tmp"
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output_dir / "manifest.json")
