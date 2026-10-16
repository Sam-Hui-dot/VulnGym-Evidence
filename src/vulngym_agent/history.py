from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .data_factory import GeneratedCase, assign_group_splits, canonical_sha256
from .repository import normalize_repo_path


SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
NODE_FIELDS = ("file", "line", "code")
SCALAR_FIELDS = (
    "commit",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_ids",
    "report_id",
    "source_link",
    "repo_url",
)


class HistoryError(RuntimeError):
    pass


def _safe_ref(value: str) -> str:
    if (
        not SAFE_REF_RE.fullmatch(value)
        or value.startswith("-")
        or ".." in value
        or "@{" in value
    ):
        raise HistoryError(f"unsafe Git ref: {value!r}")
    return value


def read_jsonl_at_ref(repository: Path, ref: str, file_path: str = "data/entries.jsonl") -> list[dict[str, Any]]:
    root = repository.resolve()
    if not (root / ".git").exists():
        raise HistoryError(f"not a Git repository: {root}")
    safe_ref = _safe_ref(ref)
    safe_path = normalize_repo_path(file_path)
    completed = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={root}",
            "-C",
            str(root),
            "show",
            f"{safe_ref}:{safe_path}",
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise HistoryError(message or f"cannot read {safe_path} at {safe_ref}")

    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(completed.stdout.decode("utf-8", errors="replace").splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise HistoryError(f"{ref}:{file_path}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise HistoryError(f"{ref}:{file_path}:{line_number}: row is not an object")
        rows.append(value)
    return rows


def history_difference_fields(candidate: dict[str, Any], reference: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    for field in SCALAR_FIELDS:
        if candidate.get(field) != reference.get(field):
            changed.append(field)

    for field in ("entry_point", "critical_operation"):
        old_node = candidate.get(field)
        new_node = reference.get(field)
        if not isinstance(old_node, dict) or not isinstance(new_node, dict):
            if old_node != new_node:
                changed.append(field)
            continue
        for node_field in NODE_FIELDS:
            if old_node.get(node_field) != new_node.get(node_field):
                changed.append(f"{field}.{node_field}")

    def trace_projection(value: Any) -> Any:
        if not isinstance(value, list):
            return value
        projected = []
        for node in value:
            if isinstance(node, dict):
                projected.append({field: node.get(field) for field in NODE_FIELDS})
            else:
                projected.append(node)
        return projected

    if trace_projection(candidate.get("trace")) != trace_projection(reference.get("trace")):
        changed.append("trace")
    return changed


def generate_history_cases(
    repository: Path,
    *,
    reference_ref: str,
    candidate_refs: list[str],
    split_unit: str,
    seed: int,
    include_unverified: bool,
    file_path: str = "data/entries.jsonl",
) -> tuple[list[GeneratedCase], dict[str, Any]]:
    reference_rows = read_jsonl_at_ref(repository, reference_ref, file_path)
    if not include_unverified:
        reference_rows = [row for row in reference_rows if row.get("verify") == 1]
    reference_by_id = {
        row["entry_id"]: row
        for row in reference_rows
        if isinstance(row.get("entry_id"), str)
    }
    assignments = assign_group_splits(reference_rows, unit=split_unit, seed=seed)
    key_field = "repo_url" if split_unit == "repo" else "report_id"

    generated: list[GeneratedCase] = []
    seen_candidates: set[tuple[str, str]] = set()
    per_ref: dict[str, int] = {}
    for candidate_ref in candidate_refs:
        count_before = len(generated)
        for old in read_jsonl_at_ref(repository, candidate_ref, file_path):
            entry_id = old.get("entry_id")
            if not isinstance(entry_id, str) or entry_id not in reference_by_id:
                continue
            reference = reference_by_id[entry_id]
            differences = history_difference_fields(old, reference)
            if not differences:
                continue

            candidate = copy.deepcopy(reference)
            fields_to_replace = {field.split(".", 1)[0] for field in differences}
            for field in fields_to_replace:
                if field in old:
                    candidate[field] = copy.deepcopy(old[field])
                else:
                    candidate.pop(field, None)

            payload_hash = canonical_sha256(candidate)
            deduplication_key = (entry_id, payload_hash)
            if deduplication_key in seen_candidates:
                continue
            seen_candidates.add(deduplication_key)

            safe_ref_id = re.sub(r"[^A-Za-z0-9]+", "-", candidate_ref).strip("-").lower()
            case_id = f"{entry_id}-history-{safe_ref_id}"
            candidate["_case_id"] = case_id
            split = assignments[reference[key_field]]
            generated.append(
                GeneratedCase(
                    split=split,
                    candidate=candidate,
                    label={
                        "case_id": case_id,
                        "source_entry_id": entry_id,
                        "split": split,
                        "mutation": "history_revision",
                        "mutation_details": f"candidate from {candidate_ref}; reference is {reference_ref}",
                        "expected_overall_verdict": "incorrect",
                        "expected_incorrect_fields": differences,
                        "candidate_ref": candidate_ref,
                        "reference_ref": reference_ref,
                        "source_sha256": canonical_sha256(reference),
                        "candidate_sha256": canonical_sha256(candidate),
                    },
                )
            )
        per_ref[candidate_ref] = len(generated) - count_before

    metadata = {
        "source_repository": str(repository.resolve()),
        "file_path": file_path,
        "reference_ref": reference_ref,
        "candidate_refs": candidate_refs,
        "split_unit": split_unit,
        "seed": seed,
        "include_unverified": include_unverified,
        "reference_records": len(reference_rows),
        "history_cases": len(generated),
        "unique_source_entries": len({case.label["source_entry_id"] for case in generated}),
        "cases_added_per_ref_after_deduplication": per_ref,
    }
    return generated, metadata

