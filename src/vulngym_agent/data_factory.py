from __future__ import annotations

import copy
import hashlib
import json
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .jsonl import write_jsonl


SPLITS = ("train", "dev", "holdout")


@dataclass(frozen=True)
class GeneratedCase:
    split: str
    candidate: dict[str, Any]
    label: dict[str, Any]


def canonical_sha256(record: dict[str, Any]) -> str:
    payload = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def assign_group_splits(
    records: list[dict[str, Any]],
    *,
    unit: str,
    seed: int,
    ratios: tuple[float, float, float] = (0.7, 0.15, 0.15),
) -> dict[str, str]:
    if unit not in {"repo", "report"}:
        raise ValueError("split unit must be 'repo' or 'report'")
    if len(ratios) != 3 or any(value <= 0 for value in ratios) or abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("split ratios must contain three positive values summing to 1")

    key_field = "repo_url" if unit == "repo" else "report_id"
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = record.get(key_field)
        if not isinstance(key, str) or not key:
            raise ValueError(f"record is missing a valid {key_field}")
        groups[key].append(record)

    def order_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[int, str]:
        key, rows = item
        digest = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
        return -len(rows), digest

    targets = {name: len(records) * ratio for name, ratio in zip(SPLITS, ratios)}
    totals = {name: 0 for name in SPLITS}
    assignments: dict[str, str] = {}
    for key, rows in sorted(groups.items(), key=order_key):
        split = min(SPLITS, key=lambda name: (totals[name] / targets[name], SPLITS.index(name)))
        assignments[key] = split
        totals[split] += len(rows)
    return assignments


def _flip_hex_character(value: str) -> str:
    replacement = "0" if value[-1] != "0" else "1"
    return value[:-1] + replacement


def _mutate_path(value: str) -> str:
    slash = value.rfind("/")
    directory, name = (value[: slash + 1], value[slash + 1 :]) if slash >= 0 else ("", value)
    dot = name.rfind(".")
    if dot > 0:
        name = f"{name[:dot]}.vulngym-mutated{name[dot:]}"
    else:
        name = f"{name}.vulngym-mutated"
    return directory + name


def _mutate_line(value: int | str) -> int | str:
    if isinstance(value, int):
        return value + 50
    start, end = (int(part) for part in value.split("-", 1))
    return f"{start + 50}-{end + 50}"


def _mutate_code(value: str) -> str:
    for index, character in enumerate(value):
        if character.isalpha() or character == "_":
            end = index + 1
            while end < len(value) and (value[end].isalnum() or value[end] == "_"):
                end += 1
            return value[:end] + "_VULNGYM_MUTATED" + value[end:]
    return value + " VULNGYM_MUTATED"


def _donor(record: dict[str, Any], pool: list[dict[str, Any]], field: str) -> dict[str, Any] | None:
    for candidate in pool:
        if candidate.get(field) != record.get(field):
            return candidate
    return None


def mutation_names(record: dict[str, Any], pool: list[dict[str, Any]]) -> list[str]:
    names = [
        "wrong_commit",
        "wrong_entry_file",
        "wrong_entry_line",
        "wrong_entry_code",
        "wrong_critical_file",
        "wrong_critical_line",
        "wrong_critical_code",
        "swapped_roles",
    ]
    if isinstance(record.get("trace"), list) and len(record["trace"]) >= 2:
        names.append("broken_trace_order")
    if _donor(record, pool, "vuln_category_l1") is not None:
        names.append("wrong_category")
    if _donor(record, pool, "vuln_title") is not None:
        names.append("wrong_title")
    if _donor(record, pool, "vuln_ids") is not None:
        names.append("wrong_vuln_ids")
    return names


def apply_mutation(
    record: dict[str, Any],
    name: str,
    pool: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str], str]:
    mutated = copy.deepcopy(record)
    details = ""
    fields: list[str]

    if name == "wrong_commit":
        original = mutated["commit"]
        mutated["commit"] = _flip_hex_character(original)
        fields, details = ["commit"], f"changed {original} to {mutated['commit']}"
    elif name == "wrong_entry_file":
        original = mutated["entry_point"]["file"]
        mutated["entry_point"]["file"] = _mutate_path(original)
        fields, details = ["entry_point.file"], f"changed path {original!r}"
    elif name == "wrong_entry_line":
        original = mutated["entry_point"]["line"]
        mutated["entry_point"]["line"] = _mutate_line(original)
        fields, details = ["entry_point.line"], f"shifted line {original!r} by 50"
    elif name == "wrong_entry_code":
        mutated["entry_point"]["code"] = _mutate_code(mutated["entry_point"]["code"])
        fields, details = ["entry_point.code"], "changed the first code identifier"
    elif name == "wrong_critical_file":
        original = mutated["critical_operation"]["file"]
        mutated["critical_operation"]["file"] = _mutate_path(original)
        fields, details = ["critical_operation.file"], f"changed path {original!r}"
    elif name == "wrong_critical_line":
        original = mutated["critical_operation"]["line"]
        mutated["critical_operation"]["line"] = _mutate_line(original)
        fields, details = ["critical_operation.line"], f"shifted line {original!r} by 50"
    elif name == "wrong_critical_code":
        mutated["critical_operation"]["code"] = _mutate_code(mutated["critical_operation"]["code"])
        fields, details = ["critical_operation.code"], "changed the first code identifier"
    elif name == "swapped_roles":
        mutated["entry_point"], mutated["critical_operation"] = (
            mutated["critical_operation"],
            mutated["entry_point"],
        )
        fields, details = ["entry_point", "critical_operation"], "swapped semantic roles"
    elif name == "broken_trace_order":
        mutated["trace"][0], mutated["trace"][-1] = mutated["trace"][-1], mutated["trace"][0]
        fields, details = ["trace"], "swapped the first and last trace nodes"
    elif name == "wrong_category":
        donor = _donor(record, pool, "vuln_category_l1")
        if donor is None:
            raise ValueError("no category donor available")
        mutated["vuln_category_l1"] = donor["vuln_category_l1"]
        mutated["vuln_category_l2"] = donor["vuln_category_l2"]
        fields, details = ["vuln_category_l1", "vuln_category_l2"], f"copied categories from {donor['entry_id']}"
    elif name == "wrong_title":
        donor = _donor(record, pool, "vuln_title")
        if donor is None:
            raise ValueError("no title donor available")
        mutated["vuln_title"] = donor["vuln_title"]
        fields, details = ["vuln_title"], f"copied title from {donor['entry_id']}"
    elif name == "wrong_vuln_ids":
        donor = _donor(record, pool, "vuln_ids")
        if donor is None:
            raise ValueError("no identifier donor available")
        mutated["vuln_ids"] = copy.deepcopy(donor["vuln_ids"])
        fields, details = ["vuln_ids"], f"copied identifiers from {donor['entry_id']}"
    else:
        raise ValueError(f"unknown mutation: {name}")
    return mutated, fields, details


def generate_cases(
    records: list[dict[str, Any]],
    *,
    seed: int,
    split_unit: str,
    mutations_per_record: int,
    include_clean: bool,
) -> list[GeneratedCase]:
    if mutations_per_record < 0:
        raise ValueError("mutations_per_record must be non-negative")
    key_field = "repo_url" if split_unit == "repo" else "report_id"
    assignments = assign_group_splits(records, unit=split_unit, seed=seed)
    pools_by_split = {
        split: [record for record in records if assignments[record[key_field]] == split]
        for split in SPLITS
    }
    generated: list[GeneratedCase] = []

    for record in sorted(records, key=lambda value: value["entry_id"]):
        split = assignments[record[key_field]]
        donor_pool = pools_by_split[split]
        source_hash = canonical_sha256(record)
        if include_clean:
            case_id = f"{record['entry_id']}-clean"
            candidate = copy.deepcopy(record)
            candidate["_case_id"] = case_id
            generated.append(
                GeneratedCase(
                    split,
                    candidate,
                    {
                        "case_id": case_id,
                        "source_entry_id": record["entry_id"],
                        "split": split,
                        "mutation": "clean",
                        "mutation_details": "unmodified verified public record",
                        "expected_overall_verdict": "correct",
                        "expected_incorrect_fields": [],
                        "source_sha256": source_hash,
                        "candidate_sha256": canonical_sha256(candidate),
                    },
                )
            )

        names = mutation_names(record, donor_pool)
        random.Random(f"{seed}:{record['entry_id']}").shuffle(names)
        for index, name in enumerate(names[:mutations_per_record], 1):
            candidate, fields, details = apply_mutation(record, name, donor_pool)
            case_id = f"{record['entry_id']}-m{index:02d}-{name}"
            candidate["_case_id"] = case_id
            generated.append(
                GeneratedCase(
                    split,
                    candidate,
                    {
                        "case_id": case_id,
                        "source_entry_id": record["entry_id"],
                        "split": split,
                        "mutation": name,
                        "mutation_details": details,
                        "expected_overall_verdict": "incorrect",
                        "expected_incorrect_fields": fields,
                        "source_sha256": source_hash,
                        "candidate_sha256": canonical_sha256(candidate),
                    },
                )
            )
    return generated


def write_dataset(output_dir: Path, cases: Iterable[GeneratedCase], *, metadata: dict[str, Any]) -> dict[str, Any]:
    materialized = list(cases)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"metadata": metadata, "splits": {}}
    for split in SPLITS:
        selected = [case for case in materialized if case.split == split]
        write_jsonl(output_dir / f"candidates.{split}.jsonl", (case.candidate for case in selected))
        write_jsonl(output_dir / f"manifest.{split}.jsonl", (case.label for case in selected))
        summary["splits"][split] = {
            "cases": len(selected),
            "clean": sum(case.label["mutation"] == "clean" for case in selected),
            "mutated": sum(case.label["mutation"] != "clean" for case in selected),
            "reports": len({case.candidate.get("report_id") for case in selected}),
            "repositories": len({case.candidate.get("repo_url") for case in selected}),
        }
    write_jsonl(output_dir / "manifest.jsonl", (case.label for case in materialized))
    summary_path = output_dir / "summary.json"
    temporary = summary_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(summary_path)
    return summary
