from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_selection(path: Path) -> list[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    cases = value.get("cases") if isinstance(value, dict) else None
    if not isinstance(cases, list):
        raise ValueError("selection file must contain a cases list")
    entry_ids: list[str] = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("entry_id"), str):
            raise ValueError("every selected case must contain an entry_id string")
        entry_ids.append(case["entry_id"])
    if len(entry_ids) != len(set(entry_ids)):
        raise ValueError("selection contains duplicate entry_id values")
    return entry_ids


def select_records(records: list[dict[str, Any]], entry_ids: list[str]) -> list[dict[str, Any]]:
    by_id = {
        record["entry_id"]: record
        for record in records
        if isinstance(record.get("entry_id"), str)
    }
    missing = [entry_id for entry_id in entry_ids if entry_id not in by_id]
    if missing:
        raise ValueError("selected entry_ids are absent from input: " + ", ".join(missing))
    return [by_id[entry_id] for entry_id in entry_ids]

