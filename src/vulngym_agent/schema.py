from __future__ import annotations

import re
from typing import Any

from .models import CheckResult, Evidence, Verdict


REQUIRED_FIELDS = (
    "entry_id",
    "report_id",
    "source_link",
    "vuln_ids",
    "origin",
    "project",
    "repo_url",
    "commit",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "entry_point",
    "critical_operation",
    "trace",
    "verify",
)

FORBIDDEN_INTERNAL_FIELDS = {
    "description",
    "human_remark",
    "pipeline_id",
    "annotated_by",
    "is_active",
    "created_at",
    "generality",
    "detection_type",
    "ground_truth",
    "taint_source",
    "taint_sink",
    "vuln_category_l3",
}

ENTRY_ID_RE = re.compile(r"^entry-\d{5}$")
GHSA_RE = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
VULN_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$")


def line_span(value: Any) -> tuple[int, int] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return (value, value) if value >= 1 else None
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return start, end
    return None


def _result(
    field: str,
    ok: bool,
    reason: str,
    observation: str,
    *,
    confidence: float = 1.0,
) -> CheckResult:
    return CheckResult(
        field=field,
        verdict=Verdict.CORRECT if ok else Verdict.INCORRECT,
        confidence=confidence,
        reason=reason,
        evidence=(Evidence("schema", field, observation),),
    )


def _non_empty_string(record: dict[str, Any], field: str) -> CheckResult:
    value = record.get(field)
    ok = isinstance(value, str) and bool(value.strip())
    return _result(field, ok, "must be a non-empty string", repr(value))


def _validate_node(node: Any, field: str) -> list[CheckResult]:
    if not isinstance(node, dict):
        return [_result(field, False, "must be an object", type(node).__name__)]

    checks: list[CheckResult] = []
    file_value = node.get("file")
    file_ok = isinstance(file_value, str) and bool(file_value.strip())
    checks.append(_result(f"{field}.file", file_ok, "must be a non-empty repository-relative path", repr(file_value)))

    span = line_span(node.get("line"))
    checks.append(
        _result(
            f"{field}.line",
            span is not None,
            "must be a positive integer or an ordered 'start-end' range",
            repr(node.get("line")),
        )
    )

    code_value = node.get("code")
    code_ok = isinstance(code_value, str) and bool(code_value.strip())
    checks.append(_result(f"{field}.code", code_ok, "must be a non-empty string", repr(code_value)[:240]))

    if "desc" in node:
        desc_value = node["desc"]
        checks.append(
            _result(
                f"{field}.desc",
                isinstance(desc_value, str) and bool(desc_value.strip()),
                "when present, desc must be a non-empty string",
                repr(desc_value)[:240],
            )
        )
    return checks


def validate_schema(record: dict[str, Any]) -> list[CheckResult]:
    checks: list[CheckResult] = []

    for field in REQUIRED_FIELDS:
        checks.append(_result(field, field in record, "required top-level field", "present" if field in record else "missing"))

    internal = sorted(FORBIDDEN_INTERNAL_FIELDS.intersection(record))
    checks.append(
        _result(
            "$internal_fields",
            not internal,
            "released rows must not expose internal annotation fields",
            ", ".join(internal) if internal else "none",
        )
    )

    entry_id = record.get("entry_id")
    checks.append(_result("entry_id.format", isinstance(entry_id, str) and bool(ENTRY_ID_RE.fullmatch(entry_id)), "must match entry-00000", repr(entry_id)))

    report_id = record.get("report_id")
    report_ok = isinstance(report_id, str) and bool(GHSA_RE.fullmatch(report_id))
    checks.append(_result("report_id.format", report_ok, "must be an uppercase GHSA identifier", repr(report_id)))

    source_link = record.get("source_link")
    expected_suffix = report_id.lower() if isinstance(report_id, str) else ""
    source_ok = (
        isinstance(source_link, str)
        and source_link.lower().startswith("https://github.com/advisories/ghsa-")
        and source_link.rstrip("/").lower().endswith(expected_suffix)
    )
    checks.append(_result("source_link.format", source_ok, "must be the canonical GitHub advisory URL for report_id", repr(source_link)))

    vuln_ids = record.get("vuln_ids")
    ids_ok = isinstance(vuln_ids, list) and all(
        isinstance(value, str) and bool(VULN_ID_RE.fullmatch(value)) for value in vuln_ids
    )
    if ids_ok:
        ids_ok = len(vuln_ids) == len(set(vuln_ids))
    checks.append(_result("vuln_ids.format", ids_ok, "must be a deduplicated list of normalized CVE/GHSA identifiers", repr(vuln_ids)))

    checks.append(_result("origin.value", record.get("origin") == "GitHub Advisory Database (reviewed)", "must use the v0.1.4 origin constant", repr(record.get("origin"))))

    for field in ("project", "vuln_title", "vuln_category_l1", "vuln_category_l2"):
        checks.append(_non_empty_string(record, field))

    repo_url = record.get("repo_url")
    repo_ok = isinstance(repo_url, str) and repo_url.startswith("https://github.com/") and len(repo_url.split("/")) >= 5
    checks.append(_result("repo_url.format", repo_ok, "must be a GitHub repository URL", repr(repo_url)))

    commit = record.get("commit")
    checks.append(_result("commit.format", isinstance(commit, str) and bool(COMMIT_RE.fullmatch(commit)), "must be a 40-character lowercase SHA", repr(commit)))

    verify = record.get("verify")
    checks.append(_result("verify.value", type(verify) is int and verify in (0, 1), "must be the integer 0 or 1", repr(verify)))

    checks.extend(_validate_node(record.get("entry_point"), "entry_point"))
    checks.extend(_validate_node(record.get("critical_operation"), "critical_operation"))

    trace = record.get("trace")
    checks.append(_result("trace.type", isinstance(trace, list), "must be a list", type(trace).__name__))
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            checks.extend(_validate_node(node, f"trace[{index}]"))

    return checks

