from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol

from .evidence import packet_evidence_ids
from .prompt_registry import CRITIC_PROMPT, JUDGE_PROMPT


SEMANTIC_FIELDS = (
    "entry_point",
    "critical_operation",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_title",
    "trace",
)


SEMANTIC_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["case_id", "entry_id", "field_results", "overall_verdict", "overall_confidence", "self_check"],
    "properties": {
        "case_id": {"type": ["string", "null"]},
        "entry_id": {"type": ["string", "null"]},
        "field_results": {
            "type": "array",
            "minItems": len(SEMANTIC_FIELDS),
            "maxItems": len(SEMANTIC_FIELDS),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["field", "verdict", "confidence", "reason", "evidence_refs", "correction"],
                "properties": {
                    "field": {"type": "string", "enum": list(SEMANTIC_FIELDS)},
                    "verdict": {"type": "string", "enum": ["correct", "incorrect", "uncertain"]},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "reason": {"type": "string", "minLength": 1},
                    # Structured Outputs does not accept JSON Schema's
                    # ``uniqueItems`` keyword. Duplicate references are still
                    # rejected by ``validate_semantic_output`` below.
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "correction": {
                        "type": ["object", "null"],
                        "additionalProperties": False,
                        "required": ["proposed_value"],
                        "properties": {
                            "proposed_value": {"type": "string"},
                        },
                    },
                },
            },
        },
        "overall_verdict": {"type": "string", "enum": ["correct", "incorrect", "uncertain"]},
        "overall_confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "self_check": {
            "type": "object",
            "additionalProperties": False,
            "required": ["looked_for_counterevidence", "unresolved_questions", "unsupported_claims_removed"],
            "properties": {
                "looked_for_counterevidence": {"type": "boolean"},
                "unresolved_questions": {"type": "array", "items": {"type": "string"}},
                "unsupported_claims_removed": {"type": "boolean"},
            },
        },
    },
}


def semantic_packet_view(packet: dict[str, Any]) -> dict[str, Any]:
    """Return the citable packet subset needed by semantic model calls.

    Full packets remain persisted for audit.  Model requests omit duplicate
    per-trace source windows and unbounded patch-candidate file lists while
    retaining every evidence object that can affect a semantic verdict.
    """
    source_contexts = [
        item
        for item in packet.get("source_contexts", [])
        if isinstance(item, dict)
        and (
            item.get("field") in {"entry_point", "critical_operation"}
            or str(item.get("evidence_id", "")).startswith(("source:entry_point", "source:critical_operation"))
        )
    ]
    patch = packet.get("patch_analysis")
    compact_patch: dict[str, Any] = {}
    if isinstance(patch, dict):
        for key in (
            "status",
            "vulnerable_commit",
            "selected_fix_commit",
            "selection_basis",
            "selection_confidence",
            "diff",
            "diff_truncated",
            "errors",
            "evidence_id",
        ):
            if key in patch:
                compact_patch[key] = patch[key]
        selected = patch.get("selected_fix_commit")
        for candidate in patch.get("candidates", []):
            if isinstance(candidate, dict) and candidate.get("commit") == selected:
                compact_patch["selected_candidate"] = {
                    key: candidate[key]
                    for key in ("commit", "subject", "overlap_files", "score", "is_direct_child")
                    if key in candidate
                }
                break
    repository = packet.get("repository")
    compact_repository = (
        {key: repository.get(key) for key in ("repo_url", "status", "origin", "reason")}
        if isinstance(repository, dict)
        else repository
    )
    return {
        key: value
        for key, value in {
            "packet_version": packet.get("packet_version"),
            "case_id": packet.get("case_id"),
            "entry_id": packet.get("entry_id"),
            "report_id": packet.get("report_id"),
            "candidate_record": packet.get("candidate_record"),
            "repository": compact_repository,
            "deterministic_audit": packet.get("deterministic_audit"),
            "source_contexts": source_contexts,
            "helper_contexts": packet.get("helper_contexts"),
            "patch_analysis": compact_patch,
            "trace_analysis": packet.get("trace_analysis"),
            "lifecycle_analysis": packet.get("lifecycle_analysis"),
            "advisory_analysis": packet.get("advisory_analysis"),
            "taxonomy_analysis": packet.get("taxonomy_analysis"),
            "evidence_policy": packet.get("evidence_policy"),
        }.items()
        if value is not None
    }


class SemanticProvider(Protocol):
    name: str

    def complete(self, request: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class ContractValidation:
    valid: bool
    errors: tuple[str, ...]


def repair_derived_overall(value: Any) -> tuple[Any, tuple[str, ...]]:
    if not isinstance(value, dict) or not isinstance(value.get("field_results"), list):
        return value, ()
    verdicts_by_field: dict[str, str] = {}
    for result in value["field_results"]:
        if not isinstance(result, dict):
            return value, ()
        field = result.get("field")
        verdict = result.get("verdict")
        if field not in SEMANTIC_FIELDS or verdict not in {"correct", "incorrect", "uncertain"} or field in verdicts_by_field:
            return value, ()
        verdicts_by_field[field] = verdict
    if set(verdicts_by_field) != set(SEMANTIC_FIELDS):
        return value, ()
    expected = (
        "incorrect"
        if "incorrect" in verdicts_by_field.values()
        else "uncertain"
        if "uncertain" in verdicts_by_field.values()
        else "correct"
    )
    if value.get("overall_verdict") == expected:
        return value, ()
    repaired = deepcopy(value)
    previous = repaired.get("overall_verdict")
    repaired["overall_verdict"] = expected
    return repaired, (f"overall_verdict: {previous!r} -> {expected!r} (derived from field_results)",)


def build_judge_request(packet: dict[str, Any]) -> dict[str, Any]:
    packet_view = semantic_packet_view(packet)
    return {
        "task": "vulngym_t1_semantic_judge",
        "prompt_metadata": JUDGE_PROMPT.metadata(),
        "instructions": list(JUDGE_PROMPT.instructions),
        "output_schema": SEMANTIC_OUTPUT_SCHEMA,
        "valid_evidence_ids": sorted(packet_evidence_ids(packet_view)),
        "packet": packet_view,
    }


def build_critic_request(packet: dict[str, Any], judgment: dict[str, Any]) -> dict[str, Any]:
    packet_view = semantic_packet_view(packet)
    return {
        "task": "vulngym_t1_semantic_critic",
        "prompt_metadata": CRITIC_PROMPT.metadata(),
        "instructions": list(CRITIC_PROMPT.instructions),
        "output_schema": SEMANTIC_OUTPUT_SCHEMA,
        "valid_evidence_ids": sorted(packet_evidence_ids(packet_view)),
        "packet": packet_view,
        "proposed_judgment": judgment,
    }


def validate_semantic_output(value: Any, evidence_ids: set[str]) -> ContractValidation:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ContractValidation(False, ("output must be an object",))
    required = {"case_id", "entry_id", "field_results", "overall_verdict", "overall_confidence", "self_check"}
    missing = sorted(required - set(value))
    if missing:
        errors.append("missing keys: " + ", ".join(missing))
    extra = sorted(set(value) - required)
    if extra:
        errors.append("unexpected keys: " + ", ".join(extra))
    if value.get("case_id") is not None and not isinstance(value.get("case_id"), str):
        errors.append("case_id must be a string or null")
    if value.get("entry_id") is not None and not isinstance(value.get("entry_id"), str):
        errors.append("entry_id must be a string or null")

    results = value.get("field_results")
    seen_fields: list[str] = []
    if not isinstance(results, list):
        errors.append("field_results must be a list")
    else:
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                errors.append(f"field_results[{index}] must be an object")
                continue
            result_required = {"field", "verdict", "confidence", "reason", "evidence_refs", "correction"}
            result_missing = sorted(result_required - set(result))
            result_extra = sorted(set(result) - result_required)
            if result_missing:
                errors.append(f"field_results[{index}] missing keys: {', '.join(result_missing)}")
            if result_extra:
                errors.append(f"field_results[{index}] unexpected keys: {', '.join(result_extra)}")
            field = result.get("field")
            if field not in SEMANTIC_FIELDS:
                errors.append(f"field_results[{index}].field is invalid")
            elif field in seen_fields:
                errors.append(f"duplicate semantic field: {field}")
            else:
                seen_fields.append(field)
            verdict = result.get("verdict")
            if verdict not in {"correct", "incorrect", "uncertain"}:
                errors.append(f"field_results[{index}].verdict is invalid")
            confidence = result.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
                errors.append(f"field_results[{index}].confidence must be within 0..1")
            reason = result.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                errors.append(f"field_results[{index}].reason must be non-empty")
            references = result.get("evidence_refs")
            if not isinstance(references, list) or not all(isinstance(item, str) for item in references):
                errors.append(f"field_results[{index}].evidence_refs must be a string list")
            else:
                unknown = sorted(set(references) - evidence_ids)
                if unknown:
                    errors.append(f"field_results[{index}] cites unknown evidence: {', '.join(unknown)}")
                if len(references) != len(set(references)):
                    errors.append(f"field_results[{index}].evidence_refs must not contain duplicates")
                if verdict in {"correct", "incorrect"} and not references:
                    errors.append(f"field_results[{index}] needs evidence for {verdict}")
            correction = result.get("correction")
            if "correction" not in result or (correction is not None and not isinstance(correction, dict)):
                errors.append(f"field_results[{index}].correction must be an object or null")
            elif isinstance(correction, dict):
                correction_required = {"proposed_value"}
                correction_missing = sorted(correction_required - set(correction))
                correction_extra = sorted(set(correction) - correction_required)
                if correction_missing:
                    errors.append(f"field_results[{index}].correction missing keys: {', '.join(correction_missing)}")
                if correction_extra:
                    errors.append(f"field_results[{index}].correction unexpected keys: {', '.join(correction_extra)}")
                proposed_value = correction.get("proposed_value")
                if not isinstance(proposed_value, str) or not proposed_value.strip():
                    errors.append(f"field_results[{index}].correction.proposed_value must be non-empty")
        if set(seen_fields) != set(SEMANTIC_FIELDS):
            errors.append("field_results must contain each semantic field exactly once")

    if value.get("overall_verdict") not in {"correct", "incorrect", "uncertain"}:
        errors.append("overall_verdict is invalid")
    elif isinstance(results, list):
        field_verdicts = [result.get("verdict") for result in results if isinstance(result, dict)]
        expected_overall = (
            "incorrect"
            if "incorrect" in field_verdicts
            else "uncertain"
            if "uncertain" in field_verdicts
            else "correct"
        )
        if value.get("overall_verdict") != expected_overall:
            errors.append(f"overall_verdict must be {expected_overall} given field_results")
    confidence = value.get("overall_confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append("overall_confidence must be within 0..1")
    self_check = value.get("self_check")
    if not isinstance(self_check, dict):
        errors.append("self_check must be an object")
    else:
        self_check_required = {"looked_for_counterevidence", "unresolved_questions", "unsupported_claims_removed"}
        self_check_missing = sorted(self_check_required - set(self_check))
        self_check_extra = sorted(set(self_check) - self_check_required)
        if self_check_missing:
            errors.append("self_check missing keys: " + ", ".join(self_check_missing))
        if self_check_extra:
            errors.append("self_check unexpected keys: " + ", ".join(self_check_extra))
        if type(self_check.get("looked_for_counterevidence")) is not bool:
            errors.append("self_check.looked_for_counterevidence must be boolean")
        if type(self_check.get("unsupported_claims_removed")) is not bool:
            errors.append("self_check.unsupported_claims_removed must be boolean")
        questions = self_check.get("unresolved_questions")
        if not isinstance(questions, list) or not all(isinstance(item, str) for item in questions):
            errors.append("self_check.unresolved_questions must be a string list")
    return ContractValidation(not errors, tuple(errors))
