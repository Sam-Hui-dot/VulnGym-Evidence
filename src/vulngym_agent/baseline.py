from __future__ import annotations

from copy import deepcopy
import time
from typing import Any

from .prompt_registry import PromptSpec
from .provider import ProviderCompletion, ProviderError
from .semantic_contract import SEMANTIC_OUTPUT_SCHEMA, SemanticProvider, repair_derived_overall, validate_semantic_output


BARE_RECORD_PROMPT = PromptSpec(
    prompt_id="vulngym.t1.baseline.bare-record",
    version="1.0.0",
    instructions=(
        "Review whether the six semantic fields in this VulnGym record accurately describe the claimed vulnerability.",
        "You have only the candidate record and no repository, patch, advisory, taxonomy, or tool evidence.",
        "Use candidate:record as the only available evidence reference.",
        "Return uncertain when the record alone is insufficient to decide.",
        "Return only an object matching output_schema.",
    ),
)


def build_bare_record_request(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": "vulngym_t1_bare_record_baseline",
        "prompt_metadata": BARE_RECORD_PROMPT.metadata(),
        "instructions": list(BARE_RECORD_PROMPT.instructions),
        "output_schema": SEMANTIC_OUTPUT_SCHEMA,
        "available_evidence": {
            "evidence_id": "candidate:record",
            "content": record,
        },
    }


def _complete(provider: SemanticProvider, request: dict[str, Any]) -> ProviderCompletion:
    try:
        completion = provider.complete(request)
        first_error: str | None = None
    except ProviderError as exc:
        first_error = str(exc)
        completion = provider.complete(request)
    if isinstance(completion, ProviderCompletion):
        if first_error is None:
            return completion
        metadata = dict(completion.metadata)
        metadata["transport_retry"] = {"attempts": 2, "first_error": first_error}
        return ProviderCompletion(completion.output, metadata)
    if isinstance(completion, dict):
        metadata = {"transport_retry": {"attempts": 2, "first_error": first_error}} if first_error else {}
        return ProviderCompletion(completion, metadata)
    raise ProviderError("provider returned neither an object nor ProviderCompletion")


def run_bare_record(record: dict[str, Any], provider: SemanticProvider) -> dict[str, Any]:
    case_id = record.get("_case_id")
    entry_id = record.get("entry_id")
    result: dict[str, Any] = {
        "case_id": case_id,
        "entry_id": entry_id,
        "provider": provider.name,
        "status": "started",
        "baseline_prompt": BARE_RECORD_PROMPT.metadata(),
        "evidence_ids": ["candidate:record"],
    }
    started = time.perf_counter()
    request = build_bare_record_request(record)
    try:
        completion = _complete(provider, request)
    except ProviderError as exc:
        result.update(status="provider_error", error=str(exc), seconds=round(time.perf_counter() - started, 6))
        return result
    result["seconds"] = round(time.perf_counter() - started, 6)
    if completion.metadata:
        result["provider_metadata"] = completion.metadata
    raw = completion.output
    repaired, repairs = repair_derived_overall(raw)
    judgment = repaired if isinstance(repaired, dict) else raw
    validation = validate_semantic_output(judgment, {"candidate:record"})
    errors = list(validation.errors)
    if isinstance(judgment, dict):
        if judgment.get("case_id") != case_id:
            errors.append("case_id does not match the candidate record")
        if judgment.get("entry_id") != entry_id:
            errors.append("entry_id does not match the candidate record")
    if repairs:
        result["raw_output"] = raw
        result["repairs"] = list(repairs)
    result["judgment"] = judgment
    result["validation"] = {"valid": not errors, "errors": errors}
    if errors:
        result["first_output"] = judgment
        result["first_validation"] = {"valid": False, "errors": errors}
        retry_request = deepcopy(request)
        retry_request["task"] += "_contract_retry"
        retry_request["instructions"] = [
            *retry_request["instructions"],
            "The previous answer failed the local output contract. Return a complete corrected answer only.",
            "Use candidate:record as the only evidence reference.",
        ]
        retry_request["contract_retry"] = {
            "validation_errors": errors,
            "valid_evidence_ids": ["candidate:record"],
            "invalid_output": judgment,
        }
        retry_started = time.perf_counter()
        try:
            retry_completion = _complete(provider, retry_request)
        except ProviderError as exc:
            result.update(
                status="retry_provider_error",
                error=str(exc),
                retry_seconds=round(time.perf_counter() - retry_started, 6),
            )
            return result
        result["retry_seconds"] = round(time.perf_counter() - retry_started, 6)
        if retry_completion.metadata:
            result["retry_provider_metadata"] = retry_completion.metadata
        retry_raw = retry_completion.output
        retry_judgment, retry_repairs = repair_derived_overall(retry_raw)
        judgment = retry_judgment if isinstance(retry_judgment, dict) else retry_raw
        retry_validation = validate_semantic_output(judgment, {"candidate:record"})
        errors = list(retry_validation.errors)
        if isinstance(judgment, dict):
            if judgment.get("case_id") != case_id:
                errors.append("case_id does not match the candidate record")
            if judgment.get("entry_id") != entry_id:
                errors.append("entry_id does not match the candidate record")
        if retry_repairs:
            result["retry_raw_output"] = retry_raw
            result["retry_repairs"] = list(retry_repairs)
        result["judgment"] = judgment
        result["validation"] = {"valid": not errors, "errors": errors}
        result["contract_retry"] = True
        if errors:
            result["status"] = "contract_error"
            return result
    result.update(status="completed", final_judgment=judgment)
    return result
