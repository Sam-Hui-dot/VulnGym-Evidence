from __future__ import annotations

from copy import deepcopy
import time
from typing import Any

from .evidence import packet_evidence_ids
from .provider import ProviderCompletion, ProviderError
from .semantic_contract import (
    ContractValidation,
    SEMANTIC_FIELDS,
    SemanticProvider,
    build_critic_request,
    build_judge_request,
    repair_derived_overall,
    validate_semantic_output,
)


def _validation_dict(validation: Any) -> dict[str, Any]:
    return {"valid": validation.valid, "errors": list(validation.errors)}


def _validate_for_packet(value: Any, evidence_ids: set[str], packet: dict[str, Any]) -> ContractValidation:
    validation = validate_semantic_output(value, evidence_ids)
    errors = list(validation.errors)
    if isinstance(value, dict):
        if value.get("case_id") != packet.get("case_id"):
            errors.append("case_id does not match the evidence packet")
        if value.get("entry_id") != packet.get("entry_id"):
            errors.append("entry_id does not match the evidence packet")
    return ContractValidation(not errors, tuple(errors))


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


def _validated_output(
    value: dict[str, Any],
    evidence_ids: set[str],
    packet: dict[str, Any],
) -> tuple[dict[str, Any], ContractValidation, dict[str, Any] | None]:
    validation = _validate_for_packet(value, evidence_ids, packet)
    if not isinstance(value, dict):
        return value, validation, None
    repaired = deepcopy(value)
    repairs: list[str] = []
    for key in ("case_id", "entry_id"):
        expected = packet.get(key)
        if repaired.get(key) != expected:
            previous = repaired.get(key)
            repaired[key] = expected
            repairs.append(f"{key}: {previous!r} -> {expected!r} (copied from evidence packet)")
    repaired, overall_repairs = repair_derived_overall(repaired)
    repairs.extend(overall_repairs)
    if not repairs or not isinstance(repaired, dict):
        return value, validation, None
    repaired_validation = _validate_for_packet(repaired, evidence_ids, packet)
    if not repaired_validation.valid:
        return value, validation, None
    repair = {
        "repairs": repairs,
        "validation_before": _validation_dict(validation),
        "validation_after": _validation_dict(repaired_validation),
    }
    return repaired, repaired_validation, repair


def _contract_retry_request(
    original_request: dict[str, Any],
    invalid_output: dict[str, Any],
    validation: ContractValidation,
    evidence_ids: set[str],
) -> dict[str, Any]:
    request = deepcopy(original_request)
    request["task"] = str(original_request.get("task", "semantic")) + "_contract_retry"
    request["instructions"] = [
        *list(original_request.get("instructions", [])),
        "The previous answer failed the local output contract. Return a complete corrected answer; do not comment on the repair.",
        "Evidence references must be copied exactly from valid_evidence_ids.",
    ]
    request["contract_retry"] = {
        "validation_errors": list(validation.errors),
        "valid_evidence_ids": sorted(evidence_ids),
        "invalid_output": invalid_output,
    }
    return request


def reconcile_judge_critic(
    judgment: dict[str, Any],
    criticism: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Apply a transparent non-regression gate to Critic field changes.

    The Critic may override the Judge when it is at least as confident.  A
    lower-confidence disagreement is retained as review metadata but cannot
    silently replace the stronger field decision.
    """
    judge_fields = {
        item.get("field"): item
        for item in judgment.get("field_results", [])
        if isinstance(item, dict) and item.get("field") in SEMANTIC_FIELDS
    }
    final = deepcopy(criticism)
    decisions: list[dict[str, Any]] = []
    final_fields: list[dict[str, Any]] = []
    for critic_field in criticism.get("field_results", []):
        if not isinstance(critic_field, dict):
            final_fields.append(critic_field)
            continue
        field = critic_field.get("field")
        judge_field = judge_fields.get(field)
        chosen = critic_field
        if (
            isinstance(judge_field, dict)
            and judge_field.get("verdict") != critic_field.get("verdict")
            and float(critic_field.get("confidence", 0.0)) < float(judge_field.get("confidence", 0.0))
        ):
            chosen = judge_field
            decisions.append(
                {
                    "field": field,
                    "selected": "judge",
                    "reason": "critic disagreement had lower confidence",
                    "judge_verdict": judge_field.get("verdict"),
                    "judge_confidence": judge_field.get("confidence"),
                    "critic_verdict": critic_field.get("verdict"),
                    "critic_confidence": critic_field.get("confidence"),
                }
            )
        elif isinstance(judge_field, dict) and judge_field.get("verdict") != critic_field.get("verdict"):
            decisions.append(
                {
                    "field": field,
                    "selected": "critic",
                    "reason": "critic disagreement had equal or higher confidence",
                    "judge_verdict": judge_field.get("verdict"),
                    "judge_confidence": judge_field.get("confidence"),
                    "critic_verdict": critic_field.get("verdict"),
                    "critic_confidence": critic_field.get("confidence"),
                }
            )
        final_fields.append(deepcopy(chosen))
    final["field_results"] = final_fields
    verdicts = [item.get("verdict") for item in final_fields if isinstance(item, dict)]
    final["overall_verdict"] = (
        "incorrect" if "incorrect" in verdicts else "uncertain" if "uncertain" in verdicts else "correct"
    )
    confidences = [
        float(item.get("confidence"))
        for item in final_fields
        if isinstance(item, dict) and isinstance(item.get("confidence"), (int, float))
    ]
    if confidences:
        final["overall_confidence"] = min(confidences)
    return final, decisions


def _run_critic(
    packet: dict[str, Any],
    provider: SemanticProvider,
    judgment: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    critic_request = build_critic_request(packet, judgment)
    evidence_ids = packet_evidence_ids(critic_request["packet"])
    result["critic_prompt"] = critic_request["prompt_metadata"]
    critic_started = time.perf_counter()
    try:
        completion = _complete(provider, critic_request)
    except ProviderError as exc:
        result.update(status="critic_provider_error", error=str(exc), critic_seconds=round(time.perf_counter() - critic_started, 6))
        return result
    result["critic_seconds"] = round(time.perf_counter() - critic_started, 6)
    if completion.metadata:
        result["critic_provider_metadata"] = completion.metadata
    raw_criticism = completion.output
    criticism, critic_validation, repair = _validated_output(raw_criticism, evidence_ids, packet)
    if repair is not None:
        result["critic_raw_output"] = raw_criticism
        result["critic_repair"] = repair
    result["criticism"] = criticism
    result["critic_validation"] = _validation_dict(critic_validation)
    if not critic_validation.valid:
        result["critic_first_output"] = criticism
        result["critic_first_validation"] = _validation_dict(critic_validation)
        retry_started = time.perf_counter()
        try:
            retry_completion = _complete(
                provider,
                _contract_retry_request(critic_request, criticism, critic_validation, evidence_ids),
            )
        except ProviderError as exc:
            result.update(
                status="critic_retry_provider_error",
                error=str(exc),
                critic_retry_seconds=round(time.perf_counter() - retry_started, 6),
            )
            return result
        result["critic_retry_seconds"] = round(time.perf_counter() - retry_started, 6)
        if retry_completion.metadata:
            result["critic_retry_provider_metadata"] = retry_completion.metadata
        retry_raw = retry_completion.output
        criticism, critic_validation, retry_repair = _validated_output(retry_raw, evidence_ids, packet)
        if retry_repair is not None:
            result["critic_retry_raw_output"] = retry_raw
            result["critic_retry_repair"] = retry_repair
        result["criticism"] = criticism
        result["critic_validation"] = _validation_dict(critic_validation)
        result["critic_contract_retry"] = True
        if not critic_validation.valid:
            result["status"] = "critic_contract_error"
            return result
    final_judgment, arbitration = reconcile_judge_critic(judgment, criticism)
    final_validation = _validate_for_packet(final_judgment, evidence_ids, packet)
    if not final_validation.valid:
        result.update(status="arbitration_contract_error", arbitration_validation=_validation_dict(final_validation))
        return result
    if arbitration:
        result["arbitration"] = arbitration
    status = "completed_with_repair" if "judge_repair" in result or "critic_repair" in result else "completed"
    result.update(status=status, final_judgment=final_judgment)
    return result


def should_run_critic(judgment: dict[str, Any], policy: str) -> tuple[bool, str]:
    if policy == "always":
        return True, "policy requires Critic for every completed Judge"
    if policy == "never":
        return False, "policy disables Critic"
    if policy != "review-risk":
        raise ValueError(f"unknown critic policy: {policy}")
    if judgment.get("overall_verdict") == "correct":
        return True, "Critic checks a whole-record acceptance for missed counterevidence"
    for item in judgment.get("field_results", []):
        if not isinstance(item, dict) or item.get("verdict") != "incorrect":
            continue
        confidence = item.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and confidence < 0.85:
            return True, "Critic reviews a low-confidence rejection"
    return False, "Judge already found high-confidence errors or only evidence-limited uncertainty"


def run_judge_critic(
    packet: dict[str, Any],
    provider: SemanticProvider,
    *,
    use_critic: bool = True,
    critic_policy: str | None = None,
) -> dict[str, Any]:
    judge_request = build_judge_request(packet)
    evidence_ids = packet_evidence_ids(judge_request["packet"])
    result: dict[str, Any] = {
        "case_id": packet.get("case_id"),
        "entry_id": packet.get("entry_id"),
        "provider": provider.name,
        "status": "started",
        "evidence_ids": sorted(evidence_ids),
    }
    result["judge_prompt"] = judge_request["prompt_metadata"]
    judge_started = time.perf_counter()
    try:
        completion = _complete(provider, judge_request)
    except ProviderError as exc:
        result.update(status="judge_provider_error", error=str(exc), judge_seconds=round(time.perf_counter() - judge_started, 6))
        return result
    result["judge_seconds"] = round(time.perf_counter() - judge_started, 6)
    if completion.metadata:
        result["judge_provider_metadata"] = completion.metadata
    raw_judgment = completion.output
    judgment, judge_validation, repair = _validated_output(raw_judgment, evidence_ids, packet)
    if repair is not None:
        result["judge_raw_output"] = raw_judgment
        result["judge_repair"] = repair
    result["judgment"] = judgment
    result["judge_validation"] = _validation_dict(judge_validation)
    if not judge_validation.valid:
        result["judge_first_output"] = judgment
        result["judge_first_validation"] = _validation_dict(judge_validation)
        retry_started = time.perf_counter()
        try:
            retry_completion = _complete(
                provider,
                _contract_retry_request(judge_request, judgment, judge_validation, evidence_ids),
            )
        except ProviderError as exc:
            result.update(
                status="judge_retry_provider_error",
                error=str(exc),
                judge_retry_seconds=round(time.perf_counter() - retry_started, 6),
            )
            return result
        result["judge_retry_seconds"] = round(time.perf_counter() - retry_started, 6)
        if retry_completion.metadata:
            result["judge_retry_provider_metadata"] = retry_completion.metadata
        retry_raw = retry_completion.output
        judgment, judge_validation, retry_repair = _validated_output(retry_raw, evidence_ids, packet)
        if retry_repair is not None:
            result["judge_retry_raw_output"] = retry_raw
            result["judge_retry_repair"] = retry_repair
        result["judgment"] = judgment
        result["judge_validation"] = _validation_dict(judge_validation)
        result["judge_contract_retry"] = True
        if not judge_validation.valid:
            result["status"] = "judge_contract_error"
            return result
    policy = critic_policy or ("always" if use_critic else "never")
    run_critic, critic_reason = should_run_critic(judgment, policy)
    result["critic_decision"] = {"policy": policy, "run": run_critic, "reason": critic_reason}
    if not run_critic:
        status = "completed_without_critic_with_repair" if "judge_repair" in result else "completed_without_critic"
        result.update(status=status, final_judgment=judgment)
        return result
    return _run_critic(packet, provider, judgment, result)


def run_critic_from_judgment(
    packet: dict[str, Any],
    provider: SemanticProvider,
    judgment: dict[str, Any],
    *,
    prior_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_ids = packet_evidence_ids(build_judge_request(packet)["packet"])
    validation = _validate_for_packet(judgment, evidence_ids, packet)
    result: dict[str, Any] = {
        "case_id": packet.get("case_id"),
        "entry_id": packet.get("entry_id"),
        "provider": provider.name,
        "status": "started",
        "judge_source": "existing_result",
        "evidence_ids": sorted(evidence_ids),
        "judgment": judgment,
        "judge_validation": _validation_dict(validation),
    }
    if prior_result:
        for key in ("judge_seconds", "judge_provider_metadata", "judge_prompt"):
            if key in prior_result:
                result[key] = prior_result[key]
    if not validation.valid:
        result["status"] = "existing_judge_contract_error"
        return result
    return _run_critic(packet, provider, judgment, result)


def repair_persisted_result(packet: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(row)
    evidence_ids = packet_evidence_ids(packet)
    if result.get("status") == "judge_contract_error" and isinstance(result.get("judgment"), dict):
        repaired, validation, repair = _validated_output(result["judgment"], evidence_ids, packet)
        if repair is not None and validation.valid:
            result["judge_raw_output"] = result["judgment"]
            result["judgment"] = repaired
            result["judge_repair"] = repair
            result["judge_validation"] = _validation_dict(validation)
            result["final_judgment"] = repaired
            result["status"] = "completed_without_critic_with_repair"
    if result.get("status") == "critic_contract_error" and isinstance(result.get("criticism"), dict):
        repaired, validation, repair = _validated_output(result["criticism"], evidence_ids, packet)
        if repair is not None and validation.valid:
            result["critic_raw_output"] = result["criticism"]
            result["criticism"] = repaired
            result["critic_repair"] = repair
            result["critic_validation"] = _validation_dict(validation)
            result["final_judgment"] = repaired
            result["status"] = "completed_with_repair"
    if isinstance(result.get("judgment"), dict) and isinstance(result.get("criticism"), dict):
        reconciled, arbitration = reconcile_judge_critic(result["judgment"], result["criticism"])
        validation = _validate_for_packet(reconciled, evidence_ids, packet)
        if validation.valid:
            result["final_judgment"] = reconciled
            if arbitration:
                result["arbitration"] = arbitration
            else:
                result.pop("arbitration", None)
    return result
