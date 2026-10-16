from __future__ import annotations

from collections import Counter
import json
import re
from typing import Any


SUBMISSION_FIELDS = (
    "entry_point",
    "critical_operation",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_title",
    "vuln_ids",
    "commit",
    "trace",
)

VERDICTS = {"correct", "incorrect", "uncertain"}


def _semantic_fields(result: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(result, dict):
        return {}
    judgment = result.get("final_judgment") or result.get("judgment")
    if not isinstance(judgment, dict) or not isinstance(judgment.get("field_results"), list):
        return {}
    fields: dict[str, dict[str, Any]] = {}
    for item in judgment["field_results"]:
        if not isinstance(item, dict):
            continue
        field = item.get("field")
        if field in SUBMISSION_FIELDS and item.get("verdict") in VERDICTS:
            fields[str(field)] = item
    return fields


def _deterministic_evidence(packet: dict[str, Any], field: str) -> list[dict[str, Any]]:
    audit = packet.get("deterministic_audit")
    if not isinstance(audit, dict) or not isinstance(audit.get("evidence"), list):
        return []

    def matches(candidate: str) -> bool:
        if field == "trace":
            return candidate.startswith("trace[")
        return candidate == field or candidate.startswith(field + ".")

    return [
        item
        for item in audit["evidence"]
        if isinstance(item, dict) and isinstance(item.get("field"), str) and matches(item["field"])
    ]


def _observation_text(items: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in items:
        reason = item.get("reason")
        evidence_id = item.get("evidence_id")
        if isinstance(reason, str) and reason:
            text = reason
            if isinstance(evidence_id, str) and evidence_id:
                text += f" [{evidence_id}]"
            parts.append(text)
    return "; ".join(dict.fromkeys(parts))


def _deterministic_correction(packet: dict[str, Any], field: str, items: list[dict[str, Any]]) -> str | None:
    """Return a correction only when deterministic evidence identifies it uniquely."""

    candidate = packet.get("candidate_record")
    if not isinstance(candidate, dict):
        return None
    matches: list[tuple[int, int]] = []
    for item in items:
        for evidence in item.get("evidence", []) if isinstance(item.get("evidence"), list) else []:
            if not isinstance(evidence, dict):
                continue
            observation = str(evidence.get("observation") or "")
            matched = re.search(r"(?:^|; )matched=(\d+)(?:-(\d+))?", observation)
            if matched:
                start = int(matched.group(1))
                end = int(matched.group(2) or matched.group(1))
                matches.append((start, end))
    unique = sorted(set(matches))
    if len(unique) != 1:
        return None
    start, end = unique[0]
    line: int | str = start if start == end else f"{start}-{end}"
    if field in {"entry_point", "critical_operation"} and isinstance(candidate.get(field), dict):
        corrected = dict(candidate[field])
        corrected["line"] = line
        return json.dumps(corrected, ensure_ascii=False, sort_keys=True)
    if field == "trace":
        return f"update the uniquely drifted trace node to line {line}; keep the remaining chain unchanged"
    return None


def _from_semantic(item: dict[str, Any]) -> dict[str, Any]:
    reason = str(item.get("reason") or "semantic judgment returned no reason")
    refs = item.get("evidence_refs")
    if isinstance(refs, list) and refs:
        reason += " Evidence: " + ", ".join(str(ref) for ref in refs)
    confidence = item.get("confidence", 0.0)
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        confidence = 0.0
    result = {
        "status": item["verdict"],
        "confidence": round(max(0.0, min(1.0, float(confidence))), 4),
        "evidence": reason,
    }
    correction = item.get("correction")
    if isinstance(correction, dict) and isinstance(correction.get("proposed_value"), str):
        proposed = correction["proposed_value"].strip()
        if proposed:
            result["suggested_correction"] = proposed
    return result


def _uncertain(field: str, deterministic: list[dict[str, Any]]) -> dict[str, Any]:
    observed = _observation_text(deterministic)
    if field in {"vuln_title", "vuln_ids"}:
        reason = "local advisory evidence has not yet been connected for this field"
    elif field == "commit":
        reason = (
            "the commit object exists, but identifying it as the vulnerable commit requires advisory or patch evidence"
            if deterministic
            else "commit identity could not be verified from advisory or patch evidence"
        )
    else:
        reason = "semantic evidence is unavailable; deterministic source existence alone cannot prove the field role"
    if observed:
        reason += "; deterministic checks: " + observed
    return {"status": "uncertain", "confidence": 0.0, "evidence": reason}


def _advisory_field(packet: dict[str, Any], field: str) -> dict[str, Any] | None:
    analysis = packet.get("advisory_analysis")
    documents = analysis.get("documents") if isinstance(analysis, dict) else None
    candidate = packet.get("candidate_record")
    if not isinstance(documents, list) or not documents or not isinstance(candidate, dict):
        return None
    refs = [item.get("evidence_id") for item in documents if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)]
    evidence = "Matched local advisory evidence: " + ", ".join(refs)
    if field == "vuln_ids":
        known = {identifier.upper() for item in documents if isinstance(item, dict) for identifier in item.get("identifiers", []) if isinstance(identifier, str)}
        claimed = {identifier.upper() for identifier in candidate.get("vuln_ids", []) if isinstance(identifier, str)}
        if claimed and claimed <= known:
            return {"status": "correct", "confidence": 0.97, "evidence": evidence}
        if claimed - known:
            return {"status": "incorrect", "confidence": 0.95, "evidence": evidence + "; unsupported identifiers: " + ", ".join(sorted(claimed - known))}
        if known and not claimed:
            return {"status": "incorrect", "confidence": 0.95, "evidence": evidence + "; candidate omits known vulnerability identifiers"}
    if field == "vuln_title":
        claimed_title = candidate.get("vuln_title")
        titles = [item.get("title") for item in documents if isinstance(item, dict) and isinstance(item.get("title"), str)]
        normalize = lambda value: " ".join(value.lower().split())
        if isinstance(claimed_title, str) and any(normalize(claimed_title) == normalize(title) for title in titles):
            return {"status": "correct", "confidence": 0.95, "evidence": evidence}
        # Non-identical wording is a semantic question. Let the Judge compare
        # product, weakness, impact and affected component using the advisory,
        # source and patch evidence instead of forcing an abstention here.
    if field == "commit":
        claimed_commit = candidate.get("commit")
        vulnerable = {commit for item in documents if isinstance(item, dict) for commit in item.get("vulnerable_commits", []) if isinstance(commit, str)}
        if isinstance(claimed_commit, str) and vulnerable:
            if any(claimed_commit.lower().startswith(commit) or commit.startswith(claimed_commit.lower()) for commit in vulnerable):
                return {"status": "correct", "confidence": 0.97, "evidence": evidence}
            return {"status": "incorrect", "confidence": 0.95, "evidence": evidence + "; candidate does not match explicitly declared vulnerable commits"}
    return None


def _patch_commit_field(packet: dict[str, Any]) -> dict[str, Any] | None:
    """Verify commit identity only from a selected, inspectable fix relation.

    Commit existence is necessary but not sufficient.  A selected patch adds
    independent support only when it names the candidate as the vulnerable
    side, names a fix, contains an inspectable diff, and passed the patch
    selector's confidence gate.  Weak automatic guesses remain uncertain.
    """

    candidate = packet.get("candidate_record")
    patch = packet.get("patch_analysis")
    if not isinstance(candidate, dict) or not isinstance(patch, dict):
        return None
    claimed = candidate.get("commit")
    vulnerable = patch.get("vulnerable_commit")
    if not isinstance(claimed, str) or not isinstance(vulnerable, str):
        return None
    if claimed.lower() != vulnerable.lower():
        return {
            "status": "incorrect",
            "confidence": 0.98,
            "evidence": "Patch provenance names a different vulnerable commit than the candidate.",
        }
    diff = patch.get("diff")
    if (
        patch.get("status") != "selected"
        or not isinstance(patch.get("selected_fix_commit"), str)
        or not isinstance(diff, str)
        or not diff.strip()
        or patch.get("provenance_status") != "verified"
    ):
        return None
    confidence = patch.get("selection_confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        confidence = 0.9
    basis = str(patch.get("provenance_basis") or "verified fix relation")
    return {
        "status": "correct",
        "confidence": round(min(0.94, max(0.8, float(confidence) - 0.05)), 4),
        "evidence": (
            "Patch provenance verifies the candidate as the vulnerable side of an inspectable "
            f"candidate-to-fix diff ({basis}) [patch:selected_diff]."
        ),
    }


def _field_report(
    packet: dict[str, Any],
    field: str,
    semantic: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    deterministic = _deterministic_evidence(packet, field)
    incorrect = [item for item in deterministic if item.get("verdict") == "incorrect"]
    if incorrect:
        confidence = max(
            (float(item.get("confidence", 0.0)) for item in incorrect if isinstance(item.get("confidence"), (int, float))),
            default=0.0,
        )
        result = {
            "status": "incorrect",
            "confidence": round(max(0.0, min(1.0, confidence)), 4),
            "evidence": _observation_text(incorrect) or "deterministic validation failed",
        }
        correction = _deterministic_correction(packet, field, incorrect)
        if correction is not None:
            result["suggested_correction"] = correction
        return result
    advisory = _advisory_field(packet, field)
    if advisory is not None:
        return advisory
    if field == "commit":
        patch_commit = _patch_commit_field(packet)
        if patch_commit is not None:
            return patch_commit
    if field in semantic:
        return _from_semantic(semantic[field])
    return _uncertain(field, deterministic)


def build_submission_report(
    packet: dict[str, Any],
    semantic_result: dict[str, Any] | None,
) -> dict[str, Any]:
    candidate = packet.get("candidate_record")
    if not isinstance(candidate, dict):
        candidate = {}
    semantic = _semantic_fields(semantic_result)
    fields = {field: _field_report(packet, field, semantic) for field in SUBMISSION_FIELDS}
    counts = Counter(item["status"] for item in fields.values())
    if counts["incorrect"]:
        verdict = "incorrect"
    elif counts["uncertain"]:
        verdict = "uncertain"
    else:
        verdict = "correct"
    summary = (
        f"overall {verdict}: {counts['correct']} correct, "
        f"{counts['incorrect']} incorrect, {counts['uncertain']} uncertain"
    )
    return {
        "case_id": packet.get("case_id") or candidate.get("_case_id"),
        "entry_id": packet.get("entry_id") or candidate.get("entry_id"),
        "report_id": packet.get("report_id") or candidate.get("report_id"),
        "verdict": verdict,
        "fields": fields,
        "summary": summary,
    }


def validate_submission_report(report: Any) -> list[str]:
    if not isinstance(report, dict):
        return ["report must be an object"]
    errors: list[str] = []
    for identity in ("entry_id", "report_id"):
        if not isinstance(report.get(identity), str) or not report[identity]:
            errors.append(f"{identity} must be a non-empty string")
    if report.get("verdict") not in VERDICTS:
        errors.append("verdict must be correct, incorrect, or uncertain")
    fields = report.get("fields")
    if not isinstance(fields, dict):
        errors.append("fields must be an object")
        return errors
    if set(fields) != set(SUBMISSION_FIELDS):
        errors.append("fields must contain exactly the current submission fields")
    for field in SUBMISSION_FIELDS:
        item = fields.get(field)
        if not isinstance(item, dict):
            errors.append(f"fields.{field} must be an object")
            continue
        if item.get("status") not in VERDICTS:
            errors.append(f"fields.{field}.status is invalid")
        confidence = item.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            errors.append(f"fields.{field}.confidence must be between 0 and 1")
        if not isinstance(item.get("evidence"), str) or not item["evidence"].strip():
            errors.append(f"fields.{field}.evidence must be a non-empty string")
    if not isinstance(report.get("summary"), str) or not report["summary"].strip():
        errors.append("summary must be a non-empty string")
    expected = (
        "incorrect"
        if any(item.get("status") == "incorrect" for item in fields.values() if isinstance(item, dict))
        else "uncertain"
        if any(item.get("status") == "uncertain" for item in fields.values() if isinstance(item, dict))
        else "correct"
    )
    if report.get("verdict") != expected:
        errors.append(f"verdict must be {expected} given fields")
    return errors
