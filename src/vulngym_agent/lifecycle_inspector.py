from __future__ import annotations

import re
from typing import Any

from .repository import ReadOnlyGitRepository, RepositoryError
from .schema import line_span


CALL_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(")
DECLARATION_PREFIX_RE = re.compile(r"^\s*(?:func\b|async\s+def\b|def\b|function\b)")
CONSTRUCTOR_PREFIXES = ("new", "create", "build", "make", "construct")
ACTIVATION_NAMES = {
    "apply",
    "commit",
    "connect",
    "delete",
    "dispatch",
    "exec",
    "execute",
    "open",
    "publish",
    "remove",
    "run",
    "send",
    "start",
    "write",
}


def _basename(call: str) -> str:
    return call.rsplit(".", 1)[-1]


def inspect_critical_lifecycle(
    repository: ReadOnlyGitRepository,
    commit: str,
    node: Any,
    *,
    forward_lines: int = 120,
) -> dict[str, Any]:
    """Expose naming and nearby activation signals without deciding a verdict."""
    evidence_id = "lifecycle:critical_operation"
    if not isinstance(node, dict):
        return {"evidence_id": evidence_id, "status": "invalid_node"}
    file_path = node.get("file")
    span = line_span(node.get("line"))
    if not isinstance(file_path, str) or span is None:
        return {"evidence_id": evidence_id, "status": "invalid_location"}
    try:
        lines = repository.read_file(commit, file_path).splitlines()
    except RepositoryError as exc:
        return {
            "evidence_id": evidence_id,
            "status": "missing",
            "file": file_path,
            "line": node.get("line"),
            "error": str(exc),
        }

    start, end = span
    declared_text = "\n".join(lines[start - 1 : min(end, len(lines))])
    candidate_calls = sorted(set(CALL_RE.findall(declared_text)))
    constructor_like = [
        call
        for call in candidate_calls
        if _basename(call).lower().startswith(CONSTRUCTOR_PREFIXES)
    ]

    scan_end = min(len(lines), end + forward_lines)
    activation_calls: list[dict[str, Any]] = []
    for number in range(end + 1, scan_end + 1):
        text = lines[number - 1]
        if DECLARATION_PREFIX_RE.match(text):
            continue
        for call in CALL_RE.findall(text):
            if _basename(call).lower() in ACTIVATION_NAMES:
                activation_calls.append(
                    {"line": number, "call": call, "source": text.strip()}
                )
                if len(activation_calls) >= 12:
                    break
        if len(activation_calls) >= 12:
            break

    return {
        "evidence_id": evidence_id,
        "status": "available",
        "commit": commit,
        "file": file_path,
        "declared_line": node.get("line"),
        "candidate_calls": candidate_calls,
        "constructor_like_calls": constructor_like,
        "downstream_activation_calls": activation_calls,
        "scan_range": f"{end + 1}-{scan_end}" if end < scan_end else None,
        "interpretation": (
            "Naming and nearby-source signals only. A constructor-like call plus a later "
            "activation call is counterevidence to claiming the constructor itself performs "
            "the side effect, but is not by itself a final field verdict."
        ),
    }
