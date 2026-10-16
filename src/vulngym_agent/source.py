from __future__ import annotations

import re
from typing import Any

from .models import CheckResult, Evidence, Verdict
from .repository import ReadOnlyGitRepository, RepositoryError
from .schema import line_span


def _compact(value: str, limit: int = 360) -> str:
    value = value.replace("\r\n", "\n")
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _normalize_code(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _strip_trailing_annotation(line: str) -> str:
    """Remove an explanatory end-of-line comment without touching strings.

    VulnGym records sometimes append a natural-language annotation to a
    literal source line.  That annotation is evidence metadata, not a claim
    that the comment exists upstream, so it must not become a deterministic
    source mismatch.  Comment markers inside quoted strings remain intact.
    """
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote is not None:
            escaped = True
            continue
        if char in {"'", '"', "`"}:
            quote = None if quote == char else char if quote is None else quote
            continue
        if quote is not None:
            continue
        if char == "#" and index > 0 and line[index - 1].isspace():
            return line[:index].rstrip()
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            if index > 0 and line[index - 1].isspace():
                return line[:index].rstrip()
    return line.rstrip()


def _normalize_without_annotations(value: str) -> str:
    lines = value.replace("\r\n", "\n").split("\n")
    return _normalize_code("\n".join(_strip_trailing_annotation(line) for line in lines))


def _find_matches(lines: list[str], expected: str) -> list[tuple[int, int]]:
    expected_lines = expected.replace("\r\n", "\n").strip("\n").split("\n")
    width = max(1, len(expected_lines))
    expected_normalized = _normalize_without_annotations(expected)
    candidates: list[tuple[int, int]] = []
    for index in range(0, max(0, len(lines) - width + 1)):
        actual = "\n".join(lines[index : index + width])
        if _normalize_code(actual) == expected_normalized:
            start = index + 1
            candidates.append((start, start + width - 1))
    return candidates


def inspect_node(
    repository: ReadOnlyGitRepository,
    commit: str,
    node: Any,
    field: str,
) -> list[CheckResult]:
    if not isinstance(node, dict):
        return []
    file_path = node.get("file")
    span = line_span(node.get("line"))
    expected = node.get("code")
    if not isinstance(file_path, str) or span is None or not isinstance(expected, str) or not expected.strip():
        return []

    try:
        content = repository.read_file(commit, file_path)
    except RepositoryError as exc:
        return [
            CheckResult(
                field=f"{field}.source",
                verdict=Verdict.INCORRECT,
                confidence=0.99,
                reason="the declared file cannot be read at the vulnerable commit",
                evidence=(Evidence("git_show", f"{commit}:{file_path}", _compact(str(exc))),),
            )
        ]

    lines = content.splitlines()
    start, declared_end = span
    expected_lines = expected.replace("\r\n", "\n").strip("\n").split("\n")
    end = start + len(expected_lines) - 1 if start == declared_end else declared_end
    actual = "\n".join(lines[start - 1 : end]) if start <= len(lines) else ""

    if any(line.strip() == "..." for line in expected_lines):
        return [
            CheckResult(
                field=f"{field}.source_summary",
                verdict=Verdict.UNCERTAIN,
                confidence=0.9,
                reason="the declared code contains an ellipsis placeholder, so literal source identity is not deterministic",
                evidence=(
                    Evidence(
                        "source",
                        f"{file_path}:{start}-{end}",
                        f"match_status=summary_placeholder; declared={start}-{end}; observed={_compact(actual)}",
                    ),
                ),
            )
        ]

    if end <= len(lines) and _normalize_code(actual) == _normalize_code(expected):
        return [
            CheckResult(
                field=f"{field}.source",
                verdict=Verdict.CORRECT,
                confidence=0.99,
                reason="file, declared location, and code agree with the vulnerable commit",
                evidence=(Evidence("source", f"{file_path}:{start}-{end}", f"match_status=exact; {_compact(actual)}"),),
            )
        ]

    annotation_normalized = _normalize_without_annotations(expected)
    if end <= len(lines) and annotation_normalized == _normalize_code(actual):
        return [
            CheckResult(
                field=f"{field}.source",
                verdict=Verdict.CORRECT,
                confidence=0.98,
                reason="file, declared location, and source code agree after removing an explanatory inline annotation",
                evidence=(
                    Evidence(
                        "source",
                        f"{file_path}:{start}-{end}",
                        f"match_status=annotated_exact; {_compact(actual)}",
                    ),
                ),
            )
        ]

    if len(expected_lines) == 1 and start <= len(lines):
        actual_anchor = _normalize_code(lines[start - 1])
        if actual_anchor and annotation_normalized.startswith(actual_anchor):
            return [
                CheckResult(
                    field=f"{field}.source_content",
                    verdict=Verdict.UNCERTAIN,
                    confidence=0.85,
                    reason="the declared line is a compressed summary anchored at the correct source location and needs semantic review",
                    evidence=(
                        Evidence(
                            "source",
                            f"{file_path}:{start}-{end}",
                            f"match_status=anchored_summary; declared={start}-{end}; observed={_compact(actual)}",
                        ),
                    ),
                )
            ]

    if len(expected_lines) > 1 and start <= len(lines):
        expected_anchor = _normalize_code(expected_lines[0])
        actual_anchor = _normalize_code(lines[start - 1])
        if expected_anchor and expected_anchor == actual_anchor:
            return [
                CheckResult(
                    field=f"{field}.source_content",
                    verdict=Verdict.UNCERTAIN,
                    confidence=0.85,
                    reason="the declared start anchor exists, but the full multiline snippet differs and needs semantic review",
                    evidence=(
                        Evidence(
                            "source",
                            f"{file_path}:{start}-{end}",
                            f"match_status=anchored_summary; declared={start}-{end}; observed={_compact(actual)}",
                        ),
                    ),
                )
            ]

    matches = _find_matches(lines, expected)
    if len(matches) == 1:
        matched_start, matched_end = matches[0]
        return [
            CheckResult(
                field=f"{field}.source_location",
                verdict=Verdict.INCORRECT,
                confidence=0.98,
                reason="the code exists uniquely in the declared file, but the declared location does not identify it",
                evidence=(
                    Evidence(
                        "source_search",
                        file_path,
                        f"match_status=drifted; declared={start}-{end}; matched={matched_start}-{matched_end}; {_compact(expected)}",
                    ),
                ),
            )
        ]

    declared = f"declared={start}-{end}, file_lines={len(lines)}"
    if len(matches) > 1:
        locations = ", ".join(f"{candidate_start}-{candidate_end}" for candidate_start, candidate_end in matches[:20])
        return [
            CheckResult(
                field=f"{field}.source_location",
                verdict=Verdict.INCORRECT,
                confidence=0.98,
                reason="the declared location does not match, and the code has multiple candidate locations",
                evidence=(
                    Evidence(
                        "source_search",
                        file_path,
                        f"match_status=ambiguous; {declared}; candidates={locations}",
                    ),
                ),
            )
        ]

    observation = f"match_status=missing; {declared}; declared_content={_compact(actual)}"
    return [
        CheckResult(
            field=f"{field}.source",
            verdict=Verdict.INCORRECT,
            confidence=0.98,
            reason="the declared code does not match the location and cannot be found exactly in the file",
            evidence=(Evidence("source_search", f"{file_path}:{start}-{end}", observation),),
        )
    ]
