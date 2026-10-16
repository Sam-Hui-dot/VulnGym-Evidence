from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import posixpath
import re
from typing import Any, Iterable

from .advisory import advisory_evidence
from .engine import AuditEngine
from .lifecycle_inspector import inspect_critical_lifecycle
from .models import Verdict
from .patch_inspector import inspect_patch
from .repository import ReadOnlyGitRepository, RepositoryError
from .repository_index import RepositoryResolution, RepositoryResolver
from .schema import line_span
from .taxonomy import taxonomy_evidence
from .trace_inspector import inspect_trace


PACKET_VERSION = "0.11.0"
CRITICAL_FORWARD_CONTEXT_LINES = 40
HELPER_CONTEXT_LIMIT = 6
HELPER_FILE_LIMIT = 24
HELPER_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}
CALL_NAME_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
RELATIVE_MODULE_RE = re.compile(r"(?:from\s+|require\(\s*)[\"'](\.{1,2}/[^\"']+)[\"']")
PYTHON_MODULE_RE = re.compile(r"^\s*from\s+([.A-Za-z_][.A-Za-z0-9_]*)\s+import\s+", re.MULTILINE)
HELPER_DEFINITION_TEMPLATES = (
    r"^\s*(?:export\s+)?(?:async\s+)?function\s+{name}\s*\(",
    r"^\s*(?:const|let|var)\s+{name}\s*=\s*(?:async\s*)?\(",
    r"^\s*(?:async\s+)?def\s+{name}\s*\(",
    r"^\s*func\s+(?:\([^)]*\)\s*)?{name}\s*\(",
)
IGNORED_CALL_NAMES = {
    "if", "for", "while", "switch", "catch", "return", "throw", "new",
    "print", "len", "str", "int", "bool", "list", "dict", "set", "tuple",
}


def load_fix_map(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(isinstance(key, str) and isinstance(commit, str) for key, commit in value.items()):
        raise ValueError("fix map must be a JSON object of entry_id/report_id -> commit SHA")
    return value


def _node_context(
    repository: ReadOnlyGitRepository,
    commit: str,
    field: str,
    node: Any,
    *,
    context_lines: int,
    after_context_lines: int | None = None,
) -> dict[str, Any]:
    evidence_id = "source:" + field.replace("[", ":").replace("]", "")
    if not isinstance(node, dict):
        return {"evidence_id": evidence_id, "field": field, "status": "invalid_node"}
    file_path = node.get("file")
    span = line_span(node.get("line"))
    if not isinstance(file_path, str) or span is None:
        return {"evidence_id": evidence_id, "field": field, "status": "invalid_location"}
    try:
        content = repository.read_file(commit, file_path)
    except RepositoryError as exc:
        return {
            "evidence_id": evidence_id,
            "field": field,
            "status": "missing",
            "file": file_path,
            "line": node.get("line"),
            "error": str(exc),
        }

    lines = content.splitlines()
    start, end = span
    context_after = context_lines if after_context_lines is None else after_context_lines
    context_start = max(1, start - context_lines)
    context_end = min(len(lines), end + context_after)
    numbered = [f"{number:6d} | {lines[number - 1]}" for number in range(context_start, context_end + 1)]
    return {
        "evidence_id": evidence_id,
        "field": field,
        "status": "available",
        "commit": commit,
        "file": file_path,
        "declared_line": node.get("line"),
        "declared_code": node.get("code"),
        "context_range": f"{context_start}-{context_end}",
        "context_before_lines": context_lines,
        "context_after_lines": context_after,
        "numbered_source": "\n".join(numbered),
    }


def _deterministic_evidence(audit: dict[str, Any]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for index, check in enumerate(audit.get("checks", [])):
        evidence = check.get("evidence", [])
        if any(item.get("tool") == "semantic_judge" for item in evidence if isinstance(item, dict)):
            continue
        is_schema_success = check.get("verdict") == Verdict.CORRECT.value and all(
            item.get("tool") == "schema" for item in evidence if isinstance(item, dict)
        )
        if is_schema_success:
            continue
        selected.append(
            {
                "evidence_id": f"deterministic:{index}",
                "field": check.get("field"),
                "verdict": check.get("verdict"),
                "confidence": check.get("confidence"),
                "reason": check.get("reason"),
                "observations": evidence,
            }
        )
    return selected


def _definition_matches(lines: list[str], name: str) -> list[int]:
    patterns = [re.compile(template.format(name=re.escape(name))) for template in HELPER_DEFINITION_TEMPLATES]
    return [index for index, line in enumerate(lines) if any(pattern.search(line) for pattern in patterns)]


def _helper_item(
    *,
    name: str,
    file_path: str,
    lines: list[str],
    definition_index: int,
    commit: str,
    context_lines: int,
    scope: str,
) -> dict[str, Any]:
    start = max(0, definition_index - 2)
    end = min(len(lines), definition_index + max(12, context_lines) + 1)
    numbered = [f"{number + 1:6d} | {lines[number]}" for number in range(start, end)]
    return {
        "evidence_id": f"source:helper:{scope}:{name}:{definition_index + 1}",
        "status": "available",
        "helper": name,
        "scope": scope,
        "commit": commit,
        "file": file_path,
        "definition_line": definition_index + 1,
        "context_range": f"{start + 1}-{end}",
        "numbered_source": "\n".join(numbered),
        "resolution": f"direct call with one {scope.replace('_', '-')} definition",
    }


def _module_candidate_files(file_path: str, source: str, tree_files: list[str]) -> list[str]:
    """Return a bounded one-hop file scope from same-directory and static imports."""
    source_path = PurePosixPath(file_path)
    parent = source_path.parent.as_posix()
    candidates = {
        item for item in tree_files
        if item != file_path
        and PurePosixPath(item).suffix in HELPER_SOURCE_SUFFIXES
        and PurePosixPath(item).parent.as_posix() == parent
    }
    module_stems: set[str] = set()
    for module in RELATIVE_MODULE_RE.findall(source):
        module_stems.add(posixpath.normpath(posixpath.join(parent, module)))
    for module in PYTHON_MODULE_RE.findall(source):
        leading = len(module) - len(module.lstrip("."))
        clean = module.lstrip(".").replace(".", "/")
        if leading:
            base = parent
            for _ in range(max(0, leading - 1)):
                base = posixpath.dirname(base)
            module_stems.add(posixpath.normpath(posixpath.join(base, clean)))
        else:
            module_stems.add(clean)
    for item in tree_files:
        suffix = PurePosixPath(item).suffix
        if suffix not in HELPER_SOURCE_SUFFIXES:
            continue
        stem = item[: -len(suffix)] if suffix else item
        if stem in module_stems:
            candidates.add(item)
        if any(stem == posixpath.join(module, "index") for module in module_stems):
            candidates.add(item)
    return sorted(candidates)[:HELPER_FILE_LIMIT]


def _helper_contexts(
    repository: ReadOnlyGitRepository,
    commit: str,
    source_contexts: list[dict[str, Any]],
    *,
    context_lines: int,
) -> list[dict[str, Any]]:
    """Resolve directly called helpers locally or across one bounded file hop.

    This deliberately bounded pass is not a call graph. It exposes nearby
    authorization/validation helpers that would otherwise remain opaque to the
    semantic judge, while avoiding repository-wide search and target execution.
    """
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    tree_files = repository.list_files(commit)
    for context in source_contexts:
        if context.get("status") != "available" or len(results) >= HELPER_CONTEXT_LIMIT:
            continue
        file_path = context.get("file")
        context_range = context.get("context_range")
        if not isinstance(file_path, str) or not isinstance(context_range, str) or "-" not in context_range:
            continue
        try:
            range_start, range_end = (int(value) for value in context_range.split("-", 1))
            content = repository.read_file(commit, file_path)
        except (RepositoryError, ValueError):
            continue
        lines = content.splitlines()
        visible = "\n".join(lines[max(0, range_start - 1) : min(len(lines), range_end)])
        for name in CALL_NAME_RE.findall(visible):
            key = (file_path, name)
            if name in IGNORED_CALL_NAMES or key in seen:
                continue
            seen.add(key)
            matches = _definition_matches(lines, name)
            if len(matches) != 1:
                continue
            definition_index = matches[0]
            results.append(_helper_item(name=name, file_path=file_path, lines=lines, definition_index=definition_index,
                                        commit=commit, context_lines=context_lines, scope="same_file"))
            if len(results) >= HELPER_CONTEXT_LIMIT:
                break
        if len(results) >= HELPER_CONTEXT_LIMIT:
            break
        local_names = {item["helper"] for item in results if item["file"] == file_path}
        candidate_files = _module_candidate_files(file_path, content, tree_files)
        candidate_sources: dict[str, list[str]] = {}
        for candidate_file in candidate_files:
            try:
                candidate_sources[candidate_file] = repository.read_file(commit, candidate_file).splitlines()
            except RepositoryError:
                continue
        for name in CALL_NAME_RE.findall(visible):
            if name in IGNORED_CALL_NAMES or name in local_names or len(results) >= HELPER_CONTEXT_LIMIT:
                continue
            definitions = [
                (candidate_file, matches[0], candidate_lines)
                for candidate_file, candidate_lines in candidate_sources.items()
                if len(matches := _definition_matches(candidate_lines, name)) == 1
            ]
            if len(definitions) != 1:
                continue
            candidate_file, definition_index, candidate_lines = definitions[0]
            results.append(_helper_item(name=name, file_path=candidate_file, lines=candidate_lines,
                                        definition_index=definition_index, commit=commit,
                                        context_lines=context_lines, scope="cross_file_one_hop"))
    return results


def build_evidence_packet(
    record: dict[str, Any],
    *,
    resolution: RepositoryResolution,
    context_lines: int = 12,
    explicit_fix_commit: str | None = None,
    advisory_documents: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    if context_lines < 0 or context_lines > 100:
        raise ValueError("context_lines must be between 0 and 100")
    repository = ReadOnlyGitRepository(resolution.path) if resolution.path else None
    audit = AuditEngine(resolution.path).audit(record).to_dict() if resolution.path else AuditEngine().audit(record).to_dict()
    advisory_analysis = advisory_evidence(record, advisory_documents)
    contexts: list[dict[str, Any]] = []
    helper_contexts: list[dict[str, Any]] = []
    patch: dict[str, Any] = {"status": "unavailable", "reason": "local repository is unresolved", "candidates": []}
    trace_analysis: dict[str, Any] = {"status": "unavailable", "contexts": [], "edges": [], "summary": {"nodes": 0, "edges": 0}}
    lifecycle_analysis: dict[str, Any] = {
        "evidence_id": "lifecycle:critical_operation",
        "status": "unavailable",
        "reason": "local repository is unresolved",
    }
    if repository and isinstance(record.get("commit"), str) and repository.has_commit(record["commit"]):
        contexts.append(
            _node_context(repository, record["commit"], "entry_point", record.get("entry_point"), context_lines=context_lines)
        )
        contexts.append(
            _node_context(
                repository,
                record["commit"],
                "critical_operation",
                record.get("critical_operation"),
                context_lines=context_lines,
                after_context_lines=(
                    max(context_lines, CRITICAL_FORWARD_CONTEXT_LINES)
                    if context_lines > 0
                    else 0
                ),
            )
        )
        trace = record.get("trace")
        if isinstance(trace, list):
            for index, node in enumerate(trace[:16]):
                contexts.append(
                    _node_context(repository, record["commit"], f"trace[{index}]", node, context_lines=context_lines)
                )
            trace_analysis = inspect_trace(repository, record["commit"], trace)
        lifecycle_analysis = inspect_critical_lifecycle(
            repository,
            record["commit"],
            record.get("critical_operation"),
        )
        patch = inspect_patch(
            repository,
            record,
            explicit_fix_commit=explicit_fix_commit,
            advisory_documents=advisory_analysis.get("documents", []),
        )
        if patch.get("diff"):
            patch["evidence_id"] = "patch:selected_diff"
        helper_contexts = _helper_contexts(
            repository,
            record["commit"],
            contexts,
            context_lines=context_lines,
        )

    packet = {
        "packet_version": PACKET_VERSION,
        "case_id": record.get("_case_id"),
        "entry_id": record.get("entry_id"),
        "report_id": record.get("report_id"),
        "candidate_record": record,
        "repository": resolution.to_dict(),
        "deterministic_audit": {
            "overall_verdict": audit["overall_verdict"],
            "confidence": audit["confidence"],
            "summary": audit["summary"],
            "evidence": _deterministic_evidence(audit),
        },
        "source_contexts": contexts,
        "helper_contexts": helper_contexts,
        "patch_analysis": patch,
        "trace_analysis": trace_analysis,
        "lifecycle_analysis": lifecycle_analysis,
        "advisory_analysis": advisory_analysis,
        "taxonomy_analysis": taxonomy_evidence(record, advisory_analysis.get("documents", [])),
        "evidence_policy": {
            "allowed_sources": ["deterministic_audit.evidence", "source_contexts", "helper_contexts", "patch_analysis.diff", "trace_analysis.contexts", "trace_analysis.edges", "lifecycle_analysis", "advisory_analysis.documents", "taxonomy_analysis.documents"],
            "missing_or_ambiguous_policy": "uncertain",
            "never_execute_target_repository_code": True,
        },
    }
    return packet


def packet_evidence_ids(packet: dict[str, Any]) -> set[str]:
    evidence_ids = {
        item["evidence_id"]
        for item in packet.get("deterministic_audit", {}).get("evidence", [])
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    }
    evidence_ids.update(
        item["evidence_id"]
        for item in packet.get("source_contexts", [])
        if isinstance(item, dict) and item.get("status") == "available" and isinstance(item.get("evidence_id"), str)
    )
    evidence_ids.update(
        item["evidence_id"]
        for item in packet.get("helper_contexts", [])
        if isinstance(item, dict) and item.get("status") == "available" and isinstance(item.get("evidence_id"), str)
    )
    patch = packet.get("patch_analysis", {})
    if isinstance(patch, dict) and patch.get("diff") and isinstance(patch.get("evidence_id"), str):
        evidence_ids.add(patch["evidence_id"])
    trace_analysis = packet.get("trace_analysis", {})
    if isinstance(trace_analysis, dict):
        evidence_ids.update(
            item["evidence_id"]
            for section in ("contexts", "edges")
            for item in trace_analysis.get(section, [])
            if isinstance(item, dict)
            and (section == "edges" or item.get("status") == "available")
            and isinstance(item.get("evidence_id"), str)
        )
    lifecycle = packet.get("lifecycle_analysis", {})
    if (
        isinstance(lifecycle, dict)
        and lifecycle.get("status") == "available"
        and isinstance(lifecycle.get("evidence_id"), str)
    ):
        evidence_ids.add(lifecycle["evidence_id"])
    evidence_ids.update(
        item["evidence_id"]
        for item in packet.get("advisory_analysis", {}).get("documents", [])
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    )
    evidence_ids.update(
        item["evidence_id"]
        for item in packet.get("taxonomy_analysis", {}).get("documents", [])
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    )
    return evidence_ids


def prepare_evidence_packets(
    records: Iterable[dict[str, Any]],
    *,
    resolver: RepositoryResolver,
    explicit_repository: Path | None = None,
    fix_map: dict[str, str] | None = None,
    context_lines: int = 12,
    advisory_documents: Iterable[dict[str, Any]] = (),
) -> Iterable[dict[str, Any]]:
    fixes = fix_map or {}
    explicit_resolution: RepositoryResolution | None = None
    if explicit_repository:
        repository = ReadOnlyGitRepository(explicit_repository)
        explicit_resolution = RepositoryResolution(
            repo_url="explicit",
            status="resolved_explicitly",
            path=repository.root,
            origin=repository.remote_origin(),
            reason="--repository applies to all input rows",
        )
    for record in records:
        resolution = explicit_resolution or resolver.resolve(record.get("repo_url", ""))
        fix_commit = fixes.get(str(record.get("entry_id"))) or fixes.get(str(record.get("report_id")))
        yield build_evidence_packet(
            record,
            resolution=resolution,
            context_lines=context_lines,
            explicit_fix_commit=fix_commit,
            advisory_documents=advisory_documents,
        )
