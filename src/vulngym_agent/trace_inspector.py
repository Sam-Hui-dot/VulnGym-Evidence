from __future__ import annotations

import re
from typing import Any

from .repository import ReadOnlyGitRepository, RepositoryError
from .schema import line_span


PYTHON_DECLARATION_RE = re.compile(r"^(?P<indent>\s*)(?:async\s+def|def|class)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
BRACE_DECLARATION_RES = (
    re.compile(r"^\s*func(?:\s+\([^)]*\))?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\("),
    re.compile(r"^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
)
CALL_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "return", "sizeof", "typeof"}


def _numbered(lines: list[str], start: int, end: int) -> str:
    return "\n".join(f"{number:6d} | {lines[number - 1]}" for number in range(start, end + 1))


def _python_region(lines: list[str], line_number: int, limit: int) -> tuple[int, int, str | None]:
    declaration_index: int | None = None
    declaration_indent = 0
    symbol: str | None = None
    for index in range(min(line_number - 1, len(lines) - 1), max(-1, line_number - 82), -1):
        match = PYTHON_DECLARATION_RE.match(lines[index])
        if match:
            declaration_index = index
            declaration_indent = len(match.group("indent").expandtabs(4))
            symbol = match.group("name")
            break
    if declaration_index is None:
        start = max(1, line_number - 20)
        return start, min(len(lines), start + limit - 1), None
    end_index = min(len(lines), declaration_index + limit)
    for index in range(declaration_index + 1, end_index):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(lines[index]) - len(lines[index].lstrip(" \t"))
        if indent <= declaration_indent:
            end_index = index
            break
    return declaration_index + 1, max(declaration_index + 1, end_index), symbol


def _brace_region(lines: list[str], line_number: int, limit: int) -> tuple[int, int, str | None]:
    declaration_index: int | None = None
    symbol: str | None = None
    for index in range(min(line_number - 1, len(lines) - 1), max(-1, line_number - 82), -1):
        match = next((pattern.match(lines[index]) for pattern in BRACE_DECLARATION_RES if pattern.match(lines[index])), None)
        signature = "\n".join(lines[index : min(len(lines), index + 8)])
        if match and match.group("name") not in CONTROL_WORDS and "{" in signature:
            declaration_index = index
            symbol = match.group("name")
            break
    if declaration_index is None:
        start = max(1, line_number - 20)
        return start, min(len(lines), start + limit - 1), None
    depth = 0
    seen_open = False
    end_index = min(len(lines), declaration_index + limit)
    for index in range(declaration_index, end_index):
        depth += lines[index].count("{") - lines[index].count("}")
        seen_open = seen_open or "{" in lines[index]
        if seen_open and depth <= 0:
            end_index = index + 1
            break
    return declaration_index + 1, max(declaration_index + 1, end_index), symbol


def _region(lines: list[str], file_path: str, line_number: int, limit: int) -> tuple[int, int, str | None]:
    if file_path.endswith(".py"):
        return _python_region(lines, line_number, limit)
    return _brace_region(lines, line_number, limit)


def _calls(text: str) -> set[str]:
    return {name for name in CALL_RE.findall(text) if name not in CONTROL_WORDS}


def inspect_trace(
    repository: ReadOnlyGitRepository,
    commit: str,
    trace: Any,
    *,
    max_nodes: int = 16,
    max_context_lines: int = 120,
) -> dict[str, Any]:
    if not isinstance(trace, list):
        return {"status": "invalid", "contexts": [], "edges": [], "summary": {"nodes": 0, "edges": 0}}
    contexts: list[dict[str, Any]] = []
    internal: list[dict[str, Any] | None] = []
    for index, node in enumerate(trace[:max_nodes]):
        evidence_id = f"trace_context:{index}"
        if not isinstance(node, dict) or not isinstance(node.get("file"), str) or line_span(node.get("line")) is None:
            contexts.append({"evidence_id": evidence_id, "trace_index": index, "status": "invalid_node"})
            internal.append(None)
            continue
        file_path = node["file"]
        start, end = line_span(node["line"]) or (0, 0)
        try:
            lines = repository.read_file(commit, file_path).splitlines()
        except RepositoryError as exc:
            contexts.append({"evidence_id": evidence_id, "trace_index": index, "status": "missing", "error": str(exc)})
            internal.append(None)
            continue
        region_start, region_end, symbol = _region(lines, file_path, start, max_context_lines)
        text = "\n".join(lines[region_start - 1 : region_end])
        context = {
            "evidence_id": evidence_id,
            "trace_index": index,
            "status": "available",
            "file": file_path,
            "declared_line": node["line"],
            "region_range": f"{region_start}-{region_end}",
            "enclosing_symbol": symbol,
            "calls": sorted(_calls(text))[:40],
            "numbered_source": _numbered(lines, region_start, region_end),
        }
        contexts.append(context)
        internal.append({**context, "start": start, "end": end, "text": text})

    edges: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    for index in range(max(0, len(internal) - 1)):
        source = internal[index]
        target = internal[index + 1]
        status = "unresolved"
        reason = "one or both trace nodes lack readable function context"
        symbols: list[str] = []
        if source is not None and target is not None:
            same_region = (
                source["file"] == target["file"]
                and source["region_range"] == target["region_range"]
            )
            if same_region:
                status = "same_function_order" if target["start"] >= source["start"] else "same_function_reverse"
                reason = "both nodes are in the same enclosing region; source order is consistent" if status == "same_function_order" else "both nodes are in the same enclosing region, but declared order is reversed"
            else:
                target_symbol = target.get("enclosing_symbol")
                source_calls = set(source.get("calls", []))
                if isinstance(target_symbol, str) and target_symbol in source_calls:
                    status = "direct_symbol_call"
                    symbols = [target_symbol]
                    reason = "the source enclosing region directly calls the target enclosing symbol"
                elif source["file"] == target["file"] and target["start"] >= source["start"]:
                    status = "same_file_order"
                    reason = "nodes occur in forward order in one file, but a direct call/data-flow edge is not proven"
                else:
                    reason = "expanded contexts do not prove a direct symbol call or same-function sequence"
        status_counts[status] = status_counts.get(status, 0) + 1
        edges.append(
            {
                "evidence_id": f"trace_edge:{index}-{index + 1}",
                "from_index": index,
                "to_index": index + 1,
                "status": status,
                "reason": reason,
                "symbols": symbols,
                "source_enclosing_symbol": source.get("enclosing_symbol") if source else None,
                "target_enclosing_symbol": target.get("enclosing_symbol") if target else None,
                "context_refs": [],
            }
        )
    expanded_indices = {
        trace_index
        for edge in edges
        if edge["status"] in {"unresolved", "same_function_reverse"}
        for trace_index in (edge["from_index"], edge["to_index"])
    }
    emitted_contexts = [context for context in contexts if context["trace_index"] in expanded_indices]
    emitted_ids = {context["evidence_id"] for context in emitted_contexts if context.get("status") == "available"}
    for edge in edges:
        edge["context_refs"] = [
            evidence_id
            for evidence_id in (f"trace_context:{edge['from_index']}", f"trace_context:{edge['to_index']}")
            if evidence_id in emitted_ids
        ]
    return {
        "status": "available",
        "contexts": emitted_contexts,
        "edges": edges,
        "summary": {
            "nodes": len(contexts),
            "expanded_contexts": len(emitted_contexts),
            "edges": len(edges),
            "edge_statuses": dict(sorted(status_counts.items())),
            "truncated_nodes": max(0, len(trace) - max_nodes),
        },
    }
