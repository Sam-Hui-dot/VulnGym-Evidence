"""Bounded source excerpts for Go structs, not a compiler or type checker.

Only follows imports within the root go.mod module and one level of local
struct fields. Duplicate definitions/build variants are kept unresolved.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any

from vulngym_agent.repository import ReadOnlyGitRepository, RepositoryError, normalize_repo_path


TOKENS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _mask(text: str) -> str:
    return TOKENS.sub(lambda match: "".join("\n" if ch == "\n" else " " for ch in match[0]), text)


def _imports(text: str, module: str) -> dict[str, str]:
    # Locate real import statements with strings/comments masked, then read paths.
    masked = _mask(text)
    result = {}
    for match in re.finditer(r'\bimport\b[^\S\n]*(?:\([^)]*\)|[^\n]*)', masked):
        block = text[match.start() + len("import"):match.end()]
        for alias, path in re.findall(r'(?:([\w.]+)\s+)?"([^"\n]+)"', block):
            if not path.startswith(module + "/") or alias in {"_", "."}:
                continue
            try:
                result[alias or path.rsplit("/", 1)[-1]] = normalize_repo_path(path[len(module) + 1:])
            except RepositoryError:
                continue
    return result


def collect_go_types(repo: ReadOnlyGitRepository, commit: str,
                     contexts: list[dict[str, Any]], claim_id: str) -> list[dict[str, Any]]:
    try:
        module_match = re.search(r'^\s*module\s+(\S+)', repo.read_file(commit, "go.mod"), re.M)
        if not module_match:
            return []
        module = module_match[1].strip('"')
        files = repo.list_files(commit)
    except RepositoryError:
        return []
    cache: dict[str, str] = {}
    def read(path: str) -> str:
        if path not in cache:
            cache[path] = repo.read_file(commit, path)
        return cache[path]
    queue = []
    for context in contexts:
        path = context.get("file", "")
        if not path.endswith(".go") or context.get("status") != "available":
            continue
        try:
            imports = _imports(read(path), module)
        except RepositoryError:
            continue
        snippet = _mask(context.get("numbered_source", ""))
        for alias, name in re.findall(r'\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)', snippet):
            if alias in imports:
                queue.append((imports[alias], name, 0))
    seen, packets = set(), []
    scanned = 0
    while queue and len(seen) < 12 and len(packets) < 6:
        folder, name, depth = queue.pop(0)
        if (folder, name) in seen:
            continue
        seen.add((folder, name))
        candidates = sorted(path for path in files if path.endswith(".go")
                            and not path.endswith("_test.go") and str(PurePosixPath(path).parent) == folder)
        if not candidates:
            continue
        base = {"evidence_id": f"{claim_id}:type:{folder}:{name}", "kind": "source_type",
                "type_name": name, "package_path": folder, "commit": commit,
                "scope": "root-module Go struct excerpts; one-level field expansion; build constraints unresolved"}
        new_reads = sum(path not in cache for path in candidates)
        if len(candidates) > 32 or scanned + new_reads > 48:
            packets.append({**base, "status": "missing", "reason": "类型所在包超过本次读取预算，未确认唯一定义"})
            continue
        scanned += new_reads
        definitions = []
        failed = False
        for path in candidates:
            try:
                text = read(path)
            except RepositoryError:
                failed = True
                continue
            masked = _mask(text)
            for match in re.finditer(r'\btype\s+' + re.escape(name) + r'\s+struct\s*\{', masked):
                definitions.append((path, text, masked, match))
        if not definitions:
            continue
        if failed or len(definitions) != 1:
            packets.append({**base, "status": "missing", "reason": "定义不唯一或包文件读取不完整，不推断实际编译版本"})
            continue
        path, text, masked, match = definitions[0]
        start = text.count("\n", 0, match.start()) + 1
        balance, finish = 1, match.end()
        while finish < len(masked) and balance:
            balance += (masked[finish] == "{") - (masked[finish] == "}")
            finish += 1
        end = text.count("\n", 0, finish) + 1
        if balance or end - start >= 100:
            packets.append({**base, "status": "missing", "file": path,
                            "reason": "结构体范围无法完整读取或超过 100 行，不补猜缺失字段"})
            continue
        lines = text.splitlines()
        packets.append({**base, "status": "available", "file": path, "context_range": f"{start}-{end}",
                        "numbered_source": "\n".join(f"{i:6d} | {lines[i - 1]}" for i in range(start, end + 1))})
        if depth == 0:
            body = masked[match.end():finish - 1]
            # Named fields only; embedded types/generics are deliberately not resolved.
            nested_types = []
            for nested in re.findall(r'^\s*\w+\s+\*?([A-Za-z_]\w*)\s*$', body, re.M):
                if nested not in {"string", "bool", "byte", "rune", "int", "int8", "int16", "int32", "int64",
                                  "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "float32", "float64",
                                  "complex64", "complex128", "any", "error"}:
                    nested_types.append((folder, nested, 1))
            # Finish the declared type's field evidence before unrelated calls
            # in the surrounding source consume the candidate budget.
            queue[0:0] = nested_types
    return packets
