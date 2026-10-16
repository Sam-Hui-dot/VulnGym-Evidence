from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

from vulngym_agent.repository import RepositoryError, normalize_repo_path
from vulngym_agent.schema import line_span


KINDS = {"source_location", "entry_point", "critical_operation", "trace", "fix_commit"}
SHA = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class InputError(ValueError):
    pass


def _text(value: Any, name: str, *, limit: int, optional: bool = False) -> str:
    if optional and value is None:
        return ""
    if not isinstance(value, str) or (not optional and not value.strip()):
        raise InputError(f"{name} 必须是{'非空' if not optional else ''}字符串")
    if len(value) > limit or "\x00" in value:
        raise InputError(f"{name} 超过长度限制或含有空字符")
    return value if name.endswith((".code", ".origin.quote")) or name == "report_text" else value.strip()


def _sha(value: Any, name: str) -> str:
    result = _text(value, name, limit=40).lower()
    if not SHA.fullmatch(result):
        raise InputError(f"{name} 需要完整的 40 位 Commit SHA")
    return result


def _url(value: Any, name: str, *, optional: bool = False) -> str:
    result = _text(value, name, limit=1500, optional=optional)
    if not result and optional:
        return ""
    parsed = urlparse(result)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise InputError(f"{name} 需要不含凭据的 HTTPS 地址")
    return result


def _node(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {"file", "line", "code", "desc"}:
        raise InputError(f"{name} 只允许 file、line、code、desc")
    try:
        path = normalize_repo_path(_text(value.get("file"), f"{name}.file", limit=500))
    except RepositoryError as exc:
        raise InputError(f"{name}.file 必须是仓库内的相对路径") from exc
    span = line_span(value.get("line"))
    if span is None or span[1] - span[0] > 100 or span[1] > 1_000_000:
        raise InputError(f"{name}.line 需要行号或最多 101 行的范围")
    result = {"file": path, "line": value["line"],
              "code": _text(value.get("code"), f"{name}.code", limit=16000)}
    if "desc" in value:
        result["desc"] = _text(value["desc"], f"{name}.desc", limit=4000)
    return result


def validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError("输入必须是 JSON 对象")
    allowed = {"schema_version", "case_id", "repo_url", "reviewed_commit", "report_text",
               "source_link", "vuln_ids", "claims"}
    if set(value) - allowed:
        raise InputError("输入含有未支持的字段：" + ", ".join(sorted(set(value) - allowed)))
    if value.get("schema_version") != "1.0":
        raise InputError('schema_version 必须是 "1.0"')
    case_id = _text(value.get("case_id"), "case_id", limit=64)
    if not ID.fullmatch(case_id):
        raise InputError("case_id 只允许字母、数字、点、下划线和连字符")
    ids = value.get("vuln_ids", [])
    if not isinstance(ids, list) or len(ids) > 8:
        raise InputError("vuln_ids 必须是最多 8 项的列表")
    normalized_ids = []
    for identifier in ids:
        identifier = _text(identifier, "vuln_ids", limit=64).upper()
        if not IDENTIFIER.fullmatch(identifier):
            raise InputError("vuln_ids 只支持 CVE / GHSA 编号")
        if identifier not in normalized_ids:
            normalized_ids.append(identifier)
    claims = value.get("claims")
    if not isinstance(claims, list) or not 1 <= len(claims) <= 8:
        raise InputError("claims 必须包含 1–8 个明确声明")
    report_text = _text(value.get("report_text"), "report_text", limit=40000, optional=True)
    normalized_claims, seen = [], set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise InputError("每个声明必须是对象")
        claim_id = _text(claim.get("claim_id"), "claim_id", limit=64)
        if not ID.fullmatch(claim_id) or claim_id in seen:
            raise InputError("claim_id 必须合法且不能重复")
        seen.add(claim_id)
        kind = claim.get("kind")
        if not isinstance(kind, str) or kind not in KINDS:
            raise InputError("不支持的声明类型")
        permitted = {"claim_id", "kind", "text", "origin"} | (
            {"nodes"} if kind == "trace" else
            {"claimed_fix_commit"} if kind == "fix_commit" else {"node"}
        )
        if set(claim) - permitted:
            raise InputError(f"{claim_id} 含有不适用于该类型的字段")
        normalized = {"claim_id": claim_id, "kind": kind,
                      "text": _text(claim.get("text"), "text", limit=4000)}
        if "origin" in claim:
            origin = claim["origin"]
            if not isinstance(origin, dict) or set(origin) != {"quote", "start", "end"}:
                raise InputError(f"{claim_id}.origin 需要原文片段及位置")
            quote = _text(origin.get("quote"), f"{claim_id}.origin.quote", limit=2000)
            start, end = origin.get("start"), origin.get("end")
            if (type(start) is not int or type(end) is not int or
                    not 0 <= start < end <= len(report_text) or report_text[start:end] != quote):
                raise InputError(f"{claim_id}.origin 与当前报告原文不一致，请重新提取或移除定位")
            normalized["origin"] = {"quote": quote, "start": start, "end": end}
        if kind == "trace":
            nodes = claim.get("nodes")
            if not isinstance(nodes, list) or not 2 <= len(nodes) <= 8:
                raise InputError("调用链需要 2–8 个节点")
            normalized["nodes"] = [_node(node, f"nodes[{i}]") for i, node in enumerate(nodes)]
        elif kind == "fix_commit":
            normalized["claimed_fix_commit"] = _sha(claim.get("claimed_fix_commit"), "claimed_fix_commit")
        else:
            normalized["node"] = _node(claim.get("node"), "node")
        normalized_claims.append(normalized)
    return {
        "schema_version": "1.0", "case_id": case_id,
        "repo_url": _url(value.get("repo_url"), "repo_url"),
        "reviewed_commit": _sha(value.get("reviewed_commit"), "reviewed_commit"),
        "report_text": report_text,
        "source_link": _url(value.get("source_link"), "source_link", optional=True),
        "vuln_ids": normalized_ids, "claims": normalized_claims,
    }


def validate_repository_query(value: Any) -> dict[str, str]:
    """Validate the read-only repository check without constructing fake claims."""
    if not isinstance(value, dict) or set(value) != {"repo_url", "reviewed_commit"}:
        raise InputError("需要仓库地址与完整代码版本")
    return {"repo_url": _url(value["repo_url"], "repo_url"),
            "reviewed_commit": _sha(value["reviewed_commit"], "reviewed_commit")}


def import_t1(record: Any) -> dict[str, Any]:
    """Import only explicitly present, supported fields; do not invent claims."""
    if not isinstance(record, dict):
        raise InputError("T1 记录必须是对象")
    claims = []
    for field in ("entry_point", "critical_operation"):
        node = record.get(field)
        if isinstance(node, dict):
            claims.append({"claim_id": field, "kind": field,
                           "text": node.get("desc") or f"报告声明此处是 {field}",
                           "node": deepcopy(node)})
    if isinstance(record.get("trace"), list) and len(record["trace"]) >= 2:
        claims.append({"claim_id": "trace", "kind": "trace",
                       "text": "报告声称这些节点构成按顺序连接的漏洞调用链",
                       "nodes": deepcopy(record["trace"])})
    return validate_request({
        "schema_version": "1.0", "case_id": record.get("entry_id") or "imported-t1",
        "repo_url": record.get("repo_url"), "reviewed_commit": record.get("commit"),
        "report_text": record.get("vuln_title", ""), "source_link": record.get("source_link", ""),
        "vuln_ids": record.get("vuln_ids", []), "claims": claims,
    })


def input_digest(request: dict[str, Any]) -> str:
    raw = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
