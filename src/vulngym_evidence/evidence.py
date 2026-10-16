from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Iterable

from vulngym_agent.advisory import advisory_evidence
from vulngym_agent.evidence import _helper_contexts, _node_context
from vulngym_agent.lifecycle_inspector import inspect_critical_lifecycle
from vulngym_agent.patch_inspector import inspect_patch
from vulngym_agent.repository import ReadOnlyGitRepository, RepositoryError
from vulngym_agent.repository_index import RepositoryResolver
from vulngym_agent.schema import line_span
from vulngym_agent.trace_inspector import inspect_trace
from .go_types import collect_go_types


Emit = Callable[[str, str], None]


def collect_evidence(
    request: dict[str, Any], *, roots: Iterable[Path] = (),
    repository: Path | None = None, advisory_documents: Iterable[dict[str, Any]] = (),
    emit: Emit = lambda stage, message: None,
) -> dict[str, Any]:
    emit("repository", "查找本地仓库与指定版本")
    mapping = {request["repo_url"]: repository} if repository else {}
    resolution = RepositoryResolver(roots=roots, mapping=mapping).resolve(request["repo_url"])
    repo = ReadOnlyGitRepository(resolution.path) if resolution.path else None
    version_present = bool(repo and repo.has_commit(request["reviewed_commit"]))
    version = {"evidence_id": "git:reviewed_commit", "kind": "git",
               "status": "available" if version_present else "missing",
               "commit": request["reviewed_commit"], "repository": resolution.to_dict(),
               "reason": "指定 Commit 可读取" if version_present else "本地仓库或 Commit 不可读取"}
    emit("advisory", "匹配已配置的公告缓存")
    record = {"repo_url": request["repo_url"], "commit": request["reviewed_commit"],
              "vuln_ids": request["vuln_ids"], "source_link": request["source_link"]}
    advisory = advisory_evidence(record, advisory_documents)
    evidence = [version]
    docs = []
    for item in advisory["documents"]:
        item = {**item, "kind": "advisory", "status": "available"}
        docs.append(item)
        evidence.append(item)
    items = []
    for claim in request["claims"]:
        claim = deepcopy(claim)
        refs = [version["evidence_id"]]
        gap = None if version_present else version["reason"]
        source_match = None
        trace_complete = None
        fix_relation = None
        if version_present and repo is not None:
            emit("source", f"读取声明 {claim['claim_id']} 的证据")
            try:
                if claim["kind"] in {"source_location", "entry_point", "critical_operation", "trace"}:
                    nodes = claim["nodes"] if claim["kind"] == "trace" else [claim["node"]]
                    contexts, literal_matches = [], []
                    for index, node in enumerate(nodes):
                        field = f"{claim['claim_id']}[{index}]"
                        context = _node_context(repo, request["reviewed_commit"], field, node,
                                                context_lines=12, after_context_lines=40)
                        context["kind"] = "source"
                        if context["status"] != "available":
                            gap = "声明引用的文件在本地指定版本中不可读取"
                        else:
                            lines = repo.read_file(request["reviewed_commit"], node["file"]).splitlines()
                            start, end = line_span(node["line"])
                            actual = lines[start - 1:end]
                            match = actual == node["code"].splitlines()
                            context["literal_match"] = match
                            context["actual_declared_range"] = "\n".join(actual)
                            literal_matches.append(match)
                        refs.append(context["evidence_id"])
                        evidence.append(context)
                        contexts.append(context)
                    source_match = all(literal_matches) if len(literal_matches) == len(nodes) else None
                    if claim["kind"] != "source_location":
                        for definition in collect_go_types(repo, request["reviewed_commit"], contexts, claim["claim_id"]):
                            refs.append(definition["evidence_id"])
                            evidence.append(definition)
                        helpers = _helper_contexts(repo, request["reviewed_commit"], contexts, context_lines=12)
                        for helper in helpers:
                            helper["evidence_id"] = claim["claim_id"] + ":" + helper["evidence_id"]
                            helper["kind"] = "source_helper"
                            refs.append(helper["evidence_id"])
                            evidence.append(helper)
                    if claim["kind"] == "trace":
                        trace = inspect_trace(repo, request["reviewed_commit"], nodes)
                        trace_complete = bool(trace["edges"]) and all(
                            edge["status"] in {"same_function_order", "direct_symbol_call"}
                            for edge in trace["edges"]
                        )
                        for section in ("contexts", "edges"):
                            for part in trace[section]:
                                part = {**part, "evidence_id": claim["claim_id"] + ":" + part["evidence_id"],
                                        "kind": "trace_" + section}
                                if section == "edges":
                                    part["edge_status"] = part["status"]
                                    part["status"] = "available"
                                part["context_refs"] = [claim["claim_id"] + ":" + ref
                                                        for ref in part.get("context_refs", [])]
                                refs.append(part["evidence_id"])
                                evidence.append(part)
                    if claim["kind"] == "critical_operation":
                        lifecycle = inspect_critical_lifecycle(repo, request["reviewed_commit"], claim["node"])
                        lifecycle["evidence_id"] = claim["claim_id"] + ":lifecycle"
                        lifecycle["kind"] = "lifecycle"
                        refs.append(lifecycle["evidence_id"])
                        evidence.append(lifecycle)
                elif claim["kind"] == "fix_commit":
                    emit("patch", f"对照公告和补丁复核声明 {claim['claim_id']}")
                    # The claimed fix is deliberately NOT passed as a trusted explicit fix.
                    patch = inspect_patch(repo, record, advisory_documents=docs)
                    patch = {**patch, "evidence_id": claim["claim_id"] + ":patch", "kind": "patch"}
                    refs.append(patch["evidence_id"])
                    evidence.append(patch)
                    claimed_fix = claim["claimed_fix_commit"]
                    fix_present = repo.has_commit(claimed_fix)
                    def matches(field: str) -> bool:
                        return any(claimed_fix.startswith(sha) for doc in docs for sha in doc.get(field, []))
                    marked_fixed, marked_vulnerable = matches("fixed_commits"), matches("vulnerable_commits")
                    if marked_fixed and marked_vulnerable:
                        gap = "公告对该提交的角色存在冲突"
                    elif not fix_present:
                        gap = "被声称的修复 Commit 不在本地仓库中"
                    elif marked_vulnerable:
                        fix_relation = "contradicted"
                    elif (marked_fixed and patch.get("selected_fix_commit") == claimed_fix
                          and patch.get("provenance_status") == "verified" and patch.get("diff")):
                        fix_relation = "supported"
                    else:
                        gap = "没有足够独立证据确认该修复角色；其他修复存在不能排除回移修复"
            except RepositoryError:
                gap = "Git/源码证据读取失败，需补齐本地材料"
        if claim["kind"] in {"entry_point", "critical_operation", "trace", "fix_commit"}:
            refs.extend(doc["evidence_id"] for doc in docs)
        items.append({"claim": claim, "evidence_refs": list(dict.fromkeys(refs)),
                      "gap": gap, "literal_match": source_match,
                      "trace_complete": trace_complete, "fix_relation": fix_relation})
    return {"packet_version": "claims-1.0", "repository": resolution.to_dict(),
            "claims": items, "evidence": evidence,
            "policy": {"target_code_executed": False, "network_fetch": False,
                       "trace_scope": "bounded static evidence; not full taint analysis",
                       "fix_scope": "advisory attribution and readable patch; not proof of total remediation"}}
