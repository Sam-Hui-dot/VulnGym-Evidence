from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
from typing import Any, Iterable


_GAP_RECOMMENDATIONS = {
    "repository_missing": "补充对应的本地只读源码仓库，未补充前保持源码语义 uncertain。",
    "source_context_incomplete": "检查候选文件、行号和 commit；仅在唯一源码位置可证明时给出修正。",
    "advisory_missing": "补充与 GHSA/CVE 标识匹配的本地公告缓存。",
    "fix_patch_unresolved": "补充公告显式修复角色或可信 fix-map，不要从 Git 拓扑反推修复关系。",
    "trace_edges_unproven": "人工复核未证明边；静态工具未解析不等于链路错误。",
    "taxonomy_missing": "补充版本化 VulnGym taxonomy 证据，缺失时保持分类 uncertain。",
}


def _case_key(row: dict[str, Any]) -> str:
    return str(row.get("case_id") or row.get("entry_id") or row.get("report_id") or "unknown")


def _field_results(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    rows = value.get("field_results")
    if not isinstance(rows, list):
        return {}
    return {
        str(item["field"]): item
        for item in rows
        if isinstance(item, dict) and isinstance(item.get("field"), str)
    }


def _cause_code(field: str, evidence: str) -> str:
    text = evidence.lower()
    if "declared location" in text or "match_status=drifted" in text:
        return "source_location_drift"
    if "cannot be found" in text or "cannot be read" in text or "match_status=missing" in text:
        return "source_identity_failure"
    if field == "commit":
        return "commit_provenance_mismatch"
    if field == "trace":
        return "trace_claim_contradiction"
    if field.startswith("vuln_category"):
        return "taxonomy_disagreement"
    if field in {"vuln_ids", "vuln_title"}:
        return "advisory_mismatch"
    return f"{field}_incorrect"


def _recommendation(code: str) -> str:
    return {
        "source_location_drift": "检查上游提取器的行号同步逻辑；优先采用唯一源码匹配位置。",
        "source_identity_failure": "检查提取器所用 commit、文件路径和代码规范化逻辑。",
        "commit_provenance_mismatch": "区分漏洞 commit、修复 commit 与普通引用 commit，并要求非循环 provenance。",
        "trace_claim_contradiction": "复核 Trace 节点角色与直接流描述，不把未解析静态边自动判错。",
        "taxonomy_disagreement": "对照公告 CWE、Patch 语义和 VulnGym L1/L2 父子关系。",
        "advisory_mismatch": "对照本地公告缓存中的规范编号、产品、影响和标题语义。",
        "critic_direction_change": "抽查 Judge 与 Critic 的反证依据，确认仲裁门没有放大低置信回退。",
        "model_contract_retry": "检查 Prompt/Provider 的结构化输出稳定性，保留重试前后的校验错误。",
    }.get(code, "抽查列出的案例和证据，确认是否来自同一上游提取或工具故障。")


def analyze_systemic_patterns(
    rows: Iterable[dict[str, Any]],
    *,
    minimum_occurrences: int = 2,
) -> dict[str, Any]:
    """Aggregate repeated, evidence-backed batch failure patterns.

    This analyzer deliberately reports observations rather than claiming causal
    proof.  A pattern needs at least ``minimum_occurrences`` distinct cases;
    one-off failures remain in the ordinary per-case report.
    """

    if minimum_occurrences < 2:
        raise ValueError("minimum_occurrences must be at least 2")
    materialized = [row for row in rows if isinstance(row, dict)]
    gap_cases: dict[str, set[str]] = defaultdict(set)
    gap_examples: dict[str, list[str]] = defaultdict(list)
    field_status_cases: dict[tuple[str, str], set[str]] = defaultdict(set)
    cause_cases: dict[str, set[str]] = defaultdict(set)
    cause_examples: dict[str, list[str]] = defaultdict(list)
    changed_cases: dict[str, set[str]] = defaultdict(set)
    contract_retry_cases: set[str] = set()
    correction_cases: dict[str, set[str]] = defaultdict(set)

    for row in materialized:
        case = _case_key(row)
        for gap in row.get("evidence_gaps", []):
            if not isinstance(gap, dict):
                continue
            code = str(gap.get("code") or "unknown_gap")
            gap_cases[code].add(case)
            reason = str(gap.get("reason") or "")
            if reason and reason not in gap_examples[code]:
                gap_examples[code].append(reason)

        report = row.get("submission_report")
        fields = report.get("fields") if isinstance(report, dict) else None
        if isinstance(fields, dict):
            for field, result in fields.items():
                if not isinstance(result, dict):
                    continue
                status = str(result.get("status") or "unknown")
                field_status_cases[(str(field), status)].add(case)
                if isinstance(result.get("suggested_correction"), str):
                    correction_cases[str(field)].add(case)
                if status == "incorrect":
                    evidence = str(result.get("evidence") or "")
                    cause = _cause_code(str(field), evidence)
                    cause_cases[cause].add(case)
                    if evidence and evidence not in cause_examples[cause]:
                        cause_examples[cause].append(evidence[:300])

        semantic = row.get("semantic_result")
        if not isinstance(semantic, dict):
            continue
        if semantic.get("judge_contract_retry") or semantic.get("judge_repair"):
            contract_retry_cases.add(case)
        judge = _field_results(semantic.get("judgment"))
        final = _field_results(semantic.get("final_judgment"))
        for field in sorted(set(judge) & set(final)):
            before = judge[field].get("verdict")
            after = final[field].get("verdict")
            if before != after:
                changed_cases[field].add(case)

    patterns: list[dict[str, Any]] = []

    def add_pattern(
        *,
        code: str,
        category: str,
        cases: set[str],
        recommendation: str,
        examples: list[str] | None = None,
        field: str | None = None,
    ) -> None:
        if len(cases) < minimum_occurrences:
            return
        item: dict[str, Any] = {
            "code": code,
            "category": category,
            "status": "repeated_signal_not_proven_root_cause",
            "occurrences": len(cases),
            "case_ids": sorted(cases),
            "recommendation": recommendation,
        }
        if field is not None:
            item["field"] = field
        if examples:
            item["evidence_examples"] = examples[:3]
        patterns.append(item)

    for code, cases in gap_cases.items():
        add_pattern(
            code=code,
            category="repeated_evidence_gap",
            cases=cases,
            recommendation=_GAP_RECOMMENDATIONS.get(code, _recommendation(code)),
            examples=gap_examples[code],
        )
    for code, cases in cause_cases.items():
        add_pattern(
            code=code,
            category="repeated_incorrect_pattern",
            cases=cases,
            recommendation=_recommendation(code),
            examples=cause_examples[code],
        )
    for field, cases in changed_cases.items():
        add_pattern(
            code="critic_direction_change",
            category="judge_critic_change",
            cases=cases,
            field=field,
            recommendation=_recommendation("critic_direction_change"),
        )
    add_pattern(
        code="model_contract_retry",
        category="provider_contract_instability",
        cases=contract_retry_cases,
        recommendation=_recommendation("model_contract_retry"),
    )
    patterns.sort(key=lambda item: (-item["occurrences"], item["category"], item["code"], item.get("field", "")))

    field_summary = {
        field: {
            status: len(field_status_cases.get((field, status), set()))
            for status in ("correct", "incorrect", "uncertain")
        }
        for field in sorted({field for field, _status in field_status_cases})
    }
    return {
        "analysis_version": "1.0.0",
        "cases": len(materialized),
        "minimum_occurrences": minimum_occurrences,
        "interpretation": (
            "Repeated signals identify review priorities, not proven causal attribution. "
            "Every pattern lists the affected cases and an evidence-bounded recommendation."
        ),
        "patterns": patterns,
        "field_statuses": field_summary,
        "correction_coverage": {
            field: len(cases) for field, cases in sorted(correction_cases.items())
        },
    }


def render_systemic_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 批次系统性错误分析",
        "",
        f"- 案例数：{report.get('cases', 0)}",
        f"- 重复信号门槛：{report.get('minimum_occurrences', 2)} 个不同案例",
        "- 口径：重复信号用于安排复核优先级，不等同于已经证明根因。",
        "",
        "## 重复模式",
        "",
    ]
    patterns = report.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        lines.append("本批次没有达到门槛的重复失败模式；单条问题仍保留在逐案报告中。")
    else:
        for index, item in enumerate(patterns, 1):
            field = f" / `{item['field']}`" if item.get("field") else ""
            lines.extend(
                [
                    f"### {index}. `{item['code']}`{field}",
                    "",
                    f"- 类型：{item['category']}",
                    f"- 影响：{item['occurrences']} 个案例",
                    f"- 案例：{', '.join(item['case_ids'])}",
                    f"- 建议：{item['recommendation']}",
                ]
            )
            examples = item.get("evidence_examples")
            if isinstance(examples, list) and examples:
                lines.append("- 证据示例：")
                lines.extend(f"  - {example}" for example in examples)
            lines.append("")
    lines.extend(["## 字段状态汇总", "", "| 字段 | correct | incorrect | uncertain |", "|---|---:|---:|---:|"])
    for field, counts in report.get("field_statuses", {}).items():
        lines.append(f"| `{field}` | {counts['correct']} | {counts['incorrect']} | {counts['uncertain']} |")
    return "\n".join(lines) + "\n"


def write_systemic_analysis(output_dir: Path, rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    report = analyze_systemic_patterns(rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "systemic-analysis.json"
    markdown_path = output_dir / "systemic-analysis.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_systemic_markdown(report), encoding="utf-8")
    return report
