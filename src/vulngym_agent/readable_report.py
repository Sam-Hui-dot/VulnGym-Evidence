"""Offline, dependency-free views of the actual validation run (never an LLM call)."""
from __future__ import annotations

import hashlib
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .submission import SUBMISSION_FIELDS, validate_submission_report

LABELS = dict(zip(SUBMISSION_FIELDS, (
    "漏洞入口", "关键操作", "一级分类", "二级分类", "漏洞标题", "漏洞编号", "漏洞 Commit", "漏洞链路",
)))
STATUS = {"correct": "正确", "incorrect": "错误", "uncertain": "证据不足"}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)


def _safe(value: Any) -> str:
    return html.escape(_text(value), quote=True)


def _md_cell(value: Any) -> str:
    return _text(value).replace("|", "\\|").replace("\n", "<br>")


def _anchor(case_index: int, evidence_id: str) -> str:
    return f"case-{case_index}-ev-" + hashlib.sha256(evidence_id.encode()).hexdigest()[:16]


def _evidence(packet: dict[str, Any]) -> list[dict[str, Any]]:
    """Index citable items, without exposing repository paths or provider config."""
    items: list[dict[str, Any]] = []
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("evidence_id"), str):
                items.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    for key in ("deterministic_audit", "source_contexts", "helper_contexts", "patch_analysis", "trace_analysis", "advisory_analysis", "taxonomy_analysis"):
        visit(packet.get(key))
    return list({item["evidence_id"]: item for item in items}.values())


def _reason_html(reason: str, ids: list[str], index: int) -> str:
    # Escape first, then replace escaped identifiers with internal links only.
    import re
    if not ids:
        return html.escape(reason)
    parts = re.split("(" + "|".join(re.escape(i) for i in sorted(ids, key=len, reverse=True)) + ")", reason)
    known = set(ids)
    return "".join(
        f'<a href="#{_anchor(index, part)}">{html.escape(part)}</a>' if part in known else html.escape(part)
        for part in parts
    )


def render_reports(rows: list[dict[str, Any]]) -> tuple[str, str]:
    """Return Markdown and a self-contained HTML report; preserve every verdict."""
    md = ["# VulnGym T1 验证报告", "", "这是保存的真实运行结果视图，不会重新调用模型；也不代表独立人工 Gold。", ""]
    cards: list[str] = []
    totals: Counter[str] = Counter()
    field_totals: Counter[str] = Counter()
    overview: list[tuple[str, str, str, str]] = []
    for index, row in enumerate(rows, 1):
        report = row.get("submission_report")
        errors = validate_submission_report(report)
        if errors:
            raise ValueError("cannot render invalid submission report: " + "; ".join(errors))
        packet = row.get("evidence_packet", {})
        candidate = packet.get("candidate_record", {})
        semantic = row.get("semantic_result", {})
        items = _evidence(packet)
        ids = [item["evidence_id"] for item in items]
        title = str(report["entry_id"]) + " · " + str(report["report_id"])
        verdict = report["verdict"]
        totals[verdict] += 1
        incorrect_fields = [LABELS[field] for field in SUBMISSION_FIELDS if report["fields"][field]["status"] == "incorrect"]
        uncertain_fields = [LABELS[field] for field in SUBMISSION_FIELDS if report["fields"][field]["status"] == "uncertain"]
        overview.append((title, STATUS[verdict], "、".join(incorrect_fields) or "—", "、".join(uncertain_fields) or "—"))
        provenance = {
            "workflow": row.get("workflow_version"),
            "evidence_packet": packet.get("packet_version"),
            "provider": semantic.get("provider"),
            "semantic_status": semantic.get("status"),
            "judge_prompt": semantic.get("judge_prompt"),
            "critic_prompt": semantic.get("critic_prompt"),
        }
        for stage in ("judge", "critic"):
            metadata = semantic.get(stage + "_provider_metadata", {})
            provenance[stage] = {
                key: metadata[key]
                for key in (
                    "requested_model",
                    "resolved_model",
                    "requested_reasoning_effort",
                    "model",
                    "transport",
                    "usage",
                )
                if key in metadata
            }
        md += [f"## {title}", "", f"总体结论：{STATUS[verdict]}", "", "### 运行来源", "", "    " + json.dumps(provenance, ensure_ascii=False), ""]
        sections = [f'<section class="case"><h2>{_safe(title)}</h2>',
                    f'<p class="badge {verdict}">总体结论：{STATUS[verdict]}</p>',
                    f'<p>{_safe(candidate.get("vuln_title", ""))}</p>',
                    f'<details><summary>运行来源 / Prompt 版本 / Token</summary><pre>{_safe(provenance)}</pre></details>']
        for field in SUBMISSION_FIELDS:
            item = report["fields"][field]
            status = item["status"]
            field_totals[status] += 1
            reason = str(item.get("evidence", ""))
            original = _text(candidate.get(field))
            correction = str(item.get("suggested_correction") or "未提出修正")
            confidence = item.get("confidence")
            confidence_text = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "未提供"
            md += [f"### {LABELS[field]} ({field}) — {STATUS[status]} · 置信度 {confidence_text}", "", "原记录：", "", *["    " + line for line in original.splitlines()], "",
                   "判断依据：", "", *["    " + line for line in reason.splitlines()], "", "建议修正：", "", *["    " + line for line in correction.splitlines()], ""]
            sections += [f'<article class="field {status}"><h3>{LABELS[field]} <small>{field}</small> · {STATUS[status]} <span class="confidence">置信度 {_safe(confidence_text)}</span></h3>',
                         '<p class="flow"><span>原记录主张</span><b>→</b><span>证据核验</span><b>→</b><span>结论与修正</span></p>',
                         f'<p class="reason">{_reason_html(reason, ids, index)}</p>',
                         f'<details><summary>原记录</summary><pre>{_safe(original)}</pre></details>',
                         f'<p><strong>建议修正：</strong>{_safe(correction)}</p></article>']
        md += ["### 证据缺口与后续动作", "", *["    " + line for line in _text(row.get("evidence_gaps", [])).splitlines()], "", "### 证据索引", ""]
        sections += [f'<details><summary>证据缺口与后续动作</summary><pre>{_safe(row.get("evidence_gaps", []))}</pre></details>', '<h3>可追溯证据</h3>']
        for item in items:
            evidence_id = item["evidence_id"]
            # Evidence is untrusted: HTML is escaped; Markdown uses indented code.
            body = _text(item)
            md += [f"#### {evidence_id}", "", *["    " + line for line in body.splitlines()], ""]
            sections.append(f'<details id="{_anchor(index, evidence_id)}"><summary>{_safe(evidence_id)}</summary><pre>{_safe(body)}</pre></details>')
        sections.append("</section>")
        cards.append("\n".join(sections))
    summary = " · ".join(f"{STATUS[v]} {totals[v]}" for v in STATUS)
    field_summary = " · ".join(f"{STATUS[v]} {field_totals[v]}" for v in STATUS)
    overview_md = ["## 一页总览", "", f"案例：{len(rows)}；字段：{field_summary}", "", "| 案例 | 总体 | 明确错误字段 | 证据不足字段 |", "|---|---|---|---|"]
    overview_md += [f"| {_md_cell(a)} | {_md_cell(b)} | {_md_cell(c)} | {_md_cell(d)} |" for a, b, c, d in overview]
    md[4:4] = overview_md + [""]
    overview_html = "".join(
        f"<tr><td>{_safe(a)}</td><td>{_safe(b)}</td><td>{_safe(c)}</td><td>{_safe(d)}</td></tr>"
        for a, b, c, d in overview
    )
    css = """body{font:16px/1.65 system-ui,sans-serif;color:#1b2937;background:#edf2f7;margin:0}main{max-width:1180px;margin:auto;padding:32px}h1{margin-bottom:8px}h2{overflow-wrap:anywhere}small{font-size:.72em;color:#5a6877}.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}.metric{background:#fff;border-radius:12px;padding:16px}.metric b{display:block;font-size:1.55rem}.overview{width:100%;border-collapse:collapse;background:white}.overview th,.overview td{padding:10px;border-bottom:1px solid #d8e0e8;text-align:left;vertical-align:top}section{background:white;padding:28px;margin:24px 0;border-radius:14px}.field{border-left:5px solid #9aabba;padding:2px 18px;margin:20px 0}.correct{border-color:#22805c}.incorrect{border-color:#c64c41}.uncertain{border-color:#ba8b28}.badge{display:inline-block;padding:5px 14px;border:1px solid;border-radius:6px}.confidence{float:right;font-size:.72em;font-weight:500;color:#52616f}.flow{display:flex;gap:10px;align-items:center;color:#52616f;font-size:.9em}.flow span{background:#eef3f7;padding:3px 8px;border-radius:5px}pre{font:13px/1.5 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:16px}details{margin:12px 0}summary{cursor:pointer;overflow-wrap:anywhere}a{color:#215dc5}.reason{white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:760px){.summary-grid{grid-template-columns:1fr 1fr}.overview{font-size:.85em}.confidence{float:none;display:block}.flow{flex-wrap:wrap}}@media print{body{background:white}main{padding:0}section{break-before:page}.field{break-inside:avoid}}"""
    page = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            f'<title>VulnGym T1 验证报告</title><style>{css}</style></head><body><main><h1>VulnGym T1 验证报告</h1>'
            f'<p>{len(rows)} 条记录 · {summary}</p><p>保存的真实运行结果视图，不重新调用模型；不是独立人工 Gold。</p>'
            f'<div class="summary-grid"><div class="metric"><b>{len(rows)}</b>案例</div><div class="metric"><b>{field_totals["correct"]}</b>字段正确</div><div class="metric"><b>{field_totals["incorrect"]}</b>字段错误</div><div class="metric"><b>{field_totals["uncertain"]}</b>证据不足</div></div>'
            f'<h2>一页总览</h2><table class="overview"><thead><tr><th>案例</th><th>总体</th><th>明确错误字段</th><th>证据不足字段</th></tr></thead><tbody>{overview_html}</tbody></table>'
            + "\n".join(cards) + '</main></body></html>')
    return "\n".join(md), page


def write_readable_reports(output_dir: Path, rows: list[dict[str, Any]]) -> None:
    markdown, page = render_reports(rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in (("report.md", markdown), ("report.html", page)):
        target = output_dir / name
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(content + "\n", encoding="utf-8")
        temporary.replace(target)
