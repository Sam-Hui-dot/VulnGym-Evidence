from __future__ import annotations

from html import escape
import json
from pathlib import Path
from typing import Any


LABEL = {"supported": "证据支持", "contradicted": "存在矛盾", "uncertain": "证据不足"}
BASIS = {"deterministic": "规则与证据核对", "model": "模型主审",
         "judge_critic": "主审与反证复核一致", "arbitration": "分歧后保留待复核",
         "guarded_model": "证据门槛未通过，保留待复核"}
SEMANTIC = {"not_needed": "无需语义模型", "not_configured": "语义模型未配置",
            "judge_completed": "主审完成", "judge_critic_completed": "主审与反证复核完成",
            "model_or_contract_failed": "模型调用或输出合同失败",
            "context_budget_exceeded": "上下文超过本次预算"}
COUNTERCHECK = {"no_conflict_in_scope": "已检查，所见范围内未发现冲突",
                "conflict_found": "已发现冲突", "unresolved": "反证仍未解决",
                "not_checked": "未完成反证检查"}


def result_label(item: dict[str, Any]) -> str:
    if item.get("review_status") in {"not_configured", "model_or_contract_failed", "context_budget_exceeded"}:
        return "复核未完成"
    if item["kind"] == "source_location" and item["verdict"] == "supported":
        return "引用一致"
    return LABEL[item["verdict"]]


def _countercheck_html(item: dict[str, Any]) -> str:
    pieces = []
    for title, key in (("主审反证检查", "countercheck"), ("复核反证检查", "critic_countercheck")):
        check = item.get(key)
        if not isinstance(check, dict):
            continue
        label = COUNTERCHECK.get(check.get("status"), "未知")
        pieces.append("<p><b>" + title + "：</b>" + escape(label) + "；" +
                      escape(str(check.get("reason", ""))) + "<br><small>检查引用：" +
                      escape(", ".join(check.get("evidence_refs", []))) + "</small></p>")
        for observation in check.get("observations", []):
            location = str(observation.get("file", "")) + ":" + str(observation.get("context_range", ""))
            pieces.append("<details><summary>反证依据摘录 · " + escape(location) +
                          "</summary><small>" + escape(str(observation.get("evidence_id", ""))) +
                          "</small><pre>" + escape(str(observation.get("quote", ""))) + "</pre></details>")
        if check.get("scope_note"):
            pieces.append("<p><small>" + escape(check["scope_note"]) + "</small></p>")
    return "".join(pieces)


def _evidence_body(item: dict[str, Any]) -> str:
    pieces = []
    def paragraph(text: Any) -> None:
        pieces.append("<p>" + escape(str(text)) + "</p>")
    def source(title: str, text: Any) -> None:
        pieces.append("<h3>" + escape(title) + "</h3><pre>" + escape(str(text)) + "</pre>")
    if item.get("file"):
        paragraph(str(item["file"]) + ":" + str(item.get("context_range", item.get("declared_line", ""))))
    if isinstance(item.get("literal_match"), bool):
        paragraph("引用片段与指定行范围一致" if item["literal_match"] else "引用片段与指定行范围不一致")
    if item.get("reason"):
        paragraph(item["reason"])
    if item.get("numbered_source"):
        source("指定版本的源码上下文", item["numbered_source"])
        if item.get("declared_code") is not None:
            source("报告引用片段", item["declared_code"])
    if item.get("kind") == "patch":
        paragraph("候选修复：" + str(item.get("selected_fix_commit") or "未确认"))
        paragraph("归属状态：" + str(item.get("provenance_status") or "未知"))
        if item.get("diff_truncated"):
            paragraph("补丁展示已截断，不能视为完整修复证据。")
        if item.get("diff"):
            source("可读取的补丁", item["diff"])
    if item.get("kind") == "advisory":
        for key in ("title", "details"):
            if item.get(key):
                paragraph(item[key])
        paragraph("公告角色仅反映配置缓存中的记录，完整来源见原始数据。")
    if item.get("edge_status"):
        paragraph("静态连接：" + str(item["edge_status"]) + "。不单独证明数据流。")
    pieces.append("<details><summary>原始证据 JSON</summary><pre>" +
                  escape(json.dumps(item, ensure_ascii=False, indent=2)) + "</pre></details>")
    return "".join(pieces)


def render_html(result: dict[str, Any]) -> str:
    evidence = result["evidence_packet"]["evidence"]
    anchors = {item["evidence_id"]: f"evidence-{i}" for i, item in enumerate(evidence)}
    rows = []
    for item in result["results"]:
        refs = " ".join(f'<a href="#{anchors[ref]}">{escape(ref)}</a>'
                        for ref in item["evidence_refs"] if ref in anchors)
        rows.append(f'<article><span class="tag {item["verdict"]}">{result_label(item)}</span>'
                    f'<h2>{escape(item["text"])}</h2>'
                    + (f'<p><small>报告原文位置 {item["origin"]["start"]}–{item["origin"]["end"]}：'
                       f'{escape(item["origin"]["quote"])}</small></p>' if item.get("origin") else "")
                    + f'<p>{escape(item["reason"])}</p>{_countercheck_html(item)}'
                    f'<small>{escape(item["claim_id"])} · {escape(item["kind"])} · '
                    f'依据：{escape(BASIS.get(item["basis"], item["basis"]))}</small><p>{refs}</p>'
                    f'<details><summary>模型自评与技术记录</summary><p>自评置信度 {item["confidence"]:.2f}；'
                    f'未校准为准确率。</p></details></article>')
    details = []
    for item in evidence:
        details.append(f'<article id="{anchors[item["evidence_id"]]}"><h2>{escape(item["evidence_id"])} '
                       f'· {escape(str(item.get("kind", "")))}</h2>{_evidence_body(item)}</article>')
    request = result["request"]
    return f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnGym Evidence 复核报告</title>
<style>body{{font:16px/1.7 system-ui;margin:40px auto;padding:0 20px;max-width:1000px;background:#f6f8fc;color:#17253b}}
article,details{{background:white;border:1px solid #dfe5ef;border-radius:12px;padding:20px;margin:16px 0}}
h2{{font-size:19px;overflow-wrap:anywhere}}h3{{font-size:14px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#f6f8fc;padding:12px}}a{{color:#2463cc;overflow-wrap:anywhere}}
.tag{{padding:4px 10px;border-radius:6px}}.supported{{background:#dcf5e9}}.contradicted{{background:#ffe2dd}}
.uncertain{{background:#fff0cf}}small{{color:#52627b}}summary{{cursor:pointer}}:target{{outline:2px solid #437bdb}}</style>
<h1>VulnGym Evidence · 声明复核报告</h1>
<p>模型状态：{escape(SEMANTIC.get(result['semantic_status'], result['semantic_status']))}</p>
<p>{escape(result['scope'])}</p><p>仓库：{escape(request['repo_url'])}<br>取证版本：{escape(request['reviewed_commit'])}</p>
<small>输入 SHA-256：{result['input_sha256']}<br>运行时间：{escape(result['created_at'])} ·
耗时 {result['elapsed_seconds']:.2f} 秒 · 模型尝试 {len(result['model_calls'])} 次</small>
{''.join(rows)}<h2>原始证据</h2>{''.join(details)}
<details><summary>本次输入（原文未全量核验）</summary><pre>{escape(json.dumps(request, ensure_ascii=False, indent=2))}</pre></details>
<details><summary>模型输出与运行记录</summary><pre>{escape(json.dumps(result['model_calls'], ensure_ascii=False, indent=2))}</pre></details>
</html>'''


def write_outputs(directory: Path, result: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    def markdown_text(text: str) -> str:
        text = escape(text, quote=False).replace("\\", "\\\\")
        for character in "`*_[](){}#+-!|~":
            text = text.replace(character, "\\" + character)
        return text
    lines = ["# VulnGym Evidence 复核报告", "", result["scope"], "",
             f"仓库：{markdown_text(result['request']['repo_url'])}",
             f"取证版本：{result['request']['reviewed_commit']}",
             f"输入 SHA-256：{result['input_sha256']}",
             "模型状态：" + SEMANTIC.get(result["semantic_status"], result["semantic_status"]), ""]
    for item in result["results"]:
        lines.extend([f"## {item['claim_id']}：{result_label(item)}", "", markdown_text(item["text"]), "",
                      markdown_text(item["reason"]), "", "证据：" + markdown_text(", ".join(item["evidence_refs"])), ""])
        if item.get("origin"):
            origin = item["origin"]
            lines.extend(["报告原文位置：" + str(origin["start"]) + "–" + str(origin["end"]), "",
                          markdown_text(origin["quote"]), ""])
        for title, key in (("主审反证检查", "countercheck"), ("复核反证检查", "critic_countercheck")):
            check = item.get(key)
            if isinstance(check, dict):
                lines.extend([title + "：" + COUNTERCHECK.get(check.get("status"), "未知"), "",
                              markdown_text(str(check.get("reason", ""))), "",
                              "检查引用：" + markdown_text(", ".join(check.get("evidence_refs", []))), ""])
                for observation in check.get("observations", []):
                    lines.extend(["反证依据摘录：" + markdown_text(observation["evidence_id"]), "",
                                  markdown_text(observation["quote"]), ""])
                if check.get("scope_note"):
                    lines.extend([markdown_text(check["scope_note"]), ""])
    contents = {"result.json": json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
                "report.html": render_html(result), "report.md": "\n".join(lines)}
    for filename, content in contents.items():
        temporary = directory / (filename + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(directory / filename)
