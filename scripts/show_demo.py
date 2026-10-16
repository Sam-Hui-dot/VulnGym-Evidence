#!/usr/bin/env python3
"""Show the small, offline WeKnora demo artifact in human-readable form."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = ROOT / "artifacts" / "demo" / "weknora.json"

FIELD_NAMES = {
    "entry_point": "漏洞入口",
    "critical_operation": "关键操作",
    "vuln_category_l1": "一级分类",
    "vuln_category_l2": "二级分类",
    "vuln_title": "漏洞标题",
    "vuln_ids": "漏洞编号",
    "commit": "漏洞 Commit",
    "trace": "漏洞链路",
}

STATUS_MARKS = {
    "correct": "✓ 正确",
    "incorrect": "✗ 错误",
    "uncertain": "? 证据不足",
}


def load_artifact(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def render(data: dict) -> str:
    case = data["case"]
    lines = [
        "VulnGym T1 离线快速演示",
        "=" * 32,
        f"项目：{case['project']}",
        f"案例：{case['entry_id']} / {case['report_id']}",
        f"漏洞：{case['vulnerability']}",
        "",
        "原记录声称：",
        f"- 关键操作：{data['candidate_claims']['critical_operation']}",
        f"- 漏洞链路：{data['candidate_claims']['trace']}",
        "",
        "系统找到的关键证据：",
    ]
    lines.extend(f"- {item}" for item in data["evidence_summary"])
    lines.extend(["", "最终八字段报告："])
    for field, status in data["final_report"].items():
        lines.append(f"- {FIELD_NAMES[field]:<12} {STATUS_MARKS[status]}")
    lines.extend(
        [
            "",
            f"总体结论：{STATUS_MARKS[data['result']]}",
            "",
            "建议修正：",
            f"- 关键操作：{data['proposed_correction']['critical_operation']}",
            f"- 漏洞链路：{data['proposed_correction']['trace']}",
            "",
            f"说明：{data['boundary']}",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--json", action="store_true", help="print the tracked JSON artifact")
    args = parser.parse_args()
    data = load_artifact(args.artifact)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(render(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
