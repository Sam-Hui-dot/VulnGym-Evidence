#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

repository=${WEKNORA_REPOSITORY:-/home/sam/rhinobird/vulngym-repos/Tencent/WeKnora}
output_dir="$root/out/recording-demo"
open_report=false
if [[ ${1:-} == "--open" ]]; then
  open_report=true
elif [[ $# -gt 0 ]]; then
  echo "usage: bash scripts/run_recording_demo.sh [--open]" >&2
  exit 2
fi

if [[ ! -f .env ]]; then
  echo "ERROR: .env is missing; configure DASHSCOPE_API_KEY first." >&2
  exit 2
fi
if [[ ! -d "$repository/.git" ]]; then
  echo "ERROR: WeKnora repository is missing: $repository" >&2
  echo "Set WEKNORA_REPOSITORY to its local Git path if it is stored elsewhere." >&2
  exit 2
fi

set -a
# The local secret file is never printed or copied into the output.
source .env
set +a
if [[ -z ${DASHSCOPE_API_KEY:-} ]]; then
  echo "ERROR: DASHSCOPE_API_KEY is not configured." >&2
  exit 2
fi

export VULNGYM_QWEN_ENABLED=true
export VULNGYM_QWEN_MODEL=${VULNGYM_QWEN_MODEL:-qwen3.8-flash}
export VULNGYM_QWEN_ENABLE_THINKING=false
export VULNGYM_QWEN_MAX_TOKENS=${VULNGYM_QWEN_MAX_TOKENS:-4096}

case "$output_dir" in
  "$root"/out/recording-demo) ;;
  *) echo "ERROR: unsafe output path: $output_dir" >&2; exit 2 ;;
esac
rm -rf -- "$output_dir"
mkdir -p "$output_dir"

echo "============================================================"
echo "VulnGym T1 真实端到端演示"
echo "============================================================"
python3 - <<'PY'
import json
from pathlib import Path

row = json.loads(Path("configs/demo/weknora.jsonl").read_text(encoding="utf-8").splitlines()[0])
print(f"输入案例：{row['entry_id']} / {row['report_id']}")
print(f"项目：{row['project']}")
print(f"候选漏洞：{row['vuln_title']}")
print(f"候选入口：{row['entry_point']['file']}:{row['entry_point']['line']}")
print(f"候选关键操作：{row['critical_operation']['file']}:{row['critical_operation']['line']}")
print(f"候选 Trace：{len(row['trace'])} 个节点")
print()
print("开始执行：规划 → 只读工具取证 → Qwen Judge/Critic → 八字段报告")
PY
echo "============================================================"

if [[ -t 0 ]]; then
  read -r -p "输入已展示。按 Enter 开始 Agent 分析..."
fi

PYTHONPATH=src python3 -m vulngym_agent validate \
  --input configs/demo/weknora.jsonl \
  --output-dir "$output_dir" \
  --provider-config configs/provider.qwen.json \
  --repository "$repository" \
  --fix-map configs/demo/weknora-fix.json \
  --advisory-cache configs/advisories/pilot-v1.jsonl

python3 - <<'PY'
import json
from pathlib import Path

path = Path("out/recording-demo/submission.jsonl")
row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
semantic = json.loads(Path("out/recording-demo/semantic.jsonl").read_text(encoding="utf-8").splitlines()[0])
labels = {
    "entry_point": "漏洞入口",
    "critical_operation": "关键操作",
    "vuln_category_l1": "一级分类",
    "vuln_category_l2": "二级分类",
    "vuln_title": "漏洞标题",
    "vuln_ids": "漏洞编号",
    "commit": "漏洞 Commit",
    "trace": "漏洞链路",
}
symbols = {"correct": "✓", "incorrect": "✗", "uncertain": "?"}
print()
print("===================== 本次新生成的结果 =====================")
provider_rows = [
    ("Judge", semantic.get("judge_provider_metadata", {}), semantic.get("judge_seconds")),
    ("Critic", semantic.get("critic_provider_metadata", {}), semantic.get("critic_seconds")),
]
provider_rows = [(role, metadata, seconds) for role, metadata, seconds in provider_rows if metadata]
total_tokens = sum(int(metadata.get("usage", {}).get("total_tokens", 0)) for _, metadata, _ in provider_rows)
models = sorted({str(metadata.get("resolved_model") or metadata.get("requested_model")) for _, metadata, _ in provider_rows})
print(f"Provider：Qwen / {', '.join(models)}")
print(f"模型调用：{len(provider_rows)} 次；返回用量：{total_tokens} tokens")
for role, metadata, seconds in provider_rows:
    usage = metadata.get("usage", {})
    suffix = f"，{float(seconds):.1f}s" if isinstance(seconds, (int, float)) else ""
    print(f"- {role}: {usage.get('total_tokens', 0)} tokens{suffix}")
print()
for name, value in row["fields"].items():
    status = value["status"]
    print(f"{labels.get(name, name):<12} {symbols.get(status, '-')} {status}")
print(f"总体结论：{row['verdict']}")
print("JSONL：out/recording-demo/submission.jsonl")
print("HTML ：out/recording-demo/report.html")
print("============================================================")
PY

if [[ "$open_report" == true ]]; then
  if command -v explorer.exe >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1; then
    explorer.exe "$(wslpath -w "$output_dir/report.html")" >/dev/null 2>&1 || true
  else
    echo "Automatic report opening is unavailable; open $output_dir/report.html manually."
  fi
fi
