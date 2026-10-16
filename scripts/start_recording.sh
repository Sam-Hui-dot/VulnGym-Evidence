#!/usr/bin/env bash
# Bounded recording session: no automatic retry; preserve prior budget ledger.
set -euo pipefail
task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$task_root/out"
export VULNGYM_QWEN_MODEL=qwen3.8-flash
export VULNGYM_QWEN_ENABLE_THINKING=false
export VULNGYM_QWEN_MAX_TOKENS=4096
export VULNGYM_QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
export VULNGYM_QWEN_BUDGET_FILE="$task_root/out/recording-budget.json"
export VULNGYM_QWEN_TOTAL_TOKEN_LIMIT=100000
export VULNGYM_QWEN_CALL_LIMIT=10
export VULNGYM_QWEN_COST_LIMIT_CNY=0.2
exec bash "$task_root/scripts/start_evidence.sh" --qwen --port 8774 "$@"
