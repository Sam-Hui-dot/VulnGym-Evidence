#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

repository=${1:-}
output_dir=${2:-out/demo-current}
model=${3:-deepseek-v4-pro}
reasoning_effort=${4:-high}
if [[ -z "$repository" || ! -d "$repository/.git" ]]; then
  echo "usage: bash scripts/run_deepseek_demo.sh /path/to/WeKnora [output-dir] [model] [reasoning-effort]" >&2
  exit 2
fi
if [[ ! -f .env ]]; then
  echo ".env is missing; copy .env.example and set DEEPSEEK_API_KEY" >&2
  exit 2
fi

set -a
# Local secret file is user-controlled and never included in outputs.
source .env
set +a
export VULNGYM_DEEPSEEK_ENABLED=true
export VULNGYM_DEEPSEEK_MODEL="$model"
export VULNGYM_DEEPSEEK_REASONING_EFFORT="$reasoning_effort"
export VULNGYM_DEEPSEEK_MAX_TOKENS=${VULNGYM_DEEPSEEK_MAX_TOKENS:-12288}

PYTHONPATH=src python3 -m vulngym_agent validate \
  --input configs/demo/weknora.jsonl \
  --output-dir "$output_dir" \
  --provider-config configs/provider.deepseek.json \
  --repository "$repository" \
  --fix-map configs/demo/weknora-fix.json \
  --advisory-cache configs/advisories/pilot-v1.jsonl

printf 'HTML report: %s/report.html\n' "$output_dir"
printf 'Markdown report: %s/report.md\n' "$output_dir"
