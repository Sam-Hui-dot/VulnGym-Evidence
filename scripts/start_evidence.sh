#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$task_root"
mode="deterministic"
check_only=false
port=8765
repositories_root=""
critic_args=()
while (($#)); do
  case "$1" in
    --qwen) mode=qwen; shift ;;
    --deterministic) mode=deterministic; shift ;;
    --check) check_only=true; shift ;;
    --port) port="${2:?请提供端口}"; shift 2 ;;
    --repositories-root) repositories_root="${2:?请提供仓库根目录}"; shift 2 ;;
    --no-critic) critic_args=(--no-critic); shift ;;
    *) printf '未知选项：%s\n' "$1" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null || { printf '需要 Python 3.10+。\n' >&2; exit 2; }
export PYTHONPATH="$task_root/src${PYTHONPATH:+:$PYTHONPATH}"
repository_args=()
if [[ -n "$repositories_root" ]]; then
  repository_args=(--repositories-root "$repositories_root")
elif [[ -d "$task_root/../vulngym-repos" ]]; then
  repository_args=(--repositories-root "$task_root/../vulngym-repos")
fi
provider_args=()
if [[ "$mode" == "qwen" ]]; then
  if [[ -z "${DASHSCOPE_API_KEY:-}" && "$check_only" == false ]]; then
    [[ -t 0 ]] || { printf '当前没有密钥；请在交互终端输入，或设置 DASHSCOPE_API_KEY。\n' >&2; exit 2; }
    read -r -s -p '输入 DashScope API Key（不回显，仅用于本次进程）：' DASHSCOPE_API_KEY
    printf '\n'
    [[ -n "$DASHSCOPE_API_KEY" ]] || { printf '密钥为空，启动取消。\n' >&2; exit 2; }
    export DASHSCOPE_API_KEY
  fi
  if [[ "$check_only" == false ]]; then
    export VULNGYM_QWEN_ENABLED=true
  fi
  provider_args=(--provider-config "$task_root/configs/provider.qwen.json")
fi
python3 -m vulngym_evidence doctor "${repository_args[@]}" "${provider_args[@]}"
if [[ "$check_only" == true ]]; then
  exit 0
fi
advisory_args=()
if [[ -f "$task_root/configs/advisories/pilot-v1.jsonl" ]]; then
  advisory_args=(--advisory-cache "$task_root/configs/advisories/pilot-v1.jsonl")
fi
printf '\n浏览器打开：http://127.0.0.1:%s\n按 Ctrl+C 停止本地服务。\n' "$port"
exec python3 -m vulngym_evidence serve --port "$port" --output-dir "$task_root/out/evidence-web" \
  "${repository_args[@]}" "${provider_args[@]}" "${advisory_args[@]}" "${critic_args[@]}"
