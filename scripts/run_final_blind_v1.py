#!/usr/bin/env python3
"""Run the single frozen five-repository final validation; preflight by default."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulngym_agent.jsonl import read_jsonl, write_jsonl
from vulngym_agent.provider import ProviderCompletion, ProviderError, load_provider
from vulngym_agent.semantic_report import summarize_semantic_results
from vulngym_agent.semantic_runner import run_judge_critic
from vulngym_agent.submission import build_submission_report
from vulngym_agent.submission_evaluation import evaluate_submission_reports


class CountingProvider:
    def __init__(self, provider: Any, maximum_calls: int) -> None:
        self._provider = provider
        self.name = provider.name
        self.maximum_calls = maximum_calls
        self.calls = 0

    def complete(self, request: dict[str, Any]) -> ProviderCompletion:
        if self.calls >= self.maximum_calls:
            raise ProviderError(f"Final validation API-call cap reached ({self.maximum_calls})")
        self.calls += 1
        return self._provider.complete(request)


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="spend quota for the one frozen attempt")
    args = parser.parse_args()
    os.chdir(ROOT)

    manifest_path = Path("artifacts/final-blind-v1/evidence-manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in manifest["sha256"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Frozen input changed: {name}")
    base = manifest["semantic_behavior_base_commit"]
    # Report rendering is presentation-only and was polished after the semantic
    # run. Keep the freeze guard focused on code that can affect evidence,
    # provider requests, Judge/Critic decisions, or submission labels.
    if subprocess.check_output([
        "git", "diff", base, "--", "src", "configs/provider.qwen.json",
        ":!src/vulngym_agent/readable_report.py",
    ]):
        raise SystemExit("Production behavior differs from the frozen behavior commit")

    selection = json.loads(Path("configs/final-blind-v1-selection.json").read_text(encoding="utf-8"))
    packets = [row for _, row in read_jsonl(Path("artifacts/final-blind-v1/evidence.jsonl"))]
    settings = selection["run_settings"]
    expected = int(settings["maximum_cases"])
    if selection.get("selection_status") != "frozen_before_model_run":
        raise SystemExit("Selection is not frozen")
    if len(packets) != expected or len({row["entry_id"] for row in packets}) != expected:
        raise SystemExit(f"Expected {expected} unique frozen cases")
    print(f"Frozen preflight passed: {expected} cases, at most {settings['maximum_total_api_calls']} calls.", flush=True)
    if not args.run:
        return 0

    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise SystemExit("Commit the freeze first; formal evaluation requires a clean worktree")
    if not os.environ.get("DASHSCOPE_API_KEY"):
        raise SystemExit("Load DASHSCOPE_API_KEY locally before --run")
    os.environ.update({
        "VULNGYM_QWEN_ENABLED": "true",
        "VULNGYM_QWEN_MODEL": settings["model"],
        "VULNGYM_QWEN_ENABLE_THINKING": str(settings["enable_thinking"]).lower(),
        "VULNGYM_QWEN_MAX_TOKENS": "8192",
        "VULNGYM_QWEN_TIMEOUT_SECONDS": "240",
    })

    output = Path("out/final-blind-v1-run")
    output.mkdir(parents=True, exist_ok=False)
    save(output / "start.json", {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "freeze_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "settings": settings,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    })
    started = time.perf_counter()
    provider = CountingProvider(load_provider(Path(settings["provider_config"])), int(settings["maximum_total_api_calls"]))
    results: list[dict[str, Any]] = []
    for packet in packets:
        if provider.calls >= provider.maximum_calls:
            break
        print(f"Starting {packet['entry_id']} ({provider.calls}/{provider.maximum_calls} calls used)", flush=True)
        try:
            result = run_judge_critic(packet, provider, critic_policy=settings["critic_policy"])
        except Exception as exc:
            result = {"entry_id": packet["entry_id"], "case_id": packet.get("case_id"),
                      "status": "runner_error", "error_type": type(exc).__name__, "error": str(exc)}
        write_jsonl(output / f"{packet['entry_id']}.jsonl", [result])
        results.append(result)
        print(f"Finished {packet['entry_id']}: {result['status']} ({provider.calls}/{provider.maximum_calls})", flush=True)

    write_jsonl(output / "semantic.jsonl", results)
    by_entry = {row["entry_id"]: row for row in results}
    completed_packets = [row for row in packets if row["entry_id"] in by_entry]
    reports = [build_submission_report(row, by_entry[row["entry_id"]]) for row in completed_packets]
    write_jsonl(output / "submission.jsonl", reports)
    reference = [row for _, row in read_jsonl(Path("artifacts/final-blind-v1/reference.jsonl"))]
    save(output / "evaluation.json", evaluate_submission_reports(reports, reference))
    summary = summarize_semantic_results(results)
    summary.update({"wall_seconds": round(time.perf_counter() - started, 3),
                    "physical_api_attempts": provider.calls,
                    "maximum_total_api_calls": provider.maximum_calls})
    save(output / "semantic-summary.json", summary)
    successful = {"completed", "completed_with_repair", "completed_without_critic", "completed_without_critic_with_repair"}
    return 0 if len(results) == len(packets) and all(row.get("status") in successful for row in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
