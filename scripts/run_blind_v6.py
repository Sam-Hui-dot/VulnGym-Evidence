#!/usr/bin/env python3
"""Run the bounded frozen Blind v6 attempt; default mode is preflight only."""
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
    """Count every physical provider attempt and enforce the frozen hard cap."""

    def __init__(self, provider: Any, maximum_calls: int) -> None:
        self._provider = provider
        self.name = provider.name
        self.maximum_calls = maximum_calls
        self.calls = 0

    def complete(self, request: dict[str, Any]) -> ProviderCompletion:
        if self.calls >= self.maximum_calls:
            raise ProviderError(f"Blind v6 API-call cap reached ({self.maximum_calls})")
        self.calls += 1
        return self._provider.complete(request)


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly spend API quota for the one frozen attempt")
    args = parser.parse_args()
    os.chdir(ROOT)

    manifest_path = Path("artifacts/blind-v6/evidence-manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in manifest["sha256"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Frozen input changed: {name}")
    base = manifest["semantic_behavior_base_commit"]
    if subprocess.check_output(["git", "diff", base, "--", "src", "configs/provider.qwen.json"]):
        raise SystemExit("Production behavior differs from the frozen behavior commit")

    selection = json.loads(Path("configs/blind-v6-selection.json").read_text(encoding="utf-8"))
    packets = [row for _, row in read_jsonl(Path("out/blind-v6/evidence-final.jsonl"))]
    settings = selection["run_settings"]
    expected_cases = int(settings["max_cases"])
    if selection.get("selection_status") != "frozen":
        raise SystemExit("Blind v6 selection is not frozen")
    if len(packets) != expected_cases or len({packet["entry_id"] for packet in packets}) != expected_cases:
        raise SystemExit(f"Expected {expected_cases} unique frozen cases")
    print(f"Frozen-input and behavior preflight passed; {expected_cases} cases, at most {settings['maximum_total_api_calls']} API attempts.", flush=True)
    if not args.run:
        return 0

    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise SystemExit("Commit the freeze first; evaluation requires a clean worktree")
    subprocess.run(["git", "ls-files", "--error-unmatch", str(manifest_path)], check=True, stdout=subprocess.DEVNULL)
    if not os.environ.get("DASHSCOPE_API_KEY"):
        raise SystemExit("Load DASHSCOPE_API_KEY locally before --run; never paste it into logs")

    os.environ.update({
        "VULNGYM_QWEN_ENABLED": "true",
        "VULNGYM_QWEN_MODEL": settings["model"],
        "VULNGYM_QWEN_ENABLE_THINKING": str(settings["enable_thinking"]).lower(),
        "VULNGYM_QWEN_MAX_TOKENS": str(settings["max_output_tokens"]),
        "VULNGYM_QWEN_TIMEOUT_SECONDS": "180",
    })
    output = Path("out/blind-v6-run")
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
            print("Call cap reached; preserving remaining cases as missing predictions.", flush=True)
            break
        print(f"Starting {packet['entry_id']} (calls used: {provider.calls}/{provider.maximum_calls})", flush=True)
        try:
            result = run_judge_critic(packet, provider, critic_policy=settings["critic_policy"])
        except Exception as exc:
            result = {
                "entry_id": packet["entry_id"],
                "case_id": packet["case_id"],
                "status": "runner_error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        write_jsonl(output / f"{packet['entry_id']}.jsonl", [result])
        results.append(result)
        print(f"Finished {packet['entry_id']}: {result['status']} (calls used: {provider.calls}/{provider.maximum_calls})", flush=True)

    write_jsonl(output / "semantic.jsonl", results)
    by_entry = {row["entry_id"]: row for row in results}
    completed_packets = [packet for packet in packets if packet["entry_id"] in by_entry]
    reports = [build_submission_report(packet, by_entry[packet["entry_id"]]) for packet in completed_packets]
    judge_reports = [build_submission_report(packet, {"judgment": by_entry[packet["entry_id"]].get("judgment")}) for packet in completed_packets]
    write_jsonl(output / "submission.jsonl", reports)
    write_jsonl(output / "judge-submission.jsonl", judge_reports)

    reference = [row for _, row in read_jsonl(Path("out/blind-v6/reference.jsonl"))]
    final_score = evaluate_submission_reports(reports, reference)
    judge_score = evaluate_submission_reports(judge_reports, reference)
    save(output / "evaluation.json", final_score)
    save(output / "judge-evaluation.json", judge_score)
    summary = summarize_semantic_results(results)
    summary["wall_seconds"] = round(time.perf_counter() - started, 3)
    summary["physical_api_attempts"] = provider.calls
    summary["maximum_total_api_calls"] = provider.maximum_calls
    summary["resource_caveat"] = "Usage metadata can exclude failed provider attempts; physical_api_attempts includes them."
    save(output / "semantic-summary.json", summary)

    successful = {
        "completed", "completed_with_repair", "completed_without_critic", "completed_without_critic_with_repair"
    }
    completed = sum(row.get("status") in successful for row in results)
    print(json.dumps({
        "completed": completed,
        "cases": len(packets),
        "physical_api_attempts": provider.calls,
        "metrics": final_score["metrics"],
        "judge_metrics": judge_score["metrics"],
    }, ensure_ascii=False, indent=2), flush=True)
    return 0 if completed == len(packets) else 2


if __name__ == "__main__":
    raise SystemExit(main())
