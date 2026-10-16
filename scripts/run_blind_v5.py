#!/usr/bin/env python3
"""Run the single frozen Blind v5 attempt; default mode is preflight only."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulngym_agent.jsonl import read_jsonl, write_jsonl
from vulngym_agent.provider import load_provider
from vulngym_agent.semantic_report import summarize_semantic_results
from vulngym_agent.semantic_runner import run_judge_critic
from vulngym_agent.submission import build_submission_report
from vulngym_agent.submission_evaluation import evaluate_submission_reports


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly spend API quota for the one frozen attempt")
    args = parser.parse_args()
    os.chdir(ROOT)

    manifest_path = Path("artifacts/blind-v5/evidence-manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in manifest["sha256"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Frozen input changed: {name}")
    base = manifest["semantic_behavior_base_commit"]
    if subprocess.check_output(["git", "diff", base, "--", "src", "configs/provider.qwen.json"]):
        raise SystemExit("Production behavior differs from the frozen behavior commit")

    selection = json.loads(Path("configs/blind-v5-selection.json").read_text(encoding="utf-8"))
    packets = [row for _, row in read_jsonl(Path("out/blind-v5/evidence.jsonl"))]
    if len(packets) != 6 or len({packet["entry_id"] for packet in packets}) != 6:
        raise SystemExit("Expected six unique frozen cases")
    print("Frozen-input and production-behavior preflight passed; 6 cases.", flush=True)
    if not args.run:
        return 0

    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise SystemExit("Commit the freeze first; evaluation requires a clean worktree")
    subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(manifest_path)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    if not os.environ.get("DASHSCOPE_API_KEY"):
        raise SystemExit("Load DASHSCOPE_API_KEY locally before --run; never paste it into logs")

    settings = selection["run_settings"]
    os.environ.update({
        "VULNGYM_QWEN_ENABLED": "true",
        "VULNGYM_QWEN_MODEL": settings["model"],
        "VULNGYM_QWEN_ENABLE_THINKING": str(settings["enable_thinking"]).lower(),
        "VULNGYM_QWEN_MAX_TOKENS": str(settings["max_output_tokens"]),
        "VULNGYM_QWEN_TIMEOUT_SECONDS": "180",
    })
    current_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(ROOT / "src") + (
        os.pathsep + current_pythonpath if current_pythonpath else ""
    )

    output = Path("out/blind-v5-run")
    output.mkdir(parents=True, exist_ok=False)
    save(output / "start.json", {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "freeze_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "settings": settings,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    })
    started = time.perf_counter()
    provider = load_provider(Path(settings["provider_config"]))
    results: list[dict] = []
    for packet in packets:
        print(f"Starting {packet['entry_id']}", flush=True)
        try:
            result = run_judge_critic(packet, provider, use_critic=True)
        except Exception as exc:
            result = {
                "entry_id": packet["entry_id"],
                "case_id": packet["case_id"],
                "status": "runner_error",
                "error_type": type(exc).__name__,
            }
        write_jsonl(output / f"{packet['entry_id']}.jsonl", [result])
        results.append(result)
        print(f"Finished {packet['entry_id']}: {result['status']}", flush=True)

    write_jsonl(output / "semantic.jsonl", results)
    by_entry = {row["entry_id"]: row for row in results}
    reports = [build_submission_report(packet, by_entry[packet["entry_id"]]) for packet in packets]
    judge_reports = [
        build_submission_report(packet, {"judgment": by_entry[packet["entry_id"]].get("judgment")})
        for packet in packets
    ]
    write_jsonl(output / "submission.jsonl", reports)
    write_jsonl(output / "judge-submission.jsonl", judge_reports)

    # Reference labels enter only after all model requests have completed.
    reference = [row for _, row in read_jsonl(Path("out/blind-v5/reference.jsonl"))]
    final_score = evaluate_submission_reports(reports, reference)
    judge_score = evaluate_submission_reports(judge_reports, reference)
    save(output / "evaluation.json", final_score)
    save(output / "judge-evaluation.json", judge_score)
    summary = summarize_semantic_results(results)
    summary["wall_seconds"] = round(time.perf_counter() - started, 3)
    summary["resource_caveat"] = "Reported usage excludes provider attempts that returned no metadata."
    save(output / "semantic-summary.json", summary)

    completed = sum(row["status"] in {"completed", "completed_with_repair"} for row in results)
    print(json.dumps({
        "completed": completed,
        "cases": len(packets),
        "metrics": final_score["metrics"],
        "judge_metrics": judge_score["metrics"],
    }, ensure_ascii=False, indent=2), flush=True)
    return 0 if completed == len(packets) else 2


if __name__ == "__main__":
    raise SystemExit(main())
