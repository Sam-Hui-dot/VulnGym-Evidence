#!/usr/bin/env python3
"""One frozen evaluation attempt; default is a read-only preflight, not an API call."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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


SENSITIVITY_EXCLUSIONS = {
    ("blind-v4-clean-entry-00276", "trace"),
    ("blind-v4-clean-entry-00171", "entry_point"),
    ("blind-v4-clean-entry-00171", "critical_operation"),
    ("blind-v4-clean-entry-00171", "trace"),
    ("blind-v4-clean-entry-00376", "entry_point"),
    ("blind-v4-clean-entry-00376", "critical_operation"),
}


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sensitivity_score(reports: list[dict], reference: list[dict]) -> dict:
    predictions = {row["case_id"]: row.get("fields", {}) for row in reports}
    total = correct = observed = expected_bad = predicted_bad = true_bad = 0
    for row in reference:
        case_id = row["case_id"]
        for field, expected in row["labels"].items():
            if (case_id, field) in SENSITIVITY_EXCLUSIONS:
                continue
            total += 1
            item = predictions.get(case_id, {}).get(field)
            predicted = item.get("status") if isinstance(item, dict) else None
            if expected == "incorrect":
                expected_bad += 1
            if predicted in {"correct", "incorrect", "uncertain"}:
                observed += 1
                correct += predicted == expected
                if predicted == "incorrect":
                    predicted_bad += 1
                    true_bad += expected == "incorrect"
    precision = true_bad / predicted_bad if predicted_bad else None
    recall = true_bad / expected_bad if expected_bad else None
    return {
        "labels": total,
        "excluded_labels": len(SENSITIVITY_EXCLUSIONS),
        "accuracy": correct / total if total else None,
        "observed_accuracy": correct / observed if observed else None,
        "missing_predictions": total - observed,
        "incorrect_precision": precision,
        "incorrect_recall": recall,
        "incorrect_f1": 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly spend API quota for the one frozen attempt")
    args = parser.parse_args()
    os.chdir(ROOT)
    manifest = json.loads(Path("artifacts/blind-v4/evidence-manifest.json").read_text())
    for name, expected in manifest["sha256"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Frozen input changed: {name}")
    base = manifest["semantic_behavior_base_commit"]
    if subprocess.check_output(["git", "diff", base, "--", "src", "configs/provider.deepseek.json"]):
        raise SystemExit("Production behavior differs from the frozen behavior commit")
    selection = json.loads(Path("configs/blind-v4-selection.json").read_text())
    packets = [row for _, row in read_jsonl(Path("out/blind-v4/evidence.jsonl"))]
    if len(packets) != 8 or len({p["entry_id"] for p in packets}) != 8:
        raise SystemExit("Expected eight unique frozen cases")
    print("Frozen-input and production-behavior preflight passed; 8 cases.", flush=True)
    if not args.run:
        return 0
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise SystemExit("Commit the freeze first; evaluation requires a clean worktree")
    subprocess.run(["git", "ls-files", "--error-unmatch", "artifacts/blind-v4/evidence-manifest.json"], check=True, stdout=subprocess.DEVNULL)
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise SystemExit("Load DEEPSEEK_API_KEY locally before --run; never paste it into logs")
    settings = selection["run_settings"]
    os.environ.update({
        "VULNGYM_DEEPSEEK_ENABLED": "true",
        "VULNGYM_DEEPSEEK_MODEL": settings["model"],
        "VULNGYM_DEEPSEEK_REASONING_EFFORT": settings["reasoning_effort"],
        "VULNGYM_DEEPSEEK_MAX_TOKENS": str(settings["max_output_tokens"]),
        "VULNGYM_DEEPSEEK_BASE_URL": "https://api.deepseek.com",
        "VULNGYM_DEEPSEEK_TIMEOUT_SECONDS": "180",
    })
    # JsonCommandProvider launches a fresh Python process. sys.path changes in
    # this runner do not cross that process boundary, so pass src explicitly.
    current_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(ROOT / "src") + (os.pathsep + current_pythonpath if current_pythonpath else "")
    output = Path("out/blind-v4-run")
    output.mkdir(parents=True, exist_ok=False)  # never silently replace a previous attempt
    save(output / "start.json", {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "freeze_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "settings": settings,
        "manifest_sha256": hashlib.sha256(Path("artifacts/blind-v4/evidence-manifest.json").read_bytes()).hexdigest(),
    })
    started = time.perf_counter()

    def run_one(packet: dict) -> dict:
        print(f"Starting {packet['entry_id']}", flush=True)
        try:
            result = run_judge_critic(packet, load_provider(Path(settings["provider_config"])), use_critic=True)
        except Exception as exc:
            # Preserve the failure without echoing arbitrary exception content or local credentials.
            result = {"entry_id": packet["entry_id"], "case_id": packet["case_id"],
                      "status": "runner_error", "error_type": type(exc).__name__}
        write_jsonl(output / f"{packet['entry_id']}.jsonl", [result])
        print(f"Finished {packet['entry_id']}: {result['status']}", flush=True)
        return result

    results = {}
    with ThreadPoolExecutor(max_workers=settings["concurrency"]) as pool:
        for future in as_completed([pool.submit(run_one, packet) for packet in packets]):
            row = future.result()
            results[row["entry_id"]] = row
    ordered = [results[p["entry_id"]] for p in packets]
    write_jsonl(output / "semantic.jsonl", ordered)
    # Reference labels enter only the scorer, AFTER every model request has finished.
    reference = [row for _, row in read_jsonl(Path("out/blind-v4/reference.jsonl"))]
    reports = [build_submission_report(p, results[p["entry_id"]]) for p in packets]
    judge_reports = [build_submission_report(p, {"judgment": results[p["entry_id"]].get("judgment")}) for p in packets]
    write_jsonl(output / "submission.jsonl", reports)
    write_jsonl(output / "judge-submission.jsonl", judge_reports)
    final_score = evaluate_submission_reports(reports, reference)
    judge_score = evaluate_submission_reports(judge_reports, reference)
    save(output / "evaluation.json", final_score)
    save(output / "judge-evaluation.json", judge_score)
    completed = {r["entry_id"] for r in ordered if r["status"] in {"completed", "completed_with_repair"}}
    strict_score = evaluate_submission_reports([r for r in reports if r["entry_id"] in completed], reference)
    save(output / "completed-only-evaluation.json", strict_score)
    save(output / "reference-sensitivity.json", sensitivity_score(reports, reference))
    summary = summarize_semantic_results(ordered)
    summary["wall_seconds"] = round(time.perf_counter() - started, 3)
    summary["resource_caveat"] = "Provider metadata may omit tokens for failed transport attempts; totals are observable usage, not a billing total."
    save(output / "semantic-summary.json", summary)
    print(json.dumps({"completed": len(completed), "cases": len(packets), "metrics": final_score["metrics"],
                      "judge_metrics": judge_score["metrics"], "strict_missing_predictions": strict_score["metrics"]["missing_predictions"]}, ensure_ascii=False, indent=2), flush=True)
    return 0 if len(completed) == len(packets) else 2


if __name__ == "__main__":
    raise SystemExit(main())
