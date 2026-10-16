#!/usr/bin/env python3
"""Run offline checks required before packaging the VulnGym Agent submission."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vulngym_agent.jsonl import read_jsonl
from vulngym_agent.submission import build_submission_report, validate_submission_report
from vulngym_agent.submission_evaluation import evaluate_submission_reports
from vulngym_agent.systemic_analysis import analyze_systemic_patterns

REQUIRED_PATHS = (
    "README.md",
    "SUBMISSION_OVERVIEW.md",
    "LICENSE",
    "pyproject.toml",
    "src/vulngym_agent/cli.py",
    "src/vulngym_agent/deepseek_provider.py",
    "src/vulngym_agent/qwen_provider.py",
    "src/vulngym_agent/advisory_fetch.py",
    "src/vulngym_agent/lifecycle_inspector.py",
    "src/vulngym_agent/readable_report.py",
    "src/vulngym_agent/systemic_analysis.py",
    ".github/workflows/ci.yml",
    "scripts/build_final_submission.py",
    "scripts/verify_clean_archive.sh",
    "scripts/run_deepseek_demo.sh",
    "scripts/run_recording_demo.sh",
    "configs/provider.deepseek.json",
    "configs/provider.qwen.json",
    "configs/demo/weknora.jsonl",
    "configs/demo/weknora-fix.json",
    "artifacts/demo/weknora.json",
    "docs/ARCHITECTURE.md",
    "docs/DESIGN_SUMMARY.md",
    "docs/INDEX.md",
    "docs/AI_CODING_LOG.md",
    "docs/EXPERIMENT_LOG.md",
    "docs/REPO_HOLDOUT_EVALUATION.md",
    "docs/BLIND_EVALUATION_V2.md",
    "docs/BLIND_V2_REVIEW_SHEET.md",
    "docs/BLIND_EVALUATION_V3.md",
    "docs/BLIND_V3_REVIEW_SHEET.md",
    "docs/BLIND_EVALUATION_V4.md",
    "docs/ROBUSTNESS_MATRIX.md",
    "docs/DEMO_SCRIPT.md",
    "docs/SUBMISSION_CHECKLIST.md",
    "tests/test_systemic_analysis.py",
    "artifacts/repo-holdout-v1/summary.json",
    "artifacts/blind-v2/manifest.json",
    "artifacts/blind-v2/evidence-manifest.json",
    "artifacts/blind-v2/result-summary.json",
    "configs/blind-v2-selection.json",
    "configs/blind-v2-fixes.json",
    "configs/advisories/blind-v2.jsonl",
    "artifacts/blind-v3/manifest.json",
    "artifacts/blind-v3/evidence-manifest.json",
    "artifacts/blind-v3/result-summary.json",
    "artifacts/post-v3-targeted-v14/summary.json",
    "configs/blind-v3-selection.json",
    "configs/blind-v3-fixes.json",
    "configs/advisories/blind-v3.jsonl",
    "artifacts/blind-v4/evidence-manifest.json",
    "configs/blind-v4-selection.json",
    "configs/blind-v4-fixes.json",
    "configs/advisories/blind-v4.jsonl",
    "scripts/run_blind_v4.py",
    "artifacts/blind-v5/evidence-manifest.json",
    "artifacts/blind-v5/result-summary.json",
    "configs/blind-v5-selection.json",
    "configs/blind-v5-fixes.json",
    "scripts/run_blind_v5.py",
    "artifacts/blind-v6/evidence-manifest.json",
    "artifacts/blind-v6/result-summary.json",
    "artifacts/blind-v6/repro/reference.jsonl",
    "artifacts/blind-v6/repro/submission.jsonl",
    "artifacts/blind-v6/repro/evaluation.json",
    "artifacts/blind-v6/repro/semantic.jsonl",
    "artifacts/blind-v6/repro/semantic-summary.json",
    "artifacts/blind-v6/repro/judge-evaluation.json",
    "artifacts/blind-v6/repro/evidence.jsonl",
    "artifacts/post-v6-provenance-hardening/evidence.jsonl",
    "artifacts/post-v6-provenance-hardening/submission.jsonl",
    "artifacts/post-v6-provenance-hardening/evaluation.json",
    "artifacts/post-v6-provenance-hardening/summary.json",
    "configs/blind-v6-selection.json",
    "docs/BLIND_EVALUATION_V6.md",
    "docs/POST_V6_PROVENANCE_HARDENING.md",
    "scripts/run_blind_v6.py",
    "docs/COST_AND_LATENCY.md",
    "configs/final-blind-v1-selection.json",
    "configs/final-blind-v1-fixes.json",
    "scripts/run_final_blind_v1.py",
    "artifacts/final-blind-v1/evidence-manifest.json",
    "artifacts/final-blind-v1/result-manifest.json",
    "artifacts/final-blind-v1/reference.jsonl",
    "artifacts/final-blind-v1/semantic.jsonl",
    "artifacts/final-blind-v1/submission.jsonl",
    "artifacts/final-blind-v1/evaluation.json",
    "artifacts/final-blind-v1/report/report.md",
    "artifacts/final-blind-v1/report/report.html",
    "artifacts/final-blind-v1/systemic-analysis.json",
    "artifacts/final-blind-v1/systemic-analysis.md",
)
EXPECTED_FIELDS = {
    "entry_point",
    "critical_operation",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_title",
    "vuln_ids",
    "commit",
    "trace",
}


def check_required_paths() -> list[str]:
    return [relative for relative in REQUIRED_PATHS if not (ROOT / relative).is_file()]


def check_demo_artifact() -> list[str]:
    path = ROOT / "artifacts" / "demo" / "weknora.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read demo artifact: {exc}"]
    errors: list[str] = []
    if data.get("case", {}).get("entry_id") != "entry-00080":
        errors.append("demo entry_id is not entry-00080")
    if set(data.get("final_report", {})) != EXPECTED_FIELDS:
        errors.append("demo final_report does not contain exactly eight T1 fields")
    if data.get("result") != "incorrect":
        errors.append("demo overall result is not incorrect")
    return errors


def check_systemic_analysis_artifact() -> list[str]:
    runs_path = ROOT / "artifacts" / "final-blind-v1" / "runs.jsonl"
    report_path = ROOT / "artifacts" / "final-blind-v1" / "systemic-analysis.json"
    try:
        expected = analyze_systemic_patterns(row for _, row in read_jsonl(runs_path))
        retained = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"cannot verify systemic analysis artifact: {exc}"]
    return [] if retained == expected else ["final blind systemic analysis artifact does not match retained runs"]


def check_holdout_artifact() -> list[str]:
    path = ROOT / "artifacts" / "repo-holdout-v1" / "summary.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read repo holdout artifact: {exc}"]
    errors: list[str] = []
    if data.get("repositories") != 10 or data.get("target_labels") != 12:
        errors.append("repo holdout dimensions are not 10 repositories / 12 target labels")
    detection = data.get("target_detection", {})
    if detection.get("bare_record", {}).get("detected") != 9:
        errors.append("repo holdout bare-record result is not 9/12")
    if detection.get("evidence_judge_critic_arbitrated", {}).get("detected") != 12:
        errors.append("repo holdout final Agent result is not 12/12")
    return errors


def check_blind_v2_artifact() -> list[str]:
    path = ROOT / "artifacts" / "blind-v2" / "result-summary.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read Blind v2 result artifact: {exc}"]
    errors: list[str] = []
    if data.get("cases") != 10 or data.get("labels") != 80:
        errors.append("Blind v2 dimensions are not 10 cases / 80 labels")
    metrics = data.get("metrics", {})
    if metrics.get("accuracy") != 0.7375 or metrics.get("missing_predictions") != 0:
        errors.append("Blind v2 retained result is not the frozen 59/80 complete run")
    if "provisional reference" not in str(data.get("reference_status", "")):
        errors.append("Blind v2 result does not disclose provisional reference status")
    return errors


def check_blind_v3_freeze() -> list[str]:
    manifest_path = ROOT / "artifacts" / "blind-v3" / "manifest.json"
    evidence_path = ROOT / "artifacts" / "blind-v3" / "evidence-manifest.json"
    selection_path = ROOT / "configs" / "blind-v3-selection.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        selection = json.loads(selection_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read Blind v3 freeze artifacts: {exc}"]
    errors: list[str] = []
    counts = manifest.get("counts", {})
    if counts.get("cases") != 13 or counts.get("labels") != 104 or counts.get("reviewed_cases") != 13:
        errors.append("Blind v3 dimensions are not 13 reviewed cases / 104 labels")
    if counts.get("incorrect") != 14 or counts.get("uncertain") != 3:
        errors.append("Blind v3 reviewed label distribution drifted")
    if selection.get("selection_status") != "frozen":
        errors.append("Blind v3 selection is not frozen")
    if evidence.get("model_runs_started") is not False:
        errors.append("Blind v3 pre-run evidence manifest does not preserve the no-model boundary")
    if evidence.get("semantic_behavior_base_commit") != manifest.get("semantic_behavior_base_commit"):
        errors.append("Blind v3 behavior commit differs across manifests")
    return errors


def check_blind_v3_result() -> list[str]:
    path = ROOT / "artifacts" / "blind-v3" / "result-summary.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read Blind v3 result artifact: {exc}"]
    errors: list[str] = []
    if data.get("cases") != 13 or data.get("labels") != 104:
        errors.append("Blind v3 dimensions are not 13 cases / 104 labels")
    metrics = data.get("metrics", {})
    if metrics.get("correct_predictions") != 70 or metrics.get("missing_predictions") != 0:
        errors.append("Blind v3 retained result is not the frozen 70/104 complete run")
    if not str(data.get("run_policy", "")).startswith("single frozen run"):
        errors.append("Blind v3 result does not preserve its single-run policy")
    return errors


def check_post_v3_targeted_result() -> list[str]:
    path = ROOT / "artifacts" / "post-v3-targeted-v14" / "summary.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read post-v3 targeted result: {exc}"]
    errors: list[str] = []
    if data.get("development_only") is not True or data.get("independent_blind_test") is not False:
        errors.append("post-v3 targeted result does not disclose its development-only status")
    agreement = data.get("agreement", {})
    if agreement.get("matched") != 31 or agreement.get("total") != 32:
        errors.append("post-v3 targeted result is not the retained 31/32 run")
    return errors


def check_blind_v5_result() -> list[str]:
    path = ROOT / "artifacts" / "blind-v5" / "result-summary.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read Blind v5 result artifact: {exc}"]
    errors: list[str] = []
    if data.get("cases") != 6 or data.get("labels") != 48:
        errors.append("Blind v5 dimensions are not 6 cases / 48 labels")
    metrics = data.get("metrics", {})
    if metrics.get("correct_predictions") != 26 or metrics.get("missing_predictions") != 0:
        errors.append("Blind v5 retained result is not the frozen 26/48 complete run")
    usage = data.get("usage", {})
    if usage.get("total_tokens") != 101099 or usage.get("judge_critic_changed_cases") != 0:
        errors.append("Blind v5 retained usage or Critic delta drifted")
    diagnostic = data.get("post_v5_source_policy_diagnostic", {})
    if diagnostic.get("independent_blind_test") is not False or diagnostic.get("model_calls") != 0:
        errors.append("post-v5 diagnostic does not disclose its non-blind zero-call status")
    return errors


def check_blind_v6_result() -> list[str]:
    summary_path = ROOT / "artifacts" / "blind-v6" / "result-summary.json"
    manifest_path = ROOT / "artifacts" / "blind-v6" / "evidence-manifest.json"
    repro_dir = ROOT / "artifacts" / "blind-v6" / "repro"
    ref_path = repro_dir / "reference.jsonl"
    sub_path = repro_dir / "submission.jsonl"
    eval_path = repro_dir / "evaluation.json"
    sem_path = repro_dir / "semantic.jsonl"
    sem_sum_path = repro_dir / "semantic-summary.json"
    judge_eval_path = repro_dir / "judge-evaluation.json"
    evidence_path = repro_dir / "evidence.jsonl"

    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read Blind v6 manifest or summary: {exc}"]

    errors: list[str] = []

    # A. Static summary assertion checks
    if data.get("cases") != 8 or data.get("labels") != 64:
        errors.append("Blind v6 dimensions are not 8 cases / 64 labels")
    metrics = data.get("metrics", {})
    if metrics.get("correct_predictions") != 62 or metrics.get("incorrect_recall") != 1.0:
        errors.append("Blind v6 retained result is not the frozen 62/64 complete run")
    usage = data.get("usage", {})
    if usage.get("physical_api_attempts") != 10 or usage.get("critic_calls") != 2:
        errors.append("Blind v6 retained bounded-call result drifted")
    limits = data.get("limits", {})
    if limits.get("not_official_hidden_test") is not True or limits.get("not_independent_expert_gold") is not True:
        errors.append("Blind v6 result does not disclose evaluation limits")

    # B. Hash provenance checks against frozen manifests
    manifest_sha = manifest.get("sha256", {})
    summary_sha = data.get("sha256", {})

    expected_hashes = [
        (evidence_path, manifest_sha.get("out/blind-v6/evidence-final.jsonl"), "evidence artifact"),
        (ref_path, manifest_sha.get("out/blind-v6/reference.jsonl"), "reference artifact"),
        (sub_path, summary_sha.get("submission"), "submission artifact"),
        (eval_path, summary_sha.get("evaluation"), "evaluation artifact"),
        (sem_path, summary_sha.get("semantic_results"), "semantic artifact"),
        (sem_sum_path, summary_sha.get("semantic_summary"), "semantic-summary artifact"),
        (judge_eval_path, summary_sha.get("judge_evaluation"), "judge-evaluation artifact"),
    ]

    for path, expected_hash, label in expected_hashes:
        if not path.is_file():
            errors.append(f"missing {label}: {path}")
            continue
        if not expected_hash:
            errors.append(f"missing frozen hash specification for {label}")
            continue
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"{label} SHA256 mismatch: expected {expected_hash}, got {actual_hash}")

    # C. Dynamic recomputation from raw repro artifacts
    if ref_path.is_file() and sub_path.is_file():
        try:
            reports = [row for _, row in read_jsonl(sub_path)]
            reference = [row for _, row in read_jsonl(ref_path)]
            recomputed = evaluate_submission_reports(reports, reference)
        except Exception as exc:
            errors.append(f"Blind v6 dynamic evaluation failed: {exc}")
            return errors

        r_totals = recomputed.get("totals", {})
        r_metrics = recomputed.get("metrics", {})

        if r_totals.get("reference_cases") != 8:
            errors.append(f"recomputed reference_cases expected 8, got {r_totals.get('reference_cases')}")
        if r_totals.get("labels") != 64:
            errors.append(f"recomputed labels expected 64, got {r_totals.get('labels')}")
        if r_metrics.get("missing_predictions") != 0:
            errors.append(f"recomputed missing_predictions expected 0, got {r_metrics.get('missing_predictions')}")

        acc = r_metrics.get("accuracy")
        if not isinstance(acc, (int, float)) or not math.isclose(acc, 62 / 64, rel_tol=1e-9):
            errors.append(f"recomputed accuracy expected 62/64 (~0.96875), got {acc}")

        recall = r_metrics.get("incorrect_recall")
        if not isinstance(recall, (int, float)) or not math.isclose(recall, 1.0, rel_tol=1e-9):
            errors.append(f"recomputed incorrect_recall expected 1.0, got {recall}")

        prec = r_metrics.get("incorrect_precision")
        if not isinstance(prec, (int, float)) or not math.isclose(prec, 10 / 11, rel_tol=1e-9):
            errors.append(f"recomputed incorrect_precision expected 10/11 (~0.90909), got {prec}")

        exact = r_metrics.get("case_exact_match")
        if not isinstance(exact, (int, float)) or not math.isclose(exact, 6 / 8, rel_tol=1e-9):
            errors.append(f"recomputed case_exact_match expected 6/8 (0.75), got {exact}")

        if eval_path.is_file():
            try:
                persisted_eval = json.loads(eval_path.read_text(encoding="utf-8"))
                if recomputed != persisted_eval:
                    errors.append("recomputed evaluation dict does not match persisted evaluation.json")
            except Exception as exc:
                errors.append(f"failed reading persisted evaluation.json for dict comparison: {exc}")

    return errors


def check_post_v6_provenance_result() -> list[str]:
    root = ROOT / "artifacts" / "post-v6-provenance-hardening"
    evidence_path = root / "evidence.jsonl"
    submission_path = root / "submission.jsonl"
    evaluation_path = root / "evaluation.json"
    summary_path = root / "summary.json"
    semantic_path = ROOT / "artifacts" / "blind-v6" / "repro" / "semantic.jsonl"
    reference_path = ROOT / "artifacts" / "blind-v6" / "repro" / "reference.jsonl"
    baseline_path = ROOT / "artifacts" / "blind-v6" / "repro" / "submission.jsonl"
    errors: list[str] = []

    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        persisted_evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        evidence_rows = [row for _, row in read_jsonl(evidence_path)]
        semantic_rows = {
            str(row.get("entry_id")): row
            for _, row in read_jsonl(semantic_path)
            if row.get("entry_id") is not None
        }
        persisted_submission = [row for _, row in read_jsonl(submission_path)]
        reference_rows = [row for _, row in read_jsonl(reference_path)]
        baseline_rows = [row for _, row in read_jsonl(baseline_path)]
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"cannot read post-v6 provenance artifacts: {exc}"]

    if summary.get("development_only") is not True or summary.get("independent_blind_test") is not False:
        errors.append("post-v6 provenance replay does not disclose its development-only status")
    if summary.get("model_calls") != 0:
        errors.append("post-v6 provenance replay is not recorded as a zero-model-call run")

    hashes = summary.get("sha256", {})
    for path, expected, label in (
        (evidence_path, hashes.get("evidence"), "post-v6 evidence"),
        (semantic_path, hashes.get("semantic"), "frozen semantic"),
        (submission_path, hashes.get("submission"), "post-v6 submission"),
        (reference_path, hashes.get("reference"), "frozen reference"),
        (evaluation_path, hashes.get("evaluation"), "post-v6 evaluation"),
    ):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if not expected or actual != expected:
            errors.append(f"{label} SHA256 mismatch: expected {expected}, got {actual}")

    recomputed_submission = []
    for packet in evidence_rows:
        entry_id = str(packet.get("entry_id"))
        if packet.get("packet_version") != "0.9.0":
            errors.append(f"post-v6 evidence {entry_id} is not Packet 0.9.0")
        provenance = packet.get("patch_analysis", {}).get("provenance_status")
        if provenance not in {"verified", "supported", "weak"}:
            errors.append(f"post-v6 evidence {entry_id} has invalid provenance status: {provenance}")
        report = build_submission_report(packet, semantic_rows.get(entry_id))
        validation_errors = validate_submission_report(report)
        if validation_errors:
            errors.append(f"recomputed post-v6 report {entry_id} is invalid: {'; '.join(validation_errors)}")
        recomputed_submission.append(report)
    if recomputed_submission != persisted_submission:
        errors.append("recomputed post-v6 submission does not match persisted submission.jsonl")

    recomputed_evaluation = evaluate_submission_reports(recomputed_submission, reference_rows)
    if recomputed_evaluation != persisted_evaluation:
        errors.append("recomputed post-v6 evaluation does not match persisted evaluation.json")
    metrics = recomputed_evaluation.get("metrics", {})
    expected_metrics = {
        "accuracy": 59 / 64,
        "incorrect_precision": 10 / 11,
        "incorrect_recall": 1.0,
        "case_exact_match": 3 / 8,
        "abstention_rate": 4 / 64,
    }
    for name, expected in expected_metrics.items():
        actual = metrics.get(name)
        if not isinstance(actual, (int, float)) or not math.isclose(actual, expected, rel_tol=1e-9):
            errors.append(f"post-v6 {name} expected {expected}, got {actual}")
    if metrics.get("missing_predictions") != 0:
        errors.append("post-v6 replay has missing predictions")

    baseline_by_id = {str(row.get("entry_id")): row for row in baseline_rows}
    hardened_by_id = {str(row.get("entry_id")): row for row in persisted_submission}
    changed = {
        entry_id
        for entry_id in baseline_by_id.keys() & hardened_by_id.keys()
        if baseline_by_id[entry_id].get("fields", {}).get("commit", {}).get("status")
        != hardened_by_id[entry_id].get("fields", {}).get("commit", {}).get("status")
    }
    if changed != {"entry-00116", "entry-00172", "entry-00187"}:
        errors.append(f"unexpected post-v6 commit-field delta set: {sorted(changed)}")
    for entry_id in baseline_by_id.keys() & hardened_by_id.keys():
        baseline_fields = baseline_by_id[entry_id].get("fields", {})
        hardened_fields = hardened_by_id[entry_id].get("fields", {})
        for field in EXPECTED_FIELDS - {"commit"}:
            if baseline_fields.get(field) != hardened_fields.get(field):
                errors.append(f"post-v6 replay unexpectedly changed {entry_id}.{field}")
    for entry_id in ("entry-00116", "entry-00172", "entry-00187"):
        before = baseline_by_id.get(entry_id, {}).get("fields", {}).get("commit", {}).get("status")
        after = hardened_by_id.get(entry_id, {}).get("fields", {}).get("commit", {}).get("status")
        if before != "correct" or after != "uncertain":
            errors.append(f"post-v6 {entry_id}.commit expected correct -> uncertain, got {before} -> {after}")

    return errors


def check_final_blind_v1_result() -> list[str]:
    root = ROOT / "artifacts" / "final-blind-v1"
    errors: list[str] = []
    try:
        manifest = json.loads((root / "result-manifest.json").read_text(encoding="utf-8"))
        persisted = json.loads((root / "evaluation.json").read_text(encoding="utf-8"))
        reports = [row for _, row in read_jsonl(root / "submission.jsonl")]
        reference = [row for _, row in read_jsonl(root / "reference.jsonl")]
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"cannot read Final Blind v1 artifacts: {exc}"]
    if manifest.get("result_status") != "stopped_at_preregistered_call_cap":
        errors.append("Final Blind v1 does not preserve its call-cap stop status")
    if manifest.get("frozen_cases") != 5 or manifest.get("completed_cases") != 4:
        errors.append("Final Blind v1 dimensions are not 5 frozen / 4 completed")
    if manifest.get("physical_api_attempts") != 8 or manifest.get("no_score_driven_retry") is not True:
        errors.append("Final Blind v1 call cap or no-retry policy drifted")
    for relative, expected in manifest.get("sha256", {}).items():
        path = root / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f"Final Blind v1 result hash mismatch: {relative}")
    recomputed = evaluate_submission_reports(reports, reference)
    if recomputed != persisted:
        errors.append("Final Blind v1 evaluation does not match raw reports and reference")
    totals = recomputed.get("totals", {})
    metrics = recomputed.get("metrics", {})
    if totals.get("reference_cases") != 5 or totals.get("complete_cases") != 4:
        errors.append("Final Blind v1 recomputed case totals drifted")
    if metrics.get("missing_predictions") != 8 or not math.isclose(metrics.get("accuracy", -1), 27 / 40, rel_tol=1e-9):
        errors.append("Final Blind v1 retained result is not 27/40 with 8 missing predictions")
    return errors


def run_tests() -> int:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-t",
            ".",
            "-q",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        check=False,
    )
    return completed.returncode


def main() -> int:
    print(f"Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    if sys.version_info < (3, 10):
        print("DELIVERY CHECK: FAIL (Python 3.10+ required)")
        return 1

    errors = [f"missing required file: {path}" for path in check_required_paths()]
    errors.extend(check_demo_artifact())
    errors.extend(check_systemic_analysis_artifact())
    errors.extend(check_holdout_artifact())
    errors.extend(check_blind_v2_artifact())
    errors.extend(check_blind_v3_freeze())
    errors.extend(check_blind_v3_result())
    errors.extend(check_post_v3_targeted_result())
    errors.extend(check_blind_v5_result())
    errors.extend(check_blind_v6_result())
    errors.extend(check_post_v6_provenance_result())
    errors.extend(check_final_blind_v1_result())
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        print("DELIVERY CHECK: FAIL")
        return 1

    print(f"Required files: {len(REQUIRED_PATHS)}/{len(REQUIRED_PATHS)}")
    print("Demo artifact: PASS")
    print("Systemic analysis artifact: PASS")
    print("Repo holdout artifact: PASS")
    print("Blind v2 artifact: PASS")
    print("Blind v3 freeze: PASS")
    print("Blind v3 result: PASS")
    print("Post-v3 targeted result: PASS")
    print("Blind v5 result: PASS")
    print("Blind v6 result: PASS")
    print("Post-v6 provenance hardening replay: PASS")
    print("Final Blind v1 result: PASS")
    print("Unit tests:")
    if run_tests() != 0:
        print("DELIVERY CHECK: FAIL (unit tests)")
        return 1
    print("DELIVERY CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
