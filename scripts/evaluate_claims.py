"""Frozen, paired development evaluation. No target program is executed."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
import zipfile

from vulngym_agent.provider import ProviderError, load_provider
from vulngym_evidence.contract import validate_request
from vulngym_evidence.workflow import PROMPT, _schema, _validate_output, verify_request

ROOT = Path(__file__).resolve().parents[1]
BASELINE_NOTE = (
    " This is the report-only comparison arm. The attached excerpts are supplied by the "
    "report author, NOT checked against Git. You have no repository tools. Assess only what "
    "these excerpts actually establish and use uncertain when verification or context is absent. "
    "Do not assume a function body, deployment state or whole call chain from a function name."
)
CRITIC_NOTE = " Independently review the original claims and evidence, actively looking for unsupported acceptance or rejection. No initial judgment is provided; reach your own conclusions."


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def tracked_inputs(manifest_path):
    paths = list((ROOT / "src").rglob("*.py"))
    paths += [ROOT / "scripts/evaluate_claims.py", ROOT / "docs/EVALUATION_PROTOCOL.md",
              ROOT / "configs/provider.qwen.json", ROOT / "pyproject.toml", manifest_path]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(paths))}


def freeze(manifest_path, directory):
    if directory.exists():
        raise ValueError("Freeze directory already exists")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ids = [case["request"]["case_id"] for case in manifest["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate cases")
    for case in manifest["cases"]:
        validate_request(case["request"])
        if len(case["request"]["claims"]) != 1 or case["expected"] not in {"supported", "contradicted", "uncertain"}:
            raise ValueError("Evaluation requires one claim and a reference label per case")
    hashes = tracked_inputs(manifest_path)
    directory.mkdir(parents=True)
    write_json(directory / "manifest.json", manifest)
    write_json(directory / "freeze.json", {
        "created_at": datetime.now(timezone.utc).isoformat(), "manifest_sha256": digest(manifest),
        "inputs_sha256": hashes, "model": "qwen3.8-flash", "max_provider_attempts": len(ids) * 4,
        "policy": "No retries or tuning until all first-pass paired predictions are saved; author-reviewed development cases, not blind external gold."
    })
    with zipfile.ZipFile(directory / "source-snapshot.zip", "x", zipfile.ZIP_DEFLATED) as archive:
        for relative in hashes:
            archive.write(ROOT / relative, relative)
    print(json.dumps({"frozen_cases": len(ids), "manifest_sha256": digest(manifest)}, ensure_ascii=False), flush=True)


class Recorder:
    def __init__(self, provider, directory):
        self.provider, self.name, self.directory = provider, provider.name, directory
        self.calls = []

    def complete(self, payload):
        if len(self.calls) >= 2:
            raise ProviderError("Two-call budget exhausted")
        row = {"role": payload["role"], "input_sha256": digest(payload), "input": deepcopy(payload)}
        self.calls.append(row)
        before = time.monotonic()
        try:
            result = self.provider.complete(payload)
            row.update(output=result.output, metadata=result.metadata, status="returned")
            return result
        except ProviderError as exc:
            row.update(status="failed", error_type=type(exc).__name__)
            raise
        finally:
            row["elapsed_seconds"] = round(time.monotonic() - before, 3)
            write_json(self.directory / "calls.json", self.calls)


def baseline_review(request, provider):
    request = validate_request(request)
    claim = request["claims"][0]
    ref = "report-excerpt:" + claim["claim_id"]
    # source is the comparison validator's syntactic category only; provenance
    # explicitly says it is an unverified author-provided excerpt, never Git evidence.
    evidence = [{"evidence_id": ref, "kind": "source", "status": "available",
                 "provenance": "unverified report excerpt; no Git or source lookup",
                 "node": claim.get("node"), "nodes": claim.get("nodes")}]
    pending = [{"claim": claim, "evidence_refs": [ref]}]
    payload = {"role": "judge", "prompt_version": "report-only-1.0", "instructions": PROMPT + BASELINE_NOTE,
               "case_id": request["case_id"], "repo_url": request["repo_url"],
               "reviewed_commit": request["reviewed_commit"], "vuln_ids": request["vuln_ids"],
               "claims": request["claims"], "allowed_refs_by_claim": {claim["claim_id"]: [ref]},
               "evidence": evidence, "output_schema": _schema([claim["claim_id"]], [ref])}
    before = time.monotonic()
    try:
        first = _validate_output(provider.complete(payload).output, pending, evidence)[claim["claim_id"]]
        result = first
        status = "judge_completed"
        if first["verdict"] != "uncertain":
            critic_payload = {**payload, "role": "critic", "instructions": payload["instructions"] + CRITIC_NOTE}
            second = _validate_output(provider.complete(critic_payload).output, pending, evidence)[claim["claim_id"]]
            status = "judge_critic_completed"
            if first["verdict"] != second["verdict"]:
                result = {**first, "verdict": "uncertain", "confidence": 0.0,
                          "reason": "主审与独立复核分歧", "basis": "arbitration"}
            else:
                result = {**first, "confidence": min(first["confidence"], second["confidence"]), "basis": "judge_critic"}
        return {"semantic_status": status, "results": [result], "elapsed_seconds": round(time.monotonic() - before, 3)}
    except (ProviderError, ValueError, TypeError, KeyError) as exc:
        return {"semantic_status": "model_or_contract_failed", "error_type": type(exc).__name__,
                "results": [], "elapsed_seconds": round(time.monotonic() - before, 3)}


def metrics(rows):
    def count(test):
        return sum(test(row) for row in rows)
    decisive = count(lambda row: row["prediction"] in {"supported", "contradicted"})
    return {"n": len(rows), "correct": count(lambda row: row["prediction"] == row["expected"]),
            "decisive": decisive, "decisive_correct": count(lambda row: row["prediction"] == row["expected"] and row["prediction"] != "uncertain"),
            "abstentions": count(lambda row: row["prediction"] == "uncertain"),
            "errors": count(lambda row: row["prediction"] == "error"),
            "false_accepts": count(lambda row: row["expected"] == "contradicted" and row["prediction"] == "supported"),
            "contradicted_references": count(lambda row: row["expected"] == "contradicted"),
            "wrong_rejections": count(lambda row: row["expected"] == "supported" and row["prediction"] == "contradicted"),
            "unsupported_decisions": count(lambda row: row["expected"] == "uncertain" and row["prediction"] in {"supported", "contradicted"})}


def score(directory):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    rows, totals = [], {}
    for arm in ("report_only", "evidence_workflow"):
        calls, tokens, elapsed = 0, 0, 0.0
        for case in manifest["cases"]:
            cid = case["request"]["case_id"]
            result = json.loads((directory / "predictions" / cid / arm / "result.json").read_text(encoding="utf-8"))
            attempts = json.loads((directory / "predictions" / cid / arm / "calls.json").read_text(encoding="utf-8"))
            prediction = ("error" if result["semantic_status"] == "model_or_contract_failed" else result["results"][0]["verdict"])
            rows.append({"case_id": cid, "arm": arm, "stratum": case["stratum"], "expected": case["expected"],
                         "prediction": prediction, "reason": result["results"][0]["reason"] if result["results"] else "调用或输出合同失败",
                         "semantic_status": result["semantic_status"]})
            calls += len(attempts)
            tokens += sum(c.get("metadata", {}).get("usage", {}).get("total_tokens", 0) for c in attempts)
            elapsed += result["elapsed_seconds"]
        totals[arm] = {"provider_attempts": calls, "returned_tokens": tokens, "sum_elapsed_seconds": round(elapsed, 3)}
    scored = {arm: {stratum: metrics([r for r in rows if r["arm"] == arm and (stratum == "all" or r["stratum"] == stratum)])
                   for stratum in ("semantic", "control", "all")} for arm in totals}
    write_json(directory / "score.json", {"metrics": scored, "cost": totals, "rows": rows})
    print(json.dumps({"metrics": scored, "cost": totals}, ensure_ascii=False, indent=2), flush=True)


def run(directory, repository_root, provider_config):
    frozen = json.loads((directory / "freeze.json").read_text(encoding="utf-8"))
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if digest(manifest) != frozen["manifest_sha256"]:
        raise ValueError("Frozen manifest changed")
    for relative, expected in frozen["inputs_sha256"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            raise ValueError("Frozen implementation changed: " + relative)
    if os.environ.get("VULNGYM_QWEN_MODEL") != frozen["model"]:
        raise ValueError("Model must match frozen configuration")
    predictions = directory / "predictions"
    predictions.mkdir(exist_ok=False)
    configured = load_provider(provider_config)
    write_json(directory / "run-environment.json", {"started_at": datetime.now(timezone.utc).isoformat(),
        "model": os.environ.get("VULNGYM_QWEN_MODEL"), "enable_thinking": os.environ.get("VULNGYM_QWEN_ENABLE_THINKING", "false"),
        "max_tokens": os.environ.get("VULNGYM_QWEN_MAX_TOKENS"), "network": "Qwen API only; no target code execution"})
    for index, case in enumerate(manifest["cases"]):
        cid = case["request"]["case_id"]
        arms = ("report_only", "evidence_workflow") if index % 2 == 0 else ("evidence_workflow", "report_only")
        for arm in arms:
            target = predictions / cid / arm
            target.mkdir(parents=True)
            recorder = Recorder(configured, target)
            print(f"[{index + 1}/{len(manifest['cases'])}] {cid} / {arm}", flush=True)
            if arm == "report_only":
                result = baseline_review(case["request"], recorder)
            else:
                result = verify_request(case["request"], roots=[repository_root], provider=recorder)
            write_json(target / "result.json", result)
            write_json(target / "calls.json", recorder.calls)
            print(json.dumps({"status": result["semantic_status"], "verdicts": [r["verdict"] for r in result["results"]],
                              "calls": len(recorder.calls)}, ensure_ascii=False), flush=True)
    score(directory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "run", "score"))
    parser.add_argument("--manifest", type=Path, default=ROOT / "configs/evidence/eval-v1/manifest.json")
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--repositories-root", type=Path, default=Path("/home/sam/rhinobird/vulngym-repos"))
    parser.add_argument("--provider-config", type=Path, default=ROOT / "configs/provider.qwen.json")
    args = parser.parse_args()
    if args.action == "freeze":
        freeze(args.manifest, args.directory)
    elif args.action == "run":
        run(args.directory, args.repositories_root, args.provider_config)
    else:
        score(args.directory)


if __name__ == "__main__":
    main()
