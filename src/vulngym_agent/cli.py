from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .advisory import load_advisory_cache
from .advisory_fetch import fetch_advisories
from .baseline import run_bare_record
from .benchmark import build_repo_holdout_mutations
from .blind_dataset import build_blind_dataset, write_blind_dataset
from .data_factory import generate_cases, write_dataset
from .engine import AuditEngine
from .evidence import load_fix_map, prepare_evidence_packets
from .evaluation import evaluate_audits, write_evaluation
from .history import HistoryError, generate_history_cases
from .jsonl import JsonlError, read_jsonl, write_jsonl
from .mutation_evaluation import compare_mutation_detection
from .provider import ProviderError, load_provider
from .repository import RepositoryError
from .repository_index import RepositoryResolver, build_repository_index, load_repository_map, write_repository_index
from .selection import load_selection, select_records
from .semantic_evaluation import evaluate_semantic_results, write_semantic_evaluation
from .semantic_report import summarize_semantic_results, write_semantic_report
from .semantic_runner import repair_persisted_result, run_critic_from_judgment, run_judge_critic
from .submission import build_submission_report, validate_submission_report
from .submission_evaluation import evaluate_submission_reports, write_submission_evaluation
from .systemic_analysis import write_systemic_analysis
from .workflow import COMPLETED_STATUSES, WORKFLOW_VERSION, run_validation_record
from .readable_report import write_readable_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulngym-agent", description="Evidence-first VulnGym audit agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="audit VulnGym JSONL records")
    audit.add_argument("--input", type=Path, required=True, help="candidate VulnGym entries JSONL")
    audit.add_argument("--output", type=Path, required=True, help="audit result JSONL")
    audit.add_argument("--repository", type=Path, help="local upstream Git repository for all input rows")
    audit.add_argument("--limit", type=int, help="process at most this many non-empty rows")

    dataset = subparsers.add_parser("build-dataset", help="build leak-resistant T1 development cases")
    dataset.add_argument("--input", type=Path, required=True, help="verified public VulnGym entries JSONL")
    dataset.add_argument("--output-dir", type=Path, required=True, help="directory for candidates and manifest")
    dataset.add_argument("--seed", type=int, default=20260819)
    dataset.add_argument("--split-unit", choices=("repo", "report"), default="repo")
    dataset.add_argument("--mutations-per-record", type=int, default=3)
    dataset.add_argument("--include-unverified", action="store_true")
    dataset.add_argument("--no-clean", action="store_true")

    evaluate = subparsers.add_parser("evaluate", help="score audit JSONL against a generated manifest")
    evaluate.add_argument("--audit", type=Path, required=True)
    evaluate.add_argument("--manifest", type=Path, required=True)
    evaluate.add_argument("--json-output", type=Path)

    history = subparsers.add_parser("mine-history", help="mine real before/after negatives from VulnGym Git refs")
    history.add_argument("--repository", type=Path, required=True, help="local VulnGym Git repository")
    history.add_argument("--reference-ref", default="v0.1.4", help="trusted target dataset ref")
    history.add_argument("--candidate-ref", action="append", dest="candidate_refs", help="older ref; repeatable")
    history.add_argument("--file-path", default="data/entries.jsonl")
    history.add_argument("--output-dir", type=Path, required=True)
    history.add_argument("--seed", type=int, default=20260819)
    history.add_argument("--split-unit", choices=("repo", "report"), default="repo")
    history.add_argument("--include-unverified", action="store_true")

    repository_index = subparsers.add_parser("index-repositories", help="map dataset repositories and required commits to local caches")
    repository_index.add_argument("--input", type=Path, required=True)
    repository_index.add_argument("--output", type=Path, required=True)
    repository_index.add_argument("--repositories-root", type=Path, action="append", default=[])
    repository_index.add_argument("--repository-map", type=Path)
    repository_index.add_argument("--verified-only", action="store_true")

    evidence = subparsers.add_parser("prepare-evidence", help="build source and patch evidence packets for semantic judges")
    evidence.add_argument("--input", type=Path, required=True)
    evidence.add_argument("--output", type=Path, required=True)
    evidence.add_argument("--repository", type=Path, help="one local repository for every input row")
    evidence.add_argument("--repositories-root", type=Path, action="append", default=[])
    evidence.add_argument("--repository-map", type=Path)
    evidence.add_argument("--fix-map", type=Path)
    evidence.add_argument("--advisory-cache", type=Path, action="append", default=[], help="offline advisory JSON/JSONL file or directory; repeatable")
    evidence.add_argument("--context-lines", type=int, default=12)
    evidence.add_argument("--limit", type=int)

    fetch_advisory = subparsers.add_parser(
        "fetch-advisories",
        help="optionally prepare a local advisory cache outside the formal validation path",
    )
    fetch_advisory.add_argument("--input", type=Path, required=True)
    fetch_advisory.add_argument("--output", type=Path, required=True)
    fetch_advisory.add_argument("--timeout", type=float, default=15.0)
    fetch_advisory.add_argument(
        "--allow-network",
        action="store_true",
        help="explicitly authorize bounded pre-run requests; do not use when organizer-provided caches are required",
    )

    selection = subparsers.add_parser("select-cases", help="materialize selected entry IDs from a VulnGym JSONL file")
    selection.add_argument("--input", type=Path, required=True)
    selection.add_argument("--selection", type=Path, required=True)
    selection.add_argument("--output", type=Path, required=True)

    semantic = subparsers.add_parser("run-semantic", help="run Judge and Critic through a JSON command provider")
    semantic.add_argument("--evidence", type=Path, required=True)
    semantic.add_argument("--output", type=Path, required=True)
    semantic.add_argument("--provider-config", type=Path, required=True)
    semantic.add_argument("--no-critic", action="store_true")
    semantic.add_argument("--critic-policy", choices=("always", "never", "review-risk"), default="always")
    semantic.add_argument("--limit", type=int)
    semantic.add_argument("--entry-id", action="append", dest="entry_ids", help="only run matching entry_id; repeatable")
    semantic.add_argument("--resume", action="store_true", help="reuse completed rows and atomically checkpoint each new row")

    critic = subparsers.add_parser("run-critic", help="run Critic from previously persisted Judge results")
    critic.add_argument("--evidence", type=Path, required=True)
    critic.add_argument("--judgments", type=Path, required=True)
    critic.add_argument("--output", type=Path, required=True)
    critic.add_argument("--provider-config", type=Path, required=True)
    critic.add_argument("--limit", type=int)
    critic.add_argument("--entry-id", action="append", dest="entry_ids", help="only run matching entry_id; repeatable")
    critic.add_argument("--resume", action="store_true", help="reuse completed rows and atomically checkpoint each new row")

    report = subparsers.add_parser("report-semantic", help="summarize Judge/Critic JSONL results")
    report.add_argument("--input", type=Path, action="append", required=True)
    report.add_argument("--output", type=Path, required=True)

    semantic_evaluation = subparsers.add_parser("evaluate-semantic", help="score Judge/Critic results against human gold")
    semantic_evaluation.add_argument(
        "--semantic",
        type=Path,
        action="append",
        required=True,
        help="semantic JSONL; repeatable and later rows replace earlier rows with the same case key",
    )
    semantic_evaluation.add_argument("--gold", type=Path, required=True)
    semantic_evaluation.add_argument("--output", type=Path, required=True)

    repair = subparsers.add_parser("repair-semantic", help="explicitly repair deterministic derived-field contract errors")
    repair.add_argument("--evidence", type=Path, required=True)
    repair.add_argument("--input", type=Path, required=True)
    repair.add_argument("--output", type=Path, required=True)

    submission = subparsers.add_parser("build-submission", help="format evidence and semantic results as T1 field reports")
    submission.add_argument("--evidence", type=Path, required=True)
    submission.add_argument("--semantic", type=Path, action="append", required=True, help="semantic JSONL; repeatable")
    submission.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate", help="run the complete T1 evidence, Judge, Critic, and report workflow")
    validate.add_argument("--input", type=Path, required=True, help="candidate VulnGym entries JSONL")
    validate.add_argument("--output-dir", type=Path, required=True, help="directory for checkpoints and final reports")
    validate.add_argument("--provider-config", type=Path, required=True)
    validate.add_argument("--repository", type=Path, help="one local repository for every input row")
    validate.add_argument("--repositories-root", type=Path, action="append", default=[])
    validate.add_argument("--repository-map", type=Path)
    validate.add_argument("--fix-map", type=Path)
    validate.add_argument("--advisory-cache", type=Path, action="append", default=[])
    validate.add_argument("--context-lines", type=int, default=12)
    validate.add_argument("--no-critic", action="store_true")
    validate.add_argument("--limit", type=int)
    validate.add_argument("--entry-id", action="append", dest="entry_ids")
    validate.add_argument("--resume", action="store_true")

    readable = subparsers.add_parser("render-report", help="render saved workflow runs as safe offline Markdown and HTML")
    readable.add_argument("--input", type=Path, required=True, help="runs.jsonl from validate")
    readable.add_argument("--output-dir", type=Path, required=True)

    systemic = subparsers.add_parser("analyze-systemic", help="aggregate repeated evidence-backed batch failure patterns")
    systemic.add_argument("--input", type=Path, required=True, help="runs.jsonl from validate")
    systemic.add_argument("--output-dir", type=Path, required=True)

    benchmark = subparsers.add_parser("build-repo-holdout-benchmark", help="build realistic targeted mutations from repository-diverse records")
    benchmark.add_argument("--input", type=Path, required=True)
    benchmark.add_argument("--candidates", type=Path, required=True)
    benchmark.add_argument("--manifest", type=Path, required=True)

    baseline = subparsers.add_parser("run-baseline", help="run a same-model bare-record baseline without tools or external evidence")
    baseline.add_argument("--input", type=Path, required=True)
    baseline.add_argument("--output", type=Path, required=True)
    baseline.add_argument("--provider-config", type=Path, required=True)
    baseline.add_argument("--limit", type=int)
    baseline.add_argument("--entry-id", action="append", dest="entry_ids")
    baseline.add_argument("--resume", action="store_true")

    comparison = subparsers.add_parser("compare-mutations", help="compare bare, Judge, and Judge-Critic detection of targeted mutations")
    comparison.add_argument("--manifest", type=Path, required=True)
    comparison.add_argument("--bare", type=Path, required=True)
    comparison.add_argument("--agent", type=Path, required=True)
    comparison.add_argument("--output", type=Path, required=True)

    blind = subparsers.add_parser(
        "build-blind-dataset",
        help="materialize a frozen clean/history benchmark from published VulnGym refs",
    )
    blind.add_argument("--repository", type=Path, required=True, help="local VulnGym Git repository")
    blind.add_argument("--selection", type=Path, required=True, help="frozen blind selection JSON")
    blind.add_argument("--output-dir", type=Path, required=True)

    submission_evaluation = subparsers.add_parser(
        "evaluate-submission",
        help="score all eight T1 report fields against a frozen reference",
    )
    submission_evaluation.add_argument("--submission", type=Path, required=True)
    submission_evaluation.add_argument("--reference", type=Path, required=True)
    submission_evaluation.add_argument("--output", type=Path, required=True)
    return parser


def _audit(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")

    engine = AuditEngine(args.repository)

    def rows():
        processed = 0
        for _line_number, record in read_jsonl(args.input):
            yield engine.audit(record).to_dict()
            processed += 1
            if args.limit is not None and processed >= args.limit:
                break

    try:
        write_jsonl(args.output, rows())
    except (OSError, JsonlError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _build_dataset(args: argparse.Namespace) -> int:
    if args.mutations_per_record < 0:
        raise SystemExit("--mutations-per-record must be non-negative")
    try:
        records = [record for _, record in read_jsonl(args.input)]
        if not args.include_unverified:
            records = [record for record in records if record.get("verify") == 1]
        cases = generate_cases(
            records,
            seed=args.seed,
            split_unit=args.split_unit,
            mutations_per_record=args.mutations_per_record,
            include_clean=not args.no_clean,
        )
        summary = write_dataset(
            args.output_dir,
            cases,
            metadata={
                "source": str(args.input),
                "seed": args.seed,
                "split_unit": args.split_unit,
                "mutations_per_record": args.mutations_per_record,
                "include_unverified": args.include_unverified,
                "include_clean": not args.no_clean,
                "source_records": len(records),
            },
        )
    except (OSError, JsonlError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    try:
        result = evaluate_audits(args.audit, args.manifest)
        if args.json_output:
            write_evaluation(args.json_output, result)
    except (OSError, JsonlError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _mine_history(args: argparse.Namespace) -> int:
    candidate_refs = args.candidate_refs or ["v0.1.0", "v0.1.1", "v0.1.2", "v0.1.3"]
    try:
        cases, metadata = generate_history_cases(
            args.repository,
            reference_ref=args.reference_ref,
            candidate_refs=candidate_refs,
            split_unit=args.split_unit,
            seed=args.seed,
            include_unverified=args.include_unverified,
            file_path=args.file_path,
        )
        summary = write_dataset(args.output_dir, cases, metadata=metadata)
    except (OSError, HistoryError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _index_repositories(args: argparse.Namespace) -> int:
    try:
        records = [record for _, record in read_jsonl(args.input)]
        if args.verified_only:
            records = [record for record in records if record.get("verify") == 1]
        resolver = RepositoryResolver(
            roots=args.repositories_root,
            mapping=load_repository_map(args.repository_map),
        )
        index = build_repository_index(records, resolver)
        write_repository_index(args.output, index)
    except (OSError, JsonlError, RepositoryError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(index["summary"], ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _prepare_evidence(args: argparse.Namespace) -> int:
    if args.context_lines < 0 or args.context_lines > 100:
        raise SystemExit("--context-lines must be between 0 and 100")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    try:
        records = [record for _, record in read_jsonl(args.input)]
        if args.limit is not None:
            records = records[: args.limit]
        resolver = RepositoryResolver(
            roots=args.repositories_root,
            mapping=load_repository_map(args.repository_map),
        )
        packets = prepare_evidence_packets(
            records,
            resolver=resolver,
            explicit_repository=args.repository,
            fix_map=load_fix_map(args.fix_map),
            context_lines=args.context_lines,
            advisory_documents=load_advisory_cache(args.advisory_cache),
        )
        write_jsonl(args.output, packets)
    except (OSError, JsonlError, RepositoryError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _fetch_advisories(args: argparse.Namespace) -> int:
    if not args.allow_network:
        print("error: network access is disabled; pass --allow-network explicitly", file=sys.stderr)
        return 2
    if args.timeout <= 0 or args.timeout > 60:
        print("error: --timeout must be between 0 and 60 seconds", file=sys.stderr)
        return 2
    if args.output.exists():
        print(f"error: refusing to overwrite advisory cache: {args.output}", file=sys.stderr)
        return 2
    try:
        records = [record for _, record in read_jsonl(args.input)]
        documents, failures = fetch_advisories(
            records,
            timeout=args.timeout,
            github_token=os.environ.get("GITHUB_TOKEN"),
        )
        write_jsonl(args.output, documents)
    except (OSError, JsonlError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"documents": len(documents), "failures": failures, "output": str(args.output)}, ensure_ascii=False))
    return 0 if documents else 2


def _select_cases(args: argparse.Namespace) -> int:
    try:
        records = [record for _, record in read_jsonl(args.input)]
        selected = select_records(records, load_selection(args.selection))
        write_jsonl(args.output, selected)
    except (OSError, JsonlError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"selected": len(selected), "output": str(args.output)}, ensure_ascii=False))
    return 0


def _filter_packets(args: argparse.Namespace) -> list[dict]:
    packets = [packet for _, packet in read_jsonl(args.evidence)]
    if args.entry_ids:
        requested = set(args.entry_ids)
        packets = [packet for packet in packets if packet.get("entry_id") in requested]
        missing = sorted(requested - {str(packet.get("entry_id")) for packet in packets})
        if missing:
            raise ValueError("entry_ids are absent from evidence: " + ", ".join(missing))
    if args.limit is not None:
        packets = packets[: args.limit]
    return packets


def _checkpoint_results(
    output: Path,
    packets: list[dict],
    run_one,
    *,
    resume: bool,
    completed_statuses: set[str],
) -> None:
    rows = [row for _, row in read_jsonl(output)] if resume and output.is_file() else []
    positions = {
        str(row.get("entry_id")): index
        for index, row in enumerate(rows)
        if row.get("entry_id") is not None
    }
    completed = {
        entry_id
        for entry_id, index in positions.items()
        if rows[index].get("status") in completed_statuses
    }
    if not rows:
        write_jsonl(output, [])
    for packet in packets:
        entry_id = str(packet.get("entry_id"))
        if entry_id in completed:
            continue
        result = run_one(packet)
        if entry_id in positions:
            rows[positions[entry_id]] = result
        else:
            positions[entry_id] = len(rows)
            rows.append(result)
        write_jsonl(output, rows)


def _run_semantic(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    try:
        packets = _filter_packets(args)
        provider = load_provider(args.provider_config)
        policy = "never" if args.no_critic else args.critic_policy
        completed_statuses = {"completed", "completed_with_repair", "completed_without_critic", "completed_without_critic_with_repair"}
        _checkpoint_results(
            args.output,
            packets,
            lambda packet: run_judge_critic(packet, provider, critic_policy=policy),
            resume=args.resume,
            completed_statuses=completed_statuses,
        )
    except (OSError, JsonlError, ProviderError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _extract_judgment(row: dict) -> dict:
    for key in ("judgment", "final_judgment"):
        value = row.get(key)
        if isinstance(value, dict):
            return value
    if isinstance(row.get("field_results"), list):
        return row
    raise ValueError(f"result for entry_id={row.get('entry_id')} contains no judgment")


def _run_critic(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    try:
        if args.judgments.resolve() == args.output.resolve():
            raise ValueError("--judgments and --output must be different files")
        packets = _filter_packets(args)
        prior_rows = [row for _, row in read_jsonl(args.judgments)]
        prior_by_entry = {
            str(row.get("entry_id")): row
            for row in prior_rows
            if row.get("entry_id") is not None
        }
        missing = sorted(
            str(packet.get("entry_id"))
            for packet in packets
            if str(packet.get("entry_id")) not in prior_by_entry
        )
        if missing:
            raise ValueError("entry_ids are absent from judgments: " + ", ".join(missing))
        provider = load_provider(args.provider_config)

        def run_one(packet: dict) -> dict:
            prior = prior_by_entry[str(packet.get("entry_id"))]
            return run_critic_from_judgment(
                packet,
                provider,
                _extract_judgment(prior),
                prior_result=prior,
            )

        _checkpoint_results(
            args.output,
            packets,
            run_one,
            resume=args.resume,
            completed_statuses={"completed", "completed_with_repair"},
        )
    except (OSError, JsonlError, ProviderError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _report_semantic(args: argparse.Namespace) -> int:
    try:
        rows = [row for path in args.input for _, row in read_jsonl(path)]
        report = summarize_semantic_results(rows)
        write_semantic_report(args.output, report)
    except (OSError, JsonlError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _evaluate_semantic(args: argparse.Namespace) -> int:
    try:
        semantic_rows = [row for path in args.semantic for _, row in read_jsonl(path)]
        gold_rows = [row for _, row in read_jsonl(args.gold)]
        result = evaluate_semantic_results(semantic_rows, gold_rows)
        write_semantic_evaluation(args.output, result)
    except (OSError, JsonlError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"totals": result["totals"], "critic_accuracy_delta": result["critic_accuracy_delta"]}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _repair_semantic(args: argparse.Namespace) -> int:
    try:
        packets = {
            str(packet.get("entry_id")): packet
            for _, packet in read_jsonl(args.evidence)
            if packet.get("entry_id") is not None
        }
        rows = [row for _, row in read_jsonl(args.input)]
        repaired_rows = []
        repaired_count = 0
        for row in rows:
            entry_id = str(row.get("entry_id"))
            if entry_id not in packets:
                raise ValueError(f"entry_id is absent from evidence: {entry_id}")
            repaired = repair_persisted_result(packets[entry_id], row)
            repaired_count += repaired != row
            repaired_rows.append(repaired)
        write_jsonl(args.output, repaired_rows)
    except (OSError, JsonlError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"rows": len(repaired_rows), "repaired": repaired_count}, ensure_ascii=False))
    return 0


def _build_submission(args: argparse.Namespace) -> int:
    try:
        semantic_rows = {
            str(row.get("entry_id")): row
            for path in args.semantic
            for _, row in read_jsonl(path)
            if row.get("entry_id") is not None
        }
        reports = []
        for _, packet in read_jsonl(args.evidence):
            entry_id = str(packet.get("entry_id"))
            report = build_submission_report(packet, semantic_rows.get(entry_id))
            errors = validate_submission_report(report)
            if errors:
                raise ValueError(f"invalid submission report for {entry_id}: " + "; ".join(errors))
            reports.append(report)
        write_jsonl(args.output, reports)
    except (OSError, JsonlError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"reports": len(reports), "output": str(args.output)}, ensure_ascii=False))
    return 0


def _write_workflow_outputs(output_dir: Path, rows: list[dict]) -> dict:
    write_jsonl(output_dir / "runs.jsonl", rows)
    write_jsonl(output_dir / "evidence.jsonl", (row["evidence_packet"] for row in rows))
    write_jsonl(output_dir / "semantic.jsonl", (row["semantic_result"] for row in rows))
    write_jsonl(output_dir / "submission.jsonl", (row["submission_report"] for row in rows))
    write_readable_reports(output_dir, rows)
    write_systemic_analysis(output_dir, rows)
    statuses: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    gap_codes: dict[str, int] = {}
    for row in rows:
        status = str(row.get("semantic_result", {}).get("status", "unknown"))
        statuses[status] = statuses.get(status, 0) + 1
        verdict = str(row.get("submission_report", {}).get("verdict", "unknown"))
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        for gap in row.get("evidence_gaps", []):
            if isinstance(gap, dict):
                code = str(gap.get("code", "unknown"))
                gap_codes[code] = gap_codes.get(code, 0) + 1
    summary = {
        "workflow_version": WORKFLOW_VERSION,
        "cases": len(rows),
        "semantic_statuses": dict(sorted(statuses.items())),
        "submission_verdicts": dict(sorted(verdicts.items())),
        "evidence_gap_cases": dict(sorted(gap_codes.items())),
        "files": {
            "runs": "runs.jsonl",
            "evidence": "evidence.jsonl",
            "semantic": "semantic.jsonl",
            "submission": "submission.jsonl",
            "markdown": "report.md",
            "html": "report.html",
            "systemic_json": "systemic-analysis.json",
            "systemic_markdown": "systemic-analysis.md",
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    temporary = output_dir / "summary.json.tmp"
    temporary.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output_dir / "summary.json")
    return summary


def _validate_workflow(args: argparse.Namespace) -> int:
    if args.context_lines < 0 or args.context_lines > 100:
        raise SystemExit("--context-lines must be between 0 and 100")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    try:
        records = [record for _, record in read_jsonl(args.input)]
        if args.entry_ids:
            requested = set(args.entry_ids)
            records = [record for record in records if record.get("entry_id") in requested]
            missing = sorted(requested - {str(record.get("entry_id")) for record in records})
            if missing:
                raise ValueError("entry_ids are absent from input: " + ", ".join(missing))
        if args.limit is not None:
            records = records[: args.limit]
        resolver = RepositoryResolver(
            roots=args.repositories_root,
            mapping=load_repository_map(args.repository_map),
        )
        fixes = load_fix_map(args.fix_map)
        advisories = load_advisory_cache(args.advisory_cache)
        provider = load_provider(args.provider_config)
        runs_path = args.output_dir / "runs.jsonl"
        rows = [row for _, row in read_jsonl(runs_path)] if args.resume and runs_path.is_file() else []
        positions = {
            str(row.get("entry_id")): index
            for index, row in enumerate(rows)
            if row.get("entry_id") is not None
        }
        for record in records:
            entry_id = str(record.get("entry_id"))
            if entry_id in positions:
                prior = rows[positions[entry_id]]
                status = prior.get("semantic_result", {}).get("status")
                if status in COMPLETED_STATUSES:
                    continue
            result = run_validation_record(
                record,
                resolver=resolver,
                provider=provider,
                explicit_repository=args.repository,
                explicit_fix_commit=fixes.get(entry_id) or fixes.get(str(record.get("report_id"))),
                advisory_documents=advisories,
                context_lines=args.context_lines,
                use_critic=not args.no_critic,
            )
            if entry_id in positions:
                rows[positions[entry_id]] = result
            else:
                positions[entry_id] = len(rows)
                rows.append(result)
            _write_workflow_outputs(args.output_dir, rows)
        summary = _write_workflow_outputs(args.output_dir, rows)
    except (OSError, JsonlError, ProviderError, RepositoryError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if rows and all(row.get("semantic_result", {}).get("status") in COMPLETED_STATUSES for row in rows) else 1


def _render_report(args: argparse.Namespace) -> int:
    try:
        rows = [row for _, row in read_jsonl(args.input)]
        write_readable_reports(args.output_dir, rows)
    except (OSError, JsonlError, ValueError, TypeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"cases": len(rows), "report": str(args.output_dir / "report.html")}, ensure_ascii=False))
    return 0


def _analyze_systemic(args: argparse.Namespace) -> int:
    try:
        rows = [row for _, row in read_jsonl(args.input)]
        report = write_systemic_analysis(args.output_dir, rows)
    except (OSError, JsonlError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"cases": report["cases"], "patterns": len(report["patterns"])}, ensure_ascii=False))
    return 0


def _build_repo_holdout_benchmark(args: argparse.Namespace) -> int:
    try:
        records = [record for _, record in read_jsonl(args.input)]
        candidates, manifest = build_repo_holdout_mutations(records)
        write_jsonl(args.candidates, candidates)
        write_jsonl(args.manifest, manifest)
    except (OSError, JsonlError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"cases": len(candidates), "target_labels": sum(len(row["target_fields"]) for row in manifest)}, ensure_ascii=False))
    return 0


def _run_baseline(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    try:
        records = [record for _, record in read_jsonl(args.input)]
        if args.entry_ids:
            requested = set(args.entry_ids)
            records = [record for record in records if record.get("entry_id") in requested]
            missing = sorted(requested - {str(record.get("entry_id")) for record in records})
            if missing:
                raise ValueError("entry_ids are absent from input: " + ", ".join(missing))
        if args.limit is not None:
            records = records[: args.limit]
        provider = load_provider(args.provider_config)
        _checkpoint_results(
            args.output,
            records,
            lambda record: run_bare_record(record, provider),
            resume=args.resume,
            completed_statuses={"completed"},
        )
    except (OSError, JsonlError, ProviderError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _compare_mutations(args: argparse.Namespace) -> int:
    try:
        result = compare_mutation_detection(
            (row for _, row in read_jsonl(args.manifest)),
            (row for _, row in read_jsonl(args.bare)),
            (row for _, row in read_jsonl(args.agent)),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(args.output)
    except (OSError, JsonlError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({name: values["target_detection_recall"] for name, values in result.items() if isinstance(values, dict)}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _build_blind_dataset(args: argparse.Namespace) -> int:
    try:
        selection = json.loads(args.selection.read_text(encoding="utf-8"))
        candidates, reference, review_queue, manifest = build_blind_dataset(
            args.repository,
            selection,
        )
        write_blind_dataset(
            args.output_dir,
            candidates=candidates,
            reference=reference,
            review_queue=review_queue,
            manifest=manifest,
        )
    except (OSError, HistoryError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest["counts"], ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _evaluate_submission(args: argparse.Namespace) -> int:
    try:
        reports = [row for _, row in read_jsonl(args.submission)]
        reference = [row for _, row in read_jsonl(args.reference)]
        result = evaluate_submission_reports(reports, reference)
        write_submission_evaluation(args.output, result)
    except (OSError, JsonlError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return _audit(args)
    if args.command == "build-dataset":
        return _build_dataset(args)
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "mine-history":
        return _mine_history(args)
    if args.command == "index-repositories":
        return _index_repositories(args)
    if args.command == "prepare-evidence":
        return _prepare_evidence(args)
    if args.command == "fetch-advisories":
        return _fetch_advisories(args)
    if args.command == "select-cases":
        return _select_cases(args)
    if args.command == "run-semantic":
        return _run_semantic(args)
    if args.command == "run-critic":
        return _run_critic(args)
    if args.command == "report-semantic":
        return _report_semantic(args)
    if args.command == "evaluate-semantic":
        return _evaluate_semantic(args)
    if args.command == "repair-semantic":
        return _repair_semantic(args)
    if args.command == "build-submission":
        return _build_submission(args)
    if args.command == "validate":
        return _validate_workflow(args)
    if args.command == "render-report":
        return _render_report(args)
    if args.command == "analyze-systemic":
        return _analyze_systemic(args)
    if args.command == "build-repo-holdout-benchmark":
        return _build_repo_holdout_benchmark(args)
    if args.command == "run-baseline":
        return _run_baseline(args)
    if args.command == "compare-mutations":
        return _compare_mutations(args)
    if args.command == "build-blind-dataset":
        return _build_blind_dataset(args)
    if args.command == "evaluate-submission":
        return _evaluate_submission(args)
    parser.error(f"unknown command: {args.command}")
    return 2
