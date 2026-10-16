from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .evidence import build_evidence_packet, packet_evidence_ids
from .repository import ReadOnlyGitRepository
from .repository_index import RepositoryResolution, RepositoryResolver
from .semantic_contract import SemanticProvider
from .semantic_runner import run_judge_critic
from .submission import build_submission_report, validate_submission_report


WORKFLOW_VERSION = "0.1.0"
COMPLETED_STATUSES = {
    "completed",
    "completed_with_repair",
    "completed_without_critic",
    "completed_without_critic_with_repair",
}


def resolve_record_repository(
    record: dict[str, Any],
    *,
    resolver: RepositoryResolver,
    explicit_repository: Path | None = None,
) -> RepositoryResolution:
    if explicit_repository is None:
        return resolver.resolve(str(record.get("repo_url") or ""))
    repository = ReadOnlyGitRepository(explicit_repository)
    return RepositoryResolution(
        repo_url=str(record.get("repo_url") or "explicit"),
        status="resolved_explicitly",
        path=repository.root,
        origin=repository.remote_origin(),
        reason="--repository applies to this validation run",
    )


def evidence_gaps(packet: dict[str, Any]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []

    def add(code: str, severity: str, reason: str, next_action: str) -> None:
        gaps.append(
            {
                "code": code,
                "severity": severity,
                "reason": reason,
                "next_action": next_action,
            }
        )

    repository = packet.get("repository")
    if not isinstance(repository, dict) or not str(repository.get("status") or "").startswith("resolved"):
        add(
            "repository_missing",
            "blocking",
            "the vulnerable source repository is not available locally",
            "provide a matching local repository or repository map",
        )

    missing_contexts = [
        str(item.get("field"))
        for item in packet.get("source_contexts", [])
        if isinstance(item, dict) and item.get("status") != "available"
    ]
    if missing_contexts:
        add(
            "source_context_incomplete",
            "blocking",
            "source context is unavailable for: " + ", ".join(missing_contexts),
            "correct the source location or fetch the required commit",
        )

    advisory = packet.get("advisory_analysis")
    documents = advisory.get("documents") if isinstance(advisory, dict) else None
    if not isinstance(documents, list) or not documents:
        add(
            "advisory_missing",
            "warning",
            "no matching advisory document is present in the evidence packet",
            "provide a GHSA/OSV advisory cache matched by identifier or canonical URL",
        )

    patch = packet.get("patch_analysis")
    patch_status = patch.get("status") if isinstance(patch, dict) else "unavailable"
    if patch_status != "selected":
        add(
            "fix_patch_unresolved",
            "warning",
            f"fix patch status is {patch_status!r}",
            "provide an explicit fix-map hint or stronger advisory commit evidence",
        )

    trace = packet.get("trace_analysis")
    edges = trace.get("edges") if isinstance(trace, dict) else None
    unresolved = [
        item
        for item in edges or []
        if isinstance(item, dict) and item.get("status") in {"unresolved", "same_file_order"}
    ]
    if unresolved:
        add(
            "trace_edges_unproven",
            "warning",
            f"{len(unresolved)} adjacent trace edge(s) lack a proven call or same-function relation",
            "let the semantic Judge review expanded contexts and abstain when continuity remains unproved",
        )

    taxonomy = packet.get("taxonomy_analysis")
    taxonomy_documents = taxonomy.get("documents") if isinstance(taxonomy, dict) else None
    if not isinstance(taxonomy_documents, list) or not taxonomy_documents:
        add(
            "taxonomy_missing",
            "warning",
            "the claimed vulnerability categories have no citable local taxonomy entry",
            "extend the versioned VulnGym taxonomy cache or keep category verdicts uncertain",
        )
    return gaps


def preflight_plan(
    record: dict[str, Any],
    *,
    resolution: RepositoryResolution,
    advisory_available: bool,
    use_critic: bool,
) -> list[dict[str, Any]]:
    repository_available = resolution.path is not None
    trace_available = isinstance(record.get("trace"), list) and len(record["trace"]) >= 2
    taxonomy_available = bool(record.get("vuln_category_l1") and record.get("vuln_category_l2"))
    return [
        {
            "step": "resolve_repository",
            "tool": "RepositoryResolver",
            "decision": "run",
            "reason": "source and commit checks require a matching local repository",
            "status": resolution.status,
        },
        {
            "step": "audit_schema_git_source",
            "tool": "AuditEngine",
            "decision": "run",
            "reason": "schema always runs; Git and source checks require a resolved repository",
            "status": "planned",
        },
        {
            "step": "read_advisory",
            "tool": "AdvisoryReader",
            "decision": "run" if advisory_available else "skip",
            "reason": "advisory cache supplied" if advisory_available else "no advisory cache is available",
            "status": "planned" if advisory_available else "skipped_unavailable",
        },
        {
            "step": "inspect_fix_patch",
            "tool": "PatchInspector",
            "decision": "run" if repository_available else "skip",
            "reason": "resolved repository can provide candidate fix diffs" if repository_available else "repository unresolved",
            "status": "planned" if repository_available else "skipped_unavailable",
        },
        {
            "step": "inspect_trace",
            "tool": "TraceInspector",
            "decision": "run" if repository_available and trace_available else "skip",
            "reason": "resolved source and a multi-node trace are available" if repository_available and trace_available else "source or multi-node trace unavailable",
            "status": "planned" if repository_available and trace_available else "skipped_unavailable",
        },
        {
            "step": "load_taxonomy",
            "tool": "TaxonomyEvidence",
            "decision": "run" if taxonomy_available else "skip",
            "reason": "candidate declares both category levels" if taxonomy_available else "candidate categories are incomplete",
            "status": "planned" if taxonomy_available else "skipped_unavailable",
        },
        {"step": "judge_semantics", "tool": "SemanticJudge", "decision": "run", "reason": "semantic fields require evidence-grounded review", "status": "planned"},
        {
            "step": "seek_counterevidence",
            "tool": "SemanticCritic",
            "decision": "run" if use_critic else "skip",
            "reason": "critic enabled" if use_critic else "disabled by caller",
            "status": "planned" if use_critic else "disabled",
        },
        {"step": "merge_evidence", "tool": "SubmissionAdapter", "decision": "run", "reason": "produce the eight-field T1 report", "status": "planned"},
    ]


def finalize_plan(plan: list[dict[str, Any]], packet: dict[str, Any], semantic_status: str) -> None:
    repository = packet.get("repository") if isinstance(packet.get("repository"), dict) else {}
    advisory = packet.get("advisory_analysis") if isinstance(packet.get("advisory_analysis"), dict) else {}
    patch = packet.get("patch_analysis") if isinstance(packet.get("patch_analysis"), dict) else {}
    trace = packet.get("trace_analysis") if isinstance(packet.get("trace_analysis"), dict) else {}
    taxonomy = packet.get("taxonomy_analysis") if isinstance(packet.get("taxonomy_analysis"), dict) else {}
    statuses = {
        "resolve_repository": repository.get("status", "missing"),
        "audit_schema_git_source": packet.get("deterministic_audit", {}).get("overall_verdict", "unknown"),
        "read_advisory": advisory.get("status", "unavailable"),
        "inspect_fix_patch": patch.get("status", "unavailable"),
        "inspect_trace": trace.get("status", "unavailable"),
        "load_taxonomy": taxonomy.get("status", "unavailable"),
        "judge_semantics": semantic_status,
        "seek_counterevidence": "completed" if semantic_status in COMPLETED_STATUSES else "not_completed",
        "merge_evidence": "completed",
    }
    for step in plan:
        if step.get("decision") != "skip":
            step["status"] = statuses.get(str(step.get("step")), "unknown")


def run_validation_record(
    record: dict[str, Any],
    *,
    resolver: RepositoryResolver,
    provider: SemanticProvider,
    explicit_repository: Path | None = None,
    explicit_fix_commit: str | None = None,
    advisory_documents: Iterable[dict[str, Any]] = (),
    context_lines: int = 12,
    use_critic: bool = True,
) -> dict[str, Any]:
    resolution = resolve_record_repository(
        record,
        resolver=resolver,
        explicit_repository=explicit_repository,
    )
    advisory_documents = list(advisory_documents)
    plan = preflight_plan(
        record,
        resolution=resolution,
        advisory_available=bool(advisory_documents),
        use_critic=use_critic,
    )
    packet = build_evidence_packet(
        record,
        resolution=resolution,
        context_lines=context_lines,
        explicit_fix_commit=explicit_fix_commit,
        advisory_documents=advisory_documents,
    )
    gaps = evidence_gaps(packet)
    evidence_ids = packet_evidence_ids(packet)
    if evidence_ids:
        semantic = run_judge_critic(packet, provider, use_critic=use_critic)
    else:
        semantic = {
            "case_id": packet.get("case_id"),
            "entry_id": packet.get("entry_id"),
            "provider": provider.name,
            "status": "skipped_no_citable_evidence",
            "evidence_ids": [],
        }
    submission = build_submission_report(packet, semantic)
    errors = validate_submission_report(submission)
    if errors:
        raise ValueError("invalid submission report: " + "; ".join(errors))

    finalize_plan(plan, packet, str(semantic.get("status", "unknown")))
    severity_counts = Counter(item["severity"] for item in gaps)
    reflection = {
        "semantic_status": semantic.get("status"),
        "final_verdict": submission["verdict"],
        "evidence_gap_counts": dict(sorted(severity_counts.items())),
        "ready_for_human_review": semantic.get("status") in COMPLETED_STATUSES,
        "next_actions": list(dict.fromkeys(item["next_action"] for item in gaps)),
    }
    return {
        "workflow_version": WORKFLOW_VERSION,
        "case_id": packet.get("case_id"),
        "entry_id": packet.get("entry_id"),
        "report_id": packet.get("report_id"),
        "plan": plan,
        "evidence_gaps": gaps,
        "evidence_packet": packet,
        "semantic_result": semantic,
        "submission_report": submission,
        "reflection": reflection,
    }
