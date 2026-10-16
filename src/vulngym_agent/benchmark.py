from __future__ import annotations

from copy import deepcopy
from typing import Any


MUTATION_KINDS = (
    "donor_entry_point",
    "donor_critical_operation",
    "donor_categories",
    "reversed_trace",
    "donor_trace",
)


def build_repo_holdout_mutations(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create one realistic, targeted semantic mutation per repository.

    Donor values come from a different repository and therefore remain plausible
    VulnGym-shaped values without introducing an obvious marker token.  The
    manifest labels only fields changed by the mutation; untouched fields are
    intentionally not treated as human gold.
    """
    if len(records) < 2:
        raise ValueError("repo holdout mutation benchmark needs at least two records")
    candidates: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    for index, source in enumerate(records):
        donor = records[(index + 1) % len(records)]
        if source.get("repo_url") == donor.get("repo_url"):
            raise ValueError("mutation donor must come from a different repository")
        mutation = MUTATION_KINDS[index % len(MUTATION_KINDS)]
        candidate = deepcopy(source)
        if mutation == "donor_entry_point":
            candidate["entry_point"] = deepcopy(donor["entry_point"])
            targets = ["entry_point"]
        elif mutation == "donor_critical_operation":
            candidate["critical_operation"] = deepcopy(donor["critical_operation"])
            targets = ["critical_operation"]
        elif mutation == "donor_categories":
            candidate["vuln_category_l1"] = donor["vuln_category_l1"]
            candidate["vuln_category_l2"] = donor["vuln_category_l2"]
            targets = ["vuln_category_l1", "vuln_category_l2"]
        elif mutation == "reversed_trace":
            trace = candidate.get("trace")
            if not isinstance(trace, list) or len(trace) < 2:
                raise ValueError(f"{source.get('entry_id')} has no reversible trace")
            candidate["trace"] = list(reversed(deepcopy(trace)))
            targets = ["trace"]
        else:
            candidate["trace"] = deepcopy(donor["trace"])
            targets = ["trace"]

        case_id = f"{source['entry_id']}-repo-holdout-{mutation}"
        candidate["_case_id"] = case_id
        candidates.append(candidate)
        manifest.append(
            {
                "case_id": case_id,
                "source_entry_id": source["entry_id"],
                "source_repo_url": source["repo_url"],
                "donor_entry_id": donor["entry_id"],
                "donor_repo_url": donor["repo_url"],
                "mutation": mutation,
                "target_fields": targets,
                "expected_target_verdict": "incorrect",
                "evaluation_policy": "score only intentionally mutated target_fields; untouched fields are not gold",
            }
        )
    return candidates, manifest
