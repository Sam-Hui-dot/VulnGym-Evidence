from __future__ import annotations

import copy
import unittest

from vulngym_agent.data_factory import assign_group_splits, generate_cases

from .helpers import valid_record


class DataFactoryTests(unittest.TestCase):
    def _records(self) -> list[dict]:
        records = []
        for index in range(1, 10):
            record = valid_record(f"entry-{index:05d}", f"https://github.com/acme/repo-{index % 4}")
            record["report_id"] = f"GHSA-{index:04d}-BBBB-CCCC"
            record["source_link"] = f"https://github.com/advisories/{record['report_id']}"
            record["vuln_title"] = f"Example vulnerability {index}"
            record["vuln_category_l1"] = f"category-{index % 3}"
            record["vuln_category_l2"] = f"subcategory-{index % 3}"
            records.append(record)
        return records

    def test_repo_split_has_no_cross_split_leakage(self) -> None:
        records = self._records()
        assignments = assign_group_splits(records, unit="repo", seed=42)
        self.assertEqual(set(assignments), {record["repo_url"] for record in records})
        for repo_url in assignments:
            self.assertEqual(len({assignments[record["repo_url"]] for record in records if record["repo_url"] == repo_url}), 1)

    def test_generation_is_deterministic_and_does_not_modify_source(self) -> None:
        records = self._records()
        original = copy.deepcopy(records)
        first = generate_cases(records, seed=42, split_unit="repo", mutations_per_record=2, include_clean=True)
        second = generate_cases(records, seed=42, split_unit="repo", mutations_per_record=2, include_clean=True)
        self.assertEqual(first, second)
        self.assertEqual(records, original)
        self.assertEqual(len(first), len(records) * 3)
        self.assertTrue(all(case.candidate.get("_case_id") == case.label["case_id"] for case in first))

    def test_donor_mutations_do_not_cross_split_boundaries(self) -> None:
        records = self._records()
        cases = generate_cases(records, seed=7, split_unit="repo", mutations_per_record=12, include_clean=False)
        split_by_entry = {
            case.label["source_entry_id"]: case.split
            for case in cases
        }
        for case in cases:
            details = case.label["mutation_details"]
            if "copied" not in details or " from entry-" not in details:
                continue
            donor_id = details.rsplit(" from ", 1)[1]
            self.assertEqual(case.split, split_by_entry[donor_id])


if __name__ == "__main__":
    unittest.main()
