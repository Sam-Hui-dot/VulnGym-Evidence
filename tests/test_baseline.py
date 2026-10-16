from __future__ import annotations

import unittest

from vulngym_agent.baseline import BARE_RECORD_PROMPT, build_bare_record_request, run_bare_record
from vulngym_agent.provider import ProviderCompletion
from vulngym_agent.semantic_contract import SEMANTIC_FIELDS

from .helpers import valid_record


class FakeProvider:
    name = "fake"

    def complete(self, request: dict) -> ProviderCompletion:
        record = request["available_evidence"]["content"]
        result = {
            "case_id": record["_case_id"],
            "entry_id": record["entry_id"],
            "field_results": [
                {
                    "field": field,
                    "verdict": "uncertain",
                    "confidence": 0.5,
                    "reason": "the record alone is insufficient",
                    "evidence_refs": ["candidate:record"],
                    "correction": None,
                }
                for field in SEMANTIC_FIELDS
            ],
            "overall_verdict": "uncertain",
            "overall_confidence": 0.5,
            "self_check": {
                "looked_for_counterevidence": True,
                "unresolved_questions": ["source unavailable"],
                "unsupported_claims_removed": True,
            },
        }
        return ProviderCompletion(result, {"resolved_model": "fake-model"})


class RetryProvider(FakeProvider):
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request: dict) -> ProviderCompletion:
        self.calls += 1
        completion = super().complete(request)
        if self.calls == 1:
            completion.output["field_results"][0]["evidence_refs"] = ["invalid:section"]
        return completion


class BaselineTests(unittest.TestCase):
    def test_bare_request_contains_no_external_packet(self) -> None:
        record = valid_record()
        record["_case_id"] = "bare-case"
        request = build_bare_record_request(record)
        self.assertEqual(request["prompt_metadata"]["prompt_id"], BARE_RECORD_PROMPT.prompt_id)
        self.assertEqual(set(request["available_evidence"]), {"evidence_id", "content"})
        self.assertNotIn("packet", request)

    def test_bare_runner_validates_same_semantic_shape(self) -> None:
        record = valid_record()
        record["_case_id"] = "bare-case"
        result = run_bare_record(record, FakeProvider())
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["final_judgment"]["overall_verdict"], "uncertain")
        self.assertEqual(result["provider_metadata"]["resolved_model"], "fake-model")

    def test_bare_runner_gets_same_single_contract_retry(self) -> None:
        record = valid_record()
        record["_case_id"] = "bare-case"
        provider = RetryProvider()

        result = run_bare_record(record, provider)

        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["contract_retry"])
        self.assertEqual(provider.calls, 2)


if __name__ == "__main__":
    unittest.main()
