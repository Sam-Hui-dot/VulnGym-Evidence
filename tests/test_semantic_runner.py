from __future__ import annotations

import json
import sys
import unittest

from vulngym_agent.provider import JsonCommandProvider, ProviderCompletion, ProviderError
from vulngym_agent.semantic_contract import (
    SEMANTIC_FIELDS,
    SEMANTIC_OUTPUT_SCHEMA,
    build_judge_request,
    repair_derived_overall,
    validate_semantic_output,
)
from vulngym_agent.semantic_runner import (
    reconcile_judge_critic,
    repair_persisted_result,
    run_critic_from_judgment,
    run_judge_critic,
    should_run_critic,
)


def judgment(evidence_id: str = "source:entry_point") -> dict:
    return {
        "case_id": "case-1",
        "entry_id": "entry-00001",
        "field_results": [
            {
                "field": field,
                "verdict": "correct",
                "confidence": 0.8,
                "reason": "fixture evidence supports the field",
                "evidence_refs": [evidence_id],
                "correction": None,
            }
            for field in SEMANTIC_FIELDS
        ],
        "overall_verdict": "correct",
        "overall_confidence": 0.8,
        "self_check": {
            "looked_for_counterevidence": True,
            "unresolved_questions": [],
            "unsupported_claims_removed": True,
        },
    }


class FakeProvider:
    name = "fake"

    def __init__(self) -> None:
        self.tasks: list[str] = []

    def complete(self, request: dict) -> dict:
        self.tasks.append(request["task"])
        return judgment()


class MetadataProvider(FakeProvider):
    def complete(self, request: dict) -> ProviderCompletion:
        self.tasks.append(request["task"])
        return ProviderCompletion(judgment(), {"usage": {"input_tokens": 10, "output_tokens": 2}})


class ContractRetryProvider(FakeProvider):
    def complete(self, request: dict) -> dict:
        self.tasks.append(request["task"])
        value = judgment()
        if request["task"] == "vulngym_t1_semantic_judge":
            value["field_results"][0]["evidence_refs"] = ["source_contexts"]
        return value


class IdentityDriftProvider(FakeProvider):
    def complete(self, request: dict) -> dict:
        self.tasks.append(request["task"])
        value = judgment()
        value["case_id"] = "derived-from-entry"
        return value


class TransientProvider(FakeProvider):
    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    def complete(self, request: dict) -> ProviderCompletion:
        self.tasks.append(request["task"])
        if not self.failed:
            self.failed = True
            raise ProviderError("temporary empty response")
        return ProviderCompletion(judgment(), {"resolved_model": "fake-model"})


class SemanticRunnerTests(unittest.TestCase):
    def test_review_risk_critic_policy_is_selective(self) -> None:
        accepted = judgment()
        self.assertTrue(should_run_critic(accepted, "review-risk")[0])
        rejected = judgment()
        rejected["overall_verdict"] = "incorrect"
        rejected["field_results"][0].update(verdict="incorrect", confidence=0.95)
        self.assertFalse(should_run_critic(rejected, "review-risk")[0])
        rejected["field_results"][0]["confidence"] = 0.7
        self.assertTrue(should_run_critic(rejected, "review-risk")[0])

    def test_review_risk_skips_critic_after_high_confidence_rejection(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        provider = FakeProvider()
        original = provider.complete
        def reject(request: dict) -> dict:
            value = original(request)
            value["field_results"][0].update(verdict="incorrect", confidence=0.95)
            value["overall_verdict"] = "incorrect"
            return value
        provider.complete = reject
        result = run_judge_critic(packet, provider, critic_policy="review-risk")
        self.assertEqual(provider.tasks, ["vulngym_t1_semantic_judge"])
        self.assertEqual(result["status"], "completed_without_critic")
        self.assertFalse(result["critic_decision"]["run"])

    def test_arbitration_rejects_lower_confidence_critic_regression(self) -> None:
        judge = judgment()
        critic = judgment()
        judge["field_results"][0].update(verdict="incorrect", confidence=0.8)
        critic["field_results"][0].update(verdict="uncertain", confidence=0.5)
        critic["overall_verdict"] = "uncertain"

        final, decisions = reconcile_judge_critic(judge, critic)

        self.assertEqual(final["field_results"][0]["verdict"], "incorrect")
        self.assertEqual(final["overall_verdict"], "incorrect")
        self.assertEqual(decisions[0]["selected"], "judge")

    def test_arbitration_accepts_higher_confidence_critic_correction(self) -> None:
        judge = judgment()
        critic = judgment()
        judge["field_results"][0].update(verdict="uncertain", confidence=0.6)
        critic["field_results"][0].update(verdict="incorrect", confidence=0.85)
        critic["overall_verdict"] = "incorrect"

        final, decisions = reconcile_judge_critic(judge, critic)

        self.assertEqual(final["field_results"][0]["verdict"], "incorrect")
        self.assertEqual(decisions[0]["selected"], "critic")

    def test_semantic_request_compacts_duplicate_and_unbounded_evidence(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "source_contexts": [
                {"field": "entry_point", "evidence_id": "source:entry_point", "status": "available"},
                {"field": "trace", "evidence_id": "source:trace:0", "status": "available"},
            ],
            "patch_analysis": {
                "status": "selected",
                "selected_fix_commit": "abc123",
                "evidence_id": "patch:abc123",
                "candidates": [
                    {
                        "commit": "abc123",
                        "subject": "fix vulnerability",
                        "changed_files": [f"path/{index}.py" for index in range(1000)],
                        "overlap_files": ["target.py"],
                        "score": 10,
                    }
                ],
            },
        }

        compact = build_judge_request(packet)["packet"]

        self.assertEqual([item["evidence_id"] for item in compact["source_contexts"]], ["source:entry_point"])
        self.assertNotIn("candidates", compact["patch_analysis"])
        self.assertNotIn("changed_files", compact["patch_analysis"]["selected_candidate"])
        self.assertEqual(compact["patch_analysis"]["selected_candidate"]["commit"], "abc123")

    def test_runs_judge_then_critic(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        provider = FakeProvider()
        result = run_judge_critic(packet, provider)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            provider.tasks,
            ["vulngym_t1_semantic_judge", "vulngym_t1_semantic_critic"],
        )
        self.assertEqual(result["judge_prompt"]["version"], "1.7.0")
        self.assertEqual(result["critic_prompt"]["version"], "1.7.0")
        self.assertEqual(result["final_judgment"]["overall_verdict"], "correct")

    def test_runs_critic_from_existing_judgment_without_repeating_judge(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        provider = MetadataProvider()
        result = run_critic_from_judgment(packet, provider, judgment())
        self.assertEqual(provider.tasks, ["vulngym_t1_semantic_critic"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["critic_provider_metadata"]["usage"]["input_tokens"], 10)

    def test_retries_one_contract_failure_with_exact_validation_feedback(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        provider = ContractRetryProvider()

        result = run_judge_critic(packet, provider)

        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["judge_contract_retry"])
        self.assertFalse(result["judge_first_validation"]["valid"])
        self.assertTrue(result["judge_validation"]["valid"])
        self.assertEqual(
            provider.tasks,
            [
                "vulngym_t1_semantic_judge",
                "vulngym_t1_semantic_judge_contract_retry",
                "vulngym_t1_semantic_critic",
            ],
        )

    def test_repairs_derived_identifiers_without_provider_retry(self) -> None:
        packet = {
            "case_id": None,
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        provider = IdentityDriftProvider()

        result = run_judge_critic(packet, provider, use_critic=False)

        self.assertEqual(provider.tasks, ["vulngym_t1_semantic_judge"])
        self.assertEqual(result["status"], "completed_without_critic_with_repair")
        self.assertIsNone(result["judgment"]["case_id"])
        self.assertIn("copied from evidence packet", result["judge_repair"]["repairs"][0])

    def test_retries_one_transient_provider_failure(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        provider = TransientProvider()

        result = run_judge_critic(packet, provider, use_critic=False)

        self.assertEqual(result["status"], "completed_without_critic")
        self.assertEqual(result["judge_provider_metadata"]["transport_retry"]["attempts"], 2)
        self.assertEqual(provider.tasks.count("vulngym_t1_semantic_judge"), 2)

    def test_contract_requires_overall_consistency(self) -> None:
        value = judgment()
        value["field_results"][0]["verdict"] = "uncertain"
        validation = validate_semantic_output(value, {"source:entry_point"})
        self.assertFalse(validation.valid)
        self.assertTrue(any("overall_verdict must be uncertain" in error for error in validation.errors))

    def test_repairs_only_derived_overall_verdict(self) -> None:
        value = judgment()
        value["field_results"][0]["verdict"] = "incorrect"
        repaired, repairs = repair_derived_overall(value)
        self.assertEqual(repaired["overall_verdict"], "incorrect")
        self.assertEqual(value["overall_verdict"], "correct")
        self.assertEqual(len(repairs), 1)

    def test_repairs_persisted_critic_contract_error_without_model_call(self) -> None:
        packet = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "deterministic_audit": {"evidence": []},
            "source_contexts": [{"status": "available", "evidence_id": "source:entry_point"}],
            "patch_analysis": {},
        }
        criticism = judgment()
        criticism["field_results"][0]["verdict"] = "incorrect"
        row = {
            "case_id": "case-1",
            "entry_id": "entry-00001",
            "status": "critic_contract_error",
            "judgment": judgment(),
            "criticism": criticism,
        }
        repaired = repair_persisted_result(packet, row)
        self.assertEqual(repaired["status"], "completed_with_repair")
        self.assertEqual(repaired["final_judgment"]["overall_verdict"], "incorrect")
        self.assertIn("critic_raw_output", repaired)

    def test_contract_rejects_duplicate_evidence_references(self) -> None:
        value = judgment()
        value["field_results"][0]["evidence_refs"] = ["source:entry_point", "source:entry_point"]
        validation = validate_semantic_output(value, {"source:entry_point"})
        self.assertFalse(validation.valid)
        self.assertTrue(any("must not contain duplicates" in error for error in validation.errors))

    def test_output_schema_uses_supported_strict_object_shapes(self) -> None:
        def walk(schema: object) -> None:
            if isinstance(schema, dict):
                schema_type = schema.get("type")
                if schema_type == "object" or (isinstance(schema_type, list) and "object" in schema_type):
                    self.assertIs(schema.get("additionalProperties"), False)
                self.assertNotIn("uniqueItems", schema)
                for child in schema.values():
                    walk(child)
            elif isinstance(schema, list):
                for child in schema:
                    walk(child)

        walk(SEMANTIC_OUTPUT_SCHEMA)

    def test_json_command_provider_uses_stdin_stdout_without_shell(self) -> None:
        payload = judgment()
        script = "import json,sys; json.load(sys.stdin); print(json.dumps(" + repr(payload) + "))"
        provider = JsonCommandProvider("fixture-command", (sys.executable, "-c", script), timeout_seconds=5)
        completion = provider.complete({"task": "fixture"})
        self.assertEqual(completion.output, payload)
        self.assertEqual(completion.metadata, {})

    def test_json_command_provider_accepts_result_metadata_envelope(self) -> None:
        payload = judgment()
        envelope = {"result": payload, "metadata": {"usage": {"input_tokens": 5}}}
        script = "import json,sys; json.load(sys.stdin); print(json.dumps(" + repr(envelope) + "))"
        provider = JsonCommandProvider("fixture-command", (sys.executable, "-c", script), timeout_seconds=5)
        completion = provider.complete({"task": "fixture"})
        self.assertEqual(completion.output, payload)
        self.assertEqual(completion.metadata["usage"]["input_tokens"], 5)


if __name__ == "__main__":
    unittest.main()
