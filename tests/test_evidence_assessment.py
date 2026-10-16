from copy import deepcopy
import unittest

from tests.test_evidence_contract import checked_output, request
from vulngym_evidence.workflow import _schema, _validate_output


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.pending = [{"claim": request()["claims"][0], "evidence_refs": ["source:entry"]}]
        self.evidence = [{"evidence_id": "source:entry", "status": "available",
                          "kind": "source", "numbered_source": "1 | input()"}]

    def output(self, assessment):
        value = checked_output()
        row = value["results"][0]
        del row["verdict"]
        del row["countercheck"]["status"]
        row["assessment"] = assessment
        return value

    def test_supported_and_contradicted_keep_existing_result_contract(self):
        for verdict, status in (("supported", "no_conflict_in_scope"), ("contradicted", "conflict_found")):
            result = _validate_output(self.output(verdict + ":" + status), self.pending, self.evidence)["entry"]
            self.assertEqual(result["verdict"], verdict)
            self.assertEqual(result["countercheck"]["status"], status)
            self.assertTrue(result["countercheck"]["observations"][0]["quote_verified"])

    def test_incompatible_pair_is_rejected(self):
        for assessment in ("contradicted:no_conflict_in_scope", "supported:unresolved", None):
            with self.subTest(assessment=assessment), self.assertRaises(ValueError):
                _validate_output(self.output(assessment), self.pending, self.evidence)

    def test_extra_status_or_verdict_cannot_override_assessment(self):
        for target, field in (("row", "verdict"), ("check", "status")):
            value = self.output("contradicted:conflict_found")
            row = value["results"][0]
            (row if target == "row" else row["countercheck"])[field] = "supported"
            with self.assertRaises(ValueError):
                _validate_output(value, self.pending, self.evidence)

    def test_new_assessment_does_not_bypass_literal_or_confidence_guard(self):
        value = self.output("supported:no_conflict_in_scope")
        value["results"][0]["countercheck"]["observations"][0]["quote"] = "invented()"
        with self.assertRaises(ValueError):
            _validate_output(value, self.pending, self.evidence)
        value = self.output("supported:no_conflict_in_scope")
        value["results"][0]["confidence"] = 0.5
        self.assertEqual(_validate_output(value, self.pending, self.evidence)["entry"]["verdict"], "uncertain")

    def test_legacy_inconsistent_status_still_abstains(self):
        value = checked_output("contradicted", status="no_conflict_in_scope")
        self.assertEqual(_validate_output(value, self.pending, self.evidence)["entry"]["verdict"], "uncertain")

    def test_schema_exposes_only_coherent_assessments(self):
        schema = _schema(["entry"], ["source:entry"], ["source:entry"])
        properties = schema["properties"]["results"]["items"]["properties"]
        self.assertNotIn("verdict", properties)
        self.assertNotIn("status", properties["countercheck"]["properties"])
        self.assertEqual(len(properties["assessment"]["enum"]), 4)
