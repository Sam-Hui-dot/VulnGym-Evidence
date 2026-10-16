from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

from tests.git_fixture import create_fix_history
from tests.test_evidence_contract import request
import tests.test_evidence_extraction_http as fixture_http
from vulngym_evidence.contract import InputError, validate_repository_query, validate_request
from vulngym_evidence.report import result_label, write_outputs
from vulngym_evidence.runtime import inspect_repository
from vulngym_evidence.workflow import verify_request


class RepositoryStatusTests(unittest.TestCase):
    def test_invalid_query_cannot_be_used_as_git_revision(self):
        for value in ({"repo_url": "https://github.com/acme/example", "reviewed_commit": "HEAD"},
                      {"repo_url": "https://token@github.com/acme/example", "reviewed_commit": "a"*40},
                      {"repo_url": "https://github.com/acme/example", "reviewed_commit": "a"*40, "path": "/tmp"}):
            with self.subTest(value=value), self.assertRaises(InputError):
                validate_repository_query(value)

    def test_repository_origin_and_missing_version_are_distinguished(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            commit, _ = create_fix_history(root)
            query = {"repo_url": "https://github.com/acme/example", "reviewed_commit": commit}
            self.assertTrue(inspect_repository(query, repository=root)["ready"])
            missing = inspect_repository({**query, "reviewed_commit": "a"*40}, repository=root)
            self.assertFalse(missing["ready"])
            self.assertIn("没有该版本", missing["message"])
            wrong = inspect_repository({**query, "repo_url": "https://github.com/other/repo"}, repository=root)
            self.assertFalse(wrong["ready"])
            self.assertIn("尚未准备", wrong["message"])

    def test_model_unavailable_does_not_relabel_completed_location_check(self):
        value = request()
        location = deepcopy(value["claims"][0])
        location.update(kind="source_location", claim_id="location")
        value["claims"].append(location)
        normalized = validate_request(value)
        items = [{"claim": claim, "evidence_refs": [], "gap": None, "literal_match": True,
                  "trace_complete": None, "fix_relation": None} for claim in normalized["claims"]]
        with patch("vulngym_evidence.workflow.collect_evidence", return_value={"claims": items, "evidence": []}):
            result = verify_request(value)
        semantic, literal = result["results"]
        self.assertEqual(semantic["review_status"], "not_configured")
        self.assertEqual(result_label(semantic), "复核未完成")
        self.assertEqual(literal["review_status"], "completed")
        self.assertEqual(result_label(literal), "引用一致")


class SavedJobTests(unittest.TestCase):
    setUp = fixture_http.ExtractionHTTPTests.setUp
    tearDown = fixture_http.ExtractionHTTPTests.tearDown

    def saved_result(self):
        value = request()
        value["claims"][0]["kind"] = "source_location"
        normalized = validate_request(value)
        item = {"claim": normalized["claims"][0], "evidence_refs": [], "gap": None, "literal_match": True,
                "trace_complete": None, "fix_relation": None}
        with patch("vulngym_evidence.workflow.collect_evidence", return_value={"claims": [item], "evidence": []}):
            return verify_request(value)

    def test_completed_job_is_restored_from_disk_without_model_calls(self):
        job_id = "a"*32
        write_outputs(Path(self.directory.name)/job_id, self.saved_result())
        job = json.loads(urlopen(self.base+"/api/jobs/"+job_id, timeout=3).read())
        self.assertTrue(job["restored_from_disk"])
        self.assertEqual(job["status"], "completed")
        self.assertEqual(self.provider.calls, 0)
        self.assertIn("引用一致", urlopen(self.base+"/reports/"+job_id+"/report.md").read().decode())

    def test_changed_input_digest_and_unsafe_job_paths_are_rejected(self):
        job_id = "b"*32
        result = self.saved_result()
        result["input_sha256"] = "0"*64
        write_outputs(Path(self.directory.name)/job_id, result)
        for path in ("/api/jobs/"+job_id, "/reports/"+job_id+"/result.json", "/api/jobs/..%2Fprivate"):
            with self.subTest(path=path), self.assertRaises(HTTPError) as error:
                urlopen(self.base+path, timeout=3)
            self.assertEqual(error.exception.code, 404)

    def test_demo_contains_no_completed_results_and_preserves_exact_origins(self):
        demo = json.loads(urlopen(self.base+"/api/demo", timeout=3).read())
        self.assertNotIn("results", demo)
        self.assertIn("教学", demo["provenance"])
        validate_request(demo["request"])
