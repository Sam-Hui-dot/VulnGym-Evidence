from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_agent.provider import ProviderCompletion, ProviderError
from vulngym_evidence.contract import validate_request
from vulngym_evidence.extraction import run_extraction, write_extraction_record
from vulngym_evidence.runtime import model_status


REPORT = "🔎报告称 app.py:42 的 input() 接收外部参数。"
CANDIDATE = {"kind": "entry_point", "text": "第 42 行接收外部输入",
             "source_quote": "app.py:42 的 input()", "file": "app.py", "line": "42",
             "code": "input()", "claimed_fix_commit": ""}


class Provider:
    name = "local-test"
    def __init__(self, rows):
        self.rows = rows
        self.count = 0
    def complete(self, payload):
        self.count += 1
        return ProviderCompletion({"candidates": deepcopy(self.rows)},
            {"resolved_model": "fixture-model", "usage": {"total_tokens": 123, "input_tokens": 100,
             "negative_tokens": -1}, "api_key": "must-not-be-saved"})


class ExtractionAuditTests(unittest.TestCase):
    def test_duplicates_do_not_add_candidates_or_model_calls(self):
        provider = Provider([CANDIDATE, CANDIDATE])
        record = run_extraction(REPORT, provider)
        self.assertEqual(record["status"], "completed")
        self.assertEqual((provider.count, len(record["candidates"]), record["duplicates_removed"]), (1, 1, 1))
        self.assertEqual(record["metadata"]["usage"]["total_tokens"], 123)
        self.assertEqual(len(record["raw_output"]["candidates"]), 2)
        self.assertNotIn("must-not-be-saved", json.dumps(record))
        with tempfile.TemporaryDirectory() as directory:
            write_extraction_record(Path(directory), record)
            self.assertEqual(json.loads((Path(directory) / "record.json").read_text())["model_call_count"], 1)

    def test_invalid_output_retains_returned_usage_and_failure(self):
        row = {**CANDIDATE, "source_quote": "不存在的原文"}
        record = run_extraction(REPORT, Provider([row]))
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["error_code"], "output_invalid")
        self.assertEqual(record["metadata"]["usage"]["total_tokens"], 123)
        self.assertEqual(record["candidates"], [])

    def test_provider_error_does_not_leak_stderr(self):
        class Broken:
            name = "fixture"
            def complete(self, payload):
                raise ProviderError("private-api-key-in-stderr")
        record = run_extraction(REPORT, Broken())
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["metadata"], {})
        self.assertNotIn("private-api-key", json.dumps(record))

    def test_emoji_span_can_be_confirmed_with_contract(self):
        candidate = run_extraction(REPORT, Provider([CANDIDATE]))["candidates"][0]
        start, end = candidate["source_span"]
        value = {"schema_version": "1.0", "case_id": "emoji-case",
                 "repo_url": "https://github.com/example/repo", "reviewed_commit": "a" * 40,
                 "report_text": REPORT, "claims": [{"claim_id": "entry", "kind": "entry_point",
                   "text": candidate["text"], "node": {"file": "app.py", "line": 42, "code": "input()"},
                   "origin": {"quote": candidate["source_quote"], "start": start, "end": end}}]}
        self.assertEqual(validate_request(value)["claims"][0]["origin"]["start"], 5)

    def test_fix_candidate_does_not_require_irrelevant_source_node(self):
        sha = "b" * 40
        row = {**CANDIDATE, "kind": "fix_commit", "source_quote": sha, "claimed_fix_commit": sha,
               "file": "", "line": "", "code": ""}
        result = run_extraction("修复 Commit：" + sha, Provider([row]))["candidates"][0]
        self.assertTrue(result["ready_to_edit"])
        self.assertEqual(result["missing"], [])

    def test_literal_location_does_not_add_vulnerability_assertion(self):
        row = {**CANDIDATE, "kind": "source_location", "text": "这里存在严重漏洞"}
        result = run_extraction(REPORT, Provider([row]))["candidates"][0]
        self.assertEqual(result["text"], "报告引用的源码位置为 app.py:42")

    def test_request_binding_recovers_only_its_associated_location_and_code(self):
        report = ("报告称：internal/handler/mcp_service.go 第 41 行的 ShouldBindJSON "
                  "将客户端提交的 JSON 请求体绑定到 service，因此这里是请求数据入口。\n\n"
                  "引用代码：\n\tif err := c.ShouldBindJSON(&service); err != nil {")
        row = {**CANDIDATE, "source_quote": "ShouldBindJSON 将客户端提交的 JSON 请求体绑定到 service",
               "file": "", "line": "", "code": ""}
        record = run_extraction(report, Provider([row]))
        result = record["candidates"][0]
        self.assertEqual((result["file"], result["line"]), ("internal/handler/mcp_service.go", "41"))
        self.assertEqual(result["code"], "\tif err := c.ShouldBindJSON(&service); err != nil {")
        self.assertTrue(result["ready_to_edit"])
        self.assertEqual(result["associated_fields"], ["file", "line", "code"])
        for field, origin in result["field_origins"].items():
            self.assertEqual(report[origin["start"]:origin["end"]], result[field])
        start, end = result["source_span"]
        self.assertEqual(report[start:end], result["source_quote"])
        self.assertEqual(record["raw_output"]["candidates"][0]["file"], "")

    def test_split_location_and_code_candidates_merge_after_association(self):
        report = "报告称 app.py:42 接收请求体。\n\n引用代码：\n\trequest.json()"
        rows = [
            {**CANDIDATE, "kind": "source_location", "source_quote": "app.py:42", "code": ""},
            {**CANDIDATE, "kind": "source_location", "source_quote": "\trequest.json()",
             "file": "", "line": "", "code": "\trequest.json()"},
        ]
        record = run_extraction(report, Provider(rows))
        self.assertEqual(len(record["candidates"]), 1)
        self.assertEqual(record["duplicates_removed"], 1)
        self.assertEqual(record["candidates"][0]["code"], "\trequest.json()")
        self.assertEqual(len(record["raw_output"]["candidates"]), 2)

    def test_fields_elsewhere_in_report_are_not_borrowed(self):
        report = "报告称 app.py:42 接收请求体。\n\n另一个声明：worker.py:99 执行任务。\n\n引用代码：\n\texecute()"
        row = {**CANDIDATE, "source_quote": "app.py:42 接收请求体",
               "file": "worker.py", "line": "99", "code": "\texecute()"}
        result = run_extraction(report, Provider([row]))["candidates"][0]
        self.assertEqual((result["file"], result["line"], result["code"]), ("app.py", "42", ""))
        self.assertFalse(result["ready_to_edit"])

    def test_multiple_locations_do_not_fill_ambiguous_fields(self):
        report = "app.py:42 和 worker.py:99 均接收输入。\n\n引用代码：\n\tinput()"
        row = {**CANDIDATE, "source_quote": "均接收输入", "file": "", "line": "", "code": ""}
        result = run_extraction(report, Provider([row]))["candidates"][0]
        self.assertEqual((result["file"], result["line"], result["code"]), ("", "", ""))
        self.assertEqual(result["associated_fields"], [])

    def test_repeated_quote_does_not_choose_a_context_arbitrarily(self):
        report = "app.py:42 接收输入。\n\nworker.py:99 接收输入。"
        row = {**CANDIDATE, "source_quote": "接收输入", "file": "", "line": "", "code": ""}
        result = run_extraction(report, Provider([row]))["candidates"][0]
        self.assertFalse(result["ready_to_edit"])
        self.assertEqual(result["file"], "")

    def test_line_numbers_and_code_cannot_be_mixed_across_explicit_locations(self):
        report = "app.py:42 接收输入，worker.py:99 执行 execute()。"
        row = {**CANDIDATE, "source_quote": report, "file": "app.py",
               "line": "99", "code": "execute()"}
        result = run_extraction(report, Provider([row]))["candidates"][0]
        self.assertEqual((result["file"], result["line"], result["code"]), ("app.py", "", ""))
        self.assertFalse(result["ready_to_edit"])

    def test_fenced_excerpt_preserves_indentation_and_ignores_following_prose(self):
        report = "app.py:42 接收请求体。\n\n" + "\x60" * 3 + "python\n\trequest.json()\n" + "\x60" * 3 + "\n\n另一个声明：worker.py:99 执行任务。"
        row = {**CANDIDATE, "source_quote": "接收请求体", "file": "", "line": "", "code": ""}
        result = run_extraction(report, Provider([row]))["candidates"][0]
        self.assertEqual(result["code"], "\trequest.json()")
        self.assertNotIn("worker.py", result["source_quote"])

    def test_unclosed_code_fence_is_not_copied_as_source(self):
        report = "app.py:42 接收请求体。\n\n引用代码：\n" + "\x60" * 3 + "python\n\trequest.json()"
        row = {**CANDIDATE, "source_quote": "接收请求体", "file": "", "line": "", "code": ""}
        result = run_extraction(report, Provider([row]))["candidates"][0]
        self.assertEqual(result["code"], "")

    def test_qwen_status_checks_environment_without_revealing_key(self):
        provider = type("Provider", (), {"name": "qwen"})()
        with patch.dict("os.environ", {"VULNGYM_QWEN_ENABLED": "true", "DASHSCOPE_API_KEY": "secret-value"}, clear=True):
            status = model_status(provider)
        self.assertTrue(status["model_ready"])
        self.assertNotIn("secret-value", json.dumps(status))
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(model_status(provider)["model_ready"])


if __name__ == "__main__":
    unittest.main()
