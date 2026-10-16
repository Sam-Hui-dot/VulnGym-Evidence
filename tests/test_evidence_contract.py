from copy import deepcopy
import unittest
from unittest.mock import patch

from vulngym_agent.provider import ProviderCompletion, ProviderError
from vulngym_evidence.contract import InputError, import_t1, validate_request
from vulngym_evidence.extraction import extract_candidates
from vulngym_evidence.report import render_html
from vulngym_evidence.go_types import collect_go_types
from vulngym_evidence.workflow import _validate_output, verify_request


def request():
    return {"schema_version": "1.0", "case_id": "case-1", "repo_url": "https://github.com/example/repo",
            "reviewed_commit": "a" * 40, "claims": [{"claim_id": "entry", "kind": "entry_point",
            "text": "此处接受外部输入", "node": {"file": "app.py", "line": 1, "code": "input()"}}]}


def checked_output(verdict="supported", refs=None, status="no_conflict_in_scope"):
    refs = ["source:entry"] if refs is None else refs
    return {"results": [{"claim_id": "entry", "verdict": verdict, "confidence": 0.9,
                         "reason": "源码上下文支持本条声明", "evidence_refs": refs,
                         "countercheck": {"status": status, "reason": "检查同一源码上下文中的相反线索",
                                          "evidence_refs": refs,
                                          "observations": ([{"evidence_id": refs[0], "quote": "input()"}]
                                                           if refs else [])}}]}


class ContractTests(unittest.TestCase):
    def test_optional_taxonomy_is_not_required(self):
        value = validate_request(request())
        self.assertEqual([item["kind"] for item in value["claims"]], ["entry_point"])
        self.assertNotIn("vuln_category_l1", value)

    def test_duplicate_claims_are_rejected(self):
        value = request()
        value["claims"].append(deepcopy(value["claims"][0]))
        with self.assertRaises(InputError):
            validate_request(value)

    def test_confirmed_origin_must_match_exact_report_span(self):
        value = request()
        value["report_text"] = " 开头：\napp.py:1 的 input() 是入口。\n"
        quote = "app.py:1 的 input()"
        start = value["report_text"].index(quote)
        value["claims"][0]["origin"] = {"quote": quote, "start": start, "end": start + len(quote)}
        normalized = validate_request(value)
        self.assertEqual(normalized["report_text"], value["report_text"])
        self.assertEqual(normalized["claims"][0]["origin"]["start"], start)
        value["report_text"] = "报告已改，原文位置不再匹配。"
        with self.assertRaises(InputError):
            validate_request(value)

    def test_escaping_repository_path_is_an_input_error(self):
        value = request()
        value["claims"][0]["node"]["file"] = "../outside.py"
        with self.assertRaises(InputError):
            validate_request(value)

    def test_fix_claim_cannot_supply_trusted_fix(self):
        value = request()
        value["claims"] = [{"claim_id": "fix", "kind": "fix_commit", "text": "修复提交归属",
                            "claimed_fix_commit": "b" * 40, "explicit_fix_commit": "b" * 40}]
        with self.assertRaises(InputError):
            validate_request(value)

    def test_t1_commit_is_only_reviewed_version(self):
        value = request()
        record = {"entry_id": "entry-00001", "repo_url": value["repo_url"],
                  "commit": "a" * 40, "entry_point": value["claims"][0]["node"]}
        result = import_t1(record)
        self.assertEqual(result["reviewed_commit"], "a" * 40)
        self.assertFalse(any(item["kind"] == "fix_commit" for item in result["claims"]))

    def test_git_existence_alone_cannot_support_security_role(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["git:reviewed_commit"]}]
        evidence = [{"evidence_id": "git:reviewed_commit", "status": "available", "kind": "git"}]
        output = checked_output(refs=["git:reviewed_commit"])
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_other_claim_evidence_cannot_be_cited(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:own"]}]
        evidence = [{"evidence_id": "source:other", "status": "available", "kind": "source", "numbered_source": "1 | input()"}]
        output = checked_output(refs=["source:other"])
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_reference_mentioned_only_in_reason_does_not_count(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:own"]}]
        evidence = [{"evidence_id": "source:own", "status": "available", "kind": "source", "numbered_source": "1 | input()"}]
        for verdict in ("supported", "uncertain"):
            with self.subTest(verdict=verdict):
                output = checked_output(verdict, refs=[])
                with self.assertRaises(ValueError):
                    _validate_output(output, pending, evidence)

    def test_failed_critic_does_not_leave_accepted_judgment(self):
        value = validate_request(request())
        item = {"claim": value["claims"][0], "evidence_refs": ["source:entry"], "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        packet = {"claims": [item], "evidence": [{"evidence_id": "source:entry",
                  "status": "available", "kind": "source", "numbered_source": "1 | input()"}], "policy": {}}
        output = checked_output()
        class Provider:
            name = "test"
            count = 0
            def complete(self, payload):
                self.count += 1
                if self.count == 2:
                    raise ProviderError("simulated failure")
                return ProviderCompletion(output, {})
        with patch("vulngym_evidence.workflow.collect_evidence", return_value=packet):
            result = verify_request(value, provider=Provider())
        self.assertEqual(result["results"][0]["verdict"], "uncertain")
        self.assertEqual(len(result["model_calls"]), 2)
        self.assertEqual(result["semantic_status"], "model_or_contract_failed")

    def test_matching_source_is_only_a_literal_location_result(self):
        value = request()
        value["claims"][0]["kind"] = "source_location"
        item = {"claim": value["claims"][0], "evidence_refs": ["source:entry"], "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        with patch("vulngym_evidence.workflow.collect_evidence", return_value={"claims": [item], "evidence": []}):
            result = verify_request(value)
        self.assertEqual(result["verdict"], "supported")
        self.assertIn("字面位置", result["results"][0]["reason"])
        self.assertEqual(result["model_calls"], [])

    def test_missing_material_is_not_a_contradiction(self):
        value = request()
        item = {"claim": value["claims"][0], "evidence_refs": ["git:reviewed_commit"],
                "gap": "指定版本不可读取", "literal_match": None, "trace_complete": None, "fix_relation": None}
        with patch("vulngym_evidence.workflow.collect_evidence", return_value={"claims": [item], "evidence": []}):
            result = verify_request(value)
        self.assertEqual(result["verdict"], "uncertain")
        self.assertEqual(result["model_calls"], [])

    def test_matching_source_does_not_prove_entry_without_model(self):
        value = request()
        item = {"claim": value["claims"][0], "evidence_refs": ["source:entry"], "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        with patch("vulngym_evidence.workflow.collect_evidence", return_value={"claims": [item], "evidence": []}):
            result = verify_request(value)
        self.assertEqual(result["verdict"], "uncertain")
        self.assertEqual(result["semantic_status"], "not_configured")

    def test_report_keeps_source_and_model_text_inert(self):
        attack = '<script>alert("source")</script>'
        value = validate_request(request())
        result = {"request": value, "verdict": "uncertain", "scope": "仅评价提交声明",
                  "input_sha256": "0" * 64, "created_at": "2026-10-02T00:00:00+00:00",
                  "elapsed_seconds": 0.1, "model_calls": [], "semantic_status": "not_configured",
                  "results": [{"claim_id": "entry", "kind": "entry_point", "text": attack,
                  "verdict": "uncertain", "confidence": 0.0, "reason": attack,
                  "evidence_refs": ["source:entry"], "basis": "deterministic"}],
                  "evidence_packet": {"evidence": [{"evidence_id": "source:entry", "kind": "source",
                  "status": "available", "file": "app.py", "numbered_source": attack}]}}
        page = render_html(result)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn('id="evidence-0"', page)
        self.assertIn('href="#evidence-0"', page)

    def test_later_activation_cannot_prove_constructor_executes_here(self):
        value = validate_request(request())
        value["claims"][0]["kind"] = "critical_operation"
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:own", "lifecycle:own", "helper:connect"]}]
        evidence = [{"evidence_id": "source:own", "status": "available", "kind": "source", "numbered_source": "1 | input()"},
                    {"evidence_id": "lifecycle:own", "status": "available", "kind": "lifecycle",
                     "constructor_like_calls": ["client.NewClient"],
                     "downstream_activation_calls": [{"line": 20, "call": "client.Start"}]},
                    {"evidence_id": "helper:connect", "status": "available", "kind": "source_helper",
                     "helper": "Connect", "numbered_source": "20 | client.Start()"}]
        output = checked_output(refs=["source:own", "lifecycle:own", "helper:connect"])
        for verdict in ("supported", "contradicted"):
            with self.subTest(verdict=verdict):
                output["results"][0]["verdict"] = verdict
                output["results"][0]["countercheck"]["status"] = "no_conflict_in_scope" if verdict == "supported" else "conflict_found"
                result = _validate_output(output, pending, evidence)["entry"]
                self.assertEqual(result["verdict"], "uncertain")
                self.assertEqual(result["basis"], "guarded_model")
                self.assertIn("constructor_activation_unresolved", result["quality_flags"])

    def test_critic_does_not_receive_initial_model_opinion(self):
        value = validate_request(request())
        item = {"claim": value["claims"][0], "evidence_refs": ["source:entry"], "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        packet = {"claims": [item], "evidence": [{"evidence_id": "source:entry", "status": "available", "kind": "source", "numbered_source": "1 | input()"}]}
        output = checked_output()
        class Provider:
            name = "test"
            payloads = []
            def complete(self, payload):
                self.payloads.append(deepcopy(payload))
                return ProviderCompletion(output, {})
        provider = Provider()
        with patch("vulngym_evidence.workflow.collect_evidence", return_value=packet):
            result = verify_request(value, provider=provider)
        self.assertEqual(len(provider.payloads), 2)
        self.assertEqual(provider.payloads[1]["role"], "critic")
        self.assertNotIn("initial_judgment", provider.payloads[1])
        for payload in provider.payloads:
            scope = payload["review_scope_by_claim"]["entry"]
            self.assertEqual(scope["assertion"], value["claims"][0]["text"])
            self.assertEqual(scope["locations"], [{"file": "app.py", "line": 1}])
            self.assertTrue(scope["background_is_not_an_assertion"])
        schema_refs = provider.payloads[0]["output_schema"]["properties"]["results"]["items"]["properties"]["evidence_refs"]["items"]["enum"]
        self.assertEqual(schema_refs, ["source:entry"])
        self.assertEqual(provider.payloads[0]["output_schema"]["properties"]["results"]["items"]["properties"]["evidence_refs"]["minItems"], 1)
        self.assertEqual(result["semantic_status"], "judge_critic_completed")

    def test_request_entry_scope_does_not_include_advisory_attack_conditions(self):
        value = request()
        value["claims"][0]["text"] = "此处将客户端 JSON 请求体绑定到 service。"
        value["claims"][0]["node"]["desc"] = "背景：漏洞报告声称存在命令注入"
        value["vuln_ids"] = ["CVE-2026-22688"]
        value["report_text"] = "命令注入报告背景；本次只确认请求绑定声明。"
        item = {"claim": value["claims"][0], "evidence_refs": ["source:entry"], "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        packet = {"claims": [item], "evidence": [
            {"evidence_id": "source:entry", "status": "available", "kind": "source", "numbered_source": "1 | input()"}]}
        payloads = []
        class Provider:
            name = "test"
            def complete(self, payload):
                payloads.append(deepcopy(payload))
                return ProviderCompletion(checked_output(), {})
        with patch("vulngym_evidence.workflow.collect_evidence", return_value=packet):
            result = verify_request(value, provider=Provider())
        for payload in payloads:
            scope = payload["review_scope_by_claim"]["entry"]
            self.assertEqual(scope["assertion"], "此处将客户端 JSON 请求体绑定到 service。")
            self.assertNotIn("命令注入", scope["assertion"])
            self.assertNotIn("desc", scope["locations"][0])
        self.assertEqual(result["results"][0]["verdict"], "supported")

    def test_countercheck_needs_specific_source_reference_for_clear_verdict(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source", "numbered_source": "1 | input()"}]
        output = checked_output(status="not_checked")
        result = _validate_output(output, pending, evidence)["entry"]
        self.assertEqual(result["verdict"], "uncertain")
        self.assertEqual(result["countercheck"]["status"], "not_checked")
        output["results"][0]["countercheck"]["status"] = "no_conflict_in_scope"
        output["results"][0]["countercheck"]["evidence_refs"] = []
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_countercheck_is_retained_in_report(self):
        value = request()
        result = {"request": value, "verdict": "supported", "scope": "只检查声明",
                  "input_sha256": "0" * 64, "created_at": "2026-10-03T00:00:00+00:00",
                  "elapsed_seconds": 0.1, "model_calls": [], "semantic_status": "judge_completed",
                  "results": [{**checked_output()["results"][0], "kind": "entry_point",
                               "text": "入口", "basis": "model"}],
                  "evidence_packet": {"evidence": [{"evidence_id": "source:entry", "kind": "source",
                                                    "status": "available"}]}}
        page = render_html(result)
        self.assertIn("主审反证检查", page)
        self.assertIn("检查同一源码上下文", page)

    def test_fabricated_countercheck_excerpt_is_rejected_despite_valid_id(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | value = input()\n2 | print(value)"}]
        output = checked_output()
        output["results"][0]["countercheck"]["observations"][0]["quote"] = "validate_all_middleware()"
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_quote_from_different_window_cannot_support_countercheck(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry", "source:other"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | input()"},
                    {"evidence_id": "source:other", "status": "available", "kind": "source",
                     "numbered_source": "8 | check_middleware()"}]
        output = checked_output()
        output["results"][0]["countercheck"]["observations"][0]["quote"] = "check_middleware()"
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_advisory_text_cannot_be_promoted_to_source_observation(self):
        value = validate_request(request())
        refs = ["source:entry", "advisory:entry"]
        pending = [{"claim": value["claims"][0], "evidence_refs": refs}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | input()"},
                    {"evidence_id": "advisory:entry", "status": "available", "kind": "advisory",
                     "numbered_source": "1 | input()"}]
        output = checked_output(refs=refs)
        output["results"][0]["countercheck"]["observations"][0]["evidence_id"] = "advisory:entry"
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_clear_verdict_without_countercheck_excerpt_abstains(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | input()"}]
        output = checked_output()
        output["results"][0]["countercheck"]["observations"] = []
        result = _validate_output(output, pending, evidence)["entry"]
        self.assertEqual(result["verdict"], "uncertain")
        self.assertIn("countercheck_excerpt_missing", result["quality_flags"])

    def test_verified_excerpt_keeps_exact_source_and_window_scope(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | value = input()\n2 | print(value)",
                     "file": "app.py", "context_range": "1-2", "commit": "a" * 40}]
        output = checked_output()
        quote = "value = input()\nprint(value)"
        output["results"][0]["countercheck"]["observations"][0]["quote"] = quote
        result = _validate_output(output, pending, evidence)["entry"]
        self.assertEqual(result["verdict"], "supported")
        observation = result["countercheck"]["observations"][0]
        self.assertEqual(observation["quote"], quote)
        self.assertTrue(observation["quote_verified"])
        self.assertEqual(observation["context_range"], "1-2")
        self.assertIn("未读取", result["countercheck"]["scope_note"])

    def test_unchecked_countercheck_can_keep_empty_observations(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | input()"}]
        output = checked_output("uncertain", status="not_checked")
        output["results"][0]["countercheck"]["observations"] = []
        result = _validate_output(output, pending, evidence)["entry"]
        self.assertEqual(result["verdict"], "uncertain")
        self.assertEqual(result["countercheck"]["observations"], [])

    def test_countercheck_schema_excludes_advisories_and_bodyless_contexts(self):
        value = request()
        refs = ["source:entry", "advisory:entry", "helper:missing-body"]
        item = {"claim": value["claims"][0], "evidence_refs": refs, "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        packet = {"claims": [item], "evidence": [
            {"evidence_id": "source:entry", "status": "available", "kind": "source", "numbered_source": "1 | input()"},
            {"evidence_id": "advisory:entry", "status": "available", "kind": "advisory", "numbered_source": "1 | input()"},
            {"evidence_id": "helper:missing-body", "status": "available", "kind": "source_helper"}]}
        payloads = []
        class Provider:
            name = "test"
            def complete(self, payload):
                payloads.append(deepcopy(payload))
                return ProviderCompletion(checked_output(), {})
        with patch("vulngym_evidence.workflow.collect_evidence", return_value=packet):
            result = verify_request(value, provider=Provider())
        self.assertEqual(result["verdict"], "supported")
        for payload in payloads:
            observations = payload["output_schema"]["properties"]["results"]["items"]["properties"]["countercheck"]["properties"]["observations"]
            self.assertEqual(observations["items"]["properties"]["source_line_id"]["enum"], ["S0L1"])

    def test_verified_excerpt_reference_is_retained_even_if_not_duplicated_in_refs(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry", "helper:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | input()"},
                    {"evidence_id": "helper:entry", "status": "available", "kind": "source_helper",
                     "numbered_source": "2 | print(value)"}]
        output = checked_output(refs=["helper:entry"])
        output["results"][0]["countercheck"]["observations"] = [{"evidence_id": "source:entry", "quote": "input()"}]
        result = _validate_output(output, pending, evidence)["entry"]
        self.assertEqual(result["verdict"], "supported")
        self.assertEqual(result["countercheck"]["evidence_refs"], ["helper:entry", "source:entry"])
        self.assertIn("source:entry", result["evidence_refs"])

    def test_source_type_excerpt_is_valid_source_but_summary_is_not(self):
        value = request()
        item = {"claim": value["claims"][0], "evidence_refs": ["type:entry"], "gap": None,
                "literal_match": True, "trace_complete": None, "fix_relation": None}
        packet = {"claims": [item], "evidence": [
            {"evidence_id": "type:entry", "status": "available", "kind": "source_type",
             "numbered_source": "22 | type Request struct {\n23 |     Name string\n24 | }"}]}
        payloads = []
        class Provider:
            name = "test"
            def complete(self, payload):
                payloads.append(deepcopy(payload))
                output = checked_output(refs=["type:entry"])
                output["results"][0]["countercheck"]["observations"] = [
                    {"evidence_id": "type:entry", "quote": "type Request struct {"}]
                return ProviderCompletion(output, {})
        with patch("vulngym_evidence.workflow.collect_evidence", return_value=packet):
            result = verify_request(value, provider=Provider())
        self.assertEqual(result["verdict"], "supported")
        for payload in payloads:
            observations = payload["output_schema"]["properties"]["results"]["items"]["properties"]["countercheck"]["properties"]["observations"]
            self.assertEqual(observations["items"]["properties"]["source_line_id"]["enum"], ["S0L22", "S0L23"])
        forged = checked_output(refs=["type:entry"])
        forged["results"][0]["countercheck"]["observations"] = [
            {"evidence_id": "type:entry", "quote": "This type has no custom unmarshaler."}]
        with self.assertRaises(ValueError):
            _validate_output(forged, [item], packet["evidence"])

    def test_excerpt_cannot_borrow_available_source_owned_by_another_claim(self):
        value = validate_request(request())
        pending = [{"claim": value["claims"][0], "evidence_refs": ["source:entry"]}]
        evidence = [{"evidence_id": "source:entry", "status": "available", "kind": "source",
                     "numbered_source": "1 | input()"},
                    {"evidence_id": "source:other", "status": "available", "kind": "source",
                     "numbered_source": "8 | validate_request()"}]
        output = checked_output()
        output["results"][0]["countercheck"]["observations"] = [{"evidence_id": "source:other", "quote": "validate_request()"}]
        with self.assertRaises(ValueError):
            _validate_output(output, pending, evidence)

    def test_extraction_keeps_unverified_candidates_and_strips_invented_fields(self):
        report = "报告称 app.py:42 的 input() 接收外部参数。"
        class Provider:
            def complete(self, payload):
                self_payload = payload
                assert self_payload["role"] == "claim_extractor"
                return ProviderCompletion({"candidates": [{"kind": "entry_point",
                    "text": "第 42 行是入口", "source_quote": "app.py:42 的 input()",
                    "file": "app.py", "line": "42", "code": "never_in_report()",
                    "claimed_fix_commit": ""}]}, {})
        candidates = extract_candidates(report, Provider())
        self.assertEqual(candidates[0]["status"], "unverified_candidate")
        self.assertEqual(candidates[0]["source_span"], [4, 23])
        self.assertEqual(candidates[0]["code"], "")
        self.assertEqual(candidates[0]["missing"], ["原始代码片段"])
        self.assertFalse(candidates[0]["ready_to_edit"])

    def test_extraction_rejects_unquoted_model_assertion(self):
        class Provider:
            def complete(self, payload):
                return ProviderCompletion({"candidates": [{"kind": "entry_point",
                    "text": "虚构入口", "source_quote": "报告中不存在",
                    "file": "", "line": "", "code": "", "claimed_fix_commit": ""}]}, {})
        with self.assertRaises(ValueError):
            extract_candidates("只有一句背景。", Provider())

    def test_go_request_fields_are_read_from_local_module_only(self):
        files = {"go.mod": "module example.org/repo\n",
                 "handler.go": 'package main\nimport (\n model "example.org/repo/types"\n other "outside.org/types"\n)\nvar service model.Service\nvar external other.Service\n' + '\n'.join('model.Helper%d()' % i for i in range(20)),
                 "types/service.go": 'package types\ntype Service struct {\n Stdio *StdioConfig `json:"stdio_config"`\n Note string `json:"}"` // } does not end struct\n}\ntype StdioConfig struct {\n Command string `json:"command"`\n Args []string `json:"args"`\n}\n'}
        class Repo:
            def read_file(self, commit, path):
                return files[path]
            def list_files(self, commit):
                return list(files)
        contexts = [{"file": "handler.go", "status": "available", "numbered_source": files["handler.go"]}]
        result = collect_go_types(Repo(), "a" * 40, contexts, "entry")
        self.assertEqual([r["type_name"] for r in result], ["Service", "StdioConfig"])
        self.assertTrue(all(r["status"] == "available" for r in result))
        self.assertIn('json:"command"', result[1]["numbered_source"])
        self.assertTrue(all(r["package_path"] == "types" for r in result))

    def test_ambiguous_go_build_definitions_are_not_promoted(self):
        files = {"go.mod": "module example.org/repo\n",
                 "handler.go": 'package main\nimport "example.org/repo/types"\nvar service types.Service\n',
                 "types/linux.go": '//go:build linux\npackage types\ntype Service struct { Value string }\n',
                 "types/windows.go": '//go:build windows\npackage types\ntype Service struct { Value int }\n'}
        class Repo:
            def read_file(self, commit, path):
                return files[path]
            def list_files(self, commit):
                return list(files)
        result = collect_go_types(Repo(), "a" * 40,
            [{"file": "handler.go", "status": "available", "numbered_source": files["handler.go"]}], "entry")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "missing")
        self.assertNotIn("numbered_source", result[0])


if __name__ == "__main__":
    unittest.main()
