from copy import deepcopy
import unittest

from vulngym_evidence.workflow import _checked_excerpts, _schema, _validate_output


class SourceLineSelectionTests(unittest.TestCase):
    def setUp(self):
        self.evidence = {"source:own": {"evidence_id": "source:own", "status": "available", "kind": "source",
            "file": "handler.go", "context_range": "10-12", "commit": "a" * 40,
            "numbered_source": "    10 | \tif valid {\n    11 | \t\treturn '\\\\u003c'\n    12 | \t}"}}
        self.check = {"status": "no_conflict_in_scope", "reason": "核对指定源码",
                      "evidence_refs": ["source:own"],
                      "observations": [{"evidence_id": "source:own", "start_line": 10, "end_line": 12}]}

    def test_literal_copy_preserves_tabs_and_escape_characters(self):
        checked = _checked_excerpts(self.check, self.evidence, {"source:own"})
        observation = checked["observations"][0]
        self.assertEqual(observation["quote"], "\tif valid {\n\t\treturn '\\\\u003c'\n\t}")
        self.assertEqual(observation["source_line_range"], [10, 12])
        self.assertTrue(observation["quote_verified"])

    def test_another_windows_lines_cannot_be_borrowed(self):
        self.evidence["source:other"] = {**self.evidence["source:own"], "numbered_source": "13 | return success"}
        self.check["observations"][0].update(start_line=12, end_line=13)
        with self.assertRaisesRegex(ValueError, "超出该证据窗口"):
            _checked_excerpts(self.check, self.evidence, {"source:own", "source:other"})

    def test_noncontiguous_or_ambiguous_source_is_rejected(self):
        for source in ("10 | before()\n12 | after()", "10 | before()\n10 | after()"):
            with self.subTest(source=source):
                self.evidence["source:own"]["numbered_source"] = source
                with self.assertRaises(ValueError):
                    _checked_excerpts(self.check, self.evidence, {"source:own"})

    def test_invalid_range_types_and_length_are_rejected(self):
        for start, end in ((True, 12), (10, False), (12, 10), (0, 1), (10, 16)):
            with self.subTest(start=start, end=end):
                self.check["observations"][0].update(start_line=start, end_line=end)
                with self.assertRaises(ValueError):
                    _checked_excerpts(self.check, self.evidence, {"source:own"})

    def test_other_claim_sources_and_non_source_items_are_rejected(self):
        with self.assertRaises(ValueError):
            _checked_excerpts(self.check, self.evidence, {"source:other"})
        self.evidence["source:own"]["kind"] = "advisory"
        with self.assertRaises(ValueError):
            _checked_excerpts(self.check, self.evidence, {"source:own"})

    def test_selector_does_not_bypass_semantic_countercheck(self):
        claim = {"claim_id": "own", "kind": "entry_point", "text": "此处绑定输入"}
        pending = [{"claim": claim, "evidence_refs": ["source:own"]}]
        output = {"results": [{"claim_id": "own", "verdict": "supported", "confidence": 0.9,
            "reason": "读取了该位置", "evidence_refs": ["source:own"],
            "countercheck": {**deepcopy(self.check), "status": "unresolved"}}]}
        result = _validate_output(output, pending, list(self.evidence.values()))["own"]
        self.assertEqual(result["verdict"], "uncertain")
        self.assertTrue(result["countercheck"]["observations"][0]["quote_verified"])

    def test_schema_binds_range_bounds_to_each_source(self):
        schema = _schema(["own"], ["source:own", "source:other"], ["source:own", "source:other"],
                         {"source:own": (10, 12), "source:other": (30, 35)})
        observations = schema["properties"]["results"]["items"]["properties"]["countercheck"]["properties"]["observations"]
        self.assertEqual(observations["minItems"], 1)
        selector = observations["items"]
        self.assertNotIn("anyOf", selector)
        self.assertEqual(selector["properties"]["evidence_id"]["enum"], ["source:own", "source:other"])
        self.assertEqual(selector["properties"]["start_line"], {"type": "integer", "minimum": 10, "maximum": 35})
        self.assertEqual(selector["properties"]["line_count"]["maximum"], 6)

    def test_count_selector_copies_only_the_requested_lines(self):
        self.check["observations"] = [{"evidence_id": "source:own", "start_line": 10, "line_count": 2}]
        observation = _checked_excerpts(self.check, self.evidence, {"source:own"})["observations"][0]
        self.assertEqual(observation["source_line_range"], [10, 11])
        self.assertEqual(observation["quote"], "\tif valid {\n\t\treturn '\\\\u003c'")

    def test_count_selector_cannot_overrun_or_bypass_the_short_range_limit(self):
        for start, count in ((10, True), (True, 2), (10, 0), (10, 7), (12, 2)):
            with self.subTest(start=start, count=count):
                self.check["observations"] = [{"evidence_id": "source:own", "start_line": start, "line_count": count}]
                with self.assertRaises(ValueError):
                    _checked_excerpts(self.check, self.evidence, {"source:own"})

    def test_schema_limits_each_selected_line_to_the_window(self):
        schema = _schema(["own"], ["source:own"], ["source:own"], {"source:own": (10, 12)})
        selector = schema["properties"]["results"]["items"]["properties"]["countercheck"]["properties"]["observations"]["items"]
        self.assertEqual(selector["required"], ["evidence_id", "start_line", "line_count"])
        self.assertEqual(selector["properties"]["start_line"], {"type": "integer", "minimum": 10, "maximum": 12})

    def test_line_array_copies_the_exact_contiguous_source(self):
        self.check["observations"] = [{"evidence_id": "source:own", "lines": [10, 11]}]
        observation = _checked_excerpts(self.check, self.evidence, {"source:own"})["observations"][0]
        self.assertEqual(observation["source_line_range"], [10, 11])
        self.assertEqual(observation["quote"], "\tif valid {\n\t\treturn '\\\\u003c'")

    def test_precomputed_selector_cannot_borrow_another_windows_line(self):
        self.check["observations"] = [{"source_line_id": "S0L11"}]
        actual = _checked_excerpts(self.check, self.evidence, {"source:own"})["observations"][0]
        self.assertEqual(actual["source_line_range"], [11, 11])
        self.assertEqual(actual["quote"], "\t\treturn '\\\\u003c'")
        for selector in ("S0L13", "S9L11", True):
            self.check["observations"] = [{"source_line_id": selector}]
            with self.assertRaises(ValueError):
                _checked_excerpts(self.check, self.evidence, {"source:own"})

    def test_selector_from_another_claim_remains_forbidden(self):
        self.evidence["source:other"] = {**self.evidence["source:own"], "evidence_id": "source:other"}
        self.check["observations"] = [{"source_line_id": "S1L11"}]
        with self.assertRaisesRegex(ValueError, "必须属于本声明"):
            _checked_excerpts(self.check, self.evidence, {"source:own"})

    def test_new_schema_only_allows_precomputed_selectors(self):
        schema = _schema(["own"], ["source:own"], ["source:own"],
                         {"source:own": (10, 12)}, ["S0L10", "S0L11"])
        selector = schema["properties"]["results"]["items"]["properties"]["countercheck"]["properties"]["observations"]["items"]
        self.assertEqual(selector["required"], ["source_line_id"])
        self.assertEqual(selector["properties"]["source_line_id"]["enum"], ["S0L10", "S0L11"])

    def test_line_array_rejects_skips_reordering_duplicates_and_invalid_values(self):
        for numbers in ([], [10, 12], [11, 10], [10, 10], [True, 11], [0], [10, 11, 12, 13], list(range(10, 17))):
            with self.subTest(numbers=numbers):
                self.check["observations"] = [{"evidence_id": "source:own", "lines": numbers}]
                with self.assertRaises(ValueError):
                    _checked_excerpts(self.check, self.evidence, {"source:own"})


if __name__ == "__main__":
    unittest.main()
