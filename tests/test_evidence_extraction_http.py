import json
from pathlib import Path
import re
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from vulngym_agent.provider import ProviderCompletion
from vulngym_evidence.server import serve_local
from http.server import ThreadingHTTPServer


class Provider:
    name = "fixture"
    calls = 0
    def complete(self, payload):
        self.calls += 1
        row = {"kind": "entry_point", "text": "第 42 行接收输入", "file": "app.py",
               "line": "42", "code": "input()", "claimed_fix_commit": "",
               "source_quote": "不存在" if payload["report_text"].startswith("bad") else "app.py:42 的 input()"}
        return ProviderCompletion({"candidates": [row, row]},
                                  {"resolved_model": "fixture", "usage": {"total_tokens": 50}})


class ExtractionHTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.provider = Provider()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        ready = threading.Event()
        def factory(address, handler):
            self.server = ThreadingHTTPServer(address, handler)
            ready.set()
            return self.server
        configuration = {"provider": self.provider, "roots": [], "repository": None,
                         "advisory_documents": [], "use_critic": True}
        with patch("vulngym_evidence.server.ThreadingHTTPServer", side_effect=factory):
            self.thread = threading.Thread(target=serve_local, kwargs={"port": self.port,
                "output_dir": Path(self.directory.name), "configuration": configuration}, daemon=True)
            self.thread.start()
            self.assertTrue(ready.wait(3))
        self.base = f"http://127.0.0.1:{self.port}"
        page = urlopen(self.base, timeout=3).read().decode("utf-8")
        self.token = re.search(r'name="evidence-token" content="([a-f0-9]+)"', page).group(1)

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(3)
        self.directory.cleanup()

    def post(self, report, origin=None):
        request = Request(self.base + "/api/extract",
            data=json.dumps({"report_text": report}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Evidence-Token": self.token,
                     "Origin": origin or self.base})
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as error:
            response = error
        return response.status, json.loads(response.read())

    def test_cached_extraction_download_has_usage_and_zero_additional_calls(self):
        status, first = self.post("🔎报告称 app.py:42 的 input() 接收外部参数。")
        self.assertEqual(status, 200)
        status, cached = self.post("🔎报告称 app.py:42 的 input() 接收外部参数。")
        self.assertEqual(status, 200)
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(cached["extraction_id"], first["extraction_id"])
        self.assertEqual(cached["additional_model_calls"], 0)
        self.assertEqual(cached["duplicates_removed"], 1)
        response = urlopen(self.base + first["download_url"], timeout=3)
        record = json.loads(response.read())
        self.assertEqual(record["metadata"]["usage"]["total_tokens"], 50)
        self.assertEqual(record["candidates"][0]["status"], "unverified_candidate")
        self.assertEqual(record["request"]["report_text"][record["candidates"][0]["source_span"][0]], "a")

    def test_failed_calls_are_saved_and_count_toward_limit(self):
        for index in range(4):
            status, value = self.post("bad report " + str(index))
            self.assertEqual(status, 502)
            record = json.loads(urlopen(self.base + value["download_url"], timeout=3).read())
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["metadata"]["usage"]["total_tokens"], 50)
        status, _ = self.post("bad report 5")
        self.assertEqual(status, 429)
        self.assertEqual(self.provider.calls, 4)

    def test_cross_origin_cannot_start_extraction(self):
        status, _ = self.post("app.py:42 的 input()", "https://outside.example")
        self.assertEqual(status, 403)
        self.assertEqual(self.provider.calls, 0)
