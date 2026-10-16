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
from http.server import ThreadingHTTPServer

from vulngym_evidence.contract import input_digest
from vulngym_evidence.demo import load_demo_result
from vulngym_evidence.server import serve_local


class ProductDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.configuration = {"provider": None, "roots": [], "repository": None,
                              "advisory_documents": [], "use_critic": True}
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.thread.join(3)
        self.directory.cleanup()

    def start(self, public=False):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        ready = threading.Event()
        def factory(address, handler):
            # Keep the test itself local even when exercising public-mode rules.
            self.server = ThreadingHTTPServer(("127.0.0.1", address[1]), handler)
            ready.set()
            return self.server
        with patch("vulngym_evidence.server.ThreadingHTTPServer", side_effect=factory):
            self.thread = threading.Thread(target=serve_local, kwargs={
                "port": self.port, "output_dir": Path(self.directory.name),
                "configuration": self.configuration,
                "public_origin": "https://example.modelscope.cn" if public else None}, daemon=True)
            self.thread.start()
            self.assertTrue(ready.wait(3))
        self.base = f"http://127.0.0.1:{self.port}"

    def fetch(self, path, *, post=False, host=None, token=None):
        headers = {}
        if host:
            headers["Host"] = host
        if token:
            headers["X-Evidence-Token"] = token
            headers["Origin"] = "https://example.modelscope.cn"
        request = Request(self.base + path, data=b"{}" if post else None, headers=headers)
        try:
            return urlopen(request, timeout=3)
        except HTTPError as error:
            return error

    def test_bundled_real_demo_integrity_and_three_distinct_outcomes(self):
        result = load_demo_result()
        self.assertEqual(result["input_sha256"], input_digest(result["request"]))
        self.assertEqual([row["verdict"] for row in result["results"]],
                         ["contradicted", "uncertain", "supported"])
        self.assertTrue(result["created_at"].startswith("2026-10-06"))
        self.assertEqual(len(result["request"]["claims"]), 3)

    def test_local_demo_export_and_module_resources_need_no_model(self):
        self.start()
        value = json.loads(self.fetch("/api/demo-result").read())
        self.assertEqual(value["result"]["input_sha256"], load_demo_result()["input_sha256"])
        self.assertEqual(self.fetch("/evidence-ui.mjs").status, 200)
        self.assertEqual(self.fetch("/polish.css").status, 200)
        for name in ("report.md", "result.json"):
            response = self.fetch("/demo-reports/" + name)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Disposition"], f'attachment; filename="{name}"')
        self.assertIn("frame-ancestors 'none'", self.fetch("/").headers["Content-Security-Policy"])

    def test_public_demo_blocks_private_jobs_and_every_mutation_even_with_token(self):
        self.start(public=True)
        page = self.fetch("/", host="example.modelscope.cn").read().decode()
        token = re.search(r'name="evidence-token" content="([a-f0-9]+)"', page).group(1)
        for path in ("/api/jobs/" + "a"*32, "/reports/"+"a"*32+"/result.json",
                     "/inputs/a.json", "/extractions/a.json"):
            self.assertEqual(self.fetch(path, host="example.modelscope.cn").status, 404)
        for path in ("/api/extract", "/api/verify", "/api/repository", "/api/inputs",
                     "/api/repository-connect"):
            self.assertEqual(self.fetch(path, post=True, host="example.modelscope.cn", token=token).status, 403)
        config = json.loads(self.fetch("/api/config", host="example.modelscope.cn").read())
        self.assertTrue(config["read_only_demo"])
        self.assertEqual(self.fetch("/api/demo-result", host="example.modelscope.cn").status, 200)
        self.assertEqual(self.fetch("/api/examples", host="example.modelscope.cn").status, 404)
        self.assertEqual(self.fetch("/demo-reports/../result.json").status, 404)
        # A cloud proxy may rewrite Host; only the fixed public allowlist is served.
        self.assertEqual(self.fetch("/", host="other.example").status, 200)
        self.assertEqual(self.fetch("/service/status", host="other.example").status, 200)
        self.assertEqual(self.fetch("/api/repository-status", host="other.example").status, 404)
        self.assertIn("https://modelscope.cn", self.fetch("/").headers["Content-Security-Policy"])

    def test_local_mode_keeps_loopback_host_and_connect_token_checks(self):
        self.start()
        self.assertEqual(self.fetch("/", host="other.example").status, 403)
        self.assertEqual(self.fetch("/api/repository-connect", post=True).status, 403)

    def test_connected_checkout_is_used_for_status_and_captured_when_job_is_queued(self):
        self.start()
        page = self.fetch("/").read().decode()
        token = re.search(r'name="evidence-token" content="([a-f0-9]+)"', page).group(1)
        demo = load_demo_result()["request"]
        selected = Path(self.directory.name) / "selected-checkout"
        state = {"repo_url": demo["repo_url"], "reviewed_commit": demo["reviewed_commit"], "ready": True}

        def post(path, value):
            request = Request(self.base + path, data=json.dumps(value).encode(), headers={
                "Content-Type": "application/json", "X-Evidence-Token": token,
                "Origin": self.base})
            return json.loads(urlopen(request, timeout=3).read())

        with patch("vulngym_evidence.server.connect_repository", return_value=(state, selected)):
            post("/api/repository-connect", {"local_path": str(selected), "repo_url": "", "revision": "HEAD"})
        with patch("vulngym_evidence.server.inspect_repository", return_value=state) as inspect:
            post("/api/repository-status", {"repo_url": demo["repo_url"], "reviewed_commit": demo["reviewed_commit"]})
            self.assertEqual(inspect.call_args.kwargs["repository"], selected)
        # Capture submission without starting a real verification or model request.
        with patch("vulngym_evidence.server.ThreadPoolExecutor.submit") as submit:
            post("/api/jobs", demo)
            self.assertEqual(submit.call_args.args[3]["repository"], selected)
            replacement = selected.parent / "another-checkout"
            with patch("vulngym_evidence.server.connect_repository", return_value=(state, replacement)):
                post("/api/repository-connect", {"local_path": str(replacement), "repo_url": "", "revision": "HEAD"})
            self.assertEqual(submit.call_args.args[3]["repository"], selected)

    def test_public_mode_rejects_credentials_paths_and_online_provider(self):
        for origin in ("https://user:password@example.cn", "https://example.cn/private",
                       "https://example.cn?key=value", "file:///tmp/a"):
            with self.assertRaises(ValueError):
                serve_local(port=8765, output_dir=Path(self.directory.name),
                            configuration=self.configuration, public_origin=origin)
        with self.assertRaises(ValueError):
            serve_local(port=8765, output_dir=Path(self.directory.name),
                        configuration={**self.configuration, "provider": object()},
                        public_origin="https://example.cn")
