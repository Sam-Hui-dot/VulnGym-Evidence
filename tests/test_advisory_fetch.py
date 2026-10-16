from __future__ import annotations

import io
import json
import unittest
from urllib.error import HTTPError

from vulngym_agent.advisory_fetch import fetch_advisories


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AdvisoryFetchTests(unittest.TestCase):
    def test_prefers_github_and_enriches_security_fields(self) -> None:
        def opener(request, timeout):
            self.assertIn("api.github.com/advisories/ghsa-2345-6789-cfgh", request.full_url)
            return Response(json.dumps({
                "ghsa_id": "GHSA-2345-6789-CFGH",
                "summary": "Example issue",
                "description": "Attacker input reaches a sink.",
                "cwes": [{"cwe_id": "CWE-78", "name": "Command Injection"}],
                "vulnerabilities": [{
                    "package": {"name": "demo"},
                    "vulnerable_version_range": "< 1.2.3",
                    "first_patched_version": {"identifier": "1.2.3"},
                }],
            }).encode())

        documents, failures = fetch_advisories(
            [{"report_id": "GHSA-2345-6789-CFGH"}], opener=opener
        )
        self.assertFalse(failures)
        self.assertEqual(documents[0]["retrieval_source"], "github")
        self.assertEqual(documents[0]["weaknesses"], ["CWE-78 Command Injection"])
        self.assertEqual(documents[0]["patched_versions"], ["demo: 1.2.3"])

    def test_falls_back_to_osv_after_github_404(self) -> None:
        def opener(request, timeout):
            if "github.com" in request.full_url:
                raise HTTPError(request.full_url, 404, "missing", {}, None)
            return Response(json.dumps({
                "id": "GHSA-2345-6789-CFGH",
                "aliases": ["CVE-2026-12345"],
                "summary": "OSV fallback",
                "details": "Fallback facts",
            }).encode())

        documents, failures = fetch_advisories(
            [{"report_id": "GHSA-2345-6789-CFGH"}], opener=opener
        )
        self.assertFalse(failures)
        self.assertEqual(documents[0]["retrieval_source"], "osv")

    def test_uses_github_html_when_api_is_rate_limited(self) -> None:
        def opener(request, timeout):
            if "api.github.com" in request.full_url:
                raise HTTPError(request.full_url, 403, "rate limited", {}, None)
            page = '''<html><head>
                <meta property="og:description" content="Example &amp; issue">
                <meta property="og:title" content="CVE-2026-12345 - GitHub Advisory Database">
                </head><body>GHSA-2345-6789-CFGH CVE-2026-12345</body></html>'''
            return Response(page.encode())

        documents, failures = fetch_advisories(
            [{"report_id": "GHSA-2345-6789-CFGH"}], opener=opener
        )
        self.assertFalse(failures)
        self.assertEqual(documents[0]["retrieval_source"], "github_html")
        self.assertEqual(documents[0]["summary"], "Example & issue")
        self.assertIn("CVE-2026-12345", documents[0]["identifiers"])


if __name__ == "__main__":
    unittest.main()
