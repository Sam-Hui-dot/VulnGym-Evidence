from __future__ import annotations


def valid_record(entry_id: str = "entry-00001", repo_url: str = "https://github.com/acme/example") -> dict:
    return {
        "entry_id": entry_id,
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "vuln_ids": ["CVE-2026-12345", "GHSA-AAAA-BBBB-CCCC"],
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "acme/example",
        "repo_url": repo_url,
        "commit": "a" * 40,
        "vuln_title": "Example vulnerability",
        "vuln_category_l1": "代码注入",
        "vuln_category_l2": "Command Injection",
        "entry_point": {"file": "src/app.py", "line": 10, "code": "handle(request)"},
        "critical_operation": {"file": "src/core.py", "line": "20-21", "code": "run(value)"},
        "trace": [
            {"file": "src/app.py", "line": 10, "code": "handle(request)"},
            {"file": "src/core.py", "line": 20, "code": "run(value)"},
        ],
        "verify": 1,
    }

