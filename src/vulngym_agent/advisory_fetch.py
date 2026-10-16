from __future__ import annotations

import json
import html
import re
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


JsonOpener = Callable[..., Any]


def _request_json(url: str, *, timeout: float, token: str | None, opener: JsonOpener) -> dict[str, Any]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "VulnGym-Agent/1.0"}
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with opener(request, timeout=timeout) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("advisory response is not an object")
    return value


def _request_text(url: str, *, timeout: float, opener: JsonOpener) -> str:
    request = Request(url, headers={"Accept": "text/html", "User-Agent": "VulnGym-Agent/1.0"})
    with opener(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _github_html_advisory(report_id: str, page: str, url: str) -> dict[str, Any]:
    meta = re.search(
        r'<meta\s+property=["\']og:description["\']\s+content=["\']([^"\']+)',
        page,
        flags=re.IGNORECASE,
    )
    title = html.unescape(meta.group(1)).strip() if meta else None
    identifiers = sorted({item.upper() for item in re.findall(r"(?:GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}|CVE-\d{4}-\d{4,})", page, flags=re.IGNORECASE)})
    if report_id.upper() not in identifiers:
        identifiers.append(report_id.upper())
    if not title:
        raise ValueError("GitHub advisory page has no structured description")
    return {
        "ghsa_id": report_id.upper(),
        "identifiers": identifiers,
        "summary": title,
        "facts": [title],
        "references": [{"url": url}],
        "retrieval_source": "github_html",
        "retrieval_url": url,
    }


def _error_label(exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    return type(exc).__name__


def _enrich_github(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    description = value.get("description")
    if isinstance(description, str) and description.strip():
        result["facts"] = [description.strip()]
    cwes = value.get("cwes")
    if isinstance(cwes, list):
        result["weaknesses"] = [
            " ".join(str(item.get(key, "")).strip() for key in ("cwe_id", "name")).strip()
            for item in cwes
            if isinstance(item, dict)
        ]
    affected: list[str] = []
    patched: list[str] = []
    for item in value.get("vulnerabilities", []) if isinstance(value.get("vulnerabilities"), list) else []:
        if not isinstance(item, dict):
            continue
        package = item.get("package") if isinstance(item.get("package"), dict) else {}
        prefix = str(package.get("name") or "package")
        version_range = item.get("vulnerable_version_range")
        if isinstance(version_range, str) and version_range:
            affected.append(f"{prefix}: {version_range}")
        first = item.get("first_patched_version")
        if isinstance(first, dict) and isinstance(first.get("identifier"), str):
            patched.append(f"{prefix}: {first['identifier']}")
    result["affected_versions"] = affected
    result["patched_versions"] = patched
    return result


def _enrich_osv(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    details = value.get("details")
    if isinstance(details, str) and details.strip():
        result["facts"] = [details.strip()]
    weaknesses: list[str] = []
    database_specific = value.get("database_specific")
    if isinstance(database_specific, dict):
        raw = database_specific.get("cwe_ids")
        if isinstance(raw, list):
            weaknesses.extend(str(item) for item in raw if isinstance(item, str))
    result["weaknesses"] = weaknesses
    return result


def fetch_advisories(
    records: Iterable[dict[str, Any]],
    *,
    timeout: float = 15.0,
    github_token: str | None = None,
    opener: JsonOpener = urlopen,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Fetch one authoritative document per report with GitHub -> OSV fallback."""
    report_ids = sorted({
        str(record.get("report_id")).upper()
        for record in records
        if isinstance(record.get("report_id"), str) and record["report_id"]
    })
    documents: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for report_id in report_ids:
        attempts = []
        if report_id.startswith("GHSA-"):
            attempts.extend([
                ("github", f"https://api.github.com/advisories/{report_id.lower()}"),
                ("github_html", f"https://github.com/advisories/{report_id.lower()}"),
            ])
        attempts.append(("osv", f"https://api.osv.dev/v1/vulns/{report_id}"))
        errors: list[str] = []
        for source, url in attempts:
            try:
                if source == "github_html":
                    value = _github_html_advisory(
                        report_id,
                        _request_text(url, timeout=timeout, opener=opener),
                        url,
                    )
                else:
                    value = _request_json(url, timeout=timeout, token=github_token, opener=opener)
                    value = _enrich_github(value) if source == "github" else _enrich_osv(value)
                    value["retrieval_source"] = source
                    value["retrieval_url"] = url
                documents.append(value)
                break
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{source}: {_error_label(exc)}")
        else:
            failures.append({"report_id": report_id, "errors": "; ".join(errors)})
    return documents, failures
