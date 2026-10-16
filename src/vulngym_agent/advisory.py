from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


IDENTIFIER_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})$", re.IGNORECASE)
COMMIT_URL_RE = re.compile(r"/commit/([0-9a-f]{7,40})(?:$|[/?#])", re.IGNORECASE)
COMMIT_SHA_RE = re.compile(r"(?<![0-9a-f])([0-9a-f]{7,40})(?![0-9a-f])", re.IGNORECASE)
INLINE_FIXED_RE = re.compile(
    r"\b(?:fixed|patched)\s+(?:in|by|with)\s+`?([0-9a-f]{7,40})`?",
    re.IGNORECASE,
)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _identifiers(value: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for field in ("id", "ghsa_id", "cve_id", "aliases", "vuln_ids", "identifiers"):
        raw = value.get(field)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    candidates.extend(_strings(item.get("value")))
                else:
                    candidates.extend(_strings(item))
        elif isinstance(raw, dict):
            candidates.extend(_strings(raw.get("value")))
        else:
            candidates.extend(_strings(raw))
    return sorted({item.upper() for item in candidates if IDENTIFIER_RE.fullmatch(item)})


def _references(value: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for field in ("references", "urls", "source_link"):
        raw = value.get(field)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    urls.extend(_strings(item.get("url")))
                else:
                    urls.extend(_strings(item))
        elif isinstance(raw, dict):
            urls.extend(_strings(raw.get("url")))
        else:
            urls.extend(_strings(raw))
    return list(dict.fromkeys(urls))


def _bounded_list(value: Any, *, max_items: int = 24, max_chars: int = 1200) -> list[str]:
    return [item[:max_chars] for item in _strings(value)[:max_items]]


def _commit_roles(value: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Extract only explicitly labelled advisory commit roles.

    A SHA appearing in a references list remains untyped.  Free-form text is
    promoted only when it appears below an explicit Markdown-style role
    heading, or in a narrow ``fixed/patched in <sha>`` statement.
    """

    vulnerable = {
        item.lower()
        for item in _strings(value.get("vulnerable_commits"))
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", item)
    }
    fixed = {
        item.lower()
        for item in _strings(value.get("fixed_commits"))
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", item)
    }
    supporting = {
        item.lower()
        for item in _strings(value.get("supporting_fix_commits"))
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", item)
    }

    texts = [
        *_strings(value.get("facts")),
        *_strings(value.get("description")),
        *_strings(value.get("details")),
    ]
    for text in texts:
        role: str | None = None
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            normalized = re.sub(r"^[#>\s]+", "", stripped).strip().lower()
            heading_like = stripped.startswith("#") or normalized.endswith(":")
            if heading_like:
                heading = normalized.rstrip(":").strip()
                if "supporting fix" in heading or "defense-in-depth" in heading or "hardening commit" in heading:
                    role = "supporting"
                elif "vulnerable commit" in heading or "introduced commit" in heading:
                    role = "vulnerable"
                elif "fix commit" in heading or "fixed commit" in heading or "security fix" in heading:
                    role = "fixed"
                else:
                    role = None
                continue

            if role:
                commits = {match.group(1).lower() for match in COMMIT_SHA_RE.finditer(stripped)}
                if role == "vulnerable":
                    vulnerable.update(commits)
                elif role == "fixed":
                    fixed.update(commits)
                else:
                    supporting.update(commits)

            fixed.update(match.group(1).lower() for match in INLINE_FIXED_RE.finditer(stripped))

    return sorted(vulnerable), sorted(fixed), sorted(supporting)


def normalize_advisory(value: dict[str, Any], *, source: str) -> dict[str, Any]:
    identifiers = _identifiers(value)
    references = _references(value)
    title = next((value[field].strip() for field in ("summary", "title") if isinstance(value.get(field), str) and value[field].strip()), None)
    referenced_commits = sorted({match.group(1).lower() for url in references for match in COMMIT_URL_RE.finditer(url)})
    vulnerable_commits, fixed_commits, supporting_fix_commits = _commit_roles(value)
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return {
        "advisory_key": identifiers[0] if identifiers else f"sha256:{digest[:16]}",
        "identifiers": identifiers,
        "title": title,
        "references": references,
        "referenced_commits": referenced_commits,
        "vulnerable_commits": vulnerable_commits,
        "fixed_commits": fixed_commits,
        "supporting_fix_commits": supporting_fix_commits,
        "facts": _bounded_list(value.get("facts")),
        "weaknesses": _bounded_list(value.get("weaknesses")),
        "affected_versions": _bounded_list(value.get("affected_versions")),
        "patched_versions": _bounded_list(value.get("patched_versions")),
        "source": source,
        "source_sha256": digest,
    }


def _objects_from_path(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    if path.suffix.lower() == ".jsonl":
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: advisory row must be an object")
            yield value, f"{path.name}:{line_number}"
        return
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and isinstance(value.get("advisories"), list):
        value = value["advisories"]
    if isinstance(value, list):
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{index}: advisory item must be an object")
            yield item, f"{path.name}:{index}"
    elif isinstance(value, dict):
        yield value, path.name
    else:
        raise ValueError(f"{path}: advisory JSON must be an object or list")


def load_advisory_cache(paths: Iterable[Path]) -> list[dict[str, Any]]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(candidate for candidate in path.rglob("*") if candidate.suffix.lower() in {".json", ".jsonl"}))
        elif path.is_file():
            files.append(path)
        else:
            raise ValueError(f"advisory cache path does not exist: {path}")
    documents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in files:
        for value, source in _objects_from_path(path):
            document = normalize_advisory(value, source=source)
            if document["source_sha256"] not in seen:
                seen.add(document["source_sha256"])
                documents.append(document)
    return documents


def advisory_evidence(record: dict[str, Any], documents: Iterable[dict[str, Any]]) -> dict[str, Any]:
    wanted_ids = {
        item.upper()
        for item in [*(_strings(record.get("report_id"))), *(_strings(record.get("vuln_ids")))]
        if IDENTIFIER_RE.fullmatch(item)
    }
    source_link = record.get("source_link")
    wanted_url = source_link.rstrip("/").lower() if isinstance(source_link, str) else None
    matches: list[dict[str, Any]] = []
    for document in documents:
        ids = set(document.get("identifiers", []))
        urls = {url.rstrip("/").lower() for url in document.get("references", []) if isinstance(url, str)}
        matched_by = []
        if wanted_ids & ids:
            matched_by.append("identifier")
        if wanted_url and wanted_url in urls:
            matched_by.append("source_link")
        if not matched_by:
            continue
        item = dict(document)
        item["matched_by"] = matched_by
        item["evidence_id"] = f"advisory:{document['advisory_key']}:{document['source_sha256'][:12]}"
        matches.append(item)
    return {
        "status": "matched" if matches else "missing",
        "query_identifiers": sorted(wanted_ids),
        "query_source_link": source_link,
        "documents": matches,
    }
