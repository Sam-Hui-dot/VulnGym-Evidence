from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def find_windows_codex_command() -> Path:
    configured = os.environ.get("VULNGYM_CODEX_CMD")
    if configured:
        path = Path(configured)
        if path.is_file():
            return path
        raise RuntimeError(f"VULNGYM_CODEX_CMD does not exist: {path}")

    discovered = shutil.which("codex")
    if discovered:
        command = Path(discovered)
        candidates = (command.with_suffix(".cmd"), command.parent / "codex.cmd")
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    raise RuntimeError("Windows codex.cmd was not found; set VULNGYM_CODEX_CMD to its WSL-visible path")


def to_windows_path(path: Path) -> str:
    completed = subprocess.run(
        ["wslpath", "-w", str(path.resolve())],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"cannot convert path for Windows: {path}")
    return completed.stdout.strip()


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _parse_codex_events(raw_stdout: bytes) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    thread_id: str | None = None
    usage: dict[str, int] | None = None
    text = raw_stdout.decode("utf-8", errors="strict")
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Codex CLI --json emitted invalid JSONL at line {line_number}: {exc}") from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise RuntimeError(f"Codex CLI --json emitted an invalid event at line {line_number}")
        event_type = event["type"]
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
        if event_type == "thread.started" and isinstance(event.get("thread_id"), str):
            thread_id = event["thread_id"]
        if event_type == "turn.completed" and isinstance(event.get("usage"), dict):
            candidate_usage = event["usage"]
            if all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in candidate_usage.values()):
                usage = dict(candidate_usage)

    metadata: dict[str, Any] = {
        "transport": "codex_exec_jsonl",
        "event_counts": dict(sorted(event_counts.items())),
    }
    if thread_id is not None:
        metadata["thread_id"] = thread_id
    if usage is not None:
        metadata["usage"] = usage
    return metadata


def run_codex(request: dict[str, Any]) -> dict[str, Any]:
    schema = request.get("output_schema")
    if not isinstance(schema, dict):
        raise RuntimeError("request.output_schema must be an object")
    codex_command = find_windows_codex_command()
    powershell = shutil.which("powershell.exe")
    if not powershell:
        raise RuntimeError("powershell.exe is unavailable through WSL interop")

    with tempfile.TemporaryDirectory(prefix="vulngym-codex-") as directory:
        root = Path(directory)
        schema_path = root / "output-schema.json"
        output_path = root / "last-message.json"
        schema_path.write_text(json.dumps(schema, ensure_ascii=False), encoding="utf-8")

        windows_codex = to_windows_path(codex_command)
        windows_schema = to_windows_path(schema_path)
        windows_output = to_windows_path(output_path)
        windows_root = to_windows_path(root)
        command = " ".join(
            [
                "&",
                _powershell_quote(windows_codex),
                "exec",
                "--json",
                "--ephemeral",
                "--sandbox read-only",
                "--skip-git-repo-check",
                "--ignore-user-config",
                "--ignore-rules",
                "--color never",
                "--output-schema",
                _powershell_quote(windows_schema),
                "--output-last-message",
                _powershell_quote(windows_output),
                "-C",
                _powershell_quote(windows_root),
                "-; exit $LASTEXITCODE",
            ]
        )
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            input=json.dumps(request, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            stdout = completed.stdout.decode("utf-8", errors="replace").strip()
            diagnostic = stderr or stdout
            if len(diagnostic) > 7000:
                diagnostic = diagnostic[:3500] + "\n… Codex CLI output truncated …\n" + diagnostic[-3500:]
            raise RuntimeError(f"Codex CLI failed with {completed.returncode}: {diagnostic}")
        if not output_path.is_file():
            raise RuntimeError("Codex CLI did not create --output-last-message")
        try:
            value = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Codex CLI final message is not JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise RuntimeError("Codex CLI final message must be a JSON object")
        return {"result": value, "metadata": _parse_codex_events(completed.stdout)}


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise RuntimeError("stdin must contain one JSON object")
        result = run_codex(request)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"codex-cli-provider: {exc}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
