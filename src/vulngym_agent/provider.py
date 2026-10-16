from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderCompletion:
    output: dict[str, Any]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class JsonCommandProvider:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        if not self.argv or not all(isinstance(value, str) and value for value in self.argv):
            raise ProviderError("provider argv must be a non-empty string list")
        if self.timeout_seconds <= 0:
            raise ProviderError("provider timeout_seconds must be positive")

    def complete(self, request: dict[str, Any]) -> ProviderCompletion:
        try:
            completed = subprocess.run(
                list(self.argv),
                check=False,
                shell=False,
                input=json.dumps(request, ensure_ascii=False).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError(f"provider command failed: {exc}") from exc
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            if len(error) > 5000:
                error = error[:2500] + "\n… provider stderr truncated …\n" + error[-2500:]
            raise ProviderError(f"provider exited with {completed.returncode}: {error}")
        try:
            value = json.loads(completed.stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError(f"provider stdout is not one UTF-8 JSON object: {exc}") from exc
        if not isinstance(value, dict):
            raise ProviderError("provider output must be a JSON object")
        if "result" not in value and "metadata" not in value:
            return ProviderCompletion(value, {})
        if set(value) != {"result", "metadata"}:
            raise ProviderError("provider envelope must contain only result and metadata")
        result = value.get("result")
        metadata = value.get("metadata")
        if not isinstance(result, dict):
            raise ProviderError("provider envelope result must be an object")
        if not isinstance(metadata, dict):
            raise ProviderError("provider envelope metadata must be an object")
        return ProviderCompletion(result, metadata)


def load_provider(path: Path) -> JsonCommandProvider:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("type") != "json_command":
        raise ProviderError("provider config type must be 'json_command'")
    argv = value.get("argv")
    if not isinstance(argv, list):
        raise ProviderError("provider config argv must be a list")
    return JsonCommandProvider(
        name=value.get("name", "json-command") if isinstance(value.get("name", "json-command"), str) else "json-command",
        argv=tuple(argv),
        timeout_seconds=float(value.get("timeout_seconds", 120.0)),
    )
