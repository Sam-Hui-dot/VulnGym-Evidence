from __future__ import annotations

import subprocess
from pathlib import Path


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def create_fix_history(root: Path, *, origin: str | None = "https://github.com/acme/example.git") -> tuple[str, str]:
    git(root, "init", "-q")
    git(root, "config", "user.name", "VulnGym Test")
    git(root, "config", "user.email", "vulngym-test@example.invalid")
    if origin:
        git(root, "remote", "add", "origin", origin)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text(
        "def endpoint(request):\n    return handle(request)\n",
        encoding="utf-8",
    )
    (root / "src" / "core.py").write_text(
        "def handle(value):\n    return run(value)\n",
        encoding="utf-8",
    )
    git(root, "add", "src/app.py", "src/core.py")
    git(root, "commit", "-q", "-m", "vulnerable implementation")
    vulnerable = git(root, "rev-parse", "HEAD")

    (root / "src" / "core.py").write_text(
        "def handle(value):\n    validated = sanitize(value)\n    return run(validated)\n",
        encoding="utf-8",
    )
    git(root, "add", "src/core.py")
    git(root, "commit", "-q", "-m", "fix security validation")
    fixed = git(root, "rev-parse", "HEAD")
    return vulnerable, fixed

