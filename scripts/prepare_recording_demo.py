"""Fetch the fixed public demo commit as Git objects; never run its code."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

URL = "https://github.com/PrefectHQ/fastmcp.git"
COMMIT = "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71"


def git(destination: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(destination), *arguments], text=True, encoding="utf-8"
    ).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="准备固定版本 FastMCP 演示材料；只下载 Git 对象")
    parser.add_argument("--root", type=Path, default=Path("materials"))
    args = parser.parse_args()
    destination = args.root.resolve() / "PrefectHQ" / "fastmcp"
    if destination.exists():
        if git(destination, "remote", "get-url", "origin") != URL:
            raise SystemExit("目标已存在且来源不匹配；请使用新目录。")
        git(destination, "cat-file", "-e", COMMIT + "^{commit}")
        print("固定版本材料已可读取：" + str(destination))
        return
    destination.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", "--initial-branch=demo-readonly", str(destination)],
                   check=True)
    git(destination, "remote", "add", "origin", URL)
    git(destination, "fetch", "--depth=1", "--no-tags", "origin", COMMIT)
    git(destination, "update-ref", "refs/heads/demo-readonly", COMMIT)
    if git(destination, "rev-parse", "HEAD") != COMMIT:
        raise SystemExit("固定版本核对失败；保留下载记录，不继续演示。")
    print("固定版本材料已准备：" + str(destination))
    print("没有检出或执行目标项目；审核时使用 Git 读取源码。")


if __name__ == "__main__":
    main()
