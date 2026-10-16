#!/usr/bin/env python3
"""Build the single ZIP requested by the activity after the demo video exists."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VIDEO_NAME = "VulnGym-T1-Sam-Demo-final.mp4"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("video", type=Path, help="path to the reviewed MP4 recording")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT.parent / "VulnGym-T1-Sam-final.zip",
        help="final ZIP path",
    )
    args = parser.parse_args()

    video = args.video.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not video.is_file():
        raise SystemExit(f"video not found: {video}")
    if video.suffix.lower() != ".mp4":
        raise SystemExit("the reviewed recording must be an MP4 file")
    if git("status", "--porcelain"):
        raise SystemExit("working tree is not clean; commit or revert changes before packaging")
    if ".env" in git("ls-files").splitlines():
        raise SystemExit("refusing to package because .env is tracked")

    commit = git("rev-parse", "HEAD")
    tags = git("tag", "--points-at", "HEAD") or "none"
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        prefix="vulngym-submission-", suffix=".zip", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        subprocess.run(
            ["git", "archive", "--format=zip", "--prefix=VulnGym-Agent/", f"--output={temporary}", "HEAD"],
            cwd=ROOT,
            check=True,
        )
        info = (
            "VulnGym T1 最终提交包\n"
            "\n"
            "建议评审顺序：\n"
            "1. SUBMISSION_OVERVIEW.md：两页提交总览\n"
            f"2. {VIDEO_NAME}：3-5 分钟演示视频\n"
            "3. docs/DESIGN_SUMMARY.md：简明设计说明\n"
            "4. artifacts/final-blind-v1/report/report.html：逐字段可读报告\n"
            "5. docs/INDEX.md：完整审计材料导航\n"
            "\n"
            "快速演示：python3 scripts/show_demo.py\n"
            "交付自检：python3 scripts/verify_delivery.py\n"
            f"Commit: {commit}\n"
            f"Tag(s): {tags}\n"
        )
        with zipfile.ZipFile(temporary, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(video, f"VulnGym-Agent/{VIDEO_NAME}")
            archive.writestr("VulnGym-Agent/SUBMISSION_INFO.txt", info)

        size = temporary.stat().st_size
        if size > MAX_UPLOAD_BYTES:
            raise SystemExit(f"final ZIP is {size / 1024 / 1024:.1f} MiB, above the 200 MiB limit")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum = output.with_suffix(output.suffix + ".sha256")
    checksum.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    print(f"Final ZIP: {output}")
    print(f"Size: {output.stat().st_size / 1024 / 1024:.1f} MiB")
    print(f"SHA256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
