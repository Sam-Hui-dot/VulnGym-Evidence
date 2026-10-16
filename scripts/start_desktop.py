"""Portable source-package launcher; never installs packages or executes target code."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def prepare_bundled_source(root: Path) -> None:
    if not shutil.which("git"):
        return
    sources = [(root / "fastmcp.bundle", "PrefectHQ", "fastmcp"),
               (ROOT / "configs" / "evidence" / "starlette.bundle", "encode", "starlette")]
    for bundle, owner, name in sources:
        destination = root / owner / name
        if not bundle.is_file() or (destination / ".git").exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(bundle), str(destination)], check=True)
        subprocess.run(["git", "-C", str(destination), "remote", "set-url", "origin",
                        f"https://github.com/{owner}/{name}.git"], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnGym Evidence 开始体验")
    parser.add_argument("--mode", choices=["menu", "demo", "qwen", "check"], default="menu")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--repositories-root", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "out" / "evidence-web")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        print("需要 Python 3.10 或以上版本。")
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.mode == "menu":
        print("VulnGym Evidence\n1. 打开应用（网页连接项目、设置模型，也可直接体验案例）\n"
              "2. 打开应用并配置 AI（进入网页后点击模型设置）\n3. 检查运行条件")
        args.mode = {"1": "demo", "2": "qwen", "3": "check"}.get(input("选择 1 / 2 / 3：").strip(), "")
        if not args.mode:
            print("请选择 1、2 或 3。")
            return 2
    material_root = args.repositories_root or next(
        (p for p in (ROOT / "materials", ROOT.parent / "materials", ROOT.parent / "vulngym-repos")
         if p.is_dir()), ROOT / "materials")
    if args.mode != "check":
        prepare_bundled_source(material_root)
    from vulngym_evidence.runtime import inspect_repository
    provider = None
    if args.mode == "qwen":
        print("在网页右上角点击‘模型设置’，选择服务和模型、填写自己的 Key。")
    status = inspect_repository({"repo_url": "https://github.com/PrefectHQ/fastmcp",
        "reviewed_commit": "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71"}, roots=[material_root])
    print("Python：" + sys.version.split()[0] + "；Git：" + ("可用" if shutil.which("git") else "未安装"))
    print("样例源码：" + status["message"])
    if not status["ready"]:
        print("完整历史演示仍可查看；准备固定源码后才能亲自核对。")
    if args.mode == "check":
        return 0 if status["ready"] else 2
    from vulngym_evidence.server import serve_local
    if not args.no_browser:
        threading.Timer(1, lambda: webbrowser.open("http://127.0.0.1:" + str(args.port))).start()
    print("模型配置默认仅本次使用；需要记住时在网页主动勾选。配置和连接测试不会自动运行。")
    serve_local(port=args.port, output_dir=args.output_dir, configuration={"roots": [material_root], "desktop_settings": True,
        "repository": None, "advisory_documents": [], "provider": provider, "use_critic": True})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("启动未完成：" + str(error))
        raise SystemExit(2)
