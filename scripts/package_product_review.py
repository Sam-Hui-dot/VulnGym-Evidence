"""Prepare a new review package without touching frozen deliveries or source refs."""
from pathlib import Path
import argparse
import hashlib
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--demo-materials", type=Path, required=True)
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    source = args.destination / "Source"
    source.mkdir(exist_ok=True)
    for directory in ("src", "configs", "scripts", "tests", "docs"):
        shutil.copytree(ROOT / directory, source / directory, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
    for name in ("README.md", "LICENSE", "CONTRIBUTING.md", "pyproject.toml", "start-evidence.cmd",
                 "Dockerfile", ".dockerignore", "ms_deploy.json"):
        shutil.copy2(ROOT / name, source / name)
    with zipfile.ZipFile(args.demo_materials) as z:
        for info in z.infolist():
            target = (source / info.filename).resolve()
            if not target.is_relative_to((source / "materials").resolve()):
                raise ValueError("Materials archive contains an unexpected path")
            z.extract(info, source)
    repository = source / "materials" / "PrefectHQ" / "fastmcp"
    actual = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"],
                                    text=True).strip()
    if actual != COMMIT:
        raise ValueError("Bundled source commit does not match the demo")
    manifest = []
    archive = args.destination / "VulnGym-Evidence-0.2.1-Source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for file in sorted(source.rglob("*")):
            if not file.is_file() or "out" in file.relative_to(source).parts or "__pycache__" in file.parts:
                continue
            relative = file.relative_to(args.destination).as_posix()
            z.write(file, relative)
            manifest.append(hashlib.sha256(file.read_bytes()).hexdigest() + "  " + relative)
    (args.destination / "SHA256SUMS.txt").write_text("\n".join(manifest) + "\n" +
        hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n", encoding="utf-8")
    print(f"Packaged {len(manifest)} files; ZIP {archive.stat().st_size} bytes")


if __name__ == "__main__":
    main()
