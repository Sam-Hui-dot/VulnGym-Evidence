from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from vulngym_agent.advisory import load_advisory_cache
from vulngym_agent.provider import ProviderError, load_provider
from vulngym_agent.repository import RepositoryError

from .contract import import_t1, validate_request
from .extraction import run_extraction, write_extraction_record
from .report import write_outputs
from .runtime import inspect_setup
from .workflow import verify_request


def read_object(path: Path):
    if path.stat().st_size > 512000:
        raise ValueError("首版输入限制为 500 KiB")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnGym Evidence：限定声明的漏洞报告复核")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="检查声明合同，或转换一条 T1 记录；不调用模型")
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--from-t1", action="store_true")
    prepare.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="复核声明并保存报告")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--output-dir", type=Path, required=True)
    serve = commands.add_parser("serve", help="启动本机交互入口；默认不调用模型")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--output-dir", type=Path, default=Path("out/evidence-web"))
    serve.add_argument("--public-demo-origin", help="仅展示固定公开样例，允许指定平台域名；禁止私人报告和模型调用")
    doctor = commands.add_parser("doctor", help="检查本地 Python/Git/目录/模型开关；不联网")
    doctor.add_argument("--json", action="store_true")
    extract = commands.add_parser("extract", help="从报告文件提取待确认候选，并保存用量与失败记录")
    extract.add_argument("--report-file", type=Path, required=True)
    extract.add_argument("--output-dir", type=Path, required=True)
    extract.add_argument("--provider-config", type=Path, required=True)
    for command in (verify, serve, doctor):
        command.add_argument("--repository", type=Path)
        command.add_argument("--repositories-root", action="append", type=Path, default=[])
        command.add_argument("--advisory-cache", action="append", type=Path, default=[])
        command.add_argument("--provider-config", type=Path)
        command.add_argument("--no-critic", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            value = read_object(args.input)
            request = import_t1(value) if args.from_t1 else validate_request(value)
            if args.output.exists():
                raise ValueError("输出文件已存在，请选用新路径")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"待确认的声明已保存：{args.output}")
            return 0
        if args.command == "extract":
            if args.output_dir.exists() and any(args.output_dir.iterdir()):
                raise ValueError("输出目录非空，请使用新目录")
            if args.report_file.stat().st_size > 100000:
                raise ValueError("报告文件超过读取预算，请分段处理")
            record = run_extraction(args.report_file.read_text(encoding="utf-8-sig"),
                                    load_provider(args.provider_config))
            write_extraction_record(args.output_dir, record)
            print(json.dumps({"status": record["status"], "candidate_count": len(record["candidates"]),
                              "output_dir": str(args.output_dir)}, ensure_ascii=False))
            return 0 if record["status"] == "completed" else 1
        provider = load_provider(args.provider_config) if args.provider_config else None
        if args.command == "doctor":
            status = inspect_setup(roots=args.repositories_root, repository=args.repository, provider=provider)
            if args.json:
                print(json.dumps(status, ensure_ascii=False))
            else:
                print("Python：" + status["python_version"] + (" ✓" if status["python_ready"] else " 需要 3.10+"))
                print("Git：" + ("可用" if status["git_ready"] else "未找到"))
                for item in status["repository_paths"]:
                    print(("目录可读：" if item["exists"] else "目录不存在：") + item["path"])
                if not status["repository_paths"]:
                    print("尚未配置取证仓库目录，可在启动时指定 --repositories-root。")
                print("模型：" + status["model_message"])
                if status["model_name"]:
                    print("配置模型：" + status["model_name"])
                print("本次没有联网、调用模型或读取密钥内容。")
            ready = status["python_ready"] and status["git_ready"] and all(p["exists"] for p in status["repository_paths"])
            return 0 if ready and (provider is None or status["model_ready"]) else 2
        configuration = {"roots": args.repositories_root, "repository": args.repository,
                         "advisory_documents": load_advisory_cache(args.advisory_cache),
                         "provider": provider,
                         "use_critic": not args.no_critic}
        if args.command == "serve":
            from .server import serve_local
            serve_local(port=args.port, output_dir=args.output_dir, configuration=configuration,
                        public_origin=args.public_demo_origin)
            return 0
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            raise ValueError("输出目录非空，请使用新目录以保留旧结果")
        result = verify_request(read_object(args.input), **configuration,
                                emit=lambda stage, message: print(message, file=sys.stderr))
        write_outputs(args.output_dir, result)
        print(json.dumps({"verdict": result["verdict"], "semantic_status": result["semantic_status"],
                          "output_dir": str(args.output_dir)}, ensure_ascii=False))
        return 1 if result["semantic_status"] == "model_or_contract_failed" else 0
    except (OSError, ValueError, ProviderError, RepositoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
