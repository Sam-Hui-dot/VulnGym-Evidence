from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from hashlib import sha256
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
from typing import Any
from urllib.parse import urlparse
import uuid

from .contract import import_t1, input_digest, validate_request
from .extraction import EXTRACTOR_VERSION, run_extraction, validate_report, write_extraction_record
from .report import write_outputs
from .runtime import connect_repository, inspect_repository, model_status
from .model_settings import ModelSettings
from vulngym_agent.provider import ProviderError
from .demo import load_demo_result
from .workflow import verify_request


def serve_local(*, port: int, output_dir: Path, configuration: dict[str, Any],
                public_origin: str | None = None) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("端口需要在 1024–65535 之间")
    public_url = urlparse(public_origin or "")
    if public_origin and (public_url.scheme not in {"http", "https"} or not public_url.hostname
                          or public_url.username or public_url.password
                          or public_url.path or public_url.query or public_url.fragment):
        raise ValueError("公开演示来源须为完整 HTTP(S) 域名，不含路径、凭证或参数")
    if public_origin and configuration.get("provider") is not None:
        raise ValueError("公开演示模式不配置在线模型；私人报告请使用本机模式")
    configuration = dict(configuration)
    desktop_settings = configuration.pop("desktop_settings", False)
    models = ModelSettings() if desktop_settings and not public_origin else None
    model_operation = False
    demo_result = load_demo_result()
    demo_folder = output_dir / "public-example"
    write_outputs(demo_folder, demo_result)
    token = secrets.token_hex(24)
    jobs: dict[str, dict[str, Any]] = {}
    inputs: dict[str, dict[str, Any]] = {}
    input_index: dict[str, str] = {}
    extraction_cache: dict[str, str] = {}
    extraction_records: dict[str, dict[str, Any]] = {}
    extraction_in_progress: set[str] = set()
    repository_bindings: dict[str, Path] = {}
    lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=1)

    def configuration_status() -> dict[str, Any]:
        state = models.status() if models else model_status(configuration["provider"])
        return {**state, "read_only_demo": bool(public_origin),
                "path_style": "windows" if sys.platform == "win32" else "posix"}

    def saved_job(job_id: str) -> dict[str, Any] | None:
        # Only completed, integrity-checked output can be restored after a restart.
        if len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id):
            return None
        location = output_dir / job_id / "result.json"
        try:
            if location.stat().st_size > 20_000_000:
                return None
            result = json.loads(location.read_text(encoding="utf-8"))
            request = validate_request(result["request"])
            if result["input_sha256"] != input_digest(request):
                return None
            if [row["claim_id"] for row in result["results"]] != [row["claim_id"] for row in request["claims"]]:
                return None
            if not all((output_dir / job_id / name).is_file() for name in ("report.html", "report.md")):
                return None
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return {"job_id": job_id, "status": "completed", "events": [], "request": request,
                "result": result, "restored_from_disk": True}

    def repository_for(repo_url: str) -> Path | None:
        from vulngym_agent.repository_index import normalize_repo_url
        with lock:
            return repository_bindings.get(normalize_repo_url(repo_url), configuration.get("repository"))

    def work(job_id: str, request: dict[str, Any], job_configuration: dict[str, Any]) -> None:
        def emit(stage: str, message: str) -> None:
            with lock:
                jobs[job_id]["events"].append({"stage": stage, "message": message,
                                              "time": datetime.now(timezone.utc).isoformat()})
        with lock:
            jobs[job_id]["status"] = "running"
        try:
            result = verify_request(request, **job_configuration, emit=emit)
            write_outputs(output_dir / job_id, result)
            with lock:
                jobs[job_id].update(status="completed", result=result)
        except Exception as exc:
            # Provider errors can contain response bodies; never send them to the browser.
            with lock:
                jobs[job_id].update(status="failed", error="本次运行未完成，请检查本地材料和配置。",
                                    error_type=type(exc).__name__)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _local_host(self) -> bool:
            allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
            return self.headers.get("Host") in allowed

        def _send(self, status: int, body: bytes, content_type: str, filename: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if filename is not None:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            ancestors = "https://modelscope.cn https://www.modelscope.cn" if public_origin else "'none'"
            self.send_header("Content-Security-Policy", "default-src 'self'; "
                             "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                             "connect-src 'self'; img-src 'self'; frame-ancestors " + ancestors + "; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, value: Any) -> None:
            self._send(status, json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self) -> None:
            # The fixed demo has an explicit read-only route allowlist below.
            # Cloud gateways rewrite Host and may rotate it on every deployment.
            # Loopback Host validation protects only the full local application.
            if not public_origin and not self._local_host():
                self._json(403, {"error": "仅支持本机访问"})
                return
            path = urlparse(self.path).path
            public_paths = {"/", "/app.js", "/style.css", "/polish.css", "/evidence-ui.mjs", "/onboarding.js",
                            "/api/demo", "/api/demo-result", "/api/config", "/health", "/service/status"}
            if public_origin and path not in public_paths and not path.startswith("/demo-reports/"):
                self._json(404, {"error": "公开演示仅提供固定公开样例"})
                return
            if path == "/":
                page = files("vulngym_evidence").joinpath("web/index.html").read_text(encoding="utf-8")
                self._send(200, page.replace("__TOKEN__", token).encode("utf-8"), "text/html; charset=utf-8")
            elif path in {"/app.js", "/style.css", "/polish.css", "/evidence-ui.mjs", "/onboarding.js"}:
                resource = files("vulngym_evidence").joinpath("web" + path)
                kind = "text/javascript" if path.endswith((".js", ".mjs")) else "text/css"
                self._send(200, resource.read_bytes(), kind + "; charset=utf-8")
            elif path == "/api/demo":
                demo = json.loads(files("vulngym_evidence").joinpath("web/demo.json").read_text(encoding="utf-8"))
                self._json(200, demo)
            elif path == "/api/examples":
                catalog = json.loads(files("vulngym_evidence").joinpath("web/examples.json").read_text(encoding="utf-8"))
                for example in catalog["examples"]:
                    example["request"] = validate_request(example["request"])
                self._json(200, catalog)
            elif path == "/api/config":
                with lock:
                    self._json(200, configuration_status())
            elif path == "/api/demo-result":
                self._json(200, {"provenance": "固定公开源码教学报告的真实历史运行；本次查看不调用模型",
                                 "result": demo_result})
            elif path in {"/health", "/service/status"}:
                self._json(200, {"status": "ready", "mode": "public-example" if public_origin else "local"})
            elif path.startswith("/demo-reports/"):
                name = path.removeprefix("/demo-reports/")
                if name not in {"report.html", "report.md", "result.json"}:
                    self._json(404, {"error": "演示报告不存在"})
                    return
                kind = {"report.html": "text/html", "report.md": "text/plain", "result.json": "application/json"}[name]
                self._send(200, (demo_folder / name).read_bytes(), kind + "; charset=utf-8",
                           name if name != "report.html" else None)
            elif path.startswith("/extractions/") and path.endswith(".json"):
                record_id = path.removeprefix("/extractions/").removesuffix(".json")
                if len(record_id) != 32 or any(c not in "0123456789abcdef" for c in record_id):
                    self._json(404, {"error": "提取记录不存在"})
                    return
                location = output_dir / "extractions" / record_id / "record.json"
                if not location.is_file():
                    self._json(404, {"error": "提取记录尚未保存"})
                    return
                self._send(200, location.read_bytes(), "application/json; charset=utf-8", "extraction-" + record_id + ".json")
            elif path.startswith("/inputs/") and path.endswith(".json"):
                input_id = path.removeprefix("/inputs/").removesuffix(".json")
                with lock:
                    saved = inputs.get(input_id)
                if saved is None:
                    self._json(404, {"error": "当前服务没有该输入记录"})
                    return
                body = (json.dumps(saved, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8", saved["case_id"] + ".json")
            elif path.startswith("/api/jobs/"):
                job_id = path.removeprefix("/api/jobs/")
                with lock:
                    # Snapshot by serialization so another request cannot mutate nested events.
                    snapshot = json.loads(json.dumps(jobs.get(job_id)))
                snapshot = snapshot or saved_job(job_id)
                self._json(200 if snapshot else 404, snapshot or {"error": "记录不存在"})
            elif path.startswith("/reports/"):
                parts = path.split("/")
                if len(parts) != 4 or parts[3] not in {"report.html", "report.md", "result.json"}:
                    self._json(404, {"error": "记录不存在"})
                    return
                job_id, filename = parts[2:]
                with lock:
                    ready = job_id in jobs and jobs[job_id]["status"] == "completed"
                ready = ready or saved_job(job_id) is not None
                if not ready:
                    self._json(404, {"error": "报告尚未生成"})
                    return
                kind = {"report.html": "text/html", "report.md": "text/plain", "result.json": "application/json"}[filename]
                self._send(200, (output_dir / job_id / filename).read_bytes(), kind + "; charset=utf-8",
                           filename if filename != "report.html" else None)
            else:
                self._json(404, {"error": "页面不存在"})

        def do_POST(self) -> None:
            nonlocal model_operation
            if public_origin:
                self._json(403, {"error": "公开演示不接收私人报告；请下载源码在本机运行"})
                return
            if (not self._local_host() or self.headers.get("X-Evidence-Token") != token
                    or self.headers.get("Origin", f"http://127.0.0.1:{port}") not in
                    {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}):
                self._json(403, {"error": "请求来源不符，请从本机页面提交"})
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                self._json(415, {"error": "需要 JSON 请求"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 512000:
                    raise ValueError("首版输入限制为 500 KiB")
                self.connection.settimeout(15)
                value = json.loads(self.rfile.read(length).decode("utf-8"))
                path = urlparse(self.path).path
                if path in {"/api/model-settings", "/api/model-test", "/api/model-clear", "/api/model-forget", "/api/model-restore"}:
                    if models is None:
                        raise ValueError("当前入口不支持网页配置，请从 start-evidence.cmd 启动本地应用")
                    with lock:
                        if model_operation or extraction_in_progress or any(
                                job["status"] in {"queued", "running"} for job in jobs.values()):
                            self._json(409, {"error": "任务正在运行，请等待完成后修改或测试模型"})
                            return
                        model_operation = True
                    try:
                        if path == "/api/model-test":
                            same = models.test(value)
                            self._json(200, {**configuration_status(), "tested_current_profile": same,
                                             "message": "连接和结构化 JSON 测试通过"})
                        else:
                            if path in {"/api/model-clear", "/api/model-forget", "/api/model-restore"}:
                                if value != {}:
                                    raise ValueError("移除配置不接受其他字段")
                                {"/api/model-clear": models.clear, "/api/model-forget": models.forget,
                                 "/api/model-restore": models.restore_saved}[path]()
                            else:
                                models.save(value)
                            with lock:
                                extraction_cache.clear()
                            self._json(200, configuration_status())
                    except ProviderError as exc:
                        self._json(502, {"error": str(exc), "configuration": configuration_status()})
                    except (OSError, subprocess.TimeoutExpired):
                        self._json(400, {"error": "系统凭据操作未完成，可选择仅本次使用"})
                    finally:
                        with lock:
                            model_operation = False
                    return
                if path == "/api/repository-connect":
                    state, repository = connect_repository(value)
                    with lock:
                        if state["repo_url"] not in repository_bindings and len(repository_bindings) >= 24:
                            raise ValueError("本次服务已连接 24 个项目，请保存结果后重新启动")
                        repository_bindings[state["repo_url"]] = repository
                    self._json(200, state)
                    return
                if path == "/api/repository-status":
                    self._json(200, inspect_repository(value, roots=configuration.get("roots", ()),
                                                     repository=repository_for(value.get("repo_url", ""))
                                                     if isinstance(value, dict) else None))
                    return
                if path == "/api/import-t1":
                    self._json(200, import_t1(value))
                    return
                if path == "/api/validate":
                    # Input-only normalization; never reads repositories or calls models.
                    self._json(200, validate_request(value))
                    return
                if path == "/api/extract":
                    if not isinstance(value, dict) or set(value) != {"report_text"}:
                        raise ValueError("仅接受报告原文")
                    report_text = validate_report(value["report_text"])
                    digest = sha256((EXTRACTOR_VERSION + "\0" + report_text).encode("utf-8")).hexdigest()
                    with lock:
                        if model_operation:
                            self._json(409, {"error": "模型设置正在处理，请稍后再提取"})
                            return
                        state = configuration_status()
                        provider = models.provider if models else configuration["provider"]
                        if not state["model_ready"]:
                            raise ValueError(state["model_message"])
                        cached_id = extraction_cache.get(digest)
                        cached = extraction_records.get(cached_id) if cached_id else None
                        busy = bool(extraction_in_progress)
                        limited = len(extraction_records) >= 4
                        if cached is None and not busy and not limited:
                            record_id = uuid.uuid4().hex
                            extraction_records[record_id] = {"extraction_id": record_id, "status": "running",
                                "created_at": datetime.now(timezone.utc).isoformat(), "report_sha256": digest,
                                "model_call_count": None, "request": {"report_text": report_text}}
                            extraction_in_progress.add(digest)
                    def response_record(record, cached=False):
                        return {key: record[key] for key in ("extraction_id", "status", "candidates", "metadata",
                            "elapsed_seconds", "duplicates_removed", "prompt_version", "report_sha256", "model_call_count")} | {
                            "cached": cached, "additional_model_calls": 0 if cached else record["model_call_count"],
                            "download_url": f'/extractions/{record["extraction_id"]}.json'}
                    if cached is not None:
                        self._json(200, response_record(cached, True))
                        return
                    if busy or limited:
                        self._json(429, {"error": "候选提取正在进行或本次会话已达到 4 次上限"})
                        return
                    try:
                        folder = output_dir / "extractions" / record_id
                        write_extraction_record(folder, extraction_records[record_id])
                        record = run_extraction(report_text, provider, record_id=record_id)
                        write_extraction_record(folder, record)
                        with lock:
                            extraction_records[record_id] = record
                            if record["status"] == "completed":
                                extraction_cache[digest] = record_id
                        response = response_record(record)
                        if record["status"] == "completed":
                            self._json(200, response)
                        else:
                            self._json(502, {**response, "error": record["message"]})
                    except ValueError:
                        raise
                    except Exception:
                        self._json(502, {"error": "候选提取未完成，请检查本地 Provider 配置后重试"})
                    finally:
                        with lock:
                            extraction_in_progress.discard(digest)
                    return
                if path == "/api/inputs":
                    request = validate_request(value)
                    digest = input_digest(request)
                    with lock:
                        input_id = input_index.get(digest)
                        if input_id is None:
                            if len(inputs) >= 24:
                                self._json(429, {"error": "本次会话输入下载记录已达到上限，请保留材料后重新启动。"})
                                return
                            input_id = uuid.uuid4().hex
                            inputs[input_id] = request
                            input_index[digest] = input_id
                    self._json(200, {"download_url": f"/inputs/{input_id}.json", "case_id": request["case_id"]})
                    return
                if path != "/api/jobs":
                    self._json(404, {"error": "接口不存在"})
                    return
                request = validate_request(value)
                # Capture the selected checkout before queuing; later UI changes cannot
                # redirect a running task to a different copy of the repository.
                job_configuration = {**configuration, "repository": repository_for(request["repo_url"])}
                with lock:
                    if model_operation:
                        self._json(409, {"error": "模型设置正在处理，请稍后再复核"})
                        return
                    job_configuration["provider"] = models.provider if models else configuration["provider"]
                    if len(jobs) >= 12:
                        self._json(429, {"error": "本次会话已达到运行上限，请保留结果后重新启动。"})
                        return
                    job_id = uuid.uuid4().hex
                    jobs[job_id] = {"job_id": job_id, "status": "queued", "events": [], "request": request}
                executor.submit(work, job_id, request, job_configuration)
                self._json(202, {"job_id": job_id})
            except (ValueError, OSError) as exc:
                self._json(400, {"error": str(exc)})

    server = ThreadingHTTPServer(("0.0.0.0" if public_origin else "127.0.0.1", port), Handler)
    print(f"VulnGym Evidence 入口：{public_origin or f'http://127.0.0.1:{port}'}")
    print("公开固定样例：不接收私人报告、不调用模型。" if public_origin else
          "完整历史演示无需 Key；亲自核查源码与语义请按对应模式运行。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        executor.shutdown(wait=True, cancel_futures=True)
