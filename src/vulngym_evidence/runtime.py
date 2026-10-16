"""Read-only local setup checks. No API calls and no credential values in output."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Iterable

from vulngym_agent.provider import JsonCommandProvider
from vulngym_agent.qwen_provider import DEFAULT_MODEL


def connect_repository(value: Any) -> tuple[dict[str, Any], Path]:
    """Resolve a user-selected local Git checkout to an immutable commit."""
    from .contract import validate_repository_query
    from vulngym_agent.repository import ReadOnlyGitRepository, RepositoryError
    from vulngym_agent.repository_index import normalize_repo_url

    if not isinstance(value, dict) or set(value) != {"local_path", "repo_url", "revision"}:
        raise ValueError("请填写本地源码文件夹、仓库地址和版本")
    raw_path = value["local_path"]
    if not isinstance(raw_path, str) or not raw_path.strip() or len(raw_path) > 4096 or "\x00" in raw_path:
        raise ValueError("请粘贴本地 Git 仓库文件夹的完整路径")
    path = Path(raw_path.strip().strip('"')).expanduser()
    if not path.is_absolute():
        raise ValueError("请使用完整路径；Windows 服务使用 C:\\…，WSL / Linux 服务使用 /home/… 或 /mnt/…")
    if not path.is_dir():
        raise ValueError("找不到这个文件夹；请使用运行服务的系统能访问的路径")
    if shutil.which("git") is None:
        raise ValueError("未安装 Git；安装后重新启动服务，或先查看完整演示")
    try:
        repo = ReadOnlyGitRepository(path)
    except RepositoryError as exc:
        raise ValueError("该文件夹不是 Git 仓库；请选择包含 .git 的项目根目录，普通源码 ZIP 不含版本历史") from exc
    origin = repo.remote_origin()
    address = value["repo_url"]
    if not isinstance(address, str) or len(address) > 1500:
        raise ValueError("仓库地址需要 HTTPS 地址")
    if address.strip():
        validate_repository_query({"repo_url": address.strip(), "reviewed_commit": "0" * 40})
    address = normalize_repo_url(address.strip() or origin or "")
    if not address:
        raise ValueError("未找到远程来源，请填写此项目的 HTTPS 仓库地址")
    # Use the same URL contract as the report, before probing a revision.
    validate_repository_query({"repo_url": address, "reviewed_commit": "0" * 40})
    if origin and normalize_repo_url(origin) != address:
        raise ValueError("仓库地址与这个文件夹的 origin 不一致；请核对文件夹或仓库地址")
    revision = value["revision"]
    if not isinstance(revision, str):
        raise ValueError("版本需要分支名、标签或完整 Commit SHA")
    revision = revision.strip() or "HEAD"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", revision):
        raise ValueError("版本请填写分支名、标签、HEAD 或完整 Commit SHA")
    resolved = repo._run("rev-parse", "--verify", "--end-of-options", revision + "^{commit}")
    commit = resolved.stdout.decode("ascii", errors="replace").strip().lower()
    if resolved.returncode or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("本地没有找到这个版本；请核对分支、标签或提交，浅克隆可能缺少历史版本")
    query = validate_repository_query({"repo_url": address, "reviewed_commit": commit})
    state = inspect_repository(query, repository=repo.root)
    if not state["ready"]:
        raise ValueError(state["message"])
    return {**state, "selected_revision": revision, "binding_scope": "service_session"}, repo.root


def model_status(provider: JsonCommandProvider | None) -> dict[str, Any]:
    if provider is None:
        return {"model_configured": False, "model_ready": False, "provider": None,
                "model_name": None, "model_message": "确定性复核；提取和语义模型尚未配置。"}
    if provider.name != "qwen":
        return {"model_configured": True, "model_ready": True, "provider": provider.name,
                "model_name": None, "model_message": "自定义模型已配置，连接尚未验证。"}
    enabled = os.environ.get("VULNGYM_QWEN_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
    key_present = bool(os.environ.get("DASHSCOPE_API_KEY", "").strip())
    message = ("Qwen 已配置，连接和账户额度尚未联网验证。" if enabled and key_present else
               "请开启 VULNGYM_QWEN_ENABLED。" if not enabled else "请在当前终端配置 DASHSCOPE_API_KEY。")
    return {"model_configured": True, "model_ready": enabled and key_present, "provider": "qwen",
            "model_name": os.environ.get("VULNGYM_QWEN_MODEL", DEFAULT_MODEL),
            "model_message": message}


def inspect_repository(value: Any, *, roots: Iterable[Path] = (),
                       repository: Path | None = None) -> dict[str, Any]:
    from .contract import validate_repository_query
    from vulngym_agent.repository import ReadOnlyGitRepository
    from vulngym_agent.repository_index import RepositoryResolver
    query = validate_repository_query(value)
    roots = tuple(roots)
    if shutil.which("git") is None:
        return {**query, "ready": False, "message": "未安装 Git；可先查看完整演示",
                "repository": None, "roots": [str(root) for root in roots]}
    mapping = {query["repo_url"]: repository} if repository else {}
    resolution = RepositoryResolver(roots=roots, mapping=mapping).resolve(query["repo_url"])
    readable = bool(resolution.path and ReadOnlyGitRepository(resolution.path).has_commit(query["reviewed_commit"]))
    message = ("本地源码与指定版本可读取" if readable else
               "本地仓库尚未准备" if not resolution.path else "本地仓库中没有该版本")
    if readable and not resolution.origin:
        message += "（本地仓库未配置远程来源）"
    return {**query, "ready": readable, "message": message,
            "repository": resolution.to_dict(), "roots": [str(root) for root in roots]}


def inspect_setup(*, roots: Iterable[Path] = (), repository: Path | None = None,
                  provider: JsonCommandProvider | None = None) -> dict[str, Any]:
    configured = ([repository] if repository else []) + list(roots)
    paths = [{"path": str(path), "exists": path.is_dir()} for path in configured]
    return {"python_version": ".".join(map(str, sys.version_info[:3])),
            "python_ready": sys.version_info >= (3, 10), "git_ready": shutil.which("git") is not None,
            "repository_paths": paths, **model_status(provider), "network_checked": False}
