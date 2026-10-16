"""Local model profiles. Secrets stay on the server and outside project files."""
from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
import json
import os
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from typing import Any

from vulngym_agent.provider import ProviderCompletion, ProviderError
from vulngym_agent.qwen_provider import build_payload, parse_response, DEFAULT_BASE_URL, DEFAULT_MODEL


class CredentialStore:
    """Windows Credential Manager, or Linux Secret Service via secret-tool."""

    target = "VulnGymEvidence/ModelProfileV1"

    @property
    def available(self) -> bool:
        return os.name == "nt" or bool(shutil.which("secret-tool"))

    def _windows(self):
        from ctypes import wintypes as w

        class Credential(ctypes.Structure):
            _fields_ = [("Flags", w.DWORD), ("Type", w.DWORD), ("TargetName", w.LPWSTR),
                        ("Comment", w.LPWSTR), ("LastWritten", w.FILETIME),
                        ("CredentialBlobSize", w.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                        ("Persist", w.DWORD), ("AttributeCount", w.DWORD), ("Attributes", ctypes.c_void_p),
                        ("TargetAlias", w.LPWSTR), ("UserName", w.LPWSTR)]

        lib = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        lib.CredReadW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.POINTER(Credential))]
        lib.CredReadW.restype = w.BOOL
        lib.CredWriteW.argtypes = [ctypes.POINTER(Credential), w.DWORD]
        lib.CredWriteW.restype = w.BOOL
        lib.CredDeleteW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD]
        lib.CredDeleteW.restype = w.BOOL
        lib.CredFree.argtypes = [ctypes.c_void_p]
        lib.CredFree.restype = None
        return lib, Credential

    def read(self) -> dict[str, Any] | None:
        if os.name == "nt":
            lib, kind = self._windows()
            entry = ctypes.POINTER(kind)()
            if not lib.CredReadW(self.target, 1, 0, ctypes.byref(entry)):
                if ctypes.get_last_error() == 1168:
                    return None
                raise ValueError("无法读取 Windows 凭据；可改用仅本次使用")
            try:
                raw = ctypes.string_at(entry.contents.CredentialBlob, entry.contents.CredentialBlobSize)
            finally:
                lib.CredFree(entry)
        elif self.available:
            result = subprocess.run(["secret-tool", "lookup", "service", self.target],
                                    capture_output=True, timeout=15, check=False)
            if result.returncode != 0:
                return None
            raw = result.stdout.strip()
        else:
            return None
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise ValueError("已保存的模型配置无法读取，请重新填写或移除") from None

    def write(self, profile: dict[str, Any]) -> None:
        raw = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > 2560:
            raise ValueError("凭据内容过长，无法记住；请选仅本次使用")
        if os.name == "nt":
            lib, kind = self._windows()
            buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
            value = kind(Type=1, TargetName=self.target, CredentialBlobSize=len(raw),
                         CredentialBlob=buffer, Persist=2, UserName="VulnGym Evidence")
            if not lib.CredWriteW(ctypes.byref(value), 0):
                raise ValueError("系统未能保存凭据；请选仅本次使用")
        elif self.available:
            result = subprocess.run(["secret-tool", "store", "--label=VulnGym Evidence 模型配置",
                                     "service", self.target], input=raw, capture_output=True,
                                    timeout=15, check=False)
            if result.returncode != 0:
                raise ValueError("系统密钥环不可用；请选仅本次使用")
        else:
            raise ValueError("本机没有可用的系统凭据存储，请选仅本次使用")

    def delete(self) -> None:
        if os.name == "nt":
            lib, _ = self._windows()
            if not lib.CredDeleteW(self.target, 1, 0) and ctypes.get_last_error() != 1168:
                raise ValueError("系统未能删除已保存凭据")
        elif self.available:
            result = subprocess.run(["secret-tool", "clear", "service", self.target],
                                    capture_output=True, timeout=15, check=False)
            if result.returncode not in (0, 1):
                raise ValueError("系统未能删除已保存凭据")


class RequestBudget:
    """Shared across profile changes. Failed/unknown calls retain reservations."""

    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0
        self.tokens = 0

    def reserve(self, payload: dict[str, Any]) -> None:
        amount = len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) + payload["max_tokens"] + 1024
        with self.lock:
            if self.calls >= 10 or self.tokens + amount > 100000:
                raise ProviderError("本次服务的 10 次调用 / 100000 token 预约上限已到；未发送请求")
            self.calls += 1
            self.tokens += amount


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class DesktopModelProvider:
    name: str
    model: str
    base_url: str
    api_key: str = field(repr=False)
    budget: RequestBudget = field(repr=False)

    def complete(self, request: dict[str, Any], *, connection_test: bool = False) -> ProviderCompletion:
        try:
            payload = build_payload(request, self.model)
        except RuntimeError:
            raise ProviderError("模型输出设置无效，请检查启动环境中的 token 配置") from None
        payload["max_tokens"] = 128 if connection_test else 4096
        if self.name != "qwen":
            payload.pop("enable_thinking", None)
        self.budget.reserve(payload)
        req = urllib.request.Request(self.base_url + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.build_opener(NoRedirect()).open(req, timeout=25 if connection_test else 180) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ProviderError("模型响应超出大小限制")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError()
            parsed = parse_response(value, self.model)
            parsed["metadata"]["transport"] = "chat_completions"
            # Only structured result and known metadata are passed to the workflow.
            return ProviderCompletion(parsed["result"], parsed["metadata"])
        except urllib.error.HTTPError as exc:
            explanations = {401: "Key 无效或认证失败", 403: "没有访问权限", 404: "接口地址或模型不存在",
                            429: "账户额度或请求频率受限"}
            raise ProviderError("模型接口 HTTP " + str(exc.code) + "：" +
                                explanations.get(exc.code, "请求失败，请检查服务商配置；未自动重试")) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderError("模型连接未完成，请检查接口地址和网络；未自动重试") from None
        except ProviderError:
            raise
        except (ValueError, KeyError, TypeError, RuntimeError):
            raise ProviderError("接口没有返回符合约定的结构化 JSON；请确认模型支持 JSON Schema") from None


class ModelSettings:
    def __init__(self):
        self.store = CredentialStore()
        self.budget = RequestBudget()
        self.provider: DesktopModelProvider | None = None
        self.saved = False
        self.saved_profile: DesktopModelProvider | None = None
        self.source = "none"
        self.connection_state = "untested"
        self.notice = ""
        try:
            saved = self.store.read()
            if saved:
                self.provider = self.candidate(saved)
                self.saved_profile = self.provider
                self.saved, self.source = True, "saved"
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.notice = "系统凭据暂不可用；可重新填写并选择仅本次使用"
        if self.provider is None and os.environ.get("DASHSCOPE_API_KEY", "").strip():
            try:
                self.provider = self.candidate({"provider": "qwen", "model": os.environ.get("VULNGYM_QWEN_MODEL", DEFAULT_MODEL),
                    "base_url": os.environ.get("VULNGYM_QWEN_BASE_URL", DEFAULT_BASE_URL),
                    "api_key": os.environ["DASHSCOPE_API_KEY"]})
                self.source = "environment"
            except ValueError:
                self.notice = "环境中的模型配置无法使用；请打开模型设置重新填写"

    def candidate(self, value: Any) -> DesktopModelProvider:
        if not isinstance(value, dict) or set(value) - {"provider", "model", "base_url", "api_key", "remember"}:
            raise ValueError("模型设置字段不正确")
        name, model, base, key = (value.get(k, "") for k in ("provider", "model", "base_url", "api_key"))
        if not all(isinstance(v, str) for v in (name, model, base, key)):
            raise ValueError("模型设置需要文本字段")
        if name not in {"qwen", "compatible"}:
            raise ValueError("请选择通义 DashScope 或兼容 Chat Completions 的服务")
        model, base, key = model.strip(), base.strip().rstrip("/"), key.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,199}", model):
            raise ValueError("请填写模型 ID，例如 qwen3.8-flash")
        try:
            url = urlsplit(base)
            valid = (url.scheme == "https" or (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}))
            valid = valid and bool(url.hostname) and not (url.username or url.password or url.query or url.fragment)
            _ = url.port
        except ValueError:
            valid = False
        if (not valid or len(base) > 500 or any(c.isspace() or ord(c) < 32 for c in base)
                or base.endswith("/chat/completions")):
            raise ValueError("请填写 HTTPS API 基地址（通常以 /v1 结尾）；本机接口可用 HTTP，不含凭证、参数或 /chat/completions")
        if not key and self.provider and (name, base) == (self.provider.name, self.provider.base_url):
            key = self.provider.api_key
        if not key or len(key) > 2048 or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in key):
            raise ValueError("请填写有效 Key；更换服务商或接口地址时必须重新填写")
        return DesktopModelProvider(name, model, base, key, self.budget)

    def status(self) -> dict[str, Any]:
        current = self.provider
        source_label = {"none": "未配置", "saved": "系统已保存", "environment": "来自启动环境", "session": "仅本次使用"}[self.source]
        state_label = {"untested": "连接未验证", "verified": "连接测试通过", "failed": "上次连接测试失败"}[self.connection_state]
        return {"model_configured": bool(current), "model_ready": bool(current),
                "provider": current.name if current else None, "model_name": current.model if current else None,
                "model_message": (source_label + " · " + state_label) if current else "先体验案例，或打开模型设置配置 AI",
                "connection_state": self.connection_state, "profile_source": self.source, "has_key": bool(current),
                "remember": self.saved, "saved_profile_available": self.saved_profile is not None,
                "credential_store_available": self.store.available, "notice": self.notice,
                "model_settings_available": True, "base_url": current.base_url if current else DEFAULT_BASE_URL,
                "request_budget": {"calls": self.budget.calls, "limit": 10, "token_reservation": self.budget.tokens, "token_limit": 100000}}

    def save(self, value: Any) -> None:
        current = self.candidate(value)
        remember = value.get("remember", False)
        if not isinstance(remember, bool):
            raise ValueError("记住配置选项需要勾选状态")
        if remember:
            self.store.write({"provider": current.name, "model": current.model,
                              "base_url": current.base_url, "api_key": current.api_key})
            self.saved_profile = current
        self.provider, self.saved = current, remember
        self.source = "saved" if remember else "session"
        self.connection_state, self.notice = "untested", ""

    def clear(self) -> None:
        self.store.delete()
        self.provider, self.saved, self.source = None, False, "none"
        self.saved_profile = None
        self.connection_state, self.notice = "untested", ""

    def forget(self) -> None:
        self.store.delete()
        self.saved_profile = None
        if self.saved:
            self.saved = False
            self.source = "session"

    def restore_saved(self) -> None:
        if self.saved_profile is None:
            raise ValueError("没有已保存的配置")
        self.provider = self.saved_profile
        self.saved, self.source, self.connection_state = True, "saved", "untested"

    def test(self, value: Any) -> bool:
        candidate = self.candidate(value)
        request = {"task": "connection_check", "instruction": "Return the JSON object {\"ok\":true}.",
            "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}},
                              "required": ["ok"], "additionalProperties": False}}
        same = candidate == self.provider
        try:
            response = candidate.complete(request, connection_test=True)
            if response.output != {"ok": True}:
                raise ProviderError("接口可达，但模型没有返回要求的 JSON 结构")
        except ProviderError:
            if same:
                self.connection_state = "failed"
            raise
        if same:
            self.connection_state = "verified"
        return same
