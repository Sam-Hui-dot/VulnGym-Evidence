"""Integrity-checked historical run of the fixed public teaching example."""
from importlib.resources import files
import json

from .contract import input_digest, validate_request


def load_demo_result():
    result = json.loads(files("vulngym_evidence").joinpath("web/demo-result.json").read_text(encoding="utf-8"))
    request = validate_request(result["request"])
    if result["input_sha256"] != input_digest(request):
        raise ValueError("演示输入完整性检查失败")
    if [r["claim_id"] for r in result["results"]] != [c["claim_id"] for c in request["claims"]]:
        raise ValueError("演示声明与结果不一致")
    return result
