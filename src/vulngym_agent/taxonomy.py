from __future__ import annotations

from typing import Any, Iterable


TAXONOMY_VERSION = "vulngym-v0.1.4"
TAXONOMY_SOURCE = "https://github.com/Tencent/VulnGym/blob/v0.1.4/README_zh.md#漏洞类型分布"

BUSINESS_LOGIC_L2 = {
    "BL-AUTHZ-BROKEN": "授权逻辑错误",
    "BL-AUTHZ-MISSING": "授权缺失",
    "BL-AGENT-CAPABILITY": "AI/Agent 能力边界绕过",
    "BL-PRIV-ESC": "特权提升",
    "BL-AUTH-BYPASS": "身份认证绕过",
    "BL-ORIGIN-INTEGRITY": "来源、签名或完整性校验缺失",
    "BL-WORKFLOW-VIOLATION": "业务流程或状态机违规",
    "BL-INSECURE-DEFAULT": "不安全默认配置",
    "BL-RACE-LOGIC": "业务层竞争条件",
    "BL-MULTI-TENANT": "多租户或隔离失效",
    "BL-MASS-ASSIGNMENT": "参数或属性污染",
    "BL-TRUST-BOUNDARY": "隐式信任内部输入",
}

# Exact category pairs observed in the 393 verified records shipped by the
# official VulnGym v0.1.4 tag.  Counts are evidence of dataset vocabulary, not
# proof that a candidate record chose the semantically correct category.
OBSERVED_CATEGORY_PAIRS = {
    ("SSRF", "DNS重绑定（DNS Rebinding）"): 1,
    ("SSRF", "服务端请求伪造"): 2,
    ("SSRF", "沙箱安全控制绕过"): 2,
    ("SSRF", "路径穿越辅助 SSRF"): 3,
    ("XSS", "Stored XSS"): 6,
    ("XSS", "存储型XSS"): 3,
    ("业务逻辑", "BL-AGENT-CAPABILITY(AI/Agent能力边界绕过)"): 36,
    ("业务逻辑", "BL-AUTH-BYPASS(身份认证绕过)"): 20,
    ("业务逻辑", "BL-AUTHZ-BROKEN(授权逻辑错误)"): 61,
    ("业务逻辑", "BL-AUTHZ-MISSING(授权缺失)"): 67,
    ("业务逻辑", "BL-INSECURE-DEFAULT(不安全默认配置)"): 22,
    ("业务逻辑", "BL-MASS-ASSIGNMENT(参数/属性污染)"): 6,
    ("业务逻辑", "BL-MULTI-TENANT(多租户/隔离失效)"): 5,
    ("业务逻辑", "BL-ORIGIN-INTEGRITY(来源/签名/完整性校验缺失)"): 16,
    ("业务逻辑", "BL-PRIV-ESC(特权提升)"): 23,
    ("业务逻辑", "BL-RACE-LOGIC(业务层竞争条件)"): 6,
    ("业务逻辑", "BL-TRUST-BOUNDARY(隐式信任内部输入)"): 7,
    ("业务逻辑", "BL-WORKFLOW-VIOLATION(业务流程/状态机违规)"): 9,
    ("代码注入", "OS命令注入（Shell注入）"): 1,
    ("代码注入", "SQL 驱动的 JavaScript 代码注入（SQL-to-JS Code Injection）"): 2,
    ("代码注入", "任意模块导入"): 6,
    ("代码注入", "沙箱逃逸"): 2,
    ("代码注入", "表达式沙箱逃逸"): 6,
    ("代码注入", "表达式注入"): 2,
    ("代码注入", "表达式注入（Expression Injection）"): 2,
    ("供应链攻击", "嵌入恶意代码"): 3,
    ("信息泄露", "内存信息泄露"): 2,
    ("原型链污染", "Prototype Pollution"): 3,
    ("反序列化", "不可信数据反序列化 / 远程代码执行"): 8,
    ("反序列化漏洞", "不可信数据反序列化"): 11,
    ("命令注入", "Git配置注入触发任意命令执行"): 1,
    ("命令注入", "OS 命令注入"): 2,
    ("命令注入", "OS命令注入"): 4,
    ("命令注入", "不可信搜索路径 / 可执行文件劫持"): 2,
    ("命令注入", "参数注入"): 3,
    ("命令注入", "脚本生成注入"): 1,
    ("文件操作安全", "TOCTOU / 符号链接跟随 / 路径穿越"): 2,
    ("文件操作安全", "TOCTOU竞争条件"): 2,
    ("权限绕过", "不安全的临时文件/目录权限"): 2,
    ("模板注入", "服务端模板注入 (SSTI)"): 3,
    ("沙箱逃逸", "代码注入 / VM 沙箱逃逸"): 2,
    ("沙箱逃逸", "文件系统竞态条件"): 1,
    ("注入", "服务端请求伪造"): 1,
    ("注入与反序列化", "不安全反序列化"): 3,
    ("注入攻击", "SQL注入"): 1,
    ("注入类", "SQL 注入 / 任意文件写入"): 2,
    ("认证绕过", "编码路径绕过（Alternate Path / Channel）"): 2,
    ("认证绕过", "路径规范化不一致导致的认证绕过"): 3,
    ("越界文件读取", "沙盒逃逸"): 3,
    ("路径穿越", "ZIP解压路径穿越"): 1,
    ("路径穿越", "任意文件写入"): 1,
    ("路径穿越", "外部文件路径控制（CWE-73）"): 3,
    ("路径穿越", "目录遍历（Directory Traversal）"): 2,
    ("路径遍历 / 任意文件读取", "Content-Type 混淆导致的路径穿越"): 1,
    ("路径遍历 / 越权写入", "TOCTOU 竞争条件导致的沙盒逃逸"): 2,
}
OBSERVED_L1_COUNTS: dict[str, int] = {}
for (_l1, _l2), _count in OBSERVED_CATEGORY_PAIRS.items():
    OBSERVED_L1_COUNTS[_l1] = OBSERVED_L1_COUNTS.get(_l1, 0) + _count


def _category_code(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.partition("(")[0].partition("（")[0].strip().upper()


def taxonomy_evidence(
    record: dict[str, Any],
    advisory_documents: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    documents: list[dict[str, Any]] = []
    l1 = record.get("vuln_category_l1")
    l2 = record.get("vuln_category_l2")

    if isinstance(l1, str) and l1.strip() == "业务逻辑":
        documents.append(
            {
                "evidence_id": f"taxonomy:{TAXONOMY_VERSION}:l1:business-logic",
                "field": "vuln_category_l1",
                "candidate_value": l1,
                "canonical_value": "业务逻辑",
                "definition": "Vulnerabilities caused by broken authorization, trust, workflow, capability, or other application security logic.",
                "source": TAXONOMY_SOURCE,
            }
        )

    code = _category_code(l2)
    if code in BUSINESS_LOGIC_L2:
        documents.append(
            {
                "evidence_id": f"taxonomy:{TAXONOMY_VERSION}:l2:{code.lower()}",
                "field": "vuln_category_l2",
                "candidate_value": l2,
                "canonical_code": code,
                "parent_l1": "业务逻辑",
                "definition": BUSINESS_LOGIC_L2[code],
                "source": TAXONOMY_SOURCE,
            }
        )

    if isinstance(l1, str) and l1 in OBSERVED_L1_COUNTS and l1 != "业务逻辑":
        documents.append(
            {
                "evidence_id": f"taxonomy:{TAXONOMY_VERSION}:l1:observed:{l1}",
                "field": "vuln_category_l1",
                "candidate_value": l1,
                "canonical_value": l1,
                "definition": f"Observed as an L1 label in {OBSERVED_L1_COUNTS[l1]} verified VulnGym v0.1.4 records.",
                "source": TAXONOMY_SOURCE,
            }
        )

    pair_count = OBSERVED_CATEGORY_PAIRS.get((l1, l2))
    if pair_count is not None and l1 != "业务逻辑":
        documents.append(
            {
                "evidence_id": f"taxonomy:{TAXONOMY_VERSION}:l2:observed:{l1}:{l2}",
                "field": "vuln_category_l2",
                "candidate_value": l2,
                "canonical_value": l2,
                "parent_l1": l1,
                "definition": f"Observed with this L1 label in {pair_count} verified VulnGym v0.1.4 record(s).",
                "relationship": "This exact L1/L2 pair is an observed dataset mapping; treat L1 as the dataset parent category, not as a synonym for the advisory CWE name.",
                "source": TAXONOMY_SOURCE,
            }
        )

    weaknesses = {
        weakness.upper()
        for document in advisory_documents
        if isinstance(document, dict)
        for weakness in document.get("weaknesses", [])
        if isinstance(weakness, str)
    }
    if "CWE-306" in weaknesses and code == "BL-AUTHZ-MISSING":
        for field, candidate_value in (
            ("vuln_category_l1", l1),
            ("vuln_category_l2", l2),
        ):
            documents.append(
                {
                    "evidence_id": f"taxonomy:{TAXONOMY_VERSION}:cross-check:cwe-306-vs-authz:{field}",
                    "field": field,
                    "candidate_value": candidate_value,
                    "cross_check": "semantic_conflict",
                    "advisory_weakness": "CWE-306 Missing Authentication for Critical Function",
                    "candidate_semantics": "BL-AUTHZ-MISSING means a missing authorization decision after identity is established",
                    "reason": "Authentication establishes identity; authorization decides what an established identity may do. Do not reinterpret missing authentication as missing authorization without separate authorization evidence.",
                    "source": TAXONOMY_SOURCE,
                }
            )

    matched_fields = sorted({document["field"] for document in documents})
    if len(matched_fields) == 2:
        status = "matched"
    elif matched_fields:
        status = "partial"
    else:
        status = "unmatched"
    return {
        "status": status,
        "taxonomy_version": TAXONOMY_VERSION,
        "source": TAXONOMY_SOURCE,
        "matched_fields": matched_fields,
        "documents": documents,
    }
