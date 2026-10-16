# Blind v2 独立复核表

这张表用于把数据集派生的 provisional reference 变成可解释的人审结论。复核者只看候选、公开公告、
固定 commit 源码与 Patch（若存在），**不得先看 Agent 输出**。复核不要求写代码，但要求能够指出支持或
反驳候选字段的具体证据。

## 复核材料

- 候选与参考差异：`out/blind-v2/review-queue.jsonl`；
- 完整证据包：`out/blind-v2/evidence.jsonl`；
- 冻结案例清单：`artifacts/blind-v2/manifest.json`；
- 公告与 Patch 边界：`artifacts/blind-v2/evidence-manifest.json`；
- 判定口径：`docs/GOLD_REVIEW_GUIDE.md`。

如果复核者无法可靠判断，填 `uncertain` 是合格结果。Entry Point、Critical Operation 与 Trace 允许多种
合理表达；复核目标是判断当前候选是否可辩护，不是强行寻找唯一答案。

## 预登记标签与逐案问题

| 案例 | 类型 | provisional `incorrect` 字段 | 复核重点 | 人审状态 |
|---|---|---|---|---|
| entry-00097 AutoGPT | 历史修订 | trace | 旧 Trace 是否遗漏 disabled block 到代码执行的必要阶段；公告与 v0.6.44 对照能否支持修订 | pending |
| entry-00334 Trivy | 历史修订 | entry_point、critical_operation、trace | 旧字段是否把供应链发布链路锚定在错误位置；无单一 fix commit 时公告与恶意 commit 是否足够 | pending |
| entry-00074 Ollama | 历史修订 | entry_point、trace | API 路由与处理函数是否构成合理入口；旧 Trace 是否忠实描述未认证模型管理流程 | pending |
| entry-00153 NeMo | 历史修订 | entry_point、trace | 广播字节到 `pickle.loads` 的数据流是否完整；旧入口行/代码是否与固定 commit 一致 | pending |
| entry-00119 Milvus expr | 历史修订 | entry_point、critical_operation、trace | `/expr` 注册、默认 auth 与表达式执行是否闭环；跨维护分支 Patch 不作为主要证据 | pending |
| entry-00314 Airflow | 干净 | 无（八字段 provisional correct） | JWT 认证与 task_instance_id 资源授权缺口是否被准确区分 | pending |
| entry-00507 n8n-mcp | 干净 | 无（八字段 provisional correct） | 未鉴权 GET `/mcp` 到现有 transport 的链路、会话影响和分类是否可由公告/Patch支持 | pending |
| entry-00311 FastMCP | 干净 | 无（八字段 provisional correct） | 静态 audience 与跨 MCP server token reuse 的因果链是否完整 | pending |
| entry-00341 NeMo checkpoint | 干净 | 无（八字段 provisional correct） | 外部 checkpoint 路径到 `torch.load(..., weights_only=False)` 是否成立 | pending |
| entry-00058 Milvus auth | 干净 | 无（八字段 provisional correct） | 可伪造 sourceId、公开成员常量与跳过凭证检查的链路是否成立 | pending |

## 每条案例必须填写

```text
case_id:
reviewer:
reviewed_at:

entry_point: correct / incorrect / uncertain
evidence:

critical_operation: correct / incorrect / uncertain
evidence:

vuln_category_l1: correct / incorrect / uncertain
evidence:

vuln_category_l2: correct / incorrect / uncertain
evidence:

vuln_title: correct / incorrect / uncertain
evidence:

vuln_ids: correct / incorrect / uncertain
evidence:

commit: correct / incorrect / uncertain
evidence:

trace: correct / incorrect / uncertain
evidence:

overall_notes:
```

## 接受条件

1. 八个字段都有结论和可定位证据，或明确说明为什么只能 `uncertain`；
2. 历史修订确认是语义纠错，不只是格式、措辞或另一种同样合理的粒度；
3. 干净案例不能因为来自 `verify=1` 就自动全判 `correct`；仍需抽查公告、源码和链路；
4. 复核结果写入新的 reviewed reference，不能覆盖冻结的 provisional reference；
5. 如果人审改变标签，保留原标签、修改理由和复核者，不据此调整本轮 Agent 后再重跑同一组。

一位复核者即可形成“人工复核参考”，但仍不能称安全专家 Gold。若要使用“独立 Gold”措辞，应由未参与
系统开发、具备代码安全判断能力的人复核；争议字段由第二位复核者仲裁，无法一致则保留 `uncertain`。
