# 仓库级开发评测（原 repo-holdout-v1）

> 口径更正（2026-08-29）：这组案例最初以仓库级留出集构建，但 Critic 在其中一例的回退直接推动了
> non-regression gate。自该规则使用同组结果验证后，这组数据已经参与开发，不能继续作为最终盲测。
> benchmark ID 和历史文件名保留以保证实验可追溯，后续统一称为“仓库级开发评测”。

## 结论

`repo-holdout-v1` 初次运行时使用 10 个此前未参与 Prompt 调试的真实开源仓库，检验“工具与证据是否
真的比直接把记录丢给同一个模型更有用”。底层模型统一为 `deepseek-v4-flash`，因此不是不同模型之间
的不公平比较。最终仲裁层的 12/12 是开发后结果，不作为独立泛化证据。

| 系统 | 检出预设错误字段 | 召回 | uncertain | 错判为 correct |
|---|---:|---:|---:|---:|
| 只看候选记录的裸模型 | 9/12 | 75% | 2 | 1 |
| Evidence Judge | 12/12 | 100% | 0 | 0 |
| Judge→Critic→仲裁 | 12/12 | 100% | 0 | 0 |

该结果证明的是：在这组仓库隔离、定向变异任务上，源码、公告、补丁、Trace 和 taxonomy 证据补足了
裸模型的盲点。它不等于官方隐藏集准确率，也不把未变异字段当作人工 Gold。

## 数据设计

- 10 个仓库：Flowise、Paperclip、Langflow、MLflow、Open WebUI、LangChain、MCP TypeScript SDK、
  ONNX、LiteLLM、NLTK；
- 每个仓库只生成一个案例，donor 必须来自另一个仓库；
- 变异类型覆盖错误 Entry、错误 Critical Operation、错误两级分类、跨仓库 Trace 和反向 Trace；
- 每个目标字段、原值、变异值、donor、变异类型与内容哈希在模型运行前写入独立 manifest；
- 一共 10 个案例、12 个目标字段。两级分类一次变异对应两个目标字段。

配置位于 `configs/repo-holdout-v1.json`、`configs/repo-holdout-v1-fixes.json` 和
`configs/advisories/repo-holdout-v1.jsonl`。摘要位于 `artifacts/repo-holdout-v1/summary.json`。

## 公平对照

裸模型只获得候选 VulnGym 记录，不获得仓库、源码、公告、patch、taxonomy 或工具输出；它仍使用与 Agent
相同的五字段结构、一次契约修复机会和同一个 DeepSeek 模型。Evidence Judge 获得紧凑可引用证据包；
完整 Agent 再增加 Critic 和确定性仲裁。

评分只查看 manifest 中预先声明的变异字段：预测 `incorrect` 算检出，`uncertain` 单列，`correct` 算漏检。
未被变异的字段不参与该项分数，避免在没有独立专家 Gold 时循环论证。

## 成本实验

初版完整 Agent 因重复源码窗口和无界 patch 候选列表消耗 650,807 Token。保留完整 Packet 落盘、只向模型
发送紧凑 Semantic Packet View 后：

- 模型请求字符总量：775,220 → 344,146（-55.6%）；
- 完整 Agent Token：650,807 → 319,784（-50.9%）；
- 变异字段检出：12/12 → 12/12；
- 运行耗时：221.54s → 221.22s，说明本轮主要优化 API 成本和上下文噪声，而非网络延迟。

## Critic 非回归门

紧凑实验中 Critic 曾把 Judge 已识别的 LiteLLM 反向 Trace 从 `incorrect, 0.70` 改成
`uncertain, 0.55`。系统没有隐藏这一失败，而是加入通用规则：Critic 与 Judge 方向相反时，只有置信度
相等或更高才可覆盖；否则保留 Judge，并记录双方 verdict、confidence 与选择理由。离线重放后最终恢复
12/12。另一个旧案例中 Critic 将 `uncertain, 0.60` 修正为 `incorrect, 0.80`，高置信改进仍被保留。

## 可复现边界

- 公开仓库与公告可以复核，但上游内容未来可能变化，固定 commit 与本地缓存用于重现本轮证据；
- 模型没有固定 seed，本报告保留 Provider、Prompt 哈希、耗时、用量和原始阶段输出；
- 正式准确率仍需主办方隐藏集或独立安全专家 Gold；本实验定位为工程化对照与失败驱动迭代证据。
