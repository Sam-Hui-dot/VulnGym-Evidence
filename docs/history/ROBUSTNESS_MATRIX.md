# Robustness Matrix

鲁棒性与字段准确率分开报告。下列案例不进入 `blind-v2` 的 80 个字段分母，避免把“资源不可用时诚实
弃权”和“有完整证据时判断字段正确性”混成一个数字。

| 场景 | 预期行为 | 当前证据 | 最终状态 |
|---|---|---|---|
| 非法 JSONL | 指出行号并非零退出，不产生半条结果 | `jsonl.py` 错误路径 | 单元回归通过 |
| 必填字段缺失 | Schema 字段级 `incorrect`，报告保留证据 | Schema/engine 单元覆盖 | 单元回归通过 |
| 上游仓库不存在 | 不猜源码语义；列出 `repository_missing` | Workflow gap planner | 单元回归通过 |
| commit 不存在 | commit 字段 `incorrect`，源码字段不伪造 | Git/Source audit | 单元回归通过 |
| 公告缓存缺失 | IDs/title/commit 依证据降为 `uncertain` | Submission adapter | 单元回归通过 |
| 修复 Patch 不可确定 | 保留 warning，让模型基于其余证据判断或弃权 | PatchInspector；post-v3 Paperclip | 在线案例验证 |
| Provider 未启用或 Key 缺失 | 网络前失败，不泄露 Key | DeepSeek/OpenRouter provider | 单元回归通过 |
| 临时 API 错误 | 有界重试；仍失败则保留 provider error | Semantic runner | 单元回归通过 |
| 模型输出不满足契约 | 携带精确校验反馈重试一次，失败不进入最终判断 | Semantic contract | 单元与在线修复路径通过 |
| Critic 中断 | Judge checkpoint 保留，可仅补跑 Critic | checkpoint/resume | 在线恢复验证 |
| 批处理中断 | 已完成记录不重复调用，恢复后继续 | `--resume` | 多轮在线恢复验证 |
| 错误引用 evidence ID | 契约拒绝，不允许幻觉证据进入报告 | Semantic contract | 单元回归通过 |

单元与在线恢复证据用于证明边界行为；最终还需在全新目录执行 `scripts/verify_delivery.py` 和离线演示，
验证打包后没有依赖当前工作区的隐藏状态。
