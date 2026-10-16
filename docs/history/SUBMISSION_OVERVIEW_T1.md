# VulnGym T1 提交总览

> 建议评审从本页开始。完整源码、过程记录、冻结评测和失败案例均保留在仓库中，但无需逐份阅读。

## 1. 作品解决什么问题

VulnGym 的候选记录会描述漏洞入口、关键操作、分类、编号、Commit 和执行链路。这些字段即使格式合法，
也可能与公告、源码或修复补丁不一致。本项目实现了一个证据优先的 T1 审核 Agent：输入 VulnGym JSONL，
自动逐字段判断 `correct / incorrect / uncertain`，给出可追溯证据，并在能够确定时提出修正建议。

系统不是用一次 Prompt 猜整条记录，而是执行：

```text
规划 → Schema/Git/源码/公告/Patch/Trace 工具取证
     → 结构化证据包 → 主审模型 → 按需复核模型 → 置信度仲裁
     → 八字段 JSONL + Markdown/HTML 报告 + 批次问题分析
```

确定性事实由工具核验；开放式安全语义交给可插拔 LLM；证据不足时主动输出 `uncertain`。

文档中的常用术语：Evidence Packet 是工具整理出的“证据包”；Judge 是第一轮主审；Critic 是按需触发
的第二轮反证复核；Arbiter 是比较两轮结果的确定性仲裁规则；Gold 指用于计算准确率的人工参考答案。

## 2. 三分钟评审路径

1. 观看根目录 `VulnGym-T1-Sam-Demo-final.mp4`（提交包组装后出现）。
2. 运行离线演示：`python3 scripts/show_demo.py`；参与者录屏使用真实入口 `bash scripts/run_recording_demo.sh --open`。
3. 阅读简明设计：[docs/DESIGN_SUMMARY.md](../docs/DESIGN_SUMMARY.md)。
4. 查看可读结果：[artifacts/final-blind-v1/report/report.html](../artifacts/final-blind-v1/report/report.html)。
5. 需要复核工程状态时运行：`python3 scripts/verify_delivery.py`。

完整文档导航见 [docs/INDEX.md](../docs/INDEX.md)。

## 3. 对照题目要求

| 题目要求 | 本项目实现 | 主要证据 |
|---|---|---|
| 八个核心字段独立三态判断 | Entry、Critical、L1/L2、Title、IDs、Commit、Trace | `artifacts/final-blind-v1/submission.jsonl` |
| 每项给证据 | 确定结论必须引用当前证据包中的真实证据编号 | `evidence.jsonl`、HTML 报告 |
| 公告与源码交叉验证 | 离线公告缓存 + 只读 Git/源码/Patch/Trace | `src/vulngym_agent/` |
| 证据不足不猜 | 缺仓库、坏 Commit、404/缺公告、来源冲突时输出 `uncertain` | `docs/ROBUSTNESS_MATRIX.md` |
| JSONL 批处理 | `validate` 一条命令完成批量输入、断点和输出 | `README.md` 使用章节 |
| Agent 循环 | 规划、工具调用、Judge、条件 Critic、仲裁、反思 | `docs/ARCHITECTURE.md` |
| 至少三类工具 | Schema、Git、Source、Advisory、Patch、Trace、Taxonomy | `docs/DESIGN_SUMMARY.md` |
| Self-check | JSON Schema/语义契约、证据引用检查、派生值重算 | `semantic_contract.py` |
| 系统性错误与修正建议 | 自动聚合跨案例重复信号；唯一证据支持时给建议值 | `systemic-analysis.md` |
| 多语言 | 已实际覆盖 Python、TypeScript/JavaScript、Go | Final Blind v1 |

题目要求的源码、设计文档、Prompt 历史、AI Coding 使用记录、调试日志、公开数据输出和演示材料也均有
对应文件；完整映射见 [docs/SUBMISSION_CHECKLIST.md](../docs/SUBMISSION_CHECKLIST.md)。

## 4. 结果摘要与边界

| 证据 | 结果 | 应如何理解 |
|---|---:|---|
| 同模型开发对照 | 裸模型 9/12 → Evidence Judge 12/12 | 10 仓定向错误字段；用于说明证据工具价值，不是盲测 |
| Token 优化 | 650,807 → 319,784（-50.9%） | 删除模型视图中的重复证据，目标字段检出保持 12/12 |
| Blind v6 | 62/64；错误检出 10/10 | 运行前冻结、唯一运行；仅 2 仓库，非官方隐藏集 |
| Final Blind v1 | 5 仓/3 语言；完成 4/5 | 8 次调用上限停止；完整分母 27/40，未补跑刷分 |

所有冻结失败、误报、弃权和中断均保留。参考标签由公告、源码和 Patch 复核，但不是官方隐藏集或
独立安全专家 Gold，因此本项目不宣称官方准确率，也不承诺特定名次。

## 5. 最快运行方式

环境：Python 3.10+。离线演示和交付检查不需要第三方依赖，也不会调用模型。

```bash
python3 scripts/show_demo.py
python3 scripts/verify_delivery.py
```

最终录屏的真实端到端演示（需要本地 WeKnora 仓库及未提交的 `.env` 中配置 Qwen Key）：

```bash
bash scripts/run_recording_demo.sh --open
```

完整 Agent 的 `validate` 命令、上游仓库布局和 Qwen/DeepSeek/Codex CLI 可插拔 Provider 配置见
[README.md](../README.md#完整-agent运行)。API Key 只能放在本地环境变量中，不得进入提交包。

## 6. 提交包结构

```text
SUBMISSION_OVERVIEW.md      本页，评审入口
README.md                   完整安装、运行和命令参考
VulnGym-T1-Sam-Demo-final.mp4  3–5 分钟演示（最终组包后出现）
src/vulngym_agent/          Agent 源代码
docs/DESIGN_SUMMARY.md      1–3 页设计说明
docs/INDEX.md               文档导航
artifacts/demo/             固定离线演示结果
artifacts/final-blind-v1/   多仓冻结评测、JSONL、HTML 和批次分析
tests/                      单元测试
scripts/                    演示、验收和最终组包工具
```

长篇 AI Coding、实验、Prompt 和决策记录属于审计附录，保留是为了证明迭代过程，并非要求评审顺序阅读。
