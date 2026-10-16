# 自评报告

## 结论先行

当前系统已经形成可交付的 T1 Agent：一条命令完成规划、只读工具取证、Judge、Critic、透明仲裁、
八字段报告和反思；结论能定位到源码、补丁、公告、Trace 与 taxonomy；模型、Prompt、成本和失败均可追溯。

我们没有宣称官方隐藏集准确率。现有同模型仓库级开发对照包含 10 个真实仓库、12 个预先登记的变异
字段，裸模型检出 9/12，Evidence Judge 检出 12/12；该组随后参与了仲裁规则开发，因此最终 Agent
12/12 只作为失败驱动迭代记录。完整八字段 Blind v2 已按 `BLIND_EVALUATION_V2.md` 单次执行：
59/80。失败驱动修复后，Blind v3 又在预测前完成公开证据复核并唯一运行：70/104（67.31%）。
2026-09-04 的 Blind v5 使用 6 条未见 entry/report 和 Qwen3.8-Max 唯一运行，冻结结果为 26/48
（54.17%），但检出全部 6 个预登记错误；Post-v5 修复确定性源码误伤后，零模型调用重放为 33/48
（68.75%）。后者只属于已见失败诊断，不冒充新盲测。
随后在预测前冻结公告完备且未见的 Blind v6，唯一运行得到 62/64（96.875%），检出 10/10 个预登记
错误，incorrect precision / recall 为 90.91% / 100%。该组只有 2 个仓库，仍是有限证据而非官方成绩。
冻结后发现 Commit 适配器存在唯一直接子提交的循环论证风险。Packet 0.9.0 修复后复用原语义输出做
零模型重放为 59/64；三项 Commit 从 `correct` 降为 `uncertain`。这属于安全性加固，不覆盖 62/64，
也不是新的盲测。
Packet 0.11.0 又补充了有界一跳跨文件 helper 取证。最终在模型调用前冻结 5 个未进入既往冻结选择的
entry/report，覆盖 5 仓库与 Python、TypeScript、Go。唯一 Qwen3.8-Flash 运行在 8 次物理调用上限内
完成 4/5；已完成字段 27/32（84.38%），把缺失项计入冻结全集为 27/40（67.50%）。该结果不会因分数
补跑，且与 Blind v6 的 62/64 分开报告。

## 当前版本

- Evidence Packet：`0.11.0`；
- Workflow：`0.1.0`；
- Judge/Critic Prompt：`1.7.0`（当前开发版；Blind v4 保留 `1.5.0`）；
- 单元测试：当前 134/134 通过（最终归档前再次复核）；
- 开发证据：5 条 Pilot、5 条早期 unseen、10 仓库 repo holdout；
- 输出：Entry、Critical、L1、L2、Title、IDs、Commit、Trace 八字段报告。

## 核心能力

1. 确定性层验证 Schema、commit、文件、行号和源码，并能定位漂移/歧义；
2. Evidence 层组合官方公告、修复 diff、Trace 静态关系和 VulnGym taxonomy；
3. 语义层逐字段输出 `correct / incorrect / uncertain`，所有确定结论必须引用真实 evidence ID；
4. Critic 主动寻找反证，置信度仲裁防止低置信回退覆盖更强判断；
5. Workflow 在取证前形成 run/skip 计划，按可用资源执行并在反思中暴露证据缺口；
6. checkpoint、resume、契约重试、Provider 安全开关和八字段适配构成可运行工程闭环。
7. `validate` 同时生成 JSONL、Markdown 和自包含 HTML 报告；GitHub Actions 在 Python 3.10/3.12
   执行单元测试、交付合同和 CLI 表面检查。
8. 批次系统性分析器对至少两个案例重复出现的证据缺口、字段错误模式、Judge→Critic 方向变化和
   模型契约重试生成 JSON/Markdown 归因线索；每条列出案例 ID，并明确不把相关性当成已证明根因。

## 同模型仓库级开发对照

| 指标 | 裸记录 | Evidence Judge | 最终 Agent |
|---|---:|---:|---:|
| 目标字段检出 | 9/12 | 12/12 | 12/12 |
| 目标字段召回 | 75% | 100% | 100% |
| uncertain | 2 | 0 | 0 |
| 错误字段误判为 correct | 1 | 0 | 0 |
| 完成案例 | 10/10 | 10/10 | 10/10 |

三组均使用 `deepseek-v4-flash`。裸模型只看候选记录；Agent 额外使用只读工具生成的证据。只评估
manifest 中预先声明的变异字段，未变异字段不冒充人工 Gold。Critic 回退推动了同组 non-regression
gate，因此该表不作为冻结盲测成绩。

## 效率与工程指标

- 完整 Agent 紧凑前：650,807 Token；紧凑后：319,784 Token，下降 50.9%；
- 请求字符总量下降 55.6%，目标字段检出保持 12/12；
- 紧凑后 10/10 完成，Judge/Critic 最终结果均通过本地契约；
- 当前完整单元测试 134/134 通过；演示产物、开发评测、Blind v2、Blind v3、Blind v5/v6、Final Blind v1 与 provenance 加固回放材料通过检查；
- 每条原子 checkpoint，支持 `--resume`、只补 Critic 和持久化结果重放；
- Prompt ID、版本、SHA-256、Provider 元数据、耗时与 Token 全部进入结果；
- 目标仓库只用只读 Git 与静态源码检查，不执行项目、PoC 或陌生依赖。
- 详细模型调用、Token、延迟及估算口径见 `docs/COST_AND_LATENCY.md`。

## 早期 Judge→Critic 对照

在另一组固定 unseen provisional 参考中，同材料单次 Judge 为 21/25，Judge→Critic 为 25/25。该结果
说明 Critic 曾找回四个源码支持的遗漏，但参考标签仍有 AI 辅助，不是独立专家 Gold。repo holdout 进一步
暴露了 Critic 也可能回退，因此当前系统增加透明仲裁，而不是无条件相信第二次模型输出。

## 已确认边界

- Helper/Trace 只做有预算的一跳静态分析，不是跨语言完整 call graph 或 taint engine；
- 模型置信度并未统计校准，仲裁门是透明工程策略，不是真实概率证明；
- Provider 无固定 seed，单轮结果保留采样波动风险；
- Blind v3 原始运行中 Commit 适配器对 13/13 条全部弃权；当前适配器已利用可检查 patch provenance，
  但缺少权威 patch 时仍会安全弃权；
- Blind v3 原始运行中 Trace 仅 6/13；当前 Prompt 已修正过度判错口径，但尚无第二组独立盲测证明
  该改动的自然分布泛化收益；
- Blind v5 的 48 字段冻结结果为 26/48，incorrect recall 100% 但 precision 仅 33.33%；这说明系统偏向
  安全拒绝，尚不能宣称整体准确率领先。修复本地误伤后的 33/48 是已见结果重放，不是独立泛化证明；
- Blind v5 全量 Critic 使用一半阶段调用但零改判，后续应改为有预算的条件触发，而不是默认双调用；
- Blind v6 的选择性 Critic 将 8 条案例控制为 10 次调用并达到 62/64，但仅覆盖 2 个仓库；两个剩余
  差异都在开放 taxonomy 边界，不能由这组结果推导总体 96.88% 泛化准确率；
- Post-v6 provenance 加固把三个缺少权威修复角色的 Commit 改为 `uncertain`，得到 59/64；该下降是
  主动移除循环论证后的诚实弃权，不是模型能力退化，也不是新盲测成绩；
- Final Blind v1 的 5 条参考均在模型前复核，但仍非独立专家 Gold；调用上限导致 1 条未预测，已完成
  结果中仍有 2 个高置信误报和 3 个弃权，不能包装成满分或官方泛化准确率；
- repo holdout 是定向变异评测，不等于自然错误分布或主办方隐藏集；
- Blind v2 首次冻结结果为 59/80；Blind v3 证据复核参考的唯一结果为 70/104；两组均不覆盖重跑；
- 正式提交前仍需参与者录制 3–5 分钟演示，并按最新通知设置仓库可见性。

## 当前交付判断

代码、架构、过程记录、Prompt 历史、评估机制、固定演示和干净归档验收均已形成交付闭环，具备完整
参赛作品形态。Blind v6 与 Final Blind v1 已提供互补的错误检出和多仓运行证据，因此效果验证可以收网；但仍不称
“稳 Top 3”，因为主办方隐藏测试、竞争作品质量和开放 taxonomy 真值未知。现阶段进入最终录屏、
干净归档复核、合并和版本标签，而不是继续针对 Blind v6 调参。
