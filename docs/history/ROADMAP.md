# Top 3 路线图

> 状态说明：这是研发期路线和阶段目标的历史记录。当前交付状态以 `RELEASE_HANDOFF.md` 与
> `SUBMISSION_CHECKLIST.md` 为准；未勾选的探索项不代表正式提交缺少必需功能。

## 核心判断

主线选择 T1，目标做到 Standard 完整度并用 Bonus 能力拉开差距。T2 的开放式抽取能力可以复用，
但不在第一阶段同时铺开，避免得到两个都不稳定的演示原型。

## 工作包

### WP1：可审计的确定性底座（已完成）

- VulnGym v0.1.4 数据适配；
- Schema、Git 对象、源码位置和代码片段工具；
- 三态结论、证据和置信度；
- 批处理 CLI；
- 不执行未知仓库代码的安全边界。

完成标准：所有输入都能得到合法 JSONL；事实性问题不交给模型猜；缺少证据时输出 uncertain。

### WP2：自己的训练与留出集

- 以官方 v0.1.4 中 `verify=1` 的记录为正例；
- 从历史版本修订中提取真实的 before/after 错误；
- 生成 commit、路径、行号、代码、角色交换、类别、trace 断裂等可控变异；
- 按 report/repository 切分，禁止同一漏洞泄漏到训练与留出集；
- 保存每个变异的错误标签和生成依据。

当前状态：合成变异、仓库隔离开发对照、独立 manifest 和 Git 历史 before→after 矿工已落地；
Blind v3 已对 13 条/104 字段完成公告、源码、Patch、Trace 与 taxonomy 证据复核，明确区分真实错误、
合理多解和纯描述升级。

完成标准：能稳定复现一套开发集和从未参与提示词调试的留出集。

### WP3：语义 Agent

- AdvisoryReader：解析漏洞公告和标识；
- PatchInspector：对比漏洞版本与修复版本；
- CodeSearcher：围绕候选入口和关键操作建立最小上下文；
- TraceInspector：验证调用/数据流连续性；
- SemanticJudge：判断 entry、critical、category、title、trace 的语义；
- Critic：主动寻找反证，必要时把 correct 降为 uncertain。

完成标准：使用同一个底层模型时，Agent 在留出集上稳定超过 one-shot 基线。

当前状态：PatchInspector、CodeSearcher/Evidence Packet、Judge/Critic、离线 AdvisoryReader 与
TraceInspector 0.1 已落地。Blind v2 失败推动 Title 语义适配和源码摘要修复；Blind v3 又暴露 Commit
provenance、Trace 过度补全和认证/授权 taxonomy 混淆。当前开发版为 Packet 0.11.0、Prompt 1.7.0；
Blind v3 原结果不重跑，已见失败只用于明确标注的 post-v3 定向回归。
Packet 0.11.0 已实现受限一跳跨文件 helper 追踪：只接受唯一静态解析，最多 24 个候选文件和 6 个结果，
歧义时弃权，不扩展为完整调用图。

### WP4：比赛评测器和优化闭环

至少跟踪：

- 字段准确率；
- 错误召回率；
- 证据可接受率；
- Schema 通过率；
- 幻觉率；
- 单条耗时、模型 token 和失败重试次数。

每次改提示词、工具描述或上下文策略，都必须在固定留出集上做 A/B，而不是凭单个案例观感判断。

当前状态：字段级语义评测器已支持 Judge/Critic、弃权、高置信错误及分批结果合并；八字段提交评测器
进一步统计 incorrect precision/recall/F1、整例完全一致率和证据覆盖。原 repo-holdout-v1 已更正为开发
评测；`blind-v2` 唯一运行 59/80，`blind-v3` 经证据复核后唯一运行 70/104，两组原始失败均固化。
post-v3 适配器重放为 79/104，四条已见失败定向回归为 31/32；两者只证明修复生效，不替换 Blind v3。

Blind v5 使用 6 条未见 entry/report、Qwen3.8-Max 和冻结的 Packet 0.8.0 / Prompt 1.7.0，唯一结果为
26/48；系统检出全部 6 个错误，但 incorrect precision 只有 33.33%。修复确定性源码误伤后的零调用
诊断为 33/48，不替换冻结结果。全量 Critic 在 6 条上零改判且总运行消耗 101,099 Token，因此下一轮
采用 Judge-first：Critic 只处理预登记的低置信、证据冲突或高风险字段，并在运行前固化调用和 Token 上限。

### WP5：Bonus 与交付

- 错误根因分类和可执行修正建议；
- 跨记录系统性问题聚类；
- T2 抽取结果直接送入 T1 复核的闭环；
- README、1–3 页设计文档、自评报告；
- 5 分钟演示脚本、录屏素材和答辩问题清单。

当前状态：README 使用闭环、架构图、5 分钟演示脚本、自评报告和答辩问答已完成；已有可审计日志、
决策、Prompt 历史、实验结果和八字段报告；DeepSeek/Qwen 可插拔后端与同模型裸记录对照已完成。
最终效果门已完成：Final Blind v1 在模型前冻结 5 仓/3 语言，唯一运行按 8 次物理调用上限停止，完成
4/5 并保留 27/40 全集结果。下一步只做交付复核、远端合并/标签和参与者录制 3–5 分钟视频，不再
根据分数反复抽样或增加无边界功能。

## 基线矩阵

所有关键迭代都比较三组：

1. one-shot：材料一次性提交给模型；
2. 通用编码 Agent：同样输入，不使用 VulnGym 专用工具；
3. VulnGym Agent：同一底层模型，加专用工具、证据约束和 critic。

只有第 3 组在隐藏风格留出集上胜出，专用 Agent 的复杂度才算有价值。
