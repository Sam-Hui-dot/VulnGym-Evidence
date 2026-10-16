# 实验记录

本文件只记录可复核的运行结果。没有人工真值或独立标签时，不把模型输出分布称为准确率。

## Pilot v1：跨仓库强模型基线

- 日期：2026-08-20。
- 样本：5 条跨仓库 VulnGym 真实记录。
- 流水线：确定性检查 → Evidence Packet → Judge → Critic → 严格契约校验。
- Prompt：Prompt 注册机制引入前的回溯基线，无法提供规范 Prompt 哈希；因此不得与 1.0.0
  混作严格 A/B 结果。
- 完成情况：5/5 形成合法最终结果，其中 1 条使用了可审计的派生 overall 离线修复。
- 最终总体分布：`correct=1`、`incorrect=2`、`uncertain=2`。
- Judge→Critic：4/5 案例至少一个字段发生变化。
- 资源：总耗时 349.361864 秒；9 次调用有 usage，1 次调用无 usage；已记录调用合计
  `input_tokens=237082`、`output_tokens=8336`、`reasoning_output_tokens=2045`。
- 可得结论：执行链、证据引用契约、Critic 和断点结果修复可工作；Critic 对最终判断有实质影响。
- 不可得结论：没有独立人工真值，不能据此声称 5 条样本的准确率，也不能证明对隐藏数据泛化。

## 后续实验模板

- 实验 ID / 日期：
- Git commit：
- 数据集与 split 哈希：
- Provider / 模型 /参数：
- Judge Prompt ID、版本、SHA-256：
- Critic Prompt ID、版本、SHA-256：
- 假设与唯一主要变量：
- 状态、字段指标、弃权率、Judge→Critic 变化：
- 耗时与 Token：
- 失败案例分类：
- 是否接受变更及理由：

## Pilot v1：公告缓存准备

- 日期：2026-08-26。
- 数据：原 Pilot 五例。
- 公告来源：GitHub Global Security Advisory REST API；每条保留官方公告页、CVE/NVD 及上游引用。
- Commit 角色验证：五个候选 commit 均由本地 Git 证明为对应修复 commit 的直接父节点；WeKnora
  与 FastMCP 的修复 commit 同时出现在官方公告引用中。
- 产物：`configs/advisories/pilot-v1.jsonl`。
- 边界：缓存中的官方标题与 VulnGym 标题存在合理改写时，不做字符串不等即错误的判断；普通引用
  commit 与显式 vulnerable/fixed commit 仍分开保存。
- 下一步：用缓存重建 Evidence Packet，测量 `vuln_ids`、`commit` 的弃权下降，以及标题仍需语义复核的比例。

## Pilot v1：Prompt 1.0.0 + Advisory Packet 0.2.0

- 日期：2026-08-26。
- Git 基线：`2a160c7` 加本轮公告缓存与 CLI 多输入改动。
- 数据：原 Pilot 五例；公告缓存 `configs/advisories/pilot-v1.jsonl`。
- Judge：`vulngym.t1.semantic.judge` 1.0.0，SHA-256
  `8f862a1491f37dffc0ab5a1936a8cf0cbe973d2f4e76591972655c44480410d9`。
- Critic：`vulngym.t1.semantic.critic` 1.0.0，SHA-256
  `603722bd959072ce316710916fd1c9b09253fbe42eb3d637f148a846ec2035d4`。
- 完成情况：5/5 `completed`；10/10 模型调用有 usage；无 provider 或 contract error。
- 最终总体分布：`correct=1`、`uncertain=4`、`incorrect=0`。
- 字段分布：Entry `3 correct / 2 uncertain`；Critical `4/1`；L1 `5/0`；L2 `5/0`；
  Trace `1/4`。
- Judge→Critic：3/5 案例至少一个字段变化。
- 资源：378.519542 秒；`input_tokens=273580`、`cached_input_tokens=11008`、
  `output_tokens=10096`、`reasoning_output_tokens=2264`。
- 八字段提交适配：五条的 `vuln_ids` 与 `commit` 均由公告/commit 角色证据支持为 `correct`；
  五条标题均因合理改写而保持 `uncertain`。
- 与旧 Pilot 的限制：本轮同时改变 Prompt 和 Evidence Packet，属于混合变量实验；不能把 contract
  稳定性或输出分布变化单独归因于其中一项。没有人工 gold，仍不能报告准确率。
- 失败队列：见 `docs/PILOT_REVIEW_QUEUE.md`。

## Pilot v1：TraceInspector 0.1 单变量运行

- 日期：2026-08-26。
- Git commit：`a08fa60`。
- 对照：上一节 Evidence Packet 0.2.0；本轮仅将证据包替换为含 TraceInspector 的 0.3.0，
  Pilot、公告缓存、Provider 和 Prompt ID/哈希保持不变。
- Packet 体积：173105 → 214213 bytes，增长 23.7%。
- 静态边分布：
  - n8n：2 direct call、5 same-function、1 same-file、3 unresolved；
  - WeKnora：2 direct call、1 same-file、0 unresolved；
  - FastMCP：1 direct call、3 same-function、2 same-file、2 unresolved；
  - OpenClaw：1 direct call、7 same-function、1 same-file、3 unresolved；
  - Google ADK：3 direct call、1 same-function、1 unresolved。
- 模型完成情况：5/5 `completed`，10/10 调用有 usage，无 provider/contract error。
- 最终字段分布：Entry `1 correct / 4 uncertain`；Critical `4/1`；L1 `5/0`；L2 `5/0`；
  Trace `1 correct / 2 incorrect / 2 uncertain`。
- Trace 配对变化：n8n、WeKnora 从 `uncertain` 变为高置信 `incorrect`，理由明确引用未证明边；
  其余三条 Trace 不变。
- 非目标字段变化：FastMCP 与 Google ADK 的 Entry 从 `correct` 变为 `uncertain`，说明模型运行存在
  不可忽略的采样波动，不能把所有配对差异都归因于 TraceInspector。
- 资源：341.317113 秒；`input_tokens=306685`、`output_tokens=10329`、
  `reasoning_output_tokens=1828`。相较对照输入 Token 增长约 12.1%，输出增长约 2.3%，耗时下降约 9.8%。
- 结论：TraceInspector 成功让模型使用结构化缺边证据，并提升了 Trace 判断的可解释性；但在缺少人工
  gold 且 Provider 不提供固定 seed 的条件下，本轮不能证明准确率提升。工具保留，是否调整结论策略
  需等待人工复核或重复运行。

## Pilot v1：Advisory Facts 0.1 定向回归

- 日期：2026-08-26。
- 数据：仅 n8n `entry-00084` 与 WeKnora `entry-00080`；Evidence Packet 0.4.0。
- 变量：Prompt 1.0.0、Provider、候选记录和 TraceInspector 不变；公告文档新增经官方来源核对的
  传播事实、CWE、影响版本与修复版本。
- 完成情况：2/2 `completed`，无 provider 或 contract error。
- WeKnora：Critical `uncertain -> incorrect`，最终理由正确指出候选把构造客户端误写为启动子进程，
  官方事实支持真正路径为 `Connect -> Start`；Trace 维持 `incorrect`。
- n8n：Entry/Critical/分类不变；Trace 从上一轮 `incorrect` 变为 `uncertain`。最终理由仍识别到遗漏
  sandbox 属性行和三条未证明边，但认为现有 Trace 完整性口径不足以直接判错。
- 与 provisional 证据参考集比较：10 个字段中 9 个一致，唯一分歧是 n8n Trace；该数字只用于开发
  回归，不能称为对人工 Gold 的正式准确率。
- 结论：公告事实扩展解决了 WeKnora 的执行位置证据缺口；n8n 剩余问题属于 Trace 判定规则，而非
  继续补公告事实。下一轮只修改版本化 Prompt 的 Trace 完整性口径。

## Pilot v1：Trace Prompt 1.1.0 定向回归

- 日期：2026-08-26。
- 唯一设计变量：Judge/Critic 从 1.0.0 升级至 1.1.0；数据、Packet 0.4.0、Provider 与参考集不变。
- Judge SHA-256：`84357a4c65f9b75d19246682b890162dccb28e6e873af3b5f8b31610e9afde0a`。
- Critic SHA-256：`cc72915f9067e451d1d3f85cacdd219464e8afd6fb9ac9a7e6e7ca5fd0c61b4d`。
- n8n：完整 Judge→Critic；Trace 从 1.0.0 的 `uncertain` 变为 `incorrect`，理由明确以遗漏必要
  sandbox 属性行为判错依据，而把 unresolved 边单独视为只足以支持不确定。Entry 同时从
  `uncertain` 变为 `correct`，属于非目标变化。
- WeKnora：完整 Judge→Critic，最终为 `correct / incorrect / correct / correct / incorrect`，与
  provisional 参考标签一致；Critical 与 Trace 理由均明确引用缺失的存储、重载和 `Connect -> Start`。
- 完成情况：2/2 最终结果 `completed`。与 provisional 参考集比较仍为 9/10：Prompt 1.0.0 的分歧是
  n8n Trace，1.1.0 的分歧是 n8n Entry，因此没有总体指标提升证据。
- 限制：n8n 非目标字段仍有采样波动，不能报告因果提升。Prompt 1.1.0 因规则语义更清晰而保留，
  后续用重复运行评估 Entry 稳定性。

## Pilot v1：Packet 0.4.0 + Prompt 1.1.0 完整五条基线

- 日期：2026-08-26。
- 完成情况：5/5 `completed`；10/10 Judge/Critic 调用有 usage，无 provider/contract error。
- 总体：`1 correct / 4 incorrect / 0 uncertain`；2/5 案例经 Critic 改变至少一个字段。
- 字段：Entry `5 correct`；Critical `4 correct / 1 incorrect`；L1/L2 各 `5 correct`；
  Trace `1 correct / 4 incorrect`。
- 资源：332.948964 秒；`input_tokens=311302`、`output_tokens=10120`、
  `reasoning_output_tokens=2180`。
- 八字段报告：五条 ID 与 commit 均 `correct`；五条标题因合理改写均保留 `uncertain`；n8n、WeKnora、
  OpenClaw、Google ADK 总体 `incorrect`，FastMCP 因标题复核未完成而总体 `uncertain`。
- 解释边界：n8n/WeKnora 的 Trace 判错已有独立证据复核材料；OpenClaw/Google ADK 是 Prompt 1.1.0
  下新增的判错，需要逐案源码复核。没有独立人工 Gold，不把更低弃权率等同于更高准确率。

## Pilot v1：Advisory Facts v2 复核后基线

- 日期：2026-08-26。
- 变量：为 OpenClaw 与 Google ADK 增加官方公告事实，不修改 Prompt 1.1.0 或 Evidence Packet 0.4.0
  合同；只重跑这两条，并按 entry_id 让新完整结果覆盖旧结果。
- 完成情况：统一结果仍为 5/5 `completed`、10/10 调用有 usage；字段分布保持 Entry `5 correct`、
  Critical `4 correct / 1 incorrect`、L1/L2 各 `5 correct`、Trace `1 correct / 4 incorrect`。
- 资源：350.186639 秒；`input_tokens=319910`、`cached_input_tokens=38400`、
  `output_tokens=9892`、`reasoning_output_tokens=1794`。
- 逐案复核：OpenClaw 的条件性文件移动和无证据连接副作用、Google ADK 的反向数据流描述均确认是
  候选 Trace 的真实问题，保留 `incorrect`。
- provisional 参考集：4 条 20 字段中最终一致 19 个，case exact 3/4；唯一分歧是 n8n Entry
  `correct` 对参考 `uncertain`。这是 AI 辅助证据参考，不是独立人工 Gold，数值仅用于开发回归。
- 结论：冻结当前 Packet/Prompt，不为消除单例粒度分歧继续调参；下一阶段扩大未见样本并完善演示、
  架构和复现实验材料。

## Unseen v1：Packet 0.4.0 + Prompt 1.1.0

- 日期：2026-08-26。
- 数据：五条未参与 Prompt 调试的新漏洞，覆盖表达式注入、表单任意文件读、Git 参数注入、设备身份
  绕过和命令 allowlist/审批绕过；选择与公告缓存在 `configs/unseen-cases-v1.json` 和
  `configs/advisories/unseen-v1.jsonl`。
- 完成情况：5/5 `completed`；10/10 调用有 usage；无 provider 或 contract error。
- 总体：`1 correct / 4 incorrect`；字段分布为 Entry `3 correct / 1 incorrect / 1 uncertain`、Critical
  `3 correct / 2 incorrect`、L1/L2 各 `4 correct / 1 uncertain`、Trace `1 correct / 4 incorrect`。
- Judge→Critic：2/5 案例至少一个字段发生变化。
- 资源：465.706683 秒；`input_tokens=285216`、`cached_input_tokens=44544`、
  `output_tokens=10497`、`reasoning_output_tokens=1845`。
- 证据复核：五条主要判错均找到源码或补丁反证；唯一系统性缺口是 entry-00146 两级分类因 Packet
  未附 VulnGym taxonomy 而弃权。

## Unseen v1：Taxonomy Packet 0.5.0 定向回归

- 日期：2026-08-26。
- 唯一设计变量：Evidence Packet 0.4.0 → 0.5.0，新增版本化 taxonomy 证据；Prompt、Provider、候选、
  公告、源码和补丁保持不变；仅重跑 entry-00146。
- 结果：L1/L2 从 `uncertain` 变为 `correct`，分别引用 business-logic L1 与
  `BL-AGENT-CAPABILITY` L2 taxonomy；Entry `correct`、Critical `incorrect`、Trace `incorrect` 的方向不变。
- 资源：87.106338 秒；两次调用输入 `72070`、输出 `2352`、reasoning `451`，其中 Critic 使用
  `11008` cached input tokens。
- provisional 参考：合并定向结果后与 unseen 参考集 25/25 字段一致、case exact 5/5。参考集仍由
  AI 辅助证据复核形成，不是独立人工 Gold，数值只用于开发回归。
- 结论：接受 Packet 0.5.0；不修改 Prompt，不继续围绕这五条调参。

## DeepSeek V4-Flash：可插拔 Provider 烟测

- 日期：2026-08-27。
- 数据：WeKnora `entry-00080`；Evidence Packet 0.5.0、Prompt 1.1.0 与候选记录不变。
- 兼容性发现：Chat Completions JSON 模式首次出现空内容；关闭默认思考后得到合法 JSON，但缺少必需
  `correction` 并引用未知 evidence ID，两次均被 Provider/语义契约拒绝，没有进入最终结果。
- 工程修正：改用 V4-Flash Responses API 的 `json_schema` 输出，仍保留本地契约作为独立校验层。
- 完成情况：Judge 与 Critic 均 `completed` 且契约错误为零；Judge 使用 9,603 Token，Critic 使用
  10,106 Token。
- 结果：两轮均输出 `entry_point correct / critical_operation correct / L1 correct / L2 correct /
  trace incorrect`。Trace 与 Codex 基线一致，但 Critical Operation 与 Codex 最终结果及已复核证据
  不一致，Critic 未纠正该分歧。
- 结论：DeepSeek 后端已完成端到端接入，证明 Agent 的模型接口可替换；单例结果同时说明模型可替换
  不代表效果等价，后续如扩大 DeepSeek 评测必须单独报告其质量，而不能沿用 Codex 基线指标。

## Repo Holdout v1：同模型裸记录与 Evidence Agent 对照

- 日期：2026-08-28。
- 数据：10 个此前未参与 Prompt 调试的真实仓库，每仓库一个案例；跨仓库 donor 构造 10 个候选、
  12 个预先登记的错误字段。
- 模型：三组统一为 `deepseek-v4-flash`；裸基线只看候选记录，Agent 使用源码、公告、patch、Trace
  与 taxonomy 证据。
- 评分：只评估 manifest 中有意变异的目标字段；`incorrect` 为检出，`uncertain` 单列，未变异字段
  不作为人工 Gold。
- 结果：裸记录 9/12（75%），其中 2 个 uncertain、1 个错误地判为 correct；Evidence Judge 12/12；
  初版 Judge→Critic 12/12。
- 结论：在相同模型和输出合同下，证据与工具层补足了裸记录分析的三个目标字段盲点。

## Repo Holdout v1：语义证据包紧凑化与 Critic 非回归

- 日期：2026-08-28。
- 问题：完整 Packet 重复发送 Trace 源码窗口，并在 LiteLLM 案例中携带无界 patch candidate 文件列表，
  10 条 Agent 消耗 650,807 Token。
- 改动：完整 Packet 继续落盘；模型请求只保留 Entry/Critical 源码、选定 patch 摘要、Trace 结构、
  公告、taxonomy、确定性审计和证据策略。
- 体积：请求字符总量 775,220 → 344,146（-55.6%）；Token 650,807 → 319,784（-50.9%）。
- 质量：Evidence Judge 仍为 12/12。Critic 把一条已检出的反向 Trace 从 `incorrect, 0.70` 回退为
  `uncertain, 0.55`，使无仲裁最终层降至 11/12。
- 修正：加入字段级置信度 non-regression gate。Critic 分歧只有在置信度相等或更高时覆盖 Judge；
  否则保留 Judge，并记录完整仲裁理由。持久化结果重放后最终为 12/12。
- 验证：75/75 单元测试通过；10/10 在线 Agent 结果完成；摘要位于
  `artifacts/repo-holdout-v1/summary.json`。
- 限制：置信度未经过概率校准；该门只是一条可解释、防静默回退的工程策略，仍需更多自然失败验证。

## Repo Holdout v1：口径更正

- 日期：2026-08-29。
- 复核：non-regression gate 由同组 LiteLLM Critic 回退直接推动，修正后的 12/12 已包含开发反馈。
- 更正：保留此前所有原始数字和失败记录，但从此将该组称为“仓库级开发评测”，不再称最终留出成绩。
- 后续：新建 `blind-v2`，在模型运行前冻结 10 条完整八字段案例；本次更正没有调用模型，也没有改动
  Prompt 1.1.0、Packet 0.5.0 或 Workflow 0.1.0 的 Agent 行为。

## Blind v2：模型运行前证据状态

- 日期：2026-08-30。
- 数据：10 条、8 个新仓库、80 个 provisional 字段标签；选择与内容哈希已经物化。
- 仓库：8/8 解析成功，10/10 候选 commit 存在；仅通过 `git show`/`git diff` 读取，不 checkout、构建
  或执行目标项目。
- Evidence Packet：60/60 声明源码位置可读；10/10 TraceInspector 可用；10/10 公告匹配。
- Patch：7 条有可重现对照；Trivy、Ollama 和跨维护分支的 Milvus expression 案例有意留空，缺失状态
  进入模型证据而不伪造修复 SHA。
- 冻结：输入与证据哈希位于 `artifacts/blind-v2/evidence-manifest.json`；当前尚未进行任何 blind-v2
  模型调用，也未观察 Agent 预测。
- 冻结后检查：79/79 单元测试、22/22 必需文件、演示产物和开发评测产物通过；首次发现的测试夹具
  预期只写了顶层 `entry_point`，与生产逻辑的完整子字段防漂移契约不一致，修正夹具后未改动冻结数据、
  Prompt 或 Agent 行为。

## Blind v2：首次冻结运行与失败分析

- 日期：2026-08-30。
- 冻结顺序：选择、参考、证据 manifest 与 Agent 基线先由 `ee622a1` 提交；79/79 检查由 `151f56e`
  提交；之后才首次读取模型预测。
- 运行：DeepSeek V4-Flash，10/10 Judge→Critic，163,613 Token，模型调用累计 146.50 秒；无缺失预测。
- provisional 结果：59/80（73.75%）；incorrect precision/recall/F1 均为 54.55%；uncertain 11/80；
  case exact match 0/10。
- 失败结构：Title 10 条全部被提交适配层降为 uncertain；Entry/Critical/Trace 分别为 6/10、7/10、
  7/10；确定性层把多行起始行和省略号摘要误作高置信错误；11 个历史错误标签只检出 6 个。
- Critic：仅改变两个字段，均把 clean provisional 标签从 correct 改为 incorrect，未表现出跨集稳定增益。
- 决策：原结果不删除、不调参重跑；该组从现在起只用于失败驱动开发。修复后另建 Blind v3，且在首次
  模型调用前完成与 Agent 输出隔离的人工复核。

## Blind v3：模型运行前证据复核与冻结

- 日期：2026-08-30。
- 行为基线：commit `231aec9`，Packet 0.6.0，Workflow 0.1.0，Judge/Critic Prompt 1.2.0。
- 数据：13 条、10 个仓库、104 个字段；排除既有 30 个 entry 和 29 个 report ID。VulnGym 仅有的
  23 个仓库此前均已出现，因此明确不宣称仓库隔离。
- 复核：版本差异标签经固定源码、GitHub Reviewed Advisory、Patch、Trace 和 taxonomy 逐条复核；
  最终为 87 correct、14 incorrect、3 uncertain，而非把 `verify=1` 或历史改动直接当绝对 Gold。
- 资源：10/10 仓库和 13/13 candidate commit 可定位；13/13 公告、13/13 Trace 可用；10 条 Patch
  可复现，3 条因无权威原子修复而有意缺失。
- 源码：92 个声明位置中 75 个可读，17 个 invalid_location 均来自预登记历史负例的 line 0，不是
  仓库缺失。
- 冻结：精确输入与证据哈希位于 `artifacts/blind-v3/evidence-manifest.json`。截至该 manifest 生成时，
  尚未调用 Blind v3 模型或查看任何预测。

## Blind v3：唯一冻结运行与误差分解

- 日期：2026-08-30。
- 顺序：行为基线 `231aec9`、证据 manifest 和 104 个复核标签先冻结；冻结提交为 `ed8793a`；之后才
  首次生成本轮模型输出。
- 运行：DeepSeek V4-Flash，13/13 案例、26/26 次 Judge/Critic 调用完成；201,925 input Token、
  32,246 output Token，模型累计 268.596904 秒。
- 结果：70/104（67.31%）；incorrect precision/recall/F1 为 43.48% / 71.43% / 54.05%；
  uncertain 14/104；case exact 0/13；Evidence coverage 100%；无缺失预测。
- 误差：Commit 13/13 全部被适配器弃权；Trace 只有 6/13，包含 6 个 false positive 和 1 个弃权；
  taxonomy 未识别两条认证/授权矛盾；Critic 对两个 Title 一好一坏、净收益为零。
- 决策：原始输出和哈希保留在 `out/blind-v3-run` 与 `artifacts/blind-v3/result-summary.json`。不重跑并
  继续称 Blind v3；后续修复属于新的 post-v3 hardening 阶段，只做回归和新案例验证。

## Post-v3：已见失败定向回归

- 日期：2026-08-30。
- 性质：从 Blind v3 已观察失败中选 4 条，用于验证 Prompt/Packet 修正；不是独立盲测，不替换
  Blind v3 的 70/104。
- 1.3.0 中间结果：4/4 Trace 从 false positive 修回参考结果，但两条 taxonomy 仍失败，Airflow Entry
  出现一次波动，证明只加自然语言提醒不够。
- 1.4.0 最终回归：Packet 0.7.0 加入 taxonomy cross-check；4 条完整八字段 31/32 一致。Entry、
  Critical、L1、L2、Title、IDs、Trace 均 4/4；Commit 3/4。
- 保留差异：Paperclip Commit 仍为 `uncertain`，因为没有权威、可检查的 candidate-to-fix Patch；不为
  满分降低证据门。
- 资源：4/4 完成、8/8 调用有 usage；62,500 input Token、9,731 output Token，模型累计 66.358985 秒。
- 摘要：`artifacts/post-v3-targeted-v14/summary.json`。

## Prompt 1.5.0 与 DeepSeek reasoning effort 开发消融

- 日期：2026-09-03。
- 性质：仅使用已见 WeKnora `entry-00080` 的开发回归；不是 Blind v4，也不替换 Blind v3。
- 问题：Prompt 1.4.0 的 V4-Flash 与 V4-Pro 无思考运行均把候选构造器描述当作真实执行点；Pro 还把
  Entry/Critical/Trace 全部判为 `correct`，与公告给出的 `Connect -> Start` 生命周期冲突。
- 改动：Prompt 1.5.0 要求审核完整字段值，区分构造/数据交接与副作用激活；DeepSeek Provider 新增
  可审计的 reasoning effort 配置和输出元数据。
- 固定对照：Prompt 1.5.0 + Pro-none 仍输出三字段全 `correct`，成功响应使用 8,452 Token；Pro-high
  Judge 输出 `Entry correct / Critical incorrect / Trace incorrect`，成功响应使用 14,413 Token；复用
  该 Judge 只跑 Critic 后保持相同三字段结论，Critic 成功响应使用 17,279 Token。
- 稳定性：Pro-high Judge 首次响应 incomplete 后由现有传输重试完成；Flash-high 在 12,288 输出上限
  内仍以 incomplete 结束，没有把失败响应计作预测，也没有继续反复抽样。
- 结论：复杂演示暂用 Pro-high；该单例只证明配置选择和 Prompt 修复方向，泛化必须由运行前冻结的
  Blind v4 单独检验。

## Qwen3.8-Flash 可插拔 Provider 试跑

- 日期：2026-09-04。
- 接入：新增百炼 OpenAI-compatible Chat Completions provider，使用严格 JSON Schema；密钥只从
  `DASHSCOPE_API_KEY` 读取，在线调用默认关闭。
- 连通：最小结构化请求成功，77 Token；模型与端点配置有效。
- 单例：复用 Blind v4 的 `entry-00110` 证据包做独立 Qwen 开发试跑，不覆盖 DeepSeek Blind v4。
  非思考 Judge 与 Critic 均完成，但各触发一次证据引用契约修复，最终仍将参考为全正确的案例判为
  `incorrect`。Judge 两次可观测用量合计 21,873 Token，Critic 两次合计 22,127 Token。
- 决策：Qwen provider 保留为可插拔备选；默认关闭思考以控制延迟。该单例不支持优于现有后端或
  泛化提升的结论，未扩展到整组评测。

### Prompt 1.6.0 开发复核

- 首轮请求新增合法 `evidence_id` 白名单；模型生成的空 `case_id` 漂移由 harness 确定性修复，均不
  改变语义字段结论。
- WeKnora 已见开发案例的非思考 Judge 与 Critic 分别在 17.9 秒 / 8,109 Token 和 11.5 秒 /
  8,674 Token 完成，结构首次通过且无契约重试；相比 1.5.0 的四次调用，闭环成本明显下降。
- 语义结果仍把构造器误作进程启动点，Critical 与 Trace 未检出；单次思考模式在 120 秒边界内未返回。
- 决策：Prompt 1.6.0 的协议改动保留；Qwen3.8-Flash 不直接作为下一轮冻结评测的主模型，除非后续
  独立开发对照证明语义门槛改善。

### Packet 0.8.0 / Prompt 1.7.0 生命周期开发回归

- Qwen3.8-Max 非思考模式在旧 Packet 上仍把 `NewStdioMCPClientWithOptions` 判作直接启动进程；
  Judge→Critic 未纠正。Max 思考模式在 120 秒实验上限内未返回，随即人工终止且未自动重试。
- Packet 0.8.0 为 Critical 源码采用前短后长窗口，并新增只读 `lifecycle_analysis`：记录构造型调用及
  同文件后续 `Connect/Start/Run/Execute` 等激活动作，只提供线索，不直接写字段真值。
- Prompt 1.7.0 要求 Judge/Critic 分别归因构造与激活。WeKnora 已见开发案例中，Max Judge→Critic
  最终把 Critical 从旧配置的错误 `correct` 修正为参考一致的 `incorrect`；Trace 从 `correct` 降为
  `uncertain`，仍未达到参考 `incorrect`。
- 边界：这仍是已见案例上的失败驱动开发，不是 Blind v5，也不证明泛化提升。下一次独立评测需使用
  开发过程中未查看答案的新记录，并在运行前冻结 Packet、Prompt、模型和参考口径。

## Blind v5：Qwen 冻结运行与成本结论

- 日期：2026-09-04。
- 冻结边界：6 条未见 entry/report、6 个仓库、48 个字段；42 correct、6 incorrect。选择、逐字段复核、
  Evidence Packet、Prompt 1.7.0、Qwen3.8-Max 非思考配置和行为提交先于模型运行冻结。该参考由固定源码和
  VulnGym v0.1.4 人工复核记录辅助建立，不是官方隐藏集，也不是独立安全专家 Gold。
- 唯一运行：6/6 案例、12/12 Judge/Critic 调用完成，无缺失预测。冻结结果为 26/48（54.17%）；
  incorrect precision/recall/F1 为 33.33% / 100% / 50%；abstention 10/48（20.83%）；证据覆盖 100%。
- 成本：89,279 input Token、11,820 output Token，共 101,099 Token；Provider 阶段累计 197.30 秒。
  Critic 没有改变任何案例或字段，因此本轮全量双阶段的边际收益为零。
- 失败分解：7 个模型语义上正确的字段被确定性源码层误伤，集中于数据记录追加的行尾解释和把多行源码
  压缩成单行摘要；公告 API 对新近 2026 GHSA 返回 404，Title/IDs 因证据缺失而诚实弃权；另有 Trace、
  taxonomy 和 Entry 的真实语义错误。
- 结果固化：`artifacts/blind-v5/result-summary.json` 保存指标、用量和原始输出哈希。原始运行不覆盖、
  不调参重跑，也不作为 Top 3 或官方准确率证明。

## Post-v5：确定性源码策略诊断

- 性质：只重建本地源码证据并重放 Blind v5 已存储的 Qwen 判断，模型调用为 0；这是已见失败上的
  post-processing 诊断，不是新的 Blind v5 成绩。
- 修复：字符串外的解释性行尾注释不再造成 exact-source 否决；有真实起始行锚点的单行压缩摘要交给
  Semantic Judge，而不是被确定性层直接判错；Qwen Chat Completions 用量字段归一化为统一报告格式。
- 诊断结果：33/48（68.75%）；incorrect precision/recall/F1 为 60% / 100% / 75%；abstention 11/48。
  这证明本地误伤已被消除，但不证明新数据泛化。
- 成本决策：下一轮新盲测先只跑 Judge；Critic 仅在预先登记的低置信、证据冲突或高风险字段上触发，
  并设置调用数和 Token 上限。不会再默认把同一完整证据包无条件发送两遍。

## Blind v6：公告完备、选择性 Critic 的冻结验证

- 日期：2026-09-05。
- 冻结边界：8 条未见 entry/report、2 个仓库、64 个字段；54 correct、10 incorrect。参考、公告缓存、
  Evidence Packet、Qwen 配置、选择性 Critic 策略和 12 次物理请求上限均在模型运行前提交。
- 唯一运行：8/8 完成，62/64（96.875%）；10/10 预登记错误全部检出，incorrect precision / recall /
  F1 为 90.91% / 100% / 95.24%，弃权 1/64，case exact 6/8。
- 成本：8 次 Judge、2 次 Critic，共 10 次物理请求；106,879 input Token、11,480 output Token，
  Provider 阶段 199.51 秒。Critic 无改判，但相较全量双阶段少 6 次调用。
- 剩余差异：1 个误报和 1 个弃权均为 L2 taxonomy 的认证/授权/来源完整性边界；源码位置、Trace、
  IDs、Commit 与 Title 全部匹配。本轮不根据答案改标签、调参或重跑。
- 边界：只有 2 个仓库，参考为 AI 辅助复核而非独立专家 Gold；结果支持修复泛化，但不代表官方隐藏集。

## Post-v6：Commit provenance 零模型加固重放

- 日期：2026-09-08。
- 触发：对冻结产物做对抗复核时发现，唯一直接子提交可越过 `0.75` 门槛，让 README-only 或普通后续
  修改被误作修复证据。
- 实现：Packet 升至 0.9.0；公告 Commit 分 fixed/supporting/vulnerable/reference 角色；确定性验证
  同时要求显式修复角色、Git 祖先关系和源码差异，并记录 verified/supported/weak。
- 验证：复用冻结 Blind v6 语义输出与参考标签，模型调用 0；结果 59/64，incorrect precision/recall
  为 90.91%/100%，弃权 4/64。三项 Commit 从错误的 `correct` 改为 `uncertain`。
- 边界：这是已见数据的开发重放，不是新盲测；冻结 62/64 不修改。新旧 Evidence、Submission、
  Evaluation 均由交付脚本校验哈希并动态复算。

## Final smoke v1：当前版本跨仓库验收

- 日期：2026-09-08。
- 冻结边界：Open WebUI、Paperclip、Flowise 三条未用于前述开发的真实记录；输入、公告、Packet 0.9.0、
  参考口径和最多 6 次调用均在模型运行前提交。参考由公告、候选源码与 Patch 辅助复核，不是官方隐藏集
  或独立专家 Gold。
- 唯一运行：Qwen3.8-Flash 非思考模式完成 3/3，实际 5 次请求；46,130 input Token、5,398 output
  Token、71.43 秒。结果 21/24（87.5%），两条正例 16/16 全对；Paperclip 关键操作判错正确，入口误判，
  Commit/Trace 弃权。
- 失败分析：Paperclip 的候选源码已经调用 `getAccessibleAgent`，该 helper 内部明确执行
  `assertCompanyAccess`；Packet 只提供调用点而未展开 helper 定义，模型因此把它当作未知行为。
- 后续实现：Packet 0.10.0 增加有界同文件 helper 定义解析，仅接受直接调用且唯一匹配的定义，不执行目标
  代码、不声称完整调用图。冻结 v1 结果不覆盖；只允许对 Paperclip 做一次预先解释的定向回归。

## Helper regression v1：Paperclip 单条定向回归

- 冻结边界：Packet 0.10.0 行为提交、单条 Evidence、参考口径、Qwen3.8-Flash 配置与最多 2 次请求均先
  于运行提交；性质为已见失败上的开发回归，不是独立盲测。
- 运行：Judge 一次完成，因高置信拒绝未触发 Critic；8,865 input Token、1,258 output Token、22.19 秒。
- 变化：Trace 从 Final smoke v1 的 `uncertain` 变为参考一致的 `incorrect`；Critical Operation 继续正确
  判错。Commit 仍因 provenance 不足弃权；Entry Point 仍采用“路由本身可作为入口”的宽松解释；Title
  因候选 Commit 已含鉴权而从 `correct` 变为 `uncertain`。
- 结论：helper 证据修复了一个真实信息缺口，但没有让开放字段全部符合严格参考。保留混合结果，不围绕
  该案例继续改 Prompt 或重跑刷分。
## 2026-09-10：Final Blind v1 唯一多仓运行

- 冻结范围：5 个此前未进入冻结选择的 entry/report，来自 open-webui、Flowise、langflow、n8n、
  WeKnora，覆盖 Python、TypeScript 与 Go；Packet 0.11.0、Qwen3.8-Flash、`review-risk` Critic。
- 参考口径：模型调用前用官方公告、候选源码、release tag 与可获取 Patch 逐条复核；不是官方隐藏集
  或独立专家 Gold，参考不进入模型请求。
- 预算：最多 5 条、8 次物理 API 尝试；契约修复同样计数；不按结果重试。
- 结果：上限内完成 4/5，物理请求 8 次，其中 6 次返回 usage；62,185 输入 Token、7,297 输出 Token、
  Provider 阶段 134.05 秒。已完成字段 27/32（84.38%），缺失 8 个字段计入冻结全集后为 27/40
  （67.50%）；2 个高置信误报、3 个 uncertain，第五条没有预测。
- 解释：这组补充了五仓运行和调用预算证据，但正例为主且参考仍有开放语义，不替代 Blind v6 的
  10/10 错误检出证据，也不支持官方泛化准确率声明。
