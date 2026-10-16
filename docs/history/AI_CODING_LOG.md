# AI Coding 使用记录

本项目允许并主动使用 AI Coding 工具，但所有架构取舍、代码接纳和最终提交均由参与者负责。
本文件记录 AI 参与了什么、产生了哪些可审计改动，以及人工保留了哪些决策。

安全边界：不记录或提交 API Key、访问令牌、私人完整对话、模型隐藏推理过程及与项目无关的信息。

## 2026-08-19 至 2026-08-20：T1 技术预研

记录类型：依据当前源码、输出产物和会话记录回溯整理，不是逐字 Prompt 转录。

- 工具：OpenAI Codex。
- 目标：验证“证据优先的 VulnGym 数据自动化审核 Agent”是否可行。
- AI 辅助工作：
  - 搭建 Python CLI、JSONL 读写和批处理框架；
  - 实现 VulnGym Schema、Git 对象、文件、行号和代码片段检查；
  - 实现按仓库隔离的数据变异、历史 before→after 负样本挖掘和评测器；
  - 实现仓库索引、修复 patch 查找和 Evidence Packet；
  - 实现严格的字段级 Judge→Critic 契约；
  - 接入 Codex CLI provider、Token/耗时 telemetry、断点续跑和 Critic-only；
  - 对 5 个跨仓库真实案例建立 Pilot 并生成汇总报告。
- 人工决策：
  - 选择 T1 为主线，不尝试复刻通用编码 Agent；
  - 不执行被审计仓库中的陌生代码；
  - 缺少证据时输出 `uncertain`，不强行猜测；
  - 模型只能引用 Evidence Packet 中存在的证据；
  - 仅允许离线修复可确定推导的 overall verdict，字段语义不得静默改写；
  - 训练、开发和留出数据按仓库或报告隔离，避免 donor 泄漏。
- 验证记录：当时最终回归共 29 项单元测试通过；Pilot 5/5 形成合法最终结果。

## 2026-08-25：正式题目对齐与工程留痕

- 工具：OpenAI Codex。
- 目标：依据新版《VulnGym - 犀牛鸟实战考题》核对 T1 正式要求。
- AI 辅助工作：
  - 完整读取并逐页检查 10 页 PDF；
  - 对照现有原型梳理输出契约、多源证据、鲁棒性和交付物差距；
  - 检查仓库中可能存在的硬编码密钥；
  - 建立本 AI Coding 日志和架构决策记录；
  - 准备初始化独立 Git 历史。
- 人工决策：
  - 继续选择 T1；
  - 保留内部严格契约，后续增加面向官方示例的输出适配层；
  - 不把 PDF 中标注为“仅作示例”的阈值当作最终评分规则硬编码；
  - 开发期可以使用在线 LLM，密钥只通过环境变量或本机登录态注入。

## 2026-08-25：正式输出适配层

- 工具：OpenAI Codex。
- 目标：在不破坏内部严格 Judge/Critic 契约的前提下，对齐新版 PDF 的逐字段报告示例。
- AI 辅助工作：
  - 新增 8 个 T1 核心字段的提交报告结构和验证器；
  - 新增 `build-submission` CLI，将 Evidence Packet 与语义结果按 `entry_id` 合并；
  - 新增确定性源码失败优先于模型结论的合并规则；
  - 为尚未接入公告证据的标题、漏洞编号和 commit 保留显式 `uncertain`；
  - 添加对应单元测试和 README 使用示例。
- 人工决策：内部 evidence reference、自检和 correction 结构继续保留；外部适配层不制造公告证据，
  也不把 commit 对象存在等同于“它就是公告对应的漏洞 commit”。
- 验证：本次按工作区规则仅完成静态实现和测试用例编写，尚未运行测试。

## 2026-08-25：宣讲会规则勘误落地

- 工具：OpenAI Codex。
- 目标：把项目负责人在宣讲会中明确否定或放宽的规则同步到 T1 实现，避免围绕旧 PDF 示例过拟合。
- AI 辅助工作：
  - 删除 CLI、审核引擎和源码检查器中的固定行号容差参数；
  - 将源码定位结果细分为 `exact`、`drifted`、`ambiguous` 和 `missing`，保留候选位置作为证据；
  - 重写 Judge/Critic 语义说明，使 Entry Point 面向可辩护的攻击输入入口，使 Critical Operation
    覆盖危险操作、关键安全决策、缺失检查与绕过点；
  - 明确允许多个合理候选，并要求 Agent 给出证据和取舍；
  - 编写行号漂移和多候选位置的回归测试。
- 人工决策：固定 `±5` 行不是可信的正确性规则；代码片段在别处出现只能证明声明位置需要复核，
  不能自动把字段判为正确。Critical Operation 也不限定为“应该 return 但没有 return”的判断点。
- 验证：执行了 Python 静态语法解析和 Git 差异检查；依照本轮授权范围未运行测试。
- 已知限制：当前源码搜索仍是规范化后的精确片段匹配，尚未实现 AST/符号级重定位；多候选的语义排序交给 Judge/Critic。

## 2026-08-25：Prompt 版本化与实验台账

- 工具：OpenAI Codex。
- 目标：把 Prompt 设计和实验过程变成可复核的工程资产，对齐宣讲会对过程记录与自建评估的要求。
- AI 辅助工作：
  - 新增 Judge/Critic Prompt 注册表，提供稳定 ID、语义版本和规范内容 SHA-256；
  - 在每次请求及持久化结果中记录实际 Prompt 元数据；
  - 新增 Prompt 演进记录、Pilot v1 回溯实验记录和后续实验模板；
  - 编写请求与执行结果的 Prompt 元数据测试，并更新 README。
- 人工决策：Pilot v1 没有独立人工真值，也发生在 Prompt 注册机制之前，因此只作为执行与成本基线，
  不宣称准确率，也不与 Judge/Critic 1.0.0 混作严格 A/B 实验。
- 验证：执行了 Python 静态语法解析和 Git 差异检查；依照本轮授权范围未运行测试。
- 下一步：建立小型人工 gold/dev 集和失败类型表，再以单变量方式比较 Prompt 或工具策略。

## 2026-08-25：语义自评闭环骨架

- 工具：OpenAI Codex。
- 目标：把“Agent 效果好坏”从输出观感升级为可复核的字段级评测。
- AI 辅助工作：
  - 新增 `evaluate-semantic` 与独立评测模块；
  - 同时计算 Judge 与最终 Critic 的字段混淆矩阵、总体/观测准确率、弃权率、incorrect
    precision/recall、完整案例严格匹配和 Critic accuracy delta；
  - 单列置信度不低于 0.8 的错误，便于优先处理危险的虚假确定性；
  - 新增 gold JSONL 示例、人工复核指南和对应测试。
- 人工决策：不把 Pilot 模型输出或 `verify=1` 直接复制为 gold；五条 Pilot 的正式标签留待独立证据复核。
- 验证：执行了 Python 静态语法解析和 Git 差异检查；依照本轮授权范围未运行测试。
- 下一步：对 Pilot 五例建立第一版双人可复核 gold，并把错误归入证据缺失、定位、多解、分类和 Trace 类型。

## 2026-08-25：离线 AdvisoryReader

- 工具：OpenAI Codex。
- 目标：为标题、漏洞标识和 commit 身份提供公告侧证据，同时维持低幻觉边界。
- AI 辅助工作：
  - 新增本地 JSON/JSONL/目录公告缓存读取器，兼容常见 GHSA/OSV 与规范化字段；
  - 通过 CVE/GHSA 或来源 URL 做精确匹配，生成可被 Judge 引用的稳定 evidence ID；
  - 提取标题、标识、引用链接及 commit 引用，并区分普通引用、漏洞 commit 和修复 commit；
  - 将公告分析接入 Evidence Packet 0.2.0 和提交报告适配层；
  - 新增公告解析、Evidence Packet 与提交字段测试。
- 人工决策：不自动联网，不用仓库名弱匹配；不把普通公告 commit URL 推断成漏洞 commit。
- 验证：执行了 Python 静态语法解析和 Git 差异检查；依照本轮授权范围未运行测试。
- 下一步：准备可公开复现的 Pilot 公告缓存，并对标题语义相似、别名完整性和 commit 角色做人工复核。

## 2026-08-26：公告证据实测与 Prompt 1.0.0 基线

- 工具：OpenAI Codex、GitHub Global Security Advisory REST API、本地 Git、Codex CLI provider。
- 目标：验证新公告层与版本化 Prompt 在五条真实 Pilot 上的端到端表现。
- AI 辅助工作：
  - 读取五条官方 GHSA 数据并保存必要字段、引用与获取日期；
  - 用本地 Git 证明五个候选 commit 均为对应修复 commit 的直接父节点；
  - 新增可复现 Pilot 公告缓存，并让 `build-submission` 支持多批语义输入；
  - 重建 Evidence Packet 0.2.0，运行五条 Judge→Critic，生成语义汇总与八字段报告；
  - 提取逐案弃权原因并形成失败队列。
- 验证：完整单元测试 39/39 通过；五条语义运行 5/5 `completed`；提交报告 5/5 生成成功。
- 人工决策：官方公告字段与本地 Git 关系分开记录；标题改写不做字符串不等即错误；本轮属于
  Prompt 与证据同时变化的混合变量实验，不声称准确率或单变量提升。
- 下一步：实现 TraceInspector 的符号/调用边扩展，并由人工复核 Pilot gold。

## 2026-08-26：TraceInspector 0.1

- 工具：OpenAI Codex。
- 目标：针对 Pilot 中 4/5 Trace 弃权，补充可审计的函数与相邻边证据。
- AI 辅助工作：
  - 新增 Python、Go、TypeScript/JavaScript 的轻量函数/代码块定位；
  - 对相邻 Trace 节点输出 `direct_symbol_call`、`same_function_order`、`same_function_reverse`、
    `same_file_order` 或 `unresolved`；
  - 仅为 unresolved/反向边附加最多 120 行的扩展上下文，并接入 Evidence Packet 0.3.0；
  - 新增跨文件调用与反向顺序测试。
- 人工决策：工具结论只描述静态可证明关系；同文件前后顺序不能当成调用链证明；不执行上游代码。
- 验证：专项测试 5/5 通过；真实 Pilot 包体较 0.2.0 增长 23.7%，WeKnora 未证明边从 2 条降为 0。
- 下一步：完整回归后，在同一 Prompt、Provider 和五条 Pilot 上做单变量 A/B。

## 2026-08-26：TraceInspector Pilot A/B

- 工具：OpenAI Codex、Codex CLI provider。
- 目标：固定 Prompt、Provider、公告缓存和 Pilot，仅替换 Evidence Packet，观察 TraceInspector 影响。
- 结果：5/5 完成；Trace 从 `1 correct / 4 uncertain` 变为 `1 correct / 2 incorrect / 2 uncertain`；
  n8n 与 WeKnora 的新结论直接引用 TraceInspector 未证明边。
- 成本：输入 Token 增长约 12.1%；输出增长约 2.3%；本轮耗时反而下降约 9.8%。
- 人工决策：保留 TraceInspector，因为它提供了此前缺失的结构化可审计证据；不宣称准确率提升，
  因为两个非目标 Entry 字段也变化，且当前没有人工 gold 或固定 seed。
- 验证：完整单元测试 41/41 通过；两轮各 5 条语义结果均有完整 Prompt/usage 元数据。
- 下一步：人工裁决 n8n/WeKnora 的 Trace 标签，并优先接入可固定参数的模型 API或重复运行策略。

## 2026-08-26：争议样本证据复核与 Advisory Facts 0.1

- 工具：OpenAI Codex、GitHub 官方公告、本地只读 Git、Codex CLI provider。
- 目标：查清 n8n/WeKnora 的 Trace 争议，并验证公告正文事实缺失是否限制语义判断。
- AI 辅助工作：
  - 静态对照两个漏洞版本、直接子修复提交和官方公告，不执行目标仓库代码；
  - 建立明确标注为“非独立人工 Gold”的两条证据复核参考集；
  - 扩展 AdvisoryReader，使长度受限的事实、CWE、影响版本和修复版本进入 Evidence Packet 0.4.0；
  - 固定 Prompt/Provider，仅针对两条争议样本重新运行 Judge→Critic。
- 结果：WeKnora Critical 从 `uncertain` 变为 `incorrect`，理由准确区分客户端构造与
  `Connect -> Start` 执行；WeKnora Trace 保持 `incorrect`；n8n Trace 本轮为 `uncertain`。
- 人工决策：不要求项目参与者冒充安全专家；参考集保留为 provisional，独立专家确认前不报告为人工
  Gold 或正式准确率。n8n 的 Trace 分歧进入 Prompt 规则单变量迭代。
- 验证：公告专项测试 8/8、完整单元测试 41/41 通过；两条语义运行均 `completed`。
- 下一步：版本化补充 Trace 完整性规则，只针对相同两条样本回归。

## 2026-08-26：Trace Prompt 1.1.0 定向回归

- 工具：OpenAI Codex、Codex CLI provider。
- 目标：只修改 Trace 完整性规则，区分 evidence missing 与 evidence of a missing required stage。
- AI 辅助工作：版本化 Judge/Critic Prompt，更新元数据测试与 Prompt 演进记录；在相同 Packet 0.4.0
  和两条争议样本上回归。
- 结果：2/2 Judge→Critic 完成；n8n Trace `uncertain -> incorrect`；WeKnora 最终五字段均符合
  provisional 参考结论。n8n Entry 同时发生非目标波动。
- 人工决策：接受规则文本，因为它修正了“已证明遗漏”仍被当作“缺证据”的概念错误；不把本轮称为
  准确率提升，因为两版与参考集都是 9/10，只是分歧字段从 n8n Trace 转移为 n8n Entry。
- 验证：完整单元测试 41/41 通过；两条最终结果均 `completed`；Prompt 版本与 SHA-256 已记录。

## 2026-08-26：Packet 0.4.0 + Prompt 1.1.0 五条基线

- 工具：OpenAI Codex、Codex CLI provider。
- 目标：在定向复核后补齐全部五条 Pilot，形成当前可复现基线和八字段提交报告。
- 结果：5/5 `completed`；10/10 调用有 usage；总体 `1 correct / 4 incorrect`；Entry 全部 correct，
  Critical `4 correct / 1 incorrect`，两级分类全部 correct，Trace `1 correct / 4 incorrect`。
- 资源：332.948964 秒；`input_tokens=311302`、`output_tokens=10120`、
  `reasoning_output_tokens=2180`。
- 人工决策：不把 Trace 判错增多直接解释为能力提升；n8n/WeKnora 已有证据复核，新增判错的
  OpenClaw/Google ADK 必须进入下一轮失败分析。
- 验证：统一语义报告与五条八字段提交报告生成成功；完整单元测试维持 41/41 通过。

## 2026-08-26：OpenClaw/Google ADK 复核与当前基线冻结

- 工具：OpenAI Codex、GitHub 官方公告、本地只读 Git、Codex CLI provider。
- 目标：确认 Prompt 1.1.0 新增的两条 Trace 判错是否为真实缺陷，而非规则过严。
- 结果：OpenClaw Trace 对连接副作用作无证据扩张，并遗漏目录存在检查；Google ADK Trace 把
  `_perform_load -> _load_from_module_or_package` 的输入数据流写成返回值流入。两条 `incorrect` 均有
  源码反证支持。
- 工程改动：补全两条公告事实和 provisional 复核标签；`evaluate-semantic --semantic` 支持重复参数，
  可直接评估断点和分批结果。
- 当前复核覆盖：4 条、20 个字段；最新最终结果与 provisional 参考集一致 19 个，唯一分歧为 n8n
  Entry 的多锚点粒度。该数值不作为正式人工 Gold 准确率。
- 人工决策：冻结 Packet 0.4.0 和 Prompt 1.1.0；下一轮以新增样本扩展和提交材料为主，不继续针对当前
  四条调参。
- 验证：完整单元测试 41/41 通过；两条更新证据后的 Judge→Critic 均完成；统一五条报告生成成功。

## 2026-08-26：未见样本扩展与 taxonomy 证据

- 工具：OpenAI Codex、GitHub Global Security Advisory REST API、本地只读 Git、Codex CLI provider。
- 目标：在不修改 Prompt 1.1.0 的前提下验证新增漏洞泛化，并由新失败驱动下一项证据工具。
- AI 辅助工作：选择五个不同漏洞、核对官方公告和直接子修复、生成 Packet 0.4.0、完成 Judge→Critic，
  并逐案对照源码形成 provisional 参考；发现分类弃权后新增 VulnGym taxonomy 证据并升级 Packet 0.5.0。
- 结果：原运行 5/5 完成；taxonomy 单变量复跑把 entry-00146 的 L1/L2 从 `uncertain` 修正为
  `correct`，其余最终字段方向保持不变。
- 人工决策：未见样本在运行前固定，不因模型结果换题；taxonomy 只能证明标签定义，字段正确性仍须
  结合公告和代码；参考标签不冒充独立人工 Gold。
- 验证：完整单元测试 42/42 通过；五条原运行和一条定向回归均完成，10+2 次调用均有 usage。

## 2026-08-27：面向参与者的两分钟离线演示

- 工具：OpenAI Codex、本地 Python。
- 目标：在不扩张核心能力的前提下，把现有 WeKnora 结果整理成参与者可亲手运行、可用两分钟讲清楚的
  阶段原型。
- AI 辅助工作：新增固定演示摘要、无网络回放命令和人话版说明；明确区分已完成结果回放与新的在线
  Agent 调用。
- 人工决策：暂不向导师发送长篇技术结项汇报；先确保参与者能理解案例、证据、八字段结论和系统边界，
  再在群内只询问会影响后续设计的方向性问题。
- 验证：离线命令成功展示 WeKnora 的关键操作与 Trace 缺陷；完整单元测试 44/44 通过。
- 已知限制：演示摘要不是独立人工 Gold，也不代替完整在线 Judge→Critic 流程。

## 2026-08-27：OpenRouter Provider 与 OX Alpha 准备

- 工具：OpenAI Codex、OpenRouter 官方模型目录与接口文档。
- 目标：解除语义 Agent 对单一 Codex 登录额度的运行时绑定，并准备 OX Alpha 小样本验证。
- AI 辅助工作：新增 OpenAI 兼容的 OpenRouter Chat Completions 适配器、严格 JSON Schema 输出、
  模型/Token/供应商元数据、错误脱敏、环境变量配置模板和离线测试。
- 人工决策：不使用或保存在聊天中暴露的 Key；真实 Key 只由参与者在本地 `.env` 设置。匿名预览模型
  仅发送公开漏洞材料，换模型后先跑一条契约烟测，再决定是否扩大实验。
- 已知限制：适配器单元测试不等于真实网络调用成功；实际服务可用性、结构化输出兼容性和结果质量需
  使用轮换后的本地 Key 验证。
- 首次真实烟测：OpenRouter 已接受认证，但返回 OX Alpha 测试期结束的 404，并明确指向正式模型
  `z-ai/glm-5.3-flash`；随后将默认 ID 切换为正式模型，并补充 HTTP 错误中用户标识的脱敏。

### DeepSeek 可插拔后端

- 目的：验证 Agent 不依赖 Codex 账户运行，并为评审提供可自行配置的官方 API 后端。
- 实现：最终采用 DeepSeek V4-Flash Responses API 的 `json_schema` 输出，结果继续由本地语义契约
  校验。
- 安全边界：Key 仅进入 Git 忽略的本地 `.env`；默认关闭在线调用，需显式设置
  `VULNGYM_DEEPSEEK_ENABLED=true`；错误输出移除常见私有标识。
- 验证策略：先用模拟 HTTP 响应验证请求、解析和安全开关，再由用户显式授权进行单条 Judge 在线烟测。
- 首轮兼容性验证发现 Chat Completions JSON 模式只保证合法 JSON，不保证遵循完整 Schema；本地契约
  正确拦截了缺失 `correction` 和未知 evidence ref。随后改用 V4-Flash Responses API 的
  `json_schema` 输出，保留本地契约作为第二道边界。
- Responses API 单条 WeKnora Judge 与 Critic 均通过契约。两轮都认定 Trace 错误，但都把
  Critical Operation 判为正确，与 Codex 基线及已复核证据存在一处实质分歧；因此只证明后端可替换，
  不声称不同模型效果等价。

## 2026-08-28：仓库级留出评测与成本优化

- 工具：OpenAI Codex、本地只读 Git、DeepSeek V4-Flash API。
- 目标：验证专用 Agent 是否真正优于同模型直接阅读记录，并降低上下文成本。
- AI 辅助工作：
  - 从 10 个未参与 Prompt 调试的仓库固定案例、修复 commit 和公告缓存；
  - 构建跨仓库 donor 定向变异、独立 manifest、裸记录基线和三阶段对照评测器；
  - 增加端到端 `validate` 工作流、条件资源规划、反思输出和原子 checkpoint；
  - 发现并删除模型请求中的重复 Trace 源码和无界 patch candidate 文件列表；
  - 识别 Critic 的一次低置信回退，加入透明字段仲裁并支持持久化结果重放。
- 人工决策：同模型公平对照；只给预先声明的变异字段计分；未变异字段不冒充 Gold；不因单次结果替换
  已固定仓库；完整 Packet 继续保留审计，只有模型视图紧凑化；Critic 不被当成天然正确。
- 验证：75/75 单元测试通过；DeepSeek 裸基线 10/10、Agent 10/10 完成；裸模型检出 9/12，Judge 与
  仲裁后最终均为 12/12；Agent Token 650,807 → 319,784。
- 已知限制：定向变异不等于自然错误分布；模型置信度未校准；正式隐藏集效果仍由主办方评测决定。

## 2026-08-29：评测口径复核与 Blind v2 冻结

- 工具：OpenAI Codex、本地 VulnGym Git 历史与公开版本元数据。
- 目标：重新审计 Top 3 论据，避免把参与过规则调整的数据继续包装成最终留出成绩。
- AI 辅助工作：识别旧评测的开发反馈污染；枚举并排除 20 个开发 entry 和 15 个开发仓库；从 8 个新
  仓库选择 5 条真实历史修订与 5 条人审干净记录；新增可复现数据物化器、八字段评测器、冻结协议和
  人工复核队列。
- 人工决策：接受对旧成绩的降级，不删除原结果；Blind v2 运行后禁止针对同组调参；资源故障另做
  robustness matrix，不混入准确率；独立复核前统一称 provisional reference。
- 验证状态：本节记录的是协议与实现变更，尚未调用 Blind v2 模型；冻结提交后完整交付检查通过，
  包含 79/79 单元测试、22/22 必需文件、演示产物和开发评测产物。

## 2026-08-30：Blind v2 证据物化

- 工具：OpenAI Codex、GitHub Advisory Database、GitHub Advisory Database 公共 Git 仓库、本地只读
  Git。
- 目标：在首轮模型调用前，为冻结的 10 条案例建立可重建、可哈希、不会执行目标仓库代码的证据输入。
- AI 辅助工作：缓存 8 个新上游仓库和 10 个指定 commit；整理 10 条官方公告；为 7 条案例解析可复现
  的修复对照；生成仓库索引、60 个源码窗口、10 份 Trace 分析和 Evidence Packet。
- 人工决策：Trivy 供应链事件和 Ollama 无权威修复 commit 的案例不猜 Patch；Milvus `entry-00119`
  虽有官方修复，但跨维护分支 diff 噪声过大，因此只保留公告证据，不把巨型 diff 送给模型。
- 验证状态：8/8 仓库可定位、60/60 声明位置可读、10/10 公告匹配、10/10 Trace 可用；本节未调用
  模型，随后冻结提交前的完整交付检查为 79/79 单元测试通过。

## 2026-08-30：Blind v2 首次冻结运行

- 工具：OpenAI Codex、DeepSeek V4-Flash API、本地八字段评测器。
- 目标：在不查看输出调参的前提下，对已提交冻结的 Blind v2 执行唯一一次 Judge→Critic 评测。
- 验证：10/10 案例、80/80 预测完成；accuracy 59/80，incorrect precision/recall/F1 均为 54.55%，
  uncertain 11/80，case exact match 0/10；总 Token 163,613。
- AI 辅助分析：定位到标题适配器系统性 abstain、多行源码起始行误判、省略号摘要字面匹配以及 Critic
  两次跨集回退。
- 人工决策：不隐藏失败，不在 Blind v2 上修改后重跑刷分；将本组降为后续开发诊断集，改进后的泛化
  主张必须来自独立冻结且先完成复核的 Blind v3。

## 2026-08-30：Blind v2 失败驱动修复

- 工具：OpenAI Codex、本地只读 Git、单元测试。
- 目标：修复 Blind v2 暴露的确定性工具和提交适配缺陷，不在同一组上重跑模型刷分。
- AI 辅助工作：将整数行号解释为多行代码起点；将独立 `...` 占位行和“首行锚点正确但正文摘要化”
  降为语义待审；把 Title 纳入第六个 Judge/Critic 字段并升级 Prompt 1.2.0；公告明确有编号而候选为空
  时输出缺失错误；Evidence Packet 升级到 0.6.0，与 Blind v2 的 0.5.0 原始运行明确隔离。
- 人工决策：只修复能由失败证据明确证明的合同错误；Entry/Critical/Trace 的开放性选点分歧不直接
  硬编码数据集答案，留给 Blind v3 验证。
- 验证：新增 5 项回归测试，完整测试 84/84 通过；没有再次调用 Blind v2 模型。

## 2026-08-30：Blind v3 唯一冻结运行与结果保留

- 工具：OpenAI Codex、DeepSeek V4-Flash API、本地八字段评测器。
- 目标：在 13 条新案例完成逐条证据复核、manifest 冻结和哈希校验后，执行一次不可覆盖的
  Judge→Critic 评测。
- 结果：13/13 案例完成，八字段 70/104（67.31%）；incorrect precision 43.48%、recall 71.43%、
  F1 54.05%，14/104 abstention，证据引用覆盖率 100%。Critic 改动两个 Title，一正一负，净收益为零。
- AI 辅助分析：确认 Commit 13/13 全部弃权来自提交适配器未利用 patch provenance；Trace 仅 6/13，
  主要原因是把“非穷举但可辩护”的链路过度判错；taxonomy 对 CWE-306 等鉴权/授权边界约束不足。
- 人工决策：保留 70/104 原始结果及输入、输出和摘要哈希，不覆盖、不重跑、不把后续改进倒灌为盲测成绩；
  该结果用于证明系统边界，而不是包装成官方隐藏集得分。

## 2026-08-30：Post-v3 定向加固与交付候选

- 工具：OpenAI Codex、DeepSeek V4-Flash API、本地只读 Git 与交付校验脚本。
- 目标：仅修复 Blind v3 已定位的 Commit provenance、Trace 口径和 taxonomy 反证缺陷，同时保持原盲测
  结果不可变。
- AI 辅助工作：
  - Commit 只有在存在可检查候选到修复版本 diff 且证据置信度足够时才判定，否则安全弃权；
  - Prompt 1.4.0 将 Trace 改为“可辩护安全链路”，不再要求穷举完整生命周期；
  - Evidence Packet 0.7.0 增加 taxonomy 交叉约束，区分 authentication 与 authorization；
  - 增加干净 Git 归档的一键验收，覆盖密钥文件扫描、离线演示、测试、交付材料和 CLI。
- 验证：对四条已见失败案例的定向开发回归为 31/32；唯一未确定项是缺少可检查权威 patch 的
  Paperclip Commit，系统选择 `uncertain`。该结果明确标注为 development-only，不冒充独立盲测。
- 工程验收：全新归档 126 个 tracked files、0 个密钥类文件、离线演示通过、92/92 单元测试、
  33/33 交付文件和 CLI 全部通过；hardening 分支已推送远端。
- 人工决策：不为追求满分猜测 Paperclip Commit；不开发与题目目标无关的 Web UI 或完整跨语言污点引擎；
  最终合并与 `v1.0.0` 标签留到参与者录制并复核演示视频之后。

## 2026-09-03：交付可读性、CI 与真实 DeepSeek 开发回归

- 工具：OpenAI Codex、本地只读 Git、DeepSeek Responses API。
- 目标：补齐陌生评审可直接阅读的输出、自动化交付检查，并验证当前代码而非历史回放可以在线完成
  Evidence -> Judge -> Critic -> 八字段报告。
- AI 辅助工作：新增 Markdown/自包含 HTML 报告器、`render-report` CLI、Python 3.10/3.12 CI、固定
  WeKnora 演示入口；Prompt 1.5.0 修复“位置合理掩盖描述错误”；DeepSeek Provider 增加可配置
  reasoning effort 和可审计元数据。
- 人工决策：不把公开候选文本或 Patch 当指令；不把 API Key 写入输出；不因导师允许多解就放过
  `构造器直接启动进程` 这类可证伪描述；同案例只做有限配置消融，停止重复抽样。
- 验证：98/98 单元测试、38/38 交付文件检查和 CLI 检查通过；Pro-high Judge 与 Critic 均完成并给出
  `Entry correct / Critical incorrect / Trace incorrect`，Pro-none 未检出该语义错误；Flash-high 的
  incomplete 被明确记录为 Provider 失败而非模型预测。
- 边界：WeKnora 是已见开发案例，不是新的泛化证据；下一步必须先冻结未见 entry/report 的 Blind v4
  选择、标签、证据和行为提交，之后才能进行唯一模型运行。

## 2026-09-03：Blind v4 预登记与证据复核

- 工具：OpenAI Codex、本地只读 Git、GitHub Reviewed Advisory/API。
- 目标：在不继续调当前 Agent 的前提下，建立一轮未见 entry/report 的独立后续评测，检查
  Post-v3 定向回归是否能迁移到新记录。
- AI 辅助工作：
  - 从未见 entry/report 中选择 4 条历史候选和 4 条当前候选，覆盖 XSS、授权、SSRF、命令注入和
    不安全默认配置；
  - 逐条核对固定 commit 源码、官方公告与可解释 Patch，纠正“后续改过就是原来错误”和
    “verify=1 就整条无误”两种捷径；
  - 预先登记完整字段口径、6 个边界字段的敏感性报告、模型配置、并发、重试与失败保留规则；
  - 编写一次性运行器：默认只做哈希/行为预检，显式 `--run` 才调用 API，拒绝覆盖已有结果。
- 接受的关键判断：历史 n8n 的另一处 sink 可以成立；Open WebUI 的共享读取前提不能被扩写为任意
  登录用户；MLflow 公告链接的提交实际修的是 artifact traversal，不能当默认密码修复。
- 参考标签：64 字段中 52 correct、11 incorrect、1 uncertain。该标签由同一开发 AI 辅助复核，
  明确不称独立安全专家 Gold，也不称官方隐藏测试。
- 冻结边界：生产行为仍绑定 `081bd14`、Packet 0.7.0、Prompt 1.5.0；本轮新增的是评测协议与输入，
  尚未发起 Blind v4 模型调用。

## 2026-09-04：Qwen3.8-Flash Provider 接入与有限试跑

- 工具：OpenAI Codex、阿里云百炼 Qwen3.8-Flash API、本地测试与交付检查。
- AI 辅助工作：新增独立 Qwen provider、严格 JSON Schema、显式在线开关、错误脱敏、配置示例和
  单元测试；保留 DeepSeek/OpenRouter，不改变 Agent harness。
- 验证：最小在线结构化请求成功；一条冻结证据包的 Judge→Critic 开发试跑完成；104/104 单元测试和
  46/46 交付文件检查通过，tracked diff 未发现密钥前缀。
- 人工边界：Qwen 结果单独保留，不续写或覆盖 DeepSeek Blind v4；单例出现误报和契约重试，因此不把
  “接通”包装成效果提升，也不扩跑整组。
- 后续加固：Prompt 1.6.0 在首轮公开合法证据 ID，harness 本地修复派生标识符；WeKnora 开发复核将
  Judge→Critic 从四次调用降为两次且无契约重试，但 Flash 仍未检出构造与启动的语义差异，思考模式
  在受控时限内未完成。因此保留工程改进，不将该模型包装为最终效果提升。
- 人工决策：换用 Qwen3.8-Max 后仍出现相同生命周期误判，因此没有把问题简单归因于 Flash；新增
  provider 无关的 LifecycleInspector、Critical 前短后长源码窗口和 Prompt 1.7.0。开发回归纠正了
  Critical，但 Trace 仍保守为 uncertain，故只记录为有效改进，不宣称完成新的盲测。

## 2026-09-04：Blind v5 冻结运行、失败复盘与成本约束

- 工具：OpenAI Codex、Qwen3.8-Max API、本地只读 Git 和八字段评测器。
- 目标：用运行前冻结的 6 条未见 entry/report 检验 Packet 0.8.0 / Prompt 1.7.0，并保留首轮完整结果。
- AI 辅助工作：建立并复核 48 个字段参考、执行 6 条 Judge→Critic、分解高置信误报；随后修复源码
  审计器对行尾解释和压缩摘要的误伤，并统一 DashScope Token 字段。
- 人工决策：参考明确标注为 AI 辅助复核而非独立专家 Gold；冻结结果 26/48 不覆盖、不调参重跑；
  Post-v5 的 33/48 仅作为零模型调用的已见失败诊断，不冒充新盲测。
- 验证：12/12 API 调用完成，6/6 案例无缺失；修复后完整单元测试 109/109 通过。原始运行共
  101,099 Token，Critic 零改判。
- 成本调整：后续默认 Judge-first，只对预登记的低置信、证据冲突或高风险字段触发 Critic；每轮先声明
  最大案例数、调用数和 Token 预算，达到上限即停止。

## 后续记录格式

每次重要迭代追加一节，至少包括：

- 日期、AI 工具和任务目标；
- AI 辅助完成的主要改动；
- 涉及的模块或提交；
- 执行过的验证；
- 人工接受、拒绝或修改的关键建议；
- 已知限制与下一步。

## 2026-09-08：Commit provenance 对抗加固

- 工具：OpenAI Codex、本地只读 Git、冻结 Blind v6 产物；未调用在线模型。
- 目标：消除“唯一直接子提交就是修复提交”的循环论证，并补齐可独立复算的交付证据。
- AI 辅助工作：定位 Patch 候选选择与 Submission 门槛耦合；构造 README、锁文件、普通引用、旁支
  Commit 等负例；实现公告角色解析、祖先关系、源码差异和 provenance 三档状态；补回放校验。
- 人工接受的原则：不为保住 62/64 放宽门槛；冻结原结果不覆盖；加固后的 59/64 明确记录为零模型
  开发重放，不宣称新盲测成绩。

## 2026-09-10：Packet 0.11.0 有界跨文件证据

- 工具：OpenAI Codex、本地只读 Git、单元测试；本阶段未调用在线模型。
- 目标：补足鉴权、校验或危险操作位于相邻模块时的证据缺口，同时维持安全和成本边界。
- AI 辅助工作：新增 Git tree 文件清单读取、静态相对导入/同目录候选解析、Python/JS/TS/Go 唯一函数
  定义定位，以及跨文件命中和歧义弃权回归测试。
- 人工接受的边界：只追踪一跳，最多 24 个候选文件与 6 个 helper；不执行目标代码，不声称完整调用图
  或污点分析，不对重名函数猜测归属。
- 验证：Packet 0.11.0 实现后完整单元测试 129/129 通过，`git diff --check` 通过。

## 2026-09-10：Final Blind v1 与交付收网

- 工具：OpenAI Codex、Qwen3.8-Flash API、GitHub Reviewed Advisory、本地只读 Git。
- 目标：补一组与既往冻结选择隔离的多仓验证，完善人类可读报告、成本表和最终交付材料。
- AI 辅助工作：预先选择并复核 5 条记录，覆盖 5 仓库及 Python/TypeScript/Go；冻结候选、公告、源码、
  Patch、参考、配置与哈希；打磨 Markdown/HTML 总览和逐字段证据流；整理 Token、延迟和估算口径。
- 正式运行：Qwen3.8-Flash 在 8 次物理请求上限内完成 4/5；已完成字段 27/32，冻结全集 27/40；
  2 个高置信误报、3 个 uncertain 与 1 条缺失均保留，没有按得分补跑。
- 人工边界：参考是 AI 辅助证据复核，不是官方隐藏集或独立专家 Gold；供应商金额只按返回 usage 的
  Token 与用户提供的参考单价估算，不冒充正式账单。
- 交付脱敏：正式运行后，公告原文中与 API token 格式相似的公开示例字符串统一替换为占位符；原冻结
  哈希与来源提交保留。Evidence Packet 与模型输出没有包含这些字符串，结果未重跑。

## 2026-09-14：批次系统性错误归因与安全修正建议

- 工具：OpenAI Codex、本地冻结运行产物、单元测试；未调用在线模型。
- 目标：把研发期人工发现的重复失败模式转化为可运行、可审计的 Bonus 能力，同时避免把统计相关性
  夸张成已证明根因。
- AI 辅助工作：新增 `systemic_analysis.py` 与 `analyze-systemic` 命令；每批 `validate` 自动输出
  `systemic-analysis.json/.md`，聚合至少两个不同案例重复出现的证据缺口、字段错误模式、
  Judge→Critic 方向变化和模型契约重试，并列出案例 ID、证据示例与有界建议。
- 修正建议：确定性源码工具只有在同一文件中找到唯一漂移位置时才给出新行号；多匹配、缺失或语义
  歧义继续不猜。语义层原有 correction 契约保持不变。
- 合规澄清：正式验证仍只读取本地公告缓存；可选联网缓存命令被明确标为赛前数据准备且不生成字段
  金标，活动若禁止相应 API 则不运行。
- 验证：新增 5 项单元回归，完整测试 134/134 通过；Final Blind v1 的离线批次分析识别出 4/4 案例
  的未证明 Trace 边和 3/4 案例的 Provider 契约重试，均标记为复核线索而非确定根因。

## 2026-09-14：最终录屏与单一上传包收尾

- 工具：OpenAI Codex、本地 Git 与 Python 标准库；未调用在线模型。
- 目标：消除录屏材料中的旧数字和功能缺口，并把活动要求的“一个 ZIP”固化为可复现步骤。
- AI 辅助工作：同步录屏台词、答辩问答、交接与提交清单；将批次系统性错误分析加入四分钟演示主线；
  新增 `build_final_submission.py`，从干净 Git 提交打包代码并加入参与者复核过的 MP4。
- 安全边界：组装器拒绝脏工作树和被跟踪的 `.env`，不包含 `.git` 或未跟踪文件，检查 200 MiB 上限并
  输出 SHA256。视频仍由参与者本人录制和回看，避免泄露账号、密钥、余额或私人聊天。

## 2026-09-14：面向评审的材料重构

- 工具：OpenAI Codex、本地文档与交付 ZIP 清单；未调用在线模型。
- 目标：让评审无需顺序阅读二十余份过程文档，也能在三分钟内理解题目、方案、结果、运行方式和边界。
- AI 辅助工作：新增根目录两页提交总览、1–3 页简明设计和分层文档导航；README 首屏增加评审路径，
  将完整能力与历史指标折叠为技术审计区；同步录屏画面和 ZIP 内 `SUBMISSION_INFO.txt`。
- 人工边界：没有删除失败、原始冻结结果或 AI Coding 留痕；长文档继续作为审计附录，精简入口不改变
  任何实验数字和证据口径。

## 2026-09-14：真实录屏入口

- 工具：OpenAI Codex、本地只读 Git、Qwen3.8-Flash API。
- 目标：把旧版“固定结果回放”升级为评审可见的输入 → 工具取证 → Judge/Critic → 新报告完整链路，
  同时保留离线回放作为 Provider 故障时的备用方案。
- AI 辅助工作：新增 `scripts/run_recording_demo.sh`，安全读取未跟踪的 `.env`，展示 WeKnora 候选输入，
  调用完整 `validate` 工作流，并打印本次 Provider、用量、耗时、八字段结论和 HTML/JSONL 路径。
- 真实试跑：Qwen3.8-Flash 完成 Judge 与 Critic 两次请求，Provider 返回合计 21,516 tokens；结果为
  6 correct / 2 incorrect，识别出候选关键操作与 Trace 错误，并生成新的 Markdown/HTML/JSONL 报告。
- 安全边界：脚本不打印、复制或提交 API Key；输出目录固定在 `out/recording-demo` 且受 Git 忽略。
