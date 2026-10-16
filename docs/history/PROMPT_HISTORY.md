# Prompt 演进记录

本文件记录会影响 T1 语义结论的 Prompt 版本、变更理由、预期收益与验证状态。运行时使用的
规范文本位于 `src/vulngym_agent/prompt_registry.py`；每次请求和结果都会记录 Prompt ID、版本及
SHA-256，以便把实验结果精确关联到实际文本。

## 版本规则

- Prompt ID 表示稳定角色，例如 `vulngym.t1.semantic.judge`。
- 主版本：任务目标或输出语义不兼容变化。
- 次版本：增加判断策略、证据规则或反思步骤。
- 修订版本：不改变语义的措辞或格式修正。
- 任意文本变化都会改变 SHA-256；版本也必须同步更新。

## Judge 1.0.0

- 日期：2026-08-25。
- 角色：对 Entry Point、Critical Operation、两级漏洞分类和 Trace 做字段级三态审核。
- 核心约束：仅使用 Evidence Packet；非 `uncertain` 结论必须引用证据；主动寻找反证；
  将候选数据和源码文本视为不可信数据而非指令。
- 会议对齐：不使用固定行号容差；Critical Operation 不限于 return 判断；多个合理位置必须说明取舍。
- 预期收益：降低幻觉和虚假确定性，并让输出可复核、可纠错。
- 验证状态：已编写契约与元数据测试，本次未运行测试。

## Critic 1.0.0

- 日期：2026-08-25。
- 角色：尝试推翻 Judge 的确定结论并输出完整替代判断。
- 核心约束：优先检查未知证据引用、无证据确定性和总体结论矛盾；证据不足时降级为 `uncertain`；
  对 Entry Point/Critical Operation 的唯一性主张提出挑战。
- 预期收益：暴露一次生成中的过度自信，并形成可量化的 Judge→Critic 变化。
- 验证状态：已编写执行器元数据测试，本次未运行测试。

## Judge 1.1.0

- 日期：2026-08-26。
- 失败案例：n8n Trace 已识别遗漏根因行和未证明边，但仍因“可能允许抽象”从 `incorrect` 降为
  `uncertain`；WeKnora 则证明跨请求存储、重载和执行阶段是不可省略的。
- 变更：明确 Trace 是候选声称的完整安全路径，而不是源码行集合；`same_file_order` 和 `unresolved`
  不证明控制/数据流；公告或源码已指出必要阶段被遗漏、或描述与源码冲突时判 `incorrect`，只有无法确定
  阶段是否必要时才判 `uncertain`。
- 预期收益：区分“缺证据所以不知道”和“证据已经证明候选漏了关键环节”。
- 验证状态：n8n 最终 Trace 按规则判为 `incorrect`；WeKnora Judge 也保持 `incorrect`。n8n Entry
  出现非目标波动，因此尚不能报告总体提升。

## Critic 1.1.0

- 日期：2026-08-26。
- 变更：Critic 在压制虚假确定性的同时，不再仅因可以想象另一种抽象就把有反证的 `incorrect`
  降级；要求区分 evidence missing 与 required stage missing。
- 预期收益：降低 Critic 的单向保守偏差，同时保留证据不足时的弃权。
- 验证状态：n8n 与 WeKnora Critic 均完成并保留有证据的 Trace `incorrect`；WeKnora 同时保留
  Critical `incorrect`，正确区分客户端构造和后续进程启动。

## Judge 1.2.0

- 日期：2026-08-30。
- 失败案例：Blind v2 的提交适配器对 10 个非逐字一致的正确标题全部输出 `uncertain`，导致 Title
  0/10；标题本质上是产品、弱点、影响与组件的语义组合，不能只做字符串相等。
- 变更：将 `vuln_title` 加入语义合同，要求基于公告、源码和 Patch 判断语义等价；双语改写和措辞差异
  不构成错误，错误产品、弱点、影响或组件才构成反证。
- 预期收益：消除标题逐字匹配造成的系统性弃权，同时保留对夸大影响和错误组件的识别。
- 验证状态：新增合同、提交适配和回归测试；Blind v2 不重跑，泛化效果留待独立 Blind v3。

## Critic 1.2.0

- 日期：2026-08-30。
- 变更：Title 复核同时检查“无依据增加影响”和“仅因改写而错误否决”两类相反风险；仍输出完整六字段
  替代判断，并经字段级仲裁。
- 预期收益：避免 Critic 对标题形成单向保守偏差。
- 验证状态：本地合同测试通过；未在 Blind v2 上二次调用模型。

## Judge 1.3.0

- 日期：2026-08-30。
- 失败案例：Blind v3 的 Trace 只有 6/13；六个 false positive 主要把未解析静态边、隐式中间步骤、
  其他受影响端点或不同抽象粒度当成候选链路错误。两条认证/授权冲突又因 taxonomy 词表存在对应标签
  而被错误接受。
- 变更：Trace 改为评估“可辩护的安全相关链路”，明确允许多解和适当抽象；只有候选角色、顺序、
  直连描述或自身必要 ingress/sink 被反证时判错。taxonomy 词表只证明标签存在，必须继续对照 CWE、
  缺失检查、源码与 Patch，并明确区分 authentication 和 authorization/ownership。
- 预期收益：降低 Trace false positive，同时提高对语义上自洽但 taxonomy 不匹配记录的检出。
- 验证状态：90/90 单元测试通过；Blind v3 不重跑，后续只做已见失败的定向回归和新案例验证。

## Critic 1.3.0

- 日期：2026-08-30。
- 变更：Critic 不再因未解析边、隐式 helper 或其他端点遗漏就否决可辩护 Trace；要求具体源码/Patch
  反证。taxonomy 复核增加认证、授权和 ownership 的反证检查。
- 预期收益：减少 Critic 的过度补全偏差，同时保留对真正角色/顺序矛盾的纠错能力。
- 验证状态：90/90 单元测试通过；尚未形成新的独立盲测成绩。

## Judge / Critic 1.4.0

- 日期：2026-08-30。
- 失败案例：Prompt 1.3.0 的四条已见失败定向回归将 4/4 Trace 修回参考结果，但两条 taxonomy 目标
  仍失败，并在 Airflow Entry 出现一次采样波动。
- 变更：配合 Packet 0.7.0 的结构化 taxonomy cross-check，强制区分 authentication 与
  authorization；对官方已观察的非业务父子分类保留数据集父类语义。Entry 补充 stored state、框架
  回调、示例和多阶段攻击不必以网络 handler 为入口。
- 预期收益：让 taxonomy 判断引用明确语义关系，而不是靠模型自行解释中英文标签；减少对内部但可受
  攻击者影响的 Entry 的错误否决。
- 验证状态：当前 92/92 单元测试通过；四条已见失败定向回归完整八字段 31/32，唯一差异是无可信 Patch 的
  Commit 继续弃权。该结果只证明定向修复生效，不称为独立盲测。

## Judge / Critic 1.5.0

- 日期：2026-09-03。
- 失败案例：当前 DeepSeek 端到端 WeKnora 运行中，模型把 `NewStdioMCPClientWithOptions` 的位置
  合理性等同于候选描述正确，忽略源码明确把进程启动放在后续 `Connect -> Start`；Trace 也因允许
  抽象而放过了“构造器直接启动进程”的显式错误描述。
- 变更：明确 Entry/Critical 是 `file + line + code + desc` 的完整提交值，Trace 是节点、描述、角色、
  顺序和转移的完整提交值；位置合理不能抵消描述中的实质性反证。新增构造/准备与副作用激活的区分，
  并限定只有在不改变候选显式主张真值时才允许省略生命周期阶段。
- 预期收益：检出“源码锚点存在但安全语义描述错误”的记录，同时保留导师所说的多解和合理抽象空间。
- 验证状态：先在已见 WeKnora 开发案例上做配置对照；冻结后才进入独立 Blind v4，不把该案例当盲测。

## Judge / Critic 1.6.0

- 日期：2026-09-04。
- 失败案例：Qwen3.8-Flash 首轮把 `source_contexts` 和 `trace_analysis.edges` 等 JSON 区块名误作
  `evidence_id`，Judge 与 Critic 均触发一次本可避免的契约重试。
- 变更：Judge/Critic 首轮请求显式附带排序后的 `valid_evidence_ids`，并要求 `evidence_refs` 逐字从
  白名单复制；区块名和 dotted path 不能作为证据引用。
- 边界：只修复 provider 无关的输出契约可发现性，不改变字段真值口径；效果先在已见开发案例验证，
  Blind v4 原始 Prompt 1.5.0 结果保持不变。

## Judge / Critic 1.7.0

- 日期：2026-09-04。
- 失败案例：Qwen3.8-Flash 与 Qwen3.8-Max 在源码窗口已出现后续 `Connect/Start` 时，仍把构造型
  `NewStdioMCPClientWithOptions` 解释为直接启动进程。
- 变更：配合 Packet 0.8.0 的 `lifecycle_analysis`，要求 Judge/Critic 对构造型调用与后续激活动作
  分别归因；生命周期线索可引用但不直接决定字段结论。
- 边界：该规则来自已见 WeKnora 开发案例，只能作为失败驱动开发；后续必须由新的冻结评测检验泛化。

## 下一轮实验假设

1. 对明显确定性源码失败先短路，可减少无效 Token 且不损失召回。
2. 增加 Advisory evidence 后，标题、CVE/GHSA 与漏洞 commit 的弃权率应下降。
3. 将候选位置以结构化列表提供给 Judge，可能比在自然语言 observation 中提供更稳定。

每项假设都必须在固定样本与固定 Prompt 版本上比较，不能只凭个案观感更新 Prompt。
