# Pilot v1 复核与失败队列

> 状态说明：这是早期 Packet/Prompt 的失败快照，下面的“待补证据”描述当时暴露的问题，不是当前
> 版本待办。后续处理与是否解决可在 `EXPERIMENT_LOG.md`、`DECISIONS.md` 和冻结评测中追踪。

来源：Prompt 1.0.0 + Advisory Evidence Packet 0.2.0 的 Judge→Critic 最终结果。该清单是人工
gold 和下一轮工具开发的输入，不把模型结论直接视为真值。

## entry-00084 · n8n

- Entry Point 多候选：声明的 HTML 分支是漏洞路径入口；更早的 `getNodeParameter` 也可视为攻击者输入边界。
- Trace 锚点：描述讨论 iframe sandbox token，但节点锚在相邻 style 行；上下文中真正 token 位于下一行。
- 待复核：确定本项目对“业务入口”与“最早污点输入”的优先口径；检查 trace 节点是否必须锚到根因表达式。

## entry-00080 · WeKnora

- Critical Operation 多候选：配置进入 `NewStdioMCPClientWithOptions` 的交接点，或后续 `Connect/Start` 激活点。
- Trace 缺边：创建接口写库 → 测试接口读库没有完整证据；构造 client → 启动进程也没有展开。
- 待补证据：repository create/get、`get_runner` 等调用点以及 stdio client 的 Connect/Start 实现。

## entry-00394 · FastMCP

- 五个语义字段均为 `correct`，可作为第一条 gold 复核候选。
- 待人工确认：路径参数编码缺失、`urljoin` 归一化和修复 diff 是否足以覆盖完整链路。

## entry-00383 · OpenClaw

- Entry Point 多候选：`operator.write` scope 注册体现授权面入口；browser handler 是最早展示的请求参数接收点。
- Trace 描述过度：证据未证明关闭“所有依赖 WebSocket”；移入 Trash 受目录存在条件约束，且中间有存在性检查。
- 待修正：把叙述降到证据能证明的范围，并补 dispatcher 到 `/reset-profile` 路由解析的直接连接。

## entry-00430 · Google ADK

- Trace 缺边：没有展示 `get_runner_async` 相关函数体，也没有展示 `_perform_load` 调用
  `_load_from_module_or_package` 的位置。
- 描述问题：函数声明本身不能证明返回值流入该函数。
- 待补证据：围绕两个函数自动扩展调用点和函数体，而不是只给声明附近固定窗口。

## 跨案例优先级

1. TraceInspector：按符号和调用关系扩展缺失函数体、调用点与持久化读写边。
2. 描述一致性检查：识别“always/all/immediately”等强断言与条件代码的冲突。
3. Entry/Critical 候选报告：允许多个可辩护锚点并解释用途，而非强制唯一答案。
4. TitleReviewer：用公告标题与漏洞机制做语义核对，不能依赖逐字相等。
5. 独立人工 gold：先复核 FastMCP，再复核争议较集中的四例；Agent 输出只能当复核材料。

## TraceInspector 0.1 A/B 后的首要裁决

- n8n：是否因遗漏真正 sandbox token 行和三条未证明边，将完整 Trace 标为 `incorrect`，还是允许核心链路
  正确但局部锚点/描述需修正而标为 `uncertain`。
- WeKnora：创建接口与测试接口之间缺持久化读写节点，且构造 client 不等于启动进程；需要决定这是完整
  Trace 的实质错误，还是可接受的抽象省略。
- FastMCP/Google ADK Entry 在两次相同 Prompt 运行间变化，应视为采样波动案例，不在没有额外证据时
  直接改 gold。
