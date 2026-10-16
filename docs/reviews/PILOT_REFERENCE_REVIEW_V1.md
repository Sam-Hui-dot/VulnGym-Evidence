# Pilot v1 证据复核参考集

## 定位与限制

这是一份由 AI 辅助、逐项对照官方公告、修复提交和本地漏洞版本源码形成的工程参考集，**不是独立人工
Gold**。它用于发现证据缺口、回归 Agent 行为和准备后续专家复核；在独立安全复核者确认前，不据此宣称
准确率。

统一口径：候选锚点只要安全语义合理即可，不强求唯一；描述与源码明确冲突，或 Trace 漏掉漏洞成立所需的
核心阶段，则判 `incorrect`；公开证据不足或多个抽象层级均可辩护时判 `uncertain`。

## entry-00084 · n8n

- 参考结论：Entry `uncertain`；Critical `correct`；L1 `correct`；L2 `correct`；Trace `incorrect`。
- 公告依据：GHSA-58jc-rcg5-95f3 将问题明确描述为 Respond to Webhook 节点中的 Stored XSS；攻击者控制的
  HTML 脚本可能在顶层窗口而非预期 sandbox 中执行。
- 补丁依据：`667656e8` 删除 `sandboxHtmlResponse` 的 iframe 包装，并在响应头设置 CSP sandbox。
- Entry：声明的 HTML 类型判断确实进入漏洞路径，但攻击者输入获取、sandbox 调用等也可作为合理入口，
  当前定义不足以证明唯一答案。
- Critical：`res.send(bodyToSend)` 是可辩护的最终浏览器输出 sink，虽然 iframe sandbox 属性行是更贴近
  根因的候选。
- Trace：记录没有锚定真正包含危险 sandbox token 的 `html-sandbox.ts` 返回行，却把相邻的纯样式行写成
  权限配置的一部分；还把若干未证明的跨层关系描述成连续调用链，因此作为完整 Trace 不可接受。

## entry-00080 · Tencent/WeKnora

- 参考结论：Entry `correct`；Critical `incorrect`；L1 `correct`；L2 `correct`；Trace `incorrect`。
- 公告依据：GHSA-78h3-63c4-5fqc 明确给出攻击链：认证用户写入 `stdio_config.command/args`，配置被持久化，
  `/test` 路径重新读取配置，随后 `Connect() -> Start()` 启动子进程。
- 补丁依据：`f7900a5e` 在创建、更新和客户端构造边界增加 stdio 配置校验。
- Entry：`ShouldBindJSON(&service)` 是公告直接列出的外部输入绑定点。
- Critical：候选把 `NewStdioMCPClientWithOptions` 描述成已经通过 `os/exec` 启动进程；本地源码显示
  `NewMCPClient` 只构造客户端，真正启动发生在随后 `Connect` 调用的 `c.client.Start(ctx)`，因此描述与
  执行位置明确冲突。
- Trace：候选从创建请求直接跳到另一条测试请求，遗漏数据库 Create、`GetByID`、`Connect` 和 `Start`，
  无法表达公告给出的存储型跨请求命令执行链。

## entry-00383 · OpenClaw

- 参考结论：Entry/Critical/L1/L2 `correct`；Trace `incorrect`。
- 公告与补丁支持 `operator.write -> browser.request -> 漏判 POST /reset-profile -> resetProfile` 主路径，
  Entry 和缺失授权判断点均可辩护。
- Trace 对末端行为作了超出证据的断言：源码只显示关闭对应 Playwright 连接，没有证明“所有依赖该
  CDP 端点的 WebSocket 会话均终止”；`movePathToTrash` 前还有目录存在检查和 early return，公告也明确
  限定为目录存在时才移动。
- 结论：主链方向正确不抵消节点描述中的明确过度断言，字段需要修正后才能作为可用 Trace。

## entry-00430 · Google ADK

- 参考结论：Entry/Critical/L1/L2 `correct`；Trace `incorrect`。
- 公告、漏洞源码和直接子修复共同支持未认证 `app_name` 进入 AgentLoader，并最终到达
  `importlib.import_module(agent_name)`；修复在加载前增加 Agent 名称校验。
- Trace 第 4 节点写成“该返回值流入 `_load_from_module_or_package`”。实际代码是 `_perform_load`
  计算 `module_base_name` 后将它作为输入参数传入该方法，返回值方向相反。
- 结论：调用链节点基本齐全，但显式数据流描述与源码冲突，不能判作完整正确。

## 可追溯来源

- n8n 公告：https://github.com/advisories/GHSA-58jc-rcg5-95f3
- n8n 修复：https://github.com/n8n-io/n8n/commit/667656e8f3d6c23a79a4b80f2f6f330024115893
- WeKnora 公告：https://github.com/advisories/GHSA-78h3-63c4-5fqc
- WeKnora 修复：https://github.com/Tencent/WeKnora/commit/f7900a5e9a18c99d25cec9589ead9e4e59ce04bb
- OpenClaw 公告：https://github.com/advisories/GHSA-xp9r-prpg-373r
- OpenClaw 修复：https://github.com/openclaw/openclaw/commit/1b3a1246d00c35de419ca81ba301332f12a11ef2
- Google ADK 公告：https://github.com/advisories/GHSA-rg7c-g689-fr3x
- Google ADK 修复：https://github.com/google/adk-python/commit/116f75d2c9cd83a70c57b301b021182dd6f158f2
- 本地源码角色：两个 selected fix commit 均由 Git 验证为候选 vulnerable commit 的直接子提交。
