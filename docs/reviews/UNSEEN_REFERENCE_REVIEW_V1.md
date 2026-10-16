# Unseen v1 证据复核参考集

## 定位

本文件对五条未参与 Prompt 1.1.0 调试的新漏洞做逐字段证据复核。标签来自官方公告、直接子修复提交、
漏洞版本源码和 VulnGym 自身 taxonomy，仍属于 **AI 辅助 provisional 参考**，不是独立人工 Gold，不能据此
宣称正式准确率。

## 逐案结论

### entry-00082 · n8n 表达式注入

- Entry `incorrect`：静态 import 只引入符号，不接收攻击者数据或执行表达式。
- Critical/L1/L2 `correct`：空 `before` hook 是修复直接替换的根因配置，公告支持表达式注入与 RCE。
- Trace `incorrect`：包含与漏洞传播无关的闭合括号，并把 evaluator 绑定排在 Tournament 构造之前，
  与模块初始化顺序相反。

### entry-00087 · n8n 表单任意文件读取

- Entry/Critical/L1/L2 `correct`：请求入口、`copyBinaryFile(file.filepath)` 和 multipart 修复相互印证。
- Trace `incorrect`：把内部 `readFile` 放在调用它的 `copyBinaryFile` 之前；同时说恶意 `files` 来自
  `bodyData`，源码却单独读取 `context.getBodyData().files`。

### entry-00107 · n8n Git 参数注入

- 五字段均 `correct`：`pathsToAdd` 在同一局部路径被读取并直接传给没有 `--` 的 `git.add`，直接子修复
  正是插入该分隔符。两节点 Trace 虽短，但已经完整表达该字段级数据流，公告补足 simple-git 下游语义。

### entry-00121 · OpenClaw 设备身份绕过

- Entry `uncertain`：WebSocket message callback 是合理入口，但包内证据不足以证明候选所称“唯一入口”。
- Critical `incorrect`：候选说三元表达式两侧都依赖 token；源码的 `hasSharedAuth` 还可由 password 单独成立。
- L1/L2 `correct`；Trace `incorrect`：候选遗漏修复差异明确显示的 device-required 与后续 authorization
  阶段，还把 `device = null` 误写成独立成功绕过。

### entry-00146 · OpenClaw allowlist/审批绕过

- Entry `correct`；Critical/Trace `incorrect`：`runCommand` 是合理 sink，但候选断言 `execArgv` 始终来自
  `command[]`。漏洞源码存在 Windows 条件分支，可用从 `rawCommand` 解析的值替换 `execArgv`，所以描述
  缺少关键适用条件。
- L1/L2 `correct`：VulnGym v0.1.4 README 明确把 `业务逻辑` 作为粗分类，并把
  `BL-AGENT-CAPABILITY — AI/Agent 能力边界绕过` 列为正式二级类别。

## 新发现的系统失败

Packet 0.4.0 没有提供 VulnGym taxonomy。Prompt 1.1.0 因此在 entry-00146 对两个正确分类输出
`uncertain`，理由是无法证明专用标签定义。Packet 0.5.0 新增版本化、可引用的 taxonomy 文档后，固定
Prompt 的单条复跑只把这两个分类改为 `correct`，其余最终字段方向不变。
