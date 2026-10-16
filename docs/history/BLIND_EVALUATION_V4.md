# Blind v4：八条未见记录的预登记评测

本轮用于检验当前系统，而非证明 Top 3 或得到官方隐藏集成绩。行为固定在 `081bd14`，
Packet 0.7.0、Prompt 1.5.0；新增文件只涉及评测数据、协议和运行器，不改变 Agent。

## 边界与参考答案

- 8 个 entry / 8 个 report / 8 个仓库，排除此前登记的 43 个 entry 和 report；仓库并不隔离。
- 4 条历史候选、4 条当前 `verify=1` 候选。`clean` 是采样来源，不保证内容正确。
- 64 个字段：52 correct、11 incorrect、1 uncertain；全猜 correct 基线 81.25%。
- 参考答案由同一开发 AI 在模型预测前辅助交叉核对源码、公告和修复差异；不是独立专家 Gold，
  也不构成统计独立、随机代表性的大规模样本。完整理由见 selection 中的 review。
- 报告审核整个字段，而不是只看源码行能否找到。可辩护的另一处 sink、解释性代码注释和省略
  隐式边不自动判错；明确虚构分支、权限范围或副作用则判错。含糊范围保留 uncertain。

| Entry | 参考非正确项 | 核心证据 |
|---|---|---|
| 00110 n8n | 无 | 旧 v-html sink 可辩护；注释不是源码篡改 |
| 00258 Flowise | Trace 错 | 多个 line 0；API-key sink 本身可辩护 |
| 00313 Airflow | Entry/Critical/Trace 错 | 声明行实际是别的语句，官方 PR 补 DAG 过滤 |
| 00317 Langflow | Trace 错 | 两个 line 0；路由与无 ownership 的查询位置成立 |
| 00276 WeKnora | Trace 错 | Chrome-first/HTTP-fallback 被写成按渲染需求选择 |
| 00446 Paperclip | 无 | PATCH 配置到归档 cleanup，再到 shell 执行的路径成立 |
| 00171 MLflow | Entry/Critical/Trace 错 | 配置并非无条件读取；不存在所述认证上下文交接 |
| 00376 Open WebUI | Entry 不确定；Critical/Trace 错 | entry 范围含糊；DB/vector 写入被混同；共享读取条件被否认 |

这些细节不代表“漏洞不存在”。尤其 MLflow、WeKnora、Open WebUI 的错误主要在候选解释，
审核器应分别报告位置、行为与描述。评分依赖上述全字段口径，不能与旧轮分数简单相减声称提升。

## 预登记的参考口径敏感性检查

主结果始终使用原 64 标签。另报告排除以下 6 个解释边界字段后的 58 字段结果，检验结论是否
过度依赖本项目的严格描述口径，不替换主分数，也不事后挑高分口径：

- entry-00276 / trace；
- entry-00171 / entry_point、critical_operation、trace；
- entry-00376 / entry_point、critical_operation。

其中 5 个是明确描述错误但核心漏洞链路仍存在的字段，1 个是范围表述含糊字段。
此外单列误报、漏报、缺失结果、Critic 改动和错误理由；只有数字对上而证据错误也必须披露。

## 公告与 Patch 不能互相冒充

8/8 公告已连接。只有 Airflow、Langflow、WeKnora 三条有本轮明确复核的 fix-map anchor。
WeKnora 的 fix 从维护仓库已发布版本中定位，不冒充公告直接引用。Langflow 公告版本元数据
与引用 release 存在不一致，采用对应源代码修复作依据。

现有 PatchInspector 还自动选中 Flowise、Paperclip、MLflow、Open WebUI 的直接子提交。这四条
仅是启发式候选，不因 `selected` 或数值 confidence 就成为权威修复。此行为在运行前已记录，
本轮不临时修工具美化输入。MLflow 公告引用的 5bf2ec2b 实际修 artifact traversal，也没有被列入
fix map。应评估 Agent 是否误把无关补丁当成漏洞证据，而不只看 Commit 的标签是否碰巧正确。

## 冻结、运行与复现

先执行（无模型）：

```bash
PYTHONPATH=src python3 -m vulngym_agent build-blind-dataset --repository ../VulnGym --selection configs/blind-v4-selection.json --output-dir out/blind-v4
PYTHONPATH=src python3 -m vulngym_agent index-repositories --input out/blind-v4/candidates.jsonl --output out/blind-v4/repository-index.json --repositories-root ../vulngym-repos
PYTHONPATH=src python3 -m vulngym_agent prepare-evidence --input out/blind-v4/candidates.jsonl --output out/blind-v4/evidence.jsonl --repositories-root ../vulngym-repos --fix-map configs/blind-v4-fixes.json --advisory-cache configs/advisories/blind-v4.jsonl --context-lines 12
python3 scripts/run_blind_v4.py
```

模型运行前必须提交 selection、协议、运行器和证据哈希。新模型调用固定 DeepSeek V4-Pro/high、
12,288 输出上限、并发 2、Judge→Critic，保留冻结代码中已有的传输与契约重试。无论结果如何不手动
重抽，不改标签再跑；错误照常保存。参考标签只在全部调用结束后的评分阶段读取，不进入模型请求。

```bash
set -a
source .env
set +a
python3 scripts/run_blind_v4.py --run
```

运行器拒绝覆盖已有 `out/blind-v4-run`；单案例完成即保存。主报告含降级时可生成的确定性字段，
同时输出 completed-only 报告（未完成案例按缺失计入分母），不可用降级分数掩盖调用失败。
Judge 对照也使用同一确定性适配器，**不是裸模型基线**。模型、Prompt、样本均与 Blind v3 不同，
因此 v3→v4 只比较不同版本快照，不能用作模型选择或单模块改进的因果证明。

记录可观察 Token 和耗时；失败请求可能没有 usage，所以不是完整账单。下一轮行为修复须另建
开发回归并保留本轮原分数。冻结时尚无本轮模型结果。
