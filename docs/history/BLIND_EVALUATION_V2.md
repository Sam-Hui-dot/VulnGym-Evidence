# Blind Evaluation v2 协议

## 目的

`repo-holdout-v1` 已经暴露过 Critic 回退，并直接推动了 non-regression gate，因此它从此只作为开发
对照，不再承担最终未见集角色。`blind-v2` 用一组此前没有进入 Pilot、unseen 或 repo-holdout 的仓库，
检验冻结后的 Agent 是否能同时发现真实历史错误并避免把干净字段误判为错误。

本实验不是主办方隐藏测试，也不宣称官方准确率。它是 **unseen-to-development** 的公开数据评测。

## 冻结规则

模型运行前必须提交以下内容：

- `configs/blind-v2-selection.json`；
- 当前 Agent 行为基线 commit；
- Evidence Packet、Workflow、Judge 和 Critic 版本；
- 10 个案例及其类型；
- 排除过往开发案例和仓库的清单；
- 候选、参考与选择文件的 SHA-256 manifest。

运行后不得依据 `blind-v2` 的错误修改 Prompt、工具或仲裁规则并重新把同一组结果称为盲测。若失败揭示
值得修复的问题，保留失败结果，把修改用于后续 `blind-v3`。

## 数据组成

固定 10 个案例、8 个未参与开发评测的仓库、80 个完整字段标签：

- 5 条自然历史错误：从公开 `v0.1.1` 取出后来在 `v0.1.2` 被人工修订的旧字段，并将其放回
  `v0.1.4` 已验证记录；
- 5 条干净记录：直接使用 `v0.1.4` 中 `verify=1` 的公开人审记录；
- 资源缺失、错误 commit 和模型故障不混入准确率分母，另列 robustness matrix。

自然历史候选只替换后来真实修订的顶层字段，其余字段保留 `v0.1.4` 值。因此八字段参考为：修订字段
`incorrect`，未修订字段 `correct`。这比跨仓库随机拼接更自然，但仍属于数据集派生的 provisional
reference，必须保留人工复核状态，不能包装成独立安全专家 Gold。

## 隔离边界

已排除开发阶段使用的 20 个 entry 和 15 个上游仓库。`blind-v2` 使用：

- Significant-Gravitas/AutoGPT；
- aquasecurity/trivy；
- ollama/ollama；
- NVIDIA/NeMo；
- milvus-io/milvus；
- apache/airflow；
- czlonkowski/n8n-mcp；
- jlowin/fastmcp。

选择时没有调用模型，也没有查看 Agent 对这些候选的输出。

## 物化命令

```bash
PYTHONPATH=src python3 -m vulngym_agent build-blind-dataset \
  --repository ../VulnGym \
  --selection configs/blind-v2-selection.json \
  --output-dir out/blind-v2
```

输出：

- `candidates.jsonl`：可直接送入完整 Agent；
- `reference.jsonl`：八字段 provisional reference；
- `review-queue.jsonl`：人工复核队列，不包含 Agent 输出；
- `manifest.json`：案例、来源、字段变化和内容哈希。

## 证据准备

候选物化后，只读取固定 commit 的源码，不 checkout、不构建、不执行上游项目：

```bash
PYTHONPATH=src python3 -m vulngym_agent index-repositories \
  --input out/blind-v2/candidates.jsonl \
  --output out/blind-v2/repository-index.json \
  --repositories-root ../vulngym-repos

PYTHONPATH=src python3 -m vulngym_agent prepare-evidence \
  --input out/blind-v2/candidates.jsonl \
  --output out/blind-v2/evidence.jsonl \
  --repositories-root ../vulngym-repos \
  --fix-map configs/blind-v2-fixes.json \
  --advisory-cache configs/advisories/blind-v2.jsonl \
  --context-lines 12
```

首轮证据物化状态：8/8 仓库可定位、60/60 个声明源码位置可读、10/10 公告匹配、10/10 Trace
分析可用。7 条提供可复现 Patch 对照；另外 3 条有意不提供：Trivy 属于供应链标签污染、Ollama
没有官方修复版本或 commit、Milvus `entry-00119` 的官方修复位于另一维护分支，跨分支差异包含大量无关
改动。完整哈希与边界记录见 `artifacts/blind-v2/evidence-manifest.json`。

这里“Patch 缺失”是证据状态，不是运行失败；Judge 必须基于其余证据判断或输出 `uncertain`，不能猜测
一个修复提交。

## 指标

最终报告必须同时给出：

- 八字段总体 accuracy；
- `incorrect` precision、recall 和 F1；
- `uncertain` 比例；
- case exact match；
- 每字段 confusion matrix；
- 缺失预测；
- evidence coverage；
- 高置信错误清单；
- 完成率、耗时和 Token 成本。

其中 precision 是关键指标：只统计错误召回会掩盖“把干净字段大量判错”的系统。

八字段报告评测命令：

```bash
PYTHONPATH=src python3 -m vulngym_agent evaluate-submission \
  --submission out/blind-v2-run/submission.jsonl \
  --reference out/blind-v2/reference.jsonl \
  --output out/blind-v2-run/evaluation.json
```

## 人工复核

首次模型运行前只查看 `review-queue.jsonl` 的公开版本差异，不查看 Agent 输出。复核者逐条确认：

1. 当前 `v0.1.4` 行是否为 `verify=1`；
2. 历史错误是否确实来自已发布旧版本；
3. 变化是否属于语义纠错，而非纯格式或 `desc` 文案变化；
4. 干净记录的八字段是否可由公告、源码和修复提交支持；
5. 无法可靠判断的标签改成 `uncertain`，并写明需要的额外证据。

完成独立复核前，文档统一使用“provisional reference”，不用“专家 Gold”。

人工复核和模型运行严格分离：复核表可以查看 candidate/reference 与公开证据，但首轮 Agent 结果生成前
不得依据预期标签调整 Prompt、规则、修复映射或上下文窗口。

逐案问题和填写模板见 `docs/BLIND_V2_REVIEW_SHEET.md`。

## 成功标准

本阶段不预先设一个必须达到的漂亮分数。成功标准是：数据在模型运行前冻结、完整报告同时衡量召回和
误报、失败不被删除、每个数字可追溯。性能目标只作为观察值记录，不反向修改 `blind-v2`。

## 首次冻结运行结果

冻结材料先由 commit `ee622a1` 固化，交付检查由 `151f56e` 固化；随后使用
`deepseek-v4-flash` 完成唯一一次 10/10 Judge→Critic 运行。原始输出保留在本地忽略目录
`out/blind-v2-run/`，可提交摘要位于 `artifacts/blind-v2/result-summary.json`。

| 指标 | 结果 |
|---|---:|
| 八字段 accuracy | 59/80（73.75%） |
| incorrect precision / recall / F1 | 54.55% / 54.55% / 54.55% |
| uncertain | 11/80（13.75%） |
| case exact match | 0/10 |
| evidence coverage | 100% |
| 缺失预测 | 0 |
| 总 Token | 163,613 |
| 模型调用累计耗时 | 146.50 秒 |

该结果否定了“开发对照 12/12 等于泛化完成”的乐观判断。字段层面 Commit、L1、L2 为 10/10，
Entry 为 6/10、Critical 为 7/10、Trace 为 7/10、IDs 为 9/10、Title 为 0/10。

首轮诊断暴露了三个明确工程问题：报告适配层对非逐字一致标题一律 abstain；多行源码的 `line` 被错误
解释成单行范围；含省略号的摘要源码被当作逐字匹配声明。另有 11 个自然历史错误标签只检出 6 个，
说明“可辩护的选点”与“数据集最终选点”之间仍存在开放性边界。Critic 只改变两个字段，且两处均使
provisional 分数退化。

这些发现会进入后续开发，但不会修改后重跑本组并继续称其为盲测。完成改进后必须另建、先复核再冻结
的 `blind-v3`。由于本组标签来自数据集历史与 `verify` 标记而非独立安全专家，本节始终称其为
provisional 结果。
