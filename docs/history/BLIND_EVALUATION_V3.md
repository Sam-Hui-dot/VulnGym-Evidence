# Blind Evaluation v3 协议

## 为什么需要第三轮

Blind v2 的唯一冻结运行只有 59/80，并暴露了标题适配、多行起始行和省略号摘要三类工程错误。修复这些
问题后不能重跑 v2 再把结果称为盲测，因此另建 Blind v3。Blind v3 在任何预测生成前完成案例选择、
公开证据采集和 104 个字段标签复核，绑定行为 commit `231aec9`、Packet `0.6.0`、Prompt `1.2.0`。

本实验仍不是主办方隐藏测试，也不是独立安全专家 Gold；它是公开数据上的、对开发 entry 与 report
隔离的证据复核评测。

## 数据与区分度

- 13 个案例、10 个仓库、104 个字段；
- 5 条 `v0.1.4 verify=1` 干净案例；
- 8 条来自 `v0.1.0` / `v0.1.1` 的自然历史候选；
- 人工证据复核后：87 `correct`、14 `incorrect`、3 `uncertain`；
- 全部预测 `correct` 的朴素基线为 87/104（83.65%），不能靠全猜正确取得满分；
- 选择排除了此前使用的 30 个 entry 和 29 个 report ID。

VulnGym v0.1.4 只有 23 个仓库，而这 23 个仓库均已在开发或 Blind v2 中出现，因此无法诚实宣称仓库
隔离。该限制预先写入 selection 和 manifest，不包装成“全新仓库隐藏集”。新增案例依然使用未见 entry
和 report，并禁止根据本轮结果调参重跑。

## 参考标签如何形成

版本差异只生成 provisional 标签，不能直接当答案。冻结前逐案交叉核对：

1. 固定候选 commit 的真实源码位置与代码；
2. GitHub Reviewed Advisory 的标题、编号、影响和 CWE；
3. 官方修复 commit、公告引用 PR 或可解释的直接子提交差异；
4. TraceInspector 的顺序、跨文件调用和无法解析边；
5. VulnGym 两级 taxonomy。

复核纠正了“版本有变化就等于旧值错误”的错误假设。例如 Airflow 只是把整数行扩为范围并补充描述，
旧 Critical/Trace 仍可辩护；Paperclip 和 Langflow 的公告/修复证明问题是缺少身份认证，不是授权缺失；
n8n legacy Code-node 的两级分类存在合理多解，因此保留 `uncertain`。

完整逐案结论见 `configs/blind-v3-selection.json` 和 `docs/BLIND_V3_REVIEW_SHEET.md`。

## 冻结与重现

```bash
PYTHONPATH=src python3 -m vulngym_agent build-blind-dataset \
  --repository ../VulnGym \
  --selection configs/blind-v3-selection.json \
  --output-dir out/blind-v3

PYTHONPATH=src python3 -m vulngym_agent index-repositories \
  --input out/blind-v3/candidates.jsonl \
  --output out/blind-v3/repository-index.json \
  --repositories-root ../vulngym-repos

PYTHONPATH=src python3 -m vulngym_agent prepare-evidence \
  --input out/blind-v3/candidates.jsonl \
  --output out/blind-v3/evidence.jsonl \
  --repositories-root ../vulngym-repos \
  --fix-map configs/blind-v3-fixes.json \
  --advisory-cache configs/advisories/blind-v3.jsonl \
  --context-lines 12
```

冻结时 10/10 仓库解析、13/13 候选 commit 存在、13/13 公告匹配、13/13 Trace 分析可用，10 条有
Patch 对照。92 个声明位置中 75 个可读；另外 17 个 `invalid_location` 正是历史负例中的行 0 证据，
不是资源丢失。精确哈希见 `artifacts/blind-v3/evidence-manifest.json`。

## 单次运行与报告规则

冻结提交之后只运行一次 Judge→Critic。无论结果好坏都保留，不依据结果修改本轮 Prompt、工具、标签、
fix map 或上下文后重跑并继续称 Blind v3。最终至少报告 accuracy、incorrect precision/recall/F1、
uncertain 比例、case exact match、字段 confusion matrix、缺失预测、Evidence coverage、Token 与耗时。

```bash
PYTHONPATH=src python3 -m vulngym_agent evaluate-submission \
  --submission out/blind-v3-run/submission.jsonl \
  --reference out/blind-v3/reference.jsonl \
  --output out/blind-v3-run/evaluation.json
```

不可变运行摘要见 `artifacts/blind-v3/result-summary.json`。

## 唯一冻结运行结果

- DeepSeek V4-Flash 完成 13/13 条、26/26 次 Judge/Critic 调用，无缺失预测；
- 八字段共 70/104，accuracy 67.31%；
- incorrect precision 43.48%、recall 71.43%、F1 54.05%；
- uncertain 14/104（13.46%），case exact match 0/13，Evidence coverage 100%；
- 资源：201,925 input Token、32,246 output Token，模型累计 268.60 秒。

字段准确率为：IDs 13/13、Critical 12/13、Entry 10/13、L2 10/13、Title 10/13、L1 9/13、
Trace 6/13、Commit 0/13。Commit 的 13 个失败全部是提交适配器 `uncertain`：候选 commit 均存在，
但适配器只接受公告显式 `vulnerable_commits`，尚未利用 patch provenance。Trace 则是相反方向的过度
确信：6 条可辩护链路被判错，1 条被弃权，主要把轻量静态分析无法证明的边、或未写入候选的实现细节，
直接当成“链路错误”。

Critic 只修改了两个 Title：一次修正 Judge，一次引入新错误，净收益为零。本结果不删除、不按结果修改
Prompt 后重跑；它从此作为下一阶段提交适配器、Trace 判定口径和 taxonomy 交叉验证的失败基线。
