# 语义 Gold 复核指南

`evaluate-semantic` 需要独立人工复核的 JSONL，不能把 Agent 自己的输出复制成 gold。每行使用
`case_id`（有变异样本时优先）或 `entry_id` 标识案例，并在 `labels` 中完整填写六个语义字段：

```json
{"entry_id":"entry-00001","labels":{"entry_point":"correct","critical_operation":"incorrect","vuln_category_l1":"correct","vuln_category_l2":"uncertain","vuln_title":"correct","trace":"incorrect"}}
```

## 标注口径

- `correct`：现有证据足以支持候选值是合理且可用的表达。
- `incorrect`：现有证据足以反驳候选值，且应指出冲突或更合理候选。
- `uncertain`：公开材料不足、存在无法消解的多解，或复核者无法给出可靠结论。
- Entry Point 和 Critical Operation 可以有多个合理答案；判断“候选是否可辩护”，不要强造唯一点。
- 行号必须与声明代码一致；代码漂移或多匹配需要单独复核，不能套固定 `±5` 规则。

建议每条记录保留 `reviewer`、`reviewed_at`、`notes`，必要时增加第二位复核者。若两位复核者不一致，
先标记 `uncertain` 或进入仲裁，不让 Agent 参与决定自己的 gold。

## 运行

```bash
PYTHONPATH=src python3 -m vulngym_agent evaluate-semantic \
  --semantic out/pilot-v1/semantic-results.jsonl \
  --gold configs/semantic-gold.dev.jsonl \
  --output out/pilot-v1/semantic-evaluation.json
```

输出同时报告 Judge 与最终 Critic 结果，包括字段准确率、弃权率、incorrect precision/recall、
高置信错误、完整案例严格匹配和 Critic accuracy delta。缺失预测会计入总体准确率分母。
