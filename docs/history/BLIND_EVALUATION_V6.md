# Blind v6：误报压缩与选择性 Critic 评测

Blind v6 用于检验 Blind v5 后的源码策略修复能否在保持错误检出率的同时减少误报。它不是主办方隐藏测试，也不冒充独立专家 Gold。

## 冻结设计

- 8 条此前未进入模型评测的 entry/report：4 条历史版本、4 条已验证干净对照。
- 64 个字段标签中，54 个 `correct`、10 个 `incorrect`；全判正确基线为 84.375%。
- 样本来自 2 个仓库，因此本轮验证的是特定策略，不用于证明跨项目总体泛化。
- 人工复核在模型调用前完成；reference 不进入 Judge 或 Critic 请求。
- 公告、候选记录、固定提交源码、调用链检查和候选 Patch 均已缓存。

## 单次运行规则

- 模型：`qwen3.8-max`，关闭 thinking，串行运行。
- 先运行 8 次 Judge；Critic 仅复核“整条接受”或低置信拒绝。
- 物理 API 尝试总数最多 12 次；传输重试与契约重试也计入上限。
- 不根据答案重跑；调用失败会保留为失败结果。
- 运行前校验所有冻结文件哈希、生产行为基线和干净工作区。

```bash
PYTHONPATH=src python3 scripts/run_blind_v6.py       # 只做 preflight
PYTHONPATH=src python3 scripts/run_blind_v6.py --run # 明确消耗 API 额度
```

本轮主要观察 `incorrect recall`、`incorrect precision`、弃权率、Critic 实际触发数和总 Token。即使结果提升，也只能作为新的有限盲测证据，不能宣称接近真实环境“全对”。

## 唯一冻结结果

- 8/8 案例完成，62/64（96.875%），case exact 6/8，证据覆盖 100%。
- 10/10 个预登记错误全部检出；incorrect precision / recall / F1 为 90.91% / 100% / 95.24%。
- 仅剩 1 个误报和 1 个弃权，均位于开放的 L2 taxonomy 边界；其余七类字段全部匹配。
- 8 次 Judge、2 次 Critic，共 10 次物理 API 请求；Critic 没有改判，证明选择性触发节省了 6 次无效复核。
- 总计 106,879 input Token、11,480 output Token，Provider 阶段 199.51 秒。

`out/blind-v6-run/` 为开发阶段的运行输出目录；最终交付包保留的冻结复核副本位于 `artifacts/blind-v6/repro/`（包含持久化的 Judge/Critic 语义结果及 provider metadata、八字段预测报告和真值参考标签），这些副本与冻结运行时的哈希完全一致。`scripts/verify_delivery.py` 会直接从这些原始产物重新计算评测指标并校验哈希源流。

### 第三方离线复核入口

在不联网、不调用任何模型的情况下，可直接执行确定性复核：

```bash
# 推荐：一键执行交付物完整性与动态复算校验（包含全部单元测试）
python3 scripts/verify_delivery.py

# 或使用评测 CLI 独立复算 Blind v6 指标（输出至临时路径，不覆盖已有产物）
PYTHONPATH=src python3 -m vulngym_agent evaluate-submission \
  --submission artifacts/blind-v6/repro/submission.jsonl \
  --reference artifacts/blind-v6/repro/reference.jsonl \
  --output /tmp/blind-v6-recomputed-evaluation.json
```
