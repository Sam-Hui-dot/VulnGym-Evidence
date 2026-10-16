# 最终提交清单

## 必交材料映射

| 要求 | 仓库材料 | 状态 |
|---|---|---|
| 评审入口 | `SUBMISSION_OVERVIEW.md`、`docs/INDEX.md` | 已完成；两页总览与分层导航 |
| Agent 源代码 | `src/vulngym_agent/` | 已完成 |
| 开源许可证 | `LICENSE`（Apache-2.0） | 已完成 |
| 系统架构与设计 | `docs/DESIGN_SUMMARY.md`、`docs/ARCHITECTURE.md` | 已完成；简版 1–3 页，详版供审计 |
| Prompt 设计历史 | `docs/PROMPT_HISTORY.md`、`src/vulngym_agent/prompt_registry.py` | 已完成 |
| AI Coding 使用记录 | `docs/AI_CODING_LOG.md`、Git commit 历史 | 已完成 |
| 调试与坑点 | `docs/EXPERIMENT_LOG.md`、`docs/DECISIONS.md` | 已完成 |
| 效果评估与边界 | `docs/SELF_EVALUATION.md`、`docs/GOLD_REVIEW_GUIDE.md`、`docs/BLIND_V2_REVIEW_SHEET.md` | 已完成 |
| 仓库级开发对照 | `docs/REPO_HOLDOUT_EVALUATION.md`、`artifacts/repo-holdout-v1/summary.json` | 已完成 |
| 冻结八字段评测 | Blind v2/v3/v5/v6 协议、冻结 manifests、不可变结果与失败分析 | Blind v6 为 62/64、10/10 错误检出；明确仅覆盖 2 仓库且非专家 Gold |
| Commit provenance 加固 | Packet 0.9.0、对抗负例、Post-v6 零模型重放与动态复算 | 已完成；59/64，不覆盖冻结结果 |
| 有界跨文件取证 | Packet 0.11.0，一跳唯一 helper 定义、严格预算与歧义弃权 | 已完成 |
| 最终多仓冻结验证 | `artifacts/final-blind-v1/` | 5 仓/3 语言冻结；唯一运行完成 4/5，27/40（完成项 27/32） |
| 成本与延迟 | `docs/COST_AND_LATENCY.md` | 已完成 |
| 可运行演示 | `scripts/run_recording_demo.sh`（真实 Qwen）、`scripts/show_demo.py`（离线备用） | 已完成 |
| 批次系统性错误分析 | `analyze-systemic`、`systemic-analysis.json/.md` | 已完成；重复信号均附案例 ID，不冒充已证明根因 |
| 单一 ZIP 组装 | `scripts/build_final_submission.py` | 已完成；收到视频后自动打包并检查 200 MiB 上限 |
| 演示视频 | 按 `docs/DEMO_SCRIPT.md` 录制 | 待参与者录制 |
| 远端仓库 | GitHub 私有仓库，提交前按活动要求设置可见性/权限 | 已创建 |

## 提交前技术检查

- [x] 运行 `python3 scripts/verify_delivery.py`：最新单元测试、必需文件、演示产物与全部保留
  评测摘要通过。
- [x] Blind v3 在预测前完成 13/13 案例证据复核，冻结 87 correct / 14 incorrect / 3 uncertain。
- [x] Blind v3 唯一冻结运行结果 70/104 已固化且由交付检查防漂移。
- [x] Post-v3 Commit/Trace/taxonomy 定向加固完成，4 条已见失败回归为 31/32；未冒充新盲测。
- [x] Blind v5 完成 6 条/48 字段唯一冻结运行，原始 26/48；修复本地源码误伤后的 33/48 仅作诊断。
- [x] Blind v6 完成 8 条/64 字段唯一冻结运行，62/64；10/10 错误检出，选择性 Critic 共 10 次调用。
- [x] Packet 0.9.0 移除唯一子提交循环论证；Post-v6 零模型重放 59/64，原冻结结果未覆盖。
- [x] Packet 0.11.0 加入一跳跨文件唯一 helper 证据；歧义、动态导入和二跳路径继续弃权。
- [x] Final Blind v1 在预测前冻结 5 仓/3 语言与参考，唯一正式运行触及 8 次调用上限并保留 4/5 结果。
- [x] 最终文档提交后 `git status --short` 没有未提交文件。
- [x] Top 3 hardening 分支已推送到私有 GitHub 远端。
- [x] Hardening 分支已 fast-forward 合并到 `main` 并推送远端。
- [x] 最新 Packet 0.11.0 / Prompt 1.7.0 / Qwen provider 变更通过当前工作树交付复核。
- [x] 发布提交版本已更新为 `1.2.1`；最终标签 `v1.2.1` 指向本清单所在发布提交。
- [x] 仓库中没有 `.env`、API Key、Token、私人对话或未公开漏洞。
- [ ] 视频没有显示 Key、账号余额、私人路径或聊天窗口。
- [ ] 视频展示一次真实 Qwen 端到端运行；若启用备用回放，明确区分离线结果、真实在线实验和 provisional 参考。

## 正式提交时需要填写

- 仓库链接；
- 版本标签或 release 链接；
- 演示视频链接；
- 一句话项目简介；
- 运行环境和快速演示命令；
- 已知限制：静态证据边界、未使用官方隐藏集、参考标签不是独立人工 Gold。

活动若另行发布命名、可见性、压缩包或平台上传要求，以最新通知为准。

全新目录复核命令：

```bash
bash scripts/verify_clean_archive.sh
```
