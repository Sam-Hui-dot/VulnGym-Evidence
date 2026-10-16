# Blind v3 证据复核表

复核在任何 Blind v3 预测生成前完成。复核者查看公开数据版本差异、固定 commit 源码、GitHub Reviewed
Advisory、Patch（若存在）和 taxonomy；没有把 `verify=1` 或“后续版本发生变化”自动等同于正确答案。

| 案例 | 非 `correct` 标签 | 主要依据 |
|---|---|---|
| Airflow entry-00464 | `vuln_ids: incorrect` | 标题声明 CVE-2025-54550，但编号列表为空；旧 sink/trace 仍可辩护 |
| MLflow entry-00102 | 无 | `spark_udf` 是有效上游入口；旧 trace 到 `chmod(0o777)` 成立 |
| NeMo entry-00335 | 无 | 变更主要为缩进、描述和新增函数签名节点，旧位置与 sink 仍成立 |
| OpenClaw entry-00122 | `entry_point: incorrect` | import 语句不是外部或持久化数据入口；其余链路由 fix 支持 |
| Paperclip entry-00438 | `L1/L2/trace: incorrect` | fix 新增 `assertAuthenticated`；两个 trace 节点为 line 0 |
| Flowise entry-00061 | 无 | 公告、源码数据流、受影响版本与修复相互支持 |
| Langflow entry-00071 | `L1/L2: incorrect` | fix 新增 `get_current_active_user`，属于缺少认证而非授权 |
| n8n entry-00090 | `L1/L2: uncertain` | helper 暴露成立，但 Agent 边界、沙箱逃逸与权限管理分类并非唯一 |
| Open WebUI entry-00057 | 无 | 链路终止于 `innerHTML`，fix 在同一数据流加入 DOMPurify |
| WeKnora entry-00271 | 无 | 公告点名 tenant 路由与 ownership 缺口，候选在受影响 v0.3.1 |
| OpenClaw entry-00410 | `entry/critical/trace: incorrect` | 历史入口、sink 和全部 trace 使用 line 0，无法定位 |
| n8n entry-00352 | `entry: uncertain; critical/trace: incorrect` | 旧 entry 可作上游入口；sink/trace line 0 且未闭合到执行点 |
| Flowise entry-00064 | `critical/trace: incorrect` | `/register` 入口合理；旧 sink 与多数 trace 为 line 0 |

汇总：87 `correct`、14 `incorrect`、3 `uncertain`。这些是项目内证据复核标签，不称独立专家 Gold。
每条完整八字段标签与详细理由均保存在 `configs/blind-v3-selection.json`，物化后的原 provisional 标签继续
保存在 `out/blind-v3/review-queue.jsonl`，便于审计标签为何改变。
