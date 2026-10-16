# Post-v6 Commit provenance 加固

## 为什么需要修复

T1 的 `commit` 字段主张“这条记录填的是漏洞版本提交”。旧适配器会在候选提交只有一个直接子提交时，
以 `0.75` 置信度选中该子提交；提交层又把 `>= 0.75` 当作足够证明。于是一个只修改 README、锁文件或
普通功能的后续提交，也可能被误称为“漏洞修复”，再反推候选 Commit 正确。这是循环论证，不是可靠
provenance。

## 新规则

Packet 0.9.0 将 Patch 证据分成三档：

- `verified`：可信显式 fix-map，或官方公告明确标为 fixed/supporting fix；同时满足候选是修复提交的
  Git 祖先，并存在可检查的源码差异；
- `supported`：源码重叠、修复关键词等启发式线索存在，但没有权威 Commit 角色；
- `weak`：只有 Git 拓扑，或后续仅修改文档、锁文件等非源码内容。

只有 `verified` 可以让 Commit 字段确定性输出 `correct`。普通公告 `/commit/<sha>` 引用保持
`referenced_commits`，不会自动升格；没有祖先关系的公告 Commit 也不能验证候选。公告列出多个修复时，
候选排序优先选择同时满足角色、祖先关系和源码差异者。

## 回归与结果

单元测试覆盖 README-only、appcast/lockfile、普通引用、无祖先关系、后代修复、路径迁移和显式 fix-map。
随后复用 Blind v6 冻结的 `semantic.jsonl` 与 `reference.jsonl` 做零模型重放：

- 原冻结结果保持 `62/64`，文件和哈希不覆盖；
- 加固后结果 `59/64`，incorrect precision `10/11`、recall `10/10`；
- `entry-00116` 从 Commit `correct` 降为 `uncertain/weak`；
- `entry-00172`、`entry-00187` 从 Commit `correct` 降为 `uncertain/supported`；
- 其余有公告显式角色、祖先关系和源码差异的 Commit 保持 `correct/verified`。

三分下降是移除不可靠确定结论后的主动弃权，不包装成效果提升。它是已见 Blind v6 上的开发重放，
不是新的盲测。可复核文件位于 `artifacts/post-v6-provenance-hardening/`，交付检查会从 Evidence Packet
和冻结语义结果重建八字段报告、重算指标并核对 SHA-256。
