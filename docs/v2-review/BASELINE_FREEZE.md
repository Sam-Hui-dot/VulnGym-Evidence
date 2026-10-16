# v1 冻结基线与 v2 工作副本

冻结日期：2026-10-04。冻结是版本与材料保留约定，不设置旧目录的只读权限。

## 保留位置

原 T1：`\\wsl.localhost\Ubuntu\home\sam\rhinobird\VulnGym-Agent`

第一版源码：`\\wsl.localhost\Ubuntu\home\sam\rhinobird\VulnGym-Evidence`

第一版材料：`C:\Users\Sam\Videos\VulnGym-Evidence-参赛材料-v1`

第一版总包：`C:\Users\Sam\Videos\VulnGym-Evidence-参赛材料-v1.zip`

新工作副本：`\\wsl.localhost\Ubuntu\home\sam\rhinobird\VulnGym-Evidence-v2`

## 精确基线

- 总包 SHA-256：`a337c2e4353f41d8301b49ae2f459959dfbc5771a173fa7982c0632430857cc5`
- Source.zip SHA-256：`cb5a338ea2b03f495bb3cffa35400451357f51516fb6016508cbd7b864427bec`
- 第一版材料目录文件数：115。
- Source.zip 文件数：270；已逐文件核对冻结源码与原工作目录相同。
- 克隆继承的 Git HEAD：`518f14eaa70eb3d5a5c937fb10aa3816c611933e`。

旧仓库中 Evidence 功能尚有未提交改动，因此普通 Git 克隆不足以复制它们。
新副本先独立克隆 Git 历史（无硬链接），再逐文件覆盖 Source.zip，补齐全部当前源码，移除新副本的 origin。
没有复制旧输出缓存、密钥或环境文件，也没有生成新的代码提交或向远程推送。

## 本轮新增

仅新增设计审核稿、页面布局示意、拍摄脚本、口播、演示报告草稿和基线说明。
新版后端及服务页面尚未修改，合并演示未执行，旧成绩不作为 v2 成绩。
后续实现均在 v2 工作副本，原项目和第一版材料保持原样。
