# WP3 资源需求

> 状态说明：这是研发早期的资源假设与待确认问题，保留用于展示决策过程，不是当前交付阻塞项。
> 当前可运行方式、离线边界和 Provider 配置以根目录 `SUBMISSION_OVERVIEW.md` 与 `README.md` 为准。

## 现在不需要

- 不需要把 API key 写入仓库；
- 不需要一次克隆全部 23 个上游项目；
- 不需要 GPU 或训练模型；
- 不运行上游仓库中的任何二进制、脚本或测试。

## Pilot 源码缓存

第一轮需要以下 5 个仓库的 Git 对象，目标是读取指定漏洞 commit、源码和可能的直接修复子提交：

1. `https://github.com/n8n-io/n8n`
2. `https://github.com/Tencent/WeKnora`
3. `https://github.com/PrefectHQ/fastmcp`
4. `https://github.com/openclaw/openclaw`
5. `https://github.com/google/adk-python`

建议缓存目录：

```text
/path/to/vulngym-repos/<owner>/<repo>
```

下载前应先确认网络和磁盘预算。优先使用 `--filter=blob:none --no-checkout --single-branch`，
随后只按证据需要取回 blob；若指定漏洞 commit 不在默认分支，再单独 fetch 对应对象。

## 语义模型

证据层完成后，需要至少一个可程序调用的模型后端来建立基线。可提供任意一种：

- OpenAI-compatible API endpoint、模型名和通过环境变量注入的 key；
- 其他厂商的结构化输出 API；
- 本地 OpenAI-compatible 服务；
- 能从 stdin 接收 JSON、向 stdout 返回 JSON 的模型命令。

模型适配器必须满足：密钥不进 Git、输出可约束为 JSON Schema、记录耗时和 token/用量、失败可重试。

## 仍需导师确认

- 最终测试时是否允许访问模型 API；
- 是否提供目标仓库与 advisory/patch 本地缓存；
- 是否禁止一切网络，还是只禁止联网抓取测试答案；
- 模型、总 token、单条时间和并发限制；
- 最终输入输出的确切 JSONL Schema。
