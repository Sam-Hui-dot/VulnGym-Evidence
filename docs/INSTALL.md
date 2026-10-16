> 0.2.2 入口已更新：正式首页先选项目/案例，模型在网页设置；旧按钮和终端输入 Key 的步骤以 [START_HERE.md](START_HERE.md) 为准。新增功能尚未运行验收，见 [当前记录](history/DELIVERY_STATUS_20261016.md)。

# 开始体验（0.2.0，2026-10-09）

## Windows

1. 将新版 Source ZIP 解压到一个新文件夹。保留目录结构，打开里面的 Source。
2. 双击 start-evidence.cmd。
3. 输入 1，按回车。浏览器自动打开，终端保留。
4. 点击页面右上方“查看完整演示”。三条结果来自 2026-10-07 保存的真实 AI 任务，本次查看无需 Key。
5. 要亲自核对源码，回到“1 粘贴报告”，点击左下“运行引用核对（无需 Key）”，再点右下“确认并复核 1 项 →”。这次读取的是随包固定源码，生成新的任务。

需要 Python 3.10+；亲自读取源码还需要 Git。没有 Python 时启动器会提示；没有 Git 时仍可查看保存的完整演示。当前机器已验证 Windows 原生启动；换一台电脑仍需具备这两项条件。

## WSL / Linux

在 Source 目录运行：

```bash
python3 scripts/start_desktop.py --mode demo
```

源码包已包含 FastMCP 固定版本的 Git 材料，无需联网下载或执行 FastMCP。开发目录仍可读取旁边的 vulngym-repos。

## 自己的报告与实时 AI

停止本次服务，在启动器输入 2，然后在终端输入自己的 DashScope API Key。不要把 Key 填进网页。

1. 页面点击“加载样例”，然后“提取核查内容 →”。
2. 点击候选卡片正文，对照左侧报告原句；勾选框决定本次复核范围。
3. 需要补字段时点“编辑核查项”，保存后点击“确认并复核 N 项 →”。
4. 结果页看原句、理由和带行号源码；点“展开上下文”查看邻近代码。
5. 点“导出报告 ▾”，下载 Markdown/JSON 或打开完整 HTML 报告。

可粘贴报告全文，也可点“导入文本”选择 UTF-8 .txt/.md；最多 100 KiB。填写其他仓库时，需先准备本地 Git 与对应版本，项目不会自动下载任意仓库。

[DashScope Key 控制台](https://bailian.console.aliyun.com/?tab=model#/api-key)。

桌面启动器固定 qwen3.8-flash，非思考模式；账本在输出目录，限制 10 次请求、100,000 Token、估算 0.2 元，失败不自动重试。该限制只约束本次启动器，不是整个阿里云账号。

## 恢复与保存

- 报告草稿只保存在当前标签页的 sessionStorage；刷新能恢复，关闭标签后不作为永久备份。
- 最近任务保存在当前浏览器，最多六条；任务结果在本机服务输出目录。
- 完整结果的 job 地址可刷新，并在同一输出目录重启服务后恢复。
- 重要材料请下载。输出目录被删除后，浏览器任务入口无法找回结果。

## 验证命令

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t . -q
node --test tests/evidence-ui.test.mjs
```

Python 是项目运行条件；Node 只用于开发者执行前端回归，不是体验项目的依赖。

## 投稿与部署

拍摄稿见 RECORDING_SCRIPT_20261009.md；本机验收见 PRODUCT_ACCEPTANCE_20261009.md。魔搭准备见 PUBLIC_DEMO.md；公开模式只展示固定历史结果，没有开放访客实时 AI 推理。
