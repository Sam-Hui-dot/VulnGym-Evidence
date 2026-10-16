> 0.2.2 入口已更新：正式首页先选项目/案例，模型在网页设置；旧按钮和终端输入 Key 的步骤以 [START_HERE.md](../START_HERE.md) 为准。新增功能尚未运行验收，见 [当前记录](DELIVERY_STATUS_20261016.md)。

# 快速开始

当前入口以 INSTALL.md 为准。演示样例为 FastMCP；新增报告提取和语义复核需要模型，字面位置控制无需 Key。

# 安装与复现（2026-10-06）

需要 Python 3.10+ 与 Git，推荐 Linux/WSL。核心为 Python 标准库；模型调用需自己的 DashScope 账户。

## 源码入口

解压 Source.zip，进入 Source 目录。路径里不要覆盖原项目。

```bash
PYTHONPATH=src python3 -m vulngym_evidence --help
python3 scripts/prepare_recording_demo.py --root materials
PYTHONPATH=src python3 -m vulngym_evidence serve --repositories-root materials --port 8765
```

准备材料命令只获取固定公开 Git 对象，不运行 FastMCP。如果已解压 Demo-Materials.zip 到材料包根目录，可直接使用其中的 materials，无需联网获取。

## wheel 安装

在材料包根目录运行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --no-deps wheel/vulngym_evidence-0.1.0-py3-none-any.whl
.venv/bin/vulngym-evidence serve --repositories-root materials --port 8765
```

不要混用旧版同名 wheel，使用本次包及 SHA-256 清单。模型环境不开启时只做确定性核对。

## 在线与录制

源码目录：

```bash
bash scripts/start_recording.sh --repositories-root ../materials
```

这里的 ../materials 指材料包根目录；如果直接在项目目录准备材料，则改为 materials。
打开 http://127.0.0.1:8774/。Key 在终端输入，不回显，不要录制输入过程。录制前先停止旧服务，再启动一个新服务清空提取缓存。在线费用属于运行者账户；不要自动重试。

Windows 当前开发目录可直接双击 start-evidence.cmd，或在 WSL 运行以上命令。应用核心便携包按 Linux/WSL 验证，未宣称 Windows 原生或第二台机器验证。

## 三项零模型控制

导入 configs/evidence/release-fastmcp-supported.json、release-fastmcp-contradicted.json、release-fastmcp-uncertain.json，分别使用新的输出目录：

```bash
PYTHONPATH=src python3 -m vulngym_evidence verify --input configs/evidence/release-fastmcp-supported.json --repositories-root ../materials --output-dir out/control-supported
```

预期依次为 supported、contradicted、uncertain，模型调用均为 0。这三项只检查位置、错误引用或缺文件，不属于语义准确率评测。

## 恢复与导出

保留结果页的 ?job= 地址，可刷新恢复；服务重启后可按同一 job 地址读取完整性检查后的落盘结果。没有历史任务浏览列表。导出 Markdown、JSON 与 HTML；Edge 弹出打开/另存为/保存时点保存。插件未收到下载通知不等于内容不存在，可打开完整 HTML 报告或核对输出目录。

录制专用启动器固定使用 qwen3.8-flash，并保留 recording-budget.json；请求前上限 10 次 HTTP、100,000 Token、估算 0.2 元。该限制只约束此启动进程，不是整个阿里云账号。失败不自动重试，不删除账本来反复运行。

本机 WSL 缺少 ensurepip 时的替代安装方法（本次实际采用）：

```bash
python3 -m venv --without-pip .venv
python3 -m pip --python .venv/bin/python install --no-index --no-deps wheel/vulngym_evidence-0.1.0-py3-none-any.whl
```

如果系统也没有 pip，可直接使用源码入口，无需为本项目安装第三方运行依赖。

本次交付源码完整测试命令：`PYTHONPATH=src python3 -m unittest discover -s tests -t . -q`（221 项）。历史 T1 测试材料保留于 artifacts，不作为新版效果宣传。
