> 0.2.2 入口已更新：正式首页先选项目/案例，模型在网页设置；旧按钮和终端输入 Key 的步骤以 [START_HERE.md](../START_HERE.md) 为准。新增功能尚未运行验收，见 [当前记录](DELIVERY_STATUS_20261016.md)。

# 录制启动与准备

先读“拍摄脚本与口播.md”。当前版本真实预演已通过；用户亲自录制，协作者不合成最终视频。

## 当前电脑最快入口

WSL 终端：

```bash
cd /home/sam/rhinobird/VulnGym-Evidence-v2
bash scripts/start_recording.sh --repositories-root /home/sam/rhinobird/vulngym-repos
```

输入 DashScope Key 时不回显，录制前完成。新服务避免使用旧提取缓存。Edge 打开 http://127.0.0.1:8774/ 。只运行一次提取和一次三声明复核，不连续点击重跑。

Windows 文件资源管理器目录：\\wsl.localhost\Ubuntu\home\sam\rhinobird\VulnGym-Evidence-v2 。双击 start-evidence.cmd 也能启动；端口 8765 如已有服务占用，使用上面的 8774。

## 便携交付包

解压 Source.zip 和 Demo-Materials.zip，得到并列 Source 与 materials。进入 Source，使用：

```bash
bash scripts/start_recording.sh --repositories-root ../materials
```

需要 Python 3.10+、Git、WSL/Linux。无需安装或执行 FastMCP。素材 zip 中只有固定只读 Git 对象；也可用 scripts/prepare_recording_demo.py 获取。

## 核对与保存

加载演示报告，AI 提取；对照原文确认两条语义内容，补充一条引用内容。补充字段.txt 提供完全可复制文本。开始复核，保留 job URL。报告下载遇到 Edge“打开/另存为/保存”请选择保存；也可打开完整 HTML 报告。

录制时不在等待期间切换其他任务。原片建议保存在新的目录，旧 T1 录像不覆盖。任务结果位于 out/evidence-web（子目录以任务 ID 命名）；只提交经过筛选的结果，不提交 .env、Key、账号页面或在读证明到公开代码仓库。

代码与视频发布和赛事提交均尚未执行。片头与材料使用已备案全名，页面简称 VulnGym Evidence，无需修改上海报名。

录制专用启动器固定使用 qwen3.8-flash，并保留 recording-budget.json；请求前上限 10 次 HTTP、100,000 Token、估算 0.2 元。该限制只约束此启动进程，不是整个阿里云账号。失败不自动重试，不删除账本来反复运行。
