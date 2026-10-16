# 录屏操作指南

最终视频由参与者本人录制，项目已经准备好命令、台词和画面顺序。本人录制有助于答辩时复述同一套
逻辑，也不会把 API Key 或私人窗口交给自动化录屏工具。

## 最简单方案

1. 按 `docs/DEMO_SCRIPT.md` 打开提交总览、简明设计、系统性分析报告和 WSL 终端。
2. Windows 按 `Win+Alt+R` 开始和结束录制。
3. 按脚本依次展示架构、运行一次受控的真实 Qwen 案例、展示新生成报告、评测记录与交付自检。
4. 使用耳机麦克风，语速保持每分钟约 220–260 个汉字。
5. 录完只做首尾裁剪即可，不需要复杂剪辑或背景音乐。

## 备用方案：OBS

- 来源选择“显示器采集”，画布和输出均设为 1920×1080。
- 帧率 30 FPS，编码器保持默认硬件编码；麦克风电平峰值约 -12 dB 至 -6 dB。
- 录制格式优先 MKV，结束后使用 OBS“文件 → 重新封装录像”转为 MP4，避免异常中断损坏整段视频。

## 录制前试跑

先在 WSL 终端运行一次，确认本地 WeKnora 仓库、`.env` 和 Qwen API 均可用：

```bash
cd /home/sam/rhinobird/VulnGym-Agent
bash scripts/run_recording_demo.sh
```

正式录制时改用 `bash scripts/run_recording_demo.sh --open`。脚本只读取 `.env`，不会打印 Key；它会先
展示输入摘要并暂停，按 Enter 后才开始取证和模型调用，结束时自动打开本次新生成的 HTML 报告。

## 不应现场展示的内容

- `.env`、任何 Key、账号余额和 Provider 后台；
- `.env` 文件内容或 Provider 后台；现场模型等待期间只解释 Agent 正在执行的步骤，不反复重跑；
- 大段源码滚动、未经解释的 JSON 或不可复现的准确率数字；
- 微信群、导师私聊和其他参与者信息。

完整台词、命令和时间轴见 `docs/DEMO_SCRIPT.md`。

## API 失败时的备用方案

若正式录制时出现余额、网络或 Provider 错误，停止本次录制，先保留错误文本供排查，不要连续重试。
确实无法恢复时才使用：

```bash
python3 scripts/show_demo.py
```

并把口播改为“这是同一案例已保存结果的离线回放”。备用方案能证明报告结构和判断逻辑，但展示力度
低于真实在线运行，因此正常情况优先使用 `run_recording_demo.sh`。

## 录完以后

1. 文件名改为 `VulnGym-T1-Sam-Demo-final.mp4`。
2. 从头回看，确认画面清楚、声音完整且没有密钥、余额、聊天或 `.env`。
3. 把视频保存到 Windows 任意位置，然后把完整路径发给协作者；由交付脚本把视频和代码合成活动要求的
   单一 ZIP。不要手工把多个文件分别上传。

交付脚本（由协作者在收到视频路径后运行）：

```bash
python3 scripts/build_final_submission.py /mnt/c/Users/Sam/Videos/VulnGym-T1-Sam-Demo-final.mp4
```

脚本只打包 Git 已跟踪文件和这一个视频，会拒绝脏工作树或被 Git 跟踪的 `.env`，检查 200 MiB 上限，
并同时生成 SHA256 校验文件。
