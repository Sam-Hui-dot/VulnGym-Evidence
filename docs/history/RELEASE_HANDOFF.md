# v1.2.1 交付交接

## 当前结论

代码、文档、冻结评测、可读报告、成本表、固定演示与批次系统性错误分析已经收网。
`codex/top3-hardening` 已 fast-forward 合并到 `main`；当前发布候选通过 134/134 单元测试、91/91
必需文件、真实录屏演示入口、离线备用演示、CLI、系统性分析产物动态复算与全部保留评测复算。最终发布标签和代码 ZIP 由
本提交生成；包含视频的活动上传包仍需参与者录制后组装。

这不等于保证 Top 3，也不等于官方隐藏集满分。最强错误检出证据是 Blind v6 的 10/10；最终多仓
Final Blind v1 冻结 5 仓/3 语言，唯一运行在 8 次物理调用上限内完成 4/5，完整分母为 27/40。
缺失、误报与 `uncertain` 均保留，没有为分数补跑。

## 现在只需参与者完成

1. 按 `docs/DEMO_SCRIPT.md` 录制 3–5 分钟视频，文件名使用 `VulnGym-T1-Sam-Demo-final.mp4`。
2. 回看视频，确认没有 `.env`、Key、账号余额、私人聊天和其他参与者信息。
3. 正常使用 `scripts/run_recording_demo.sh --open` 展示真实 Qwen 调用；仅在 API 故障时使用离线备用回放。
4. 将视频路径交给协作者，生成包含代码与视频的单一最终 ZIP，再按活动最新通知上传。

最终 ZIP 由 `scripts/build_final_submission.py` 从干净 Git 提交和视频组装；脚本不会带入 `.env`、`.git`
或其他未跟踪文件，并会检查平台 200 MiB 上限、输出 SHA256。

## 演示前快速检查

```bash
cd /home/sam/rhinobird/VulnGym-Agent
python3 scripts/verify_delivery.py
bash scripts/run_recording_demo.sh
```

第二条会真实调用 Qwen；若只检查离线备用回放，运行 `python3 scripts/show_demo.py`。

Windows 文件资源管理器可粘贴：

```text
\\wsl.localhost\Ubuntu\home\sam\rhinobird\VulnGym-Agent
```
