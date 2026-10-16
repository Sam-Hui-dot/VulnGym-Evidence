# 魔搭创空间：公开固定样例

更新：2026-10-12。该版本让评委无需安装、无需 Key 就能阅读三类复核结果。展示 2026-10-07 北京时间保存的真实 AI 任务，页面标注时间；不接收访客报告，不执行新的模型推理。完整本机版继续支持自己的报告、AI 提取、人工确认、实时源码复核与导出。

## 已有空间与最近记录

空间：[SamiHui/VulnGym-Evidence](https://modelscope.cn/studios/SamiHui/VulnGym-Evidence)。2026-10-11 的记录为“运行中、非公开”；首页、三类结果、源码上下文、HTML 和 Markdown/JSON 下载均通过私有访问验收。此前代理 Host 的 403 与私有 iframe 下载丢失认证已经修复，修复现已合回主源码。

本轮没有重新部署或修改空间可见性。远端 README 尚待替换，准备好的访客说明见 MODELSCOPE_README.md；公开访客访问仍需在负责人确认公开后单独检查。

## 已准备的部署文件

- `Dockerfile`：Python 3.11 标准库服务，监听 `0.0.0.0:7860`。
- `ms_deploy.json`：Docker SDK、CPU 资源及端口声明。
- `scripts/start_public_demo.py`：启动公开只读模式。
- 默认输出目录 `/mnt/workspace/evidence-example`，只包含公开样例导出。

官方说明要求 Docker 服务使用 7860 端口，Docker 路线涉及阿里云绑定和实名认证，持久化目录为 /mnt/workspace。来源：[ModelScope 官方创空间部署说明](https://modelscope.cn/skills/modelscope/modelscope-studio)。

## 新建空间时的部署步骤

1. 登录 https://modelscope.cn/studios，确认账号可创建 Docker 创空间及所选资源。
2. 先建私有空间，上传 Source 中的部署文件与 src、scripts。不要上传 out、账本、Key 或个人报告。
3. 在空间运行配置中设置 `PUBLIC_DEMO_ORIGIN`，值为应用实际访问域名，格式为 `https://实际应用域名`。它不是带 /studios/用户名/作品名 路径的介绍页地址。以平台提供的实际运行地址为准。
4. 启动后检查主页、三类结果、源码详情、Markdown/JSON 导出、刷新重进。检查没有私人输入和任务查询接口。
5. 私有验收通过、负责人确认公开后再公开；最终比赛表填写空间介绍页链接。

不需要 DASHSCOPE_API_KEY。服务器拒绝全部 POST，阻止私人任务、输入、提取记录和结果目录查询。本机模式保留原有来源及 token 校验。

## 本机验证范围

10 月 9 日 Docker 镜像与本机容器已有 14 项 HTTP 验收；10 月 11 日完成真实平台私有访问和下载验收。10 月 12 日相关本地回归覆盖动态代理 Host、固定 GET 白名单、所有 POST 拒绝及本机来源保护。尚未完成的是公开访客访问，不是私有空间的启动和下载。

上传保留 Source 的 src/scripts 结构，使用根目录 Dockerfile。此前网页上传曾把包放到仓库根目录，其 Dockerfile.remote-copy 只适用于那次扁平目录；不要把它与标准 Source 目录混用。源码统一后，后续部署从同一个 Source 生成。
