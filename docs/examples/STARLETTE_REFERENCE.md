# Starlette 教学报告：作者参考

输入：starlette-report.md；预先整理的核查项：starlette-input.json。页面“更多设置 → 其他教学样例”只加载报告，随后由用户启动提取；预先整理的 JSON 可通过“导入声明 JSON”使用，两条路径的来源不同。

源码版本：`6beaa2e39d3381e1d7ddb89d4cc7cbb8c7ac0961`。来源：[Starlette CORS 源码](https://github.com/encode/starlette/blob/6beaa2e39d3381e1d7ddb89d4cc7cbb8c7ac0961/starlette/middleware/cors.py#L93-L100)。许可证随附于 STARLETTE_LICENSE.md，Git bundle 位于 configs/evidence/starlette.bundle。

| 报告中的具体说法 | 作者参考 | 对应依据 |
|---|---|---|
| 正则用 search，任意子串匹配即可通过 | 与源码矛盾 | 第 97 行调用 fullmatch，匹配成功后第 98 行返回 True |
| 执行到正则分支时，完整匹配则返回 True，否则查来源列表 | 证据支持 | 第 97—100 行直接展示此分支与回退逻辑；声明限定为已到达正则判断，不覆盖前面的允许所有来源分支 |
| 生产实例关闭全部来源，只批准两个域名 | 证据不足 | 第 94 行读取实例配置，但教学输入未提供生产实例的配置值 |

这些参考在模型运行前编写，用于解释教学案例。2026-10-12 未为本案例调用在线模型，没有新准确率成绩。不要把以上预期填成模型的实际输出。

本案例来自此前使用过的仓库和相关函数族，不属于独立留出评测。已有 11/11、15/15 的记录仍保留各自样本范围。
