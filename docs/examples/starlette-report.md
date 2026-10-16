Starlette 跨域来源检查：教学复核报告

这是一份根据公开源码编写的教学报告，用于练习核对具体说法，不是实际漏洞举报。
代码仓库：https://github.com/encode/starlette
代码版本：6beaa2e39d3381e1d7ddb89d4cc7cbb8c7ac0961

一、匹配方式
报告声称：这个正则分支使用 search，只要 origin 的任意子串匹配即可通过。
引用文件：starlette/middleware/cors.py
引用行号：97
引用代码：
        if self.allow_origin_regex is not None and self.allow_origin_regex.fullmatch(origin):

二、函数行为
报告声称：执行到正则判断这一分支时，正则完整匹配 origin 则返回 True；否则会检查 origin 是否位于 allow_origins 列表。
引用文件：starlette/middleware/cors.py
引用行号：97-100
引用代码：
        if self.allow_origin_regex is not None and self.allow_origin_regex.fullmatch(origin):
            return True

        return origin in self.allow_origins

三、实际部署
报告声称：当前生产实例没有启用允许所有来源，并且 allow_origins 只包含两个经过批准的域名。
引用文件：starlette/middleware/cors.py
引用行号：94
引用代码：
        if self.allow_all_origins:
