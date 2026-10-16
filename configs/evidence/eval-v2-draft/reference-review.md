# 新仓库评测参考判断草稿

日期：2026-10-03。27 条参考判断尚待独立人工核对，未运行模型预测。
24 条语义项：支持/矛盾/不足各 8；3 条控制项单列。声明由开发代理依据源码编写，不是自然提交的漏洞报告。
四个仓库不在此前本地材料根目录中；模型训练是否接触过这些代码未知。Flask 与 Werkzeug 有依赖关系，同一函数家族中的样例相互相关。
不足项集中于缺少部署/调用方材料，因此不能代表全部静态调用链困难。后续取得真实报告时应另建样本层。
当前官网文档只作问题背景；参考依据下面的固定历史 Git 版本，避免把新版行为套到旧版。

局部行为参考以固定版本的原始库实现为前提，不包含运行时 monkeypatch 或子类重写。部署与上层调用方状态未提供；不足不等于这些检查不存在。

## 版本与背景来源

- pallets/werkzeug：3.1.3 / 6389612fd1ee1bd93579eed5026e8fd471d04abd；[官方背景文档](https://werkzeug.palletsprojects.com/en/stable/utils/)
- pallets/flask：3.1.1 / 7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[官方背景文档](https://flask.palletsprojects.com/en/stable/web-security/)
- encode/starlette：0.47.2 / 6ee94f2cac955eeae68d2898a8dec8cf17b48736；[官方背景文档](https://www.starlette.io/staticfiles/)
- fastapi/fastapi：0.116.1 / 313723494be79d4b24ccaa60e4f6d1f96c150fed；[官方背景文档](https://fastapi.tiangolo.com/tutorial/security/first-steps/)

## h01 · semantic · supported

此处把生成的 salt、password 和 method 传给 _hash_internal，并把返回的算法标识、salt 和哈希拼成返回值。

参考理由：generate_password_hash 的 107–109 行明确生成 salt、调用 _hash_internal，再返回 method$salt$hash；内部实现为 scrypt 或 pbkdf2，声明不涉及某部署的实际强度。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/security.py#L20-L109)

引用片段：

```python
    h, actual_method = _hash_internal(method, salt, password)
```

## h02 · semantic · supported

此处重新计算给定口令在存储 method 与 salt 下的哈希，并调用 hmac.compare_digest 与存储哈希值比较。

参考理由：126–131 行拆出 method、salt、hashval，最终返回 compare_digest(_hash_internal(...)[0], hashval)。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/security.py#L112-L131)

引用片段：

```python
    return hmac.compare_digest(_hash_internal(method, salt, password)[0], hashval)
```

## h03 · semantic · contradicted

generate_password_hash 在这里调用 AES 加密口令，并返回可由同一密钥还原的 AES 密文。

参考理由：所列函数及 _hash_internal 显示 scrypt/pbkdf2 密码哈希和盐，未使用 AES；该局部函数的操作声明被实现反证，不推断外部系统安全。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/security.py#L20-L109)

引用片段：

```python
    h, actual_method = _hash_internal(method, salt, password)
```

## h04 · semantic · contradicted

safe_join 在这里仅把文件名字符串拼接起来，没有规范化路径，也不会拒绝 .. 或 ../ 开头的片段。

参考理由：152 行 normpath 规范化，154–162 行明确拒绝多种绝对路径及 ..、../ 前缀。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/security.py#L134-L166)

引用片段：

```python
            filename = posixpath.normpath(filename)
```

## h05 · semantic · uncertain

部署调用方在进入 safe_join 前已经核验登录用户有权访问该目录，并保证 directory 只能来自可信配置。

参考理由：函数只收到 directory/pathnames。没有部署路由、鉴权和 directory 来源；局部路径检查既不能证明也不能否定调用方授权。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/security.py#L134-L166)

引用片段：

```python
    return posixpath.join(*parts)
```

## h06 · semantic · uncertain

这套生产服务的全部文件下载请求都经过这个 send_from_directory 调用，因此其他路由不存在绕过。

参考理由：可见单个函数对路径检查后调用 send_file，没有完整生产路由和配置，不能证明全部下载入口均经过此函数。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/utils.py#L538-L577)

引用片段：

```python
    return send_file(path_str, environ, **kwargs)
```

## h07 · semantic · supported

此处将客户端 session cookie 交给签名序列化器的 loads，并传入由应用 permanent_session_lifetime 计算的 max_age；BadSignature 被捕获。

参考理由：337–349 行包含 cookie 读取、max_age 计算、s.loads 和 BadSignature 分支；317–335 行提供 serializer 配置。

取证版本：7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[固定源码与完整核对范围](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/sessions.py#L317-L349)

引用片段：

```python
            data = s.loads(val, max_age=max_age)
```

## h08 · semantic · supported

此处先收集 SECRET_KEY_FALLBACKS，再把当前 app.secret_key 追加到 keys，随后将该列表传入 URLSafeTimedSerializer。

参考理由：配置列表的顺序和构造参数可直接从 321–335 行确认；没有声称构造时已验证某个 cookie。

取证版本：7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[固定源码与完整核对范围](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/sessions.py#L317-L335)

引用片段：

```python
        keys.append(app.secret_key)  # itsdangerous expects current key at top
```

## h09 · semantic · contradicted

save_session 在这个 set_cookie 调用中无条件使用 secure=True，不受应用配置影响。

参考理由：357 行由 get_cookie_secure(app) 取得 secure；对应 getter 220 行读取 SESSION_COOKIE_SECURE，395 行使用该变量而非固定 True。

取证版本：7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[固定源码与完整核对范围](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/sessions.py#L351-L399)

引用片段：

```python
            secure=secure,
```


补充核对：[src/flask/sessions.py:215-220](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/sessions.py#L215-L220)

## h10 · semantic · contradicted

open_session 这里只进行普通 JSON 反序列化，没有通过签名序列化器校验，也没有传入有效期。

参考理由：get_signing_serializer 创建 URLSafeTimedSerializer，346 行 s.loads(val,max_age=max_age)，348 行捕获 BadSignature，反证该局部操作描述。

取证版本：7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[固定源码与完整核对范围](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/sessions.py#L317-L349)

引用片段：

```python
            data = s.loads(val, max_age=max_age)
```

## h11 · semantic · uncertain

当前线上 app.secret_key 已配置为至少 32 个随机字节，而且旧的泄露密钥不在回退列表中。

参考理由：源码读配置而未给出运行时 secret_key 或 fallback 值、生成过程和泄露记录；不能由源码默认机制证明部署密钥质量。

取证版本：7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[固定源码与完整核对范围](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/sessions.py#L317-L335)

引用片段：

```python
        keys.append(app.secret_key)  # itsdangerous expects current key at top
```

## h12 · semantic · uncertain

当前生产应用实际将 MAX_FORM_MEMORY_SIZE 配为 50000，并且没有给本请求设置覆盖值。

参考理由：getter 可返回请求覆盖值、基类值或当前配置；部署值和该请求实例均未提供，不能用默认值替代实际值。

取证版本：7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1；[固定源码与完整核对范围](https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/src/flask/wrappers.py#L93-L117)

引用片段：

```python
        return current_app.config["MAX_FORM_MEMORY_SIZE"]  # type: ignore[no-any-return]
```

## h13 · semantic · supported

当 follow_symlink 为 False 时，此处先对文件与目录取 realpath，再用 commonpath 检查候选是否仍处于目录内；不在目录内会 continue。

参考理由：151–167 行分支、realpath、commonpath 比较和 continue 均明确；仅声明所见算法，不证明任何部署绝对安全。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/staticfiles.py#L151-L167)

引用片段：

```python
            if os.path.commonpath([full_path, directory]) != str(directory):
```

## h14 · semantic · supported

此处在 allow_origin_regex 存在时使用 fullmatch(origin) 检查整个 origin；成功返回 True，否则再检查 allow_origins 列表。

参考理由：95–102 行明示 fullmatch 和 allow_origins 成员判断；未声明 allow_all_origins 当前配置为 False。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/middleware/cors.py#L95-L102)

引用片段：

```python
        if self.allow_origin_regex is not None and self.allow_origin_regex.fullmatch(origin):
```

## h15 · semantic · contradicted

lookup_path 这里用字符串 commonprefix 比较前缀作为目录边界，完全没有调用 commonpath。

参考理由：指定源码行直接调用 os.path.commonpath，和所声称 commonprefix 相矛盾。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/staticfiles.py#L151-L167)

引用片段：

```python
            if os.path.commonpath([full_path, directory]) != str(directory):
```

## h16 · semantic · contradicted

这个正则分支使用 search，只要 origin 的任意子串匹配即可通过。

参考理由：99 行使用 fullmatch(origin)，不是 search；局部匹配方式的描述错误。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/middleware/cors.py#L95-L102)

引用片段：

```python
        if self.allow_origin_regex is not None and self.allow_origin_regex.fullmatch(origin):
```

## h17 · semantic · uncertain

当前生产实例的 allow_all_origins 为 False，且 allow_origins 只含两个经过人工批准的域名。

参考理由：只有配置消费逻辑，没有生产构造参数或实例状态，无法确定布尔值、列表长度与批准流程。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/middleware/cors.py#L95-L102)

引用片段：

```python
        if self.allow_all_origins:
```

## h18 · semantic · uncertain

生产路由在调用 StaticFiles 之前已通过另一层中间件验证账号与文件访问权限，所以未授权请求无法到达这一行。

参考理由：文件路径查找不提供外层应用路由和认证中间件；没有鉴权证据不能反推外层完全没有鉴权。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/staticfiles.py#L151-L167)

引用片段：

```python
                return full_path, os.stat(full_path)
```

## h19 · semantic · supported

OAuth2PasswordBearer 在这里从 Authorization 请求头接收输入，经 get_authorization_scheme_param 拆分并检查 bearer scheme，最终返回 param。

参考理由：488–500 行完整展示输入读取、scheme 检查和返回；不声称 param 已经过 JWT 或账号授权校验。

取证版本：313723494be79d4b24ccaa60e4f6d1f96c150fed；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/oauth2.py#L488-L500)

引用片段：

```python
        authorization = request.headers.get("Authorization")
```


补充核对：[fastapi/security/utils.py:1-10](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/utils.py#L1-L10)

## h20 · semantic · supported

HTTPBasic 在此把 param 做 Base64 解码并按 ASCII 读取，再以冒号分离 username 和 password；解码失败或缺冒号时抛出认证错误。

参考理由：205–217 行明确解码、异常捕获、partition(':') 和缺分隔符错误；不声称核验账号密码真实性。

取证版本：313723494be79d4b24ccaa60e4f6d1f96c150fed；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/http.py#L187-L217)

引用片段：

```python
            data = b64decode(param).decode("ascii")
```

## h21 · semantic · contradicted

OAuth2PasswordBearer 的这个 __call__ 在返回 param 前调用 JWT 签名、exp 和 issuer 校验，只有通过这些校验的 token 才会返回。

参考理由：488–500 行只有头读取、字符串拆分和 scheme 检查后返回；helper 仅做头字段拆分，没有 JWT 校验调用。结论限该函数，外层依赖另论。

取证版本：313723494be79d4b24ccaa60e4f6d1f96c150fed；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/oauth2.py#L488-L500)

引用片段：

```python
        return param
```


补充核对：[fastapi/security/utils.py:1-10](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/utils.py#L1-L10)

## h22 · semantic · contradicted

APIKeyHeader 的 __call__ 在这里把头字段提交给数据库或身份中心校验访问权限，再返回通过校验的 API key。

参考理由：198–200 行读取头值后交给 check_api_key；13–20 行该 helper 仅检查有无值并按 auto_error 抛错或返回，没有数据库/身份中心调用。

取证版本：313723494be79d4b24ccaa60e4f6d1f96c150fed；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/api_key.py#L13-L20)

引用片段：

```python
        return self.check_api_key(api_key, self.auto_error)
```


补充核对：[fastapi/security/api_key.py:198-200](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/api_key.py#L198-L200)

## h23 · semantic · uncertain

本应用的上层依赖会在取得 param 后验证 JWT 签名、撤销状态和用户资源权限，因此整个请求链已完成这些检查。

参考理由：库函数的返回值不能证明某应用的上层依赖实现。应用依赖、配置和完整请求链未提供。

取证版本：313723494be79d4b24ccaa60e4f6d1f96c150fed；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/oauth2.py#L488-L500)

引用片段：

```python
        return param
```

## h24 · semantic · uncertain

当前应用创建 APIKeyHeader 时设置 auto_error=False，并在返回 None 后必定使用另一种身份认证方式兜底。

参考理由：库函数只消费 auto_error，没有应用构造参数和依赖组合，不能确定该实例配置和兜底认证。

取证版本：313723494be79d4b24ccaa60e4f6d1f96c150fed；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/api_key.py#L198-L200)

引用片段：

```python
        return self.check_api_key(api_key, self.auto_error)
```

## h25 · control · supported

引用片段与所列版本、文件和行号一致。

参考理由：固定 Git 对象和指定行可读，原始代码逐字符一致。

取证版本：6389612fd1ee1bd93579eed5026e8fd471d04abd；[固定源码与完整核对范围](https://github.com/pallets/werkzeug/blob/6389612fd1ee1bd93579eed5026e8fd471d04abd/src/werkzeug/security.py#L126-L131)

引用片段：

```python
    return hmac.compare_digest(_hash_internal(method, salt, password)[0], hashval)
```

## h26 · control · contradicted

引用片段与所列版本、文件和行号一致。

参考理由：控制项故意将 commonpath 改成 commonprefix；指定行真实代码不匹配。

取证版本：6ee94f2cac955eeae68d2898a8dec8cf17b48736；[固定源码与完整核对范围](https://github.com/encode/starlette/blob/6ee94f2cac955eeae68d2898a8dec8cf17b48736/starlette/staticfiles.py#L151-L167)

引用片段：

```python
            if os.path.commonprefix([full_path, directory]) != str(directory):
```

## h27 · control · uncertain

引用片段与所列版本、文件和行号一致。

参考理由：控制项指定不存在的全零 Git 对象，不能用真实 tag 的同名文件代替该版本。

取证版本：0000000000000000000000000000000000000000；[固定源码与完整核对范围](https://github.com/fastapi/fastapi/blob/313723494be79d4b24ccaa60e4f6d1f96c150fed/fastapi/security/oauth2.py#L488-L500)

引用片段：

```python
        return param
```
