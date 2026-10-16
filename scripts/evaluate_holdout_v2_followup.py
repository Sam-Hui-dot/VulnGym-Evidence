"""Separate known-failure regression from newly frozen follow-up assertions."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import evaluate_holdout_v2 as bench


def followup_manifest():
    cases = []
    def add(slug,path,anchor,label,text,reason):
        n = 1 + sum(c['project'] == slug for c in cases)
        row = bench.case(slug,n,path,anchor,label,text,reason)
        row['request']['case_id'] = 'fresh-' + row['request']['case_id']
        row['request']['claims'][0]['claim_id'] = row['request']['case_id']
        cases.append(row)
    w='pallets/werkzeug'
    p='src/werkzeug/utils.py'
    a='filename = unicodedata.normalize("NFKD", filename)'
    add(w,p,a,'supported','secure_filename 在本函数中做 NFKD 规范化、ASCII 转换、路径分隔符替换和字符白名单清理。','完整函数体按上述顺序清理字符串，不断言外部文件或访问控制安全。')
    add(w,p,a,'contradicted','secure_filename 对任意输入都会生成非空且随机唯一的文件名，本函数保证不会与已有文件重名。','完整函数只确定性清理字符串；空输入的变换仍为空，且没有随机数或文件存在性检查。')
    add(w,p,a,'uncertain','调用 secure_filename 的上传业务在写入之前一定拒绝重名文件，并对上传者做了目录访问授权。','没有业务上传调用方和写入策略；字符串处理不能证明重名拒绝或授权。')
    s='encode/starlette'
    p='starlette/middleware/cors.py'
    a='failure_text = "Disallowed CORS " + ", ".join(failures)'
    add(s,p,a,'supported','preflight_response 在 failures 非空时返回带 Disallowed CORS 说明的 400 响应；无失败时返回 200。','所引 if failures 分支 return status_code=400，下一条无失败 return status_code=200。')
    add(s,p,a,'contradicted','preflight_response 无论 failures 是否非空，都无条件返回状态码 200。','failures 非空的分支明确提前返回 400。')
    add(s,p,a,'uncertain','生产部署为所有路由安装了同一套严格的 CORS 配置，绝不允许任何不可信站点携带凭据访问。','没有应用安装位置、选项和路由覆盖；函数分支不能证明生产全局配置。')
    e='expressjs/express'
    p='lib/response.js'
    a="callback = callback.replace(/[^\\[\\]\\w$.]/g, '');"
    add(e,p,a,'supported','res.jsonp 对非空字符串 callback 用字符白名单正则移除不允许的字符，然后才把 callback 用于响应体。','callback 分支中的 replace 位于后续 body 拼接之前，声明仅限可见处理顺序。')
    add(e,p,a,'contradicted','res.jsonp 在本函数中先对 callback 执行 eval，然后才把执行结果作为 JSONP 响应。','完整 callback 分支为 replace 和字符串拼接，并未调用 eval；body 最后 this.send。')
    add(e,p,a,'uncertain','所有使用 res.jsonp 的业务接口都会先验证用户权限，且不向未登录用户返回敏感数据。','没有应用路由或敏感数据选择逻辑，库函数无法证明业务授权。')
    g='go-chi/chi'
    p='middleware/basic_auth.go'
    a='if !credUserOk || subtle.ConstantTimeCompare([]byte(pass), []byte(credPass)) != 1 {'
    add(g,p,a,'supported','BasicAuth 在用户名不属于 creds 或密码的 ConstantTimeCompare 不相等时调用 basicAuthFailed 并提前返回。','所引 if 的两个条件覆盖用户不存在和密码不匹配，分支调用失败处理并 return。')
    add(g,p,a,'contradicted','BasicAuth 只检查用户名是否在 creds 中，不比较传入密码；只要用户名存在就执行下一处理器。','条件包含传入 pass 与 credPass 的 ConstantTimeCompare；不相等会拒绝。')
    add(g,p,a,'uncertain','该应用的 BasicAuth 凭据在部署时按用户独立生成高强度随机密码，并由安全的外部秘密管理系统轮换。','没有凭据生成、部署或秘密管理系统配置；比较函数不能证明密码来源与轮换。')
    h='honojs/hono'
    p='src/utils/cookie.ts'
    a='parsedCookie[key] = isVerified ? signedValue : false'
    add(h,p,a,'supported','parseSigned 对签名验证结果为真的 cookie 返回 signedValue，对验证结果为假的 cookie 把对应值设为 false。','isVerified = await verifySignature 后的条件表达式直接支持这两个返回值分支。')
    add(h,p,a,'contradicted','parseSigned 即使签名验证结果为假，也把 signedValue 作为有效 cookie 值放进返回对象。','条件表达式在 isVerified 为假时写入 false，直接反驳。')
    add(h,p,a,'uncertain','读取 parseSigned 结果的所有会话认证入口都会拒绝 false，并在授权前校验会话对应的用户状态。','没有业务读取方、会话授权或用户状态校验实现，不能由签名解析推定。')
    reports=[]
    for slug in bench.VERSIONS:
        selected=[c for c in cases if c['project']==slug]
        text='\n\n'.join(f'第 {i+1} 项\n'+c['request']['report_text'] for i,c in enumerate(selected))
        reports.append({'report_id':'fresh-'+slug.split('/')[-1],'project':slug,'report_text':text,
                        'expected_case_ids':[c['request']['case_id'] for c in selected]})
    return {'version':'new-function-followup-v2','cases':cases,'reports':reports,
        'limitations':['Author-reviewed designed statements, not independent human gold or natural user reports.',
          'Fresh statement/function families after the first-pass fixes; repositories and fixed commits are shared.',
          'Do not pool this run with first-pass scores or known-failure regressions.']}


def regression_manifest():
    original=json.loads((bench.DEFAULT_OUT.parent/'20261005-first-pass/manifest.json').read_text())
    scored=json.loads((bench.DEFAULT_OUT.parent/'20261005-first-pass/score.json').read_text())
    failed={r['case_id'] for r in scored['rows'] if r['stratum']=='semantic' and r['prediction'] != r['expected']}
    cases=[deepcopy(c) for c in original['cases'] if c['request']['case_id'] in failed]
    return {'version':'known-failure-regression-only','cases':cases,'reports':[],
            'limitations':['Known failure cases only; cannot establish independent accuracy or replace original predictions.']}


if __name__=='__main__':
    mode=sys.argv[1]
    action=sys.argv[2]
    directory=Path(sys.argv[3])
    if action=='freeze':
        bench.build=followup_manifest if mode=='fresh' else regression_manifest
    getattr(bench,action)(directory)
