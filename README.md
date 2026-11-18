# pairwise-open-redirect

登录成功后的回跳参数一放开，开放重定向就来了：只判断 `return_url` 是否以 `/` 开头，`//evil.com` 照样跳外站；`https://app.example@evil.com` 用 userinfo 伪装；URL 编码和双重编码没有归一，`%2f%2f` 绕过；相对路径里的 `..` 能跳出站点；CRLF 注入还能改写响应头；白名单只做前缀匹配，`app.example.evil.com` 也能过；失败后默认跳到 Referer；移动端 scheme 不限制，`javascript:` 和 `intent:` 直接执行；多级跳转只检查第一跳。security/open_redirect.py 是核心，tests/test_open_redirect.py 15个红。要修的是：绝对 URL 解析后再比对；拒绝 userinfo；编码归一；路径归一；CRLF 拒绝；精确 host 白名单；固定失败落点；scheme 白名单；每跳复核。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
