# Security Penetration Test Report

**Generated:** 2026-01-17 23:39:39 UTC

# Executive Summary

本次对 https://www.h-acker.cn 及子域进行黑盒深度测试，确认一项高危漏洞：SSO/OAuth 授权流程缺少 state/PKCE 且 redirect_uri 可篡改，已提交漏洞报告。其他接口（投票、上香、评论等）存在未鉴权但当前缺乏真实数据无法验证影响，WordPress 子域未发现直接可利用的未授权漏洞。整体风险以 OAuth 授权码劫持为核心。

# Methodology

采用 OWASP WSTG 方法论，执行子域与端口服务枚举（subfinder/naabu/httpx），目录与参数模糊测试（ffuf/dirsearch/Arjun），深度爬取与 JS 资产解析（katana/浏览器），针对性业务与认证测试（自编脚本/HTTP 请求），以及 WordPress 基线枚举（wpscan）。对 OAuth 流程进行跨站授权劫持验证。

# Technical Analysis

1) OAuth 授权码劫持（已报告：vuln-0001）：/sso 流程跳转 blog.h-acker.cn/oauth/authorize，缺失 state/PKCE，且 redirect_uri 可任意修改，允许攻击者发起跨站授权请求并接收授权码，风险为账户接管/会话劫持。已生成 PoC 钓鱼页面 oauth_code_capture.html。2) 业务与接口观测：/api/hacker/*、/hacker/comment/*、/hacker/ranking/*、/hacker/shangxiang 等接口未登录返回 200 但数据为空；评论/投票/上香等请求缺少鉴权与 CSRF 控制，因无真实数据未能确认状态变更。3) 搜索/资源/日志等接口在注入/遍历测试时被前置拦截或返回空数据，未确认可利用注入/泄露。4) blog.h-acker.cn WordPress 6.8.2 + Zibll 8.2 + WP OAuth Server 插件在线，核心/主题/插件未发现未授权利用；敏感 REST 枚举被 WAF 拦截，需有效 client_id/登录态进一步测试。

# Recommendations

1) 立即修复 OAuth：强制 state 与 PKCE，严格校验 redirect_uri 与注册值一致，拒绝任意回调；禁止固定对称密钥解密 client_id。2) 为所有业务接口（评论/投票/上香等）添加鉴权与 CSRF 防护，校验对象归属与防重/速率限制，并返回明确信息便于审计。3) 对 API 前置 WAF 以外，后端仍需参数化查询与权限校验；增加数据存在性检查与错误区分。4) WordPress：升级核心与主题，核查 WP OAuth Server 配置与客户端白名单；对 admin-ajax 及 REST 进行权限与速率限制；使用 wpscan 等在维护窗口补充插件漏洞排查。5) 进行一次修复后复测，覆盖 OAuth、业务未授权与 WordPress 插件/主题安全。

