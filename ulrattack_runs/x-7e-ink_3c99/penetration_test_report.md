# Security Penetration Test Report

**Generated:** 2026-01-19 01:00:34 UTC

# Executive Summary

对目标 https://x.7e.ink 的外部渗透测试表明，站点前置于腾讯云 EdgeOne L7 安全层，未授权流量被一致性阻断并返回自定义拦截页（页面标题为 AccessDeny，响应首行表现为 567 Unknown Status）。在当前访问条件下无法建立站点地图或进入业务层进行动态漏洞测试，因此对应用真实安全姿态的评估受到限制。尽管未能验证应用层漏洞，仍观察到边缘侧存在弱协议启用（TLS 1.0/1.1），建议在边缘关闭以降低降级与兼容性攻击风险。总体风险结论为：因前置策略完全阻断而导致风险不可见，需在受控的测试窗口下开放访问以完成针对 IDOR、SQL 注入、SSRF、XSS、XXE、RCE、CSRF 等高影响向量的系统性验证。

# Methodology

本次评估遵循 OWASP Web Security Testing Guide（WSTG）的黑盒外部渗透方法。首先进行广度优先的侦察与指纹识别，覆盖 DNS、证书与 TLS 配置、HTTP 安全头与服务器标识；随后尝试全站爬取与端点映射，并对边缘/CDN 策略进行系统化绕过与直连探测（包含 HTTP/1.1 与 HTTP/2、方法与头部组合、路径编码与变体、SNI/Host 一致性与直连边缘 IP 等）。同时结合被动情报（证书透明度与历史索引）生成离线端点与参数词库，拟作为后续喷射与验证的基础。在未获得业务层访问的情况下，严格避免对源站施加破坏性操作，仅进行非破坏性指纹化与策略验证。

# Technical Analysis

侦察结果显示：x.7e.ink 为 CNAME 到 x.7e.ink.eo.dnse0.com，A 记录指向 EdgeOne 边缘节点段；访问根路径及常见资源路径（例如 robots.txt、favicon.ico、/_next/static、/cdn-cgi/trace 等）均返回拦截页，响应头含 Server: EdgeOne_L7S_OC 与 HSTS。证书为 TrustAsia DV TLS RSA CA 2025 签发（CN/SAN= x.7e.ink），有效期截至 2026-03-07。边缘侧启用了 TLS 1.0/1.1/1.2/1.3，建议收敛到 1.2/1.3。尝试的绕过策略（UA/Accept/Referer/Origin 组合、HEAD/OPTIONS 方法、路径与编码扰动、X-Forwarded-* 伪造、HTTP/2 客户端栈差异、直连候选边缘 IP 并设定 SNI/Host）均未产生业务响应，常见行为为 567 拦截、8080 重定向到 HTTPS 后继续拦截、CNAME 直连返回 418 拒绝及在 443 上握手拒绝。变体域 www.x.7e.ink 当前无法解析，直连 Host/SNI=www.x.7e.ink 的候选节点同样被 EdgeOne 阻断。由于业务层不可达，未能进行端点与参数枚举、认证与授权边界验证或注入类漏洞测试；为后续工作已准备离线的端点与参数词库，待获得受控访问窗口后用于快速喷射与验证。

# Recommendations

优先建议在受控的安全评估窗口内为测试源开放最小化白名单，或提供预发布/镜像域名以绕过边缘的全站拦截；在该窗口中仅放行必要路径并启用速率限制与日志审计。建议在边缘侧关闭 TLS 1.0/1.1，统一强制 TLS 1.2/1.3，并复核 HSTS 策略是否满足预期。在获得访问能力后，应立即执行端点与参数映射与喷射，按高影响向量进行系统化测试，包括对象访问控制（IDOR/BFLA）、SQL 注入、SSRF、XSS、XXE、RCE、CSRF、文件上传与业务逻辑缺陷；同时复核源站安全头（CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy、COOP/COEP/CORP）与会话管理（Cookie 属性、令牌存储与有效期、重新认证要求）。为提升可观测性，应开启对异常访问、拦截事件与重定向链路的细粒度日志与告警，并在整改后进行集中回归测试以确认不存在策略绕过与编码/重定向类变体造成的误放行。

