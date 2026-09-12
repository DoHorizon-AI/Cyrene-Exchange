# Security Policy / 安全策略

## Reporting / 报告方式

Do not open a public issue for a suspected vulnerability. Use this repository's
GitHub Security Advisory form and include the affected revision, reachable
surface, impact, and a minimal reproduction that contains no real credentials
or user data.

疑似漏洞请勿提交公开 Issue。请使用本仓库 GitHub Security Advisory，并提供受影响
revision、可达表面、影响和不含真实凭据或用户数据的最小复现。

<https://github.com/DoHorizon-AI/Cyrene-Exchange/security/advisories/new>

## Supported versions / 支持版本

Security fixes are developed on `develop` and released from `main`. Until the
first tagged public release, only the current protected branch heads are in
scope; unmerged branches and historical snapshots are unsupported.

安全修复在 `develop` 开发并从 `main` 发布。首个公开 tag 之前，只支持当前受保护
分支 head；未合并分支与历史快照不在支持范围内。

## Sensitive data / 敏感数据

Exchange credentials must enter through deployment secret management or local
environment variables. Logs, readiness records, audits, and test fixtures must
not contain bearer values, provider secrets, prompts, responses, or private
provider URLs.

Exchange 凭据必须通过部署 Secret 管理或本地环境变量注入。日志、readiness、审计
与测试夹具不得包含 Bearer 值、Provider secret、Prompt、响应或私有 Provider URL。
