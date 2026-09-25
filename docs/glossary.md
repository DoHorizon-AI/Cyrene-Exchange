# Glossary / 术语表

| Term | 中文 | Meaning |
| --- | --- | --- |
| `GatewayEndpoint` | 网关端点 | Product-owned external API resource |
| `GatewayRoute` | 网关路由 | Product-owned mapping to an opaque provider binding |
| `RequestPrincipal` | 请求身份 | Trusted actor/workspace/credential reference resolved from a bearer token |
| `TenantQuota` | 租户配额 | Product-owned token limit, without usage aggregation |
| `connection_ref` | 连接引用 | Opaque endpoint reference consumed by a Product adapter |
| Capability | 能力 | Versioned operation contract selected through Platform |
| Provider | 提供方 | Plugins-owned adapter or service that executes `model.provider.v1` |
| Request audit | 请求审计 | Content-free persisted lifecycle and observed-usage facts |
| Hosted evidence | 托管证据 | CI jobs that actually executed at the exact accepted SHA |
---
<!-- Chinese Translation / 中文翻译 -->

## 术语释义中文对照

| 术语 | 中文释义 |
| --- | --- |
| `GatewayEndpoint` | 由 Product 拥有的外部 API 资源。 |
| `GatewayRoute` | 由 Product 拥有、指向不透明 Provider 绑定的映射。 |
| `RequestPrincipal` | 从 Bearer token 解析出的可信 actor、workspace 和 credential reference。 |
| `TenantQuota` | 由 Product 拥有的 Token 上限，不负责用量汇总。 |
| `connection_ref` | Product 适配器使用的不透明端点引用。 |
| Capability | 通过 Platform 选择的版本化操作契约。 |
| Provider | 由 Plugins 拥有、负责执行 `model.provider.v1` 的适配器或服务。 |
| Request audit | 不含内容的持久化生命周期与观测用量事实。 |
| Hosted evidence | 在精确 accepted SHA 上实际执行的 CI 作业。 |
