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
