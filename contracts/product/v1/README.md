# Exchange Product contract v1

Status: `REFERENCE_MVP_READY`; persisted routing through generic Platform
selection, a direct Plugins-owned endpoint, and real HTTP is proven. Production
gateway deployment, HA policy storage, and external adapters remain future work.

Exchange owns externally published `GatewayEndpoint` and `GatewayRoute`
resources plus request policy. It reuses generic `model.routing.v1` and
`model.provider.v1` capabilities for selection and execution.

## Authority

- A `GatewayEndpoint` is the external model API publication surface. It is not a
  Reactor serving Endpoint and it does not imply a Deployment exists.
- A `GatewayRoute` maps an external model pattern to an opaque capability
  binding. `targetBindingId` is not parsed as provider/package identity.
- The persisted route planner adapts Product state to the existing
  `ModelRoutingCapability`; the existing `ExchangeGateway` keeps authentication,
  normalization, cancellation, fallback-before-first-byte, and streaming policy.
- `authPolicyRef` is a reference. Secret material is never accepted or returned.
- Product state is SQLite in the MVP and is never inferred from plugin binding or
  gateway process state.
- Events are notifications after state commits, not the source of truth.

`build_gateway_from_store` composes one selected Product endpoint with a
caller-owned Platform resolver. `PlatformResolverAdapter` accepts the execution
modes declared by canonical manifests and maps a selected implementation reference
to a caller-owned direct Plugin client. Neither adapter creates a binding registry,
Plugin lifecycle, plugin identity, or second route authority. Platform does not
receive, parse, or proxy Product request and response payloads.

## Notifications

After durable commits, Exchange may publish created/updated notifications for
`gateway-endpoint` and `gateway-route`, using types such as
`dev.cyrene.exchange.gateway-route.created.v1`. The common Product event
envelope contains only resource URI/version and change kind; consumers re-read
Exchange and tolerate duplicates, reordering, and newer versions. Data-plane
requests are telemetry, not Product events. The MVP does not claim a durable
outbox publisher.

## State

`GatewayEndpoint`: `ACTIVE <-> DISABLED`.

`GatewayRoute`: `ACTIVE | DISABLED`; disabling an Endpoint makes all of its
routes ineligible without rewriting the route records.

## Compatibility

The control API is `/api/v1`; the external data plane is the industry-compatible
`/v1/chat/completions` surface already implemented by Exchange Product Core.
OpenAPI is 3.1.2, JSON Schema is Draft 2020-12, and the control API consumes the
Workspace `product-http-v1` compatibility profile. Existing OpenAI-shaped
data-plane errors remain compatible with clients.

`Idempotency-Key` uses the shared Cyrene replay/conflict semantics. Deprecation,
migration window, and removal follow the common profile rather than a private
Exchange rule.

The data-plane normalizer preserves text tool definitions, tool choices, tool
result history, indexed streamed tool-call fragments, and provider-reported
usage. It never estimates token counts when a provider omits them. Plain text
requests continue through direct Plugin `model.provider.v1` interface version 1;
requests containing structured chat fields negotiate interface version 2 and
the `chat_completion_v2` method. A provider that only advertises v1 therefore
fails at the Plugins-owned contract boundary instead of silently dropping agent semantics.

The Product-owned SQLite request audit remains the terminal request authority.
When a `BillingUsageClient` is configured, Exchange sends the same content-free,
provider-reported usage facts to the Plugins-owned `billing.usage.v1` ledger by
request ID. The billing plugin derives summaries and cost; it does not receive
prompts, responses, credentials, or route state.

数据面标准化器会保留文本工具定义、工具选择、工具结果历史、带索引的流式工具调用
片段以及 provider 报告的 usage；provider 未提供 token 数量时不会估算。普通文本请求继续
通过 `model.provider.v1` v1 直连 Plugin；包含结构化 chat 字段的请求协商 v2 与
`chat_completion_v2`。只声明 v1 的 provider 会在 Plugins 契约边界安全拒绝，不会静默丢失 Agent 语义。

Product 所有的 SQLite 请求审计仍是请求终态权威。配置 `BillingUsageClient` 后，Exchange
会按请求 ID 把同一份不含内容的 provider 用量事实发送给 Plugins 所有的
`billing.usage.v1` 账本。计费插件负责汇总与费用计算，不接收 Prompt、响应、凭据或路由状态。
---
<!-- Chinese Translation / 中文翻译 -->

# Exchange Product 契约 v1

状态为 `REFERENCE_MVP_READY`：已证明通过通用 Platform 选择、Plugins 所有的直连端点和真实 HTTP 完成持久化路由。生产网关部署、高可用策略存储和外部适配器仍属于未来工作。

Exchange 拥有对外发布的 `GatewayEndpoint` 与 `GatewayRoute` 资源以及请求策略。它复用通用 `model.routing.v1` 和 `model.provider.v1` 能力完成选择与执行。

## 权威边界

- `GatewayEndpoint` 是对外模型 API 的发布表面。它不是 Reactor serving Endpoint，也不代表存在 Deployment。
- `GatewayRoute` 将外部模型模式映射到不透明的能力绑定。不得把 `targetBindingId` 解析为 Provider 或包身份。
- 持久化路由规划器将 Product 状态适配到现有 `ModelRoutingCapability`；现有 `ExchangeGateway` 继续负责认证、规范化、取消、首字节前回退和流式策略。
- `authPolicyRef` 是引用；系统不会接受或返回密钥材料。
- MVP 使用 SQLite 保存 Product 状态，不会从插件绑定或网关进程状态推断 Product 状态。
- 事件是在状态提交后的通知，不是真相来源。

`build_gateway_from_store` 将一个选定的 Product 端点与调用方拥有的 Platform resolver 组合起来。`PlatformResolverAdapter` 接受规范 manifest 声明的执行模式，并将选定的实现引用映射到调用方拥有的直连 Plugin 客户端。任一适配器都不会创建绑定注册表、Plugin 生命周期、插件身份或第二套路由权威。Platform 不接收、解析或代理 Product 请求与响应载荷。

## 通知

持久化提交后，Exchange 可以为 `gateway-endpoint` 和 `gateway-route` 发布创建/更新通知，例如 `dev.cyrene.exchange.gateway-route.created.v1`。通用 Product 事件信封只包含资源 URI/版本和变更类型；消费者应重新读取 Exchange，并容忍重复、乱序和更新版本。数据面请求属于遥测，而不是 Product 事件。MVP 不宣称具备持久化 outbox 发布器。

## 状态

`GatewayEndpoint` 的状态可在 `ACTIVE` 与 `DISABLED` 之间切换。

`GatewayRoute` 可处于 `ACTIVE` 或 `DISABLED`；禁用一个 Endpoint 会使其所有 Route 失去候选资格，但不会改写 Route 记录。

## 兼容性

控制 API 为 `/api/v1`；外部数据面使用 Exchange Product Core 已实现的行业兼容 `/v1/chat/completions` 接口。OpenAPI 版本为 3.1.2，JSON Schema 版本为 Draft 2020-12，控制 API 使用 Workspace 的 `product-http-v1` 兼容配置文件。现有 OpenAI 风格的数据面错误仍与客户端兼容。

`Idempotency-Key` 遵循 Cyrene 通用的重放/冲突语义。弃用、迁移窗口和移除遵循通用配置文件，而不是 Exchange 私有规则。

数据面规范化器会保留文本工具定义、工具选择、工具结果历史、带索引的流式工具调用片段以及 Provider 报告的用量。Provider 未提供 Token 数量时，系统不会估算。纯文本请求继续使用直连 Plugin 的 `model.provider.v1` 接口版本 1；包含结构化聊天字段的请求协商接口版本 2 和 `chat_completion_v2` 方法。只声明 v1 的 Provider 会在 Plugins 所有的契约边界失败，不会静默丢弃 Agent 语义。

Product 所有的 SQLite 请求审计仍是请求终态的权威来源。配置 `BillingUsageClient` 后，Exchange 会按请求 ID 将同一份不含内容、由 Provider 报告的用量事实发送到 Plugins 所有的 `billing.usage.v1` 账本。计费插件负责派生汇总和费用；它不会接收提示词、响应、凭据或路由状态。
