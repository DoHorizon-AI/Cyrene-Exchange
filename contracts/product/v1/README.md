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
