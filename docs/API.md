# Exchange Product API / Product API

`contracts/product/v1/openapi.yaml` is the machine-readable HTTP contract.
This document describes only surfaces implemented by the current source.

`contracts/product/v1/openapi.yaml` 是机器可读 HTTP 契约。本文只描述当前源码已实现
的表面。

## Control plane / 控制面

| Operation | Purpose |
| --- | --- |
| `POST /api/v1/gateway-endpoints` | Create or replay a `GatewayEndpoint` using `Idempotency-Key` |
| `GET /api/v1/gateway-endpoints/{endpointId}` | Read an endpoint |
| `POST /api/v1/gateway-endpoints/{endpointId}/actions/disable` | Disable an endpoint |
| `POST /api/v1/gateway-routes` | Create or replay an active route |
| `GET /api/v1/gateway-routes/{routeId}` | Read a route or draft |
| `POST /api/v1/gateway-route-drafts` | Create a DRAFT from an explicit Product handoff |
| `PATCH /api/v1/gateway-route-drafts/{routeId}` | Edit the inspected DRAFT version |
| `POST /api/v1/gateway-route-drafts/{routeId}/actions/confirm` | Revalidate and activate the exact DRAFT version |

Control credentials are configured by the host and mapped to a trusted actor,
workspace, and credential reference. Request bodies cannot override identity.
Draft confirmation fails closed when source or provider validation is absent or
fails.

控制凭据由 host 配置并映射为可信 actor、workspace 与 credential reference；请求体
不能覆盖身份。来源或 Provider 校验缺失、失败时，DRAFT 确认按 fail-closed 处理。

## Chat data plane / Chat 数据面

`POST /v1/chat/completions` supports OpenAI-compatible unary and SSE chat,
structured tool calls, provider-reported usage, and cancellation. The route
planner reads ACTIVE Product routes, while each `targetBindingId` remains opaque
to Exchange and is resolved through the Platform/Plugins boundary.

`POST /v1/chat/completions` 支持 OpenAI-compatible 普通与 SSE Chat、结构化工具
调用、Provider 报告的用量与取消。Route planner 只读取 ACTIVE Product Route；
`targetBindingId` 对 Exchange 保持不透明，并经 Platform/Plugins 边界解析。

Every transport response receives a server-generated `X-Request-Id`. Once a
request enters Product execution, the same ID indexes the content-free durable
audit. Prompts, responses, bearer tokens, and provider secrets are never audit
fields.

每个传输响应都有服务端生成的 `X-Request-Id`。请求进入 Product 执行后，同一 ID
索引不含内容的持久化审计；Prompt、响应、Bearer token 与 Provider secret 永不写入
审计字段。

## Quota and billing boundary / 配额与计费边界

`TenantQuota` is persisted in `ExchangeStore`. When a billing client is
configured, `ProductQuotaGuard` obtains the complete observed token total from
Plugins-owned `billing.usage.v1` and compares it with the Product limit. Exchange
does not estimate missing tokens or maintain a second usage ledger. A configured
quota fails closed with HTTP 503 when no usage source is available.

`TenantQuota` 由 `ExchangeStore` 持久化。配置 billing client 后，
`ProductQuotaGuard` 从 Plugins-owned `billing.usage.v1` 读取完整的已观察 Token
总量，并与 Product 配额比较；Exchange 不估算缺失 Token，也不维护第二套用量账本。
已配置配额但用量来源不可用时，以 HTTP 503 fail closed。

## Explicitly unsupported / 明确未支持

Anthropic Messages, WebSocket streaming, `GatewayFilterService`, MCP, worker
health/control, scheduler telemetry, training, and custom-script RPCs are not
part of the current API.

Anthropic Messages、WebSocket streaming、`GatewayFilterService`、MCP、Worker
健康/控制、调度遥测、训练与自定义脚本 RPC 均不属于当前 API。
