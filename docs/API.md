# Exchange Product API / Product API

`contracts/product/v1/openapi.yaml` is the machine-readable HTTP contract.
This document describes only surfaces implemented by the current source.

`contracts/product/v1/openapi.yaml` 是机器可读 HTTP 契约。本文只描述当前源码已实现
的表面。

## Control plane / 控制面

| Operation | Purpose |
| --- | --- |
| `POST /api/v1/gateway-endpoints` | Create or replay a `GatewayEndpoint` using `Idempotency-Key` |
| `GET /api/v1/gateway-endpoints` | List persisted endpoints |
| `GET /api/v1/gateway-endpoints/{endpointId}` | Read an endpoint |
| `POST /api/v1/gateway-endpoints/{endpointId}/actions/disable` | Disable an endpoint |
| `POST /api/v1/gateway-routes` | Create or replay an active route |
| `GET /api/v1/gateway-routes` | List legacy routes without organization attribution |
| `GET /api/v1/gateway-routes/{routeId}` | Read one legacy route without organization attribution |
| `GET /api/v1/workspace/gateway-routes` | List routes for the authenticated organization/workspace |
| `POST /api/v1/gateway-route-drafts` | Create a DRAFT from an explicit Product handoff |
| `POST /api/v1/workspace/gateway-route-drafts` | Create a scoped DRAFT with an operator-granted endpoint |
| `PATCH /api/v1/gateway-route-drafts/{routeId}` | Edit the inspected DRAFT version |
| `POST /api/v1/gateway-route-drafts/{routeId}/actions/confirm` | Revalidate and activate the exact DRAFT version |
| `POST /api/v1/api-keys` | Generate a gateway API key; the secret is returned once |
| `GET /api/v1/api-keys` | List this workspace's key metadata without secrets |
| `GET /api/v1/api-keys/{apiKeyId}` | Read one key's metadata |
| `POST /api/v1/api-keys/{apiKeyId}/actions/revoke` | Revoke a key |

Control credentials are configured by the host and mapped to a trusted actor,
organization, workspace, and credential reference. Request bodies cannot
override identity. The private Workspace aliases require an organization-scoped
credential. Endpoint use also requires the operator's exact
`(endpointId, organizationId, workspaceId)` grant; an old global endpoint is
not automatically authorized. The legacy list/get paths expose only rows with
no organization attribution, including migrated workspace-only rows. Scoped
rows do not appear through those paths. Organization-bound credentials cannot
use legacy global write operations; those remain available to existing
organization-unscoped control credentials. Draft confirmation fails closed
when source or provider validation is absent or fails.

控制凭据由 host 配置并映射为可信 actor、组织、workspace 与 credential reference；请求体
不能覆盖身份。私有 Workspace 别名要求组织范围凭据。Endpoint 使用还需要 operator
配置精确的 `(endpointId, organizationId, workspaceId)` grant；旧全局 Endpoint 不会自动
授权。旧 list/get 只暴露没有组织归属的记录，包括迁移后的 workspace-only 历史记录；
私有 scope 记录不会出现在旧路径中。组织范围凭据不能使用旧全局写入操作；旧写入只对
现有无组织范围控制凭据保留。来源或 Provider 校验缺失、失败时，DRAFT 确认按
fail-closed 处理。

## Integrations / 集成

The opt-in integration routes use Platform Authority to verify the current
first-party Bearer and return a frozen issuer, subject, organization, workspace,
and exact operation grants. Exchange never accepts identity or role fields in
request bodies. Account linking and credential leases stay in Account Center.
Repository connections and notification bindings are group resources; each member
attaches their own Account Center link and narrowly scoped Platform delegation
through an actor binding. OAuth callback is GitHub's fixed GET callback with
only `state` and `code`; Account Center resolves the private session by stored
state digest.

启用集成路由后，普通调用可由 Platform Authority 验证当前第一方 Bearer；Platform 通用
Product 调用则必须携带其签发的执行凭据，并由 Exchange 通过注册的 mTLS workload 通道再次验证。
两种方式都绑定当前 actor、workspace 和精确 operation；执行凭据还绑定实际 method、path、原始
body、resource 与幂等键。Exchange 不接受请求体中的身份或角色字段。账号关联与 credential lease
由 Account Center 管理。Repository connection 和
notification binding 是群组资源；每位成员通过 actor binding 附加自己的 Account Center 链接和
范围最小化的 Platform delegation。OAuth callback 使用 GitHub 固定 GET 地址，仅接收 `state` 和
`code`；Account Center 根据已存 state 摘要解析私有 session。

| Operation | Purpose |
| --- | --- |
| `POST /api/v1/accounts/link-sessions` | Begin a GitHub or WeCom account link in Account Center; requires `Idempotency-Key` |
| `GET /api/v1/accounts/github/callback?state=…&code=…` | Complete the fixed GitHub OAuth callback |
| `POST /api/v1/accounts/link-sessions/wecom/confirm` | Confirm a WeCom link; requires `Idempotency-Key` |
| `GET /api/v1/accounts/links` | List the verified actor's linked account metadata |
| `POST /api/v1/accounts/links/{account_ref}/actions/unlink` | Unlink; requires `Idempotency-Key` |
| `POST /api/v1/integrations/connections` | Create a repository connection; requires `Idempotency-Key` |
| `GET /api/v1/integrations/connections` | List this actor's scoped repository connections |
| `GET /api/v1/integrations/connections/{connection_id}/health` | Read the fixed Plugin runtime health observation; offline targets return `UNKNOWN` |
| `POST /api/v1/integrations/sync-bindings` | Create a notification-only binding; requires `Idempotency-Key` |
| `GET /api/v1/integrations/sync-bindings` | List scoped bindings |
| `POST /api/v1/integrations/sync-bindings/{binding_id}/actor-bindings` | Attach this member's own account link and Platform grant; requires `Idempotency-Key` |
| `GET /api/v1/integrations/sync-bindings/{binding_id}/actor-bindings` | List only this member's actor binding |
| `POST /api/v1/integrations/sync-bindings/{binding_id}/issues/actions/snapshot` | Read only an actor-scoped cached snapshot using `{ "issueNumber": 42 }` |
| `POST .../actions/query` | Queue an Authority-approved read and return `202` plus `Location`; requires `Idempotency-Key` |
| `POST .../actions/comment` | Queue a durable idempotent issue comment and return `202` plus `Location` |
| `POST .../actions/state` | Queue a durable idempotent OPEN/CLOSED transition and return `202` plus `Location` |
| `GET /api/v1/integrations/operations/{operation_id}` | Read the durable Product operation state |
| `POST /api/v1/integrations/operations/{operation_id}/actions/reconcile` | Read provider state for safe reconciliation; never resends a write |
| `POST /api/v1/integrations/hooks/github/{connection_id}` | Verify the original GitHub HMAC in the GitHub Plugin before inbox persistence |

All public mutations and queued reads require `Idempotency-Key`; a repeated key
with the same request returns the same resource/operation, while a changed request
conflicts. Query callers poll the operation and read the cached snapshot only
after success. Writes run only through the signed Authority execution route and
remain `UNKNOWN` after an ambiguous external result until a read-only
reconciliation proves the desired state. A known explicit provider rejection is
`FAILED`. An accepted WeCom connector ACK means vendor acceptance only, not
end-user delivery. API and dispatcher are separate process roles. The default
gateway-only process does not load integration adapters; integration-only and
combined modes require the closed host configuration and separate integration
database.

所有公开写入和排队读取都必须提供 `Idempotency-Key`；相同请求重放会返回原资源/operation，改变请求则冲突。
查询调用方应轮询 operation，并仅在成功后读取缓存 snapshot。写入只能通过带签名的 Authority execution
route 执行；结果不明确时保留 `UNKNOWN`，直到只读 reconcile 验证目标状态。明确的 Provider 拒绝会标记为
`FAILED`。WeCom connector 的 accepted ACK 只表示服务端接受请求，不代表用户已收到。API 与 dispatcher
是独立进程角色。默认 gateway-only 进程不加载集成 adapter；integration-only 和 combined 模式要求闭合的
host 配置及独立 integration database。

## Gateway API keys / 网关密钥

API keys are generated by the server as `cyk_…` secrets. Exchange stores only
the SHA-256 digest and returns the plaintext exactly once in the creation
response; replaying the `Idempotency-Key` returns the same resource without the
secret. A key carries a name, an optional expiry, and an optional model scope of
`fnmatch` patterns. Empty scope admits every active route.

API Key 由服务端生成为 `cyk_…` 密钥；Exchange 只保存 SHA-256 摘要，明文仅在创建
响应中返回一次。使用同一 `Idempotency-Key` 重放会返回同一资源但不再包含明文。
密钥包含名称、可选过期时间和可选的 `fnmatch` 模型范围；范围为空表示允许全部
ACTIVE 路由。

`GET /v1/models` and `POST /v1/chat/completions` require a Gateway data-plane
credential or a generated API key. Organization-scoped Workspace control
credentials are accepted only by their fixed private control paths and receive
401 on both data-plane paths. The legacy organization-unscoped
`--control-token(-env)` remains dual-use for compatibility and cannot access the
private Workspace aliases. A key outside its model scope receives a
`model_not_permitted` error and the rejected request is audited.

`GET /v1/models` 与 `POST /v1/chat/completions` 要求独立的 Gateway 数据面凭据
或服务端生成的 API key。组织范围 Workspace 控制凭据只能调用固定私有控制路径，
访问两个数据面路径均返回 401。为兼容保留的旧无组织范围
`--control-token(-env)` 仍可双用途使用，但不能调用私有 Workspace 别名。超出模型
范围的 key 请求返回 `model_not_permitted`，且拒绝会写入审计。

The serve CLI reads new secrets from environment variables: use repeatable
`--control-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME` for private
control access and `--gateway-credential-env CREDENTIAL_REF=WORKSPACE_ID=ENV_NAME`
for a separate data-plane bearer. Never assign the same secret to both roles.
Generated API keys remain valid data-plane credentials. Legacy control tokens
must be organization-unscoped; prefer the environment-variable form to avoid
placing secret values in process arguments.

Serve CLI 使用环境变量读取新密钥：私有控制访问使用可重复的
`--control-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME`，独立数据面
Bearer 使用 `--gateway-credential-env CREDENTIAL_REF=WORKSPACE_ID=ENV_NAME`。同一密钥
不能配置为两种新角色。服务端生成的 API key 仍可作为数据面凭据。旧控制令牌必须无组织
范围；为避免明文进入进程参数，优先使用环境变量形式。

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
---
<!-- Chinese Translation / 中文翻译 -->

## 控制面操作中文对照

| 操作 | 说明 |
| --- | --- |
| `POST /api/v1/gateway-endpoints` | 使用 `Idempotency-Key` 创建或重放一个 `GatewayEndpoint`。 |
| `GET /api/v1/gateway-endpoints` | 列出已持久化的 Endpoint。 |
| `GET /api/v1/gateway-endpoints/{endpointId}` | 读取一个 Endpoint。 |
| `POST /api/v1/gateway-endpoints/{endpointId}/actions/disable` | 禁用一个 Endpoint。 |
| `POST /api/v1/gateway-routes` | 创建或重放一条活动 Route。 |
| `GET /api/v1/gateway-routes` | 按优先级列出组织归属未知的 legacy Route。 |
| `GET /api/v1/gateway-routes/{routeId}` | 读取一条组织归属未知的 legacy Route。 |
| `GET /api/v1/workspace/gateway-routes` | 按认证身份的组织/workspace 列出 Route。 |
| `POST /api/v1/gateway-route-drafts` | 根据显式 Product 交接信息创建 DRAFT。 |
| `POST /api/v1/workspace/gateway-route-drafts` | 使用 operator endpoint grant 创建 scoped DRAFT。 |
| `PATCH /api/v1/gateway-route-drafts/{routeId}` | 编辑已检查版本的 DRAFT。 |
| `POST /api/v1/gateway-route-drafts/{routeId}/actions/confirm` | 重新校验并启用精确版本的 DRAFT。 |
| `POST /api/v1/api-keys` | 生成网关 API key；秘密值只返回一次。 |
| `GET /api/v1/api-keys` | 列出当前 workspace 的密钥元数据，不含秘密值。 |
| `GET /api/v1/api-keys/{apiKeyId}` | 读取一条密钥的元数据。 |
| `POST /api/v1/api-keys/{apiKeyId}/actions/revoke` | 撤销一条密钥。 |

控制 API 会把 `TenantQuota` 与 Plugins 用量账本中完整、实际观测到的 Token 总量比较。若没有可用用量来源，已配置的配额将以 HTTP 503 失败关闭。Anthropic Messages、WebSocket streaming、`GatewayFilterService`、MCP、Worker 健康/控制、调度遥测、训练和自定义脚本 RPC 均不属于当前 API。
