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
| `POST /api/v1/integrations/connections` | Create a fixed provider connection using configured opaque aliases; requires `Idempotency-Key` |
| `GET /api/v1/integrations/connections` | List the caller's minimal connection projection: Product id, provider, display name, legacy GitHub repository fields, enabled state, and timestamps |
| `GET /api/v1/integrations/connections/{connection_id}/health` | Read the fixed Plugin runtime health observation; offline targets return `UNKNOWN` |
| `GET /api/v1/integrations/connections/{connection_id}/authorization-health` | Read cached provider login and authorization facts; first observation returns `UNKNOWN` |
| `POST /api/v1/accounts/authorizations/{authorization_id}/renewal-sessions` | Start or replay the actor-owned provider renewal session; requires `Idempotency-Key` and returns `202` plus a Product `Location` |
| `GET /api/v1/accounts/renewal-sessions/{session_id}` | Read one actor-owned Product renewal session UUID; the stored session binds its exact native authorization |
| `GET /api/v1/integrations/connections/{connection_id}/resources` | Read latest cloud observations with source and freshness |
| `POST /api/v1/integrations/connections/{connection_id}/actions/refresh` | Queue an idempotent read-only cloud refresh; returns `202` plus a Product operation `Location` |
| `GET /api/v1/integrations/notifications?after={sequence}` | Read the durable actor-scoped notification feed after a sequence cursor |
| `GET /api/v1/integrations/notifications/events` | Direct HTTP SSE for the same feed-read grant; `Last-Event-ID` resumes after a sequence |
| `POST /api/v1/integrations/notifications/{notification_id}/ack` | Acknowledge an actor-owned notification; requires `Idempotency-Key` |
| `POST /api/v1/integrations/notifications/{notification_id}/actions/deliver` | Queue one actor-owned email request to the host-fixed recipient alias; requires `integrationDeliverNotification` and `Idempotency-Key` |
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

The private `/internal/v1/connector-operations/{connectionRef}` facade now
supports the fixed proactive GitHub tool set documented in
[`contracts/product/v1/connector-operations.md`](../contracts/product/v1/connector-operations.md).
It continues through the existing `tool.provider.v1` provider catalog/call path.
Each call requires a fresh exact Directory grant and one-use Account Center
lease. Mutating operations preserve an unknown outcome until independent provider
readback; Exchange does not replay an uncertain write.

私有 `/internal/v1/connector-operations/{connectionRef}` facade 支持的主动 GitHub
工具，以及各自的资源 target，见
[`contracts/product/v1/connector-operations.md`](../contracts/product/v1/connector-operations.md)。
调用仍沿用现有 `tool.provider.v1` provider catalog/call 路径。每次调用都要求新的精确
Directory grant 与 Account Center 一次性 lease。写操作结果未知时会等待独立 Provider
回读；Exchange 不会重放结果不明的写入。

The same private facade also accepts the four fixed `computer.*` operations only
when a host-owned `connectorHost.computerRunner` profile is configured. It binds
one mTLS DirectPlugin endpoint to one organization/workspace and logical runner
workspace. Directory authorization remains per caller and exact operation;
Exchange sends only typed tool arguments over mTLS and does not create an
external account link. Command and file-write results use durable operation
receipts, and uncertain effects are never automatically replayed.

同一私有 facade 还支持四个固定 `computer.*` 操作，但必须由 Host 配置
`connectorHost.computerRunner` profile。该 profile 将一个 mTLS DirectPlugin endpoint 固定
到一个组织/workspace 与逻辑 runner workspace。Directory 仍按当前调用者和精确 operation
授权；Exchange 只通过 mTLS 发送类型化工具参数，不创建外部账号关联。命令和文件写入保存持久
operation 回执，效果不明时不会自动重放。

Public Product HTTP timestamps use RFC3339 UTC with a trailing `Z`. Exchange
normalizes stored or provider timestamps at the HTTP serialization boundary; it
does not rewrite persistence or provider SDK values.

Platform identity RPC `UNAUTHENTICATED` maps to HTTP 401, `PERMISSION_DENIED` to
403, and transport, deadline, or unknown protocol failures to 503. These are
first-party identity/scope outcomes; only a confirmed provider invalidation maps
to the connection reauthorization 409.

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

Authorization health preserves the provider's separate login and authorization
states. `UNKNOWN` and `UNAVAILABLE` never imply `VALID` or expired. Exchange checks
connections every 15 minutes, alerts on known expiry at 24 hours and 1 hour, and
emits a confirmed reauthorization incident immediately. An unacknowledged
actionable incident can repeat after 6 hours; unchanged state stays quiet. The
health route continues to return the observed provider state. Resource reads and
refreshes return HTTP 409 for a confirmed reauthorization block with code
`EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED` and actor-scoped
`context.connectionId` / `context.authorizationRef`. It is distinct from HTTP 401,
HTTP 403, and Platform `AWAITING_AUTHORITY`.

Cloud refresh is a fixed provider query over a server-configured opaque target
selector. REST accepts no endpoint, shell command, credential, or model-selected
scope. A failed provider read leaves the last observation in place and its
freshness ages to `STALE`; it does not report a resource as stopped. The independent
email outbox commits `SENDING` before calling the mail adapter. Email requires a
fresh `integrationDeliverNotification` Platform grant and a host-enabled actor
allowlist; `integrationListNotifications` does not authorize sending. A lost or
ambiguous send becomes `UNKNOWN` and is not automatically resent. The explicit
delivery route is idempotent and returns the existing job state for a previously
queued or sent notification.

The SSE route keeps the HTTP `integrationStreamNotifications` operation ID and
`Last-Event-ID` recovery, but it is not a generic v2 catalog operation because
its response is `text/event-stream`, not JSON. It uses the exact
`integrationListNotifications` READ grant with the same actor and workspace
checks; streaming the same feed does not add a privilege.

Renewal creates a Product session intent before the provider call. A confirmed
session exposes the provider's strictly verified WeCom navigation URI in the
existing `authorizationUrl` field: either the fixed onboarding QR flow or the
existing-profile authorization management page. The field is a navigation URI,
not a QR discriminator. Exchange validates each path with its own exact host and
query rules, then canonicalizes the management URL. An opaque QR attachment ref
may also be returned. If the start result is ambiguous, the session remains `VERIFYING`
with a `provider_start_outcome_unknown` reason and no URL. Exchange does not start
another session automatically; once the provider's durable replay implementation
is enabled, the caller may repeat the exact POST with the same `Idempotency-Key` to
recover that same session. A new key is a new user-authorized start.

For a provider that advertises request-ID status lookup, the renewal GET may use
the signed Product start request ID as a read-only status alias and then bind the
returned provider session ref to the same Product session. Exchange never invokes
the start tool from GET. If the adapter does not advertise this capability or the
lookup cannot verify the original session, the session remains `VERIFYING` until
manual reconciliation or an explicit same-key POST replay.

授权健康状态分别保留 Provider 登录状态与授权状态。`UNKNOWN` 和 `UNAVAILABLE` 不代表
`VALID`，也不代表已过期。Exchange 每 15 分钟检查连接，在已知到期前 24 小时和 1 小时
提醒，并在 Provider 确认需要重新授权时立即创建事件。未确认的可操作事件可每 6 小时
再次提醒；状态无变化时保持安静。刷新遇到已确认的重新授权阻塞会返回 HTTP 409，错误码
为 `EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED`，并在 actor 范围内的
`context.connectionId` / `context.authorizationRef` 中提供精确引用。它与 HTTP 401、HTTP 403
及 Platform `AWAITING_AUTHORITY` 不同。

Cloud 刷新只会查询服务器配置的固定 Provider 和 opaque target selector。REST 不接受
Endpoint、Shell 命令、凭据或模型选择的范围。Provider 读取失败会保留最后一次观察，并让
freshness 随时间变为 `STALE`；不会据此报告资源已停止。独立邮件发件箱会先持久化
`SENDING` 再调用邮件适配器；发送结果丢失或不明确时标记为 `UNKNOWN`，且不会自动重发。

重新授权会在调用 Provider 前持久化 Product session intent。确认创建的 session 在现有
`authorizationUrl` 字段中返回经过严格校验的 WeCom 导航 URI：固定 onboarding QR 流程或既有
profile 的授权管理页。该字段表示导航 URI，不表示其一定是二维码。Exchange 对两种路径分别执行精确
Host/query 校验，并对管理页 URL 规范化；也可返回 opaque QR attachment ref。启动结果不明确时，session
保持 `VERIFYING`，附 `provider_start_outcome_unknown`，不提供 URL。Exchange 不会自动启动另一个
session；Provider 的持久化重放实现启用后，调用方可使用相同 `Idempotency-Key` 重放完全相同的
POST，以取回同一 session。新 key 表示新的用户授权操作。

通知 SSE 保留 HTTP `integrationStreamNotifications` operationId 和 `Last-Event-ID` 恢复，但因响应类型为
`text/event-stream`，它不进入通用 v2 catalog。该路由复用相同 actor/workspace 校验和
`integrationListNotifications` READ grant；流式读取同一通知资源不增加权限。

对于声明支持 request-ID 状态查询的 Provider，renewal GET 可以把带签名的 Product 启动 request ID
作为只读状态别名，并将返回的 Provider session ref 绑定到原 Product session。GET 永远不会调用
start 工具。如果 adapter 未声明此能力，或无法验证原 session，则状态保持 `VERIFYING`，直到人工核对
或调用方显式使用同一个 key 重放 POST。

Product HTTP 对外时间戳统一使用末尾为 `Z` 的 RFC3339 UTC 格式。Exchange 只在 HTTP 序列化边界
规范化存储或 Provider 时间，不改写持久化值或 Provider SDK 对象。

Platform identity RPC 的 `UNAUTHENTICATED` 映射为 HTTP 401，`PERMISSION_DENIED` 映射为 403；传输、超时或
未知协议故障映射为 503。这些是第一方身份/范围结果；只有 Provider 确认授权失效才映射为连接重新授权 409。

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

Enterprise and self-hosted inference use this same route and provider seam:
the Plugin deployment owns the upstream service endpoint and its credential
reference, while Product stores only the opaque `targetBindingId` and target
model. The caller-facing `GatewayEndpoint` is separate from the upstream model
endpoint. Exchange records the provider and model facts it receives and leaves
usage aggregation to the existing billing capability. This configuration path
does not by itself prove private-network inference or a deployed private model.

`POST /v1/chat/completions` 支持 OpenAI-compatible 普通与 SSE Chat、结构化工具
调用、Provider 报告的用量与取消。Route planner 只读取 ACTIVE Product Route；
`targetBindingId` 对 Exchange 保持不透明，并经 Platform/Plugins 边界解析。

企业及自托管推理沿用同一 Route 和 Provider 边界：Plugin 部署管理上游服务地址与凭据
引用，Product 只保存不透明的 `targetBindingId` 和目标模型。面向调用方的
`GatewayEndpoint` 与上游模型地址分开。Exchange 记录 Provider 返回的实际 Provider 与
模型事实，并由现有 billing 能力汇总用量。仅有配置路径不能证明私有网络推理或私有模型
已经部署。

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
