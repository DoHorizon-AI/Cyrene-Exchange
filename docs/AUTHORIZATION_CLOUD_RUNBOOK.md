# Authorization and cloud integrations runbook

This runbook configures Exchange's fixed authorization monitor, read-only cloud
observations, and independent email outbox. It uses the existing Platform
Authority first-party identity verifier on every background call. Exchange does
not create a system principal, extend an expired token, or derive identity from a
stored connection.

本手册配置 Exchange 固定授权监控、只读云资源观察与独立邮件发件箱。每次后台调用都会使用现有
Platform Authority 第一方身份校验器重新验证。Exchange 不创建系统主体、不延长过期令牌，也不从
持久化连接推断身份。

## Host configuration

Start from [`integration-configuration.authorization-cloud.json`](../product/examples/integration-configuration.authorization-cloud.json).
It is a complete structural example; `.invalid` hosts, placeholder identifiers,
and environment-variable names are synthetic. The fragment schema is
[`authorization-cloud-configuration.schema.json`](../product/examples/authorization-cloud-configuration.schema.json).
To explicitly enable email, merge
[`email-notifications.enabled.fragment.json`](../product/examples/email-notifications.enabled.fragment.json)
and its `hostSecretRefs` entry into the host configuration. Do not put token or
key values in JSON.

`hostSecretRefs` maps stable references to injected environment-variable names.
`currentAuthority.contexts[]` pins an expected actor and a `bearerTokenEnvRef`.
The mapped environment value must be a currently issued first-party bearer for
that exact actor and workspace. The host secret is resolved again for every
provider operation. Platform `VerifyIdentity` and the actor's current
role-filtered Exchange-operation catalog snapshot run before each signing step;
the provider adapter repeats the exact operation and owner/resource checks
immediately before signing. The token and resulting principal are never cached.
Configure a real credential rotation procedure in the host secret store and restart or
reload the service environment when required by the host. This path provides
bounded support for currently issued member credentials; it does not promise a
perpetual non-user service identity.

`authorizationCloud.profiles` is a closed map owned by the host. A Product
connection's `bindingRef` selects one profile. Cloud `targetRef` selects one
target alias inside that profile. Each profile pins the DirectPluginRuntime
`bindingId`, `connectionRef`, transport, caller workload, audience, expected
issuer, HMAC key reference, organization/workspace, and allowed current-actor
context references. Each target can further narrow those actor references. The
WeCom profile pins its native provider `authorizationRef`; Exchange never treats
an Account Center `accountLinkRef` as that native ref.

`emailNotifications` is disabled by default. When enabled, it pins a separate
Email Plugin binding, workload, audience, issuer, tenant, HMAC key, fixed
`recipientRef`, and explicit actor context allowlist. The Email Plugin owns the
SMTP server, mailbox mapping, sender, SMTP credentials, and its private replay
ledger. Exchange REST never accepts an email address or message body. Email
requires the fresh Platform `integrationDeliverNotification` grant and the host
allowlist; notification-feed read permission alone cannot send mail.

If the bearer is missing, expired, revoked, or lacks the exact operation grant,
Exchange makes no provider call. Authorization health becomes `UNAVAILABLE` with
an actionable reason, cloud refresh operations become `FAILED` with
`current_authority_unavailable`, and email jobs stay durably deferred with that
reason. A lost email outcome after the provider call is `UNKNOWN` and is never
automatically resent.

如果 bearer 缺失、过期、已撤销或缺少精确 operation grant，Exchange 不会调用 Provider。授权健康会变为
`UNAVAILABLE` 并保留可操作原因；云刷新作业会以 `current_authority_unavailable` 变为 `FAILED`；邮件作业会
持久化延后及相同原因。Provider 调用后的邮件结果若丢失则变为 `UNKNOWN`，不会自动重发。

Run the side-effect-free configuration preflight before deploying:

```sh
cyrene-exchange integrations check-config
```

The preflight checks required fields, secret-reference names, HMAC key sizes,
TLS file ownership/modes, direct endpoint schemes, actor/profile pins, and the
exact consumed secret-reference set. It does not dial Platform, Plugins, SMTP,
or cloud APIs. It permits an absent current bearer so a running worker can
persist an unavailable observation instead of reporting false health.

## Process modes

The Product API server and the monitor/outbox worker share the same separate
integration SQLite database. Use the same absolute database path for both
processes.

```sh
# Gateway process only; no integration Plugin clients are constructed.
cyrene-exchange --database /var/lib/cyrene/exchange.sqlite3 serve --mode gateway-only

# Product API for integrations, connections, notifications, and renewal.
cyrene-exchange --database /var/lib/cyrene/exchange.sqlite3 serve \
  --mode integration-only \
  --integration-database /var/lib/cyrene/integrations.sqlite3 \
  --host 127.0.0.1 --port 8081

# Optional combined API process; gateway and integration state remain separate.
cyrene-exchange --database /var/lib/cyrene/exchange.sqlite3 serve \
  --mode combined \
  --integration-database /var/lib/cyrene/integrations.sqlite3

# Independent auth/cloud/email monitor loop or one deterministic cycle.
cyrene-exchange integrations authorization-cloud \
  --integration-database /var/lib/cyrene/integrations.sqlite3
cyrene-exchange integrations authorization-cloud-once \
  --integration-database /var/lib/cyrene/integrations.sqlite3

# The existing issue-command dispatcher remains independently invocable.
cyrene-exchange integrations dispatch \
  --integration-database /var/lib/cyrene/integrations.sqlite3
```

`gateway-only` remains independent of Authority and provider integrations.
`integration-only` and `combined` construct the host-configured integration
clients. The monitor process uses SQLite WAL fencing and can restart separately
from the API process. There is no extra Plugin lifecycle manager.

`gateway-only` 不依赖 Authority 或 Provider 集成。`integration-only` 与 `combined` 会构建 Host 配置的
集成客户端。监控进程通过 SQLite WAL fencing 持久化状态，可以独立于 API 重启。本功能没有额外的 Plugin
生命周期管理器。

## Connection and operation flow

Create a cloud connection using only configured aliases. The actual Plugin
binding and target come from host configuration:

```sh
curl -X POST http://127.0.0.1:8081/api/v1/integrations/connections \
  -H 'Authorization: Bearer <current-first-party-bearer>' \
  -H 'X-Cyrene-Workspace-Id: workspace-a' \
  -H 'Idempotency-Key: create-vm-prod-1' \
  -H 'Content-Type: application/json' \
  -d '{"provider":"azure","bindingRef":"azure-primary","targetRef":"vm-prod"}'
```

Create a WeCom authorization connection without a target selector:

```sh
curl -X POST http://127.0.0.1:8081/api/v1/integrations/connections \
  -H 'Authorization: Bearer <current-first-party-bearer>' \
  -H 'X-Cyrene-Workspace-Id: workspace-a' \
  -H 'Idempotency-Key: create-wecom-primary-1' \
  -H 'Content-Type: application/json' \
  -d '{"provider":"wecom","bindingRef":"wecom-primary"}'
```

Each response row contains the Product connection UUID, provider, display name,
legacy GitHub repository fields, enabled state, and timestamps. It omits actor,
tenant, account, target, and Plugin binding identifiers. Use the returned
connection UUID for authorization-health and resource reads:

```sh
curl 'http://127.0.0.1:8081/api/v1/integrations/connections/<connection-id>/authorization-health?workspaceId=workspace-a' \
  -H 'Authorization: Bearer <current-first-party-bearer>'

curl 'http://127.0.0.1:8081/api/v1/integrations/connections/<connection-id>/resources?workspaceId=workspace-a' \
  -H 'Authorization: Bearer <current-first-party-bearer>'
```

Resource `source` is the normalized provider ID, and `freshness` is `FRESH`,
`STALE`, or `UNKNOWN`. A refresh is a durable read-only Product job; poll the
`Location` returned by the `202` response. Failed provider reads preserve the
last observation and never infer that a resource stopped.

Only a non-null, server-observed native WeCom `authorizationRef` can start a
renewal. The Product creates a durable session before provider I/O and returns
`202` plus a flat Product session `Location`:

```sh
curl -X POST 'http://127.0.0.1:8081/api/v1/accounts/authorizations/<native-authorization-ref>/renewal-sessions?workspaceId=workspace-a' \
  -H 'Authorization: Bearer <current-first-party-bearer>' \
  -H 'Idempotency-Key: renewal-wecom-1'

curl 'http://127.0.0.1:8081/api/v1/accounts/renewal-sessions/<product-session-uuid>?workspaceId=workspace-a' \
  -H 'Authorization: Bearer <current-first-party-bearer>'
```

`authorizationUrl` is one generic navigation field. Exchange returns it only
after one of two independent checks: the exact official onboarding QR URL
(`/ai/qc/gen` with its fixed `source`/`scode` query), or an existing-profile
management URL on the exact official host/path (`/ai/aiHelper/authorizationList`
with its exact 11 typed parameters). Management query keys are unique, unknown
keys are rejected, and the returned query is canonicalized in fixed key order.
The field does not classify every URL as a QR flow. An ambiguous start remains
`VERIFYING` without a URL; a user may explicitly repeat the same POST with the
same key only when the configured provider advertises durable replay. GET
performs only read-only status lookup.

An actor with the dedicated delivery operation can queue the one fixed mail
recipient for an existing notification. The endpoint accepts no recipient or
message fields:

```sh
curl -X POST 'http://127.0.0.1:8081/api/v1/integrations/notifications/<notification-id>/actions/deliver?workspaceId=workspace-a' \
  -H 'Authorization: Bearer <current-first-party-bearer>' \
  -H 'Idempotency-Key: deliver-notification-1'
```

The email job appears at the Product `Location`. `ACCEPTED` reports the SMTP
provider's result, not end-user delivery. An ambiguous post-send result is
`UNKNOWN`; support staff reconcile it manually rather than sending it again.

## 中文部署步骤

1. 复制 `product/examples/integration-configuration.authorization-cloud.json`，只替换 Host 资源引用、固定 Plugin binding、组织/workspace 与稳定别名。`hostSecretRefs` 的值必须是 Host 注入的环境变量名；JSON 中只能出现引用，不能放 bearer、HMAC key、证书私钥或 SMTP 密码。
2. `authorizationCloud.currentAuthority.contexts[]` 中的 issuer、subject、organizationId、workspaceId 是身份匹配 pin。`bearerTokenEnvRef` 每次调用都从 Host 环境重读，随后执行 Platform `VerifyIdentity` 和当前 role-filtered catalog 检查。每次 Provider 签名之前会重新检查精确 operation、actor owner、profile 与 target allowlist。Exchange 不创建或缓存长期用户会话；运维方必须轮换真实签发的第一方 bearer。令牌缺失、过期、撤销或 grant 缺失会产生可操作的 unavailable/deferred 状态，不会伪报健康。
3. `authorizationCloud.profiles` 是闭合的 Host profile map。创建云连接时，`bindingRef` 选择 profile，`targetRef` 选择该 profile 的 target alias；这两个字段都不是 URL。Profile 固定 DirectPlugin `bindingId`、`connectionRef`、transport/mTLS secret refs、caller workload、audience、issuer、HMAC 引用和 organization/workspace。Target alias 将 Product 选择器映射到 Plugin 自己配置的 opaque target，并可进一步限制 `allowedContextRefs`。WeCom profile 固定 `authorizationRef`；不要把 Account Center `accountLinkRef` 当作本地 CLI 授权引用。
4. 执行 `cyrene-exchange integrations check-config`，然后启动 `integration-only` 或 `combined` API。`gateway-only` 不构造这些集成客户端。API 与独立 monitor 使用同一个 integration SQLite 文件；worker 可单独运行 `integrations authorization-cloud` 或单轮 `authorization-cloud-once`。SQLite WAL fencing 保证 worker 重启后检查和通知状态可恢复。
5. 使用当前第一方 bearer 和 `integrationCreateConnection` 创建连接：云连接传入配置过的 `provider`、`bindingRef` 与 `targetRef`；WeCom 连接只传 `provider` 与 `bindingRef`。从响应取得 Product connection UUID，再调用 authorization-health/resources，或对只读云刷新返回的 `202 Location` 轮询 Product operation。连接列表响应为顶层 array，不返回 actor、tenant、target 或 Plugin binding 私有字段。
6. 只有健康检查观察到的非空 native WeCom `authorizationRef` 才能开始 renewal。POST start 使用 `Idempotency-Key` 并返回 `202 Location`；GET 使用单资源路径 `/api/v1/accounts/renewal-sessions/{session_id}`，其中 session id 是 Product UUID。未知 start 不得换 key 自动重试；仅在 Provider 支持 durable replay 时，由用户显式使用相同 key 恢复原 session。
7. 邮件默认关闭。若有业务授权，复制启用片段，固定 `recipientRef` alias 与 `allowedContextRefs`，并为 Exchange/Email Plugin 的 binding 注入同一 HMAC key。Email Plugin 将 alias 映射到固定邮箱，Exchange API 不接受邮箱或邮件内容。用户必须同时持有当前 `integrationDeliverNotification` grant，并位于 Host allowlist；outbox 在 SMTP 前持久化 `SENDING`。明确的发送前授权失败会延后 job，发送结果不确定则进入 `UNKNOWN`，不自动重发。

`emailNotifications.enabled.fragment.json` 中的 `ops-oncall` 只是虚构 alias；真实邮箱地址仅配置在 Email Plugin 的受信任 binding 中。JSON Schema 描述字段结构，`check-config` 还会验证 secret 引用、身份交叉约束、Provider profile、mTLS 和 target/context allowlist。

`authorizationUrl` 是通用导航字段，不代表二维码。Exchange 只允许两种互相独立的来源：固定 onboarding QR 路径 `/ai/qc/gen` 与精确的 `source`/`scode` 参数；或既有 profile 管理路径 `/ai/aiHelper/authorizationList`，并要求官方 Host、11 个唯一且无额外键的 typed 参数。管理链接会按固定键顺序规范化。Client 应按已校验的路径呈现为 QR onboarding 或 profile 权限管理，不能把两类 URL 混为新登录二维码。
