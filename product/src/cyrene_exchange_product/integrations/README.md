# Product integrations / 产品集成

This package owns durable business state for fixed external integrations. It stores
shared group bindings, exact member-owned ActorBinding references, verified inbound
event metadata, scoped operations, provider observations, and explicit delivery
evidence. It never stores provider credentials or invokes a model or agent.

本目录负责固定外部集成的业务状态，保存 Account Center 和 Platform delegation 的不透明引用、
共享群组绑定、成员专属 ActorBinding、已验证事件元数据、范围内操作、Provider 观察结果与明确的发送证据；
不保存 Provider 凭据，也不调用模型或 Agent。

| File | Responsibility |
| --- | --- |
| `models.py` | CamelCase API models, durable entities, and exact integration errors. |
| `store.py` | Separate SQLite WAL persistence, inbox deduplication, idempotency, and fenced outbox jobs. |
| `ports.py` | Typed Account Center, GitHub, Message, and Delegation boundaries. |
| `commands.py` | Bounded fixed `/issue` command grammar without LLM interpretation. |
| `dispatcher.py` | Durable Authority enqueue/poll runner plus signed execute callback and read-only reconciliation. |
| `authorization_cloud.py` | Fresh-authority-gated provider monitoring, cloud refresh jobs, and email outbox worker. |
| `authorization_cloud_profiles.py` | Closed host profile parsing, actor pins, and binding/resource allowlists. |
| `authorization_cloud_provider.py` | Signed DirectPlugin calls and per-call Platform authority revalidation. |
| `connector_profiles.py` | Closed Navigator HMAC, Teams egress, and isolated computer runner host bindings. |
| `connector_security.py` | Raw-body Navigator HMAC, pinned Platform grant verification, and RFC 8785 connector digests. |
| `connector_operations.py` | Closed GitHub (including proactive task/CI operations), Hugging Face, cloud, and Teams operation/resource maps and safe provider-result projection. |
| `api.py` | Fixed HTTP routes for account profiles, connector authorization/invocation, Teams egress, connections, and webhooks. |
| `auth.py` | Verified Platform identity and signed Product-to-capability caller context. |
| `clients.py` | Typed DirectPlugin invokers for Account Center, GitHub Issues, Teams, and webhook verification. |
| `intake.py` | Authenticated WeCom message admission, fixed `/issue` handling, and link-challenge outbox routing. |

Suggested reading order: `models.py` → `ports.py` → `store.py` → `commands.py` →
`dispatcher.py` → `authorization_cloud.py`.

Legacy background authorization and cloud calls resolve current
Directory/delegation evidence for the exact actor, organization, workspace, and
operation on every cycle. A missing or mismatched context defers provider work;
stored connection creator fields are never used as a substitute identity.
Connector-only `allowedActors` are host pins for provider context signing; a fresh
Directory connector grant is still required for every connector operation. Email
jobs persist `SENDING` before network I/O and transition an expired send to
`UNKNOWN` without automatic replay.

## Authorization and cloud host settings

`authorizationCloud` and `emailNotifications` are optional top-level fields in the
closed `CYRENE_EXCHANGE_INTEGRATION_CONFIGURATION_JSON` object. The profile map is
host-owned: REST `bindingRef` selects one profile and REST `targetRef` selects one
configured target alias. Neither field accepts a URL, DirectPlugin connection
reference, provider binding ID, bearer token, HMAC key, recipient address, or
credential. User-facing connection creation checks the verified actor against the
profile's `allowedContextRefs` or exact `allowedActors` and the target's optional
narrower context allowlist.

Each `currentAuthority.contexts[]` entry pins one expected issuer, subject,
organization, and workspace and names a `bearerTokenEnvRef`. That reference must
exist in `hostSecretRefs`; its mapped environment variable contains a currently
issued first-party bearer. Exchange reads the value on every background provider
call and calls Platform `VerifyIdentity` and the role-filtered catalog snapshot
again. It does not cache or extend a session, infer a principal from a stored
connection, or turn a missing bearer into a service identity. Operators must
rotate the actual current bearer through the host secret store and restart or
reload the service environment as required by the host. A missing, expired, or
revoked bearer or an absent operation grant produces an unavailable authorization
observation, a failed cloud refresh with a reason code, or a deferred email job;
none is reported as healthy.

The email sender is disabled unless `emailNotifications.enabled` is explicitly
`true`. Its profile fixes a DirectPlugin endpoint, HMAC context key reference,
caller workload, audience, tenant, one `recipientRef`, and allowed actor contexts.
The recipient reference resolves inside the email Plugin to a configured
recipient alias. A fresh `integrationDeliverNotification` grant and host actor
allowlist are both required before the outbox reaches `SENDING`. The explicit
delivery route accepts no recipient, subject, or message body from a caller; it
queues an idempotent Product operation for an actor-owned notification. Previously
accepted or `UNKNOWN` jobs are returned as-is and never resubmitted.

An abridged host-owned configuration shape is:

```json
{
  "hostSecretRefs": {
    "bearers/member-a": "EXCHANGE_MEMBER_A_BEARER",
    "keys/wecom": "WECOM_AUTH_CONTEXT_KEY",
    "keys/azure": "CLOUD_AUTH_CONTEXT_KEY",
    "keys/email": "EMAIL_CONTEXT_HMAC_KEY"
  },
  "authorizationCloud": {
    "monitorIntervalSeconds": 900,
    "currentAuthority": {
      "contexts": [
        {
          "contextRef": "member-a",
          "issuer": "https://identity.example.invalid",
          "subject": "member-a",
          "organizationId": "org-a",
          "workspaceId": "workspace-a",
          "bearerTokenEnvRef": "bearers/member-a"
        }
      ]
    },
    "profiles": {
      "wecom-primary": {
        "provider": "wecom",
        "directPlugin": {
          "bindingId": "host-wecom-auth-binding",
          "connectionRef": "grpcs://wecom-plugin.internal:7443",
          "transport": "mtls",
          "mtls": {
            "rootCertificateRef": "tls/plugin-root",
            "clientCertificateRef": "tls/exchange-client-cert",
            "clientKeyRef": "tls/exchange-client-key"
          }
        },
        "callerWorkload": "exchange.integrations",
        "audience": "wecom-authorization",
        "expectedIssuer": "https://identity.example.invalid",
        "contextKeyRef": "keys/wecom",
        "organizationId": "org-a",
        "workspaceId": "workspace-a",
        "allowedContextRefs": ["member-a"],
        "displayName": "WeCom Production",
        "authorizationRef": "native-wecom-auth-ref"
      },
      "azure-primary": {
        "provider": "azure",
        "directPlugin": {
          "bindingId": "host-cloud-binding",
          "connectionRef": "grpc://127.0.0.1:7444",
          "transport": "local"
        },
        "callerWorkload": "exchange.integrations",
        "audience": "cloud-resources",
        "expectedIssuer": "https://identity.example.invalid",
        "contextKeyRef": "keys/azure",
        "organizationId": "org-a",
        "workspaceId": "workspace-a",
        "allowedContextRefs": ["member-a"],
        "targets": {
          "vm-prod": {
            "targetRef": "provider-target-vm-prod",
            "displayName": "Production VM",
            "allowedContextRefs": ["member-a"]
          }
        }
      }
    }
  },
  "emailNotifications": {
    "enabled": false
  }
}
```

When email is enabled, `emailNotifications` also requires a fixed `directPlugin`,
`callerWorkload`, `audience`, `expectedIssuer`, `contextKeyRef`,
`organizationId`, `workspaceId`, `recipientRef`, and `allowedContextRefs`. SMTP
endpoints, mailbox addresses, sender identity, and SMTP credentials remain in the
Email Plugin activation. The HMAC keys for WeCom, cloud, and email must match the
corresponding Plugin binding keys injected by the host.

## Directory-authorized connector calls

The internal connector facade is separate from Product execution credentials.
Navigator authenticates `POST /internal/v1/connector-operation-grants` with
`X-Cyrene-Navigator-Key-Id`, `X-Cyrene-Navigator-Timestamp`, and
`X-Cyrene-Navigator-Signature`. The signature covers the exact raw JSON bytes,
HTTP method, path, and timestamp. `connectorHost.navigatorConnector.keyFileRef`
resolves through `hostSecretRefs` to `NAVIGATOR_EXCHANGE_HMAC_KEY_FILE`, whose
value is a mounted-file path containing exactly 32 key bytes. Ordinary internal
HMAC bodies stay capped at 128 KiB; only the fixed connector-grant mint path allows
up to 1,500,000 raw bytes so a valid 1 MiB Hugging Face upload can be authorized.
The cap is selected from the fixed HTTP method/path, never from a request field.
Exchange bounds the body before parsing, rejects duplicate JSON members and
replayed request IDs, and calls the Platform connector-only Authority RPC over the
pinned Exchange workload mTLS identity. It returns a maximum 15-second signed grant
only after the current Directory membership and exact operation role are approved.

Navigator invokes
`POST /internal/v1/connector-operations/{connectionRef}` with the exact provider,
profile, operation, resource reference, arguments, and request ID. The
`X-Cyrene-Connector-Grant-Bin` header carries the Authority grant; the Product
execution-credential header is never accepted on this route. Exchange derives
mutability from its closed provider operation catalog and independently rebuilds
the profile/resource scope and RFC 8785 argument digest before the provider call.
`rfc8785==0.1.4` provides the canonical UTF-8 bytes used for connector argument
digests, resource references, and Teams route hashes; non-finite numbers and
integers outside the interoperable safe range are rejected.

Provider responses use the fixed envelope
`{requestId,outcome,operationRef?,result:{content,isError}}`, where `outcome` is
`verified`, `pending`, `uncertain`, or `failed`. Only submitted writes can become
`pending` or `uncertain`; provider states such as CI `PENDING` or resource `RUNNING`
remain business data for a verified read. Pending writes require an operation
reference. Unknown writes are never submitted again automatically. A later
terminal `cloud.operation.status.read` reconciles the matching pending receipt.
The durable ledger stores request/profile/resource digests, lifecycle state, and a
receipt of at most 16 KiB; it never stores provider response bodies, private file
content, or credentials. Exact same-attempt replay requires a fresh matching
Authority grant and returns a `receiptOnly` summary. Read results say
`freshRequestRequired` when the original data is not cached; mutation receipts
say `do-not-repeat`. Unresolved writes remain tombstones until status reconciliation
or an explicit owner-verified new task. Terminal receipts are bounded by entry
and byte budgets and may expire after 24 hours.

Teams egress uses the same grant and receipt boundary at
`POST /internal/v1/teams/messages` with a nested `conversation` containing tenant,
team, channel, conversation ID, numeric root thread message ID, and the validated
Bot Framework `serviceUrl`, plus `text`. Exchange accepts only the configured
tenant/team/channel and official service URL routes. The complete conversation is
covered by the resource reference and the canonical `{conversation,text}` digest;
the URL is passed to the Teams provider as the `service_url` vendor fact so replies
stay in their regional Bot Framework endpoint. The Teams provider alone reads its
bot secret. A `429` preserves `Retry-After`; a delivery with unknown outcome is
persisted and returned as `uncertain` without creating a resend.

Directory-authorized provider operations are available only to actors granted
`navigator.connector.operator.v1`. Typed provider API tools bind their fixed
resource scope; native GitHub, Hugging Face, Azure, GCP, and RunPod CLI calls bind
the host-owned profile and exact `argv` array, suppress all
stdout/stderr, and block credential-export arguments. CLI command completion is
not treated as remote resource success: an unverified remote state remains
`uncertain` until a typed status read confirms it.

For a Teams/GitHub/Hugging Face deployment, start from
[`integration-configuration.teams-connectors.json`](../../../examples/integration-configuration.teams-connectors.json).
It uses only the dedicated `platformAuthority.connectorWorkload` mTLS identity;
it does not require legacy Product `identity`/`productWorkload` services or any
WeCom binding. The Account Center gets its own mTLS certificate/key references;
GitHub, Hugging Face, and Teams provider runtimes use the separate plugin client
identity. GitHub callback and WeCom source caller/key pairs are optional and
remain closed with a typed unavailable response when omitted. The Authority
public keyring must be mounted read-only and named by
`CYRENE_EXCHANGE_AUTHORITY_SIGNING_KEYS_FILE`; its JSON shape is
`{"keys":{"key-id":"<base64 raw 32-byte Ed25519 public key>"}}`. Do not mount
the Authority private signing key into Exchange.

For a production integration-only listener, run `serve --mode integration-only`
with both `CYRENE_EXCHANGE_TLS_CERT_FILE` and `CYRENE_EXCHANGE_TLS_KEY_FILE` set
to the mounted certificate and private-key paths (or pass `--tls-cert-file` and
`--tls-key-file`). The certificate must cover the internal `exchange` DNS name.
Exchange rejects a missing half-pair, invalid PEM, or mismatched key before
starting Uvicorn. Leave both unset only for local development HTTP. The internal
root CA belongs on Navigator's HTTPS client trust path and is not mounted as an
Exchange server secret.

Initial profile setup is a local operator action, not an HTTP endpoint. Copy the
[`private-connector-bootstrap.template.json`](../../../examples/private-connector-bootstrap.template.json)
to a 0600 private file and fill the expected `actor` issuer/subject/organization/
workspace and GitHub installation/repository data. Add the optional HF block when
its host OAuth profile is ready; it contains only HF profile/target aliases and a
stable `credentialSecretRef` (`huggingface/connector-token` in the example), never
OAuth tokens. Keep idempotency keys stable across retries. Then run:

```bash
cyrene-exchange integrations bootstrap-connectors \
  --integration-database /var/lib/cyrene/exchange/integrations.sqlite3 \
  --private-config /run/cyrene/private/connector-bootstrap.json \
  --plan-only
```

The plan-only command verifies one fresh signed `github.repository.list` grant
and prints stable profile references and connection UUIDs; it does not link an
account or write a connection. For each profile intended to be shared, add its
planned profile reference to the private Account Center
`workspace_operator_profile_refs` setting, then run the same command without
`--plan-only`. Exchange requires Account Center's profile readback to confirm
the configured access mode before saving the connection. `actor_owned` is the
default; `workspace_operator` is an explicit host-side opt-in. This opt-in does
not add other actors to `allowedActors` or impersonate the bootstrap actor.

Every shared-profile operation is authorized for the actual caller by a fresh
Directory grant bound to its exact provider, profile, resource, and argument
digest. Exchange passes the verified grant claims to Account Center with each
GitHub/Hugging Face credential-lease request; Account Center accepts a shared
lease only for that same actor and workspace and consumes the grant reference
once. Adding a maintainer later requires only granting that person
`navigator.connector.operator.v1` in the same organization/workspace. Their
next operation uses their own verified identity; revocation affects the next
grant check. Other organizations, workspaces, or issuers cannot use the shared
connection.
For HF device OAuth, set the HF host profile's `authMode` to `device_oauth` and
configure Account Center's private OAuth seed file for the stable
`huggingface/connector-token` source. The local OAuth helper and Account Center
own the access/refresh tokens and automatic renewal; Exchange sends only that
stable reference and the declared repository scopes.

## Proactive GitHub provider tools

Exchange exposes the provider catalog's `tool.provider.v1` GitHub tools only
when their exact IDs appear in the fixed operation map. The new reads are issue
search, Actions job listing, and bounded job-log excerpts. The new writes create
or delete task branches, commit a bounded file on a task branch, open a draft
pull request, and rerun failed jobs for an exact CI attempt. Three additional
readbacks locate an exact branch, branch file, or draft pull request after an
uncertain write. Resource targets
use the stable GitHub repository ID/name plus the exact branch, file, or run
locator; the full argument digest also binds queries, content, and optimistic
preconditions. GitHub App calls still require a fresh Directory grant and
one-use Account Center lease. Ambiguous writes remain blocked until readback;
they are never retried automatically. See the
[`connector-operations.md`](../../../../contracts/product/v1/connector-operations.md)
contract for the target map.

## Host computer runner

The optional `connectorHost.computerRunner` section binds the fixed
`computer-runtime` provider binding to one logical runner workspace and exact
organization/workspace/issuer. It is a host-owned runtime profile; it does not
create an OAuth integration connection or Account Center credential. When the
profile is absent, the computer operation map and catalog entry are omitted.
The profile uses the configured DirectPlugin mTLS channel, passes only the
provider's typed arguments, and caps file writes at 1 MiB, each file read at
64 KiB, and each command output stream at 64 KiB. The physical isolation root
remains owned by the runner deployment.

The host profile contains only a logical UUID, the admitted caller scope, and
the fixed DirectPlugin reference. The TLS references resolve through the
existing `hostSecretRefs` map; do not put key material or filesystem paths in
this Exchange profile. Example shape:

```json
{
  "computerRunner": {
    "profileRef": "computer-workspace-main",
    "connectionRef": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "organizationId": "organization-id",
    "workspaceId": "workspace-id",
    "expectedIssuer": "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0",
    "directPlugin": {
      "bindingId": "computer-runtime",
      "connectionRef": "grpcs://computer-runner.internal:443",
      "transport": "mtls",
      "mtls": {
        "rootCertificateRef": "computer/root-ca",
        "clientCertificateRef": "exchange/computer-client-cert",
        "clientKeyRef": "exchange/computer-client-key"
      }
    },
    "maxCommandTimeoutMs": 600000,
    "maxFileBytes": 1048576,
    "maxReadBytes": 65536,
    "maxDirectoryDepth": 32
  }
}
```

## Private Navigator tool catalog snapshot

Before Navigator starts, export tool schemas from the configured provider
DirectPluginRuntime channels and the exact Exchange connection rows:

```bash
cyrene-exchange integrations connector-tool-catalog \
  --integration-database /var/lib/cyrene/exchange/integrations.sqlite3 \
  --issuer "$CONNECTOR_ACTOR_ISSUER" \
  --subject "$CONNECTOR_ACTOR_SUBJECT" \
  --organization-id "$CONNECTOR_ORGANIZATION_ID" \
  --workspace-id "$CONNECTOR_WORKSPACE_ID"
```

The command writes one JSON snapshot to stdout and nothing else there. Capture
it atomically in the host-owned private config directory, set mode `0600`, then
mount it read-only at `/run/config/connector-tool-catalog.json` and configure
Navigator with `CYRENE_CONNECTOR_TOOL_CATALOG_FILE`. Its closed shape is
`{schemaVersion:1,items:[{bindingId,capabilityId,providerId,connectionRef,
profileRef,tools:[{id,name,description,readOnly,inputSchema}]}]}`. Tool names,
descriptions, and schemas come directly from each provider's typed `list_tools`
response over its configured DirectPluginRuntime channel. Exchange filters that
catalog to its fixed operation map and derives `readOnly` from the same closed
mutation table used by grant enforcement. A missing required tool, malformed
schema, wrong Plugin binding, or credential-like schema property aborts export;
no partial or fabricated catalog is emitted. Message connectors such as Teams
are not model tools and remain on the message egress facade.

The legacy GitHub issue-sync Product API still accepts its exact actor-owned
repository connection shape without provider-profile selectors. That connection
continues through the existing sync-binding and ActorBinding flow. It is not a
GitHub App profile and is intentionally absent from the Directory-authorized
tool catalog; modern connector calls still require a verified App profile.

The full legacy authorization/cloud example remains available at
[`integration-configuration.authorization-cloud.json`](../../../examples/integration-configuration.authorization-cloud.json).

## Directory 授权的 Connector 调用

内部 Connector facade 与 Product execution credential 相互独立。Navigator 使用
`X-Cyrene-Navigator-Key-Id`、`X-Cyrene-Navigator-Timestamp` 和
`X-Cyrene-Navigator-Signature` 调用
`POST /internal/v1/connector-operation-grants`。签名覆盖原始 JSON 字节、HTTP 方法、路径和
时间戳。`connectorHost.navigatorConnector.keyFileRef` 通过 `hostSecretRefs` 指向
`NAVIGATOR_EXCHANGE_HMAC_KEY_FILE`；该变量存放宿主只读密钥文件的路径，文件内必须恰好有
32 字节密钥。普通内部 HMAC 正文限制为 128 KiB；仅固定的 connector grant mint 路由允许最多
1,500,000 字节原始正文，以覆盖合法的 1 MiB Hugging Face 文件上传。上限只由固定 HTTP method/path
选择，不接受请求字段覆盖。Exchange 在解析前限制正文大小，拒绝重复 JSON 字段和重放的 request ID，
再使用固定的 Exchange workload mTLS 身份调用 Platform connector-only Authority RPC。只有当前
Directory 成员关系和精确操作角色均通过，才会签发最长 15 秒的 grant。

Navigator 随后调用
`POST /internal/v1/connector-operations/{connectionRef}`，提交精确的 provider、profile、
operation、resource reference、arguments 和 request ID，并通过独立的
`X-Cyrene-Connector-Grant-Bin` header 传递 Authority grant。该路由不接受 Product execution
credential。Exchange 从固定的 provider operation 表推导是否写入，并重新计算 profile/resource
范围与 RFC 8785 参数摘要后才调用 provider。连接器参数摘要、resource reference 和 Teams 会话
路由摘要使用 `rfc8785==0.1.4` 生成规范 UTF-8 字节；非有限数字或超出安全整数范围的值会被拒绝。

Provider 返回固定 envelope，`outcome` 为 `verified`、`pending`、`uncertain` 或 `failed`。
只有已提交的写操作才会根据远端状态进入 `pending` 或 `uncertain`；CI 的 `PENDING` 和资源的
`RUNNING` 等状态仍是已验证读取的业务数据。异步写操作必须返回 operation reference。结果未知的
写入不会自动重发，后续 `cloud.operation.status.read` 终态回读会对账对应的回执。

持久账本只保存 request/profile/resource 摘要、生命周期状态和最多 16 KiB 的回执，不保存完整
provider 响应、私有文件内容或凭据。相同 attempt 的回放必须仍带有效且匹配的 Authority grant，
并且只返回 `receiptOnly` 摘要。读取回执会用 `freshRequestRequired` 指示原始数据未缓存；写入
回执返回 `do-not-repeat`。未对账的写操作 tombstone 会保留到状态回读或 owner 明确发起新任务；
终态回执按条目数与字节数双重限额，并可在 24 小时后过期。

Teams egress 也经过同一 grant 和回执边界：请求发往
`POST /internal/v1/teams/messages`，正文包含嵌套 `conversation`（租户、团队、频道、会话 ID、
数字型根帖消息 ID 和经验证的 Bot Framework `serviceUrl`）及 `text`。Exchange 只接受配置的
tenant/team/channel 和官方服务 URL 路由。完整会话对象参与 resource reference 和
`{conversation,text}` 参数摘要；Exchange 将 `serviceUrl` 作为 `service_url` vendor fact 传给
Teams provider，使回复留在原区域。Bot secret 只由 Teams provider 读取。`429` 会保留
`Retry-After`；发送结果未知时 Exchange 持久化并返回 `uncertain`，不创建重发。

只有获得 `navigator.connector.operator.v1` 的主体才能使用 Directory 授权的连接器操作。类型化
Provider API 工具绑定固定资源范围；GitHub、Hugging Face、Azure、GCP 和 RunPod 的原生 CLI
调用绑定宿主管理的 profile 和完整 `argv` 数组，始终隐藏
stdout/stderr 并阻止凭据导出参数。CLI 命令结束不代表云端资源已成功；只有状态回读确认后，
才能报告远端终态。

Teams/GitHub/Hugging Face 最小部署可使用
[`integration-configuration.teams-connectors.json`](../../../examples/integration-configuration.teams-connectors.json)。
它只需要专用 `platformAuthority.connectorWorkload` mTLS 身份，不要求旧 Product
`identity`/`productWorkload` 服务，也不需要 WeCom 配置。Account Center 使用独立的 mTLS
证书/密钥引用；GitHub、Hugging Face 和 Teams provider 使用另一套 Plugin client 身份。
省略 GitHub callback 或 WeCom source caller/key 后，对应功能保持关闭并返回明确的 unavailable
错误。Authority 公钥 keyring 通过只读挂载文件 `CYRENE_EXCHANGE_AUTHORITY_SIGNING_KEYS_FILE`
指定，格式为 `{"keys":{"key-id":"<base64 raw 32-byte Ed25519 public key>"}}`；Exchange
不得挂载 Authority 私钥。

生产环境的 integration-only listener 需运行 `serve --mode integration-only`，并同时设置
`CYRENE_EXCHANGE_TLS_CERT_FILE` 与 `CYRENE_EXCHANGE_TLS_KEY_FILE` 指向挂载的证书和私钥文件，
也可使用 `--tls-cert-file` / `--tls-key-file`。证书 SAN 必须覆盖内部 DNS 名 `exchange`。
缺少任一文件、PEM 无效或证书与私钥不匹配时，Exchange 会在启动 Uvicorn 前失败。仅在本机开发时
才同时省略两者并使用 HTTP。内部根 CA 只供 Navigator HTTPS 客户端验证服务端证书，不作为 Exchange
监听器密钥挂载。

首次连接配置仅能从本地 operator 命令执行，不开放 HTTP 管理入口。复制
[`private-connector-bootstrap.template.json`](../../../examples/private-connector-bootstrap.template.json)
到权限为 0600 的私有文件，填写期望 actor 的 issuer/subject/organization/workspace，以及 GitHub
App installation ID 和仓库信息。HF OAuth host profile 准备好后再加入可选 HF 段，其中只有
profile/target alias 和 stable `credentialSecretRef`（示例为 `huggingface/connector-token`），不含
OAuth token。重试时保持幂等键不变。设备 OAuth 模式需在 HF host profile 设置
`authMode: device_oauth`，并在 Account Center 私有 OAuth seed file 中为稳定来源
`huggingface/connector-token` 配置本地认证。OAuth helper 与 Account Center 管理并自动轮换
access/refresh token；Exchange 只提交稳定引用和声明的仓库范围。

```bash
cyrene-exchange integrations bootstrap-connectors \
  --integration-database /var/lib/cyrene/exchange/integrations.sqlite3 \
  --private-config /run/cyrene/private/connector-bootstrap.json
```

命令先取得并验证一份新的 `github.repository.list` 签名 grant，以确认 Directory operator 角色，
再通过配置好的签名 host caller 调用 Account Center，并幂等创建 Exchange connection。输出只有
profile reference 和连接 UUID，供 `cyrene-exchange integrations connector-bindings` 使用，不会输出
Provider 凭据。共享 profile 先用 `--plan-only` 验证 Directory 授权并取得稳定 profile reference；将该
reference 加入 Account Center 私有配置 `workspace_operator_profile_refs` 后，再去掉 `--plan-only` 执行链接和
connection 持久化。默认 `actor_owned`；只有私有部署配置显式启用 `workspace_operator` 时才共享。公开 API
不接受调用者自行申请共享，也不会将其他维护者写入 `allowedActors` 或冒充初始化者。

每次共享 profile 操作都会针对真实调用者、provider、profile、资源和参数摘要重新申请短时 Directory grant。
Exchange 把已验证的 grant claims 随 GitHub/Hugging Face lease 请求交给 Account Center；Account Center 只在
actor、workspace 和参数摘要完全匹配且 grant 未过期、未使用时签发 lease。后续增补维护者只需在同一组织和
workspace 授予 `navigator.connector.operator.v1`；其操作使用本人的验证身份，撤权会影响下一次 grant 检查。
其他 issuer、组织或 workspace 不能使用该共享连接。

## 主动 GitHub Provider 工具

只有固定 operation map 中的精确 ID 会从 Provider `tool.provider.v1` catalog 暴露给
Exchange。新增读取操作包括 Issue 搜索、Actions job 列表和有行数上限的 job 日志摘要；
新增写入操作包括创建/删除任务分支、向任务分支提交有限大小文件、创建 Draft PR，以及
针对精确 CI attempt 重跑失败 job。另有三个读取操作分别按准确分支、分支文件和 Draft PR
定位，供写入结果不明时独立回读。资源 target 使用稳定 GitHub 仓库 ID/name 和准确的
branch、file 或 run 定位符；完整参数 digest 还绑定查询文本、内容和乐观并发前置条件。
GitHub App 调用仍要求新的 Directory grant 与 Account Center 一次性 lease。写入结果有歧义时
保持阻塞，等待回读，不会自动重试。目标映射见
[`connector-operations.md`](../../../../contracts/product/v1/connector-operations.md)。

## Host computer runner

可选 `connectorHost.computerRunner` section 将固定的 `computer-runtime` provider binding
绑定到一个逻辑 runner workspace 和精确的组织/workspace/issuer。它是 Host 管理的运行时
profile，不创建 OAuth 集成 connection 或 Account Center 凭据。未配置 profile 时，computer
操作 map 与工具目录项都会关闭。profile 使用已配置的 DirectPlugin mTLS 通道，只传递 Provider
声明的类型化参数；文件写入上限 1 MiB、每次文件读取 64 KiB、command 的 stdout/stderr 各
64 KiB。物理隔离根目录由 runner 部署管理。

Host profile 只保存逻辑 UUID、允许的调用者 scope 和固定 DirectPlugin 引用。TLS 引用通过
已有 `hostSecretRefs` 映射解析；Exchange profile 不包含密钥内容或文件系统路径。字段形状
见上方 JSON。

## Navigator 私有工具目录快照

Navigator 启动前，通过已配置的 DirectPluginRuntime 通道和 Exchange 持久连接导出工具 schema：

```bash
cyrene-exchange integrations connector-tool-catalog \
  --integration-database /var/lib/cyrene/exchange/integrations.sqlite3 \
  --issuer "$CONNECTOR_ACTOR_ISSUER" \
  --subject "$CONNECTOR_ACTOR_SUBJECT" \
  --organization-id "$CONNECTOR_ORGANIZATION_ID" \
  --workspace-id "$CONNECTOR_WORKSPACE_ID"
```

命令只向 stdout 输出一份 JSON 快照。宿主应将其原子写入私有配置目录、设置为 `0600`，再以只读方式挂载到
`/run/config/connector-tool-catalog.json`，并设置 Navigator 的
`CYRENE_CONNECTOR_TOOL_CATALOG_FILE`。固定结构为
`{schemaVersion:1,items:[{bindingId,capabilityId,providerId,connectionRef,profileRef,
tools:[{id,name,description,readOnly,inputSchema}]}]}`。工具名称、说明和 schema 直接来自对应 Provider 的
typed `list_tools` 响应；Exchange 只保留闭合 operation map 中的工具，并从同一授权 mutability 表推导
`readOnly`。缺少必需工具、schema 格式错误、插件 binding 不匹配或 schema 属性包含类似凭据的字段时，命令失败且不输出部分或伪造目录。Teams 等消息 connector 仍通过消息发送 facade，不作为模型工具暴露。

旧 GitHub issue-sync Product API 仍支持完全不含 provider profile selector 的 actor-owned 仓库连接，并继续
走现有 sync-binding / ActorBinding 流程。该连接不代表 GitHub App profile，也不会进入 Directory 授权工具目录；
新的 connector 调用仍必须使用经过验证的 App profile。

后台授权和云端调用每轮都会为精确 actor、组织、workspace 和 operation 重新解析当前
Directory/delegation 证据。缺少或不匹配上下文时会延后 Provider 工作；不会把持久化的
connection 创建者字段当作替代身份。邮件作业会在网络调用前持久化 `SENDING`，过期发送
状态转为 `UNKNOWN`，不会自动重放。
