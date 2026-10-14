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
| `api.py` | Fixed HTTP routes for account links, connections, bindings, issue actions, and webhooks. |
| `auth.py` | Verified Platform identity and signed Product-to-capability caller context. |
| `clients.py` | Typed DirectPlugin invokers for Account Center, GitHub Issues, and webhook verification. |
| `intake.py` | Authenticated WeCom message admission, fixed `/issue` handling, and link-challenge outbox routing. |

Suggested reading order: `models.py` → `ports.py` → `store.py` → `commands.py` →
`dispatcher.py` → `authorization_cloud.py`.

Background authorization and cloud calls resolve current Directory/delegation
evidence for the exact actor, organization, workspace, and operation on every
cycle. A missing or mismatched context defers provider work; stored connection
creator fields are never used as a substitute identity. Email jobs persist
`SENDING` before network I/O and transition an expired send to `UNKNOWN` without
automatic replay.

## Authorization and cloud host settings

`authorizationCloud` and `emailNotifications` are optional top-level fields in the
closed `CYRENE_EXCHANGE_INTEGRATION_CONFIGURATION_JSON` object. The profile map is
host-owned: REST `bindingRef` selects one profile and REST `targetRef` selects one
configured target alias. Neither field accepts a URL, DirectPlugin connection
reference, provider binding ID, bearer token, HMAC key, recipient address, or
credential. The API checks the verified actor against the selected profile's
`allowedContextRefs` and the target's optional narrower context allowlist.

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

后台授权和云端调用每轮都会为精确 actor、组织、workspace 和 operation 重新解析当前
Directory/delegation 证据。缺少或不匹配上下文时会延后 Provider 工作；不会把持久化的
connection 创建者字段当作替代身份。邮件作业会在网络调用前持久化 `SENDING`，过期发送
状态转为 `UNKNOWN`，不会自动重放。
