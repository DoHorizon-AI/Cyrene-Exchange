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

后台授权和云端调用每轮都会为精确 actor、组织、workspace 和 operation 重新解析当前
Directory/delegation 证据。缺少或不匹配上下文时会延后 Provider 工作；不会把持久化的
connection 创建者字段当作替代身份。邮件作业会在网络调用前持久化 `SENDING`，过期发送
状态转为 `UNKNOWN`，不会自动重放。
