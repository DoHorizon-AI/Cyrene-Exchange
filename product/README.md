# Cyrene Exchange Product

This package owns Exchange's persisted Product resources and control APIs:
gateway endpoints, routes and route drafts, trusted credential mappings,
content-free request audits, and tenant quota limits. Provider execution and
usage aggregation remain Plugins-owned capabilities.

本包拥有 Exchange 的持久化 Product 资源与控制 API：Gateway Endpoint、Route 与
Route Draft、可信凭据映射、不含请求内容的审计，以及租户配额上限。Provider 执行
与用量汇总仍由 Plugins 能力拥有。

## Exchange route drafts / Exchange 路由草稿

`Send to Exchange` creates an existing Product `GatewayRoute` in `DRAFT` state.
The existing SQLite authority persists it, and the existing route planner selects
only ACTIVE rows. A draft therefore creates no publicly routable model service.
The receiving Product owns edits and publication; source Endpoint URI/version
and model Artifact digest remain references to Reactor.

“发送到 Exchange”创建 DRAFT 路由，复用已有路由存储和选择器。部署成功不会自动
创建或启用路由。草稿保存来源 Endpoint URI/version、Artifact digest、真实控制用户
与 workspace；幂等键和草稿在同一事务落盘。没有新增全局资源注册中心。

## Receiver operations / 接收方操作

- `POST /api/v1/gateway-route-drafts`, with a mandatory `Idempotency-Key`, is the
  legacy organization-unscoped writer. It creates a draft from `endpointId`,
  `modelPattern`, `targetBindingId`, `targetModel`, `priority` and `source`
  (`product=reactor`, `resourceUri`, `resourceVersion`, `artifactDigest`). The
  configured legacy control credential determines the actor and workspace.
- `GET /api/v1/gateway-routes/{id}` opens an existing organization-unscoped
  resource for inspection.
- `PATCH /api/v1/gateway-route-drafts/{id}` edits model pattern, permitted target,
  target model and priority using the current `resourceVersion`.
- `POST /api/v1/gateway-route-drafts/{id}/actions/confirm` takes the inspected
  `resourceVersion`. Confirmation rechecks source read permission, Endpoint version,
  READY state, protocol/model/Artifact compatibility, and a real inference probe
  through Platform selection and the direct Plugins-owned provider endpoint. The store commits
  ACTIVE only if that draft version still matches after validation.

## Private Workspace adapter / 私有 Workspace 适配器

Platform service calls use these fixed Product paths:

- `GET /api/v1/workspace/gateway-routes` lists only routes for the Bearer
  credential's configured organization and workspace.
- `POST /api/v1/workspace/gateway-route-drafts` creates a `DRAFT` in that same
  scope and requires `Idempotency-Key`.
- `POST /api/v1/workspace/gateway-route-drafts/direct` creates a source-less
  `DRAFT` for a provider binding explicitly admitted by the Exchange operator.
  It still requires the current endpoint grant and cannot accept a Reactor URL.
- `POST /api/v1/workspace/gateway-route-drafts/{routeId}/actions/confirm`
  confirms the exact draft version after rechecking actor, organization,
  workspace, current endpoint grant, endpoint state and provider availability.
  DirectPlugin bindings must report `SERVING` for the expected plugin ID and
  `model.provider.v1` before activation.

The host maps each Bearer secret to a `ProductPrincipal` containing a
server-assigned actor, organization, workspace and credential reference. Exchange
persists only the SHA-256 token digest. Multiple configured tokens may share one
organization/workspace under distinct credential references during rotation.
Credentials without an organization and missing credentials cannot call either
private path. Configure endpoint access separately through
`WorkspaceEndpointGrant(endpoint_id, organization_id, workspace_id)`; private
draft creation checks the exact grant and endpoint in the same SQLite write
transaction. Historical global endpoints receive no workspace grant by
migration. Request bodies cannot supply the organization, workspace, actor or
endpoint grant.

Gateway data-plane route selection uses the organization and workspace resolved
from the authenticated bearer. An organization-scoped credential sees only
ACTIVE routes for that exact pair; it never falls back to another workspace or
the legacy global route list. An unscoped legacy credential continues to see
only rows with unknown organization attribution. The models list, readiness
probe, and service route count use the same persisted state without exposing
another workspace's route definitions.

## Embeddings data plane

The fused Product server exposes `POST /v1/embeddings` through the same persisted
route planner, Gateway credentials, and `model.provider.v1` facade as chat. It
accepts one text or an ordered batch of up to 128 texts with
`encoding_format: "float"`; response indexes follow input order and the response
model comes from the provider. Product rejects incomplete batches, dimension
drift, non-finite values, and zero vectors before returning a response. Client
disconnects signal cancellation to the provider call. Typed provider failures
retain their HTTP status and finite `Retry-After` hint. The endpoint never
synthesizes vectors or chooses a chat model as an embedding fallback.

The legacy `/api/v1/gateway-routes` list and `/{routeId}` read return only rows
whose organization is unknown (`organization_id IS NULL`). Existing
workspace-only rows stay visible through those paths after migration and remain
unknown to the private adapter. New private rows are not visible or editable via
the legacy route paths. Organization-bound credentials cannot use legacy global
write operations; organization-unscoped control credentials retain the old
writer behavior and create unscoped rows. Draft idempotency keys are partitioned
by a digest of the trusted organization/workspace pair.

The operator CLI accepts repeatable `--control-credential-env
CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME` entries for private control Bearers
and `--gateway-credential-env CREDENTIAL_REF=[ORG_ID=]WORKSPACE_ID=ENV_NAME`
entries for separate chat/data-plane Bearers. The new
`--control-only-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME`
entry (use `-` for an unscoped organization) configures an operator API Bearer
that is explicitly excluded from Gateway authentication. All secret values are
read from environment variables; arguments contain only variable names. Keep
the roles distinct.
The old `--control-token(-env)` remains organization-unscoped and dual-use for
legacy compatibility, but cannot call the private Workspace aliases. Prefer
the environment form because raw CLI arguments can be visible to local process
inspection. Endpoint grants use repeatable
`--workspace-endpoint-grant ENDPOINT_UUID=ORG_ID=WORKSPACE_ID` entries. Multiple
control credential entries can provide same-scope token rotation under distinct
credential references.

For a local Plugins-owned provider, repeat
`--direct-plugin-provider BINDING=grpc://127.0.0.1:PORT`. This local transport
accepts only loopback or Unix-socket targets. Workspace route confirmation
performs a bounded DirectPlugin Health check before publishing the binding.
For authorized media, set `--work-attachment-origin` and repeat
`--work-attachment-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ACTOR_ID=ENV_NAME`.
Each Work bearer is separate from Exchange tokens and is bound to that exact
Exchange principal; Work authorizes the attachment read and Exchange checks
the returned digest, MIME type and bounded byte count before the model call.

来源资源不可达、无权读取、版本变化、协议不兼容或 provider 探针失败时，草稿保持
DRAFT 并返回明确错误。控制 API 不会把普通网关聊天凭据当作发布权限。只有上文的
私有 Workspace 别名按组织和 workspace 隔离；其他 legacy control 路径保留现有实例级
语义。WSL 不提供多租户 GPU 硬隔离。

Platform 私有调用固定使用 `GET /api/v1/workspace/gateway-routes` 与
`POST /api/v1/workspace/gateway-route-drafts`。模型提供方绑定还可通过
`POST /api/v1/workspace/gateway-route-drafts/direct` 创建不带 Reactor 来源的 DRAFT；
该路径只接受 operator 已准入的 binding，仍需精确 endpoint grant。
`POST /api/v1/workspace/gateway-route-drafts/{routeId}/actions/confirm` 使用相同
Workspace 控制凭据确认草稿，并在激活前重新检查 endpoint grant、Endpoint 状态、版本与
Provider 健康。Host 将 Bearer 摘要映射到服务端配置的
actor、组织、workspace 和 credential reference；数据库不保存明文 token。同一
组织/workspace 可用不同 credential reference 配置多个轮换 token。没有组织范围或
没有凭据时，私有路径拒绝请求。Operator 还必须通过
`WorkspaceEndpointGrant(endpoint_id, organization_id, workspace_id)` 明确授权目标
GatewayEndpoint；私有草稿在同一 SQLite 写事务中检查精确 grant 和 endpoint，历史
全局 endpoint 不会自动授权。请求体不能声明组织、workspace、actor 或 grant。

旧 `/api/v1/gateway-routes` 列表与 `/{routeId}` 读取只返回组织归属未知
（`organization_id IS NULL`）的记录，因此迁移后 workspace-only 历史记录仍可读，
但不会被当作私有 scope。新私有记录不会通过旧路由读取或编辑接口暴露。组织范围凭据
不能调用旧的全局写入操作；无组织范围的旧控制凭据保留原写入语义并创建 unscoped
记录。草稿幂等键按可信组织/workspace 派生摘要分区。

Gateway 数据面路由选择使用认证 Bearer 解析出的组织和 workspace。组织范围凭据只可
读取精确 scope 的 ACTIVE Route，不会回退到其他 workspace 或 legacy 全局路由；无组织
范围的旧凭据仍只读取组织归属未知的路由。Models 列表、readyz 和服务路由计数基于同一
持久状态，不返回其他 workspace 的路由定义。

## Embeddings 数据面

融合的 Product 服务通过与 Chat 相同的持久路由规划器、Gateway 凭据和
`model.provider.v1` facade 提供 `POST /v1/embeddings`。请求接受单条文本或最多 128 条
有序文本，并仅支持 `encoding_format: "float"`；响应 index 与输入顺序一致，模型名来自
Provider 实际回报。Product 在返回前拒绝不完整批次、维度漂移、非有限值和零向量。客户端
断开会向 Provider 传播取消；有类型 Provider 错误保留 HTTP 状态和有限 `Retry-After`。
此 endpoint 不伪造向量，也不会把 Chat 模型作为 embeddings 回退。
CLI 使用可重复的
`--control-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME` 配置私有控制
Bearer，并用 `--gateway-credential-env CREDENTIAL_REF=[ORG_ID=]WORKSPACE_ID=ENV_NAME` 配置独立
聊天/数据面 Bearer。`--control-only-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME`
（无组织范围使用 `-`）能配置一个明确排除数据面认证的 Operator API Bearer；秘密从环境变量读取，参数中仅出现变量名。各角色必须分开。
旧 `--control-token(-env)` 仅保留无组织范围的双用途兼容，不能调用私有 Workspace 别名。
优先使用环境变量形式，避免明文出现在本机进程参数中。Endpoint grant 通过可重复的
`--workspace-endpoint-grant ENDPOINT_UUID=ORG_ID=WORKSPACE_ID` 配置。多个控制凭据可用不同
credential reference 为同一 scope 提供轮换。

本地 Plugins-owned Provider 使用可重复的
`--direct-plugin-provider BINDING=grpc://127.0.0.1:PORT`，只允许 loopback 或 Unix socket；
Workspace 草稿确认前会通过 DirectPlugin Health 核对插件身份与 `model.provider.v1`。
授权媒体使用 `--work-attachment-origin` 和可重复的
`--work-attachment-credential-env CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ACTOR_ID=ENV_NAME`；
Work Bearer 独立于 Exchange 凭据并绑定到确切 Exchange principal。Work 负责授权附件读取，
Exchange 在模型调用前校验摘要、MIME 与字节上限。

## Existing runner integration / 现有运行入口

`scripts/run_product_vllm_smoke.py` composes generic Platform selection with a
direct Official Plugin endpoint. Its optional `--serve --draft-control-port PORT` mode
creates a dedicated empty GatewayEndpoint and an authenticated control API;
it does not auto-create an ACTIVE route. Supply `--reactor-base-url` and
`--reactor-credential-file` for source read-back. Readiness reports `controlUrl`,
`endpointId`, binding and data-plane URL, without secrets. An explicit
`CYRENE_EXCHANGE_CONTROL_BEARER_TOKEN` is separate from the existing data token.

这条模式在已有直连 Plugin 运行脚本上增加接收草稿入口，沿用现有 provider、协议、路由和审计。
凭据应由私有文件/管道传入启动环境，不放进命令参数、日志或源代码。Reactor 负责
创建 Deployment，本入口只负责显式路由和已有 Navigator 可使用的网关。

## Verification / 验证

Run `uv sync --frozen --group dev --extra integrations`, Ruff, strict mypy, `uv run pytest -q`, and
`uv run openapi-spec-validator ../contracts/product/v1/openapi.yaml`.
Draft tests cover persistence, retries, edits, permissions, version checks and
failure keeping routes unpublished. Their controlled validator callbacks are
unit-test evidence, not real model inference or a Navigator acceptance result.

真实 CUDA 部署、跨产品探针、流式、取消和 Navigator 回答必须另行记录，不能用
测试回调或此前为客户端手工启动的模型替代。

## Quota authority / 配额权威

`ExchangeStore.save_tenant_quota` persists the Product-owned monthly token
limit. Gateway composition with a `billing.usage.v1` client enables
`ProductQuotaGuard`, which compares that limit with the Plugins-owned complete
usage total. Exchange never stores a second aggregate or estimates absent token
facts.

`ExchangeStore.save_tenant_quota` 持久化 Product 所有的月度 Token 上限。网关组合
提供 `billing.usage.v1` client 后启用 `ProductQuotaGuard`，将该上限与
Plugins-owned 完整用量总数比较；Exchange 不保存第二套汇总，也不估算缺失 Token。
---
<!-- Chinese Translation / 中文翻译 -->

## 接收方操作接口

- `POST /api/v1/gateway-route-drafts` 是 organization-unscoped legacy 写入路径，必须提供 `Idempotency-Key`，并根据 `endpointId`、`modelPattern`、`targetBindingId`、`targetModel`、`priority` 和 `source` 创建草稿。`source` 包含 `product=reactor`、`resourceUri`、`resourceVersion` 与 `artifactDigest`。Legacy 控制凭据决定 actor 和 workspace。
- `GET /api/v1/gateway-routes/{id}` 打开组织归属未知的 legacy 资源供检查。
- `PATCH /api/v1/gateway-route-drafts/{id}` 使用当前 `resourceVersion` 编辑模型模式、允许的目标、目标模型和优先级。
- `POST /api/v1/gateway-route-drafts/{id}/actions/confirm` 接收已检查的 `resourceVersion`。确认时会重新检查源读取权限、Endpoint 版本、READY 状态、协议/模型/Artifact 兼容性，并通过 Platform 选择和 Plugins 所有的直连 Provider 端点执行真实推理探测。仅当校验后草稿版本仍匹配时，存储才会提交 ACTIVE 状态。

来源资源不可达、无权读取、版本变化、协议不兼容或 Provider 探测失败时，草稿保持 DRAFT，并返回明确错误。控制 API 不会把普通网关聊天凭据视为发布权限。首版每个控制实例只支持一个配置的 workspace；WSL 不提供多租户 GPU 硬隔离。

## 现有运行入口说明

`scripts/run_product_vllm_smoke.py` 将 Platform 通用选择与 Official Plugin 直连端点组合起来。可选的 `--serve --draft-control-port PORT` 模式会创建专用的空 `GatewayEndpoint` 和经过认证的控制 API，但不会自动创建 ACTIVE Route。通过 `--reactor-base-url` 和 `--reactor-credential-file` 配置来源回读。就绪报告会输出 `controlUrl`、`endpointId`、binding 和数据面 URL，不包含秘密值。显式的 `CYRENE_EXCHANGE_CONTROL_BEARER_TOKEN` 与现有 data token 相互独立。

## 验证说明

验证命令包括 `uv sync --frozen --group dev --extra integrations`、Ruff、strict mypy、`uv run pytest -q` 和 `uv run openapi-spec-validator ../contracts/product/v1/openapi.yaml`。完整 Product 测试需要可选集成 SDK；Gateway-only 导入测试会验证基础安装无需该 SDK。草稿测试覆盖持久化、重试、编辑、权限、版本检查，以及失败时不发布 Route。受控验证回调仅是单元测试证据，不代表真实模型推理或 Navigator 验收。

真实 CUDA 部署、跨 Product 探测、流式处理、取消和 Navigator 回答必须另行记录；不能用测试回调或此前为客户端手动启动的模型替代。
