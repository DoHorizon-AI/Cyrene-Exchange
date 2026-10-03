# Architecture overview / 架构总览

The active repository has two Python layers: `src/cyrene_exchange` contains
request normalization, gateway policy, capability ports, direct Plugin
transport, and the replaceable HTTP adapter; `product/src/cyrene_exchange_product`
contains the SQLite authority, control API, route admission, audit, and quota
policy.

当前仓库有两层 Python 源码：`src/cyrene_exchange` 包含请求规范化、网关策略、能力
端口、Plugin 直连传输与可替换 HTTP adapter；
`product/src/cyrene_exchange_product` 包含 SQLite 权威、控制 API、Route admission、
审计与配额策略。

```mermaid
sequenceDiagram
    participant C as Client
    participant E as ExchangeGateway
    participant S as ExchangeStore
    participant R as Platform resolver
    participant P as Plugins endpoint
    C->>E: bearer token + chat request
    E->>S: resolve trusted principal and ACTIVE routes
    E->>R: capability + opaque binding
    R-->>E: selected endpoint transport
    E->>P: typed model.provider.v1 request
    P-->>E: chunks and observed usage
    E->>S: content-free terminal audit
    E-->>C: JSON or SSE + X-Request-Id
```

There is no active Coordinator worker pool or Exchange-owned inference RPC.
Queueing, execution placement, worker health, GPU telemetry, and serving belong
outside this Product repository.

当前不存在 Coordinator Worker pool 或 Exchange-owned inference RPC。排队、执行
放置、Worker 健康、GPU 遥测和模型服务属于本 Product 仓库之外。

## Authority table / 权威表

| Concern | Canonical owner |
| --- | --- |
| Endpoint, route, credential, audit, quota limit | Exchange Product `ExchangeStore` |
| Request normalization, fallback, response policy | `ExchangeGateway` |
| Capability resolution and execution mode selection | Platform |
| `model.provider.v1` contract and endpoint | Plugins |
| Provider translation and serving | Official provider Plugin, Reactor, or external provider |
| Usage aggregation and cost calculation | Plugins `billing.usage.v1` |
| Worker/process lifecycle and hardware facts | Platform/Reactor execution plane |
---
<!-- Chinese Translation / 中文翻译 -->

## 权威表中文说明

| 关注点 | 规范所有者 |
| --- | --- |
| Endpoint、Route、凭据、审计和配额上限 | Exchange Product 的 `ExchangeStore` |
| 请求规范化、回退和响应策略 | `ExchangeGateway` |
| 能力解析和执行模式选择 | Platform |
| `model.provider.v1` 契约与端点 | Plugins |
| Provider 转换和模型服务 | Official provider Plugin、Reactor 或外部 Provider |
| 用量汇总和费用计算 | Plugins 的 `billing.usage.v1` |
| Worker/进程生命周期和硬件事实 | Platform/Reactor 执行平面 |
