# Plugin dependencies / Plugin 依赖

Exchange consumes capability contracts; it does not embed Plugin
implementations.

Exchange 只消费能力契约，不嵌入 Plugin 实现。

| Capability or package | Purpose | Ownership |
| --- | --- | --- |
| `model.provider.v1` | Execute normalized chat requests through one selected direct endpoint | Plugins owns the contract and endpoint; Exchange owns Product request policy |
| `model.routing.v1` | Return ordered opaque route candidates | Exchange persists Product routes; the reusable selection contract remains outside provider execution |
| `billing.usage.v1` | Record and aggregate exact provider-reported usage | Plugins owns idempotency, aggregation, and cost calculation; Exchange owns quota limits |
| `cyrene-model-provider-contracts` | Typed Python codecs for `model.provider.v1` | `Cyrene-Plugins-Official` |
| `cyrene-plugin-runtime` | Direct endpoint client and transport | `Cyrene-Plugins-Official` |

The two SDK packages are pinned in `pyproject.toml` and `uv.lock` to exact Git
revision `c3f75689ebb10b2e07b3816310e768d74ae6cc10`. Before public release, that
revision must be reachable through an anonymous clone and its own license
mapping must explicitly cover both SDK directories. A maintainer cache or
private checkout is not acceptance evidence.

两个 SDK 在 `pyproject.toml` 与 `uv.lock` 中固定到精确 Git revision
`c3f75689ebb10b2e07b3816310e768d74ae6cc10`。公开前必须验证匿名 clone 可读取该
revision，且 Plugins 的许可证映射明确覆盖两个 SDK；维护者缓存或私有 checkout
不能作为验收证据。

The retired `cyrene-plugin-python-gateway-lite`, Spring prompt-cache host, and
worker gRPC protocol are not active dependencies.

已退役的 `cyrene-plugin-python-gateway-lite`、Spring prompt-cache host 与 Worker
gRPC 协议不再是活动依赖。
