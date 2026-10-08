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
revision `3afbac4d386eb7a27f6778149187884820c0b7f6`. Before public release, that
revision must be reachable through an anonymous clone and its own license
mapping must explicitly cover both SDK directories. A maintainer cache or
private checkout is not acceptance evidence.

两个 SDK 在 `pyproject.toml` 与 `uv.lock` 中固定到精确 Git revision
`3afbac4d386eb7a27f6778149187884820c0b7f6`。公开前必须验证匿名 clone 可读取该
revision，且 Plugins 的许可证映射明确覆盖两个 SDK；维护者缓存或私有 checkout
不能作为验收证据。

The retired `cyrene-plugin-python-gateway-lite`, Spring prompt-cache host, and
worker gRPC protocol are not active dependencies.

已退役的 `cyrene-plugin-python-gateway-lite`、Spring prompt-cache host 与 Worker
gRPC 协议不再是活动依赖。
---
<!-- Chinese Translation / 中文翻译 -->

## 能力与依赖归属

| 能力或包 | 用途 | 所有权 |
| --- | --- | --- |
| `model.provider.v1` | 通过选定的直连端点执行规范化聊天请求 | Plugins 拥有契约和端点；Exchange 拥有 Product 请求策略 |
| `model.routing.v1` | 返回按顺序排列的不透明路由候选 | Exchange 持久化 Product 路由；可复用的选择契约仍独立于 Provider 执行 |
| `billing.usage.v1` | 记录并汇总 Provider 精确报告的用量 | Plugins 拥有幂等、汇总和费用计算；Exchange 拥有配额上限 |
| `cyrene-model-provider-contracts` | `model.provider.v1` 的 Python 类型化编解码器 | `Cyrene-Plugins-Official` |
| `cyrene-plugin-runtime` | 直连端点客户端和传输 | `Cyrene-Plugins-Official` |

SDK 固定版本必须可匿名读取，并具有覆盖两个 SDK 目录的明确许可证映射。已退役的 Gateway、prompt-cache host 和 Worker gRPC 协议都不是当前依赖。
