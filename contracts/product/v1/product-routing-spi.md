# Persisted Product routing adapter

`StoredRoutePlanner` implements the existing `model.routing.v1` consumer seam:

```text
plan(normalizedRequest) -> ordered RouteTarget[]
```

It reads active routes from the Exchange Product store, matches `modelPattern`,
and returns opaque `targetBindingId` values. A delegating resolver intercepts
only `model.routing.v1`; all `model.provider.v1` resolution continues through the
canonical Platform resolver. The adapter neither imports plugin packages nor
owns provider lifecycle.

`build_gateway_from_store(store, endpoint_id, delegate, ...)` is the public
composition seam for one selected `GatewayEndpoint`. The caller retains the
store, Platform resolver, direct Plugin client, and HTTP transport lifecycles,
so the helper remains a pure wiring operation rather than another authority.
---
<!-- Chinese Translation / 中文翻译 -->

# 持久化 Product 路由适配器

`StoredRoutePlanner` 实现现有的 `model.routing.v1` 消费端接缝：

```text
plan(normalizedRequest) -> ordered RouteTarget[]
```

它从 Exchange Product 存储中读取活动路由，匹配 `modelPattern`，并返回不透明的
`targetBindingId` 值。委托解析器只拦截 `model.routing.v1`；所有
`model.provider.v1` 解析仍由规范 Platform 解析器处理。该适配器既不导入插件包，
也不拥有提供方生命周期。

`build_gateway_from_store(store, endpoint_id, delegate, ...)` 是为一个选定的
`GatewayEndpoint` 提供的公开组合接缝。调用方保留存储、Platform 解析器、直接 Plugin
客户端和 HTTP 传输的生命周期，因此该辅助函数只是纯粹的连线操作，不会形成另一处权威。
