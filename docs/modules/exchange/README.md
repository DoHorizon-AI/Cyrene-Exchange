# Exchange gateway core / 网关核心

`src/cyrene_exchange` owns normalized request policy and consumes generic
capability boundaries. It contains no Product database and no concrete provider
implementation.

`src/cyrene_exchange` 拥有规范化请求策略并消费通用能力边界；它不包含 Product
数据库，也不包含具体 Provider 实现。

| File | Responsibility | 职责 |
| --- | --- | --- |
| `protocol.py` | OpenAI request normalization | OpenAI 请求规范化 |
| `capabilities.py` | Minimal routing/provider/resolver ports | 最小路由、Provider 与 resolver 端口 |
| `gateway.py` | Trusted identity, fallback, cancellation, and response policy | 可信身份、回退、取消与响应策略 |
| `direct_plugin.py` | Typed direct `model.provider.v1` adapter | 类型化直连 Provider 适配器 |
| `platform_resolver.py` | Platform selection and opaque binding composition | Platform 选择与不透明 binding 组合 |
| `billing.py` | Direct `billing.usage.v1` client | 直连用量能力客户端 |
| `http.py` | Replaceable reference HTTP transport | 可替换参考 HTTP 传输 |
| `reference_routing.py` | Test/reference routing fixture | 测试/参考路由夹具 |

Product persistence and quota policy live under
`product/src/cyrene_exchange_product`, not in a second in-memory repository.

Product 持久化与配额策略位于 `product/src/cyrene_exchange_product`，不再维护第二套
内存 repository。
