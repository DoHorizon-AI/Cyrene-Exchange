# Gateway core directory / 网关核心目录

| File | Responsibility | 职责 |
| --- | --- | --- |
| `__init__.py` | Stable package exports and lazy optional adapters | 稳定包导出与惰性可选 adapter |
| `billing.py` | Direct `billing.usage.v1` client | 直连 billing capability client |
| `capabilities.py` | Product-consumer routing and provider ports | Product 消费侧路由与 Provider 端口 |
| `direct_plugin.py` | Typed direct Plugin execution adapter | 类型化 Plugin 直连执行 adapter |
| `gateway.py` | Authentication, routing lifecycle, fallback, and response policy | 认证、路由生命周期、回退与响应策略 |
| `http.py` | Replaceable OpenAI-compatible HTTP transport | 可替换 OpenAI-compatible HTTP 传输 |
| `platform_resolver.py` | Generic Platform selection adapter | 通用 Platform 选择 adapter |
| `protocol.py` | Request normalization | 请求规范化 |
| `reference_routing.py` | Explicit test/reference route planner | 显式测试/参考 Route planner |

Read `protocol.py`, `capabilities.py`, `gateway.py`, `platform_resolver.py`,
`direct_plugin.py`, then `http.py` and tests.

推荐依次阅读 `protocol.py`、`capabilities.py`、`gateway.py`、
`platform_resolver.py`、`direct_plugin.py`、`http.py` 与测试。
