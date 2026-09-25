# Active modules / 活动模块

| Module | Responsibility | Reading order |
| --- | --- | --- |
| [`exchange/`](exchange/README.md) | Gateway core and capability adapters | protocol → gateway → resolver → direct plugin → HTTP |
| `../../product/src/cyrene_exchange_product/` | Persisted Product state and control surfaces | domain → store → service → routing → audit/quota → API |

The removed Kotlin Coordinator and protobuf worker data plane are not active
modules and are not published as compatibility source.

已删除的 Kotlin Coordinator 与 protobuf Worker 数据面不是活动模块，也不作为兼容
源码发布。
---
<!-- Chinese Translation / 中文翻译 -->

## 活动模块中文导览

| 模块 | 职责 | 阅读顺序 |
| --- | --- | --- |
| [`exchange/`](exchange/README.md) | 网关核心与能力适配器 | protocol → gateway → resolver → direct plugin → HTTP |
| `../../product/src/cyrene_exchange_product/` | 持久化 Product 状态与控制面 | domain → store → service → routing → audit/quota → API |

已删除的 Kotlin Coordinator 和 protobuf Worker 数据面不是活动模块，也不会作为兼容源码发布。
