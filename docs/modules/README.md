# Active modules / 活动模块

| Module | Responsibility | Reading order |
| --- | --- | --- |
| [`exchange/`](exchange/README.md) | Gateway core and capability adapters | protocol → gateway → resolver → direct plugin → HTTP |
| `../../product/src/cyrene_exchange_product/` | Persisted Product state and control surfaces | domain → store → service → routing → audit/quota → API |

The removed Kotlin Coordinator and protobuf worker data plane are not active
modules and are not published as compatibility source.

已删除的 Kotlin Coordinator 与 protobuf Worker 数据面不是活动模块，也不作为兼容
源码发布。
