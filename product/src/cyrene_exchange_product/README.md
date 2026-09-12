# Product source / Product 源码

This directory is the single persisted Product authority.

本目录是唯一的持久化 Product 权威。

| File | Responsibility | 职责 |
| --- | --- | --- |
| `domain.py` | Endpoint, route, principal, audit, and quota models | Endpoint、Route、Principal、审计与配额模型 |
| `store.py` | SQLite persistence and idempotency | SQLite 持久化与幂等 |
| `service.py` | Endpoint and route commands | Endpoint 与 Route 命令 |
| `routing.py` | ACTIVE-route projection and gateway composition | ACTIVE Route 投影与网关组合 |
| `route_admission.py` | Explicit source and provider validation | 显式来源与 Provider 校验 |
| `audit.py` | Content-free request lifecycle observer | 不含内容的请求生命周期 observer |
| `quota.py` | Product limit enforcement using Plugins-owned totals | 使用 Plugins-owned 总量执行 Product 上限 |
| `api.py` | Control HTTP API | 控制面 HTTP API |
| `audit_api.py` | Authenticated audit read API | 鉴权审计读取 API |
| `errors.py` | Stable Product error mapping | 稳定 Product error 映射 |

Suggested order: domain → store → service → routing → audit/quota → API.

推荐顺序：domain → store → service → routing → audit/quota → API。
