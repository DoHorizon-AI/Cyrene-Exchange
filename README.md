# Cyrene Exchange

Cyrene Exchange is the Product-owned API gateway and model-routing service. It
normalizes OpenAI-compatible chat requests, authenticates a trusted Product
principal, projects persisted routes, and invokes a Plugins-owned
`model.provider.v1` endpoint selected through the Platform resolver.

Cyrene Exchange 是 Product 所有的 API 网关与模型路由服务。它规范化
OpenAI-compatible chat 请求、解析可信 Product 身份、投影持久化路由，并调用经
Platform resolver 选择的 Plugins-owned `model.provider.v1` Endpoint。

## Implemented surface / 已实现表面

- SQLite-backed `GatewayEndpoint`, `GatewayRoute`, credential, request-audit,
  and tenant-quota state.
- Explicit `DRAFT` route creation, edit, validation, and confirmation.
- `/v1/chat/completions` unary and SSE responses, tool-call propagation,
  cancellation, and bounded fallback.
- Direct `model.provider.v1` execution and optional `billing.usage.v1` usage
  delivery. Exchange owns quota limits; the billing Plugin owns usage totals.

- 基于 SQLite 的 Endpoint、Route、凭据、请求审计与租户配额权威。
- 显式 DRAFT 路由创建、编辑、校验与确认。
- `/v1/chat/completions` 普通与 SSE 响应、工具调用透传、取消和有界回退。
- 直连 `model.provider.v1`，并可把精确用量交给 `billing.usage.v1`；Exchange
  只拥有配额上限，billing Plugin 拥有用量汇总。

Exchange does not contain an inference worker, scheduler, GPU telemetry
collector, training API, custom-script runner, Anthropic shim, WebSocket data
plane, MCP server, or policy-filter implementation. Those are not compatibility
aliases; unsupported surfaces are absent and fail closed.

Exchange 不包含推理 Worker、调度器、GPU 遥测接收器、训练 API、自定义脚本执行、
Anthropic shim、WebSocket 数据面、MCP server 或策略过滤实现。未支持表面不保留
兼容别名，并按 fail-closed 处理。

## Build and verify / 构建与验证

The root package requires Python 3.11 or newer; Product validation uses Python
3.12. Dependencies are locked by `uv.lock` and `product/uv.lock`.

```bash
uv sync --frozen --extra dev
uv run --no-sync ruff check src tests integration_tests
uv run --no-sync ruff format --check src tests integration_tests
uv run --no-sync pytest -p no:cacheprovider -q tests

cd product
PYTHONPATH=../src:src uv run --frozen --group dev ruff check src tests
PYTHONPATH=../src:src uv run --frozen --group dev ruff format --check src tests
PYTHONPATH=../src:src uv run --frozen --group dev mypy
PYTHONPATH=../src:src uv run --frozen --group dev pytest -p no:cacheprovider -q
uv run --frozen --group dev openapi-spec-validator ../contracts/product/v1/openapi.yaml
```

The root lock currently pins two SDK packages to an exact
`Cyrene-Plugins-Official` Git revision. Anonymous clean-clone installation is a
publication gate: that revision must be accepted and publicly readable before
Exchange is made public. See [Plugin dependencies](PLUGIN_DEPENDENCIES.md).

根锁文件把两个 SDK 固定到 `Cyrene-Plugins-Official` 的精确 Git revision。
Exchange 公开前必须确认该 revision 已合并且可匿名读取；本地缓存或私有凭据不算
公开依赖闭包证明。

## Documentation / 文档

- [Product API](docs/API.md)
- [Architecture](ARCHITECTURE.md)
- [Lifecycle and ownership](docs/REPOSITORY-LIFECYCLE.md)
- [Security policy](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.product.md)

Local vLLM composition helpers live under `scripts/` and `product/scripts/`.
Their output is local integration evidence only; it is not hosted CI, GPU,
deployment, release, or canonical merge evidence.

本地 vLLM 组合脚本位于 `scripts/` 与 `product/scripts/`；其结果只证明本地集成，
不等同于 Hosted CI、GPU、部署、发布或规范分支合并证据。
---
<!-- Chinese Translation / 中文翻译 -->

## 构建与验证说明

根目录程序要求 Python 3.11 或更新版本；Product 校验使用 Python 3.12。依赖分别由 `uv.lock` 和 `product/uv.lock` 锁定。文档中的命令展示预期的本地构建与检查方式。

根锁文件目前将两个 SDK 固定到 `Cyrene-Plugins-Official` 的精确 Git revision。公开发布前必须确保该 revision 已被接受并可匿名读取；本地缓存或私有凭据不能证明公开依赖闭包完整。

## 文档导航

- [Product API](docs/API.md)：Product HTTP API。
- [架构](ARCHITECTURE.md)：当前所有权与请求流。
- [生命周期与所有权](docs/REPOSITORY-LIFECYCLE.md)：分支、CI 和发布门槛。
- [安全策略](SECURITY.md)：安全报告与处置方式。
- [第三方声明](THIRD_PARTY_NOTICES.product.md)：第三方依赖与许可信息。

本地 vLLM 组合脚本只提供本地集成证据，不能作为 Hosted CI、GPU、部署、发布或规范分支合并的证明。
