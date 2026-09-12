# External protocol boundary / 外部协议边界

Exchange does not implement or own an MCP server. Its supported integration
boundary is `model.provider.v1`; a provider or connector may use MCP internally,
but Exchange receives only the versioned capability contract and an opaque
binding reference.

Exchange 不实现也不拥有 MCP server。受支持的集成边界是
`model.provider.v1`；Provider 或 Connector 可以在内部使用 MCP，但 Exchange 只接收
版本化能力契约与不透明 binding reference。

Rules / 规则：

- Product request normalization stays independent of external protocol details.
- Platform selects implementations but never proxies chat payloads.
- Plugins endpoints translate transport failures into canonical provider errors.
- Unsupported protocols are absent; there is no fallback compatibility shim.

- Product 请求规范化不依赖外部协议细节。
- Platform 只选择实现，不代理 Chat 业务载荷。
- Plugins Endpoint 把传输失败转换为规范 Provider error。
- 未支持协议不保留兼容 shim。
