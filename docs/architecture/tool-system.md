# Capability and Routing System

Exchange consumes two capability seams: `model.routing.v1` returns ordered route candidates and `model.provider.v1` executes a normalized request. The Product gateway owns the lifecycle around those calls, while each capability owns its own algorithm or service translation.

Exchange 消费两个能力边界：`model.routing.v1` 返回有序路由候选，`model.provider.v1` 执行规范请求。Product gateway 负责调用周边生命周期，各能力负责自己的算法或服务转换。

## Execution sequence / 执行顺序

```text
HTTP request -> normalize -> authenticate -> resolve router
请求       -> 规范化   -> 认证      -> 解析 router
             -> ordered targets -> resolve provider -> collect/stream
             -> 有序候选       -> 解析 provider -> 收集/流式输出
```

`RouteTarget.provider_ref` is opaque to Exchange. It is passed back to the resolver and must not be interpreted as a Python module, filesystem path, or package identity by the Product layer.

`RouteTarget.provider_ref` 对 Exchange 是不透明值。它会传回 resolver，Product 层不得将其解释为 Python 模块、文件系统路径或包身份。

## Fallback / 回退

Fallback is an Exchange-owned policy around an ordered candidate list. A provider failure can advance the list; request cancellation stops the operation and must not be silently converted into a successful fallback response.

回退是 Exchange 围绕有序候选列表拥有的 policy。provider 失败可以推进列表；请求取消会停止操作，不得悄然转换为成功的回退响应。

## Learning checkpoints / 学习检查点

- Read `capabilities.py` to learn the smallest Product-consumer interfaces.
- Read `gateway.py` to see policy and response ownership.
- Read `platform_resolver.py` to see generic manifest-entrypoint binding.
- Read the provider implementation only after the seam is clear.

- 阅读 `capabilities.py`，了解最小 Product 消费接口。
- 阅读 `gateway.py`，了解 policy 与响应归属。
- 阅读 `platform_resolver.py`，了解通用 manifest-entrypoint 绑定。
- 明确边界后再阅读 provider 实现。
