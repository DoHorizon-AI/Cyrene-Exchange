# FAQ / 常见问题

## Who owns routing? / 谁拥有路由？

Exchange persists route intent and owns fallback lifecycle. The routing port
returns ordered candidates; Platform selects a declared implementation; the
provider Plugin executes the request.

Exchange 持久化 Route intent 并拥有回退生命周期；routing port 返回有序候选，
Platform 选择已声明实现，Provider Plugin 执行请求。

## Is `targetBindingId` an import path? / 它是 import path 吗？

No. It is opaque Product state and must not be interpreted as a Python module,
filesystem path, or process command by Exchange.

不是。它是不透明 Product 状态，Exchange 不得把它解释为 Python 模块、文件路径或
进程命令。

## Where are worker and telemetry APIs? / Worker 与遥测 API 在哪里？

They were removed. Execution lifecycle and hardware facts belong to
Platform/Reactor; there is no Exchange compatibility endpoint.

它们已删除。执行生命周期与硬件事实属于 Platform/Reactor；Exchange 不保留兼容
Endpoint。

## What proves public readiness? / 什么证明可以公开？

An anonymous clean clone must resolve the exact Plugins SDK pin and execute the
hosted checks at the accepted SHA. Local green tests, cached private
dependencies, or a zero-step CI failure do not prove that gate.

匿名 clean clone 必须能解析精确 Plugins SDK pin，并在 accepted SHA 实际执行 Hosted
checks。仅本地绿色、私有依赖缓存或 zero-step CI 失败都不能证明该门已通过。
