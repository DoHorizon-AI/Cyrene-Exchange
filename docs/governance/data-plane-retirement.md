# Exchange data-plane retirement / 数据面退役

The Spring Coordinator and `proto/ai_service.proto` were removed from the active
repository because they implemented a second inference gateway and directly
owned worker registration, health checks, draining, scheduling feedback, GPU
telemetry, training messages, and custom-script messages.

Spring Coordinator 与 `proto/ai_service.proto` 已从活动仓库删除，因为它们形成第二
套推理网关，并直接拥有 Worker 注册、健康检查、排空、调度反馈、GPU 遥测、训练
消息与自定义脚本消息。

Current authority is:

- Exchange: authentication, Product route state, quota limits, request audit,
  fallback, and response policy.
- Platform/Reactor: execution and worker lifecycle, placement, serving, and
  hardware facts.
- Plugins: versioned provider/billing contracts and endpoints.
- Yield: training Product state and training workflows.

当前权威分配如下：Exchange 负责认证、Product Route、配额上限、请求审计、回退与
响应策略；Platform/Reactor 负责执行与 Worker 生命周期、放置、服务和硬件事实；
Plugins 负责版本化 Provider/Billing 契约与 Endpoint；Yield 负责训练 Product 状态与
流程。

No field numbers or service names are reserved in a replacement Exchange proto
because there is no replacement Exchange-owned gRPC contract. Consumers must
move to the canonical owner API; the retired wire is not a compatibility
surface.

本仓库没有新的 Exchange-owned gRPC 替代契约，因此不会在新 proto 中保留旧 tag 或
service 名。消费者必须迁移到规范 owner API；退役 wire 不构成兼容表面。
