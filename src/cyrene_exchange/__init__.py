###############################################################################
# 📄 File: src/cyrene_exchange/__init__.py
# 中文：文件：src/cyrene_exchange/__init__.py；模块：Cyrene Exchange；职责：Exchange Product 实现。
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; runtime behavior is unchanged.
# 中文：此文件头说明模块所有权；运行时行为保持不变。
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；运行时行为保持不变。
###############################################################################
"""Exchange Product Core and reference transport adapter.

The package deliberately depends on capability protocols instead of concrete
plugin implementations.  The HTTP server is a replaceable reference adapter;
the Product semantics live in :class:`ExchangeGateway`.

中文：Exchange Product Core 与参考传输 adapter。package 刻意依赖 capability protocol，而不依赖具体 plugin 实现。HTTP server 是可替换的参考 adapter；Product 语义由 ExchangeGateway 承载。
"""
# 中文：Exchange Product 核心与参考传输适配器。本包依赖能力协议，而不依赖具体插件实现。HTTP 服务器是可替换的参考适配器；Product 语义由 :class:`ExchangeGateway` 承载。

from .capabilities import (
    MODEL_PROVIDER_CAPABILITY,
    MODEL_ROUTING_CAPABILITY,
    CapabilityResolver,
    ProviderChunk,
    ProviderUsage,
    RouteTarget,
    ToolCallDelta,
)
from .billing import (
    BillingUsageClient,
    BillingUsageError,
    HttpBillingUsageClient,
    TokenUsageEvent,
)
from .gateway import (
    AuthenticationError,
    ExchangeGateway,
    GatewayError,
    GatewayResponse,
    InvalidRequestError,
    NoRouteError,
    ProviderFailureError,
    QuotaExceededError,
    QuotaUnavailableError,
    RequestCancelled,
)
from .protocol import NormalizedInferenceRequest

_ADAPTER_EXPORTS = {
    "DirectPluginInvoker": (".direct_plugin", "DirectPluginInvoker"),
    "DirectPluginModelProvider": (
        ".direct_plugin",
        "DirectPluginModelProvider",
    ),
    "ModelProviderExecutionError": (
        ".direct_plugin",
        "ModelProviderExecutionError",
    ),
    "PlatformResolverAdapter": (".platform_resolver", "PlatformResolverAdapter"),
    "PlatformResolverError": (".platform_resolver", "PlatformResolverError"),
    "local_plugin_client": (".direct_plugin", "local_plugin_client"),
}


def __getattr__(name: str) -> object:
    """Load Platform-dependent adapters only when a caller requests them.

    中文：只有调用方请求时才加载依赖 Platform 的 adapter。
    """
# 中文：仅在调用方请求时加载依赖 Platform 的适配器。

    target = _ADAPTER_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    from importlib import import_module

    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


__all__ = [
    "AuthenticationError",
    "BillingUsageClient",
    "BillingUsageError",
    "CapabilityResolver",
    "DirectPluginInvoker",
    "DirectPluginModelProvider",
    "ExchangeGateway",
    "GatewayError",
    "GatewayResponse",
    "InvalidRequestError",
    "HttpBillingUsageClient",
    "MODEL_PROVIDER_CAPABILITY",
    "MODEL_ROUTING_CAPABILITY",
    "ModelProviderExecutionError",
    "NoRouteError",
    "NormalizedInferenceRequest",
    "ProviderChunk",
    "ProviderUsage",
    "ProviderFailureError",
    "QuotaExceededError",
    "QuotaUnavailableError",
    "RequestCancelled",
    "RouteTarget",
    "ToolCallDelta",
    "TokenUsageEvent",
    "PlatformResolverAdapter",
    "PlatformResolverError",
    "local_plugin_client",
]
