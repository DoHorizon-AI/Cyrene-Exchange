###############################################################################
# 📄 File: src/cyrene_exchange/__init__.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; runtime behavior is unchanged.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；运行时行为保持不变。
###############################################################################
"""Exchange Product Core and reference transport adapter.

The package deliberately depends on capability protocols instead of concrete
plugin implementations.  The HTTP server is a replaceable reference adapter;
the Product semantics live in :class:`ExchangeGateway`.
"""

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
    """Load Platform-dependent adapters only when a caller requests them."""

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
