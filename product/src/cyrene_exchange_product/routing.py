"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 routing.py                                                      │
│  Module: cyrene_exchange_product.routing                            │
│  Role: Adapt persisted Product routes to existing capability seams.  │
│                                                                     │
│  模块职责：将持久化产品路由适配到既有能力接口。                             │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from collections.abc import Mapping
from fnmatch import fnmatchcase
from uuid import UUID

from cyrene_exchange.billing import BillingUsageClient
from cyrene_exchange.capabilities import (
    MODEL_ROUTING_CAPABILITY,
    CapabilityResolver,
    RouteTarget,
)
from cyrene_exchange.gateway import (
    ExchangeGateway,
    TokenPrincipalResolver,
)
from cyrene_exchange.protocol import NormalizedInferenceRequest

from cyrene_exchange_product.audit import RequestAuditRecorder
from cyrene_exchange_product.domain import EndpointState, ProductPrincipal
from cyrene_exchange_product.quota import ProductQuotaGuard
from cyrene_exchange_product.store import ExchangeStore


class StoredRoutePlanner:
    """Read-only `model.routing.v1` projection of Product state. | 产品路由只读投影。"""

    def __init__(self, store: ExchangeStore, endpoint_id: UUID) -> None:
        self._store = store
        self._endpoint_id = endpoint_id

    def plan(self, request: NormalizedInferenceRequest) -> list[RouteTarget]:
        """Return eligible opaque bindings in Product priority order. | 返回候选绑定。"""

        endpoint = self._store.get_endpoint(self._endpoint_id)
        if endpoint is None or endpoint.state != EndpointState.ACTIVE:
            return []
        return [
            RouteTarget(
                provider_ref=route.target_binding_id,
                route_id=str(route.id),
                model=route.target_model,
            )
            for route in self._store.active_routes(endpoint.id)
            if fnmatchcase(request.model, route.model_pattern)
        ]


class ProductRoutingResolver:
    """Intercept routing only; delegate provider resolution unchanged. | 仅拦截路由能力。"""

    def __init__(self, planner: StoredRoutePlanner, delegate: CapabilityResolver) -> None:
        self._planner = planner
        self._delegate = delegate

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        """Resolve persisted routing or delegate a generic capability. | 解析或委托能力。"""

        if capability_id == MODEL_ROUTING_CAPABILITY:
            return self._planner
        return self._delegate.resolve(capability_id, implementation_ref)


def build_gateway_from_store(
    store: ExchangeStore,
    endpoint_id: UUID,
    delegate: CapabilityResolver,
    *,
    credentials: Mapping[str, ProductPrincipal],
    billing: BillingUsageClient | None = None,
    record_requests: bool = True,
    max_route_attempts: int = 1,
) -> ExchangeGateway:
    """Compose persisted Product routing with a caller-owned capability resolver.

    The caller owns the store, resolver, direct Plugin client, and transport
    lifecycles. Routes remain a live read-only projection of the Product store;
    this helper creates no second routing, binding, or provider authority.
    Product requests use one route attempt by default so a provider request is
    never silently replayed. A durable Product audit is enabled when the
    controlled ``credentials`` mapping is supplied.

    The ``credentials`` keys are controlled bearer tokens
    and its values are trusted Product principals. The request body cannot
    override those identities. If a billing client is supplied, Product-owned
    quota policy is enforced against the Plugins-owned observed-usage total.

    将持久化 Product 路由与调用方拥有的能力解析器组合；本函数不创建第二权威。
    """

    store.configure_credentials(credentials)
    principal_resolver: TokenPrincipalResolver = store.resolve_credential
    observer = RequestAuditRecorder(store, billing) if record_requests else None
    return ExchangeGateway(
        ProductRoutingResolver(StoredRoutePlanner(store, endpoint_id), delegate),
        principal_resolver=principal_resolver,
        lifecycle_observer=observer,
        quota_checker=ProductQuotaGuard(store, billing),
        max_route_attempts=max_route_attempts,
    )
