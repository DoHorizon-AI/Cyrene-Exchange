"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 api.py                                                          │
│  Module: cyrene_exchange_product.api                                │
│  Role: Versioned HTTP adapter for Exchange control resources.        │
│                                                                     │
│  模块职责：Exchange 控制资源的版本化 HTTP 适配器。                        │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
import sys
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, Request
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from cyrene_exchange_product.domain import (
    ApiKey,
    ConfirmRouteRequest,
    CreateApiKeyRequest,
    CreatedApiKey,
    CreateEndpointRequest,
    CreateRouteDraftRequest,
    CreateRouteRequest,
    EditRouteDraftRequest,
    GatewayEndpoint,
    GatewayRoute,
    ProblemDetails,
    ProductPrincipal,
)
from cyrene_exchange_product.errors import ExchangeProductError, map_exchange_error
from cyrene_exchange_product.logging import (
    format_cyrene_log,
    parse_w3c_traceparent,
    sanitize_request_id,
)
from cyrene_exchange_product.service import ExchangeProductService
from cyrene_exchange_product.store import ExchangeStore

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")


def _incoming_trace_id(value: str) -> str | None:
    match = _TRACEPARENT.fullmatch(value)
    if match is None or match.group(1) == "0" * 32 or match.group(2) == "0" * 16:
        return None
    return match.group(1)


def create_app(
    *,
    database_path: Path,
    control_credentials: Mapping[str, ProductPrincipal] | None = None,
    allowed_binding_ids: frozenset[str] = frozenset(),
    validate_route_target: Callable[[GatewayRoute], None] | None = None,
    store: ExchangeStore | None = None,
) -> FastAPI:
    """Build the Exchange Product control API. | 创建 Exchange 产品控制 API。

    A caller that already owns the store (for example a fused gateway that
    resolves providers from persisted routes) passes it in so control and data
    plane share exactly one connection and one credential set.
    """

    store = store or ExchangeStore(database_path)
    service = ExchangeProductService(store)
    if len({p.workspace_id for p in (control_credentials or {}).values()}) > 1:
        raise ValueError("the first route-control profile requires one configured workspace")
    if control_credentials is not None:
        store.configure_credentials(control_credentials)
    control_refs = {p.credential_ref for p in (control_credentials or {}).values()}

    def principal(request: Request) -> ProductPrincipal:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        identity = store.resolve_credential(token) if scheme == "Bearer" else None
        if identity is None or identity.credential_ref not in control_refs:
            raise ExchangeProductError(
                code="EXCHANGE_CONTROL_PERMISSION_DENIED",
                title="Control permission required",
                detail="Use an explicitly configured Exchange control credential.",
                status=403,
            )
        return ProductPrincipal(identity.actor_id, identity.workspace_id, identity.credential_ref)

    def protect_configured_control(request: Request) -> None:
        # The control API is the only surface this guard owns. Data-plane
        # routes authenticate through the gateway, and liveness probes must
        # stay reachable for orchestrators and reverse proxies.
        # 中文:此守卫只负责控制 API;数据平面路由通过网关进行身份验证,且必须保持可访问,以供编排器和反向代理使用。
        if control_credentials is not None and request.url.path.startswith("/api/"):
            principal(request)

    app = FastAPI(
        title="Cyrene Exchange Product API",
        version="1.0.0",
        dependencies=[Depends(protect_configured_control)],
    )
    app.state.exchange_store = store
    app.state.exchange_service = service

    @app.middleware("http")
    async def propagate_trace(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        parsed_trace = parse_w3c_traceparent(request.headers.get("traceparent"))
        if parsed_trace is not None:
            trace_id, _ = parsed_trace
        else:
            trace_id = uuid4().hex

        raw_req_id = request.headers.get("x-request-id")
        request_id = sanitize_request_id(raw_req_id) or str(uuid4())

        request.state.trace_id = trace_id
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["traceparent"] = f"00-{trace_id}-0000000000000001-01"
        response.headers["x-request-id"] = request_id
        return response

    @app.exception_handler(ExchangeProductError)
    async def product_error(request: Request, exc: ExchangeProductError) -> JSONResponse:
        mapping = map_exchange_error(exc.code)
        trace_id = getattr(request.state, "trace_id", None) or uuid4().hex
        request_id = getattr(request.state, "request_id", None)
        problem = ProblemDetails(
            type=f"https://errors.cyrene.dev/exchange/{exc.code.lower()}",
            title=exc.title,
            status=exc.status,
            detail=exc.detail,
            instance=request.url.path,
            code=exc.code,
            retryable=exc.retryable,
            trace_id=trace_id,
            resource_ref=exc.resource_ref,
        )
        # Emit structured diagnostic log to stderr
        # 中文:向标准错误输出结构化诊断日志。
        log_line = format_cyrene_log(
            level="WARN" if exc.status < 500 else "ERROR",
            event_name="exchange.product.error",
            message=exc.detail,
            trace_id=trace_id,
            attributes={
                "error.code": mapping.canonical_code,
                "cause.kind": mapping.cause_kind,
                "recovery.action": mapping.recovery_action,
                "http.status": exc.status,
                "request_id": request_id,
                "path": request.url.path,
            },
        )
        sys.stderr.write(log_line + "\n")
        return JSONResponse(
            status_code=exc.status,
            content=problem.model_dump(by_alias=True, exclude_none=True, mode="json"),
            media_type="application/problem+json",
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _exc: RequestValidationError) -> JSONResponse:
        mapping = map_exchange_error("EXCHANGE_REQUEST_INVALID")
        trace_id = getattr(request.state, "trace_id", None) or uuid4().hex
        request_id = getattr(request.state, "request_id", None)
        problem = ProblemDetails(
            type="https://errors.cyrene.dev/exchange/request-invalid",
            title="Request validation failed",
            status=422,
            detail="The request does not conform to the Exchange Product API v1 contract.",
            instance=request.url.path,
            code="EXCHANGE_REQUEST_INVALID",
            retryable=False,
            trace_id=trace_id,
        )
        log_line = format_cyrene_log(
            level="WARN",
            event_name="exchange.product.validation_failed",
            message="Request validation failed",
            trace_id=trace_id,
            attributes={
                "error.code": mapping.canonical_code,
                "cause.kind": mapping.cause_kind,
                "recovery.action": mapping.recovery_action,
                "http.status": 422,
                "request_id": request_id,
                "path": request.url.path,
            },
        )
        sys.stderr.write(log_line + "\n")
        return JSONResponse(
            status_code=422,
            content=problem.model_dump(by_alias=True, mode="json"),
            media_type="application/problem+json",
        )

    @app.post(
        "/api/v1/gateway-endpoints",
        response_model=GatewayEndpoint,
        status_code=201,
    )
    def create_endpoint(
        command: CreateEndpointRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> GatewayEndpoint:
        return service.create_endpoint(command, idempotency_key)

    @app.get("/api/v1/gateway-endpoints/{endpointId}", response_model=GatewayEndpoint)
    def get_endpoint(
        endpoint_id: Annotated[UUID, ApiPath(alias="endpointId")],
    ) -> GatewayEndpoint:
        return service.get_endpoint(endpoint_id)

    @app.get("/api/v1/gateway-endpoints", response_model=list[GatewayEndpoint])
    def list_endpoints() -> list[GatewayEndpoint]:
        return service.list_endpoints()

    @app.post(
        "/api/v1/gateway-endpoints/{endpointId}/actions/disable",
        response_model=GatewayEndpoint,
    )
    def disable_endpoint(
        endpoint_id: Annotated[UUID, ApiPath(alias="endpointId")],
    ) -> GatewayEndpoint:
        return service.disable_endpoint(endpoint_id)

    @app.post("/api/v1/gateway-routes", response_model=GatewayRoute, status_code=201)
    def create_route(
        command: CreateRouteRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> GatewayRoute:
        return service.create_route(command, idempotency_key)

    @app.get("/api/v1/gateway-routes/{routeId}", response_model=GatewayRoute)
    def get_route(route_id: Annotated[UUID, ApiPath(alias="routeId")]) -> GatewayRoute:
        return service.get_route(route_id)

    @app.get("/api/v1/gateway-routes", response_model=list[GatewayRoute])
    def list_routes() -> list[GatewayRoute]:
        return service.list_routes()

    def admit_binding(binding_id: str) -> None:
        if binding_id not in allowed_binding_ids:
            raise ExchangeProductError(
                code="EXCHANGE_BINDING_PERMISSION_DENIED",
                title="Binding not permitted",
                detail="Select a model provider binding admitted by this Exchange workspace.",
                status=403,
            )

    @app.post("/api/v1/gateway-route-drafts", response_model=GatewayRoute, status_code=201)
    def create_draft(
        command: CreateRouteDraftRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> GatewayRoute:
        actor = principal(request)
        admit_binding(command.target_binding_id)
        return service.create_route_draft(command, idempotency_key, actor)

    @app.patch("/api/v1/gateway-route-drafts/{routeId}", response_model=GatewayRoute)
    def edit_draft(
        route_id: Annotated[UUID, ApiPath(alias="routeId")],
        command: EditRouteDraftRequest,
        request: Request,
    ) -> GatewayRoute:
        actor = principal(request)
        admit_binding(command.target_binding_id)
        return service.edit_route_draft(route_id, command, actor)

    @app.post("/api/v1/gateway-route-drafts/{routeId}/actions/confirm", response_model=GatewayRoute)
    def confirm_draft(
        route_id: Annotated[UUID, ApiPath(alias="routeId")],
        command: ConfirmRouteRequest,
        request: Request,
    ) -> GatewayRoute:
        actor = principal(request)
        route = service.get_route(route_id)
        admit_binding(route.target_binding_id)
        if validate_route_target is None:
            raise ExchangeProductError(
                code="EXCHANGE_TARGET_VALIDATOR_UNAVAILABLE",
                title="Target verification unavailable",
                detail="Configure the source and provider verifier before publishing this draft.",
                status=503,
                retryable=True,
            )
        return service.confirm_route_draft(
            route_id, command.resource_version, actor, validate_route_target
        )

    @app.post(
        "/api/v1/api-keys",
        response_model=CreatedApiKey,
        response_model_exclude_none=True,
        status_code=201,
    )
    def create_api_key(
        command: CreateApiKeyRequest,
        request: Request,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> CreatedApiKey:
        actor = principal(request)
        created, _ = service.create_api_key(command, actor, idempotency_key)
        return created

    @app.get("/api/v1/api-keys", response_model=list[ApiKey])
    def list_api_keys(request: Request) -> list[ApiKey]:
        return service.list_api_keys(principal(request))

    @app.get("/api/v1/api-keys/{apiKeyId}", response_model=ApiKey)
    def get_api_key(
        api_key_id: Annotated[UUID, ApiPath(alias="apiKeyId")],
        request: Request,
    ) -> ApiKey:
        return service.get_api_key(api_key_id, principal(request))

    @app.post("/api/v1/api-keys/{apiKeyId}/actions/revoke", response_model=ApiKey)
    def revoke_api_key(
        api_key_id: Annotated[UUID, ApiPath(alias="apiKeyId")],
        request: Request,
    ) -> ApiKey:
        return service.revoke_api_key(api_key_id, principal(request))

    return app
