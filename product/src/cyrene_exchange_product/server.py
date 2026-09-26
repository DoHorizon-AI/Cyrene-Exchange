"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 server.py                                                       │
│  Module: cyrene_exchange_product.server                             │
│  Role: Self-contained Exchange gateway process (control + data).     │
│                                                                     │
│  模块职责：Exchange 独立网关进程，融合控制面与数据面并支持 SSE 流式。      │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Lock
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from cyrene_exchange.capabilities import (
    MODEL_PROVIDER_CAPABILITY,
    ProviderChunk,
    ProviderInvocationCancelled,
    ProviderUsage,
)
from cyrene_exchange.gateway import GatewayError
from cyrene_exchange.protocol import NormalizedInferenceRequest
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.domain import EndpointState, ProductPrincipal
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.routing import build_gateway_from_store
from cyrene_exchange_product.store import ExchangeStore

_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
_SSE_DATA_PREFIX = "data:"


class ProviderUnavailableError(RuntimeError):
    """The configured provider endpoint could not serve the request.

    The gateway already maps any provider exception onto its own typed failure,
    so this stays a plain error that the draft validator can also catch.

    中文:已配置的提供方端点无法处理该请求。

        中文：Gateway 会将任何提供方异常映射为自身的有类型失败,因此这里保留为普通错误,
        草稿验证器也可以捕获它。
    """


class OpenAICompatibleProvider:
    """Provider seam over one operator-configured OpenAI-compatible endpoint.

    The adapter reports only provider facts: it never estimates token usage and
    never replays a partially streamed response.

    中文:面向一个由操作者配置的 OpenAI 兼容端点的提供方接口。

        中文:适配器只报告提供方事实:不会估算 token 用量,也不会重放部分流式响应。
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout_seconds: float = 300.0,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("provider base_url must be an http(s) URL")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds

    def complete(
        self,
        request: NormalizedInferenceRequest,
        *,
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        """Invoke the upstream endpoint and yield ordered provider chunks.

        中文:调用上游端点,并按顺序产出提供方数据块。"""

        payload = request.to_provider_dict()
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = "Bearer " + self._api_key
        if request.stream:
            yield from self._stream(payload, headers, cancel_event)
        else:
            yield from self._collect(payload, headers, cancel_event)

    def _collect(
        self,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        if cancel_event.is_set():
            raise ProviderInvocationCancelled("request was cancelled before the provider call")
        try:
            with httpx.Client(timeout=self._timeout, trust_env=False) as client:
                response = client.post(
                    self._base_url + "/chat/completions", json=payload, headers=headers
                )
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"provider request failed: {exc}") from exc
        if response.status_code >= 400:
            raise ProviderUnavailableError(
                f"provider returned HTTP {response.status_code}: {response.text[:400]}"
            )
        body = response.json()
        choices = body.get("choices") or []
        if not choices:
            raise ProviderUnavailableError("provider returned no choices")
        choice = choices[0]
        message = choice.get("message") or {}
        yield ProviderChunk(
            role=message.get("role") or "assistant",
            delta=message.get("content") or "",
            finish_reason=choice.get("finish_reason") or "stop",
            usage=_usage(body.get("usage")),
        )

    def _stream(
        self,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        try:
            with (
                httpx.Client(timeout=self._timeout, trust_env=False) as client,
                client.stream(
                    "POST",
                    self._base_url + "/chat/completions",
                    json=payload,
                    headers=headers,
                ) as response,
            ):
                if response.status_code >= 400:
                    response.read()
                    raise ProviderUnavailableError(f"provider returned HTTP {response.status_code}")
                for line in response.iter_lines():
                    if cancel_event.is_set():
                        raise ProviderInvocationCancelled(
                            "request was cancelled during provider streaming"
                        )
                    chunk = _stream_chunk(line)
                    if chunk is not None:
                        yield chunk
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"provider stream failed: {exc}") from exc


def _usage(value: Any) -> ProviderUsage | None:
    """Project an upstream usage object without inventing missing facts.

    中文:映射上游用量对象,不虚构缺失事实。"""

    if not isinstance(value, Mapping):
        return None
    return ProviderUsage(
        prompt_tokens=_token(value.get("prompt_tokens")),
        completion_tokens=_token(value.get("completion_tokens")),
        total_tokens=_token(value.get("total_tokens")),
    )


def _token(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _stream_chunk(line: str) -> ProviderChunk | None:
    """Map one upstream SSE line onto a provider chunk.

    中文:将一行上游 SSE 数据映射为一个提供方数据块。"""

    if not line.startswith(_SSE_DATA_PREFIX):
        return None
    payload = line[len(_SSE_DATA_PREFIX) :].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ProviderUnavailableError("provider emitted malformed JSON in an SSE event") from exc
    if not isinstance(event, Mapping):
        return None
    choices = event.get("choices") or []
    if not choices:
        return ProviderChunk(usage=_usage(event.get("usage")))
    choice = choices[0]
    delta = choice.get("delta") or {}
    return ProviderChunk(
        role=delta.get("role"),
        delta=delta.get("content") or "",
        finish_reason=choice.get("finish_reason"),
        usage=_usage(event.get("usage")),
    )


class OperatorBindingResolver:
    """Resolve configured provider bindings from explicit operator configuration.

    中文:从操作者显式配置中解析提供方绑定。"""

    def __init__(self, bindings: Mapping[str, Any]) -> None:
        self._bindings = dict(bindings)

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        if capability_id != MODEL_PROVIDER_CAPABILITY:
            raise ProviderUnavailableError(f"unsupported capability: {capability_id}")
        provider = self._bindings.get(implementation_ref or "")
        if provider is None:
            raise ProviderUnavailableError(
                f"no operator provider is configured for binding {implementation_ref!r}"
            )
        return provider


class RouteSourceProviderResolver:
    """Resolve a binding through the persisted route's declared source endpoint.

    A route target carries only an opaque binding id, so the route's own source
    reference is the authoritative place the upstream URL lives. Following it
    keeps the gateway configuration free of duplicated endpoint URLs while still
    failing closed when the source is missing or unreachable.

    中文:通过持久化路由声明的源端点解析绑定。

        中文：路由目标只携带不透明的绑定 ID,因此路由自己的源引用是上游 URL 所在的权威位置。
        沿此引用解析可避免在 Gateway 配置中重复保存端点 URL;若源缺失或无法访问,则按失败即拒绝处理。
    """

    def __init__(
        self,
        store: ExchangeStore,
        *,
        timeout_seconds: float = 300.0,
        source_bearer_token: str | None = None,
        allowed_source_origins: frozenset[str] = frozenset(),
    ) -> None:
        self._store = store
        self._timeout = timeout_seconds
        self._source_token = source_bearer_token
        self._allowed_origins = frozenset(
            origin.rstrip("/") for origin in allowed_source_origins if origin.strip()
        )
        self._providers: dict[tuple[str, int], OpenAICompatibleProvider] = {}
        self._lock = Lock()

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        if capability_id != MODEL_PROVIDER_CAPABILITY:
            raise ProviderUnavailableError(f"unsupported capability: {capability_id}")
        binding_id = implementation_ref or ""
        route = next(
            (
                item
                for item in self._store.list_active_routes()
                if item.target_binding_id == binding_id
            ),
            None,
        )
        if route is None or route.source is None:
            raise ProviderUnavailableError(
                f"no ACTIVE route declares a source endpoint for binding {binding_id!r}"
            )
        return self._provider_for(route.source)

    def validate_route(self, route: Any) -> None:
        """Verify a draft's own source endpoint before it becomes ACTIVE.

        中文:草稿进入 ACTIVE 前验证其自身的源端点。"""

        if route.source is None:
            raise ProviderUnavailableError("route declares no source endpoint")
        self._provider_for(route.source)

    def _provider_for(self, source: Any) -> OpenAICompatibleProvider:
        cache_key = (source.resource_uri, source.resource_version)
        with self._lock:
            cached = self._providers.get(cache_key)
        if cached is not None:
            return cached
        provider = OpenAICompatibleProvider(
            self._source_endpoint_url(source.resource_uri),
            timeout_seconds=self._timeout,
        )
        with self._lock:
            self._providers[cache_key] = provider
        return provider

    def _source_endpoint_url(self, resource_uri: str) -> str:
        """Read the serving URL the route source publishes, under strict limits.

        The URI arrives from Product state, so Exchange constrains it to the
        operator-admitted origins, refuses redirects, and never guesses a
        fallback URL from an untrusted response.

        中文:在严格限制下读取路由源发布的服务 URL。

                中文：URI 来自 Product 状态,因此 Exchange 会将其限制在操作者准入的 origin 范围内、
                拒绝重定向,并且不会根据不可信响应猜测回退 URL。
        """

        origin = _origin(resource_uri)
        if origin is None:
            raise ProviderUnavailableError(
                f"route source URI is not an absolute http(s) URL: {resource_uri}"
            )
        if self._allowed_origins and origin not in self._allowed_origins:
            raise ProviderUnavailableError(f"route source origin is not admitted: {origin}")
        headers = {"Accept": "application/json"}
        if self._source_token:
            headers["Authorization"] = "Bearer " + self._source_token
        try:
            with httpx.Client(
                timeout=self._timeout, trust_env=False, follow_redirects=False
            ) as client:
                response = client.get(resource_uri, headers=headers)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderUnavailableError(
                f"route source endpoint is unavailable: {resource_uri}"
            ) from exc
        url = payload.get("url") if isinstance(payload, Mapping) else None
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ProviderUnavailableError(
                f"route source endpoint publishes no URL: {resource_uri}"
            )
        return url


def _origin(resource_uri: str) -> str | None:
    """Return the scheme://host:port origin of an absolute http(s) URL.

    中文:返回绝对 http(s) URL 的 scheme://host:port origin。"""

    parsed = urlsplit(resource_uri)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    port = parsed.port
    return (
        f"{parsed.scheme}://{parsed.hostname}:{port}"
        if port
        else f"{parsed.scheme}://{parsed.hostname}"
    )


def _route_validator(resolver: Any) -> Callable[[Any], None]:
    """Verify a draft against the same resolver the data plane will use.

    中文:使用数据平面将采用的同一解析器验证草稿。"""

    def validate(route: Any) -> None:
        try:
            validate_route = getattr(resolver, "validate_route", None)
            if callable(validate_route):
                validate_route(route)
                return
            resolver.resolve(MODEL_PROVIDER_CAPABILITY, route.target_binding_id)
        except ProviderUnavailableError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_TARGET_UNREACHABLE",
                title="Route target unreachable",
                detail=(
                    "The configured provider binding could not be reached; repair the source "
                    "endpoint before publishing this draft."
                ),
                status=502,
                retryable=True,
            ) from exc

    return validate


def _select_endpoint(store: ExchangeStore, endpoint_id: UUID | None) -> UUID:
    """Fail closed unless the data plane owns exactly one serving endpoint.

    中文:除非数据平面恰好拥有一个服务端点,否则按失败即拒绝处理。"""

    if endpoint_id is not None:
        return endpoint_id
    active = [item for item in store.list_endpoints() if item.state is EndpointState.ACTIVE]
    if len(active) != 1:
        raise ValueError(
            "EXCHANGE_ENDPOINT_AMBIGUOUS: select --endpoint-id when the store does not hold "
            "exactly one ACTIVE gateway endpoint"
        )
    return active[0].id


def _find_web_dist() -> Path | None:
    env_path = os.environ.get("CYRENE_WEB_DIST")
    server_file = Path(__file__).resolve()
    candidates = [
        Path(env_path) if env_path else None,
        server_file.parent / "web_dist",
        server_file.parents[2] / "web_dist",
        server_file.parents[3] / "web_dist",
        Path.cwd() / "web_dist",
        Path.cwd().parent / "web_dist",
        Path("/app/web_dist"),
        Path("/app/exchange/web_dist"),
        server_file.parents[4]
        / "Cyrene-Client"
        / "apps"
        / "web"
        / "services"
        / "navigator"
        / "dist",
        server_file.parents[5]
        / "Cyrene-Client"
        / "apps"
        / "web"
        / "services"
        / "navigator"
        / "dist",
    ]
    for candidate in candidates:
        if candidate and candidate.is_dir() and (candidate / "index.html").is_file():
            return candidate.resolve()
    return None


def _query_gpu() -> dict[str, Any]:
    """Query NVIDIA GPUs through nvidia-smi; unavailable returns an empty list.

    中文:通过 nvidia-smi 查询 NVIDIA GPU;不可用时返回空列表而非缺失字段,
    便于 Web 控制台统一渲染 "UNAVAILABLE" 状态。
    """
    try:
        out = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,memory.used,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return {"available": False, "gpus": []}
        gpus: list[dict[str, Any]] = []
        for line in out.stdout.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4:
                gpus.append(
                    {
                        "name": parts[0],
                        "totalMib": float(parts[1]) if "." in parts[1] else int(parts[1]),
                        "usedMib": float(parts[2]) if "." in parts[2] else int(parts[2]),
                        "utilizationPct": float(parts[3]) if "." in parts[3] else int(parts[3]),
                    }
                )
        return {"available": True, "gpus": gpus}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, ValueError):
        return {"available": False, "gpus": []}


def _query_disk() -> dict[str, Any]:
    """Return basic disk usage for the workspace root filesystem.

    中文:返回工作区根文件系统的基本磁盘使用情况。
    """
    try:
        usage = shutil.disk_usage("/")
        total = usage.total if usage.total > 0 else 1
        return {
            "available": True,
            "totalGib": round(usage.total / 1024**3, 1),
            "usedGib": round(usage.used / 1024**3, 1),
            "freeGib": round(usage.free / 1024**3, 1),
            "usedPct": round(usage.used * 100 / total, 1),
        }
    except OSError:
        return {"available": False}


def build_product_app(
    *,
    database_path: Any,
    resolver: Any = None,
    resolver_factory: Callable[[Any], Any] | None = None,
    control_credentials: Mapping[str, ProductPrincipal] | None = None,
    allowed_binding_ids: frozenset[str] = frozenset(),
    endpoint_id: UUID | None = None,
    validate_route_target: Callable[[Any], None] | None = None,
    record_requests: bool = True,
    web_dist: Path | str | None = None,
) -> FastAPI:
    """Fuse the control-plane API with the OpenAI-compatible data plane.

    A ``resolver_factory`` receives the Product store, which lets a resolver
    follow persisted route sources instead of duplicating endpoint URLs into
    process configuration. Exactly one of ``resolver``/``resolver_factory`` is
    required, and the draft validator defaults to the same resolver so a route
    can only be published when the data plane can actually reach it.

    中文:将控制平面 API 与 OpenAI 兼容数据平面组合起来。

        中文：``resolver_factory`` 接收 Product store,使解析器能够跟随持久化路由源,
        而无需将端点 URL 重复写入进程配置。必须且只能提供 ``resolver`` 或 ``resolver_factory``
        其中之一。草稿验证器默认使用同一解析器,因此只有数据平面确实可达时才能发布路由。
    """

    if (resolver is None) == (resolver_factory is None):
        raise ValueError(
            "EXCHANGE_RESOLVER_INVALID: provide exactly one of resolver or resolver_factory"
        )
    public_base_url = os.environ.get("CYRENE_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if public_base_url:
        parsed_public_url = urlsplit(public_base_url)
        if (
            parsed_public_url.scheme not in {"http", "https"}
            or not parsed_public_url.hostname
            or parsed_public_url.username
            or parsed_public_url.password
            or parsed_public_url.path
            or parsed_public_url.query
            or parsed_public_url.fragment
        ):
            raise ValueError("CYRENE_PUBLIC_BASE_URL must be an http(s) origin")
    store = ExchangeStore(database_path)
    effective = resolver_factory(store) if resolver_factory is not None else resolver
    app = create_app(
        database_path=database_path,
        control_credentials=control_credentials,
        allowed_binding_ids=allowed_binding_ids,
        validate_route_target=validate_route_target or _route_validator(effective),
        store=store,
    )
    gateway = build_gateway_from_store(
        store,
        _select_endpoint(store, endpoint_id),
        effective,
        credentials=control_credentials or {},
        record_requests=record_requests,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Report process liveness for orchestrators and reverse proxies.

        中文:向编排器和反向代理报告进程存活状态。"""

        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        """Report readiness only when the data plane can serve at least one route.

        中文:只有数据平面至少能服务一条路由时才报告就绪。"""

        routes = store.list_active_routes()
        if not routes:
            return JSONResponse(status_code=503, content={"status": "no-active-route"})
        return JSONResponse(status_code=200, content={"status": "ready", "routes": len(routes)})

    @app.get("/v1/models")
    def models(request: Request) -> Any:
        """List the model patterns the caller's gateway credential may use.

        The data plane authenticates with the same Bearer credential as
        ``/v1/chat/completions``; a key's model scope filters the projection.

        中文:列出调用方 Gateway 凭据可使用的模型模式。

                中文：数据平面使用与 ``/v1/chat/completions`` 相同的 Bearer 凭据进行认证;
                ApiKey 的模型范围会筛选此投影结果。
        """

        principal = None
        if control_credentials is not None:
            scheme, _, token = request.headers.get("authorization", "").partition(" ")
            principal = store.resolve_credential(token) if scheme == "Bearer" else None
            if principal is None:
                return _openai_error(401, "authentication_error", "invalid credentials")
        seen: list[str] = []
        for route in store.list_active_routes():
            if route.model_pattern in seen:
                continue
            if principal is not None and not principal.permits(route.model_pattern):
                continue
            seen.append(route.model_pattern)
        return {
            "object": "list",
            "data": [
                {"id": pattern, "object": "model", "owned_by": "cyrene-exchange"}
                for pattern in seen
            ],
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Any:
        raw = await request.body()
        if not raw or len(raw) > _MAX_PAYLOAD_BYTES:
            return _openai_error(400, "invalid_request_error", "invalid request body")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return _openai_error(400, "invalid_request_error", "request body must be JSON")
        if not isinstance(payload, Mapping):
            return _openai_error(400, "invalid_request_error", "request body must be an object")
        cancel_event = Event()
        try:
            gateway_headers = dict(request.headers.items())
            trace_id = getattr(request.state, "trace_id", None)
            if isinstance(trace_id, str):
                gateway_headers["traceparent"] = f"00-{trace_id}-0000000000000001-01"
            # The gateway and its provider adapters are synchronous, so the call
            # runs on the worker thread instead of stalling the event loop that
            # also serves probes and concurrent requests.
            # 中文:Gateway 及其提供方适配器是同步的,因此调用会在线程池工作线程中执行,
            # 避免阻塞同时处理探测和并发请求的事件循环。
            response = await run_in_threadpool(
                gateway.handle_openai_chat,
                gateway_headers,
                payload,
                cancel_event=cancel_event,
            )
        except GatewayError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.to_openai_error())
        if not response.stream:
            return JSONResponse(status_code=response.status_code, content=response.body)
        return StreamingResponse(
            _sse(response.body, cancel_event),
            media_type="text/event-stream",
            headers={"X-Request-Id": response.request_id, "Cache-Control": "no-cache"},
        )

    @app.middleware("http")
    async def rewrite_exchange_proxy_path(request: Request, call_next: Any) -> Any:
        path = request.scope.get("path", "")
        if path.startswith("/api/v1/exchange/api/v1/"):
            request.scope["path"] = path[len("/api/v1/exchange") :]
        return await call_next(request)

    @app.get("/api/v1/system/status")
    def system_status(request: Request) -> dict[str, Any]:
        routes = store.list_active_routes()
        keys = store.list_api_keys()
        active_keys = sum(
            1
            for k in keys
            if getattr(k, "state", None) == "ACTIVE" or getattr(k, "revoked_at", None) is None
        )
        revoked_keys = len(keys) - active_keys
        now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        base_url = public_base_url or str(request.base_url).rstrip("/")
        gpu_info = _query_gpu()
        disk_info = _query_disk()
        blockers: list[dict[str, Any]] = []
        if not gpu_info.get("available"):
            blockers.append(
                {
                    "code": "GPU_UNAVAILABLE",
                    "message": "No GPU detected. Model fine-tuning and inference require a GPU.",
                }
            )
        return {
            "service": "cyrene-exchange",
            "status": "UP",
            "version": "1.0.0",
            "authenticated": True,
            "proxyPrefixes": ["/api/v1/exchange"],
            "credentials": {
                "active": active_keys,
                "revoked": revoked_keys,
            },
            "routes": len(routes),
            "gatewayBaseUrl": base_url,
            "gpu": gpu_info,
            "disk": disk_info,
            "services": [],
            "blockers": blockers,
            "observedAt": now_utc,
        }

    @app.get("/api/v1/auth/session")
    def auth_session() -> dict[str, Any]:
        return {
            "authenticated": True,
            "state": "AUTHENTICATED",
            "sessionId": "sso-session",
            "expiresAt": "2099-01-01T00:00:00Z",
            "refreshExpiresAt": "2099-01-01T00:00:00Z",
            "refreshable": False,
            "csrfToken": None,
            "refreshed": False,
        }

    @app.post("/api/v1/auth/session/refresh")
    def auth_refresh() -> dict[str, Any]:
        return auth_session()

    @app.post("/api/v1/auth/pair")
    def auth_pair() -> dict[str, Any]:
        return auth_session()

    @app.delete("/api/v1/auth/session")
    def auth_logout() -> dict[str, Any]:
        return {"status": "ok"}

    active_route_state: dict[str, Any] = {}

    @app.get("/api/v1/navigator/active-route")
    def get_active_route(request: Request) -> dict[str, Any]:
        if active_route_state:
            return active_route_state
        routes = store.list_active_routes()
        base_url = public_base_url or str(request.base_url).rstrip("/")
        if routes:
            first_route = routes[0]
            return {
                "gatewayEndpointId": str(first_route.endpoint_id),
                "modelId": first_route.model_pattern,
                "baseUrl": f"{base_url}/v1",
                "apiKeyHint": "",
            }
        return {
            "gatewayEndpointId": "default",
            "modelId": "default",
            "baseUrl": f"{base_url}/v1",
            "apiKeyHint": "",
        }

    @app.post("/api/v1/navigator/active-route")
    async def set_active_route(request: Request) -> dict[str, Any]:
        payload = await request.json()
        active_route_state.clear()
        active_route_state.update(payload)
        return active_route_state

    @app.post("/api/proxy/exchange-gateway/v1/chat/completions")
    async def proxy_chat_completions(request: Request) -> Any:
        return await chat_completions(request)

    effective_web_dist = Path(web_dist) if web_dist is not None else _find_web_dist()
    if (
        effective_web_dist
        and effective_web_dist.is_dir()
        and (effective_web_dist / "index.html").is_file()
    ):
        assets_dir = effective_web_dist / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/")
        async def serve_index() -> FileResponse:
            return FileResponse(str(effective_web_dist / "index.html"))

        @app.get("/{full_path:path}")
        async def spa_fallback(full_path: str) -> Any:
            target = effective_web_dist / full_path
            if target.is_file() and not full_path.startswith(
                ("api/", "v1/", "healthz", "readyz", "docs", "openapi.json")
            ):
                return FileResponse(str(target))
            if not full_path.startswith(
                ("api/", "v1/", "healthz", "readyz", "docs", "openapi.json")
            ):
                return FileResponse(str(effective_web_dist / "index.html"))
            return JSONResponse(status_code=404, content={"detail": "Not Found"})

    return app


async def _sse(body: Any, cancel_event: Event) -> AsyncIterator[str]:
    """Emit structured SSE without blocking the loop while the provider streams.

    Provider chunks are pulled one at a time on the worker thread, and closing
    the response cancels the in-flight provider call.

    中文:提供方进行流式输出时,以非阻塞方式发送结构化 SSE。

        中文:提供方数据块会在工作线程中逐个读取;关闭响应会取消正在执行的提供方调用。
    """

    if not isinstance(body, Iterable):
        raise TypeError("stream response body must be iterable")
    iterator = iter(body)
    sentinel = object()
    try:
        while True:
            item = await run_in_threadpool(next, iterator, sentinel)
            if item is sentinel:
                return
            if cancel_event.is_set():
                return
            encoded = item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))
            yield f"data: {encoded}\n\n"
    except GatewayError:
        return  # diagnostic-allow: Gateway persists the failed stream audit before closing SSE.
    finally:
        cancel_event.set()


def _openai_error(status: int, error_type: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"type": error_type, "message": message}},
    )
