###############################################################################
# 📄 File: src/cyrene_exchange/gateway.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; response shaping preserves tools and usage.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；响应整形保留工具调用与 usage 事实。
###############################################################################
"""Exchange Product Core request policy and capability orchestration.

Exchange Product Core 的请求策略与能力编排。
"""

from __future__ import annotations

import hashlib
import sys
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase
from threading import Event
from typing import Any, Literal, Protocol

from .capabilities import (
    MODEL_PROVIDER_CAPABILITY,
    MODEL_ROUTING_CAPABILITY,
    CapabilityResolver,
    ModelEmbeddingCapability,
    ModelProviderCapability,
    ModelRoutingCapability,
    ProviderChunk,
    ProviderEmbeddingBatch,
    ProviderEmbeddingError,
    ProviderInvocationCancelled,
    ProviderUsage,
    RouteTarget,
    ToolCallDelta,
)
from .logging import format_cyrene_log, parse_w3c_traceparent
from .protocol import MAX_CHAT_MEDIA_BYTES, NormalizedEmbeddingRequest, NormalizedInferenceRequest, ProtocolError


class GatewayError(Exception):
    """An error with a defined Product-to-transport response mapping.

    具有明确 Product 到传输层响应映射的错误。
    """

    status_code = 500
    error_type = "gateway_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def to_openai_error(self) -> dict[str, Any]:
        return {"error": {"message": self.message, "type": self.error_type}}


class GatewayLifecycleError(GatewayError):
    """A durable request lifecycle callback failed before the request was safe.

    请求达到安全执行条件之前,持久化生命周期回调失败。
    """

    status_code = 500
    error_type = "gateway_lifecycle_error"


class AuthenticationError(GatewayError):
    status_code = 401
    error_type = "authentication_error"


class InvalidRequestError(GatewayError):
    status_code = 400
    error_type = "invalid_request_error"


class MediaArtifactUnavailableError(GatewayError):
    """A requested opaque media reference could not be safely resolved.

    中文:请求中的不透明媒体引用无法安全解析。
    """

    status_code = 424
    error_type = "media_artifact_unavailable"


class ModelNotPermittedError(GatewayError):
    """The credential's model scope excludes the requested model.

    凭据的模型范围不包含所请求的模型。
    """

    status_code = 403
    error_type = "model_not_permitted"


class NoRouteError(GatewayError):
    status_code = 503
    error_type = "no_route"


class ProviderFailureError(GatewayError):
    status_code = 502
    error_type = "provider_error"

    def __init__(self, message: str, *, usage: ProviderUsage | None = None) -> None:
        super().__init__(message)
        self.usage = usage


class EmbeddingProviderResponseError(GatewayError):
    """A typed error returned by the selected embeddings provider.

    中文:所选 embeddings 提供方返回的有类型错误。
    """

    _ERRORS = {
        1: (400, "invalid_request_error"),
        2: (404, "model_not_found"),
        3: (502, "provider_error"),
        4: (502, "provider_error"),
        5: (429, "rate_limit_error"),
    }

    def __init__(self, error: ProviderEmbeddingError) -> None:
        self.status_code, self.error_type = self._ERRORS[error.code]
        self.code = error.code
        self.retry_after_seconds = error.retry_after_seconds
        super().__init__(error.message)

    def to_openai_error(self) -> dict[str, Any]:
        detail: dict[str, Any] = {"message": self.message, "type": self.error_type, "code": self.code}
        if self.retry_after_seconds is not None:
            detail["retry_after_seconds"] = self.retry_after_seconds
        return {"error": detail}


class RequestCancelled(GatewayError):
    status_code = 499
    error_type = "request_cancelled"

    def __init__(self, message: str, *, usage: ProviderUsage | None = None) -> None:
        super().__init__(message)
        self.usage = usage


class QuotaExceededError(GatewayError):
    status_code = 429
    error_type = "quota_exceeded"


class QuotaUnavailableError(GatewayError):
    status_code = 503
    error_type = "quota_unavailable"


@dataclass(frozen=True)
class RequestPrincipal:
    """Trusted identity resolved from an Exchange credential.

    Request payloads never participate in constructing this value.  Product
    adapters may persist only the references, never the credential itself.
    An empty ``model_scope`` admits every model pattern; a non-empty scope is a
    set of fnmatch patterns the requested model must match.

    根据 Exchange 凭据解析出的可信身份。请求载荷不会参与构造此值。Product adapter 只能持久化这些引用,不能持久化凭据本身。空的 ``model_scope`` 表示允许所有模型模式;非空范围是一组 fnmatch 模式,请求的模型必须匹配其中之一。
    """

    actor_id: str
    workspace_id: str
    credential_ref: str
    model_scope: frozenset[str] = field(default_factory=frozenset)
    organization_id: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("actor_id", "workspace_id", "credential_ref"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"request principal {field_name} must be non-empty text")
        if self.organization_id is not None and (
            not isinstance(self.organization_id, str) or not self.organization_id.strip()
        ):
            raise ValueError("request principal organization_id must be non-empty text when configured")
        for pattern in self.model_scope:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError("request principal model_scope patterns must be non-empty text")

    def permits(self, model: str) -> bool:
        """Return whether the requested model is inside this scope.

        返回请求的模型是否属于此范围。
        """

        if not self.model_scope:
            return True
        return any(fnmatchcase(model, pattern) for pattern in self.model_scope)


@dataclass(frozen=True)
class ResolvedMediaArtifact:
    """Authorized media bytes and their content identity from a Product store.

    中文:Product 存储返回的、已授权媒体 bytes 及其内容身份。
    """

    mime_type: str
    data: bytes
    sha256: str
    size: int


class MediaArtifactResolver(Protocol):
    """Product adapter that resolves an opaque media ID for one principal.

    中文:按调用主体解析不透明媒体 ID 的 Product adapter。
    """

    def read(
        self,
        artifact_id: str,
        *,
        principal: RequestPrincipal,
        cancel_event: Event,
    ) -> ResolvedMediaArtifact:
        """Return the artifact only when this principal may read it.

        仅在此主体有权读取制品时返回内容。
        """


@dataclass(frozen=True)
class RequestMetadata:
    """Non-content request facts exposed to a Product lifecycle recorder.

    提供给 Product 生命周期记录器的非内容类请求事实。
    """

    request_id: str
    model: str
    stream: bool
    route_id: str
    provider_ref: str
    principal: RequestPrincipal


RequestAuditTerminalStatus = Literal["completed", "failed", "cancelled"]
RequestRejectionStatus = Literal["rejected", "cancelled"]


class RequestLifecycleObserver(Protocol):
    """Durable observer for request admission and terminal provider facts.

    用于记录请求准入和提供方终态事实的持久化观察器。
    """

    def on_request_started(self, metadata: RequestMetadata) -> None:
        """Record trusted route and identity facts before provider execution.

        在执行提供方调用前记录可信路由和身份事实。
        """

    def on_request_finished(
        self,
        metadata: RequestMetadata,
        *,
        status: RequestAuditTerminalStatus,
        usage: ProviderUsage | None,
        error_type: str | None,
    ) -> None:
        """Record exactly one terminal outcome and observed provider usage.

        精确记录一次终态结果和观测到的提供方用量。
        """

    def on_request_rejected(
        self,
        *,
        request_id: str,
        principal: RequestPrincipal | None,
        status: RequestRejectionStatus,
        error_type: str,
        model: str | None,
        stream: bool | None,
    ) -> None:
        """Record a request that never reached a provider.

        记录一条未到达提供方的请求。
        """


class NoOpLifecycleObserver:
    """Non-recording observer that satisfies the mandatory observer contract.

    中文:满足强制 observer 契约的非记录型观察器。
    """

    allow_multiple_attempts = True

    def on_request_started(self, metadata: RequestMetadata) -> None:
        pass

    def on_request_finished(
        self,
        metadata: RequestMetadata,
        *,
        status: RequestAuditTerminalStatus,
        usage: ProviderUsage | None,
        error_type: str | None,
    ) -> None:
        pass

    def on_request_rejected(
        self,
        *,
        request_id: str,
        principal: RequestPrincipal | None,
        status: RequestRejectionStatus,
        error_type: str,
        model: str | None,
        stream: bool | None,
    ) -> None:
        pass


def _request_for_routing(request: NormalizedInferenceRequest) -> NormalizedInferenceRequest:
    """Keep media bytes and artifact IDs out of model-route selection.

    中文:路由选择只保留媒体类型和大小，不传媒体 bytes 或 artifact ID。
    """

    messages: list[dict[str, Any]] = []
    for message in request.messages:
        content = message.get("content")
        if not isinstance(content, (list, tuple)):
            messages.append(dict(message))
            continue
        routed_parts: list[dict[str, Any]] = []
        for part in content:
            if not isinstance(part, Mapping) or part.get("type") == "text":
                routed_parts.append(dict(part) if isinstance(part, Mapping) else {})
                continue
            metadata: dict[str, Any] = {"type": part.get("type"), "mime_type": part.get("mime_type")}
            data = part.get("data")
            if isinstance(data, bytes):
                metadata["byte_length"] = len(data)
            else:
                metadata["has_artifact"] = "artifact_id" in part
            routed_parts.append(metadata)
        routed_message = dict(message)
        routed_message["content"] = tuple(routed_parts)
        messages.append(routed_message)
    return replace(request, messages=tuple(messages))


@dataclass(frozen=True)
class GatewayResponse:
    """Normalized Product response returned to a transport adapter.

    返回给传输 adapter 的规范化 Product 响应。
    """

    request_id: str
    model: str
    status_code: int
    body: dict[str, Any] | Iterable[dict[str, Any] | str]
    stream: bool
    route_id: str
    usage: ProviderUsage | None = None


@dataclass
class _ToolCallAccumulator:
    """Mutable assembly state for one indexed provider tool call.

    用于组装一条带索引的提供方工具调用的可变状态。
    """

    index: int
    call_id: str | None = None
    call_type: str | None = None
    function_name: str = ""
    function_arguments: str = ""
    function_name_seen: bool = False
    function_arguments_seen: bool = False

    def merge(self, delta: ToolCallDelta) -> None:
        """Append one fragment while rejecting conflicting call identity.

        追加一个片段,并拒绝调用身份冲突的情况。
        """

        if delta.index != self.index:
            raise ProviderFailureError("provider tool-call index changed during assembly")
        if delta.id is not None:
            if self.call_id is not None and self.call_id != delta.id:
                raise ProviderFailureError(f"provider returned conflicting tool-call ids for index {self.index}")
            self.call_id = delta.id
        if delta.type is not None:
            if self.call_type is not None and self.call_type != delta.type:
                raise ProviderFailureError(f"provider returned conflicting tool-call types for index {self.index}")
            self.call_type = delta.type
        if delta.function_name is not None:
            self.function_name_seen = True
            self.function_name += delta.function_name
        if delta.function_arguments is not None:
            self.function_arguments_seen = True
            self.function_arguments += delta.function_arguments

    def to_openai_message(self) -> dict[str, Any]:
        """Serialize complete accumulated tool-call state.

        序列化已完整累积的工具调用状态。
        """

        function: dict[str, str] = {}
        if self.function_name_seen:
            function["name"] = self.function_name
        if self.function_arguments_seen:
            function["arguments"] = self.function_arguments
        # ``index`` orders streamed fragments; OpenAI's completed message
        # schema represents that order by the list position and omits it.
        # ``index`` 用于排列流式片段;OpenAI 完成消息的 schema 通过列表顺序表达该顺序,因此省略此字段。
        result: dict[str, Any] = {}
        if self.call_id is not None:
            result["id"] = self.call_id
        if self.call_type is not None:
            result["type"] = self.call_type
        if function:
            result["function"] = function
        return result


TokenPrincipalResolver = Callable[[str], RequestPrincipal | None]


class ExchangeGateway:
    """Product-owned policy around Platform-resolved model capabilities.

    The resolver is the only way this class obtains routing and provider
    implementations.  Exchange owns candidate lifecycle and fallback policy;
    the routing capability owns candidate selection/scoring.

    围绕 Platform 解析出的模型能力执行 Product 所有的策略。此类只能通过 resolver 获取路由和提供方实现。Exchange 拥有候选项生命周期和 fallback 策略;路由能力拥有候选项选择与评分。
    """

    def __init__(
        self,
        resolver: CapabilityResolver,
        *,
        principal_resolver: TokenPrincipalResolver | None = None,
        lifecycle_observer: RequestLifecycleObserver | None = None,
        quota_checker: Callable[[RequestPrincipal], None] | None = None,
        media_artifact_resolver: MediaArtifactResolver | None = None,
        max_route_attempts: int = 3,
    ) -> None:
        if max_route_attempts <= 0:
            raise ValueError("max_route_attempts must be positive")
        if principal_resolver is None:
            raise ValueError("principal_resolver is required")
        if lifecycle_observer is None:
            raise ValueError("lifecycle_observer is required")
        if max_route_attempts != 1 and not getattr(lifecycle_observer, "allow_multiple_attempts", False):
            raise ValueError("V1 request auditing requires one provider attempt per request")
        self._resolver = resolver
        self._principal_resolver = principal_resolver
        self._lifecycle_observer = lifecycle_observer
        self._quota_checker = quota_checker
        self._media_artifact_resolver = media_artifact_resolver
        self._max_route_attempts = max_route_attempts

    # ════════════════════════════════════════════════════════════════════════
    # 🔧 FUNCTION: ExchangeGateway.handle_openai_chat
    #
    #   Owns Product request policy: authentication, capability resolution,
    #   bounded fallback, cancellation, and response shaping.
    #
    #   负责 Product 请求 policy：认证、能力解析、有界回退、取消和响应整形。
    # ════════════════════════════════════════════════════════════════════════
    def handle_openai_chat(
        self,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        *,
        cancel_event: Event | None = None,
        request_id: str | None = None,
    ) -> GatewayResponse:
        """Handle one OpenAI-compatible chat request.

        Fallback is deliberately limited to failures before a usable provider
        response begins.  Once a stream has emitted a chunk, Exchange cannot
        safely replay a partial response through another route.

        处理一个 OpenAI 兼容的 chat 请求。Fallback 仅用于可用的提供方响应开始之前发生的故障。流一旦发出数据块,Exchange 就无法安全地通过另一条路由重放部分响应。
        """

        request_id = request_id or f"chatcmpl-{uuid.uuid4().hex}"
        cancel_event = cancel_event or Event()
        try:
            principal = self._authenticate(headers)
        except AuthenticationError as exc:
            self._observe_rejected(
                request_id=request_id,
                principal=None,
                status="rejected",
                error_type=exc.error_type,
                model=self._payload_model(payload),
                stream=self._payload_stream(payload),
            )
            raise

        if self._quota_checker is not None:
            try:
                self._quota_checker(principal)
            except (QuotaExceededError, QuotaUnavailableError) as exc:
                self._observe_rejected(
                    request_id=request_id,
                    principal=principal,
                    status="rejected",
                    error_type=exc.error_type,
                    model=self._payload_model(payload),
                    stream=self._payload_stream(payload),
                )
                raise
        if cancel_event.is_set():
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="cancelled",
                error_type=RequestCancelled.error_type,
                model=self._payload_model(payload),
                stream=self._payload_stream(payload),
            )
            raise RequestCancelled("request was cancelled before routing")

        try:
            request = NormalizedInferenceRequest.from_openai(payload)
        except ProtocolError as exc:
            error = InvalidRequestError(str(exc))
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=self._payload_model(payload),
                stream=self._payload_stream(payload),
            )
            raise error from exc

        if not principal.permits(request.model):
            error = ModelNotPermittedError(f"credential is not permitted to use model {request.model}")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise error

        try:
            router = self._resolve_router()
        except NoRouteError as exc:
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=exc.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise
        except Exception as exc:
            error = NoRouteError(f"model routing capability resolution failed: {exc}")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise error from exc
        try:
            candidates = self._plan_routes(
                router,
                _request_for_routing(request),
                principal,
            )[: self._max_route_attempts]
        except Exception as exc:
            error = NoRouteError(f"model routing failed: {exc}")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise error from exc
        if not candidates:
            error = NoRouteError(f"no route available for model '{request.model}'")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise error

        try:
            request = self._resolve_media_artifacts(request, principal, cancel_event)
        except RequestCancelled as exc:
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="cancelled",
                error_type=exc.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise
        except MediaArtifactUnavailableError as exc:
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=exc.error_type,
                model=request.model,
                stream=request.stream,
            )
            raise

        failures: list[str] = []
        for target in candidates:
            if cancel_event.is_set():
                self._observe_rejected(
                    request_id=request_id,
                    principal=principal,
                    status="cancelled",
                    error_type=RequestCancelled.error_type,
                    model=request.model,
                    stream=request.stream,
                )
                raise RequestCancelled("request was cancelled before provider execution")
            route_id = target.route_id or target.provider_ref
            metadata = RequestMetadata(
                request_id=request_id,
                model=request.model,
                stream=request.stream,
                route_id=route_id,
                provider_ref=target.provider_ref,
                principal=principal,
            )
            started = False
            try:
                # Admission is deliberately before provider resolution and
                # invocation, so failed bindings remain auditable too.
                # 准入必须在解析和调用提供方之前完成,因此绑定失败也能留下审计记录。
                self._observe_started(metadata)
                started = True
                provider = self._resolve_provider(target)
                provider_request = request
                if target.model and target.model != request.model:
                    provider_request = NormalizedInferenceRequest(
                        model=target.model,
                        messages=request.messages,
                        stream=request.stream,
                        temperature=request.temperature,
                        max_tokens=request.max_tokens,
                        tools=request.tools,
                        tool_choice=request.tool_choice,
                        parallel_tool_calls=request.parallel_tool_calls,
                        stream_options=request.stream_options,
                    )
                chunks = iter(provider.complete(provider_request, cancel_event=cancel_event))
                first = next(chunks)
                if request.stream:
                    return GatewayResponse(
                        request_id=request_id,
                        model=request.model,
                        status_code=200,
                        body=self._stream_body(
                            request_id,
                            request.model,
                            first,
                            chunks,
                            cancel_event,
                            include_usage=bool(
                                request.stream_options and request.stream_options.get("include_usage", False)
                            ),
                            metadata=metadata,
                        ),
                        stream=True,
                        route_id=route_id,
                    )
                response = self._collect_response(
                    request_id,
                    request.model,
                    target,
                    first,
                    chunks,
                    cancel_event,
                )
                self._observe_finished(metadata, status="completed", usage=response.usage, error_type=None)
                return response
            except RequestCancelled as exc:
                if started:
                    self._observe_finished(
                        metadata,
                        status="cancelled",
                        usage=exc.usage,
                        error_type=RequestCancelled.error_type,
                    )
                raise
            except ProviderInvocationCancelled as exc:
                error = RequestCancelled("provider invocation was cancelled")
                if started:
                    self._observe_finished(
                        metadata,
                        status="cancelled",
                        usage=None,
                        error_type=error.error_type,
                    )
                raise error from exc
            except GatewayLifecycleError:
                raise
            except Exception as exc:
                if cancel_event.is_set():
                    error = RequestCancelled("request was cancelled during provider execution")
                    if started:
                        self._observe_finished(
                            metadata,
                            status="cancelled",
                            usage=getattr(exc, "usage", None),
                            error_type=error.error_type,
                        )
                    raise error from exc
                if started:
                    self._observe_finished(
                        metadata,
                        status="failed",
                        usage=getattr(exc, "usage", None),
                        error_type=self._audit_error_type(exc),
                    )
                failures.append(f"{target.route_id or target.provider_ref}: {exc}")
                continue

        detail = "; ".join(failures) or "all provider candidates failed"
        raise ProviderFailureError(detail)

    def handle_openai_embeddings(
        self,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        *,
        cancel_event: Event | None = None,
        request_id: str | None = None,
    ) -> GatewayResponse:
        """Authenticate, route, audit and execute one embeddings request.

        中文:认证、路由、审计并执行一次 embeddings 请求。
        """

        request_id = request_id or f"emb-{uuid.uuid4().hex}"
        cancel_event = cancel_event or Event()
        try:
            principal = self._authenticate(headers)
        except AuthenticationError as exc:
            self._observe_rejected(
                request_id=request_id,
                principal=None,
                status="rejected",
                error_type=exc.error_type,
                model=self._payload_model(payload),
                stream=False,
            )
            raise

        if self._quota_checker is not None:
            try:
                self._quota_checker(principal)
            except (QuotaExceededError, QuotaUnavailableError) as exc:
                self._observe_rejected(
                    request_id=request_id,
                    principal=principal,
                    status="rejected",
                    error_type=exc.error_type,
                    model=self._payload_model(payload),
                    stream=False,
                )
                raise
        if cancel_event.is_set():
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="cancelled",
                error_type=RequestCancelled.error_type,
                model=self._payload_model(payload),
                stream=False,
            )
            raise RequestCancelled("request was cancelled before routing")

        try:
            request = NormalizedEmbeddingRequest.from_openai(payload)
        except ProtocolError as exc:
            error = InvalidRequestError(str(exc))
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=self._payload_model(payload),
                stream=False,
            )
            raise error from exc

        if not principal.permits(request.model):
            error = ModelNotPermittedError(f"credential is not permitted to use model {request.model}")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=False,
            )
            raise error

        try:
            router = self._resolve_router()
            candidates = self._plan_routes(router, request, principal)[: self._max_route_attempts]
        except NoRouteError as exc:
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=exc.error_type,
                model=request.model,
                stream=False,
            )
            raise
        except Exception as exc:
            error = NoRouteError(f"model routing failed: {exc}")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=False,
            )
            raise error from exc
        if not candidates:
            error = NoRouteError(f"no route available for model '{request.model}'")
            self._observe_rejected(
                request_id=request_id,
                principal=principal,
                status="rejected",
                error_type=error.error_type,
                model=request.model,
                stream=False,
            )
            raise error

        failures: list[str] = []
        for target in candidates:
            if cancel_event.is_set():
                self._observe_rejected(
                    request_id=request_id,
                    principal=principal,
                    status="cancelled",
                    error_type=RequestCancelled.error_type,
                    model=request.model,
                    stream=False,
                )
                raise RequestCancelled("request was cancelled before provider execution")
            route_id = target.route_id or target.provider_ref
            metadata = RequestMetadata(
                request_id=request_id,
                model=request.model,
                stream=False,
                route_id=route_id,
                provider_ref=target.provider_ref,
                principal=principal,
            )
            started = False
            try:
                self._observe_started(metadata)
                started = True
                provider = self._resolve_embedding_provider(target)
                provider_request = request
                if target.model and target.model != request.model:
                    provider_request = NormalizedEmbeddingRequest(
                        model=target.model,
                        inputs=request.inputs,
                    )
                batch = provider.embed(provider_request, cancel_event=cancel_event)
                if not isinstance(batch, ProviderEmbeddingBatch) or len(batch.vectors) != len(request.inputs):
                    raise ProviderFailureError("embedding provider returned an incomplete batch")
                body = {
                    "object": "list",
                    "data": [
                        {"object": "embedding", "embedding": list(vector), "index": index}
                        for index, vector in enumerate(batch.vectors)
                    ],
                    "model": batch.model,
                }
                if cancel_event.is_set():
                    raise RequestCancelled("request was cancelled during embedding provider execution")
                self._observe_finished(metadata, status="completed", usage=None, error_type=None)
                return GatewayResponse(
                    request_id=request_id,
                    model=batch.model,
                    status_code=200,
                    body=body,
                    stream=False,
                    route_id=route_id,
                )
            except RequestCancelled as exc:
                if started:
                    self._observe_finished(metadata, status="cancelled", usage=None, error_type=exc.error_type)
                raise
            except ProviderInvocationCancelled as exc:
                error = RequestCancelled("embedding provider invocation was cancelled")
                if started:
                    self._observe_finished(metadata, status="cancelled", usage=None, error_type=error.error_type)
                raise error from exc
            except ProviderEmbeddingError as exc:
                error = EmbeddingProviderResponseError(exc)
                if started:
                    self._observe_finished(metadata, status="failed", usage=None, error_type=error.error_type)
                raise error from exc
            except GatewayLifecycleError:
                raise
            except Exception as exc:
                if cancel_event.is_set():
                    error = RequestCancelled("request was cancelled during provider execution")
                    if started:
                        self._observe_finished(metadata, status="cancelled", usage=None, error_type=error.error_type)
                    raise error from exc
                if started:
                    self._observe_finished(
                        metadata,
                        status="failed",
                        usage=None,
                        error_type=self._audit_error_type(exc),
                    )
                failures.append(f"{route_id}: {exc}")

        detail = "; ".join(failures) or "all embedding provider candidates failed"
        raise ProviderFailureError(detail)

    def _authenticate(self, headers: Mapping[str, str]) -> RequestPrincipal:
        authorization = next(
            (value for key, value in headers.items() if key.lower() == "authorization"),
            None,
        )
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise AuthenticationError("Authorization must use a Bearer token")
        token = authorization[7:].strip()
        if not token:
            raise AuthenticationError("Bearer token is empty")
        try:
            principal = self._principal_resolver(token)
        except Exception as exc:
            traceparent = next(
                (value for key, value in headers.items() if key.lower() == "traceparent"),
                None,
            )
            trace = parse_w3c_traceparent(traceparent)
            sys.stderr.write(
                format_cyrene_log(
                    level="WARN",
                    event_name="exchange.gateway.auth_failed",
                    message="Token principal resolution failed",
                    trace_id=trace[0] if trace else None,
                    span_id=trace[1] if trace else None,
                    attributes={"cause_type": type(exc).__name__},
                )
                + "\n"
            )
            principal = None
        if isinstance(principal, RequestPrincipal):
            return principal
        raise AuthenticationError("invalid credentials")

    def _resolve_media_artifacts(
        self,
        request: NormalizedInferenceRequest,
        principal: RequestPrincipal,
        cancel_event: Event,
    ) -> NormalizedInferenceRequest:
        total_bytes = 0
        resolved_messages: list[dict[str, Any]] = []
        for message_index, message in enumerate(request.messages):
            content = message.get("content")
            if not isinstance(content, (list, tuple)):
                resolved_messages.append(dict(message))
                continue
            resolved_parts: list[dict[str, Any]] = []
            for part_index, raw_part in enumerate(content):
                if not isinstance(raw_part, Mapping) or "artifact_id" not in raw_part:
                    inline = raw_part.get("data") if isinstance(raw_part, Mapping) else None
                    if isinstance(inline, bytes):
                        total_bytes += len(inline)
                        if total_bytes > MAX_CHAT_MEDIA_BYTES:
                            raise MediaArtifactUnavailableError("resolved media exceeds the maximum aggregate size")
                    resolved_parts.append(dict(raw_part) if isinstance(raw_part, Mapping) else {})
                    continue
                if cancel_event.is_set():
                    raise RequestCancelled("request was cancelled while resolving media")
                resolver = self._media_artifact_resolver
                if resolver is None:
                    raise MediaArtifactUnavailableError("media artifact resolution is unavailable")
                artifact_id = raw_part.get("artifact_id")
                if not isinstance(artifact_id, str):
                    raise MediaArtifactUnavailableError("media artifact reference is invalid")
                try:
                    artifact = resolver.read(
                        artifact_id,
                        principal=principal,
                        cancel_event=cancel_event,
                    )
                except RequestCancelled:
                    raise
                except Exception as exc:
                    raise MediaArtifactUnavailableError("media artifact is unavailable to this principal") from exc
                if cancel_event.is_set():
                    raise RequestCancelled("request was cancelled while resolving media")
                if not isinstance(artifact, ResolvedMediaArtifact):
                    raise MediaArtifactUnavailableError("media artifact resolver returned an invalid result")
                expected_mime = raw_part.get("mime_type")
                if artifact.mime_type != expected_mime or not isinstance(artifact.data, bytes) or not artifact.data:
                    raise MediaArtifactUnavailableError("media artifact content does not match its reference")
                if artifact.size != len(artifact.data) or artifact.size > MAX_CHAT_MEDIA_BYTES:
                    raise MediaArtifactUnavailableError("media artifact size is invalid")
                digest = hashlib.sha256(artifact.data).hexdigest()
                if artifact.sha256 != digest:
                    raise MediaArtifactUnavailableError("media artifact digest verification failed")
                total_bytes += artifact.size
                if total_bytes > MAX_CHAT_MEDIA_BYTES:
                    raise MediaArtifactUnavailableError("resolved media exceeds the maximum aggregate size")
                resolved = dict(raw_part)
                resolved.pop("artifact_id", None)
                resolved["data"] = artifact.data
                resolved_parts.append(resolved)
            copied = dict(message)
            copied["content"] = tuple(resolved_parts)
            resolved_messages.append(copied)
        return replace(request, messages=tuple(resolved_messages))

    @staticmethod
    def _payload_model(payload: Mapping[str, Any]) -> str | None:
        value = payload.get("model")
        return value if isinstance(value, str) else None

    @staticmethod
    def _payload_stream(payload: Mapping[str, Any]) -> bool | None:
        value = payload.get("stream")
        return value if isinstance(value, bool) else None

    def _observe_started(self, metadata: RequestMetadata) -> None:
        try:
            self._lifecycle_observer.on_request_started(metadata)
        except GatewayLifecycleError:
            raise
        except Exception as exc:
            raise GatewayLifecycleError(f"request admission persistence failed: {exc}") from exc

    def _observe_finished(
        self,
        metadata: RequestMetadata,
        *,
        status: RequestAuditTerminalStatus,
        usage: ProviderUsage | None,
        error_type: str | None,
    ) -> None:
        try:
            self._lifecycle_observer.on_request_finished(
                metadata,
                status=status,
                usage=usage,
                error_type=error_type,
            )
        except GatewayLifecycleError:
            raise
        except Exception as exc:
            raise GatewayLifecycleError(f"request terminal persistence failed: {exc}") from exc

    def _observe_rejected(
        self,
        *,
        request_id: str,
        principal: RequestPrincipal | None,
        status: RequestRejectionStatus,
        error_type: str,
        model: str | None,
        stream: bool | None,
    ) -> None:
        try:
            self._lifecycle_observer.on_request_rejected(
                request_id=request_id,
                principal=principal,
                status=status,
                error_type=error_type,
                model=model,
                stream=stream,
            )
        except GatewayLifecycleError:
            raise
        except Exception as exc:
            raise GatewayLifecycleError(f"request rejection persistence failed: {exc}") from exc

    @staticmethod
    def _audit_error_type(exc: Exception) -> str:
        """Prefer stable Gateway error types over implementation class names.

        优先使用稳定的 Gateway 错误类型,而不是实现类名称。
        """

        return exc.error_type if isinstance(exc, GatewayError) else type(exc).__name__

    def _resolve_router(self) -> ModelRoutingCapability:
        router = self._resolver.resolve(MODEL_ROUTING_CAPABILITY)
        if not hasattr(router, "plan"):
            raise NoRouteError("resolved model routing capability is invalid")
        return router  # type: ignore[return-value]

    @staticmethod
    def _plan_routes(
        router: Any,
        request: NormalizedInferenceRequest | NormalizedEmbeddingRequest,
        principal: RequestPrincipal,
    ) -> list[RouteTarget]:
        """Pass authenticated identity to Product routers with scoped routes.

        Generic model-routing providers keep their request-only protocol.
        Product adapters may expose an additive plan_for_principal method whose
        scope is derived from authenticated credentials, never request fields.

        中文：对支持租户隔离的 Product 路由器传入认证主体；通用路由接口保持兼容。
        """

        plan_for_principal = getattr(router, "plan_for_principal", None)
        if callable(plan_for_principal):
            return list(plan_for_principal(request, principal=principal))
        return list(router.plan(request))

    def _resolve_provider(self, target: RouteTarget) -> ModelProviderCapability:
        provider = self._resolver.resolve(MODEL_PROVIDER_CAPABILITY, target.provider_ref)
        if not hasattr(provider, "complete"):
            raise ProviderFailureError(f"resolved provider '{target.provider_ref}' is invalid")
        return provider  # type: ignore[return-value]

    def _resolve_embedding_provider(self, target: RouteTarget) -> ModelEmbeddingCapability:
        provider = self._resolver.resolve(MODEL_PROVIDER_CAPABILITY, target.provider_ref)
        if not hasattr(provider, "embed"):
            raise ProviderFailureError(f"resolved embedding provider '{target.provider_ref}' is invalid")
        return provider  # type: ignore[return-value]

    def _collect_response(
        self,
        request_id: str,
        model: str,
        target: RouteTarget,
        first: ProviderChunk,
        chunks: Iterable[ProviderChunk],
        cancel_event: Event,
    ) -> GatewayResponse:
        collected = [first]
        try:
            for chunk in chunks:
                if cancel_event.is_set():
                    raise RequestCancelled(
                        "request was cancelled during provider execution",
                        usage=self._merge_chunk_usage(collected),
                    )
                collected.append(chunk)
        except RequestCancelled:
            raise
        except ProviderInvocationCancelled as exc:
            raise RequestCancelled(
                "provider invocation was cancelled during provider execution",
                usage=self._merge_chunk_usage(collected),
            ) from exc
        except Exception as exc:
            # No bytes have reached the client in non-stream mode, so Product
            # fallback may safely be attempted by the caller's next request.
            # 非流式模式尚未向客户端发送任何字节,因此调用方可以安全地在下一次请求中尝试 Product fallback。
            raise ProviderFailureError(
                f"{target.route_id or target.provider_ref}: {exc}",
                usage=self._merge_chunk_usage(collected),
            ) from exc

        message = self._assemble_message(collected)
        has_tool_calls = any(chunk.tool_calls for chunk in collected)
        finish_reason = next(
            (chunk.finish_reason for chunk in reversed(collected) if chunk.finish_reason),
            "tool_calls" if has_tool_calls else "stop",
        )
        observed_usage = self._merge_chunk_usage(collected)
        body: dict[str, Any] = {
            "id": request_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": finish_reason,
                }
            ],
        }
        if observed_usage is not None:
            serialized_usage = observed_usage.to_openai_dict()
            if serialized_usage:
                body["usage"] = serialized_usage
        return GatewayResponse(
            request_id=request_id,
            model=model,
            status_code=200,
            body=body,
            stream=False,
            route_id=target.route_id or target.provider_ref,
            usage=observed_usage,
        )

    def _stream_body(
        self,
        request_id: str,
        model: str,
        first: ProviderChunk,
        chunks: Iterable[ProviderChunk],
        cancel_event: Event,
        *,
        include_usage: bool,
        metadata: RequestMetadata,
    ) -> Iterable[dict[str, Any] | str]:
        emitted_finish = False
        saw_tool_calls = False
        usage: ProviderUsage | None = None
        usage_emitted = False
        terminal_status: RequestAuditTerminalStatus | None = None
        terminal_error: str | None = None
        terminal_attempted = False

        def provider_chunks() -> Iterable[ProviderChunk]:
            """Map provider cancellation while the lazy stream is consumed.

            在消费惰性数据流时映射提供方取消结果。
            """

            try:
                yield from self._with_first(first, chunks)
            except ProviderInvocationCancelled as exc:
                raise RequestCancelled("provider invocation was cancelled during streaming") from exc

        try:
            for chunk in provider_chunks():
                if cancel_event.is_set():
                    raise RequestCancelled("request was cancelled during streaming")
                finish_reason = chunk.finish_reason
                emitted_finish = emitted_finish or finish_reason is not None
                saw_tool_calls = saw_tool_calls or bool(chunk.tool_calls)
                usage = self._merge_usage(usage, chunk.observed_usage())
                delta: dict[str, Any] = {}
                if chunk.role is not None:
                    delta["role"] = chunk.role
                if chunk.delta:
                    delta["content"] = chunk.delta
                if chunk.tool_calls:
                    delta["tool_calls"] = [call.to_openai_delta() for call in chunk.tool_calls]
                event: dict[str, Any] = {
                    "id": request_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": (
                        []
                        if not delta and finish_reason is None
                        else [{"index": 0, "delta": delta, "finish_reason": finish_reason}]
                    ),
                }
                if include_usage and usage is not None:
                    serialized_usage = usage.to_openai_dict()
                    if serialized_usage:
                        event["usage"] = serialized_usage
                        usage_emitted = True
                yield event
            if cancel_event.is_set():
                raise RequestCancelled("request was cancelled after streaming")
            if not emitted_finish:
                yield {
                    "id": request_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {},
                            "finish_reason": "tool_calls" if saw_tool_calls else "stop",
                        }
                    ],
                }
            if include_usage and usage is not None and not usage_emitted:
                serialized_usage = usage.to_openai_dict()
                if serialized_usage:
                    yield {
                        "id": request_id,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [],
                        "usage": serialized_usage,
                    }
            terminal_status = "completed"
            # The client may stop reading at DONE. Commit the terminal audit
            # before publishing it; a failed commit must close without DONE.
            # 客户端可能在 DONE 后停止读取，因此必须先提交终态审计。
            terminal_attempted = True
            self._observe_finished(metadata, status="completed", usage=usage, error_type=None)
            yield "[DONE]"
        except RequestCancelled:
            terminal_status = "cancelled"
            terminal_error = RequestCancelled.error_type
            raise
        except Exception as exc:
            terminal_status = "cancelled" if cancel_event.is_set() else "failed"
            terminal_error = RequestCancelled.error_type if cancel_event.is_set() else self._audit_error_type(exc)
            raise
        finally:
            if terminal_status is None:
                terminal_status = "cancelled" if cancel_event.is_set() else "failed"
                terminal_error = RequestCancelled.error_type if cancel_event.is_set() else "stream_closed"
            if not terminal_attempted:
                self._observe_finished(
                    metadata,
                    status=terminal_status,
                    usage=usage,
                    error_type=terminal_error,
                )

    @staticmethod
    def _merge_usage(
        current: ProviderUsage | None,
        observed: ProviderUsage | None,
    ) -> ProviderUsage | None:
        """Merge provider-reported usage facts without estimating missing data.

        合并提供方报告的用量事实,不估算缺失数据。
        """

        if observed is None:
            return current
        if current is None:
            return observed
        return ProviderUsage(
            prompt_tokens=(observed.prompt_tokens if observed.prompt_tokens is not None else current.prompt_tokens),
            completion_tokens=(
                observed.completion_tokens if observed.completion_tokens is not None else current.completion_tokens
            ),
            total_tokens=(observed.total_tokens if observed.total_tokens is not None else current.total_tokens),
            source=observed.source,
        )

    @classmethod
    def _merge_chunk_usage(cls, chunks: Iterable[ProviderChunk]) -> ProviderUsage | None:
        """Collect the last known exact usage components from provider chunks.

        从提供方数据块中收集最近一次已知的精确用量分项。
        """

        usage: ProviderUsage | None = None
        for chunk in chunks:
            usage = cls._merge_usage(usage, chunk.observed_usage())
        return usage

    @staticmethod
    def _assemble_message(chunks: Iterable[ProviderChunk]) -> dict[str, Any]:
        """Assemble text and indexed tool-call fragments into one assistant message.

        将文本和带索引的工具调用片段组装成一条 assistant 消息。
        """

        content = "".join(chunk.delta for chunk in chunks)
        role = next((chunk.role for chunk in chunks if chunk.role is not None), "assistant")
        accumulators: dict[int, _ToolCallAccumulator] = {}
        for chunk in chunks:
            for call in chunk.tool_calls:
                accumulator = accumulators.setdefault(call.index, _ToolCallAccumulator(call.index))
                accumulator.merge(call)

        message: dict[str, Any] = {
            "role": role,
            "content": content if content or not accumulators else None,
        }
        if accumulators:
            message["tool_calls"] = [accumulators[index].to_openai_message() for index in sorted(accumulators)]
        return message

    @staticmethod
    def _with_first(first: ProviderChunk, rest: Iterable[ProviderChunk]) -> Iterable[ProviderChunk]:
        yield first
        yield from rest
