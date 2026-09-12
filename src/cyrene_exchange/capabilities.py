###############################################################################
# 📄 File: src/cyrene_exchange/capabilities.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; provider chunks preserve tool and usage facts.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；provider chunk 保留工具调用与 usage 事实。
###############################################################################
"""Minimal experimental capability seams consumed by Exchange.

These protocols describe only the behavior needed by the first vertical
slice.  They are Product-consumer seams, not a replacement for the canonical
Platform capability contracts.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from threading import Event
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .protocol import NormalizedInferenceRequest


MODEL_ROUTING_CAPABILITY = "model.routing.v1"
MODEL_PROVIDER_CAPABILITY = "model.provider.v1"


@dataclass(frozen=True)
class ToolCallDelta:
    """One provider tool-call fragment in OpenAI-compatible shape.

    ``function_arguments`` is intentionally a fragment. Providers commonly
    split JSON arguments over several streamed chunks, so Exchange preserves
    ordering and the provider-supplied call index instead of parsing or
    reserializing the arguments.
    """

    index: int
    id: str | None = None
    type: str | None = None
    function_name: str | None = None
    function_arguments: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise ValueError("tool call index must be a non-negative integer")
        for field_name in ("id", "type", "function_name", "function_arguments"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"tool call {field_name} must be text when provided")

    def to_openai_delta(self) -> dict[str, Any]:
        """Return the exact structured delta expected by the HTTP gateway."""

        function: dict[str, str] = {}
        if self.function_name is not None:
            function["name"] = self.function_name
        if self.function_arguments is not None:
            function["arguments"] = self.function_arguments
        value: dict[str, Any] = {"index": self.index}
        if self.id is not None:
            value["id"] = self.id
        if self.type is not None:
            value["type"] = self.type
        if function:
            value["function"] = function
        return value


@dataclass(frozen=True)
class ProviderUsage:
    """Exact token facts reported by the upstream provider.

    Exchange never estimates token counts from text. ``total_tokens`` may be
    derived only when both component counts are provider facts; a partial
    report remains partial in the public response.
    """

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    source: str = "provider"

    def __post_init__(self) -> None:
        for field_name in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = getattr(self, field_name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"usage {field_name} must be a non-negative integer")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("usage source must be a non-empty string")

    def to_openai_dict(self) -> dict[str, int]:
        """Serialize observed usage without fabricating missing components."""

        result: dict[str, int] = {}
        if self.prompt_tokens is not None:
            result["prompt_tokens"] = self.prompt_tokens
        if self.completion_tokens is not None:
            result["completion_tokens"] = self.completion_tokens
        total_tokens = self.total_tokens
        if total_tokens is None and self.prompt_tokens is not None and self.completion_tokens is not None:
            total_tokens = self.prompt_tokens + self.completion_tokens
        if total_tokens is not None:
            result["total_tokens"] = total_tokens
        return result


@dataclass(frozen=True)
class RouteTarget:
    """A candidate returned by ``model.routing.v1``.

    ``provider_ref`` is opaque to Exchange.  It is passed back to the Platform
    resolver and never interpreted as a Python module or plugin path.
    """

    provider_ref: str
    route_id: str = ""
    model: str | None = None


@dataclass(frozen=True)
class ProviderChunk:
    """Provider-neutral output used by the Product normalization layer."""

    delta: str = ""
    finish_reason: str | None = None
    role: str | None = None
    tool_calls: tuple[ToolCallDelta, ...] = ()
    usage: ProviderUsage | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.delta, str):
            raise TypeError("provider delta must be text")
        if self.role is not None and not isinstance(self.role, str):
            raise TypeError("provider role must be text when provided")
        if not isinstance(self.tool_calls, tuple):
            raise TypeError("provider tool_calls must be a tuple")
        if any(not isinstance(call, ToolCallDelta) for call in self.tool_calls):
            raise TypeError("provider tool_calls must contain ToolCallDelta values")
        if self.usage is not None and not isinstance(self.usage, ProviderUsage):
            raise TypeError("provider usage must be ProviderUsage")

    def observed_usage(self) -> ProviderUsage | None:
        """Return the provider's explicit usage report, when present."""

        return self.usage


class ProviderInvocationCancelled(RuntimeError):
    """A provider execution ended with canonical cancellation semantics."""


class ModelRoutingCapability(Protocol):
    """Reusable route candidate selection supplied by ``model.routing.v1``."""

    def plan(self, request: NormalizedInferenceRequest) -> Sequence[RouteTarget]:
        """Return candidates in the order selected by the routing algorithm."""


class ModelProviderCapability(Protocol):
    """Provider execution supplied by ``model.provider.v1``."""

    def complete(
        self,
        request: NormalizedInferenceRequest,
        *,
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        """Yield provider-neutral chunks and observe the cancellation event."""


class CapabilityResolver(Protocol):
    """Platform resolver seam used by the Exchange Product Core."""

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        """Resolve a capability implementation without exposing plugin packages."""
