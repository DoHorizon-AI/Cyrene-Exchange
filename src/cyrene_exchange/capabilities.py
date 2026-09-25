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

中文:Exchange 使用的最小实验性能力接口。

中文:这些协议只描述首个纵向切片所需的行为,是 Product 消费方接口,不替代 Platform 的规范能力契约。
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

    中文:一个采用 OpenAI 兼容结构的提供方工具调用片段。

        中文:``function_arguments`` 特意保留为片段。提供方通常会把 JSON 参数拆分到多个流式数据块中,因此 Exchange 会保留顺序和提供方给出的调用索引,而不解析或重新序列化参数。
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
        """Return the exact structured delta expected by the HTTP gateway.

        中文:返回 HTTP Gateway 所需的精确结构化增量。"""

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

    中文:上游提供方报告的精确 token 事实。

        中文:Exchange 不会根据文本估算 token 数。只有两个组成计数都来自提供方事实时,才可以推导 ``total_tokens``;部分报告在公开响应中仍保持部分状态。
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
        """Serialize observed usage without fabricating missing components.

        中文:序列化观测到的用量,不虚构缺失的组成项。"""

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

    中文:由 ``model.routing.v1`` 返回的候选项。

        中文:``provider_ref`` 对 Exchange 是不透明值。它会原样交给 Platform resolver,不会被解释为 Python 模块或插件路径。
    """

    provider_ref: str
    route_id: str = ""
    model: str | None = None


@dataclass(frozen=True)
class ProviderChunk:
    """Provider-neutral output used by the Product normalization layer.

    中文:Product 规范化层使用的提供方无关输出。"""

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
        """Return the provider's explicit usage report, when present.

        中文:若提供方明确报告了用量,则返回该报告。"""

        return self.usage


class ProviderInvocationCancelled(RuntimeError):
    """A provider execution ended with canonical cancellation semantics.

    中文:一次提供方执行按规范取消语义结束。"""


class ModelRoutingCapability(Protocol):
    """Reusable route candidate selection supplied by ``model.routing.v1``.

    中文:由 ``model.routing.v1`` 提供的可复用路由候选选择器。"""

    def plan(self, request: NormalizedInferenceRequest) -> Sequence[RouteTarget]:
        """Return candidates in the order selected by the routing algorithm.

        中文:按路由算法选定的顺序返回候选项。"""


class ModelProviderCapability(Protocol):
    """Provider execution supplied by ``model.provider.v1``.

    中文:由 ``model.provider.v1`` 提供的提供方执行能力。"""

    def complete(
        self,
        request: NormalizedInferenceRequest,
        *,
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        """Yield provider-neutral chunks and observe the cancellation event.

        中文:产出提供方无关的数据块,并观察取消事件。"""


class CapabilityResolver(Protocol):
    """Platform resolver seam used by the Exchange Product Core.

    中文:Exchange Product Core 使用的 Platform resolver 接口。"""

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        """Resolve a capability implementation without exposing plugin packages.

        中文:解析能力实现,但不暴露插件软件包。"""
