"""Exchange adapter for direct Plugins-owned model-provider execution.

This module projects Product-owned normalized chat intent into the Plugins-owned
``model.provider.v1`` contract and calls one already-resolved Plugin endpoint.
It owns no plugin selection, process lifecycle, retry policy, or Platform data
plane.

本模块把 Product 自有的标准化聊天意图投影为 Plugins 所有的
``model.provider.v1`` 契约，并直连一个已解析的 Plugin 端点。它不拥有插件选择、
进程生命周期、重试策略或 Platform 数据面。
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import json
from threading import Event
from typing import Protocol

from cyrene_model_provider_contracts import (
    CAPABILITY_ID,
    CHAT_COMPLETION_CHUNK_TYPE_URL,
    CHAT_COMPLETION_METHOD,
    CHAT_COMPLETION_REQUEST_TYPE_URL,
    CHAT_COMPLETION_RESPONSE_TYPE_URL,
    CHAT_COMPLETION_V2_INTERFACE_VERSION,
    CHAT_COMPLETION_V2_METHOD,
    INTERFACE_VERSION,
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatFunction,
    ChatMessage,
    ChatRole,
    ChatTool,
    ChatToolCall,
    ChatToolCallDelta,
    ChatToolCallFunction,
    ChatToolChoice,
    decode_chat_completion_chunk,
    decode_chat_completion_chunk_v2,
    decode_chat_completion_response,
    decode_chat_completion_response_v2,
    encode_chat_completion_request,
    encode_chat_completion_request_v2,
)
from cyrene_plugin_runtime import (
    DirectPayload,
    DirectPluginClient,
    DirectPluginError,
    DirectPluginFailure,
    DirectPluginInvocationCancelled,
)

from .capabilities import ProviderChunk, ProviderInvocationCancelled, ProviderUsage
from .protocol import NormalizedInferenceRequest


_ROLE_VALUES = {
    "system": ChatRole.SYSTEM,
    "user": ChatRole.USER,
    "assistant": ChatRole.ASSISTANT,
    "tool": ChatRole.TOOL,
}
_MESSAGE_FIELDS = frozenset({"role", "content", "name", "tool_call_id", "tool_calls"})


class DirectPluginInvoker(Protocol):
    """Product-facing subset of the Plugins-owned direct endpoint client.

    面向 Product 的接口子集，底层客户端归 Plugins 所有并直接访问端点。
    """

    def invoke(
        self,
        *,
        capability: str,
        interface_version: str,
        method: str,
        request: DirectPayload,
        deadline_seconds: float | None = None,
        cancel_event: Event | None = None,
        request_id: str | None = None,
    ) -> DirectPayload:
        """Invoke one method on the already-selected Plugin endpoint.

        在已选定的 Plugin 端点上调用一个方法。
        """

    def invoke_stream(
        self,
        *,
        capability: str,
        interface_version: str,
        method: str,
        request: DirectPayload,
        deadline_seconds: float | None = None,
        cancel_event: Event | None = None,
        request_id: str | None = None,
    ) -> Iterable[DirectPayload]:
        """Yield ordered results from the selected Plugin endpoint.

        按顺序产出所选 Plugin 端点返回的结果。
        """


class ModelProviderExecutionError(RuntimeError):
    """The model-provider invocation or contract projection failed.

    模型提供方调用失败，或契约投影失败。
    """


class DirectPluginModelProvider:
    """Implement Exchange's provider seam through one direct Plugin client.

    通过单个 Direct Plugin 客户端实现 Exchange 的提供方接口。
    """

    def __init__(
        self,
        client: DirectPluginInvoker,
        *,
        deadline_seconds: float = 30.0,
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        self._client = client
        self._deadline_seconds = deadline_seconds

    def complete(
        self,
        request: NormalizedInferenceRequest,
        *,
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        """Invoke the negotiated chat method and return ordered provider chunks.

        调用协商后的 chat 方法，并按顺序返回提供方数据块。
        """

        typed_request = _to_chat_request(request)
        structured = _requires_structured_chat(request)
        if request.stream:
            return self._stream_chunks(
                typed_request,
                structured=structured,
                cancel_event=cancel_event,
            )
        try:
            response = self._client.invoke(
                capability=CAPABILITY_ID,
                interface_version=(CHAT_COMPLETION_V2_INTERFACE_VERSION if structured else INTERFACE_VERSION),
                method=(CHAT_COMPLETION_V2_METHOD if structured else CHAT_COMPLETION_METHOD),
                request=_pack_chat_request(typed_request, structured=structured),
                deadline_seconds=self._deadline_seconds,
                cancel_event=cancel_event,
            )
            decoded = _unpack_chat_response(response, structured=structured)
        except DirectPluginInvocationCancelled as error:
            raise ProviderInvocationCancelled(str(error)) from error
        except DirectPluginFailure as error:
            if error.is_cancelled:
                raise ProviderInvocationCancelled(str(error)) from error
            raise ModelProviderExecutionError(str(error)) from error
        except DirectPluginError as error:
            raise ModelProviderExecutionError(str(error)) from error

        chunks = tuple(_from_chat_chunk(chunk) for chunk in decoded.chunks)
        if not chunks:
            raise ModelProviderExecutionError("model.provider.v1 returned no chat-completion chunks")
        return chunks

    def _stream_chunks(
        self,
        typed_request: ChatCompletionRequest,
        *,
        structured: bool,
        cancel_event: Event,
    ) -> Iterable[ProviderChunk]:
        """Forward Plugin-owned typed chunks without local materialization.

        转发 Plugins 所有的类型化数据块，不在本地物化完整结果。
        """

        method = CHAT_COMPLETION_V2_METHOD if structured else CHAT_COMPLETION_METHOD
        interface_version = CHAT_COMPLETION_V2_INTERFACE_VERSION if structured else INTERFACE_VERSION

        def iter_chunks() -> Iterable[ProviderChunk]:
            saw_chunk = False
            try:
                payloads = self._client.invoke_stream(
                    capability=CAPABILITY_ID,
                    interface_version=interface_version,
                    method=method,
                    request=_pack_chat_request(typed_request, structured=structured),
                    deadline_seconds=self._deadline_seconds,
                    cancel_event=cancel_event,
                )
                for payload in payloads:
                    chunk = _unpack_chat_chunk(payload, structured=structured)
                    saw_chunk = True
                    yield _from_chat_chunk(chunk)
                if not saw_chunk:
                    raise ModelProviderExecutionError("model.provider.v1 returned no chat-completion stream chunks")
            except DirectPluginInvocationCancelled as error:
                raise ProviderInvocationCancelled(str(error)) from error
            except DirectPluginFailure as error:
                if error.is_cancelled:
                    raise ProviderInvocationCancelled(str(error)) from error
                raise ModelProviderExecutionError(str(error)) from error
            except DirectPluginError as error:
                raise ModelProviderExecutionError(str(error)) from error

        return iter_chunks()


def local_plugin_client(connection_ref: str) -> DirectPluginClient:
    """Create a loopback-only client for one Plugin connection reference.

    为一个 Plugin connection reference 创建仅允许 loopback 的客户端。
    """

    return DirectPluginClient.for_local_connection_ref(connection_ref)


def _pack_chat_request(request: ChatCompletionRequest, *, structured: bool) -> DirectPayload:
    encoded = encode_chat_completion_request_v2(request) if structured else encode_chat_completion_request(request)
    return DirectPayload(CHAT_COMPLETION_REQUEST_TYPE_URL, encoded)


def _unpack_chat_response(payload: DirectPayload, *, structured: bool):
    if payload.type_url != CHAT_COMPLETION_RESPONSE_TYPE_URL:
        raise ModelProviderExecutionError(f"unexpected payload type {payload.type_url!r}")
    return (
        decode_chat_completion_response_v2(payload.value)
        if structured
        else decode_chat_completion_response(payload.value)
    )


def _unpack_chat_chunk(payload: DirectPayload, *, structured: bool) -> ChatCompletionChunk:
    if payload.type_url != CHAT_COMPLETION_CHUNK_TYPE_URL:
        raise ModelProviderExecutionError(f"unexpected payload type {payload.type_url!r}")
    return decode_chat_completion_chunk_v2(payload.value) if structured else decode_chat_completion_chunk(payload.value)


def _to_chat_request(request: NormalizedInferenceRequest) -> ChatCompletionRequest:
    messages = tuple(_to_chat_message(index, item) for index, item in enumerate(request.messages))
    tools: list[ChatTool] = []
    for index, tool in enumerate(request.tools):
        if not isinstance(tool, Mapping):
            raise ModelProviderExecutionError(f"tools[{index}] must be an object")
        function = tool.get("function")
        if not isinstance(function, Mapping):
            raise ModelProviderExecutionError(f"tools[{index}].function must be an object")
        name = function.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ModelProviderExecutionError(f"tools[{index}].function.name is invalid")
        parameters = function.get("parameters", {})
        if not isinstance(parameters, Mapping):
            raise ModelProviderExecutionError(f"tools[{index}].function.parameters must be an object")
        description = function.get("description")
        if description is not None and not isinstance(description, str):
            raise ModelProviderExecutionError(f"tools[{index}].function.description must be text")
        strict = function.get("strict")
        if strict is not None and not isinstance(strict, bool):
            raise ModelProviderExecutionError(f"tools[{index}].function.strict must be boolean")
        tool_type = tool.get("type")
        if not isinstance(tool_type, str) or not tool_type:
            raise ModelProviderExecutionError(f"tools[{index}].type is invalid")
        tools.append(
            ChatTool(
                type=tool_type,
                function=ChatFunction(
                    name=name,
                    description=description,
                    parameters_json=json.dumps(parameters, ensure_ascii=False, separators=(",", ":")),
                    strict=strict,
                ),
            )
        )

    tool_choice: ChatToolChoice | None = None
    if request.tool_choice is not None:
        if isinstance(request.tool_choice, str):
            tool_choice = ChatToolChoice(mode=request.tool_choice)
        elif isinstance(request.tool_choice, Mapping):
            function = request.tool_choice.get("function")
            if not isinstance(function, Mapping) or not isinstance(function.get("name"), str):
                raise ModelProviderExecutionError("tool_choice.function.name is invalid")
            tool_choice = ChatToolChoice(mode="function", function_name=function["name"])
        else:
            raise ModelProviderExecutionError("tool_choice is invalid")

    return ChatCompletionRequest(
        messages=messages,
        model=request.model,
        stream=request.stream,
        temperature=request.temperature,
        max_tokens=request.max_tokens,
        tools=tuple(tools),
        tool_choice=tool_choice,
        parallel_tool_calls=request.parallel_tool_calls,
        include_usage=(
            bool(request.stream_options.get("include_usage", False)) if request.stream_options is not None else None
        ),
    )


def _requires_structured_chat(request: NormalizedInferenceRequest) -> bool:
    """Select v2 only when the request contains fields absent from v1.

    仅当请求包含 v1 不具备的字段时才选择 v2。
    """

    return bool(
        request.tools
        or request.tool_choice is not None
        or request.parallel_tool_calls is not None
        or request.stream_options is not None
        or any("tool_calls" in message for message in request.messages)
    )


def _to_chat_message(index: int, message: Mapping[str, object]) -> ChatMessage:
    unsupported = set(message) - _MESSAGE_FIELDS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ModelProviderExecutionError(f"messages[{index}] contains unsupported canonical fields: {names}")

    role = message.get("role")
    content = message.get("content")
    if not isinstance(role, str) or role not in _ROLE_VALUES:
        raise ModelProviderExecutionError(f"messages[{index}].role is invalid")
    if content is None:
        content = ""
    if not isinstance(content, str):
        raise ModelProviderExecutionError(f"messages[{index}].content must be text or null")

    values: dict[str, str | None] = {"name": None, "tool_call_id": None}
    for field in values:
        value = message.get(field)
        if value is not None and not isinstance(value, str):
            raise ModelProviderExecutionError(f"messages[{index}].{field} must be text when provided")
        values[field] = value

    tool_calls: list[ChatToolCall] = []
    raw_tool_calls = message.get("tool_calls")
    if raw_tool_calls is not None:
        if not isinstance(raw_tool_calls, (list, tuple)):
            raise ModelProviderExecutionError(f"messages[{index}].tool_calls must be an array")
        for call_index, raw_call in enumerate(raw_tool_calls):
            if not isinstance(raw_call, Mapping):
                raise ModelProviderExecutionError(f"messages[{index}].tool_calls[{call_index}] must be an object")
            call_id = raw_call.get("id")
            call_type = raw_call.get("type", "function")
            function = raw_call.get("function")
            if not isinstance(call_id, str) or not call_id.strip():
                raise ModelProviderExecutionError(f"messages[{index}].tool_calls[{call_index}].id is invalid")
            if not isinstance(call_type, str) or not call_type.strip():
                raise ModelProviderExecutionError(f"messages[{index}].tool_calls[{call_index}].type is invalid")
            if not isinstance(function, Mapping):
                raise ModelProviderExecutionError(f"messages[{index}].tool_calls[{call_index}].function is invalid")
            name = function.get("name")
            arguments = function.get("arguments", "")
            if not isinstance(name, str) or not name.strip() or not isinstance(arguments, str):
                raise ModelProviderExecutionError(f"messages[{index}].tool_calls[{call_index}].function is invalid")
            tool_calls.append(
                ChatToolCall(
                    id=call_id,
                    type=call_type,
                    function=ChatToolCallFunction(name=name, arguments=arguments),
                )
            )
    return ChatMessage(
        role=_ROLE_VALUES[role],
        content=content,
        name=values["name"],
        tool_call_id=values["tool_call_id"],
        tool_calls=tuple(tool_calls),
    )


def _from_chat_chunk(chunk: ChatCompletionChunk) -> ProviderChunk:
    usage: ProviderUsage | None = None
    if any(value is not None for value in (chunk.prompt_tokens, chunk.completion_tokens, chunk.total_tokens)):
        usage = ProviderUsage(
            prompt_tokens=chunk.prompt_tokens,
            completion_tokens=chunk.completion_tokens,
            total_tokens=chunk.total_tokens,
        )
    return ProviderChunk(
        delta=chunk.delta,
        finish_reason=chunk.finish_reason,
        role=chunk.role,
        tool_calls=tuple(_from_tool_call_delta(call) for call in chunk.tool_calls),
        usage=usage,
    )


def _from_tool_call_delta(call: ChatToolCallDelta):
    """Project one Plugins-owned tool-call delta into Exchange facts.

    将一条 Plugins 所有的 tool-call 增量投影为 Exchange 事实。
    """

    from .capabilities import ToolCallDelta

    return ToolCallDelta(
        index=call.index,
        id=call.id,
        type=call.type,
        function_name=call.function_name,
        function_arguments=call.function_arguments,
    )


__all__ = [
    "DirectPluginInvoker",
    "DirectPluginModelProvider",
    "ModelProviderExecutionError",
    "local_plugin_client",
]
