"""Unit tests for Exchange's direct Plugin model-provider adapter.

Exchange 直连 Plugin 模型提供方适配器的单元测试。
"""

from __future__ import annotations

from threading import Event

import grpc
import pytest

from cyrene_model_provider_contracts import (
    CHAT_COMPLETION_REQUEST_TYPE_URL,
    CHAT_COMPLETION_RESPONSE_TYPE_URL,
    CHAT_COMPLETION_V2_INTERFACE_VERSION,
    CHAT_COMPLETION_V2_METHOD,
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
    decode_chat_completion_request,
    decode_chat_completion_request_v2,
    encode_chat_completion_response,
)
from cyrene_plugin_runtime import (
    DirectPayload,
    DirectPluginFailure,
    DirectPluginInvocationCancelled,
)
from cyrene_exchange.capabilities import ProviderInvocationCancelled, ProviderUsage
from cyrene_exchange.direct_plugin import (
    DirectPluginModelProvider,
    ModelProviderExecutionError,
)
from cyrene_exchange.protocol import NormalizedInferenceRequest


class RecordingInvoker:
    """Record one typed invocation and return a configurable response.

    中文:记录一次类型化调用,并返回可配置的响应。
    """
    # 中文:记录一次有类型的调用,并返回可配置的响应。

    def __init__(self, response: DirectPayload) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []
        self.error: Exception | None = None

    def invoke(self, **arguments: object) -> DirectPayload:
        self.calls.append(arguments)
        if self.error is not None:
            raise self.error
        return self.response

    def invoke_stream(self, **arguments: object):
        self.calls.append(arguments)
        if self.error is not None:
            raise self.error
        yield self.response


def response_payload(*chunks: ChatCompletionChunk) -> DirectPayload:
    response = ChatCompletionResponse(chunks=tuple(chunks))
    return DirectPayload(
        CHAT_COMPLETION_RESPONSE_TYPE_URL,
        encode_chat_completion_response(response),
    )


def normalized_request(**overrides: object) -> NormalizedInferenceRequest:
    values: dict[str, object] = {
        "model": "requested-model",
        "messages": (
            {
                "role": "user",
                "content": "hello",
                "name": "operator",
            },
        ),
        "stream": False,
        "temperature": 0.0,
        "max_tokens": 32,
    }
    values.update(overrides)
    return NormalizedInferenceRequest(**values)


def test_provider_calls_direct_endpoint_with_canonical_typed_payload():
    invoker = RecordingInvoker(
        response_payload(
            ChatCompletionChunk(delta="real "),
            ChatCompletionChunk(
                delta="path",
                finish_reason="stop",
                prompt_tokens=1,
                completion_tokens=2,
            ),
        )
    )
    provider = DirectPluginModelProvider(invoker, deadline_seconds=7.5)
    cancellation = Event()

    chunks = tuple(provider.complete(normalized_request(), cancel_event=cancellation))

    assert [chunk.delta for chunk in chunks] == ["real ", "path"]
    assert chunks[-1].finish_reason == "stop"
    assert chunks[-1].usage == ProviderUsage(prompt_tokens=1, completion_tokens=2)
    assert len(invoker.calls) == 1
    call = invoker.calls[0]
    assert call["capability"] == "model.provider.v1"
    assert call["interface_version"] == "1"
    assert call["method"] == "chat_completion"
    assert "binding_id" not in call
    assert call["deadline_seconds"] == 7.5
    assert call["cancel_event"] is cancellation
    typed = call["request"]
    assert isinstance(typed, DirectPayload)
    assert typed.type_url == CHAT_COMPLETION_REQUEST_TYPE_URL
    request = decode_chat_completion_request(typed.value)
    assert request.messages[0].role == request.messages[0].role.ROLE_USER
    assert request.messages[0].content == "hello"
    assert request.messages[0].name == "operator"
    assert request.temperature == 0.0
    assert request.max_tokens == 32


def test_provider_rejects_unrepresented_message_shape_before_dispatch():
    invoker = RecordingInvoker(response_payload(ChatCompletionChunk(delta="unused")))
    provider = DirectPluginModelProvider(invoker)
    request = normalized_request(
        messages=(
            {
                "role": "user",
                "content": [{"type": "text", "text": "multimodal"}],
            },
        )
    )

    with pytest.raises(ModelProviderExecutionError, match="content must be text"):
        tuple(provider.complete(request, cancel_event=Event()))

    assert invoker.calls == []


def test_provider_negotiates_v2_when_exchange_request_contains_tool_metadata():
    invoker = RecordingInvoker(response_payload(ChatCompletionChunk(delta="unused")))
    provider = DirectPluginModelProvider(invoker)
    request = normalized_request(
        tools=(
            {
                "type": "function",
                "function": {"name": "weather", "parameters": {"type": "object"}},
            },
        ),
        tool_choice="auto",
    )

    chunks = tuple(provider.complete(request, cancel_event=Event()))

    assert chunks[0].delta == "unused"
    assert len(invoker.calls) == 1
    call = invoker.calls[0]
    assert call["interface_version"] == CHAT_COMPLETION_V2_INTERFACE_VERSION
    assert call["method"] == CHAT_COMPLETION_V2_METHOD
    typed = call["request"]
    assert isinstance(typed, DirectPayload)
    decoded = decode_chat_completion_request_v2(typed.value)
    assert decoded.tools[0].function.name == "weather"
    assert decoded.tool_choice is not None
    assert decoded.tool_choice.mode == "auto"


def test_provider_preserves_plugin_failure_and_rejects_wrong_response_type():
    invoker = RecordingInvoker(DirectPayload("type.googleapis.com/example.Wrong", b""))
    provider = DirectPluginModelProvider(invoker)

    with pytest.raises(ModelProviderExecutionError, match="unexpected payload type"):
        tuple(provider.complete(normalized_request(), cancel_event=Event()))

    invoker.error = DirectPluginFailure(5, "plugin failed")
    with pytest.raises(ModelProviderExecutionError, match="plugin failed"):
        tuple(provider.complete(normalized_request(), cancel_event=Event()))


def test_provider_rejects_empty_typed_response():
    invoker = RecordingInvoker(response_payload())
    provider = DirectPluginModelProvider(invoker)

    with pytest.raises(ModelProviderExecutionError, match="no chat-completion chunks"):
        tuple(provider.complete(normalized_request(), cancel_event=Event()))


@pytest.mark.parametrize(
    "error",
    [
        DirectPluginInvocationCancelled(grpc.StatusCode.CANCELLED, "caller cancelled"),
        DirectPluginFailure(3, "plugin cancelled"),
    ],
)
def test_provider_preserves_canonical_cancellation(error):
    invoker = RecordingInvoker(response_payload(ChatCompletionChunk(delta="unused")))
    invoker.error = error
    provider = DirectPluginModelProvider(invoker)

    with pytest.raises(ProviderInvocationCancelled):
        tuple(provider.complete(normalized_request(), cancel_event=Event()))
