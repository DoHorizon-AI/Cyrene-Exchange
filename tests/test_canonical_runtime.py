###############################################################################
# 📄 File: tests/test_canonical_runtime.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; runtime behavior is unchanged.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；运行时行为保持不变。
###############################################################################
from __future__ import annotations

import http.client
import inspect
import json
import threading
from collections.abc import Iterable
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from cyrene_exchange.capabilities import (
    MODEL_PROVIDER_CAPABILITY,
    MODEL_ROUTING_CAPABILITY,
    ProviderChunk,
    ProviderInvocationCancelled,
    ProviderUsage,
    RouteTarget,
    ToolCallDelta,
)
from cyrene_exchange.gateway import (
    AuthenticationError,
    ExchangeGateway,
    InvalidRequestError,
    RequestCancelled,
    RequestPrincipal,
)
from cyrene_exchange.http import create_reference_server
from cyrene_exchange.protocol import NormalizedInferenceRequest


HEADERS = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
TEST_PRINCIPAL = RequestPrincipal("actor-test", "workspace-test", "credential-test")


def resolve_test_principal(token: str) -> RequestPrincipal | None:
    """Resolve only the explicit test credential to a trusted identity."""

    return TEST_PRINCIPAL if token == "test-token" else None


class FakeRouter:
    def __init__(self, targets: list[RouteTarget]):
        self.targets = targets
        self.requests = []

    def plan(self, request):
        self.requests.append(request)
        return self.targets


class FakeProvider:
    def __init__(self, chunks: Iterable[ProviderChunk] | None = None, error: Exception | None = None):
        self.chunks = list(chunks or [])
        self.error = error
        self.requests = []
        self.cancel_events: list[Event] = []

    def complete(self, request, *, cancel_event: Event):
        self.requests.append(request)
        self.cancel_events.append(cancel_event)
        if self.error:
            raise self.error
        yield from self.chunks


class FailingAfterFirstProvider(FakeProvider):
    def complete(self, request, *, cancel_event: Event):
        self.requests.append(request)
        self.cancel_events.append(cancel_event)
        yield ProviderChunk(delta="partial")
        raise RuntimeError("stream disconnected upstream")


class CancellingAfterFirstProvider(FakeProvider):
    def complete(self, request, *, cancel_event: Event):
        self.requests.append(request)
        self.cancel_events.append(cancel_event)
        yield ProviderChunk(delta="partial")
        raise ProviderInvocationCancelled("provider stream cancelled")


class Resolver:
    def __init__(self, router, providers):
        self.router = router
        self.providers = providers
        self.calls: list[tuple[str, str | None]] = []

    def resolve(self, capability_id: str, implementation_ref: str | None = None):
        self.calls.append((capability_id, implementation_ref))
        if capability_id == MODEL_ROUTING_CAPABILITY:
            return self.router
        if capability_id == MODEL_PROVIDER_CAPABILITY:
            return self.providers[implementation_ref]
        raise AssertionError(f"unexpected capability {capability_id}")


def payload(*, stream: bool = False) -> dict[str, Any]:
    return {
        "model": "requested-model",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": stream,
    }


def tool_payload(*, stream: bool = False, include_usage: bool = False) -> dict[str, Any]:
    """Build a text-only request with one function tool and tool history."""

    value: dict[str, Any] = {
        "model": "requested-model",
        "messages": [
            {"role": "user", "content": "look up the weather"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_previous",
                        "type": "function",
                        "function": {"name": "weather", "arguments": '{"city":"Paris"}'},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_previous",
                "content": "20C",
            },
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "weather",
                    "description": "Get current weather",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"],
                    },
                },
            }
        ],
        "tool_choice": {"type": "function", "function": {"name": "weather"}},
        "parallel_tool_calls": False,
        "stream": stream,
    }
    if include_usage:
        value["stream_options"] = {"include_usage": True}
    return value


def make_gateway(router, providers):
    return ExchangeGateway(
        Resolver(router, providers),
        principal_resolver=resolve_test_principal,
    )


def http_json_request(gateway, request_payload, headers=HEADERS):
    server = create_reference_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("POST", "/v1/chat/completions", json.dumps(request_payload), headers)
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        return response.status, body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def http_stream_request(gateway, request_payload, headers=HEADERS):
    """Send one real HTTP request and return its status, headers, and SSE body."""

    server = create_reference_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("POST", "/v1/chat/completions", json.dumps(request_payload), headers)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        content_type = response.getheader("Content-Type")
        connection.close()
        return response.status, content_type, body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_request_uses_platform_resolver_routing_provider_and_normalizes_response():
    router = FakeRouter([RouteTarget("provider-a", route_id="primary")])
    provider = FakeProvider([ProviderChunk(delta="hello "), ProviderChunk(delta="world", finish_reason="stop")])
    resolver = Resolver(router, {"provider-a": provider})
    gateway = ExchangeGateway(resolver, principal_resolver=resolve_test_principal)
    server = create_reference_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("POST", "/v1/chat/completions", json.dumps(payload()), HEADERS)
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status == 200
    assert body["choices"][0]["message"]["content"] == "hello world"
    assert "usage" not in body
    assert resolver.calls == [(MODEL_ROUTING_CAPABILITY, None), (MODEL_PROVIDER_CAPABILITY, "provider-a")]
    assert router.requests[0].model == "requested-model"
    assert provider.requests[0].messages[0]["content"] == "hello"


def test_normalized_request_preserves_tool_metadata_and_tool_results():
    request = NormalizedInferenceRequest.from_openai(tool_payload(stream=True, include_usage=True))

    assert request.tools[0]["function"]["name"] == "weather"
    assert request.tool_choice == {"type": "function", "function": {"name": "weather"}}
    assert request.parallel_tool_calls is False
    assert request.stream_options == {"include_usage": True}
    assert request.messages[1]["tool_calls"][0]["function"]["arguments"] == '{"city":"Paris"}'
    assert request.messages[2]["tool_call_id"] == "call_previous"
    assert request.to_provider_dict()["tools"] == list(request.tools)


def test_http_non_stream_reassembles_tool_call_fragments_and_real_usage():
    router = FakeRouter([RouteTarget("provider-a", route_id="primary")])
    provider = FakeProvider(
        [
            ProviderChunk(
                tool_calls=(
                    ToolCallDelta(
                        index=0,
                        id="call_weather",
                        type="function",
                        function_name="weather",
                        function_arguments='{"city":',
                    ),
                )
            ),
            ProviderChunk(
                tool_calls=(ToolCallDelta(index=0, function_arguments='"Paris"}'),),
                finish_reason="tool_calls",
                usage=ProviderUsage(prompt_tokens=8, completion_tokens=5, source="upstream"),
            ),
        ]
    )
    gateway = make_gateway(router, {"provider-a": provider})

    status, body = http_json_request(gateway, tool_payload())

    assert status == 200
    assert body["choices"][0]["message"] == {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_weather",
                "type": "function",
                "function": {"name": "weather", "arguments": '{"city":"Paris"}'},
            }
        ],
    }
    assert body["choices"][0]["finish_reason"] == "tool_calls"
    assert body["usage"] == {"prompt_tokens": 8, "completion_tokens": 5, "total_tokens": 13}


def test_http_sse_preserves_tool_call_fragments_and_usage_event():
    router = FakeRouter([RouteTarget("provider-a", route_id="primary")])
    provider = FakeProvider(
        [
            ProviderChunk(
                role="assistant",
                tool_calls=(
                    ToolCallDelta(
                        index=0,
                        id="call_weather",
                        type="function",
                        function_name="weather",
                        function_arguments='{"city":',
                    ),
                ),
            ),
            ProviderChunk(
                tool_calls=(ToolCallDelta(index=0, function_arguments='"Paris"}'),),
                finish_reason="tool_calls",
                usage=ProviderUsage(prompt_tokens=8, completion_tokens=5),
            ),
        ]
    )
    gateway = make_gateway(router, {"provider-a": provider})

    status, content_type, body = http_stream_request(
        gateway,
        tool_payload(stream=True, include_usage=True),
    )

    assert status == 200
    assert content_type == "text/event-stream"
    assert '"tool_calls":[{"index":0,"id":"call_weather","type":"function"' in body
    assert '"arguments":"{\\"city\\":"' in body
    assert '"arguments":"\\"Paris\\"}"' in body
    assert '"finish_reason":"tool_calls"' in body
    assert '"usage":{"prompt_tokens":8,"completion_tokens":5,"total_tokens":13}' in body
    assert body.rstrip().endswith("data: [DONE]")


def test_http_sse_streaming_normalizes_provider_chunks():
    router = FakeRouter([RouteTarget("provider-a", route_id="primary")])
    provider = FakeProvider([ProviderChunk(delta="one"), ProviderChunk(delta="two")])
    gateway = make_gateway(router, {"provider-a": provider})
    server = create_reference_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("POST", "/v1/chat/completions", json.dumps(payload(stream=True)), HEADERS)
        response = connection.getresponse()
        text = response.read().decode("utf-8")
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status == 200
    assert response.getheader("Content-Type") == "text/event-stream"
    assert '"content":"one"' in text
    assert '"content":"two"' in text
    assert '"finish_reason":"stop"' in text
    assert text.rstrip().endswith("data: [DONE]")


def test_invalid_auth_and_invalid_request_are_product_errors():
    router = FakeRouter([])
    gateway = make_gateway(router, {})
    with pytest.raises(AuthenticationError):
        gateway.handle_openai_chat({}, payload())
    with pytest.raises(InvalidRequestError):
        gateway.handle_openai_chat(HEADERS, {"model": "x", "messages": []})
    assert router.requests == []


def test_http_maps_invalid_auth_and_invalid_request_without_resolving_capabilities():
    router = FakeRouter([])
    resolver = Resolver(router, {})
    gateway = ExchangeGateway(resolver, principal_resolver=resolve_test_principal)

    auth_status, auth_body = http_json_request(gateway, payload(), headers={})
    request_status, request_body = http_json_request(
        gateway,
        {"model": "requested-model", "messages": []},
    )

    assert auth_status == 401
    assert auth_body["error"]["type"] == "authentication_error"
    assert request_status == 400
    assert request_body["error"]["type"] == "invalid_request_error"
    assert resolver.calls == []


def test_provider_failure_before_first_token_uses_routing_candidates_in_order():
    router = FakeRouter([RouteTarget("down", route_id="primary"), RouteTarget("healthy", route_id="fallback")])
    down = FakeProvider(error=RuntimeError("connection refused"))
    healthy = FakeProvider([ProviderChunk(delta="fallback response", finish_reason="stop")])
    resolver = Resolver(router, {"down": down, "healthy": healthy})
    gateway = ExchangeGateway(resolver, principal_resolver=resolve_test_principal)

    response = gateway.handle_openai_chat(HEADERS, payload())

    assert response.body["choices"][0]["message"]["content"] == "fallback response"
    assert response.route_id == "fallback"
    assert resolver.calls == [
        (MODEL_ROUTING_CAPABILITY, None),
        (MODEL_PROVIDER_CAPABILITY, "down"),
        (MODEL_PROVIDER_CAPABILITY, "healthy"),
    ]


def test_provider_cancellation_never_falls_back_to_another_route():
    router = FakeRouter([RouteTarget("cancelled"), RouteTarget("healthy")])
    cancelled = FakeProvider(error=ProviderInvocationCancelled("execution cancelled"))
    healthy = FakeProvider([ProviderChunk(delta="must not run")])
    resolver = Resolver(router, {"cancelled": cancelled, "healthy": healthy})
    gateway = ExchangeGateway(resolver, principal_resolver=resolve_test_principal)

    with pytest.raises(RequestCancelled):
        gateway.handle_openai_chat(HEADERS, payload())

    assert healthy.requests == []
    assert resolver.calls == [
        (MODEL_ROUTING_CAPABILITY, None),
        (MODEL_PROVIDER_CAPABILITY, "cancelled"),
    ]


def test_provider_failure_after_first_stream_token_is_not_double_routed():
    router = FakeRouter([RouteTarget("partial", route_id="primary"), RouteTarget("healthy", route_id="fallback")])
    partial = FailingAfterFirstProvider()
    healthy = FakeProvider([ProviderChunk(delta="fallback")])
    resolver = Resolver(router, {"partial": partial, "healthy": healthy})
    gateway = ExchangeGateway(resolver, principal_resolver=resolve_test_principal)

    response = gateway.handle_openai_chat(HEADERS, payload(stream=True))
    events = iter(response.body)
    assert json.loads(json.dumps(next(events)))["choices"][0]["delta"]["content"] == "partial"
    with pytest.raises(RuntimeError, match="stream disconnected"):
        next(events)
    assert resolver.calls == [
        (MODEL_ROUTING_CAPABILITY, None),
        (MODEL_PROVIDER_CAPABILITY, "partial"),
    ]


def test_provider_cancellation_after_first_stream_token_maps_to_request_cancelled():
    router = FakeRouter([RouteTarget("cancelled", route_id="primary"), RouteTarget("healthy")])
    cancelled = CancellingAfterFirstProvider()
    healthy = FakeProvider([ProviderChunk(delta="must not run")])
    gateway = ExchangeGateway(
        Resolver(router, {"cancelled": cancelled, "healthy": healthy}),
        principal_resolver=resolve_test_principal,
    )

    response = gateway.handle_openai_chat(HEADERS, payload(stream=True))
    events = iter(response.body)
    first = next(events)
    assert first["choices"][0]["delta"]["content"] == "partial"
    with pytest.raises(RequestCancelled, match="provider invocation was cancelled during streaming"):
        next(events)
    assert healthy.requests == []


def test_cancellation_is_propagated_to_provider_and_product_does_not_claim_success():
    router = FakeRouter([RouteTarget("provider-a")])
    provider = FakeProvider([ProviderChunk(delta="first"), ProviderChunk(delta="second")])
    gateway = make_gateway(router, {"provider-a": provider})
    cancel_event = Event()
    response = gateway.handle_openai_chat(HEADERS, payload(stream=True), cancel_event=cancel_event)
    events = iter(response.body)
    next(events)
    cancel_event.set()
    with pytest.raises(RequestCancelled):
        next(events)
    assert provider.cancel_events == [cancel_event]


def test_product_core_has_no_concrete_plugin_or_legacy_control_plane_dependency():
    package_root = Path(__file__).parents[1] / "src" / "cyrene_exchange"
    source = "\n".join(path.read_text(encoding="utf-8") for path in package_root.glob("*.py"))
    assert "plugins." not in source
    assert "cyrene_exchange.legacy" not in source
    assert "cy_control_plane" not in source
    assert "cyrene-core-compat" not in source
    assert "self._resolver.resolve" in inspect.getsource(ExchangeGateway)
