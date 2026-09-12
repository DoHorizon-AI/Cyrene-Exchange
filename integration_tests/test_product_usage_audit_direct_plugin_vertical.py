"""
Prove Product usage/audit through Platform the direct Official Plugin.

验证 Product usage/audit 经 Platform resolver 与官方直连 Plugin 的真实路径。
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from http.client import HTTPConnection, HTTPResponse
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from uuid import UUID

from cyrene_exchange import ExchangeGateway, PlatformResolverAdapter
from cyrene_exchange.http import create_reference_server
from cyrene_exchange_product import ProductPrincipal, build_gateway_from_store, create_app
from cyrene_exchange_product.domain import RequestAuditStatus, UsageState
from fastapi.testclient import TestClient

from tests.test_platform_integration import (
    PLATFORM_ROOT,
    PROVIDER_MANIFEST,
    upstream_requests,
)


def _provision_route(database: Path, *, binding_id: str) -> UUID:
    """Create the Product endpoint and route through its real control API."""

    control = create_app(database_path=database)
    try:
        with TestClient(control) as client:
            endpoint_response = client.post(
                "/api/v1/gateway-endpoints",
                headers={"Idempotency-Key": f"usage-endpoint-{binding_id}"},
                json={
                    "name": "usage-proof-api",
                    "publicBaseUrl": "http://exchange.example/v1",
                    "authPolicyRef": "policy://exchange/usage-proof",
                },
            )
            assert endpoint_response.status_code == 201
            endpoint = endpoint_response.json()
            route_response = client.post(
                "/api/v1/gateway-routes",
                headers={"Idempotency-Key": f"usage-route-{binding_id}"},
                json={
                    "endpointId": endpoint["id"],
                    "modelPattern": "product-*",
                    "targetBindingId": binding_id,
                    "targetModel": "official-worker-model",
                    "priority": 10,
                },
            )
            assert route_response.status_code == 201
            return UUID(endpoint["id"])
    finally:
        control.state.exchange_store.close()


def _platform_delegate(platform_binaries: dict[str, Path], plugin_runtime: dict[str, Any]):
    """Resolve Product bindings through the actual Platform resolver and direct Plugin runtime."""

    return PlatformResolverAdapter(
        [str(platform_binaries["cyrene-capability-resolver"])],
        [PROVIDER_MANIFEST],
        resolver_cwd=PLATFORM_ROOT,
        plugin_clients=plugin_runtime["clients"],
        provider_deadline_seconds=5,
    )


@contextmanager
def _running_gateway(gateway: ExchangeGateway):
    """Run and close a real loopback Exchange HTTP server."""

    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def _stream_first_event(
    server: ThreadingHTTPServer,
    payload: dict[str, Any],
) -> tuple[HTTPConnection, HTTPResponse, str]:
    """Open one stream and return its first event id before the client closes."""

    client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    body = json.dumps(payload).encode("utf-8")
    client.connect()
    client.putrequest("POST", "/v1/chat/completions")
    client.putheader("Authorization", "Bearer usage-proof-secret")
    client.putheader("Content-Type", "application/json")
    client.putheader("Content-Length", str(len(body)))
    client.endheaders()
    client.send(body)
    response = client.getresponse()
    try:
        line = response.fp.readline() if response.fp is not None else b""
        assert line.startswith(b"data: {")
        event = json.loads(line[len(b"data: ") :])
        assert response.getheader("X-Request-Id") == event["id"]
    except BaseException:
        response.close()
        client.close()
        raise
    return client, response, str(event["id"])


def test_real_product_usage_audit_records_tool_stream_and_survives_restart(
    tmp_path: Path,
    platform_binaries: dict[str, Path],
    plugin_runtime: dict[str, Any],
    upstream: ThreadingHTTPServer,
) -> None:
    """Record exact tool usage after a real Product→direct Plugin request."""

    database = tmp_path / "exchange.sqlite3"
    endpoint_id = _provision_route(database, binding_id="model-provider-stream")
    control = create_app(database_path=database)
    resolver = _platform_delegate(platform_binaries, plugin_runtime)
    gateway = build_gateway_from_store(
        control.state.exchange_store,
        endpoint_id,
        resolver,
        credentials={
            "usage-proof-secret": ProductPrincipal(
                "actor-usage-proof", "workspace-usage-proof", "credential-usage-proof"
            )
        },
        max_route_attempts=1,
    )
    unary_id = ""
    stream_id = ""
    try:
        with _running_gateway(gateway) as server:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            payload = {
                "model": "product-chat",
                "messages": [{"role": "user", "content": "real tool"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {"name": "weather", "parameters": {"type": "object"}},
                    }
                ],
                "tool_choice": "auto",
            }
            connection.request(
                "POST",
                "/v1/chat/completions",
                json.dumps(payload),
                {
                    "Authorization": "Bearer usage-proof-secret",
                    "Content-Type": "application/json",
                    "X-Request-Id": "untrusted-client-request-id",
                },
            )
            unary_response = connection.getresponse()
            assert unary_response.status == 200, unary_response.read()
            unary = json.loads(unary_response.read())
            connection.close()
            unary_id = str(unary["id"])
            assert unary_response.getheader("X-Request-Id") == unary_id
            assert unary_id != "untrusted-client-request-id"
            assert unary["usage"] == {
                "prompt_tokens": 8,
                "completion_tokens": 4,
                "total_tokens": 12,
            }

            connection, stream_response, stream_id = _stream_first_event(
                server,
                payload | {"stream": True, "stream_options": {"include_usage": True}},
            )
            remaining = stream_response.read().decode("utf-8")
            stream_response.close()
            connection.close()
            assert '"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}' in remaining
            assert remaining.rstrip().endswith("data: [DONE]")
    finally:
        store = control.state.exchange_store
        audits = store.list_request_audits(workspace_id="workspace-usage-proof")
        assert {record.request_id for record in audits} >= {unary_id, stream_id}
        for record in audits:
            if record.request_id in {unary_id, stream_id}:
                assert record.status == RequestAuditStatus.COMPLETED
                assert record.usage_state == UsageState.FINAL
                assert (record.prompt_tokens, record.completion_tokens, record.total_tokens) == (8, 4, 12)
        store.close()

    reopened = create_app(database_path=database)
    try:
        unary_record = reopened.state.exchange_store.get_request_audit(unary_id)
        stream_record = reopened.state.exchange_store.get_request_audit(stream_id)
        assert unary_record is not None and stream_record is not None
        assert unary_record.status == stream_record.status == RequestAuditStatus.COMPLETED
        assert upstream_requests(upstream)[-1]["path"] == "/success/v1/chat/completions"
    finally:
        reopened.state.exchange_store.close()


def test_real_product_failed_request_exposes_its_durable_audit_id(
    tmp_path: Path,
    platform_binaries: dict[str, Path],
    plugin_runtime: dict[str, Any],
) -> None:
    """A provider failure remains queryable without a final response body ID.

    Provider 失败时仍返回服务端请求 ID，用于读取持久化审计记录。
    """

    database = tmp_path / "exchange.sqlite3"
    endpoint_id = _provision_route(database, binding_id="model-provider-failure-error")
    control = create_app(database_path=database)
    gateway = build_gateway_from_store(
        control.state.exchange_store,
        endpoint_id,
        _platform_delegate(platform_binaries, plugin_runtime),
        credentials={
            "usage-proof-secret": ProductPrincipal(
                "actor-usage-proof", "workspace-usage-proof", "credential-usage-proof"
            )
        },
        max_route_attempts=1,
    )
    try:
        with _running_gateway(gateway) as server:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                connection.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps(
                        {
                            "model": "product-chat",
                            "messages": [{"role": "user", "content": "provider failure"}],
                            "stream": True,
                        }
                    ),
                    {"Authorization": "Bearer usage-proof-secret", "Content-Type": "application/json"},
                )
                response = connection.getresponse()
                assert response.status == 502
                assert json.loads(response.read())["error"]["type"] == "provider_error"
                request_id = response.getheader("X-Request-Id")
                assert request_id is not None
                record = control.state.exchange_store.get_request_audit(request_id)
                assert record is not None
                assert record.status == RequestAuditStatus.FAILED
                assert record.usage_state == UsageState.UNKNOWN
                assert record.actor_id == "actor-usage-proof"
            finally:
                connection.close()
    finally:
        control.state.exchange_store.close()


def test_real_product_cancelled_stream_is_audited_and_recovers_after_restart(
    tmp_path: Path,
    platform_binaries: dict[str, Path],
    plugin_runtime: dict[str, Any],
    upstream: ThreadingHTTPServer,
) -> None:
    """Cancellation produces one terminal audit row with no fabricated usage."""

    database = tmp_path / "exchange.sqlite3"
    endpoint_id = _provision_route(database, binding_id="model-provider-cancelled-tool-stream")
    control = create_app(database_path=database)
    resolver = _platform_delegate(platform_binaries, plugin_runtime)
    gateway = build_gateway_from_store(
        control.state.exchange_store,
        endpoint_id,
        resolver,
        credentials={
            "usage-proof-secret": ProductPrincipal(
                "actor-usage-proof", "workspace-usage-proof", "credential-usage-proof"
            )
        },
        max_route_attempts=1,
    )
    request_id = ""
    upstream.slow_tool_first_chunk.clear()
    upstream.slow_tool_release.clear()
    upstream.slow_tool_disconnected.clear()
    upstream.slow_tool_usage_sent.clear()
    upstream.slow_tool_terminal_sent.clear()
    payload = {
        "model": "product-chat",
        "messages": [{"role": "user", "content": "cancel after tool"}],
        "tools": [
            {
                "type": "function",
                "function": {"name": "weather", "parameters": {"type": "object"}},
            }
        ],
        "tool_choice": "auto",
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    try:
        with _running_gateway(gateway) as server:
            client, response, request_id = _stream_first_event(server, payload)
            assert response.status == 200
            assert upstream.slow_tool_first_chunk.wait(timeout=3)
            response.close()
            client.close()
            assert upstream.slow_tool_disconnected.wait(timeout=3)
            assert not upstream.slow_tool_usage_sent.is_set()
            assert not upstream.slow_tool_terminal_sent.is_set()
            deadline = time.monotonic() + 3
            record = None
            while time.monotonic() < deadline:
                record = control.state.exchange_store.get_request_audit(request_id)
                if record is not None and record.status != RequestAuditStatus.STARTED:
                    break
                time.sleep(0.05)
            assert record is not None
            assert record.status == RequestAuditStatus.CANCELLED
            assert record.usage_state == UsageState.UNKNOWN
            assert (record.prompt_tokens, record.completion_tokens, record.total_tokens) == (None, None, None)
    finally:
        upstream.slow_tool_release.set()
        control.state.exchange_store.close()

    reopened = create_app(database_path=database)
    try:
        record = reopened.state.exchange_store.get_request_audit(request_id)
        assert record is not None
        assert record.status == RequestAuditStatus.CANCELLED
        assert record.usage_state == UsageState.UNKNOWN
    finally:
        reopened.state.exchange_store.close()
