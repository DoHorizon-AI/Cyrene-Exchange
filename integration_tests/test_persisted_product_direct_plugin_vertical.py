"""
Prove persisted Exchange Product routes through the Platform resolver and Official direct Plugin.

验证持久化 Exchange Product 路由经 Platform resolver 与官方直连 Plugin 完成真实 HTTP 纵向链。
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from uuid import UUID

from cyrene_exchange import ExchangeGateway, PlatformResolverAdapter
from cyrene_exchange.http import create_reference_server
from cyrene_exchange_product import ProductPrincipal, build_gateway_from_store, create_app
from fastapi.testclient import TestClient

from tests.test_platform_integration import (
    PLATFORM_ROOT,
    PROVIDER_MANIFEST,
    post,
    upstream_requests,
)


def _provision_route(database: Path, *, binding_id: str) -> UUID:
    """Create Product endpoint/route resources through the control HTTP API.

    中文:通过 control HTTP API 创建 Product endpoint 和 route 资源。
    """
# 中文:通过控制 HTTP API 创建 Product 端点和路由资源。

    control = create_app(database_path=database)
    try:
        with TestClient(control) as client:
            endpoint_response = client.post(
                "/api/v1/gateway-endpoints",
                headers={"Idempotency-Key": f"endpoint-{binding_id}"},
                json={
                    "name": "canonical-worker-api",
                    "publicBaseUrl": "http://exchange.example/v1",
                    "authPolicyRef": "policy://exchange/canonical-worker",
                },
            )
            assert endpoint_response.status_code == 201
            endpoint = endpoint_response.json()
            route_response = client.post(
                "/api/v1/gateway-routes",
                headers={"Idempotency-Key": f"route-{binding_id}"},
                json={
                    "endpointId": endpoint["id"],
                    "modelPattern": "product-*",
                    "targetBindingId": binding_id,
                    "targetModel": "official-worker-model",
                    "priority": 10,
                },
            )
            assert route_response.status_code == 201
            assert route_response.json()["targetBindingId"] == binding_id
            return UUID(endpoint["id"])
    finally:
        control.state.exchange_store.close()


def _platform_delegate(
    platform_binaries: dict[str, Path],
    plugin_runtime: dict[str, Any],
) -> PlatformResolverAdapter:
    """Bind Product lookups to Platform selection and direct Plugin clients.

    中文:让 Product 查询通过 Platform 选择和 Direct Plugin client 完成。
    """
# 中文:将 Product 查询绑定到 Platform 选择和直接 Plugin 客户端。

    return PlatformResolverAdapter(
        [str(platform_binaries["cyrene-capability-resolver"])],
        [PROVIDER_MANIFEST],
        resolver_cwd=PLATFORM_ROOT,
        plugin_clients=plugin_runtime["clients"],
        provider_deadline_seconds=5,
    )


@contextmanager
def _running_gateway(gateway: ExchangeGateway) -> Iterator[ThreadingHTTPServer]:
    """Run the real loopback HTTP adapter and release its listener deterministically.

    中文:运行真实 loopback HTTP adapter,并确定性地释放 listener。
    """
# 中文:运行真实的 loopback HTTP 适配器,并以确定方式释放其监听器。

    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_persisted_route_reaches_official_worker_after_product_restart(
    tmp_path: Path,
    platform_binaries: dict[str, Path],
    plugin_runtime: dict[str, Any],
    upstream: ThreadingHTTPServer,
) -> None:
    """Exercise control HTTP, SQLite, resolver, direct Plugin endpoint, and data-plane HTTP.

    中文:通过 control HTTP、SQLite、resolver、Direct Plugin endpoint 和 data-plane HTTP 进行端到端验证。
    """
# 中文:覆盖控制 HTTP、SQLite、解析器、直接 Plugin 端点和数据平面 HTTP。

    database = tmp_path / "exchange.sqlite3"
    endpoint_id = _provision_route(database, binding_id="model-provider-local")
    request_count = len(upstream_requests(upstream))

    restarted = create_app(database_path=database)
    resolver = _platform_delegate(platform_binaries, plugin_runtime)
    gateway = build_gateway_from_store(
        restarted.state.exchange_store,
        endpoint_id,
        resolver,
        credentials={
            "exchange-test": ProductPrincipal("actor-integration", "workspace-integration", "credential-integration")
        },
    )
    try:
        with _running_gateway(gateway) as server:
            status, _, body = post(
                server,
                {
                    "model": "product-chat",
                    "messages": [{"role": "user", "content": "persisted route"}],
                },
            )
            assert status == 200, body
            assert json.loads(body)["choices"][0]["message"]["content"] == "real path"

            stream_status, content_type, stream_body = post(
                server,
                {
                    "model": "product-chat",
                    "messages": [{"role": "user", "content": "persisted stream"}],
                    "stream": True,
                },
            )
            assert stream_status == 200, stream_body
            assert content_type.startswith("text/event-stream")
            assert '"content":"real "' in stream_body
            assert '"content":"path"' in stream_body
            assert "data: [DONE]" in stream_body

            with TestClient(restarted) as client:
                disabled = client.post(f"/api/v1/gateway-endpoints/{endpoint_id}/actions/disable")
                assert disabled.status_code == 200
                assert disabled.json()["state"] == "DISABLED"

            disabled_status, _, disabled_body = post(
                server,
                {
                    "model": "product-chat",
                    "messages": [{"role": "user", "content": "disabled"}],
                },
            )
            assert disabled_status == 503
            assert json.loads(disabled_body)["error"]["type"] == "no_route"
    finally:
        restarted.state.exchange_store.close()

    assert resolver.resolutions == [
        {
            "capability": "model.provider.v1",
            "plugin": "cyrene.providers.model-api-connector",
            "reference": "model-provider-local",
            "execution_mode": "SERVICE",
        },
        {
            "capability": "model.provider.v1",
            "plugin": "cyrene.providers.model-api-connector",
            "reference": "model-provider-local",
            "execution_mode": "SERVICE",
        },
    ]
    requests = upstream_requests(upstream)[request_count:]
    assert [request["path"] for request in requests] == [
        "/success/v1/chat/completions",
        "/success/v1/chat/completions",
    ]
    assert [request["payload"]["model"] for request in requests] == [
        "official-worker-model",
        "official-worker-model",
    ]


def test_persisted_unknown_binding_fails_closed_without_plugin_endpoint(
    tmp_path: Path,
    platform_binaries: dict[str, Path],
    plugin_runtime: dict[str, Any],
) -> None:
    """Keep an unknown Product binding opaque until Product composition rejects it.

    中文:保持未知的 Product binding 不透明,直到 Product 组合层将其拒绝。
    """
# 中文:在 Product 组合拒绝未知绑定之前,始终将其视为不透明值。

    database = tmp_path / "exchange.sqlite3"
    endpoint_id = _provision_route(database, binding_id="model-provider-missing")
    restarted = create_app(database_path=database)
    resolver = _platform_delegate(platform_binaries, plugin_runtime)
    gateway = build_gateway_from_store(
        restarted.state.exchange_store,
        endpoint_id,
        resolver,
        credentials={
            "exchange-test": ProductPrincipal("actor-integration", "workspace-integration", "credential-integration")
        },
    )
    try:
        with _running_gateway(gateway) as server:
            status, _, body = post(
                server,
                {
                    "model": "product-chat",
                    "messages": [{"role": "user", "content": "missing"}],
                },
            )
    finally:
        restarted.state.exchange_store.close()

    assert status == 502
    error = json.loads(body)["error"]
    assert error["type"] == "provider_error"
    assert "no direct Plugin client is configured" in error["message"]
    assert resolver.resolutions == [
        {
            "capability": "model.provider.v1",
            "plugin": "cyrene.providers.model-api-connector",
            "reference": "model-provider-missing",
            "execution_mode": "SERVICE",
        }
    ]
