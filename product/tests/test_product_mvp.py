"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_product_mvp.py                                             │
│  Module: tests.test_product_mvp                                     │
│  Role: Persisted routing, real HTTP, failure, and restart acceptance.│
│                                                                     │
│  模块职责：验证持久化路由、真实 HTTP、失败与重启恢复。                       │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from typing import Any
from uuid import UUID

from cyrene_exchange.capabilities import MODEL_PROVIDER_CAPABILITY, ProviderChunk
from cyrene_exchange.http import create_reference_server
from cyrene_exchange.protocol import NormalizedInferenceRequest
from fastapi.testclient import TestClient
from jsonschema import FormatChecker, validate
from openapi_spec_validator.readers import read_from_filename

from cyrene_exchange_product import ProductPrincipal, build_gateway_from_store, create_app


class UpstreamHandler(BaseHTTPRequestHandler):
    """Real local model HTTP peer used by the reference provider adapter.

    中文:供参考 provider adapter 使用的本地真实模型 HTTP peer。
    """
# 中文:参考提供方适配器使用的真实本地模型 HTTP 对端。

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        content = request["messages"][-1]["content"]
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": f"upstream:{content}"},
                        "finish_reason": "stop",
                    }
                ]
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class LocalHttpProvider:
    """Small real-HTTP provider used only to exercise the persisted routing path.

    中文:仅用于验证持久化路由流程的小型真实 HTTP provider。
    """
# 中文:仅用于覆盖持久化路由路径的小型真实 HTTP 提供方。

    def __init__(self, server: ThreadingHTTPServer) -> None:
        self._server = server

    def complete(
        self, request: NormalizedInferenceRequest, *, cancel_event: Event
    ) -> Iterable[ProviderChunk]:
        if cancel_event.is_set():
            return
        connection = HTTPConnection("127.0.0.1", self._server.server_port, timeout=3)
        connection.request(
            "POST",
            "/v1/chat/completions",
            json.dumps(request.to_provider_dict()),
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        yield ProviderChunk(
            delta=payload["choices"][0]["message"]["content"],
            finish_reason=payload["choices"][0]["finish_reason"],
        )


class ProviderResolver:
    """Delegate that exposes only an opaque bound provider capability.

    中文:仅暴露不透明、已绑定 provider capability 的委托对象。
    """
# 中文:只公开不透明已绑定提供方能力的委托对象。

    def __init__(self, binding_id: str, provider: LocalHttpProvider) -> None:
        self._binding_id = binding_id
        self._provider = provider

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        assert capability_id == MODEL_PROVIDER_CAPABILITY
        assert implementation_ref == self._binding_id
        return self._provider


def test_runtime_paths_match_frozen_control_openapi(tmp_path: Path) -> None:
    app = create_app(database_path=tmp_path / "exchange.sqlite3")
    contract, _ = read_from_filename(
        str(Path(__file__).parents[2] / "contracts/product/v1/openapi.yaml")
    )
    control_paths = {path for path in contract["paths"] if path.startswith("/api/")}
    assert set(app.openapi()["paths"]) == control_paths
    app.state.exchange_store.close()


def _post_gateway(server: ThreadingHTTPServer) -> tuple[int, dict[str, Any]]:
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    connection.request(
        "POST",
        "/v1/chat/completions",
        json.dumps({"model": "demo-model", "messages": [{"role": "user", "content": "hello"}]}),
        {"Authorization": "Bearer acceptance", "Content-Type": "application/json"},
    )
    response = connection.getresponse()
    body = json.loads(response.read())
    connection.close()
    return response.status, body


def test_persisted_route_drives_real_gateway_http_after_restart(tmp_path: Path) -> None:
    database = tmp_path / "exchange.sqlite3"
    control = create_app(database_path=database)
    with TestClient(control) as client:
        endpoint_response = client.post(
            "/api/v1/gateway-endpoints",
            headers={"Idempotency-Key": "endpoint-demo"},
            json={
                "name": "public-model-api",
                "publicBaseUrl": "http://exchange.example/v1",
                "authPolicyRef": "policy://exchange/demo",
            },
        )
        assert endpoint_response.status_code == 201
        endpoint = endpoint_response.json()
        route_response = client.post(
            "/api/v1/gateway-routes",
            headers={"Idempotency-Key": "route-demo"},
            json={
                "endpointId": endpoint["id"],
                "modelPattern": "demo-*",
                "targetBindingId": "binding:local-http",
                "targetModel": "upstream-model",
                "priority": 10,
            },
        )
        assert route_response.status_code == 201
        route = route_response.json()
        assert route["targetCapabilityType"] == "model.provider.v1"
    control.state.exchange_store.close()

    restarted = create_app(database_path=database)
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    gateway_server = None
    gateway_thread = None
    try:
        gateway = build_gateway_from_store(
            restarted.state.exchange_store,
            UUID(endpoint["id"]),
            ProviderResolver("binding:local-http", LocalHttpProvider(upstream)),
            credentials={
                "acceptance": ProductPrincipal(
                    "actor-acceptance", "workspace-acceptance", "credential-acceptance"
                )
            },
        )
        gateway_server = create_reference_server(gateway)
        gateway_thread = Thread(target=gateway_server.serve_forever, daemon=True)
        gateway_thread.start()

        status, body = _post_gateway(gateway_server)
        assert status == 200
        assert body["choices"][0]["message"]["content"] == "upstream:hello"

        with TestClient(restarted) as client:
            assert client.get(f"/api/v1/gateway-endpoints/{endpoint['id']}").json() == endpoint
            assert client.get(f"/api/v1/gateway-routes/{route['id']}").json() == route
            disabled = client.post(
                f"/api/v1/gateway-endpoints/{endpoint['id']}/actions/disable"
            ).json()
            assert disabled["state"] == "DISABLED"

        disabled_status, disabled_body = _post_gateway(gateway_server)
        assert disabled_status == 503
        assert disabled_body["error"]["type"] == "no_route"

        contract_root = Path(__file__).parents[2] / "contracts/product/v1"
        endpoint_schema = json.loads((contract_root / "gateway-endpoint.schema.json").read_text())
        route_schema = json.loads((contract_root / "gateway-route.schema.json").read_text())
        validate(instance=endpoint, schema=endpoint_schema, format_checker=FormatChecker())
        validate(instance=route, schema=route_schema, format_checker=FormatChecker())
    finally:
        if gateway_server is not None:
            gateway_server.shutdown()
            gateway_server.server_close()
        if gateway_thread is not None:
            gateway_thread.join(timeout=3)
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=3)
        restarted.state.exchange_store.close()


def test_route_for_unknown_endpoint_is_typed_problem(tmp_path: Path) -> None:
    control = create_app(database_path=tmp_path / "exchange.sqlite3")
    try:
        with TestClient(control) as client:
            response = client.post(
                "/api/v1/gateway-routes",
                json={
                    "endpointId": "00000000-0000-0000-0000-000000000001",
                    "modelPattern": "*",
                    "targetBindingId": "binding:missing",
                    "priority": 1,
                },
            )
            assert response.status_code == 404
            assert response.headers["content-type"].startswith("application/problem+json")
            assert response.json()["code"] == "EXCHANGE_ENDPOINT_NOT_FOUND"
    finally:
        control.state.exchange_store.close()
