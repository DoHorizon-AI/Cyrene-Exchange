"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_gateway_server.py                                          │
│  Module: tests.test_gateway_server                                  │
│  Role: Independent gateway process, probes, models, SSE, and CLI.   │
│                                                                     │
│  模块职责：验证独立网关进程、探活、模型列表、流式对话与运维 CLI。           │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from uuid import UUID

from fastapi.testclient import TestClient

from cyrene_exchange_product import cli, create_app
from cyrene_exchange_product.domain import ProductPrincipal
from cyrene_exchange_product.server import (
    OpenAICompatibleProvider,
    OperatorBindingResolver,
    RouteSourceProviderResolver,
    build_product_app,
)

CONTROL_HEADERS = {"Authorization": "Bearer control-token"}
CONTROL_PRINCIPAL = ProductPrincipal("actor", "workspace", "cred://exchange/control")


class UpstreamHandler(BaseHTTPRequestHandler):
    """Real OpenAI-compatible peer that supports both response modes.

    中文:支持两种响应模式的真实 OpenAI 兼容 peer。
    """

    # 中文:支持两种响应模式的真实 OpenAI 兼容对端。

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        content = request["messages"][-1]["content"]
        if request.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for piece in ("upstream:", content):
                event = {
                    "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]
                }
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": f"upstream:{content}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 4},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _seed_endpoint(database: Path, name: str) -> str:
    """Create one ACTIVE gateway endpoint before the data plane starts.

    中文:在 data plane 启动前创建一个状态为 ACTIVE 的 gateway endpoint。
    """
    # 中文:在数据平面启动前创建一个 ACTIVE 网关端点。

    with TestClient(
        create_app(database_path=database, control_credentials={"control-token": CONTROL_PRINCIPAL})
    ) as client:
        return _seed_endpoint_via(client, name)


def _gateway_app(tmp_path: Path, upstream: ThreadingHTTPServer):
    """Build the fused control and data plane against one real upstream peer.

    中文:基于一个真实上游 peer 构建融合式 control plane 和 data plane。
    """
    # 中文:基于同一个真实上游对端构建组合的控制面和数据平面。

    provider = OpenAICompatibleProvider(f"http://127.0.0.1:{upstream.server_port}/v1")
    return build_product_app(
        database_path=tmp_path / "exchange.sqlite3",
        resolver=OperatorBindingResolver({"binding:local": provider}),
        control_credentials={"control-token": CONTROL_PRINCIPAL},
        allowed_binding_ids=frozenset({"binding:local"}),
    )


def _seed_endpoint_via(client: TestClient, name: str) -> str:
    response = client.post(
        "/api/v1/gateway-endpoints",
        json={
            "name": name,
            "publicBaseUrl": "http://127.0.0.1:8000",
            "authPolicyRef": "policy://local",
        },
        headers=CONTROL_HEADERS,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_gateway_probes_models_and_both_response_modes(tmp_path: Path) -> None:
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    Thread(target=upstream.serve_forever, daemon=True).start()
    try:
        endpoint_id = _seed_endpoint(tmp_path / "exchange.sqlite3", "Acceptance Gateway")
        app = _gateway_app(tmp_path, upstream)
        with TestClient(app) as client:
            assert client.get("/healthz").json() == {"status": "ok"}
            assert client.get("/readyz").status_code == 503
            created = client.post(
                "/api/v1/gateway-routes",
                json={
                    "endpointId": endpoint_id,
                    "modelPattern": "qwen-acceptance-lora",
                    "targetBindingId": "binding:local",
                    "targetModel": "local-model",
                    "priority": 10,
                },
                headers=CONTROL_HEADERS,
            )
            assert created.status_code == 201, created.text

            ready = client.get("/readyz")
            assert ready.status_code == 200 and ready.json()["routes"] == 1
            models = client.get("/v1/models", headers=CONTROL_HEADERS)
            assert models.status_code == 200
            assert models.json()["data"][0]["id"] == "qwen-acceptance-lora"

            completion = client.post(
                "/v1/chat/completions",
                json={
                    "model": "qwen-acceptance-lora",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                headers=CONTROL_HEADERS,
            )
            assert completion.status_code == 200, completion.text
            assert completion.json()["choices"][0]["message"]["content"] == "upstream:hi"

            streamed = client.post(
                "/v1/chat/completions",
                json={
                    "model": "qwen-acceptance-lora",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": True,
                },
                headers=CONTROL_HEADERS,
            )
            assert streamed.status_code == 200
            assert streamed.headers["content-type"].startswith("text/event-stream")
            assert "upstream:" in streamed.text
            assert '"object":"chat.completion.chunk"' in streamed.text
    finally:
        upstream.shutdown()


def test_operator_cli_manages_routes_and_keys(tmp_path: Path, capsys) -> None:
    database = tmp_path / "exchange.sqlite3"
    base = ["--database", str(database)]

    with TestClient(
        create_app(
            database_path=database,
            control_credentials={"control-token": CONTROL_PRINCIPAL},
        )
    ) as client:
        endpoint_id = _seed_endpoint_via(client, "CLI Gateway")

    assert (
        cli.run(
            [
                *base,
                "route",
                "create",
                "--endpoint-id",
                endpoint_id,
                "--model-pattern",
                "cli-model",
                "--target-binding",
                "binding:local",
                "--priority",
                "5",
            ]
        )
        == 0
    )
    assert (
        cli.run(
            [
                *base,
                "key",
                "create",
                "--token",
                "control-token",
                "--credential-ref",
                "cred://exchange/control",
            ]
        )
        == 0
    )

    capsys.readouterr()
    assert cli.run([*base, "route", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert [item["modelPattern"] for item in listed["data"]] == ["cli-model"]

    assert cli.run([*base, "key", "issue", "--name", "cli-issued", "--model-scope", "cli-*"]) == 0
    issued = json.loads(capsys.readouterr().out)
    assert issued["secret"].startswith("cyk_")
    assert issued["modelScope"] == ["cli-*"]
    assert cli.run([*base, "key", "list"]) == 0
    listed_keys = json.loads(capsys.readouterr().out)
    assert [item["id"] for item in listed_keys["data"]] == [issued["id"]]
    assert "secret" not in listed_keys["data"][0]
    assert cli.run([*base, "key", "revoke", "--api-key-id", issued["id"]]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "REVOKED"

    assert cli.run([*base, "key", "revoke", "--credential-ref", "cred://exchange/control"]) == 0
    assert cli.run([*base, "key", "revoke", "--credential-ref", "cred://exchange/control"]) == 1

    from cyrene_exchange_product.store import ExchangeStore

    store = ExchangeStore(database)
    try:
        assert store.resolve_credential("control-token") is None
        assert store.list_active_routes()[0].model_pattern == "cli-model"
    finally:
        store.close()


def test_route_enable_activates_a_reactor_handoff_draft(tmp_path: Path) -> None:
    from cyrene_exchange_product.domain import CreateRouteDraftRequest, RouteSource
    from cyrene_exchange_product.service import ExchangeProductService
    from cyrene_exchange_product.store import ExchangeStore

    database = tmp_path / "exchange.sqlite3"
    with TestClient(
        create_app(database_path=database, control_credentials={"control-token": CONTROL_PRINCIPAL})
    ) as client:
        endpoint_id = _seed_endpoint_via(client, "Draft Gateway")

    store = ExchangeStore(database)
    try:
        service = ExchangeProductService(store)
        draft = service.create_route_draft(
            CreateRouteDraftRequest(
                endpoint_id=UUID(endpoint_id),
                model_pattern="draft-model",
                target_binding_id="binding:local",
                target_model="local-model",
                priority=1,
                source=RouteSource(
                    resource_uri="http://127.0.0.1:19301/api/v1/endpoints/ep",
                    resource_version=1,
                    artifact_digest="sha256:" + "a" * 64,
                ),
            ),
            "draft-route",
            ProductPrincipal("reactor", "workspace", "cred://reactor"),
        )
        assert draft.state.value == "DRAFT"
    finally:
        store.close()

    assert (
        cli.run(
            [
                "--database",
                str(database),
                "route",
                "enable",
                "--route-id",
                str(draft.id),
                "--resource-version",
                str(draft.resource_version),
                "--actor-id",
                "reactor",
                "--workspace-id",
                "workspace",
                "--credential-ref",
                "cred://reactor",
            ]
        )
        == 0
    )

    store = ExchangeStore(database)
    try:
        assert [item.model_pattern for item in store.list_active_routes()] == ["draft-model"]
    finally:
        store.close()


class SourceHandler(BaseHTTPRequestHandler):
    """Stand-in Reactor endpoint that publishes its serving URL.

    中文:会发布自身 serving URL 的 Reactor endpoint 替身。
    """

    # 中文:发布其服务 URL 的 Reactor 代用端点。

    serving_url = ""

    def do_GET(self) -> None:
        body = json.dumps({"url": self.serving_url}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def test_gateway_resolves_the_provider_from_the_route_source(tmp_path: Path) -> None:
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    Thread(target=upstream.serve_forever, daemon=True).start()
    SourceHandler.serving_url = f"http://127.0.0.1:{upstream.server_port}/v1"
    SourceHandler.expected_authorization = "Bearer reactor-control-token"
    source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
    Thread(target=source.serve_forever, daemon=True).start()
    try:
        endpoint_id = _seed_endpoint(tmp_path / "exchange.sqlite3", "Source Gateway")
        app = build_product_app(
            database_path=tmp_path / "exchange.sqlite3",
            resolver_factory=partial(
                RouteSourceProviderResolver,
                source_bearer_token="reactor-control-token",
                allowed_source_origins=frozenset({f"http://127.0.0.1:{source.server_port}"}),
            ),
            control_credentials={"control-token": CONTROL_PRINCIPAL},
            allowed_binding_ids=frozenset({"binding:local"}),
        )
        with TestClient(app) as client:
            draft = client.post(
                "/api/v1/gateway-route-drafts",
                json={
                    "endpointId": endpoint_id,
                    "modelPattern": "source-model",
                    "targetBindingId": "binding:local",
                    "targetModel": "local-model",
                    "priority": 1,
                    "source": {
                        "product": "reactor",
                        "resourceUri": f"http://127.0.0.1:{source.server_port}/api/v1/endpoints/ep",
                        "resourceVersion": 1,
                        "artifactDigest": "sha256:" + "a" * 64,
                    },
                },
                headers={**CONTROL_HEADERS, "Idempotency-Key": "source-draft"},
            )
            assert draft.status_code == 201, draft.text
            confirmed = client.post(
                f"/api/v1/gateway-route-drafts/{draft.json()['id']}/actions/confirm",
                json={"resourceVersion": draft.json()["resourceVersion"]},
                headers=CONTROL_HEADERS,
            )
            assert confirmed.status_code == 200, confirmed.text

            completion = client.post(
                "/v1/chat/completions",
                json={"model": "source-model", "messages": [{"role": "user", "content": "hi"}]},
                headers=CONTROL_HEADERS,
            )
            assert completion.status_code == 200, completion.text
            assert completion.json()["choices"][0]["message"]["content"] == "upstream:hi"
    finally:
        source.shutdown()
        upstream.shutdown()


def test_draft_confirmation_fails_closed_when_the_source_is_unreachable(tmp_path: Path) -> None:
    endpoint_id = _seed_endpoint(tmp_path / "exchange.sqlite3", "Dead Source Gateway")
    app = build_product_app(
        database_path=tmp_path / "exchange.sqlite3",
        resolver_factory=RouteSourceProviderResolver,
        control_credentials={"control-token": CONTROL_PRINCIPAL},
        allowed_binding_ids=frozenset({"binding:local"}),
    )
    with TestClient(app) as client:
        draft = client.post(
            "/api/v1/gateway-route-drafts",
            json={
                "endpointId": endpoint_id,
                "modelPattern": "dead-model",
                "targetBindingId": "binding:local",
                "targetModel": "local-model",
                "priority": 1,
                "source": {
                    "product": "reactor",
                    "resourceUri": "http://127.0.0.1:1/api/v1/endpoints/ep",
                    "resourceVersion": 1,
                    "artifactDigest": "sha256:" + "b" * 64,
                },
            },
            headers={**CONTROL_HEADERS, "Idempotency-Key": "dead-source-draft"},
        )
        assert draft.status_code == 201, draft.text
        confirmed = client.post(
            f"/api/v1/gateway-route-drafts/{draft.json()['id']}/actions/confirm",
            json={"resourceVersion": draft.json()["resourceVersion"]},
            headers=CONTROL_HEADERS,
        )
        assert confirmed.status_code == 502
        assert confirmed.json()["code"] == "EXCHANGE_TARGET_UNREACHABLE"


def test_route_source_origin_outside_the_allow_list_is_refused(tmp_path: Path) -> None:
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    Thread(target=upstream.serve_forever, daemon=True).start()
    SourceHandler.serving_url = f"http://127.0.0.1:{upstream.server_port}/v1"
    SourceHandler.expected_authorization = ""
    source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
    Thread(target=source.serve_forever, daemon=True).start()
    try:
        endpoint_id = _seed_endpoint(tmp_path / "exchange.sqlite3", "SSRF Gateway")
        app = build_product_app(
            database_path=tmp_path / "exchange.sqlite3",
            resolver_factory=partial(
                RouteSourceProviderResolver,
                allowed_source_origins=frozenset({"http://127.0.0.1:19300"}),
            ),
            control_credentials={"control-token": CONTROL_PRINCIPAL},
            allowed_binding_ids=frozenset({"binding:local"}),
        )
        with TestClient(app) as client:
            draft = client.post(
                "/api/v1/gateway-route-drafts",
                json={
                    "endpointId": endpoint_id,
                    "modelPattern": "ssrf-model",
                    "targetBindingId": "binding:local",
                    "targetModel": "local-model",
                    "priority": 1,
                    "source": {
                        "product": "reactor",
                        "resourceUri": f"http://127.0.0.1:{source.server_port}/api/v1/endpoints/ep",
                        "resourceVersion": 1,
                        "artifactDigest": "sha256:" + "c" * 64,
                    },
                },
                headers={**CONTROL_HEADERS, "Idempotency-Key": "ssrf-draft"},
            )
            assert draft.status_code == 201, draft.text
            confirmed = client.post(
                f"/api/v1/gateway-route-drafts/{draft.json()['id']}/actions/confirm",
                json={"resourceVersion": draft.json()["resourceVersion"]},
                headers=CONTROL_HEADERS,
            )
            assert confirmed.status_code == 502
            assert confirmed.json()["code"] == "EXCHANGE_TARGET_UNREACHABLE"
    finally:
        source.shutdown()
        upstream.shutdown()
