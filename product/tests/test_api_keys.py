"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_api_keys.py                                                │
│  Module: tests.test_api_keys                                        │
│  Role: Gateway API key lifecycle, scope, expiry, and isolation.     │
│                                                                     │
│  模块职责：验证网关密钥生命周期、模型范围、过期与工作区隔离。               │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from uuid import uuid4

from fastapi.testclient import TestClient
from test_gateway_server import CONTROL_HEADERS, CONTROL_PRINCIPAL, UpstreamHandler

from cyrene_exchange_product import create_app
from cyrene_exchange_product.domain import ProductPrincipal
from cyrene_exchange_product.server import (
    OpenAICompatibleProvider,
    OperatorBindingResolver,
    build_product_app,
)

OTHER_PRINCIPAL = ProductPrincipal("actor-b", "workspace-b", "cred://exchange/other")


def _control_app(database: Path) -> TestClient:
    return TestClient(
        create_app(database_path=database, control_credentials={"control-token": CONTROL_PRINCIPAL})
    )


def _seed_endpoint(client: TestClient, name: str) -> str:
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


def _create_key(
    client: TestClient,
    *,
    name: str = "acceptance",
    model_scope: list[str] | None = None,
    expires_at: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    body: dict = {"name": name}
    if model_scope is not None:
        body["modelScope"] = model_scope
    if expires_at is not None:
        body["expiresAt"] = expires_at
    headers = dict(CONTROL_HEADERS)
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    response = client.post("/api/v1/api-keys", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_api_key_lifecycle_reveals_the_secret_once(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "exchange.sqlite3",
        control_credentials={"control-token": CONTROL_PRINCIPAL},
    )
    try:
        with TestClient(app) as client:
            expires_at = (datetime.now(UTC) + timedelta(days=30)).isoformat()
            created = _create_key(
                client,
                model_scope=["qwen-*"],
                expires_at=expires_at,
                idempotency_key="issue-acceptance-key",
            )
            assert created["state"] == "ACTIVE"
            assert created["secret"].startswith("cyk_")
            assert created["credentialRef"] == f"api-key://{created['id']}"
            assert created["modelScope"] == ["qwen-*"]
            assert created["expiresAt"]

            listed = client.get("/api/v1/api-keys", headers=CONTROL_HEADERS)
            assert listed.status_code == 200
            assert [item["id"] for item in listed.json()] == [created["id"]]
            assert "secret" not in listed.json()[0]

            fetched = client.get(f"/api/v1/api-keys/{created['id']}", headers=CONTROL_HEADERS)
            assert fetched.status_code == 200
            assert "secret" not in fetched.json()

            replay = client.post(
                "/api/v1/api-keys",
                json={
                    "name": "acceptance",
                    "modelScope": ["qwen-*"],
                    "expiresAt": expires_at,
                },
                headers={**CONTROL_HEADERS, "Idempotency-Key": "issue-acceptance-key"},
            )
            assert replay.status_code == 201
            assert replay.json()["id"] == created["id"]
            assert "secret" not in replay.json()

            store = app.state.exchange_store
            assert store.resolve_credential(created["secret"]) is not None

            revoked = client.post(
                f"/api/v1/api-keys/{created['id']}/actions/revoke", headers=CONTROL_HEADERS
            )
            assert revoked.status_code == 200
            assert revoked.json()["state"] == "REVOKED"
            assert revoked.json()["revokedAt"]
            assert store.resolve_credential(created["secret"]) is None

            twice = client.post(
                f"/api/v1/api-keys/{created['id']}/actions/revoke", headers=CONTROL_HEADERS
            )
            assert twice.status_code == 200
            assert twice.json()["state"] == "REVOKED"

            missing = client.get(f"/api/v1/api-keys/{uuid4()}", headers=CONTROL_HEADERS)
            assert missing.status_code == 404
            assert missing.headers["content-type"].startswith("application/problem+json")
            assert missing.json()["code"] == "EXCHANGE_API_KEY_NOT_FOUND"
    finally:
        app.state.exchange_store.close()


def test_api_key_rejects_past_expiry(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "exchange.sqlite3",
        control_credentials={"control-token": CONTROL_PRINCIPAL},
    )
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/api-keys",
                json={
                    "name": "expired",
                    "expiresAt": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                },
                headers=CONTROL_HEADERS,
            )
            assert response.status_code == 422
            assert response.json()["code"] == "EXCHANGE_API_KEY_EXPIRY_INVALID"
    finally:
        app.state.exchange_store.close()


def test_api_keys_are_isolated_per_workspace(tmp_path: Path) -> None:
    database = tmp_path / "exchange.sqlite3"
    app = create_app(
        database_path=database, control_credentials={"control-token": CONTROL_PRINCIPAL}
    )
    try:
        with TestClient(app) as client:
            created = _create_key(client, name="workspace-a")
    finally:
        app.state.exchange_store.close()

    other = create_app(database_path=database, control_credentials={"other-token": OTHER_PRINCIPAL})
    try:
        with TestClient(other) as client:
            listed = client.get("/api/v1/api-keys", headers={"Authorization": "Bearer other-token"})
            assert listed.status_code == 200
            assert listed.json() == []
            hidden = client.get(
                f"/api/v1/api-keys/{created['id']}",
                headers={"Authorization": "Bearer other-token"},
            )
            assert hidden.status_code == 404
            refused = client.post(
                f"/api/v1/api-keys/{created['id']}/actions/revoke",
                headers={"Authorization": "Bearer other-token"},
            )
            assert refused.status_code == 404
    finally:
        other.state.exchange_store.close()


def test_model_scope_filters_models_and_chat(tmp_path: Path) -> None:
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    Thread(target=upstream.serve_forever, daemon=True).start()
    database = tmp_path / "exchange.sqlite3"
    try:
        provider = OpenAICompatibleProvider(f"http://127.0.0.1:{upstream.server_port}/v1")
        setup = TestClient(
            create_app(
                database_path=database,
                control_credentials={"control-token": CONTROL_PRINCIPAL},
            )
        )
        with setup as client:
            endpoint_id = _seed_endpoint(client, "Scoped Gateway")
        app = build_product_app(
            database_path=database,
            resolver=OperatorBindingResolver({"binding:local": provider}),
            control_credentials={"control-token": CONTROL_PRINCIPAL},
            allowed_binding_ids=frozenset({"binding:local"}),
        )
        with TestClient(app) as client:
            for pattern in ("qwen-acceptance-lora", "other-model"):
                created = client.post(
                    "/api/v1/gateway-routes",
                    json={
                        "endpointId": endpoint_id,
                        "modelPattern": pattern,
                        "targetBindingId": "binding:local",
                        "targetModel": "local-model",
                        "priority": 10,
                    },
                    headers=CONTROL_HEADERS,
                )
                assert created.status_code == 201, created.text
            key = _create_key(client, name="scoped", model_scope=["qwen-*"])

            unauthenticated = client.get("/v1/models")
            assert unauthenticated.status_code == 401
            assert unauthenticated.json()["error"]["type"] == "authentication_error"

            models = client.get("/v1/models", headers={"Authorization": "Bearer " + key["secret"]})
            assert models.status_code == 200
            assert [item["id"] for item in models.json()["data"]] == ["qwen-acceptance-lora"]

            refused = client.post(
                "/v1/chat/completions",
                json={"model": "other-model", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": "Bearer " + key["secret"]},
            )
            assert refused.status_code == 403
            assert refused.json()["error"]["type"] == "model_not_permitted"

            allowed = client.post(
                "/v1/chat/completions",
                json={
                    "model": "qwen-acceptance-lora",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                headers={"Authorization": "Bearer " + key["secret"]},
            )
            assert allowed.status_code == 200, allowed.text
            assert allowed.json()["choices"][0]["message"]["content"] == "upstream:hi"

            records = app.state.exchange_store.list_request_audits(
                workspace_id="workspace", actor_id="actor"
            )
            rejected = [record for record in records if record.error_type == "model_not_permitted"]
            assert rejected and rejected[0].status.value == "rejected"
    finally:
        upstream.shutdown()


def test_gateway_lists_are_persisted_and_stable(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "exchange.sqlite3",
        control_credentials={"control-token": CONTROL_PRINCIPAL},
    )
    try:
        with TestClient(app) as client:
            endpoint_id = _seed_endpoint(client, "Listed Gateway")
            client.post(
                "/api/v1/gateway-routes",
                json={
                    "endpointId": endpoint_id,
                    "modelPattern": "listed-model",
                    "targetBindingId": "binding:local",
                    "targetModel": "local-model",
                    "priority": 5,
                },
                headers=CONTROL_HEADERS,
            )
            endpoints = client.get("/api/v1/gateway-endpoints", headers=CONTROL_HEADERS)
            assert [item["id"] for item in endpoints.json()] == [endpoint_id]
            routes = client.get("/api/v1/gateway-routes", headers=CONTROL_HEADERS)
            assert [item["modelPattern"] for item in routes.json()] == ["listed-model"]
    finally:
        app.state.exchange_store.close()
