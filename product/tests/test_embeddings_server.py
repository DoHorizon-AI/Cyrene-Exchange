"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_embeddings_server.py                                        │
│  Module: product.tests                                               │
│  Role: Verify the Product embeddings HTTP route and scoped provider.   │
│                                                                      │
│  模块职责：验证 Product embeddings HTTP 路由与 workspace 路由隔离。   │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

import grpc
import httpx
import pytest
from cyrene_exchange.capabilities import MODEL_PROVIDER_CAPABILITY
from cyrene_model_provider_contracts import (
    EMBEDDINGS_RESPONSE_TYPE_URL,
    EmbeddingBatch,
    EmbeddingError,
    EmbeddingsRequest,
    EmbeddingsResponse,
    EmbeddingVector,
    decode_embeddings_request,
    encode_embeddings_response,
)
from cyrene_plugin_runtime import DirectPayload, DirectPluginInvocationCancelled
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.domain import ProductPrincipal, WorkspaceEndpointGrant
from cyrene_exchange_product.server import (
    HealthCheckedDirectPluginModelProvider,
    OperatorBindingResolver,
    build_product_app,
)

ORG_A = "embedding-org-a"
ORG_B = "embedding-org-b"
WORKSPACE = "embedding-workspace"
BOOTSTRAP = "embedding-bootstrap-secret"
CONTROL_A = "embedding-org-a-control-secret"
CONTROL_B = "embedding-org-b-control-secret"
DATA_A = "embedding-org-a-data-secret"
DATA_B = "embedding-org-b-data-secret"
DATA_OTHER_WORKSPACE = "embedding-other-workspace-data-secret"
BINDING = "binding:model-api-connector"
REQUEST_MODEL = "e5-requested-alias"
ROUTE_MODEL = "e5-route-model"
ACTUAL_MODEL = "e5-provider-actual"


def test_product_http_embeddings_uses_persisted_scoped_route_and_direct_provider(
    tmp_path: Path,
) -> None:
    direct = FakeDirectInvoker(_response(((0.25, -0.5), (1.0, 0.0)), dimensions=2))
    app, endpoint_id = _build_app(tmp_path, direct)
    try:
        with TestClient(app) as client:
            response = client.post(
                "/v1/embeddings",
                headers={"Authorization": f"Bearer {DATA_A}"},
                json={
                    "model": REQUEST_MODEL,
                    "input": ["passage: alpha", "passage: beta"],
                },
            )

            assert response.status_code == 200, response.text
            body = response.json()
            assert body["object"] == "list"
            assert body["model"] == ACTUAL_MODEL
            assert [item["index"] for item in body["data"]] == [0, 1]
            assert [item["embedding"] for item in body["data"]] == [
                [0.25, -0.5],
                [1.0, 0.0],
            ]
            assert response.headers["x-request-id"]

            assert direct.requests == [
                EmbeddingsRequest(
                    inputs=("passage: alpha", "passage: beta"),
                    model=ROUTE_MODEL,
                )
            ]
            assert direct.calls[0]["capability"] == MODEL_PROVIDER_CAPABILITY
            assert direct.calls[0]["interface_version"] == "1"
            assert direct.calls[0]["method"] == "embeddings"

            openapi_response = app.openapi()["paths"]["/v1/embeddings"]["post"]["responses"]["200"][
                "content"
            ]["application/json"]["schema"]
            assert openapi_response["$ref"] == "#/components/schemas/OpenAIEmbeddingsResponse"

        route_rows = app.state.exchange_store.active_routes(
            endpoint_id,
            organization_id=ORG_A,
            workspace_id=WORKSPACE,
        )
        assert len(route_rows) == 1
        assert route_rows[0].target_binding_id == BINDING
    finally:
        app.state.exchange_store.close()


def test_embeddings_reject_auth_missing_route_and_cross_scope_before_provider(
    tmp_path: Path,
) -> None:
    direct = FakeDirectInvoker(_response(((0.5, -0.5),), dimensions=2))
    app, _endpoint_id = _build_app(tmp_path, direct)
    payload = {"model": REQUEST_MODEL, "input": "passage: alpha"}
    try:
        with TestClient(app) as client:
            unauthenticated = client.post("/v1/embeddings", json=payload)
            other_org = client.post(
                "/v1/embeddings",
                headers={"Authorization": f"Bearer {DATA_B}"},
                json=payload,
            )
            other_workspace = client.post(
                "/v1/embeddings",
                headers={"Authorization": f"Bearer {DATA_OTHER_WORKSPACE}"},
                json=payload,
            )
            missing_model_route = client.post(
                "/v1/embeddings",
                headers={"Authorization": f"Bearer {DATA_A}"},
                json={"model": "no-matching-route", "input": "passage: alpha"},
            )

        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["error"]["type"] == "authentication_error"
        assert other_org.status_code == 503
        assert other_workspace.status_code == 503
        assert missing_model_route.status_code == 503
        assert all(
            response.json()["error"]["type"] == "no_route"
            for response in (
                other_org,
                other_workspace,
                missing_model_route,
            )
        )
        assert direct.calls == []
    finally:
        app.state.exchange_store.close()


@pytest.mark.parametrize(
    ("vectors", "dimensions", "inputs"),
    [
        (((0.1,),), 1, ("passage: alpha", "passage: beta")),
        (((0.1, 0.2),), 3, ("passage: alpha",)),
        (((0.0, 0.0),), 2, ("passage: alpha",)),
        (((float("nan"), 0.2),), 2, ("passage: alpha",)),
    ],
)
def test_embeddings_reject_incomplete_or_invalid_provider_vectors(
    tmp_path: Path,
    vectors: tuple[tuple[float, ...], ...],
    dimensions: int,
    inputs: tuple[str, ...],
) -> None:
    direct = FakeDirectInvoker(_response(vectors, dimensions=dimensions))
    app, _endpoint_id = _build_app(tmp_path, direct)
    try:
        with TestClient(app) as client:
            response = client.post(
                "/v1/embeddings",
                headers={"Authorization": f"Bearer {DATA_A}"},
                json={"model": REQUEST_MODEL, "input": list(inputs)},
            )
        assert response.status_code == 502, response.text
        assert response.json()["error"]["type"] == "provider_error"
    finally:
        app.state.exchange_store.close()


def test_embeddings_preserve_provider_rate_limit_status_and_retry_after(tmp_path: Path) -> None:
    direct = FakeDirectInvoker(
        EmbeddingsResponse(
            error=EmbeddingError(
                code=5,
                message="provider busy",
                retry_after_seconds=2.2,
            )
        )
    )
    app, _endpoint_id = _build_app(tmp_path, direct)
    try:
        with TestClient(app) as client:
            response = client.post(
                "/v1/embeddings",
                headers={"Authorization": f"Bearer {DATA_A}"},
                json={"model": REQUEST_MODEL, "input": "passage: alpha"},
            )
        assert response.status_code == 429
        assert response.headers["retry-after"] == "3"
        assert response.json()["error"]["type"] == "rate_limit_error"
        assert response.json()["error"]["code"] == 5
    finally:
        app.state.exchange_store.close()


def test_embeddings_http_cancellation_reaches_provider_and_keeps_typed_audit(
    tmp_path: Path,
) -> None:
    direct = FakeDirectInvoker(_response(((0.2,),), dimensions=1), block_until_cancel=True)
    app, _endpoint_id = _build_app(tmp_path, direct)

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://exchange.test",
        ) as client:
            call = asyncio.create_task(
                client.post(
                    "/v1/embeddings",
                    headers={"Authorization": f"Bearer {DATA_A}"},
                    json={"model": REQUEST_MODEL, "input": "passage: alpha"},
                )
            )
            assert await asyncio.to_thread(direct.started.wait, 2)
            call.cancel()
            with pytest.raises(asyncio.CancelledError):
                await call
            assert await asyncio.to_thread(direct.cancel_seen.wait, 2)
            audits = app.state.exchange_store.list_request_audits(
                workspace_id=WORKSPACE,
                actor_id="actor-a",
            )
            assert audits[0].status.value == "cancelled"
            assert audits[0].error_type == "request_cancelled"

    try:
        asyncio.run(exercise())
    finally:
        app.state.exchange_store.close()


def _build_app(tmp_path: Path, direct: FakeDirectInvoker):
    database = tmp_path / "embeddings-data-plane.sqlite3"
    endpoint_id = _create_endpoint(database)
    principals = {
        BOOTSTRAP: ProductPrincipal("operator", WORKSPACE, "cred://bootstrap"),
        CONTROL_A: ProductPrincipal("actor-a", WORKSPACE, "cred://control/a", ORG_A),
        CONTROL_B: ProductPrincipal("actor-b", WORKSPACE, "cred://control/b", ORG_B),
    }
    provider = HealthCheckedDirectPluginModelProvider(
        BINDING,
        direct,
        FakePluginHealth(),
    )
    app = build_product_app(
        database_path=database,
        resolver_factory=lambda _store: OperatorBindingResolver({BINDING: provider}),
        endpoint_id=endpoint_id,
        control_credentials=principals,
        control_only_credentials={BOOTSTRAP: principals[BOOTSTRAP]},
        gateway_credentials={
            DATA_A: ProductPrincipal("actor-a", WORKSPACE, "cred://data/a", ORG_A),
            DATA_B: ProductPrincipal("actor-b", WORKSPACE, "cred://data/b", ORG_B),
            DATA_OTHER_WORKSPACE: ProductPrincipal(
                "actor-a", "another-workspace", "cred://data/a-other", ORG_A
            ),
        },
        workspace_endpoint_grants=(WorkspaceEndpointGrant(endpoint_id, ORG_A, WORKSPACE),),
        allowed_binding_ids=frozenset({BINDING}),
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/workspace/gateway-route-drafts/direct",
            headers={
                "Authorization": f"Bearer {CONTROL_A}",
                "Idempotency-Key": "embeddings-route-v1",
            },
            json={
                "endpointId": str(endpoint_id),
                "modelPattern": "e5-*",
                "targetBindingId": BINDING,
                "targetModel": ROUTE_MODEL,
                "priority": 10,
            },
        )
        assert created.status_code == 201, created.text
        draft = created.json()
        confirmed = client.post(
            f"/api/v1/workspace/gateway-route-drafts/{draft['id']}/actions/confirm",
            headers={"Authorization": f"Bearer {CONTROL_A}"},
            json={"resourceVersion": draft["resourceVersion"]},
        )
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["state"] == "ACTIVE"
    return app, endpoint_id


def _create_endpoint(database: Path) -> UUID:
    bootstrap = ProductPrincipal("operator", WORKSPACE, "cred://bootstrap")
    app = create_app(database_path=database, control_credentials={BOOTSTRAP: bootstrap})
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/gateway-endpoints",
                headers={
                    "Authorization": f"Bearer {BOOTSTRAP}",
                    "Idempotency-Key": "embeddings-endpoint-v1",
                },
                json={
                    "name": "Embeddings API route test",
                    "publicBaseUrl": "http://127.0.0.1:18682/v1",
                    "authPolicyRef": "policy://exchange/embeddings-test",
                },
            )
        assert response.status_code == 201, response.text
        return UUID(response.json()["id"])
    finally:
        app.state.exchange_store.close()


def _response(
    vectors: Sequence[Sequence[float]],
    *,
    dimensions: int,
    model: str = ACTUAL_MODEL,
) -> EmbeddingsResponse:
    return EmbeddingsResponse(
        embeddings=EmbeddingBatch(
            vectors=tuple(EmbeddingVector(values=tuple(vector)) for vector in vectors),
            dimensions=dimensions,
            model=model,
        )
    )


class FakePluginHealth:
    """Report one test-bound DirectPlugin as serving the canonical capability."""

    def observe(self):
        return type(
            "HealthObservation",
            (),
            {
                "status": "SERVING",
                "plugin_id": "cyrene.providers.model-api-connector",
                "capabilities": (MODEL_PROVIDER_CAPABILITY,),
            },
        )()

    def close(self) -> None:
        return None


class FakeDirectInvoker:
    """Fake the DirectPlugin wire peer, not the Product provider facade."""

    def __init__(
        self,
        response: EmbeddingsResponse,
        *,
        block_until_cancel: bool = False,
    ) -> None:
        self.response = response
        self.block_until_cancel = block_until_cancel
        self.requests: list[EmbeddingsRequest] = []
        self.calls: list[dict[str, object]] = []
        self.started = threading.Event()
        self.cancel_seen = threading.Event()

    def invoke(self, **arguments: object) -> DirectPayload:
        request = arguments["request"]
        assert isinstance(request, DirectPayload)
        self.calls.append(arguments)
        self.requests.append(decode_embeddings_request(request.value))
        if self.block_until_cancel:
            cancel_event = arguments["cancel_event"]
            assert isinstance(cancel_event, threading.Event)
            self.started.set()
            cancel_event.wait(3)
            self.cancel_seen.set()
            raise DirectPluginInvocationCancelled(grpc.StatusCode.CANCELLED, "cancelled")
        return DirectPayload(
            EMBEDDINGS_RESPONSE_TYPE_URL,
            encode_embeddings_response(self.response),
        )

    def close(self) -> None:
        return None
