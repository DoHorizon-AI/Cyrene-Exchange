"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_route_drafts.py                                            │
│  Module: exchange_product.tests                                    │
│  Role: Draft publication, authority and version-race regressions.  │
│  模块职责：验证草稿不发布、权限和版本竞争，不把测试回调作为真实推理证据。      │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock
from uuid import UUID

import httpx
import pytest
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.domain import GatewayRoute, ProductPrincipal
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.route_admission import ReactorRouteAdmission
from cyrene_exchange_product.store import ExchangeStore

TOKEN = "route-control-unit-test-credential"
HEADERS = {"Authorization": "Bearer " + TOKEN}
PRINCIPAL = ProductPrincipal("actor", "workspace", "route-control")


def draft(client: TestClient) -> dict[str, object]:
    endpoint = client.post(
        "/api/v1/gateway-endpoints",
        headers=HEADERS,
        json={
            "name": "draft-test",
            "publicBaseUrl": "https://exchange.example/v1",
            "authPolicyRef": "policy://test",
        },
    ).json()
    body = {
        "endpointId": endpoint["id"],
        "modelPattern": "chat",
        "targetBindingId": "permitted",
        "targetModel": "actual-target-name",
        "priority": 10,
        "source": {
            "resourceUri": "https://reactor.example/api/v1/endpoints/11111111-1111-4111-8111-111111111111",
            "resourceVersion": 2,
            "artifactDigest": "sha256:" + "a" * 64,
        },
    }
    response = client.post(
        "/api/v1/gateway-route-drafts",
        json=body,
        headers={**HEADERS, "Idempotency-Key": "one-send"},
    )
    assert response.status_code == 201
    result = response.json()
    assert result["state"] == "DRAFT"
    assert (
        client.post(
            "/api/v1/gateway-route-drafts",
            json=body,
            headers={**HEADERS, "Idempotency-Key": "one-send"},
        ).json()["id"]
        == result["id"]
    )
    return dict(result)


def test_draft_is_persisted_editable_and_invisible_until_confirmed(tmp_path: Path) -> None:
    database = tmp_path / "exchange.sqlite3"
    observed: list[str] = []

    def verified(route: GatewayRoute) -> None:
        observed.append(route.model_pattern)

    app = create_app(
        database_path=database,
        control_credentials={TOKEN: PRINCIPAL},
        allowed_binding_ids=frozenset({"permitted"}),
        validate_route_target=verified,
    )
    with TestClient(app) as client:
        route = draft(client)
        store = ExchangeStore(database)
        assert store.active_routes(UUID(str(route["endpointId"]))) == []
        assert store.get_route(UUID(str(route["id"]))).state == "DRAFT"
        path = "/api/v1/gateway-route-drafts/" + str(route["id"])
        edited = client.patch(
            path,
            headers=HEADERS,
            json={
                "resourceVersion": 1,
                "modelPattern": "reviewed-chat",
                "targetBindingId": "permitted",
                "targetModel": "actual-target-name",
                "priority": 5,
            },
        )
        assert edited.status_code == 200
        assert edited.json()["source"] == route["source"]
        assert (
            client.post(
                path + "/actions/confirm", headers=HEADERS, json={"resourceVersion": 1}
            ).status_code
            == 409
        )
        assert observed == []
        confirmed = client.post(
            path + "/actions/confirm", headers=HEADERS, json={"resourceVersion": 2}
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["state"] == "ACTIVE"
        assert observed == ["reviewed-chat"]
        assert len(store.active_routes(UUID(str(route["endpointId"])))) == 1
        store.close()


def test_unavailable_verifier_and_missing_permission_never_activate(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "exchange.sqlite3",
        control_credentials={TOKEN: PRINCIPAL},
        allowed_binding_ids=frozenset({"permitted"}),
    )
    with TestClient(app) as client:
        route = draft(client)
        path = "/api/v1/gateway-route-drafts/" + str(route["id"]) + "/actions/confirm"
        assert client.post(path, json={"resourceVersion": 1}).status_code == 403
        response = client.post(path, headers=HEADERS, json={"resourceVersion": 1})
        assert response.status_code == 503
        assert response.json()["code"] == "EXCHANGE_TARGET_VALIDATOR_UNAVAILABLE"
        assert (
            client.get("/api/v1/gateway-routes/" + str(route["id"]), headers=HEADERS).json()[
                "state"
            ]
            == "DRAFT"
        )


def test_source_probe_failure_preserves_draft(tmp_path: Path) -> None:
    def unreachable(_route: GatewayRoute) -> None:
        raise ExchangeProductError(
            code="EXCHANGE_SOURCE_UNREACHABLE",
            title="Source unavailable",
            detail="Controlled verifier failure",
            status=503,
            retryable=True,
        )

    app = create_app(
        database_path=tmp_path / "exchange.sqlite3",
        control_credentials={TOKEN: PRINCIPAL},
        allowed_binding_ids=frozenset({"permitted"}),
        validate_route_target=unreachable,
    )
    with TestClient(app) as client:
        route = draft(client)
        response = client.post(
            "/api/v1/gateway-route-drafts/" + str(route["id"]) + "/actions/confirm",
            headers=HEADERS,
            json={"resourceVersion": 1},
        )
        assert response.status_code == 503
        assert app.state.exchange_store.active_routes(UUID(str(route["endpointId"]))) == []


@pytest.mark.parametrize("mismatch", ["version", "model", "artifact", "identity"])
def test_source_mismatch_cannot_reach_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    app = create_app(
        database_path=tmp_path / "source.sqlite3",
        control_credentials={TOKEN: PRINCIPAL},
        allowed_binding_ids=frozenset({"permitted"}),
    )
    with TestClient(app) as client:
        route = GatewayRoute.model_validate(draft(client))
    endpoint_id = "11111111-1111-4111-8111-111111111111"
    deployment_id = "22222222-2222-4222-8222-222222222222"

    def source(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-source-token"
        if "/endpoints/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "id": deployment_id if mismatch == "identity" else endpoint_id,
                    "resourceVersion": 3 if mismatch == "version" else 2,
                    "protocol": "openai.chat.v1",
                    "state": "READY",
                    "model": "different-model" if mismatch == "model" else route.target_model,
                    "deploymentId": deployment_id,
                },
            )
        return httpx.Response(
            200,
            json={"id": deployment_id, "modelArtifact": {"digest": "sha256:" + "b" * 64}},
        )

    transport = httpx.MockTransport(source)
    original_client = httpx.Client
    monkeypatch.setattr(
        "cyrene_exchange_product.route_admission.httpx.Client",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )
    resolver = Mock()
    admission = ReactorRouteAdmission(
        reactor_base_url="https://reactor.example",
        reactor_token="test-source-token",
        resolver=resolver,
    )
    with pytest.raises(ExchangeProductError) as caught:
        admission(route)
    assert caught.value.status == 409
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize(
    "case", ["matching", "changed-adapter", "missing-reference", "missing-version"]
)
def test_composed_identity_is_verified_even_when_base_artifact_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """An unchanged base digest cannot authorize a different adapter. | 比较完整模型版本。"""
    version_id = "model-version://sha256/" + "c" * 64
    app = create_app(
        database_path=tmp_path / "composed-source.sqlite3",
        control_credentials={TOKEN: PRINCIPAL},
        allowed_binding_ids=frozenset({"permitted"}),
    )
    with TestClient(app) as client:
        route_body = draft(client)
    route = GatewayRoute.model_validate(route_body)
    assert route.source is not None
    if case != "missing-reference":
        route.source = route.source.model_copy(update={"model_version_id": version_id})
    endpoint_id = "11111111-1111-4111-8111-111111111111"
    deployment_id = "22222222-2222-4222-8222-222222222222"

    def source(request: httpx.Request) -> httpx.Response:
        if "/endpoints/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "id": endpoint_id,
                    "resourceVersion": 2,
                    "protocol": "openai.chat.v1",
                    "state": "READY",
                    "model": route.target_model,
                    "deploymentId": deployment_id,
                },
            )
        return httpx.Response(
            200,
            json={
                "id": deployment_id,
                "composition": "BASE_PLUS_LORA",
                "modelArtifact": {"digest": "sha256:" + "a" * 64},
                "modelVersion": None
                if case == "missing-version"
                else {
                    "id": "model-version://sha256/" + "d" * 64
                    if case == "changed-adapter"
                    else version_id
                },
            },
        )

    original_client = httpx.Client
    monkeypatch.setattr(
        "cyrene_exchange_product.route_admission.httpx.Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(source), **kwargs),
    )
    resolver = Mock()
    resolver.resolve.return_value.complete.return_value = [Mock(delta="ready")]
    admission = ReactorRouteAdmission(
        reactor_base_url="https://reactor.example",
        reactor_token="test-source-token",
        resolver=resolver,
    )
    if case == "matching":
        admission(route)
        resolver.resolve.assert_called_once()
        serialized = GatewayRoute.model_validate(route.model_dump(mode="json"))
        assert serialized.source is not None
        assert serialized.source.model_version_id == version_id
    else:
        with pytest.raises(ExchangeProductError) as caught:
            admission(route)
        assert caught.value.code == "EXCHANGE_SOURCE_MODEL_VERSION_MISMATCH"
        resolver.resolve.assert_not_called()
