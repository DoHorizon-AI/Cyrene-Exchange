"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_workspace_route_data_plane.py                              │
│  Module: tests.test_workspace_route_data_plane                      │
│  Role: Verify persisted route selection respects authenticated scope. │
│                                                                     │
│  模块职责：验证数据面按认证主体隔离持久化模型路由。                        │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from cyrene_exchange.capabilities import ProviderChunk
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.domain import (
    ProductPrincipal,
    WorkspaceEndpointGrant,
)
from cyrene_exchange_product.server import OperatorBindingResolver, build_product_app

_WORKSPACE = "shared"
_ORG_A = "org-a"
_ORG_B = "org-b"
_BOOTSTRAP = "bootstrap-control-secret"
_CONTROL_A = "org-a-control-secret"
_CONTROL_B = "org-b-control-secret"
_DATA_A = "org-a-data-secret"
_DATA_B = "org-b-data-secret"
_DATA_OTHER_WORKSPACE = "other-workspace-data-secret"
_DATA_LEGACY = "legacy-data-secret"


class _FixedProvider:
    """Return one controlled, provider-owned answer for one binding."""

    def __init__(self, content: str) -> None:
        self._content = content

    def complete(self, _request, *, cancel_event):
        if cancel_event.is_set():
            return ()
        return (
            ProviderChunk(
                role="assistant",
                delta=self._content,
                finish_reason="stop",
            ),
        )


def _create_endpoint(database: Path) -> UUID:
    bootstrap = ProductPrincipal("operator", _WORKSPACE, "cred://bootstrap")
    app = create_app(database_path=database, control_credentials={_BOOTSTRAP: bootstrap})
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/gateway-endpoints",
                headers={
                    "Authorization": f"Bearer {_BOOTSTRAP}",
                    "Idempotency-Key": "route-scope-endpoint-v1",
                },
                json={
                    "name": "Workspace route scope integration test",
                    "publicBaseUrl": "http://127.0.0.1:18682/v1",
                    "authPolicyRef": "policy://exchange/route-scope-test",
                },
            )
        assert response.status_code == 201, response.text
        return UUID(response.json()["id"])
    finally:
        app.state.exchange_store.close()


def test_persisted_routes_are_selected_only_for_authenticated_workspace(tmp_path: Path) -> None:
    database = tmp_path / "scoped-data-plane.sqlite3"
    endpoint_id = _create_endpoint(database)
    principals = {
        _BOOTSTRAP: ProductPrincipal("operator", _WORKSPACE, "cred://bootstrap"),
        _CONTROL_A: ProductPrincipal(
            "actor-a", _WORKSPACE, "cred://control/a", organization_id=_ORG_A
        ),
        _CONTROL_B: ProductPrincipal(
            "actor-b", _WORKSPACE, "cred://control/b", organization_id=_ORG_B
        ),
    }
    resolver = OperatorBindingResolver(
        {
            "binding:org-a": _FixedProvider("selected:org-a"),
            "binding:org-b": _FixedProvider("selected:org-b"),
            "binding:global": _FixedProvider("selected:legacy-global"),
        }
    )
    app = build_product_app(
        database_path=database,
        resolver=resolver,
        endpoint_id=endpoint_id,
        control_credentials=principals,
        control_only_credentials={_BOOTSTRAP: principals[_BOOTSTRAP]},
        gateway_credentials={
            _DATA_A: ProductPrincipal("actor-a", _WORKSPACE, "cred://data/a", _ORG_A),
            _DATA_B: ProductPrincipal("actor-b", _WORKSPACE, "cred://data/b", _ORG_B),
            _DATA_OTHER_WORKSPACE: ProductPrincipal(
                "actor-a", "other-workspace", "cred://data/a-other", _ORG_A
            ),
            _DATA_LEGACY: ProductPrincipal("legacy-actor", _WORKSPACE, "cred://data/legacy"),
        },
        workspace_endpoint_grants=(
            WorkspaceEndpointGrant(endpoint_id, _ORG_A, _WORKSPACE),
            WorkspaceEndpointGrant(endpoint_id, _ORG_B, _WORKSPACE),
        ),
        allowed_binding_ids=frozenset({"binding:org-a", "binding:org-b", "binding:global"}),
    )
    headers_by_control = {
        _ORG_A: {"Authorization": f"Bearer {_CONTROL_A}"},
        _ORG_B: {"Authorization": f"Bearer {_CONTROL_B}"},
    }
    direct_route = {
        "endpointId": str(endpoint_id),
        "modelPattern": "shared-model",
        "priority": 10,
    }
    try:
        with TestClient(app) as client:
            for org_id, token, binding, target in (
                (_ORG_A, _CONTROL_A, "binding:org-a", "org-a-model"),
                (_ORG_B, _CONTROL_B, "binding:org-b", "org-b-model"),
            ):
                created = client.post(
                    "/api/v1/workspace/gateway-route-drafts/direct",
                    headers={
                        **headers_by_control[org_id],
                        "Idempotency-Key": f"{org_id}-private-route-v1",
                    },
                    json={
                        **direct_route,
                        "targetBindingId": binding,
                        "targetModel": target,
                    },
                )
                assert created.status_code == 201, created.text
                draft = created.json()
                confirmed = client.post(
                    f"/api/v1/workspace/gateway-route-drafts/{draft['id']}/actions/confirm",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"resourceVersion": draft["resourceVersion"]},
                )
                assert confirmed.status_code == 200, confirmed.text
                assert confirmed.json()["state"] == "ACTIVE"

            readiness = client.get("/readyz")
            assert readiness.status_code == 200
            assert readiness.json()["routes"] == 2

            legacy_route = client.post(
                "/api/v1/gateway-routes",
                headers={
                    "Authorization": f"Bearer {_BOOTSTRAP}",
                    "Idempotency-Key": "shared-legacy-route-v1",
                },
                json={
                    **direct_route,
                    "targetBindingId": "binding:global",
                    "targetModel": "global-model",
                },
            )
            assert legacy_route.status_code == 201, legacy_route.text

            for token, expected in (
                (_DATA_A, "selected:org-a"),
                (_DATA_B, "selected:org-b"),
                (_DATA_LEGACY, "selected:legacy-global"),
            ):
                models = client.get(
                    "/v1/models",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert models.status_code == 200, models.text
                assert [item["id"] for item in models.json()["data"]] == ["shared-model"]

                completion = client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "model": "shared-model",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )
                assert completion.status_code == 200, completion.text
                assert completion.json()["choices"][0]["message"]["content"] == expected

            other_workspace_models = client.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {_DATA_OTHER_WORKSPACE}"},
            )
            assert other_workspace_models.status_code == 200
            assert other_workspace_models.json()["data"] == []
            denied_cross_workspace = client.post(
                "/v1/chat/completions",
                headers={"Authorization": f"Bearer {_DATA_OTHER_WORKSPACE}"},
                json={
                    "model": "shared-model",
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
            assert denied_cross_workspace.status_code == 503
            assert denied_cross_workspace.json()["error"]["type"] == "no_route"

            denied_control_data_plane = client.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {_BOOTSTRAP}"},
            )
            assert denied_control_data_plane.status_code == 401
    finally:
        app.state.exchange_store.close()
