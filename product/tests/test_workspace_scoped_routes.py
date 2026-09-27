"""Private Workspace route scope, legacy isolation, and migration regressions."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from cyrene_exchange_product import cli
from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.cli import _workspace_endpoint_grants, parser
from cyrene_exchange_product.domain import (
    GatewayEndpoint,
    GatewayRoute,
    ProductPrincipal,
    RouteSource,
    WorkspaceEndpointGrant,
    WorkspaceReactorEndpointGrant,
    utc_now,
)
from cyrene_exchange_product.server import OperatorBindingResolver, build_product_app
from cyrene_exchange_product.store import ExchangeStore

ORG_A = "org-a"
ORG_B = "org-b"
WORKSPACE = "shared-name"
TOKEN_A = "private-service-a"
TOKEN_A_ROTATION = "private-service-a-next"
TOKEN_B = "private-service-b"
TOKEN_WRONG_WORKSPACE = "private-service-wrong-workspace"
TOKEN_LEGACY = "legacy-control-token"
REACTOR_ENDPOINT_ID = UUID("11111111-1111-4111-8111-111111111111")


def _endpoint(endpoint_id: UUID) -> GatewayEndpoint:
    now = utc_now()
    return GatewayEndpoint(
        id=endpoint_id,
        name="shared-exchange-endpoint",
        public_base_url="https://exchange.example/v1",
        auth_policy_ref="policy://exchange/test",
        created_at=now,
        updated_at=now,
        resource_version=1,
    )


def _draft_body(endpoint_id: UUID) -> dict[str, object]:
    return {
        "endpointId": str(endpoint_id),
        "modelPattern": "chat",
        "targetBindingId": "permitted",
        "targetModel": "upstream-chat",
        "priority": 10,
        "source": {
            "resourceUri": "https://reactor.example/api/v1/endpoints/"
            "11111111-1111-4111-8111-111111111111",
            "resourceVersion": 2,
            "artifactDigest": "sha256:" + "a" * 64,
        },
    }


def _workspace_draft_body(endpoint_id: UUID) -> dict[str, object]:
    return {
        "endpointId": str(endpoint_id),
        "modelPattern": "chat",
        "targetBindingId": "permitted",
        "targetModel": "upstream-chat",
        "priority": 10,
        "sourceEndpoint": {
            "product": "reactor",
            "endpointId": str(REACTOR_ENDPOINT_ID),
            "resourceVersion": 2,
        },
    }


def _app(tmp_path: Path):
    database = tmp_path / "exchange-scope.sqlite3"
    store = ExchangeStore(database)
    granted_endpoint_id = uuid4()
    legacy_endpoint_id = uuid4()
    store.save_endpoint(_endpoint(granted_endpoint_id))
    store.save_endpoint(_endpoint(legacy_endpoint_id))
    credentials = {
        TOKEN_A: ProductPrincipal("actor", WORKSPACE, "cred://exchange/a", organization_id=ORG_A),
        TOKEN_A_ROTATION: ProductPrincipal(
            "actor", WORKSPACE, "cred://exchange/a-rotation", organization_id=ORG_A
        ),
        TOKEN_B: ProductPrincipal("actor", WORKSPACE, "cred://exchange/b", organization_id=ORG_B),
        TOKEN_WRONG_WORKSPACE: ProductPrincipal(
            "actor", "other-workspace", "cred://exchange/wrong-workspace", organization_id=ORG_A
        ),
        TOKEN_LEGACY: ProductPrincipal("actor", WORKSPACE, "cred://exchange/legacy"),
    }
    grants = (
        WorkspaceEndpointGrant(granted_endpoint_id, ORG_A, WORKSPACE),
        WorkspaceEndpointGrant(granted_endpoint_id, ORG_B, WORKSPACE),
    )
    reactor_grants = (
        WorkspaceReactorEndpointGrant(REACTOR_ENDPOINT_ID, ORG_A, WORKSPACE),
        WorkspaceReactorEndpointGrant(REACTOR_ENDPOINT_ID, ORG_B, WORKSPACE),
    )
    app = create_app(
        database_path=database,
        store=store,
        control_credentials=credentials,
        workspace_endpoint_grants=grants,
        workspace_reactor_endpoint_grants=reactor_grants,
        resolve_workspace_reactor_endpoint=lambda selector, _target_model: RouteSource(
            resource_uri=f"https://reactor.example/api/v1/endpoints/{selector.endpoint_id}",
            resource_version=selector.resource_version,
            artifact_digest="sha256:" + "a" * 64,
        ),
        allowed_binding_ids=frozenset({"permitted"}),
    )
    return app, store, granted_endpoint_id, legacy_endpoint_id


def _create_private_draft(
    client: TestClient, token: str, endpoint_id: UUID, key: str
) -> dict[str, object]:
    response = client.post(
        "/api/v1/workspace/gateway-route-drafts",
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key},
        json=_workspace_draft_body(endpoint_id),
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def test_private_routes_are_scoped_and_legacy_paths_do_not_expose_them(
    tmp_path: Path,
) -> None:
    app, store, endpoint_id, ungranted_endpoint_id = _app(tmp_path)
    try:
        resolved = store.resolve_product_credential(TOKEN_A)
        assert resolved is not None
        assert (resolved.organization_id, resolved.workspace_id) == (ORG_A, WORKSPACE)
        credential = store._connection.execute(
            "SELECT token_digest FROM api_credentials WHERE credential_ref = ?",
            ("cred://exchange/a",),
        ).fetchone()
        assert credential is not None
        assert credential["token_digest"] == hashlib.sha256(TOKEN_A.encode()).hexdigest()
        with TestClient(app) as client:
            route_a = _create_private_draft(client, TOKEN_A, endpoint_id, "same-key")
            replay_a = _create_private_draft(client, TOKEN_A_ROTATION, endpoint_id, "same-key")
            route_b = _create_private_draft(client, TOKEN_B, endpoint_id, "same-key")
            assert route_a["id"] == replay_a["id"]
            assert route_a["id"] != route_b["id"]
            assert route_a["state"] == route_b["state"] == "DRAFT"
            assert "organizationId" not in route_a
            assert route_a["sourceProvenance"] == {
                "product": "reactor",
                "resourceVersion": 2,
                "artifactDigest": "sha256:" + "a" * 64,
            }
            assert "source" not in route_a
            assert "reactor.example" not in str(route_a)

            private_a = client.get(
                "/api/v1/workspace/gateway-routes",
                headers={"Authorization": f"Bearer {TOKEN_A}"},
            )
            private_b = client.get(
                "/api/v1/workspace/gateway-routes",
                headers={"Authorization": f"Bearer {TOKEN_B}"},
            )
            assert [row["id"] for row in private_a.json()] == [route_a["id"]]
            assert [row["id"] for row in private_b.json()] == [route_b["id"]]
            private_source = private_a.json()[0]["sourceProvenance"]
            assert private_source == {
                "product": "reactor",
                "resourceVersion": 2,
                "artifactDigest": "sha256:" + "a" * 64,
            }
            assert "source" not in private_a.json()[0]
            assert "reactor.example" not in private_a.text

            legacy_list = client.get(
                "/api/v1/gateway-routes", headers={"Authorization": f"Bearer {TOKEN_A}"}
            )
            assert legacy_list.status_code == 200
            assert legacy_list.json() == []
            assert (
                client.get(
                    f"/api/v1/gateway-routes/{route_a['id']}",
                    headers={"Authorization": f"Bearer {TOKEN_A}"},
                ).status_code
                == 404
            )
            assert (
                client.patch(
                    f"/api/v1/gateway-route-drafts/{route_a['id']}",
                    headers={"Authorization": f"Bearer {TOKEN_A}"},
                    json={
                        "resourceVersion": 1,
                        "modelPattern": "changed",
                        "targetBindingId": "permitted",
                        "targetModel": "upstream-chat",
                        "priority": 10,
                    },
                ).status_code
                == 403
            )

            # Product bodies cannot set the authenticated organization.
            forged_body = _workspace_draft_body(endpoint_id)
            forged_body["organizationId"] = ORG_B
            assert (
                client.post(
                    "/api/v1/workspace/gateway-route-drafts",
                    headers={
                        "Authorization": f"Bearer {TOKEN_A}",
                        "Idempotency-Key": "forged-scope",
                    },
                    json=forged_body,
                ).status_code
                == 422
            )

            # Existing global endpoints need an exact operator grant per scope.
            for token, blocked_endpoint in (
                (TOKEN_A, ungranted_endpoint_id),
                (TOKEN_WRONG_WORKSPACE, endpoint_id),
            ):
                denied = client.post(
                    "/api/v1/workspace/gateway-route-drafts",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Idempotency-Key": f"denied-{blocked_endpoint}",
                    },
                    json=_workspace_draft_body(blocked_endpoint),
                )
                assert denied.status_code == 403

            # The old draft writer remains unscoped, and legacy reads retain it.
            scoped_legacy_write = client.post(
                "/api/v1/gateway-route-drafts",
                headers={
                    "Authorization": f"Bearer {TOKEN_A}",
                    "Idempotency-Key": "scoped-legacy-write",
                },
                json=_draft_body(endpoint_id),
            )
            assert scoped_legacy_write.status_code == 403
            legacy_created = client.post(
                "/api/v1/gateway-route-drafts",
                headers={
                    "Authorization": f"Bearer {TOKEN_LEGACY}",
                    "Idempotency-Key": "legacy-write",
                },
                json=_draft_body(endpoint_id),
            )
            assert legacy_created.status_code == 201
            expected_resource_uri = (
                "https://reactor.example/api/v1/endpoints/11111111-1111-4111-8111-111111111111"
            )
            assert legacy_created.json()["source"]["resourceUri"] == expected_resource_uri
            legacy_id = legacy_created.json()["id"]
            assert store.get_route(UUID(legacy_id)).organization_id is None
            assert [
                row["id"]
                for row in client.get(
                    "/api/v1/gateway-routes",
                    headers={"Authorization": f"Bearer {TOKEN_LEGACY}"},
                ).json()
            ] == [legacy_id]
            legacy_fetched = client.get(
                f"/api/v1/gateway-routes/{legacy_id}",
                headers={"Authorization": f"Bearer {TOKEN_LEGACY}"},
            )
            assert legacy_fetched.status_code == 200
            assert legacy_fetched.json()["source"]["resourceUri"] == expected_resource_uri
            private_after_legacy_write = client.get(
                "/api/v1/workspace/gateway-routes",
                headers={"Authorization": f"Bearer {TOKEN_A}"},
            )
            assert [row["id"] for row in private_after_legacy_write.json()] == [route_a["id"]]

            # A valid legacy credential without an organization cannot use aliases.
            assert (
                client.get(
                    "/api/v1/workspace/gateway-routes",
                    headers={"Authorization": f"Bearer {TOKEN_LEGACY}"},
                ).status_code
                == 403
            )
    finally:
        store.close()


def test_control_and_gateway_bearers_have_separate_route_authority(tmp_path: Path) -> None:
    database = tmp_path / "exchange-bearer-boundaries.sqlite3"
    endpoint_id = uuid4()
    store = ExchangeStore(database)
    store.save_endpoint(_endpoint(endpoint_id))
    store.close()

    scoped_token = "workspace-control-only"
    legacy_token = "legacy-dual-use"
    gateway_token = "gateway-data-plane-only"
    app = build_product_app(
        database_path=database,
        resolver=OperatorBindingResolver({}),
        endpoint_id=endpoint_id,
        control_credentials={
            scoped_token: ProductPrincipal(
                "actor", WORKSPACE, "cred://exchange/workspace-control", organization_id=ORG_A
            ),
            legacy_token: ProductPrincipal("actor", WORKSPACE, "cred://exchange/legacy"),
        },
        gateway_credentials={
            gateway_token: ProductPrincipal("gateway", "gateway-workspace", "cred://gateway/api")
        },
    )
    draft_body = _workspace_draft_body(endpoint_id)
    with TestClient(app) as client:
        private_read = client.get(
            "/api/v1/workspace/gateway-routes",
            headers={"Authorization": f"Bearer {scoped_token}"},
        )
        assert private_read.status_code == 200
        assert private_read.json() == []

        for token in (legacy_token, gateway_token):
            denied_private_read = client.get(
                "/api/v1/workspace/gateway-routes",
                headers={"Authorization": f"Bearer {token}"},
            )
            denied_private_write = client.post(
                "/api/v1/workspace/gateway-route-drafts",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": "private-denied",
                },
                json=draft_body,
            )
            assert denied_private_read.status_code == 403
            assert denied_private_write.status_code == 403

        for path, kwargs in (
            ("/v1/models", {}),
            (
                "/v1/chat/completions",
                {
                    "json": {
                        "model": "chat",
                        "messages": [{"role": "user", "content": "hello"}],
                    }
                },
            ),
        ):
            response = client.request(
                "GET" if path.endswith("models") else "POST",
                path,
                headers={"Authorization": f"Bearer {scoped_token}"},
                **kwargs,
            )
            assert response.status_code == 401

        assert (
            client.get(
                "/v1/models", headers={"Authorization": f"Bearer {gateway_token}"}
            ).status_code
            == 200
        )


def test_serve_cli_keeps_scoped_control_secret_out_of_gateway_map(
    tmp_path: Path, monkeypatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setenv("EXCHANGE_CONTROL_SECRET", "private-control-secret")
    monkeypatch.setenv("EXCHANGE_GATEWAY_SECRET", "separate-gateway-secret")
    monkeypatch.setattr(
        cli,
        "build_product_app",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    monkeypatch.setattr(cli.uvicorn, "run", lambda _app, **_kwargs: None)

    assert (
        cli.run(
            [
                "--database",
                str(tmp_path / "cli.sqlite3"),
                "serve",
                "--control-credential-env",
                "cred://exchange/private=org-a=workspace-a=EXCHANGE_CONTROL_SECRET",
                "--gateway-credential-env",
                "cred://exchange/gateway=workspace-a=EXCHANGE_GATEWAY_SECRET",
            ]
        )
        == 0
    )
    control_credentials = captured["control_credentials"]
    gateway_credentials = captured["gateway_credentials"]
    assert list(control_credentials) == ["private-control-secret"]
    assert list(gateway_credentials) == ["separate-gateway-secret"]
    assert control_credentials["private-control-secret"].organization_id == "org-a"

    monkeypatch.setenv("EXCHANGE_LEGACY_SECRET", "legacy-control-secret")
    with pytest.raises(SystemExit, match="cannot carry organization scope"):
        cli.run(
            [
                "--database",
                str(tmp_path / "legacy.sqlite3"),
                "serve",
                "--control-token-env",
                "EXCHANGE_LEGACY_SECRET",
                "--organization-id",
                "org-a",
            ]
        )


def test_unconfigured_private_alias_fails_closed(tmp_path: Path) -> None:
    endpoint_id = uuid4()
    store = ExchangeStore(tmp_path / "unconfigured.sqlite3")
    store.save_endpoint(_endpoint(endpoint_id))
    app = create_app(database_path=tmp_path / "unconfigured.sqlite3", store=store)
    try:
        with TestClient(app) as client:
            assert client.get("/api/v1/workspace/gateway-routes").status_code == 403
            assert (
                client.post(
                    "/api/v1/workspace/gateway-route-drafts",
                    json=_workspace_draft_body(endpoint_id),
                    headers={"Idempotency-Key": "missing-auth"},
                ).status_code
                == 403
            )
    finally:
        store.close()


def test_workspace_api_keys_do_not_cross_organization_boundaries(tmp_path: Path) -> None:
    app, store, _endpoint_id, _ungranted_endpoint_id = _app(tmp_path)
    try:
        with TestClient(app) as client:
            key_a_response = client.post(
                "/api/v1/api-keys",
                headers={
                    "Authorization": f"Bearer {TOKEN_A}",
                    "Idempotency-Key": "same-api-key-idempotency",
                },
                json={"name": "org-a-key", "modelScope": ["chat"]},
            )
            key_b_response = client.post(
                "/api/v1/api-keys",
                headers={
                    "Authorization": f"Bearer {TOKEN_B}",
                    "Idempotency-Key": "same-api-key-idempotency",
                },
                json={"name": "org-a-key", "modelScope": ["chat"]},
            )
            assert key_a_response.status_code == key_b_response.status_code == 201
            key_a = key_a_response.json()
            key_b = key_b_response.json()
            assert key_a["id"] != key_b["id"]
            assert "organizationId" not in key_a

            listed_a = client.get(
                "/api/v1/api-keys", headers={"Authorization": f"Bearer {TOKEN_A}"}
            )
            listed_b = client.get(
                "/api/v1/api-keys", headers={"Authorization": f"Bearer {TOKEN_B}"}
            )
            assert [item["id"] for item in listed_a.json()] == [key_a["id"]]
            assert [item["id"] for item in listed_b.json()] == [key_b["id"]]
            assert (
                client.get(
                    f"/api/v1/api-keys/{key_b['id']}",
                    headers={"Authorization": f"Bearer {TOKEN_A}"},
                ).status_code
                == 404
            )
            assert (
                client.get(
                    "/api/v1/api-keys", headers={"Authorization": f"Bearer {TOKEN_LEGACY}"}
                ).json()
                == []
            )
    finally:
        store.close()


def test_workspace_only_legacy_rows_survive_scope_migration(tmp_path: Path) -> None:
    database = tmp_path / "old-exchange.sqlite3"
    endpoint_id = uuid4()
    route_id = uuid4()
    endpoint = _endpoint(endpoint_id)
    route = GatewayRoute(
        id=route_id,
        endpoint_id=endpoint_id,
        model_pattern="historic-chat",
        target_binding_id="historic-binding",
        priority=5,
        created_at=utc_now(),
        updated_at=utc_now(),
        resource_version=1,
        created_by="historic-actor",
        workspace_id="historic-workspace",
    )
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE gateway_endpoints (id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE gateway_routes (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                priority INTEGER NOT NULL,
                state TEXT NOT NULL,
                document TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO gateway_endpoints(id, document) VALUES (?, ?)",
            (str(endpoint.id), endpoint.model_dump_json(by_alias=True, exclude_none=True)),
        )
        connection.execute(
            "INSERT INTO gateway_routes(id, endpoint_id, priority, state, document) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                str(route.id),
                str(route.endpoint_id),
                route.priority,
                route.state.value,
                route.model_dump_json(by_alias=True, exclude_none=True),
            ),
        )
        connection.commit()
        old_columns = {row[1] for row in connection.execute("PRAGMA table_info(gateway_routes)")}
        assert "organization_id" not in old_columns
    finally:
        connection.close()

    store = ExchangeStore(database)
    app = create_app(
        database_path=database,
        store=store,
        control_credentials={
            TOKEN_LEGACY: ProductPrincipal("historic-actor", "historic-workspace", "cred://old")
        },
    )
    try:
        stored = store.get_route(route_id)
        assert stored is not None
        assert stored.workspace_id == "historic-workspace"
        assert stored.organization_id is None
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {TOKEN_LEGACY}"}
            listed = client.get("/api/v1/gateway-routes", headers=headers)
            assert listed.status_code == 200
            assert [row["id"] for row in listed.json()] == [str(route_id)]
            fetched = client.get(f"/api/v1/gateway-routes/{route_id}", headers=headers)
            assert fetched.status_code == 200
            assert fetched.json()["workspaceId"] == "historic-workspace"
            private_read = client.get("/api/v1/workspace/gateway-routes", headers=headers)
            assert private_read.status_code == 403
    finally:
        store.close()


def test_azure_deploy_script_keeps_exchange_ingress_internal() -> None:
    repository_root = Path(__file__).parents[2]
    script = (repository_root / "scripts/deploy_to_azure_containerapp.sh").read_text()
    assert "--ingress external" not in script
    assert "--ingress internal" in script
    assert "az containerapp ingress enable" in script
    assert "--type internal" in script
    assert "AZURE_CONTAINERAPP_VERIFY_URL" in script


def test_cli_accepts_server_side_scope_and_rotation_configuration(tmp_path: Path) -> None:
    endpoint_id = uuid4()
    grant_arg = f"{endpoint_id}=org-a=workspace-a"
    parsed_grants = _workspace_endpoint_grants([grant_arg])
    assert parsed_grants == (WorkspaceEndpointGrant(endpoint_id, "org-a", "workspace-a"),)

    arguments = parser().parse_args(
        [
            "--database",
            str(tmp_path / "exchange.sqlite3"),
            "serve",
            "--control-credential-env",
            "cred://one=org-a=workspace-a=EXCHANGE_ONE",
            "--control-credential-env",
            "cred://two=org-b=workspace-b=EXCHANGE_TWO",
            "--workspace-endpoint-grant",
            grant_arg,
        ]
    )
    assert arguments.control_credential_env == [
        "cred://one=org-a=workspace-a=EXCHANGE_ONE",
        "cred://two=org-b=workspace-b=EXCHANGE_TWO",
    ]
    assert arguments.workspace_endpoint_grant == [grant_arg]
