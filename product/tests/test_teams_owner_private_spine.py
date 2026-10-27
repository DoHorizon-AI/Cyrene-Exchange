"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_teams_owner_private_spine.py                                │
│  Module: product.tests.test_teams_owner_private_spine                 │
│  Role: Verify Exchange-to-Teams private send and grant isolation.     │
│                                                                      │
│  模块职责：验证 Exchange 到 Teams 私聊发送链路与 grant 隔离。           │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import base64
import importlib
import os
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.clients import TeamsMessageClient
from cyrene_exchange_product.integrations.connector_operations import (
    teams_personal_resource_ref,
)
from cyrene_exchange_product.integrations.connector_profiles import parse_connector_host_settings
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    digest_arguments,
)
from cyrene_exchange_product.integrations.models import IntegrationPrincipal
from cyrene_exchange_product.integrations.store import IntegrationStore

_TENANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_BOT_APP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_ACTOR_ID = "11111111-1111-4111-8111-111111111111"
_OTHER_ACTOR_ID = "22222222-2222-4222-8222-222222222222"
_ISSUER = f"https://login.microsoftonline.com/{_TENANT_ID}/v2.0"
_SERVICE_URL = "https://smba.trafficmanager.net/amer/"
_PROFILE_REF = "teams-private-profile"
_CONNECTION_REF = "teams-private-connection"
_GRANT_PATH = "/internal/v1/teams/messages"


def _plugins_root() -> Path:
    """Resolve and verify the exact sibling Plugins checkout used by the spine gate."""

    configured = os.environ.get("CYRENE_PLUGINS_ROOT") or os.environ.get("CYRENE_PLUGINS_WORKTREE")
    if not configured:
        if os.environ.get("CI") == "true" or os.environ.get("CYRENE_TEAMS_SPINE_REQUIRED") == "1":
            pytest.fail("the required pinned Plugins checkout is unavailable")
        pytest.skip("set CYRENE_PLUGINS_ROOT to run the local Teams connector spine")
    root = Path(configured).resolve()
    source = root / "plugins/connectors/teams/src"
    if not (source / "teams_connector/connector.py").is_file():
        pytest.fail("the selected Plugins checkout has no Teams connector source")
    expected_sha = os.environ.get("CYRENE_PLUGINS_SHA")
    if expected_sha:
        observed_sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if observed_sha != expected_sha:
            pytest.fail("Teams connector spine did not load the locked Plugins revision")
    elif os.environ.get("CI") == "true" or os.environ.get("CYRENE_TEAMS_SPINE_REQUIRED") == "1":
        pytest.fail("CYRENE_PLUGINS_SHA is required for the Teams spine gate")
    source_text = str(source)
    if source_text not in sys.path:
        sys.path.insert(0, source_text)
    return root


class _FakeTeamsApp:
    """Capture private sends without opening a Microsoft Teams connection."""

    def __init__(self, *, fail_uncertain: bool = False) -> None:
        self.fail_uncertain = fail_uncertain
        self.calls: list[tuple[str, str, str | None]] = []

    async def send(
        self,
        conversation_id: str,
        text: str,
        *,
        service_url: str | None = None,
    ) -> SimpleNamespace:
        self.calls.append((conversation_id, text, service_url))
        if self.fail_uncertain:
            raise TimeoutError("synthetic unknown delivery state")
        return SimpleNamespace(id="synthetic-private-message")


class _LocalTeamsInvoker:
    """Pass Exchange protobuf bytes directly into the real Teams connector entrypoint."""

    def __init__(self, connector: Any) -> None:
        self.connector = connector
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if (
            kwargs["capability"] != "message.connector.v1"
            or kwargs["interface_version"] != "1"
            or kwargs["method"] != "send_message"
        ):
            raise AssertionError("Exchange invoked an unexpected Teams capability")
        accepted, response = self.connector.on_invoke(
            kwargs["capability"],
            kwargs["method"],
            kwargs["request"].value,
            request_type_url=kwargs["request"].type_url,
            request_id=kwargs.get("request_id"),
        )
        if not accepted:
            raise RuntimeError("the local Teams connector rejected the request")
        return response


class _GrantVerifier:
    """Return exact synthetic claims while preserving one-use grant consumption."""

    def __init__(self) -> None:
        self.claims: dict[bytes, ConnectorGrantClaims] = {}
        self.consumed: set[str] = set()

    def add(self, payload: Mapping[str, Any], *, subject: str = _ACTOR_ID) -> bytes:
        request_id = str(payload["requestId"])
        conversation = dict(payload["conversation"])
        arguments = {
            "targetKind": "owner_private",
            "conversation": conversation,
            "text": str(payload["text"]),
        }
        grant_index = len(self.claims) + 1
        grant = f"synthetic-grant-{grant_index}".encode()
        self.claims[grant] = ConnectorGrantClaims(
            request_id=request_id,
            audience="exchange",
            organization_id="org-teams-private",
            workspace_id="workspace-teams-private",
            principal_issuer=_ISSUER,
            principal_subject=subject,
            connection_ref=_CONNECTION_REF,
            provider_id="msteams",
            profile_ref=_PROFILE_REF,
            operation_id="msteams.message.reply",
            resource_ref=teams_personal_resource_ref(conversation),
            arguments_digest_sha256=bytes.fromhex(digest_arguments(arguments)),
            issued_at_epoch=float(int(time.time())),
            expires_at_epoch=float(int(time.time()) + 60),
            grant_ref=f"sha256:{grant_index:064x}",
        )
        return grant

    def inspect(
        self,
        grant: bytes,
        *,
        expected: Mapping[str, Any] | None = None,
    ) -> ConnectorGrantClaims:
        claims = self.claims.get(grant)
        if claims is None:
            raise PermissionError("unknown synthetic Teams grant")
        if expected is not None:
            observed = {
                "request_id": claims.request_id,
                "organization_id": claims.organization_id,
                "workspace_id": claims.workspace_id,
                "principal_issuer": claims.principal_issuer,
                "principal_subject": claims.principal_subject,
                "connection_ref": claims.connection_ref,
                "provider_id": claims.provider_id,
                "profile_ref": claims.profile_ref,
                "operation_id": claims.operation_id,
                "resource_ref": claims.resource_ref,
                "arguments_digest_sha256": claims.arguments_digest_sha256,
            }
            if any(observed[key] != value for key, value in expected.items()):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Teams connector authorization denied",
                    detail="Synthetic Teams grant scope mismatch.",
                    status=403,
                )
        return claims

    def consume(
        self,
        grant: bytes,
        *,
        expected: Mapping[str, Any],
    ) -> ConnectorGrantClaims:
        claims = self.inspect(grant, expected=expected)
        if claims.grant_ref in self.consumed:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Teams connector authorization denied",
                detail="Synthetic Teams grant was replayed.",
                status=403,
            )
        self.consumed.add(claims.grant_ref)
        return claims


def _profile(*, allowed_actors: list[str] | None = None) -> Any:
    """Build one host-owned profile; an omitted actor list remains disabled."""

    profile: dict[str, Any] = {
        "profileRef": _PROFILE_REF,
        "connectionRef": _CONNECTION_REF,
        "organizationId": "org-teams-private",
        "workspaceId": "workspace-teams-private",
        "tenantId": _TENANT_ID,
        "allowedTeamIds": ["team-private"],
        "allowedChannelIds": [],
        "botAppId": _BOT_APP_ID,
        "directPlugin": {
            "bindingId": "teams-private-binding",
            "connectionRef": "grpcs://teams-private:50051",
            "transport": "local",
        },
        "expectedIssuer": _ISSUER,
    }
    if allowed_actors is not None:
        profile["personalActorSubjects"] = allowed_actors
    settings = parse_connector_host_settings({"teamsMessages": profile})
    assert settings.teams_messages is not None
    return settings.teams_messages


def _payload(*, request_id: str = "teams-private-1") -> dict[str, Any]:
    """Return a fixed, actor-bound private chat request body."""

    return {
        "requestId": request_id,
        "providerId": "msteams",
        "targetKind": "owner_private",
        "conversation": {
            "tenantId": _TENANT_ID,
            "botAppId": _BOT_APP_ID,
            "actorAadObjectId": _ACTOR_ID,
            "conversationId": "a:host-resolved-private-chat",
            "serviceUrl": _SERVICE_URL,
        },
        "text": "The scheduled task needs your attention.",
    }


def _services(
    tmp_path: Path,
    *,
    profile: Any,
    invoker: _LocalTeamsInvoker,
    verifier: _GrantVerifier,
) -> IntegrationServices:
    """Assemble the internal egress route around the exact DirectPlugin seam."""

    tmp_path.mkdir(parents=True, exist_ok=True)
    store = IntegrationStore(tmp_path / "teams-owner-private.sqlite3")
    principal = IntegrationPrincipal(
        issuer=_ISSUER,
        subject=_ACTOR_ID,
        organization_id="org-teams-private",
        workspace_id="workspace-teams-private",
        allowed_operation_ids=frozenset(),
    )
    return IntegrationServices(
        store=store,
        authorizer=None,
        accounts=SimpleNamespace(),  # type: ignore[arg-type]
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=principal,
        connector_grant_verifier=verifier,
        teams_message_profile=profile,
        teams_message_client=TeamsMessageClient(invoker),
    )


def _post_private(
    client: TestClient,
    verifier: _GrantVerifier,
    payload: dict[str, Any],
    *,
    subject: str = _ACTOR_ID,
) -> Any:
    grant = verifier.add(payload, subject=subject)
    return client.post(
        _GRANT_PATH,
        json=payload,
        headers={"x-cyrene-connector-grant-bin": base64.b64encode(grant).decode("ascii")},
    )


def _load_teams_connector(root: Path) -> Any:
    """Load the selected first-party connector implementation without vendor I/O."""

    path = str(root / "plugins/connectors/teams/src")
    if path not in sys.path:
        sys.path.insert(0, path)
    return importlib.import_module("teams_connector.connector").TeamsConnector


def test_exchange_private_send_reaches_pinned_teams_connector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh actor grant carries Exchange's PRIVATE protobuf into the connector."""

    root = _plugins_root()
    connector_type = _load_teams_connector(root)
    monkeypatch.setenv("TEAMS_BOT_APP_SECRET", "synthetic-not-a-credential")
    app = _FakeTeamsApp()
    connector = connector_type(
        {
            "binding_id": "teams-private-binding",
            "bot_app_id": _BOT_APP_ID,
            "tenant_id": _TENANT_ID,
            "allowed_team_ids": ["team-private"],
            "client_secret_env_ref": "TEAMS_BOT_APP_SECRET",
            "personal_chat_enabled": True,
        },
        sdk_app_factory=lambda _config, _secret: app,
    )
    invoker = _LocalTeamsInvoker(connector)
    verifier = _GrantVerifier()
    services = _services(
        tmp_path,
        profile=_profile(allowed_actors=[_ACTOR_ID]),
        invoker=invoker,
        verifier=verifier,
    )
    try:
        with TestClient(
            create_app(
                database_path=tmp_path / "exchange.sqlite3",
                integrations=services,
            )
        ) as client:
            payload = _payload()
            response = _post_private(client, verifier, payload)
            assert response.status_code == 200, response.text
            assert response.json() == {
                "requestId": "teams-private-1",
                "status": "accepted",
                "vendorMessageId": "synthetic-private-message",
                "reasonCode": None,
            }
            assert app.calls == [
                (
                    "a:host-resolved-private-chat",
                    payload["text"],
                    _SERVICE_URL,
                )
            ]
            assert len(invoker.calls) == 1
    finally:
        connector.on_shutdown()
        services.close()


def test_private_actor_route_spoof_and_empty_allowlist_fail_closed(tmp_path: Path) -> None:
    """Actor, grant-bound route, and host actor selection cannot be substituted."""

    root = _plugins_root()
    connector_type = _load_teams_connector(root)
    connector = connector_type(
        {
            "binding_id": "teams-private-binding",
            "bot_app_id": _BOT_APP_ID,
            "tenant_id": _TENANT_ID,
            "allowed_team_ids": ["team-private"],
            "client_secret_env_ref": "TEAMS_BOT_APP_SECRET",
            "personal_chat_enabled": True,
        },
        sdk_app_factory=lambda _config, _secret: _FakeTeamsApp(),
    )
    invoker = _LocalTeamsInvoker(connector)
    verifier = _GrantVerifier()
    services = _services(
        tmp_path,
        profile=_profile(allowed_actors=[_ACTOR_ID]),
        invoker=invoker,
        verifier=verifier,
    )
    try:
        with TestClient(
            create_app(
                database_path=tmp_path / "exchange.sqlite3",
                integrations=services,
            )
        ) as client:
            missing_provider = _payload(request_id="missing-provider")
            missing_provider.pop("providerId")
            assert client.post(_GRANT_PATH, json=missing_provider).status_code == 400

            unsigned_profile_ref = {
                **_payload(request_id="unsigned-profile-ref"),
                "profileRef": _PROFILE_REF,
            }
            assert client.post(_GRANT_PATH, json=unsigned_profile_ref).status_code == 400

            actor_spoof = _payload(request_id="actor-spoof")
            actor_spoof["conversation"]["actorAadObjectId"] = _OTHER_ACTOR_ID
            denied_actor = _post_private(client, verifier, actor_spoof)
            assert denied_actor.status_code == 403

            route_spoof = _payload(request_id="route-spoof")
            grant = verifier.add(route_spoof)
            changed_route = {
                **route_spoof,
                "conversation": {
                    **route_spoof["conversation"],
                    "conversationId": "a:substituted-private-chat",
                },
            }
            denied_route = client.post(
                _GRANT_PATH,
                json=changed_route,
                headers={"x-cyrene-connector-grant-bin": base64.b64encode(grant).decode("ascii")},
            )
            assert denied_route.status_code == 403

            revoked_verifier = _GrantVerifier()
            revoked_services = _services(
                tmp_path / "revoked",
                profile=_profile(),
                invoker=invoker,
                verifier=revoked_verifier,
            )
            try:
                with TestClient(
                    create_app(
                        database_path=tmp_path / "revoked-exchange.sqlite3",
                        integrations=revoked_services,
                    )
                ) as revoked_client:
                    denied_profile = _post_private(
                        revoked_client,
                        revoked_verifier,
                        _payload(request_id="host-profile-disabled"),
                    )
                    assert denied_profile.status_code == 403
            finally:
                revoked_services.close()

            assert invoker.calls == []
    finally:
        connector.on_shutdown()
        services.close()


def test_unknown_private_delivery_duplicate_returns_receipt_without_resend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown plugin result is durable and an exact replay never sends twice."""

    root = _plugins_root()
    connector_type = _load_teams_connector(root)
    monkeypatch.setenv("TEAMS_BOT_APP_SECRET", "synthetic-not-a-credential")
    app = _FakeTeamsApp(fail_uncertain=True)
    connector = connector_type(
        {
            "binding_id": "teams-private-binding",
            "bot_app_id": _BOT_APP_ID,
            "tenant_id": _TENANT_ID,
            "allowed_team_ids": ["team-private"],
            "client_secret_env_ref": "TEAMS_BOT_APP_SECRET",
            "personal_chat_enabled": True,
        },
        sdk_app_factory=lambda _config, _secret: app,
    )
    invoker = _LocalTeamsInvoker(connector)
    verifier = _GrantVerifier()
    services = _services(
        tmp_path,
        profile=_profile(allowed_actors=[_ACTOR_ID]),
        invoker=invoker,
        verifier=verifier,
    )
    try:
        with TestClient(
            create_app(
                database_path=tmp_path / "exchange.sqlite3",
                integrations=services,
            )
        ) as client:
            payload = _payload(request_id="unknown-private-delivery")
            grant = verifier.add(payload)
            headers = {"x-cyrene-connector-grant-bin": base64.b64encode(grant).decode("ascii")}
            first = client.post(_GRANT_PATH, json=payload, headers=headers)
            second = client.post(_GRANT_PATH, json=payload, headers=headers)
            assert first.status_code == second.status_code == 200
            assert (
                first.json()
                == second.json()
                == {
                    "requestId": "unknown-private-delivery",
                    "status": "uncertain",
                    "reasonCode": "teams_delivery_outcome_unknown",
                }
            )
            assert app.calls == [
                (
                    "a:host-resolved-private-chat",
                    payload["text"],
                    _SERVICE_URL,
                )
            ]
    finally:
        connector.on_shutdown()
        services.close()
