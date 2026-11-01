"""Bilibili Product routing, authorization, and fixed lease projections."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.authorization_cloud import ProviderObservationUnavailable
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    AuthorizationCloudProfileRegistry,
    parse_authorization_cloud_settings,
)
from cyrene_exchange_product.integrations.authorization_cloud_provider import (
    AuthorizationCloudDirectProvider,
)
from cyrene_exchange_product.integrations.clients import IntegrationAccountCenterPort
from cyrene_exchange_product.integrations.connector_operations import (
    ConnectorOperationDispatcher,
    _account_lease_target,
    _resource_projection,
    _resource_ref,
    _validate_bilibili_arguments,
    connector_binding_tools,
)
from cyrene_exchange_product.integrations.connector_security import (
    NavigatorHmacAuthenticator,
    NavigatorHmacSettings,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationPrincipal,
)
from cyrene_exchange_product.integrations.ports import ProviderProfileMetadata
from cyrene_exchange_product.integrations.store import IntegrationStore

ISSUER = "https://identity.example.test"
SUBJECT = "bilibili-owner"
ORG = "org-bilibili"
WORKSPACE = "workspace-bilibili"
PROFILE_REF = "00000000-0000-4000-8000-000000000101"
ACTOR = IntegrationPrincipal(
    issuer=ISSUER,
    subject=SUBJECT,
    organization_id=ORG,
    workspace_id=WORKSPACE,
    allowed_operation_ids=frozenset(
        {
            "navigator.connector.operator.v1",
            "bilibili.auth.qr.begin",
            "bilibili.auth.qr.status",
            "bilibili.search",
            "bilibili.dm.send",
            "integrationCreateConnection",
        }
    ),
)


def _profile() -> ProviderProfileMetadata:
    return ProviderProfileMetadata(
        profile_ref=PROFILE_REF,
        provider="bilibili",
        identity_ref="12345",
        target_scope={"schema_version": 1, "account_id": "12345"},
        auth_status="healthy",
        external_subject="12345",
        expires_at=1_900_000_000,
        auth_mode="session_cookie",
        access_mode="actor_owned",
        credential_revision=1,
    )


class _Authorizer:
    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal:
        if bearer_token != "first-party-token" or workspace_id != WORKSPACE:
            raise PermissionError("identity denied")
        return ACTOR


class _Accounts:
    def __init__(self, profile: ProviderProfileMetadata) -> None:
        self.profile = profile

    def list_provider_profiles(self, principal: IntegrationPrincipal) -> dict[str, Any]:
        assert principal == ACTOR
        return {
            "profiles": [
                {
                    "profile_ref": self.profile.profile_ref,
                    "provider": self.profile.provider,
                    "identity_ref": self.profile.identity_ref,
                    "target_scope": dict(self.profile.target_scope),
                    "auth_status": self.profile.auth_status,
                    "external_subject": self.profile.external_subject,
                    "expires_at": self.profile.expires_at,
                    "auth_mode": self.profile.auth_mode,
                    "access_mode": self.profile.access_mode,
                    "credential_revision": self.profile.credential_revision,
                }
            ]
        }

    def get_owned_provider_profile(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        provider: str | None = None,
    ) -> ProviderProfileMetadata | None:
        if (
            principal.issuer != ACTOR.issuer
            or principal.subject != ACTOR.subject
            or principal.organization_id != ACTOR.organization_id
            or principal.workspace_id != ACTOR.workspace_id
            or profile_ref != self.profile.profile_ref
            or provider not in {None, "bilibili"}
        ):
            return None
        return self.profile

    def list_owned_provider_profiles(
        self,
        principal: IntegrationPrincipal,
        *,
        provider: str | None = None,
    ) -> tuple[ProviderProfileMetadata, ...]:
        if (
            principal.issuer != ACTOR.issuer
            or principal.subject != ACTOR.subject
            or principal.organization_id != ACTOR.organization_id
            or principal.workspace_id != ACTOR.workspace_id
        ):
            return ()
        return (self.profile,) if provider in {None, "bilibili"} else ()


class _BilibiliAuthProvider:
    def __init__(self, png: bytes, profile: ProviderProfileMetadata) -> None:
        self.png = png
        self.profile = profile
        self.calls: list[dict[str, Any]] = []

    def invoke_bilibili_auth_tool(
        self,
        principal: IntegrationPrincipal,
        **kwargs: Any,
    ) -> dict[str, Any]:
        assert principal.issuer == ACTOR.issuer
        assert principal.subject == ACTOR.subject
        assert principal.organization_id == ACTOR.organization_id
        assert principal.workspace_id == ACTOR.workspace_id
        self.calls.append(kwargs)
        if kwargs["operation_id"] == "bilibili.auth.qr.begin":
            return {
                "status": "PENDING",
                "login_flow_id": "a" * 64,
                "qr_png_base64": base64.b64encode(self.png).decode("ascii"),
                "qr_png_sha256": hashlib.sha256(self.png).hexdigest(),
                "expires_at": "2030-01-01T00:10:00Z",
            }
        assert kwargs["operation_id"] == "bilibili.auth.qr.status"
        return {
            "status": "LINKED",
            "profile": {
                "profile_ref": self.profile.profile_ref,
                "provider": "bilibili",
                "auth_status": "healthy",
                "external_subject": self.profile.external_subject,
                "expires_at": self.profile.expires_at,
                "auth_mode": "session_cookie",
                "access_mode": "actor_owned",
                "credential_revision": self.profile.credential_revision,
            },
        }


class _Registry:
    def __init__(self) -> None:
        profile = SimpleNamespace(
            profile_ref="host-bilibili",
            provider="bilibili",
            access_mode="actor_owned",
            caller_workload="cyrene.exchange.integrations",
            targets={},
            organization_id=ORG,
            workspace_id=WORKSPACE,
            expected_issuer=ISSUER,
        )
        self.settings = SimpleNamespace(
            bilibili_auth_binding_ref="host-bilibili",
            profiles={"host-bilibili": profile},
        )

    @staticmethod
    def principal_allowed_for_profile(
        principal: IntegrationPrincipal,
        profile: Any,
    ) -> bool:
        return (
            principal.issuer == profile.expected_issuer
            and principal.organization_id == profile.organization_id
            and principal.workspace_id == profile.workspace_id
        )


class _Authority:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def authorize_connector_operation(self, **kwargs: Any) -> bytes:
        self.calls.append(kwargs)
        return b"directory-grant"


class _GrantVerifier:
    configured = True

    def __init__(self) -> None:
        self.validated: list[dict[str, Any]] = []
        self.consumed: list[dict[str, Any]] = []

    def validate_authority_response(
        self,
        grant: bytes,
        *,
        expected: dict[str, Any],
    ) -> SimpleNamespace:
        assert grant == b"directory-grant"
        self.validated.append(expected)
        return SimpleNamespace(grant_ref="directory-grant-ref")

    def consume(self, grant: bytes, *, expected: dict[str, Any]) -> SimpleNamespace:
        assert grant == b"directory-grant"
        self.consumed.append(expected)
        return SimpleNamespace(grant_ref="directory-grant-ref")


def _signed_internal_body(
    path: str,
    payload: dict[str, Any],
    *,
    key: bytes,
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    message = b"POST\n" + path.encode("ascii") + b"\n" + timestamp.encode("ascii") + b"\n" + body
    return body, {
        "content-type": "application/json",
        "x-cyrene-navigator-key-id": "navigator-bilibili-test-v1",
        "x-cyrene-navigator-timestamp": timestamp,
        "x-cyrene-navigator-signature": hmac.new(key, message, hashlib.sha256).hexdigest(),
    }


def test_bilibili_provider_catalog_hides_qr_and_marks_only_writes_mutating() -> None:
    tools = connector_binding_tools("bilibili")
    ids = {str(tool["operationId"]) for tool in tools}
    assert len(ids) == 11
    assert not any(operation.startswith("bilibili.auth.qr.") for operation in ids)
    assert {str(tool["operationId"]) for tool in tools if tool["mutating"]} == {
        "bilibili.comment.create",
        "bilibili.dynamic.publish",
        "bilibili.dm.send",
    }


def test_bilibili_host_binding_fails_closed_on_wrong_direct_plugin_identity(tmp_path: Path) -> None:
    registry = _Registry()

    class Health:
        def observe(self) -> SimpleNamespace:
            return SimpleNamespace(
                status="SERVING",
                plugin_id="another.connector",
                capabilities=("tool.provider.v1",),
            )

    store = IntegrationStore(tmp_path / "wrong-plugin-health.sqlite3")
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,  # type: ignore[arg-type]
        provider_clients={},
        provider_health_clients={"host-bilibili": Health()},
        email_client=None,
        account_center=None,
        current_context_resolver=None,
        context_key=lambda _reference: b"k" * 32,
    )
    try:
        with pytest.raises(ProviderObservationUnavailable):
            provider._require_bilibili_runtime(registry.settings.profiles["host-bilibili"])
    finally:
        store.close()


def test_bilibili_lease_projection_omits_query_and_write_content() -> None:
    search = {"keyword": "cat videos", "search_type": "video", "page": 3}
    target = _resource_projection(
        provider_id="bilibili",
        profile_ref=PROFILE_REF,
        operation_id="bilibili.search",
        arguments=search,
    )
    assert target == {"search_type": "video"}
    assert _account_lease_target("bilibili", "bilibili.search", target, search) == target

    write = {"peer_user_id": "123", "content": "hello"}
    dm_target = _resource_projection(
        provider_id="bilibili",
        profile_ref=PROFILE_REF,
        operation_id="bilibili.dm.send",
        arguments=write,
    )
    assert dm_target == {"peer_user_id": "123"}
    assert _account_lease_target("bilibili", "bilibili.dm.send", dm_target, write) == dm_target
    assert (
        hashlib.sha256(str(search).encode()).digest()
        != hashlib.sha256(str({**search, "page": 4}).encode()).digest()
    )


def test_bilibili_arguments_are_closed_and_comment_target_is_exact() -> None:
    _validate_bilibili_arguments(
        "bilibili.comment.create",
        {
            "video_id": "BV1234567890",
            "root_comment_id": "0",
            "parent_comment_id": "0",
            "content": "top-level comment",
        },
    )
    with pytest.raises(PermissionError, match="inconsistent"):
        _validate_bilibili_arguments(
            "bilibili.comment.create",
            {
                "video_id": "BV1234567890",
                "root_comment_id": "0",
                "parent_comment_id": "123",
                "content": "reply",
            },
        )
    with pytest.raises(PermissionError, match="fixed operation schema"):
        _validate_bilibili_arguments(
            "bilibili.dm.send",
            {"peer_user_id": "123", "content": "secret", "cookie": "model"},
        )


def test_bilibili_write_dispatch_requires_work_operation_key(tmp_path: Path) -> None:
    registry = AuthorizationCloudProfileRegistry(
        parse_authorization_cloud_settings(
            {
                "currentAuthority": {"contexts": []},
                "profiles": {
                    "bilibili-host": {
                        "provider": "bilibili",
                        "directPlugin": {
                            "bindingId": "bilibili-runtime",
                            "connectionRef": "grpc://127.0.0.1:5100",
                            "transport": "local",
                        },
                        "callerWorkload": "cyrene.exchange.integrations",
                        "audience": "cyrene-exchange",
                        "expectedIssuer": ISSUER,
                        "contextKeyRef": "keys/bilibili",
                        "organizationId": ORG,
                        "workspaceId": WORKSPACE,
                        "allowedActors": [{"issuer": ISSUER, "subject": SUBJECT}],
                        "accessMode": "actor_owned",
                    }
                },
            },
            email_value={"enabled": False},
        )
    )
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = store.create_connection(
        ACTOR,
        CreateIntegrationConnection(
            provider="bilibili",
            binding_ref="bilibili-host",
            account_link_ref=PROFILE_REF,
        ),
        idempotency_key="bilibili-connection",
    )
    dispatcher = ConnectorOperationDispatcher(
        store=store,
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=registry,
    )
    arguments = {"peer_user_id": "123", "content": "hello"}
    target = _resource_projection(
        provider_id="bilibili",
        profile_ref=PROFILE_REF,
        operation_id="bilibili.dm.send",
        arguments=arguments,
    )
    resource_ref = _resource_ref(
        provider_id="bilibili",
        profile_ref=PROFILE_REF,
        operation_id="bilibili.dm.send",
        target=target,
    )
    try:
        with pytest.raises(PermissionError, match="stable host-generated"):
            dispatcher.prepare_connection_operation(
                principal=ACTOR,
                connection=connection,
                provider_id="bilibili",
                profile_ref=PROFILE_REF,
                operation_id="bilibili.dm.send",
                resource_ref=resource_ref,
                arguments=arguments,
                request_id="volatile-request-1",
            )
        prepared = dispatcher.prepare_connection_operation(
            principal=ACTOR,
            connection=connection,
            provider_id="bilibili",
            profile_ref=PROFILE_REF,
            operation_id="bilibili.dm.send",
            resource_ref=resource_ref,
            arguments=arguments,
            request_id="volatile-request-2",
            idempotency_key="work-operation:00000000-0000-4000-8000-000000000222",
        )
        assert prepared.account_lease_target == {"peer_user_id": "123"}
        assert prepared.idempotency_key == ("work-operation:00000000-0000-4000-8000-000000000222")
    finally:
        store.close()


def test_exchange_account_profile_port_returns_actor_listed_metadata() -> None:
    profile = _profile()

    class Client:
        def list_provider_profiles(self, principal: IntegrationPrincipal) -> dict[str, Any]:
            assert principal == ACTOR
            return {
                "profiles": [
                    {
                        "profile_ref": profile.profile_ref,
                        "provider": profile.provider,
                        "identity_ref": profile.identity_ref,
                        "target_scope": dict(profile.target_scope),
                        "auth_status": profile.auth_status,
                        "external_subject": profile.external_subject,
                        "expires_at": profile.expires_at,
                        "auth_mode": profile.auth_mode,
                        "access_mode": profile.access_mode,
                        "credential_revision": profile.credential_revision,
                    }
                ]
            }

    port = IntegrationAccountCenterPort(Client())  # type: ignore[arg-type]
    assert (
        port.get_owned_provider_profile(ACTOR, profile_ref=profile.profile_ref, provider="bilibili")
        == profile
    )
    assert (
        port.get_owned_provider_profile(
            ACTOR, profile_ref="00000000-0000-4000-8000-000000000999", provider="bilibili"
        )
        is None
    )


def test_account_center_port_accepts_actor_owned_bilibili_credential_lease() -> None:
    target = {"peer_user_id": "9988"}
    digest = "a" * 64

    class Client:
        def create_provider_credential_lease(
            self,
            principal: IntegrationPrincipal,
            **kwargs: Any,
        ) -> dict[str, Any]:
            assert principal == ACTOR
            return {
                "lease_ref": "00000000-0000-4000-8000-000000000301",
                "profile_ref": PROFILE_REF,
                "provider": "bilibili",
                "operation_id": "bilibili.dm.send",
                "target": target,
                "arguments_sha256": digest,
                "expires_at": 1_900_000_000,
            }

    lease = IntegrationAccountCenterPort(Client()).create_provider_credential_lease(
        ACTOR,
        profile_ref=PROFILE_REF,
        operation_id="bilibili.dm.send",
        target=target,
        arguments_sha256=digest,
    )
    assert lease.provider == "bilibili"
    assert lease.profile_ref == PROFILE_REF
    assert lease.operation_id == "bilibili.dm.send"
    assert lease.target == target
    assert lease.arguments_sha256 == digest


def test_bilibili_profile_list_lookup_and_qr_routes_use_server_owned_binding(
    tmp_path: Path,
) -> None:
    profile = _profile()
    accounts = _Accounts(profile)
    qr_png = b"\x89PNG\r\n\x1a\nsynthetic-qr"
    provider = _BilibiliAuthProvider(qr_png, profile)
    authority = _Authority()
    verifier = _GrantVerifier()
    services = IntegrationServices(
        store=IntegrationStore(tmp_path / "integrations.sqlite3"),
        authorizer=_Authorizer(),  # type: ignore[arg-type]
        accounts=accounts,  # type: ignore[arg-type]
        account_center=accounts,
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=ACTOR,
        authorization_profile_registry=_Registry(),
        authorization_cloud=provider,
        connector_grant_authority=authority,
        connector_grant_verifier=verifier,
    )
    app = create_app(database_path=tmp_path / "exchange-product.sqlite3", integrations=services)
    headers = {
        "Authorization": "Bearer first-party-token",
        "X-Cyrene-Workspace-Id": WORKSPACE,
    }

    with TestClient(app) as client:
        listed = client.get(
            "/api/v1/accounts/provider-profiles?provider=bilibili",
            headers=headers,
        )
        exact = client.get(
            f"/api/v1/accounts/provider-profiles/bilibili/{profile.profile_ref}",
            headers=headers,
        )
        begin = client.post(
            "/api/v1/accounts/provider-profiles/bilibili/qr-sessions",
            headers={**headers, "Idempotency-Key": "begin-bili-account-1"},
        )
        repeat = client.post(
            "/api/v1/accounts/provider-profiles/bilibili/qr-sessions",
            headers={**headers, "Idempotency-Key": "begin-bili-account-1"},
        )
        poll = client.get(
            "/api/v1/accounts/provider-profiles/bilibili/qr-sessions/" + "a" * 64,
            headers=headers,
        )
        injected = client.post(
            "/api/v1/accounts/provider-profiles/bilibili/qr-sessions",
            headers={**headers, "Idempotency-Key": "begin-bili-account-2"},
            json={"binding_ref": "attacker", "url": "https://example.invalid"},
        )

    assert listed.status_code == 200, listed.text
    assert listed.json()["profiles"][0]["profileRef"] == profile.profile_ref
    assert exact.status_code == 200, exact.text
    assert exact.json()["provider"] == "bilibili"
    assert "credential_json" not in exact.text
    assert begin.status_code == 202, begin.text
    assert repeat.status_code == 202, repeat.text
    assert begin.json() == repeat.json()
    assert begin.json()["status"] == "PENDING"
    assert begin.json()["qrPngSha256"] == hashlib.sha256(qr_png).hexdigest()
    assert "profileRef" not in begin.json()
    assert poll.status_code == 200, poll.text
    assert poll.json()["status"] == "LINKED"
    assert poll.json()["profile"]["profileRef"] == profile.profile_ref
    assert "credential_json" not in poll.text
    assert "SESSDATA" not in poll.text
    assert injected.status_code == 422
    begin_calls = [
        call for call in provider.calls if call["operation_id"] == "bilibili.auth.qr.begin"
    ]
    assert len(begin_calls) == 2
    assert begin_calls[0]["arguments"] == begin_calls[1]["arguments"]
    assert begin_calls[0]["arguments"]["idempotency_key"] != "begin-bili-account-1"
    assert "binding_ref" not in begin_calls[0]["arguments"]
    assert len(authority.calls) == 3
    assert {call["provider_id"] for call in authority.calls} == {"bilibili"}
    assert {call["connection_ref"] for call in authority.calls} == {"bilibili-auth:host-bilibili"}
    assert {call["profile_ref"] for call in authority.calls} == {"host-bilibili"}
    assert {call["operation_id"] for call in authority.calls} == {
        "bilibili.auth.qr.begin",
        "bilibili.auth.qr.status",
    }
    assert len(verifier.consumed) == 3


def test_bilibili_internal_routes_require_signed_actor_and_directory_grants(
    tmp_path: Path,
) -> None:
    profile = _profile()
    accounts = _Accounts(profile)
    provider = _BilibiliAuthProvider(b"\x89PNG\r\n\x1a\ninternal-qr", profile)
    authority = _Authority()
    verifier = _GrantVerifier()
    store = IntegrationStore(tmp_path / "internal-integrations.sqlite3")
    connection = store.create_connection(
        ACTOR,
        CreateIntegrationConnection(
            provider="bilibili",
            binding_ref="bilibili-host",
            account_link_ref=PROFILE_REF,
        ),
        idempotency_key="bilibili-internal-connection",
    )
    key = b"b" * 32
    assert len(key) == 32
    key_file = tmp_path / "navigator-hmac.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    services = IntegrationServices(
        store=store,
        authorizer=None,
        accounts=accounts,  # type: ignore[arg-type]
        account_center=accounts,
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=ACTOR,
        authorization_profile_registry=_Registry(),
        authorization_cloud=provider,
        navigator_hmac_authenticator=NavigatorHmacAuthenticator(
            NavigatorHmacSettings(
                key_id="navigator-bilibili-test-v1",
                key_file=key_file,
            ),
            replay_guard=store,
        ),
        connector_grant_authority=authority,
        connector_grant_verifier=verifier,
    )
    app = create_app(database_path=tmp_path / "internal-exchange.sqlite3", integrations=services)
    base = {
        "principal_issuer": ISSUER,
        "principal_subject": SUBJECT,
        "organization_id": ORG,
        "workspace_id": WORKSPACE,
    }

    def post(client: TestClient, path: str, request_id: str, **selectors: Any) -> Any:
        payload = {"request_id": request_id, **base, **selectors}
        body, headers = _signed_internal_body(path, payload, key=key)
        return client.post(path, content=body, headers=headers)

    with TestClient(app) as client:
        listed = post(client, "/internal/v1/bilibili/provider-profiles/list", "list-actor-1")
        exact = post(
            client,
            "/internal/v1/bilibili/provider-profiles/get",
            "get-actor-1",
            profile_ref=PROFILE_REF,
        )
        connections = post(client, "/internal/v1/bilibili/connections/list", "connections-1")
        begin = post(
            client,
            "/internal/v1/bilibili/qr-sessions/begin",
            "qr-begin-1",
            idempotency_key="navigator-bilibili-link-1",
        )
        poll = post(
            client,
            "/internal/v1/bilibili/qr-sessions/status",
            "qr-status-1",
            login_flow_id="a" * 64,
        )
        intruder = post(
            client,
            "/internal/v1/bilibili/provider-profiles/get",
            "get-intruder-1",
            principal_subject="another-actor",
            profile_ref=PROFILE_REF,
        )
        extra_selector = post(
            client,
            "/internal/v1/bilibili/qr-sessions/begin",
            "qr-begin-injected-1",
            idempotency_key="navigator-bilibili-link-2",
            binding_ref="attacker-selected",
        )
        bearer_body, bearer_headers = _signed_internal_body(
            "/internal/v1/bilibili/provider-profiles/list",
            {"request_id": "list-bearer-1", **base},
            key=key,
        )
        bearer = client.post(
            "/internal/v1/bilibili/provider-profiles/list",
            content=bearer_body,
            headers={**bearer_headers, "Authorization": "Bearer service-token"},
        )

    assert listed.status_code == 200, listed.text
    assert listed.json()["profiles"][0]["profileRef"] == PROFILE_REF
    assert "credential_json" not in listed.text
    assert exact.status_code == 200, exact.text
    assert exact.json()["profileRef"] == PROFILE_REF
    assert connections.status_code == 200, connections.text
    assert connections.json()["connections"] == [
        {
            "connectionRef": str(connection.id),
            "provider": "bilibili",
            "profileRef": PROFILE_REF,
            "displayName": connection.display_name,
            "enabled": True,
            "createdAt": connection.created_at.isoformat().replace("+00:00", "Z"),
            "updatedAt": connection.updated_at.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert begin.status_code == 200, begin.text
    assert begin.json()["status"] == "PENDING"
    assert poll.status_code == 200, poll.text
    assert poll.json()["status"] == "LINKED"
    assert "credential_json" not in poll.text
    assert intruder.status_code == 404
    assert extra_selector.status_code == 400
    assert bearer.status_code == 401
    assert len(authority.calls) == 2
    assert [call["operation_id"] for call in authority.calls] == [
        "bilibili.auth.qr.begin",
        "bilibili.auth.qr.status",
    ]
    assert [item["request_id"] for item in verifier.consumed] == [
        "qr-begin-1",
        "qr-status-1",
    ]
