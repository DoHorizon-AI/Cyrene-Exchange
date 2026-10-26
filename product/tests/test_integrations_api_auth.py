"""Focused authentication tests for the opt-in Product integration REST API."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import ssl
import threading
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import grpc
import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

import cyrene_exchange_product.cli as exchange_cli
import cyrene_exchange_product.integrations.cli as integration_cli
import cyrene_exchange_product.server as product_server
from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.cli import _integration_listener_tls_options
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2 as authority_wire,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2_grpc as authority_grpc,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.product.v2 import (
    product_api_pb2 as product_wire,
)
from cyrene_exchange_product.integrations.api import (
    IntegrationServices,
    _invoke_connector_dispatcher,
    _teams_resource_ref,
)
from cyrene_exchange_product.integrations.auth import PlatformAuthorityIdentityVerifier
from cyrene_exchange_product.integrations.clients import DirectPluginHealthClient
from cyrene_exchange_product.integrations.connector_operations import (
    ConnectorOperationDispatcher,
    _resource_projection,
    _resource_ref,
)
from cyrene_exchange_product.integrations.connector_profiles import parse_connector_host_settings
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    NavigatorHmacAuthenticator,
    NavigatorHmacSettings,
    digest_arguments,
    navigator_hmac_body_limit,
)
from cyrene_exchange_product.integrations.models import (
    AuthorizationCapabilityRecord,
    AuthorizationHealthRecord,
    AuthorizationState,
    CreateActorBinding,
    CreateIntegrationConnection,
    CreateSyncBinding,
    IntegrationConnection,
    IntegrationPrincipal,
    LoginState,
    ResourceSnapshot,
    SnapshotFreshness,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


def test_system_notification_grant_mint_resolves_exact_profile_owner_and_route(
    tmp_path: Path,
) -> None:
    """The signed Navigator grant path admits only the configured notification identity."""

    tenant_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    owner_subject = "11111111-1111-4111-8111-111111111111"
    settings = parse_connector_host_settings(
        {
            "teamsMessages": {
                "profileRef": "teams-chat-host",
                "connectionRef": "teams-connection",
                "organizationId": "org-teams",
                "workspaceId": "workspace-teams",
                "tenantId": tenant_id,
                "allowedTeamIds": ["team-1"],
                "allowedChannelIds": ["channel-1"],
                "botAppId": "bot-app",
                "directPlugin": {
                    "bindingId": "teams-ingress",
                    "connectionRef": "grpcs://teams-ingress:50051",
                    "transport": "local",
                },
                "expectedIssuer": issuer,
                "systemNotification": {
                    "profileRef": "teams-notifications-v1",
                    "ownerSubject": owner_subject,
                    "fixedRoute": {
                        "tenantId": tenant_id,
                        "teamId": "team-1",
                        "channelId": "channel-1",
                        "conversationId": "19:conversation-id@thread.tacv2",
                        "rootThreadId": "1740000000000",
                        "serviceUrl": "https://smba.trafficmanager.net/amer/",
                    },
                },
            }
        }
    )
    root_profile = settings.teams_messages
    assert root_profile is not None
    notification_profile = root_profile.profile_for_ref("teams-notifications-v1")
    assert notification_profile is not None
    key = b"n" * 32
    key_file = tmp_path / "navigator-system-notification.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    store = IntegrationStore(tmp_path / "system-notification.sqlite3")
    authority_calls: list[dict[str, Any]] = []
    grant_claims: dict[bytes, ConnectorGrantClaims] = {}

    class Authority:
        def authorize_connector_operation(self, **kwargs: Any) -> bytes:
            authority_calls.append(kwargs)
            return b"signed-synthetic-authority-grant"

    class GrantVerifier:
        def validate_authority_response(
            self,
            grant: bytes,
            *,
            expected: Mapping[str, Any],
        ) -> ConnectorGrantClaims:
            now_epoch = float(int(time.time()))
            claims = ConnectorGrantClaims(
                request_id=str(expected["request_id"]),
                audience="exchange",
                organization_id=str(expected["organization_id"]),
                workspace_id=str(expected["workspace_id"]),
                principal_issuer=str(expected["principal_issuer"]),
                principal_subject=str(expected["principal_subject"]),
                connection_ref=str(expected["connection_ref"]),
                provider_id=str(expected["provider_id"]),
                profile_ref=str(expected["profile_ref"]),
                operation_id=str(expected["operation_id"]),
                resource_ref=str(expected["resource_ref"]),
                arguments_digest_sha256=expected["arguments_digest_sha256"],
                issued_at_epoch=now_epoch,
                expires_at_epoch=now_epoch + 15,
                grant_ref="sha256:" + "c" * 64,
            )
            grant_claims[grant] = claims
            return claims

        def inspect(
            self,
            grant: bytes,
            *,
            expected: Mapping[str, Any] | None = None,
        ) -> ConnectorGrantClaims:
            claims = grant_claims.get(grant)
            if claims is None:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Connector authorization denied",
                    detail="Synthetic grant is unavailable.",
                    status=403,
                )
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
                        title="Connector authorization denied",
                        detail="Synthetic grant scope mismatch.",
                        status=403,
                    )
            return claims

        def consume(
            self,
            grant: bytes,
            *,
            expected: Mapping[str, Any],
        ) -> ConnectorGrantClaims:
            return self.inspect(grant, expected=expected)

    class MessageClient:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def send_reply(self, **kwargs: Any) -> Any:
            self.calls.append(kwargs)
            return SimpleNamespace(
                accepted=True,
                vendor_message_id="synthetic-message-1",
                evidence={"status": "ACCEPTED"},
            )

    dispatcher = ConnectorOperationDispatcher(
        store=store,
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
    )
    grant_verifier = GrantVerifier()
    message_client = MessageClient()
    owner = IntegrationPrincipal(
        issuer=issuer,
        subject=owner_subject,
        organization_id="org-teams",
        workspace_id="workspace-teams",
        allowed_operation_ids=frozenset(),
    )
    services = IntegrationServices(
        store=store,
        authorizer=None,
        accounts=SimpleNamespace(),  # type: ignore[arg-type]
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=owner,
        navigator_hmac_authenticator=NavigatorHmacAuthenticator(
            NavigatorHmacSettings(key_id="navigator-system-test-v1", key_file=key_file),
            replay_guard=store,
        ),
        connector_grant_authority=Authority(),
        connector_grant_verifier=grant_verifier,
        connector_operation_dispatcher=dispatcher,
        teams_message_profile=root_profile,
        teams_message_client=message_client,
    )
    app = create_app(
        database_path=tmp_path / "system-notification.sqlite3",
        integrations=services,
    )
    path = "/internal/v1/connector-operation-grants"
    route = {
        "tenantId": tenant_id,
        "teamId": "team-1",
        "channelId": "channel-1",
        "conversationId": "19:conversation-id@thread.tacv2",
        "rootThreadId": "1740000000000",
        "serviceUrl": "https://smba.trafficmanager.net/amer/",
    }
    arguments = {"conversation": route, "text": "Credential authorization needs attention."}

    def signed_headers(body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        message = (
            b"POST\n" + path.encode("utf-8") + b"\n" + timestamp.encode("ascii") + b"\n" + body
        )
        return {
            "content-type": "application/json",
            "x-cyrene-navigator-key-id": "navigator-system-test-v1",
            "x-cyrene-navigator-timestamp": timestamp,
            "x-cyrene-navigator-signature": hmac.new(
                key,
                message,
                hashlib.sha256,
            ).hexdigest(),
        }

    def grant_payload(
        *,
        request_id: str,
        profile_ref: str = "teams-notifications-v1",
        subject: str = owner_subject,
        selected_arguments: dict[str, Any] = arguments,
    ) -> bytes:
        payload = {
            "request_id": request_id,
            "workspace_id": "workspace-teams",
            "principal_issuer": issuer,
            "principal_subject": subject,
            "connection_ref": "teams-connection",
            "provider_id": "msteams",
            "profile_ref": profile_ref,
            "operation_id": "msteams.message.reply",
            "resource_ref": _teams_resource_ref(selected_arguments["conversation"]),
            "arguments": selected_arguments,
            "arguments_digest_sha256": digest_arguments(selected_arguments),
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    try:
        with TestClient(app) as client:
            accepted_body = grant_payload(request_id="teams-notify-accepted")
            accepted = client.post(
                path,
                content=accepted_body,
                headers=signed_headers(accepted_body),
            )
            assert accepted.status_code == 200, accepted.text
            assert accepted.json()["claims"]["profileRef"] == "teams-notifications-v1"
            assert authority_calls[-1]["principal_subject"] == owner_subject
            notification_body = {
                "requestId": "teams-notify-accepted",
                "conversation": route,
                "text": arguments["text"],
            }
            sent = client.post(
                "/internal/v1/teams/messages",
                json=notification_body,
                headers={"x-cyrene-connector-grant-bin": accepted.json()["connectorGrantBin"]},
            )
            assert sent.status_code == 200, sent.text
            assert sent.json()["status"] == "accepted"
            assert message_client.calls[0]["root_thread_id"] == "1740000000000"
            wrong_thread = client.post(
                "/internal/v1/teams/messages",
                json={
                    **notification_body,
                    "conversation": {**route, "rootThreadId": "1740000000001"},
                },
                headers={"x-cyrene-connector-grant-bin": accepted.json()["connectorGrantBin"]},
            )
            assert wrong_thread.status_code == 403, wrong_thread.text
            assert len(message_client.calls) == 1

            bad_cases = (
                grant_payload(
                    request_id="teams-notify-host-alias",
                    profile_ref="teams-chat-host-alias",
                ),
                grant_payload(
                    request_id="teams-notify-wrong-owner",
                    subject="22222222-2222-4222-8222-222222222222",
                ),
                grant_payload(
                    request_id="teams-notify-wrong-thread",
                    selected_arguments={
                        "conversation": {**route, "rootThreadId": "1740000000001"},
                        "text": arguments["text"],
                    },
                ),
            )
            for raw_body in bad_cases:
                rejected = client.post(path, content=raw_body, headers=signed_headers(raw_body))
                assert rejected.status_code == 403, rejected.text
            assert len(authority_calls) == 1
    finally:
        services.close()


def test_slow_connector_dispatch_keeps_event_loop_responsive() -> None:
    """A bounded provider wait must not stall concurrent async requests."""

    release = threading.Event()
    watchdog = threading.Timer(2.0, release.set)
    principal = IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject="member-a",
        organization_id="org-a",
        workspace_id="workspace-a",
        allowed_operation_ids=frozenset(),
    )
    claims = ConnectorGrantClaims(
        request_id="slow-provider-request",
        audience="exchange",
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        principal_issuer=principal.issuer,
        principal_subject=principal.subject,
        connection_ref="github-connection",
        provider_id="github",
        profile_ref="github-profile",
        operation_id="github.repository.list",
        resource_ref="sha256:" + "a" * 64,
        arguments_digest_sha256=b"a" * 32,
        issued_at_epoch=int(time.time()),
        expires_at_epoch=int(time.time()) + 15,
        grant_ref="sha256:" + "b" * 64,
    )

    class SlowDispatcher:
        def invoke(
            self,
            _prepared: object,
            *,
            principal: IntegrationPrincipal,
            claims: ConnectorGrantClaims,
        ) -> dict[str, Any]:
            assert principal is not None and claims is not None
            if not release.wait(timeout=3.0):
                raise TimeoutError("test provider was not released")
            return {"state": "SUCCEEDED"}

    async def run_probe() -> tuple[bool, dict[str, Any]]:
        watchdog.start()
        dispatch = asyncio.create_task(
            _invoke_connector_dispatcher(
                SlowDispatcher(),
                object(),
                principal=principal,
                claims=claims,
            )
        )

        async def quick_request() -> bool:
            await asyncio.sleep(0.01)
            return not release.is_set()

        responsive = await quick_request()
        release.set()
        watchdog.cancel()
        return responsive, await dispatch

    try:
        responsive, result = asyncio.run(run_probe())
    finally:
        release.set()
        watchdog.cancel()

    assert responsive
    assert result == {"state": "SUCCEEDED"}


class _Authorizer:
    def __init__(self, principal: IntegrationPrincipal) -> None:
        self.principal = principal
        self.calls: list[tuple[str, str]] = []

    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal:
        self.calls.append((bearer_token, workspace_id))
        if bearer_token != "first-party-token" or workspace_id != self.principal.workspace_id:
            raise RuntimeError("Platform rejected current identity")
        return self.principal


class _Accounts:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def begin_link(
        self,
        principal: IntegrationPrincipal,
        *,
        provider: str,
        workspace_id: str | None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self.calls.append(f"{provider}:{idempotency_key}")
        return {
            "linkSessionRef": "2b76ba4d-3612-41be-9b93-e944968c3a51",
            "callbackNonce": "n" * 32,
            "expiresAt": 1_800_000_000,
        }

    def list_links(
        self, principal: IntegrationPrincipal, *, workspace_id: str | None
    ) -> dict[str, Any]:
        return {
            "links": [
                {
                    "account_ref": "5e58f013-b7a5-4817-90d8-50c8a7aa9aa5",
                    "provider": "github",
                    "status": "active",
                    "workspace_id": workspace_id,
                }
            ]
        }

    def list_provider_profiles(self, principal: IntegrationPrincipal) -> dict[str, Any]:
        del principal
        return {
            "profiles": [
                {
                    "profile_ref": "gh-profile-1",
                    "provider": "github",
                    "auth_status": "healthy",
                    "target_scope": {
                        "repositories": [
                            {"repository_id": "17", "owner": "owner", "name": "repository"}
                        ]
                    },
                }
            ]
        }


class _Store:
    def list_connections(self, principal: IntegrationPrincipal) -> list[Any]:
        raise AssertionError("permission-denied route must not read the store")


class _GitHub:
    pass


class _WebhookVerifier:
    pass


class _DelegationAuthorizer:
    def validate_binding(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs


class _ExecutionVerifier:
    def __init__(self, approved: Any) -> None:
        self.approved = approved

    def verify(self, encoded_credential: bytes) -> Any:
        assert encoded_credential == b"signed-authority-credential"
        return self.approved


class _ExecutionDispatcher:
    def __init__(self) -> None:
        self.evidence: Any = None

    def execute_authorized_action(
        self, principal: Any, operation_id: UUID, **kwargs: Any
    ) -> dict[str, str]:
        self.evidence = kwargs["authority_evidence"]
        return {"operationId": str(operation_id), "state": "SUCCEEDED"}


class _LocalAuthority(authority_grpc.WorkspaceAuthorityServiceServicer):
    """Native local gRPC Authority serving fixed synthetic identity evidence."""

    def NegotiateVersion(self, request: Any, context: Any) -> Any:
        del request, context
        return authority_wire.NegotiateVersionResponse(selected_version=2, supported_versions=[2])

    def VerifyIdentity(self, request: Any, context: Any) -> Any:
        assert request.workspace_id == "workspace-1"
        metadata = {item.key: item.value for item in context.invocation_metadata()}
        assert metadata["authorization"] == "Bearer native-test-token"
        return authority_wire.VerifyIdentityResponse(
            issuer="https://issuer.example",
            subject="native-user-1",
            organization_id="org-1",
            workspace_id="workspace-1",
        )

    def GetCatalogSnapshot(self, request: Any, context: Any) -> Any:
        assert request.workspace_id == "workspace-1"
        metadata = {item.key: item.value for item in context.invocation_metadata()}
        assert metadata["authorization"] == "Bearer native-test-token"
        return authority_wire.CatalogSnapshotResponse(
            organization_id="org-1",
            workspace_id="workspace-1",
            owners=[
                authority_wire.OwnerSnapshot(
                    owner_id="exchange",
                    granted_operation_ids=["accountBeginLink"],
                )
            ],
        )


class _AbortingIdentityAuthority(_LocalAuthority):
    """Exercise real gRPC status propagation for first-party identity failures."""

    def __init__(self, status: grpc.StatusCode, *, abort_method: str) -> None:
        self.status = status
        self.abort_method = abort_method

    def NegotiateVersion(self, request: Any, context: Any) -> Any:
        if self.abort_method == "NegotiateVersion":
            context.abort(self.status, "synthetic negotiation failure")
        return super().NegotiateVersion(request, context)

    def VerifyIdentity(self, request: Any, context: Any) -> Any:
        if self.abort_method == "VerifyIdentity":
            context.abort(self.status, "synthetic identity result")
        return authority_wire.VerifyIdentityResponse(
            issuer="https://issuer.example",
            subject="native-user-1",
            organization_id="org-1",
            workspace_id=request.workspace_id,
        )

    def GetCatalogSnapshot(self, request: Any, context: Any) -> Any:
        if self.abort_method == "GetCatalogSnapshot":
            context.abort(self.status, "synthetic catalog result")
        return authority_wire.CatalogSnapshotResponse(
            organization_id="org-1",
            workspace_id=request.workspace_id,
            owners=[
                authority_wire.OwnerSnapshot(
                    owner_id="exchange",
                    granted_operation_ids=["integrationListConnections"],
                )
            ],
        )


def _services(
    principal: IntegrationPrincipal,
) -> tuple[IntegrationServices, _Authorizer, _Accounts]:
    authorizer = _Authorizer(principal)
    accounts = _Accounts()
    callback = IntegrationPrincipal(
        issuer="urn:cyrene:service",
        subject="exchange-oauth-callback",
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        allowed_operation_ids=frozenset(),
    )
    return (
        IntegrationServices(
            store=_Store(),  # type: ignore[arg-type]
            authorizer=authorizer,
            accounts=accounts,  # type: ignore[arg-type]
            github=_GitHub(),  # type: ignore[arg-type]
            webhook_verifier=_WebhookVerifier(),  # type: ignore[arg-type]
            delegation_authorizer=_DelegationAuthorizer(),  # type: ignore[arg-type]
            callback_principal=callback,
        ),
        authorizer,
        accounts,
    )


def _https_server_credentials(tmp_path: Path) -> tuple[Path, Path, Path]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Exchange test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = tmp_path / "exchange-tls-cert.pem"
    key_path = tmp_path / "exchange-tls-key.pem"
    ca_path = tmp_path / "exchange-root-ca.pem"
    cert_path.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    key_path.chmod(0o600)
    cert_path.chmod(0o600)
    ca_path.chmod(0o600)
    return cert_path, key_path, ca_path


@pytest.mark.parametrize("configured_through_environment", [False, True])
def test_integration_only_cli_passes_valid_listener_tls_files_to_uvicorn(
    tmp_path: Path,
    monkeypatch: Any,
    configured_through_environment: bool,
) -> None:
    cert_path, key_path, _ca_path = _https_server_credentials(tmp_path)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)
    services = SimpleNamespace(close=lambda: None)
    app = SimpleNamespace()
    captured: dict[str, Any] = {}
    monkeypatch.setattr(integration_cli, "build_production_services", lambda _path: services)
    monkeypatch.setattr(
        product_server,
        "build_integration_app",
        lambda **_kwargs: app,
    )
    monkeypatch.setattr(
        exchange_cli.uvicorn,
        "run",
        lambda selected_app, **kwargs: captured.update(app=selected_app, **kwargs),
    )
    command = [
        "serve",
        "--mode",
        "integration-only",
        "--host",
        "0.0.0.0",
        "--port",
        "8081",
        "--integration-database",
        str(tmp_path / "exchange.sqlite3"),
    ]
    if configured_through_environment:
        monkeypatch.setenv("CYRENE_EXCHANGE_TLS_CERT_FILE", str(cert_path))
        monkeypatch.setenv("CYRENE_EXCHANGE_TLS_KEY_FILE", str(key_path))
    else:
        command.extend(["--tls-cert-file", str(cert_path), "--tls-key-file", str(key_path)])
    result = exchange_cli.run(command)

    assert result == 0
    assert captured["app"] is app
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 8081
    assert captured["ssl_certfile"] == str(cert_path)
    assert captured["ssl_keyfile"] == str(key_path)


def test_account_link_uses_platform_identity_and_ignores_body_identity(tmp_path: Path) -> None:
    principal = IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="subject-1",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset({"accountBeginLink"}),
    )
    services, authorizer, accounts = _services(principal)
    app = create_app(database_path=tmp_path / "exchange.sqlite3", integrations=services)

    with TestClient(app) as client:
        missing = client.post(
            "/api/v1/accounts/link-sessions?workspaceId=workspace-1",
            headers={"Idempotency-Key": "begin-link-1"},
            json={"provider": "github"},
        )
        injected_identity = client.post(
            "/api/v1/accounts/link-sessions?workspaceId=workspace-1",
            headers={
                "Authorization": "Bearer first-party-token",
                "Idempotency-Key": "begin-link-2",
            },
            json={"provider": "github", "subject": "attacker", "roles": ["admin"]},
        )
        response = client.post(
            "/api/v1/accounts/link-sessions?workspaceId=workspace-1",
            headers={
                "Authorization": "Bearer first-party-token",
                "Idempotency-Key": "begin-link-3",
            },
            json={"provider": "github"},
        )

    assert missing.status_code == 401
    assert injected_identity.status_code == 422
    assert response.status_code == 201
    assert accounts.calls == ["github:begin-link-3"]
    assert authorizer.calls == [("first-party-token", "workspace-1")]
    assert response.json()["callbackNonce"] == "n" * 32


def test_unsupported_operation_is_denied_before_store_access(tmp_path: Path) -> None:
    principal = IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="subject-1",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset({"accountListLinks"}),
    )
    services, _, _ = _services(principal)
    app = create_app(database_path=tmp_path / "exchange.sqlite3", integrations=services)

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/integrations/connections?workspaceId=workspace-1",
            headers={"Authorization": "Bearer first-party-token"},
        )

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "EXCHANGE_INTEGRATION_PERMISSION_DENIED"


def test_native_platform_authority_grpc_verification_flows_into_rest(tmp_path: Path) -> None:
    socket_path = tmp_path / "authority.sock"
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    authority_grpc.add_WorkspaceAuthorityServiceServicer_to_server(_LocalAuthority(), server)
    assert server.add_insecure_port(f"unix:{socket_path}") > 0
    server.start()
    try:
        verifier = PlatformAuthorityIdentityVerifier.from_unix_socket(socket_path)
        callback_principal = IntegrationPrincipal(
            issuer="urn:cyrene:exchange-service",
            subject="github-callback",
            organization_id="exchange-service",
            workspace_id="exchange-service",
            allowed_operation_ids=frozenset(),
        )
        accounts = _Accounts()
        services = IntegrationServices(
            store=_Store(),  # type: ignore[arg-type]
            authorizer=verifier,
            accounts=accounts,  # type: ignore[arg-type]
            github=_GitHub(),  # type: ignore[arg-type]
            webhook_verifier=_WebhookVerifier(),  # type: ignore[arg-type]
            delegation_authorizer=_DelegationAuthorizer(),  # type: ignore[arg-type]
            callback_principal=callback_principal,
        )
        app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/accounts/link-sessions?workspaceId=workspace-1",
                headers={
                    "Authorization": "Bearer native-test-token",
                    "Idempotency-Key": "native-link-1",
                },
                json={"provider": "github"},
            )
        assert response.status_code == 201
        assert accounts.calls == ["github:native-link-1"]
    finally:
        server.stop(0).wait()


@pytest.mark.parametrize(
    ("abort_method", "rpc_status", "http_status", "problem_code"),
    [
        (
            "VerifyIdentity",
            grpc.StatusCode.UNAUTHENTICATED,
            401,
            "EXCHANGE_INTEGRATION_AUTH_REQUIRED",
        ),
        (
            "VerifyIdentity",
            grpc.StatusCode.PERMISSION_DENIED,
            403,
            "EXCHANGE_INTEGRATION_PERMISSION_DENIED",
        ),
        (
            "VerifyIdentity",
            grpc.StatusCode.UNAVAILABLE,
            503,
            "EXCHANGE_PLATFORM_AUTH_UNAVAILABLE",
        ),
        (
            "VerifyIdentity",
            grpc.StatusCode.DEADLINE_EXCEEDED,
            503,
            "EXCHANGE_PLATFORM_AUTH_UNAVAILABLE",
        ),
        (
            "VerifyIdentity",
            grpc.StatusCode.UNKNOWN,
            503,
            "EXCHANGE_PLATFORM_AUTH_UNAVAILABLE",
        ),
        (
            "NegotiateVersion",
            grpc.StatusCode.UNAUTHENTICATED,
            503,
            "EXCHANGE_PLATFORM_AUTH_UNAVAILABLE",
        ),
        (
            "GetCatalogSnapshot",
            grpc.StatusCode.UNAUTHENTICATED,
            401,
            "EXCHANGE_INTEGRATION_AUTH_REQUIRED",
        ),
        (
            "GetCatalogSnapshot",
            grpc.StatusCode.PERMISSION_DENIED,
            403,
            "EXCHANGE_INTEGRATION_PERMISSION_DENIED",
        ),
    ],
)
def test_actual_authority_rpc_status_maps_to_auth_http_status(
    tmp_path: Path,
    abort_method: str,
    rpc_status: grpc.StatusCode,
    http_status: int,
    problem_code: str,
) -> None:
    socket_path = tmp_path / f"authority-{rpc_status.name.lower()}.sock"
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    authority_grpc.add_WorkspaceAuthorityServiceServicer_to_server(
        _AbortingIdentityAuthority(rpc_status, abort_method=abort_method), server
    )
    assert server.add_insecure_port(f"unix:{socket_path}") > 0
    server.start()
    try:
        principal = IntegrationPrincipal(
            issuer="https://issuer.example",
            subject="native-user-1",
            organization_id="org-1",
            workspace_id="workspace-1",
            allowed_operation_ids=frozenset({"integrationListConnections"}),
        )
        services, _, _ = _services(principal)
        services.authorizer = PlatformAuthorityIdentityVerifier.from_unix_socket(socket_path)
        app = create_app(database_path=tmp_path / "exchange.sqlite3", integrations=services)
        with TestClient(app) as client:
            response = client.get(
                "/api/v1/integrations/connections?workspaceId=workspace-1",
                headers={"Authorization": "Bearer invalid-first-party-token"},
            )
        assert response.status_code == http_status
        assert response.json()["code"] == problem_code
    finally:
        server.stop(0).wait()


def test_execution_route_binds_actual_http_request_to_platform_approval(tmp_path: Path) -> None:
    operation_id = UUID("f10d2668-a986-41fb-9695-7be4cc89d9a1")
    binding_id = UUID("d18b63e4-f3f8-4f45-aeec-524cba89a55f")
    argument_digest = "a" * 64
    body = json.dumps(
        {"operationId": str(operation_id), "argumentDigest": argument_digest},
        separators=(",", ":"),
    ).encode()
    path = f"/api/v1/integrations/sync-bindings/{binding_id}/execute-issue-comment"
    invocation = product_wire.ProductApiInvocationV2(
        owner_id="exchange",
        operation_id="integrationExecuteIssueComment",
        json_body=body,
        resource_id=str(binding_id),
        idempotency_key=str(operation_id),
    )
    envelope = authority_wire.CanonicalInvocationEnvelope(
        invocation_id="2eef77ea-6cee-490a-ab12-7965ce9e0a95",
        invocation=invocation,
        target=authority_wire.ExecutionTarget(
            target_component="exchange-product",
            http_method="POST",
            endpoint=path,
            resource_id=str(binding_id),
            scope="org-1/workspace-1",
            idempotency_key=str(operation_id),
        ),
        organization_id="org-1",
        workspace_id="workspace-1",
        principal_issuer="https://issuer.example",
        principal_subject="subject-1",
    )
    envelope.expires_at.FromDatetime(datetime.now(UTC) + timedelta(minutes=2))
    approved = authority_wire.ApprovedInvocation(
        invocation_id=envelope.invocation_id,
        canonical_envelope=envelope,
        credential=authority_wire.ExecutionCredential(invocation_id=envelope.invocation_id),
    )
    dispatcher = _ExecutionDispatcher()
    services = IntegrationServices(
        store=_Store(),  # type: ignore[arg-type]
        authorizer=_Authorizer(
            IntegrationPrincipal(
                issuer="https://issuer.example",
                subject="subject-1",
                organization_id="org-1",
                workspace_id="workspace-1",
                allowed_operation_ids=frozenset(),
            )
        ),
        accounts=_Accounts(),  # type: ignore[arg-type]
        github=_GitHub(),  # type: ignore[arg-type]
        webhook_verifier=_WebhookVerifier(),  # type: ignore[arg-type]
        delegation_authorizer=_DelegationAuthorizer(),  # type: ignore[arg-type]
        callback_principal=IntegrationPrincipal(
            issuer="urn:cyrene:service",
            subject="exchange-oauth-callback",
            organization_id="org-1",
            workspace_id="workspace-1",
            allowed_operation_ids=frozenset(),
        ),
        dispatcher=dispatcher,
        execution_authorization_verifier=_ExecutionVerifier(approved),
    )
    app = create_app(database_path=tmp_path / "exchange.sqlite3", integrations=services)

    with TestClient(app) as client:
        response = client.post(
            path,
            headers={
                "x-cyrene-execution-credential-bin": base64.b64encode(
                    b"signed-authority-credential"
                ).decode("ascii"),
                "Idempotency-Key": str(operation_id),
                "Content-Type": "application/json",
            },
            content=body,
        )
        mismatch = client.post(
            path,
            headers={
                "x-cyrene-execution-credential-bin": base64.b64encode(
                    b"signed-authority-credential"
                ).decode("ascii"),
                "Idempotency-Key": str(operation_id),
                "Content-Type": "application/json",
            },
            content=json.dumps(
                {"operationId": str(operation_id), "argumentDigest": "b" * 64},
                separators=(",", ":"),
            ).encode(),
        )

    assert response.status_code == 200, response.text
    assert response.json()["state"] == "SUCCEEDED"
    assert dispatcher.evidence is not None
    assert dispatcher.evidence.raw_body == body
    assert dispatcher.evidence.content_type == "application/json"
    assert mismatch.status_code == 403


def test_catalog_read_accepts_only_exact_signed_product_approval(tmp_path: Path) -> None:
    path = "/api/v1/integrations/connections"
    envelope = authority_wire.CanonicalInvocationEnvelope(
        invocation_id="db23965c-0a33-48ef-b134-3f4c184fc297",
        invocation=product_wire.ProductApiInvocationV2(
            owner_id="exchange",
            operation_id="integrationListConnections",
        ),
        target=authority_wire.ExecutionTarget(
            target_component="exchange-product",
            http_method="GET",
            endpoint=path,
        ),
        organization_id="org-1",
        workspace_id="workspace-1",
        principal_issuer="https://issuer.example",
        principal_subject="approved-member",
    )
    envelope.expires_at.FromDatetime(datetime.now(UTC) + timedelta(minutes=2))
    approved = authority_wire.ApprovedInvocation(
        invocation_id=envelope.invocation_id,
        canonical_envelope=envelope,
        credential=authority_wire.ExecutionCredential(invocation_id=envelope.invocation_id),
    )

    class _OwnedConnectionStore:
        def list_connections(self, actor: IntegrationPrincipal) -> list[dict[str, Any]]:
            assert actor.issuer == "https://issuer.example"
            assert actor.subject == "approved-member"
            assert actor.workspace_id == "workspace-1"
            assert actor.allowed_operation_ids == frozenset({"integrationListConnections"})
            return [
                {
                    "id": "b7649d78-8daf-4be3-b429-e98d9d2d9c92",
                    "provider": "github",
                    "displayName": "owner/repository",
                    "repositoryId": "17",
                    "repositoryName": "owner/repository",
                    "enabled": True,
                    "createdAt": "2026-10-14T00:00:00Z",
                    "updatedAt": "2026-10-14T00:00:00Z",
                    "organizationId": "private-org",
                    "workspaceId": "private-workspace",
                    "actorIssuer": "private-issuer",
                    "actorSubject": "private-subject",
                    "accountLinkRef": "private-account-ref",
                    "bindingRef": "private-binding-ref",
                    "targetRef": "private-target-ref",
                }
            ]

    services, authorizer, _ = _services(
        IntegrationPrincipal(
            issuer="https://unused.example",
            subject="unused",
            organization_id="org-1",
            workspace_id="workspace-1",
            allowed_operation_ids=frozenset(),
        )
    )
    services.store = _OwnedConnectionStore()  # type: ignore[assignment]
    services.execution_authorization_verifier = _ExecutionVerifier(approved)
    app = create_app(database_path=tmp_path / "execution-auth.sqlite3", integrations=services)
    signed_headers = {
        "x-cyrene-execution-credential-bin": base64.b64encode(
            b"signed-authority-credential"
        ).decode("ascii"),
        "X-Cyrene-Workspace-Id": "workspace-1",
    }

    with TestClient(app) as client:
        accepted = client.get(path, headers=signed_headers)
        wrong_path = client.request("GET", path, headers=signed_headers, content=b"{}")
        wrong_workspace = client.get(
            path,
            headers={
                **signed_headers,
                "X-Cyrene-Workspace-Id": "workspace-2",
            },
        )

    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == [
        {
            "id": "b7649d78-8daf-4be3-b429-e98d9d2d9c92",
            "provider": "github",
            "displayName": "owner/repository",
            "repositoryId": "17",
            "repositoryName": "owner/repository",
            "enabled": True,
            "createdAt": "2026-10-14T00:00:00Z",
            "updatedAt": "2026-10-14T00:00:00Z",
        }
    ]
    assert wrong_path.status_code == 403
    assert wrong_workspace.status_code == 403
    assert authorizer.calls == []


def test_catalog_mutation_accepts_signed_proof_only_for_approved_raw_body(
    tmp_path: Path,
) -> None:
    path = "/api/v1/integrations/connections"
    idem = "approved-create-connection"
    body = (
        b'{"repositoryId":"17","repositoryName":"owner/repository","accountLinkRef":"gh-profile-1"}'
    )
    envelope = authority_wire.CanonicalInvocationEnvelope(
        invocation_id="79b9a8f7-9fee-4cc6-8b4d-b94a53d322d3",
        invocation=product_wire.ProductApiInvocationV2(
            owner_id="exchange",
            operation_id="integrationCreateConnection",
            json_body=body,
            idempotency_key=idem,
        ),
        target=authority_wire.ExecutionTarget(
            target_component="exchange-product",
            http_method="POST",
            endpoint=path,
            idempotency_key=idem,
        ),
        organization_id="org-1",
        workspace_id="workspace-1",
        principal_issuer="https://issuer.example",
        principal_subject="approved-member",
    )
    envelope.expires_at.FromDatetime(datetime.now(UTC) + timedelta(minutes=2))
    approved = authority_wire.ApprovedInvocation(
        invocation_id=envelope.invocation_id,
        canonical_envelope=envelope,
        credential=authority_wire.ExecutionCredential(invocation_id=envelope.invocation_id),
    )

    class _OwnedConnectionStore:
        calls = 0

        def create_connection(
            self,
            actor: IntegrationPrincipal,
            request: CreateIntegrationConnection,
            *,
            idempotency_key: str,
        ) -> dict[str, str]:
            self.calls += 1
            assert actor.subject == "approved-member"
            assert actor.allowed_operation_ids == frozenset({"integrationCreateConnection"})
            assert request.repository_id == "17"
            assert request.account_link_ref == "gh-profile-1"
            assert idempotency_key == idem
            return IntegrationConnection(
                id=UUID("b7649d78-8daf-4be3-b429-e98d9d2d9c92"),
                organization_id=actor.organization_id,
                workspace_id=actor.workspace_id,
                actor_issuer=actor.issuer,
                actor_subject=actor.subject,
                provider="github",
                display_name="owner/repository",
                repository_id="17",
                repository_name="owner/repository",
                created_at=datetime(2026, 10, 14, tzinfo=UTC),
                updated_at=datetime(2026, 10, 14, tzinfo=UTC),
            )

    services, authorizer, _ = _services(
        IntegrationPrincipal(
            issuer="https://unused.example",
            subject="unused",
            organization_id="org-1",
            workspace_id="workspace-1",
            allowed_operation_ids=frozenset(),
        )
    )
    store = _OwnedConnectionStore()
    services.store = store  # type: ignore[assignment]
    services.execution_authorization_verifier = _ExecutionVerifier(approved)
    app = create_app(database_path=tmp_path / "execution-create.sqlite3", integrations=services)
    headers = {
        "x-cyrene-execution-credential-bin": base64.b64encode(
            b"signed-authority-credential"
        ).decode("ascii"),
        "X-Cyrene-Workspace-Id": "workspace-1",
        "Idempotency-Key": idem,
        "Content-Type": "application/json",
    }

    with TestClient(app) as client:
        accepted = client.post(path, headers=headers, content=body)
        mismatch = client.post(
            path,
            headers=headers,
            content=b'{"repositoryId":"18","repositoryName":"owner/repository"}',
        )

    assert accepted.status_code == 201, accepted.text
    assert mismatch.status_code == 403
    assert store.calls == 1
    assert authorizer.calls == []


def test_actor_binding_attach_forwards_approved_credential_to_self_grant_check(
    tmp_path: Path,
) -> None:
    binding_id = UUID("d18b63e4-f3f8-4f45-aeec-524cba89a55f")
    idem = "approved-attach-binding"
    path = f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings"
    body = (
        b'{"accountLinkRef":"5e58f013-b7a5-4817-90d8-50c8a7aa9aa5",'
        b'"delegationRef":"9b318b07-e47f-46d4-92b5-499f19337768"}'
    )
    envelope = authority_wire.CanonicalInvocationEnvelope(
        invocation_id="43b2c577-7f14-4ea8-88e3-14a5d4c6d665",
        invocation=product_wire.ProductApiInvocationV2(
            owner_id="exchange",
            operation_id="integrationAttachActorBinding",
            json_body=body,
            resource_id=str(binding_id),
            idempotency_key=idem,
        ),
        target=authority_wire.ExecutionTarget(
            target_component="exchange-product",
            http_method="POST",
            endpoint=path,
            resource_id=str(binding_id),
            idempotency_key=idem,
        ),
        organization_id="org-1",
        workspace_id="workspace-1",
        principal_issuer="https://issuer.example",
        principal_subject="approved-member",
    )
    envelope.expires_at.FromDatetime(datetime.now(UTC) + timedelta(minutes=2))
    approved = authority_wire.ApprovedInvocation(
        invocation_id=envelope.invocation_id,
        canonical_envelope=envelope,
        credential=authority_wire.ExecutionCredential(invocation_id=envelope.invocation_id),
    )

    class _ScopedStore:
        def get_binding(self, *_args: Any, **_kwargs: Any) -> object:
            return object()

        def create_actor_binding(
            self, _actor: IntegrationPrincipal, request: Any, *, idempotency_key: str
        ) -> dict[str, str]:
            assert request.binding_id == binding_id
            assert idempotency_key == idem
            return {"bindingId": str(binding_id)}

    class _ExecutionDelegationAuthorizer:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def validate_binding(self, actor: IntegrationPrincipal, **kwargs: Any) -> None:
            self.calls.append(kwargs)
            assert actor.subject == "approved-member"
            assert kwargs["bearer_token"] is None

    services, _, _ = _services(
        IntegrationPrincipal(
            issuer="https://unused.example",
            subject="unused",
            organization_id="org-1",
            workspace_id="workspace-1",
            allowed_operation_ids=frozenset(),
        )
    )
    services.store = _ScopedStore()  # type: ignore[assignment]
    authorizer = _ExecutionDelegationAuthorizer()
    services.delegation_authorizer = authorizer  # type: ignore[assignment]
    services.execution_authorization_verifier = _ExecutionVerifier(approved)
    app = create_app(database_path=tmp_path / "execution-attach.sqlite3", integrations=services)

    with TestClient(app) as client:
        response = client.post(
            path,
            headers={
                "x-cyrene-execution-credential-bin": base64.b64encode(
                    b"signed-authority-credential"
                ).decode("ascii"),
                "X-Cyrene-Workspace-Id": "workspace-1",
                "Idempotency-Key": idem,
                "Content-Type": "application/json",
            },
            content=body,
        )

    assert response.status_code == 201, response.text
    assert authorizer.calls[0]["execution_credential"] == b"signed-authority-credential"


def test_issue_query_is_authority_queued_and_status_hides_internal_refs(tmp_path: Path) -> None:
    principal = IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="member-5",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationCreateBinding",
                "integrationAttachActorBinding",
                "integrationQueryIssue",
                "integrationGetIssue",
                "integrationGetOperation",
            }
        ),
    )
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = store.create_connection(
        principal,
        CreateIntegrationConnection(repository_id="17", repository_name="owner/repository"),
        idempotency_key="create-connection-1",
    )
    binding = store.create_binding(
        principal,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="wecom-group-main",
        ),
        idempotency_key="create-binding-1",
    )
    store.create_actor_binding(
        principal,
        CreateActorBinding(
            binding_id=binding.id,
            account_link_ref="5e58f013-b7a5-4817-90d8-50c8a7aa9aa5",
            delegation_ref="9b318b07-e47f-46d4-92b5-499f19337768",
        ),
        idempotency_key="actor-binding-1",
    )
    services, _, _ = _services(principal)
    services.store = store
    app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)

    with TestClient(app) as client:
        queued = client.post(
            f"/api/v1/integrations/sync-bindings/{binding.id}/issues/actions/query?workspaceId=workspace-1",
            headers={"Authorization": "Bearer first-party-token", "Idempotency-Key": "query-42"},
            json={"issueNumber": 42},
        )
        status = client.get(
            queued.headers["Location"] + "?workspaceId=workspace-1",
            headers={"Authorization": "Bearer first-party-token"},
        )
        store.save_snapshot(
            ResourceSnapshot(
                organization_id=principal.organization_id,
                workspace_id=principal.workspace_id,
                actor_issuer=principal.issuer,
                actor_subject=principal.subject,
                connection_id=connection.id,
                resource_type="github.issue",
                resource_id="17#42",
                version="snapshot-v1",
                observed_at=datetime.now(UTC),
                freshness=SnapshotFreshness.FRESH,
                document={
                    "repositoryId": "17",
                    "issueNumber": 42,
                    "state": "OPEN",
                    "title": "Safe title",
                    "body": "private issue body",
                },
            )
        )
        snapshot = client.post(
            f"/api/v1/integrations/sync-bindings/{binding.id}/issues/actions/snapshot"
            "?workspaceId=workspace-1",
            headers={"Authorization": "Bearer first-party-token"},
            json={"issueNumber": 42},
        )

    assert queued.status_code == 202
    assert status.status_code == 200
    assert status.json()["state"] == "QUEUED"
    assert set(status.json()) == {
        "operationId",
        "action",
        "state",
        "issueNumber",
        "createdAt",
        "updatedAt",
        "result",
    }
    assert "delegationRef" not in status.json()
    assert "accountLinkRef" not in queued.json()

    assert snapshot.status_code == 200
    assert snapshot.json() == {
        "issueNumber": 42,
        "state": "OPEN",
        "title": "Safe title",
        "version": "snapshot-v1",
        "freshness": "FRESH",
        "observedAt": snapshot.json()["observedAt"],
    }
    assert "body" not in snapshot.json()


def test_public_issue_request_uses_camelcase_and_rejects_identity_claims(
    tmp_path: Path,
) -> None:
    principal = IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="member-5",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationCreateBinding",
                "integrationAttachActorBinding",
                "integrationCreateIssueComment",
            }
        ),
    )
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = store.create_connection(
        principal,
        CreateIntegrationConnection(repository_id="17", repository_name="owner/repository"),
        idempotency_key="camel-connection",
    )
    binding = store.create_binding(
        principal,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="wecom-group-main",
        ),
        idempotency_key="camel-binding",
    )
    services, _, _ = _services(principal)
    services.store = store
    app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)

    with TestClient(app) as client:
        attached = client.post(
            f"/api/v1/integrations/sync-bindings/{binding.id}/actor-bindings",
            params={"workspaceId": "workspace-1"},
            headers={
                "Authorization": "Bearer first-party-token",
                "Idempotency-Key": "camel-actor-binding",
            },
            json={
                "accountLinkRef": "5e58f013-b7a5-4817-90d8-50c8a7aa9aa5",
                "delegationRef": "9b318b07-e47f-46d4-92b5-499f19337768",
            },
        )
        valid = client.post(
            f"/api/v1/integrations/sync-bindings/{binding.id}/issues/actions/comment",
            params={"workspaceId": "workspace-1"},
            headers={
                "Authorization": "Bearer first-party-token",
                "Idempotency-Key": "camel-comment",
            },
            json={"issueNumber": 42, "body": "Please investigate"},
        )
        injected = client.post(
            f"/api/v1/integrations/sync-bindings/{binding.id}/issues/actions/comment",
            params={"workspaceId": "workspace-1"},
            headers={
                "Authorization": "Bearer first-party-token",
                "Idempotency-Key": "camel-comment-injected",
            },
            json={
                "issueNumber": 43,
                "body": "Please investigate",
                "actorSubject": "attacker",
                "roles": ["admin"],
            },
        )

    assert attached.status_code == 201, attached.text
    assert valid.status_code == 202, valid.text
    assert injected.status_code == 422


def test_connection_health_route_uses_real_direct_runtime_health_rpc(tmp_path: Path) -> None:
    from cyrene_plugin_runtime._generated import direct_plugin_runtime_pb2_grpc as plugin_grpc
    from cyrene_plugin_runtime.server import DirectPluginService

    class _HealthPlugin:
        plugin_id = "synthetic-github-plugin"
        version = "1.2.3"
        capabilities = ("tool.provider.v1",)

    class _OwnedConnectionStore:
        def get_connection(self, *_args: Any, **_kwargs: Any) -> object:
            return object()

    principal = IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="subject-health",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset({"integrationGetConnectionHealth"}),
    )
    services, _, _ = _services(principal)
    services.store = _OwnedConnectionStore()  # type: ignore[assignment]

    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    plugin_grpc.add_DirectPluginRuntimeServicer_to_server(
        DirectPluginService(_HealthPlugin(), "tool.provider.v1", "1"), server
    )
    port = server.add_insecure_port("127.0.0.1:0")
    assert port > 0
    server.start()
    health = DirectPluginHealthClient(f"grpc://127.0.0.1:{port}")
    services.plugin_health = health
    app = create_app(database_path=tmp_path / "health.sqlite3", integrations=services)

    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/v1/integrations/connections/2f8250f0-6f63-4f33-a1ab-3fe56cfb1459/health"
                "?workspaceId=workspace-1",
                headers={"Authorization": "Bearer first-party-token"},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "SERVING"
        assert body["pluginId"] == "synthetic-github-plugin"
        assert body["pluginVersion"] == "1.2.3"
        assert body["capabilities"] == ["tool.provider.v1"]
        assert body["errorCode"] is None
    finally:
        health.close()
        server.stop(grace=0).wait()


def test_direct_runtime_health_reports_offline_endpoint_as_unknown() -> None:
    health = DirectPluginHealthClient("grpc://127.0.0.1:1", deadline_seconds=0.05)
    try:
        observation = health.observe()
    finally:
        health.close()

    assert observation.status == "UNKNOWN"
    assert observation.error_code == "plugin_health_unavailable"


def test_offline_plugin_health_does_not_fail_gateway_readiness(tmp_path: Path) -> None:
    from cyrene_exchange_product.server import OperatorBindingResolver, build_product_app

    class _OwnedConnectionStore:
        def get_connection(self, *_args: Any, **_kwargs: Any) -> object:
            return object()

    principal = IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="health-member",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset({"integrationGetConnectionHealth"}),
    )
    services, _, _ = _services(principal)
    services.store = _OwnedConnectionStore()  # type: ignore[assignment]
    health = DirectPluginHealthClient("grpc://127.0.0.1:1", deadline_seconds=0.05)
    services.plugin_health = health
    database = tmp_path / "offline-health.sqlite3"
    control = create_app(database_path=database)
    with TestClient(control) as client:
        endpoint = client.post(
            "/api/v1/gateway-endpoints",
            headers={"Idempotency-Key": "health-endpoint"},
            json={
                "name": "health-gateway",
                "publicBaseUrl": "http://exchange.example/v1",
                "authPolicyRef": "policy://exchange/health",
            },
        )
        route = client.post(
            "/api/v1/gateway-routes",
            headers={"Idempotency-Key": "health-route"},
            json={
                "endpointId": endpoint.json()["id"],
                "modelPattern": "demo-*",
                "targetBindingId": "binding:health-test",
                "targetModel": "health-model",
                "priority": 10,
            },
        )
    assert endpoint.status_code == 201, endpoint.text
    assert route.status_code == 201, route.text
    control.state.exchange_store.close()
    app = build_product_app(
        database_path=database,
        resolver=OperatorBindingResolver({}),
        integrations=services,
    )

    try:
        with TestClient(app) as client:
            readiness = client.get("/readyz")
            observation = client.get(
                "/api/v1/integrations/connections/2f8250f0-6f63-4f33-a1ab-3fe56cfb1459/health",
                headers={
                    "Authorization": "Bearer first-party-token",
                    "X-Cyrene-Workspace-Id": "workspace-1",
                },
            )
        assert readiness.status_code == 200
        assert observation.status_code == 200
        assert observation.json()["status"] == "UNKNOWN"
        assert observation.json()["errorCode"] == "plugin_health_unavailable"
    finally:
        health.close()


def test_large_huggingface_upload_grant_floors_fractional_epochs_and_uses_route_scoped_hmac_limit(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    key = b"n" * 32
    key_file = tmp_path / "navigator-hmac.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    grant_times: dict[str, float] = {"issued_at": 0.0, "expires_at": 0.0}
    request_clock = {"now": int(time.time())}

    class CountingHmacAuthenticator(NavigatorHmacAuthenticator):
        verify_calls = 0

        def verify(self, **kwargs: Any) -> int:
            self.verify_calls += 1
            return super().verify(**kwargs)

    class Authority:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def authorize_connector_operation(self, **kwargs: Any) -> bytes:
            self.calls.append(kwargs)
            return b"signed-synthetic-authority-grant"

    class GrantVerifier:
        def validate_authority_response(
            self,
            _grant: bytes,
            *,
            expected: dict[str, Any],
        ) -> ConnectorGrantClaims:
            grant_times["issued_at"] = float(int(time.time())) + 0.25
            grant_times["expires_at"] = grant_times["issued_at"] + 15.0
            return ConnectorGrantClaims(
                request_id=str(expected["request_id"]),
                audience="exchange",
                organization_id=str(expected["organization_id"]),
                workspace_id=str(expected["workspace_id"]),
                principal_issuer=str(expected["principal_issuer"]),
                principal_subject=str(expected["principal_subject"]),
                connection_ref=str(expected["connection_ref"]),
                provider_id=str(expected["provider_id"]),
                profile_ref=str(expected["profile_ref"]),
                operation_id=str(expected["operation_id"]),
                resource_ref=str(expected["resource_ref"]),
                arguments_digest_sha256=expected["arguments_digest_sha256"],
                issued_at_epoch=grant_times["issued_at"],
                expires_at_epoch=grant_times["expires_at"],
                grant_ref="sha256:" + "a" * 64,
            )

    owner = IntegrationPrincipal(
        issuer="https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0",
        subject="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        organization_id="org-large-upload",
        workspace_id="workspace-large-upload",
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )
    store = IntegrationStore(tmp_path / "large-upload.sqlite3")
    connection = store.create_connection(
        owner,
        CreateIntegrationConnection(
            provider="hf",
            binding_ref="hf-primary",
            target_ref="hf-target",
            account_link_ref="30000000-0000-4000-8000-000000000001",
        ),
        idempotency_key="large-hf-upload-connection",
    )
    profile = SimpleNamespace(
        provider="hf",
        account_scopes={
            "repositories": [
                {
                    "repo_type": "model",
                    "repo_id": "example-org/private-model",
                    "permissions": ["read", "write"],
                }
            ]
        },
        targets={"hf-target": SimpleNamespace(target_ref="example-org/private-model")},
    )
    dispatcher = ConnectorOperationDispatcher(
        store=store,
        accounts=None,
        github=None,
        authorization_cloud=None,
        registry=SimpleNamespace(settings=SimpleNamespace(profiles={"hf-primary": profile})),
    )
    authority = Authority()
    authenticator = CountingHmacAuthenticator(
        NavigatorHmacSettings(key_id="navigator-test-v1", key_file=key_file),
        replay_guard=store,
        clock=lambda: request_clock["now"],
    )
    services = IntegrationServices(
        store=store,
        authorizer=None,
        accounts=SimpleNamespace(),  # type: ignore[arg-type]
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=owner,
        navigator_hmac_authenticator=authenticator,
        connector_grant_authority=authority,
        connector_grant_verifier=GrantVerifier(),
        connector_operation_dispatcher=dispatcher,
    )
    app = create_app(database_path=tmp_path / "large-upload-product.sqlite3", integrations=services)

    def headers(raw_body: bytes) -> dict[str, str]:
        request_clock["now"] = int(time.time())
        timestamp = str(request_clock["now"])
        message = (
            b"POST\n/internal/v1/connector-operation-grants\n"
            + timestamp.encode("ascii")
            + b"\n"
            + raw_body
        )
        return {
            "content-type": "application/json",
            "x-cyrene-navigator-key-id": "navigator-test-v1",
            "x-cyrene-navigator-timestamp": timestamp,
            "x-cyrene-navigator-signature": hmac.new(key, message, hashlib.sha256).hexdigest(),
        }

    file_content = b"x" * 1_048_576
    arguments: dict[str, Any] = {
        "repo_type": "model",
        "repo_id": "example-org/private-model",
        "path": "upload.bin",
        "content_base64": base64.b64encode(file_content).decode("ascii"),
    }
    profile_ref = connection.account_link_ref
    assert profile_ref is not None
    resource_projection = _resource_projection(
        provider_id="huggingface",
        profile_ref=profile_ref,
        operation_id="huggingface.file.upload",
        arguments=arguments,
    )
    request_body = {
        "request_id": "large-hf-upload-grant",
        "workspace_id": owner.workspace_id,
        "principal_issuer": owner.issuer,
        "principal_subject": owner.subject,
        "connection_ref": str(connection.id),
        "provider_id": "huggingface",
        "profile_ref": profile_ref,
        "operation_id": "huggingface.file.upload",
        "resource_ref": _resource_ref(
            provider_id="huggingface",
            profile_ref=profile_ref,
            operation_id="huggingface.file.upload",
            target=resource_projection,
        ),
        "arguments": arguments,
        "arguments_digest_sha256": digest_arguments(arguments),
    }
    raw_body = json.dumps(request_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(arguments["content_base64"]) == 1_398_104
    assert 128 * 1024 < len(raw_body) < 1_500_000

    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)
    cert_path, key_path, ca_path = _https_server_credentials(tmp_path)
    listener_tls = _integration_listener_tls_options(
        SimpleNamespace(tls_cert_file=cert_path, tls_key_file=key_path),
        runtime_mode="integration-only",
    )
    assert listener_tls == {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            access_log=False,
            log_level="critical",
            **listener_tls,
        )
    )
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        assert server.servers
        port = server.servers[0].sockets[0].getsockname()[1]
        with httpx.Client(
            verify=ssl.create_default_context(cafile=str(ca_path)),
            trust_env=False,
            timeout=10.0,
        ) as client:
            accepted = client.post(
                f"https://127.0.0.1:{port}/internal/v1/connector-operation-grants",
                headers=headers(raw_body),
                content=raw_body,
            )
            assert accepted.status_code == 200, accepted.text
            grant = accepted.json()
            assert grant["claims"]["argumentsDigestSha256"] == digest_arguments(arguments)
            assert type(grant["issuedAt"]) is int
            assert type(grant["expiresAt"]) is int
            assert grant["issuedAt"] == int(grant_times["issued_at"])
            assert grant["expiresAt"] == int(grant_times["expires_at"])
            assert 0 < grant["expiresAt"] - grant["issuedAt"] <= 15
            assert authenticator.verify_calls == 1
            assert len(authority.calls) == 1
            assert authority.calls[0]["arguments_digest_sha256"] == bytes.fromhex(
                digest_arguments(arguments)
            )

            body_limit = navigator_hmac_body_limit(
                "POST", "/internal/v1/connector-operation-grants"
            )
            oversized = raw_body + b" " * (body_limit + 1 - len(raw_body))
            rejected = client.post(
                f"https://127.0.0.1:{port}/internal/v1/connector-operation-grants",
                headers=headers(oversized),
                content=oversized,
            )
        assert rejected.status_code == 413, rejected.text
        assert authenticator.verify_calls == 1
        assert len(authority.calls) == 1
        assert navigator_hmac_body_limit("POST", "/internal/v1/teams/events") == 128 * 1024
        ordinary_hmac_body = b"x" * (128 * 1024 + 1)
        with pytest.raises(ExchangeProductError) as oversized_default:
            authenticator.verify(
                method="POST",
                path="/internal/v1/another-hmac-route",
                headers=headers(ordinary_hmac_body),
                raw_body=ordinary_hmac_body,
            )
        assert oversized_default.value.status == 413
    finally:
        server.should_exit = True
        server_thread.join(timeout=10)
        services.close()


def test_host_computer_write_uses_directory_grant_and_keeps_unknown_result_blocked(
    tmp_path: Path,
) -> None:
    """A host runner has no OAuth connection, yet keeps grant and replay protections."""

    issuer = "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0"
    subject = "11111111-1111-4111-8111-111111111111"
    settings = parse_connector_host_settings(
        {
            "computerRunner": {
                "profileRef": "computer-owner-workspace",
                "connectionRef": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "organizationId": "org-computer",
                "workspaceId": "workspace-computer",
                "expectedIssuer": issuer,
                "directPlugin": {
                    "bindingId": "computer-runtime",
                    "connectionRef": "grpcs://computer-runner.test:443",
                    "transport": "mtls",
                    "mtls": {
                        "rootCertificateRef": "test/root-ca",
                        "clientCertificateRef": "test/client-cert",
                        "clientKeyRef": "test/client-key",
                    },
                },
            }
        }
    )
    profile = settings.computer_runner
    assert profile is not None
    principal = IntegrationPrincipal(
        issuer=issuer,
        subject=subject,
        organization_id=profile.organization_id,
        workspace_id=profile.workspace_id,
        allowed_operation_ids=frozenset({"computer.file.write"}),
    )
    database = tmp_path / "computer-runner.sqlite3"
    store = IntegrationStore(database)
    key_file = tmp_path / "navigator-exchange-hmac.key"
    key = b"n" * 32
    key_file.write_bytes(key)
    key_file.chmod(0o600)

    class _Authority:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def authorize_connector_operation(self, **kwargs: Any) -> bytes:
            self.calls.append(kwargs)
            return b"synthetic-computer-directory-grant"

    class _GrantVerifier:
        def __init__(self) -> None:
            self.claims: ConnectorGrantClaims | None = None
            self.consumed = False

        def validate_authority_response(
            self,
            _grant: bytes,
            *,
            expected: dict[str, Any],
        ) -> ConnectorGrantClaims:
            self.claims = ConnectorGrantClaims(
                request_id=str(expected["request_id"]),
                audience="exchange",
                organization_id=str(expected["organization_id"]),
                workspace_id=str(expected["workspace_id"]),
                principal_issuer=str(expected["principal_issuer"]),
                principal_subject=str(expected["principal_subject"]),
                connection_ref=str(expected["connection_ref"]),
                provider_id=str(expected["provider_id"]),
                profile_ref=str(expected["profile_ref"]),
                operation_id=str(expected["operation_id"]),
                resource_ref=str(expected["resource_ref"]),
                arguments_digest_sha256=expected["arguments_digest_sha256"],
                issued_at_epoch=time.time(),
                expires_at_epoch=time.time() + 15,
                grant_ref="sha256:" + "b" * 64,
            )
            return self.claims

        def inspect(
            self,
            _grant: bytes,
            *,
            expected: dict[str, Any] | None = None,
        ) -> ConnectorGrantClaims:
            assert self.claims is not None
            if expected is not None:
                assert self.claims.request_id == expected["request_id"]
                assert self.claims.connection_ref == expected["connection_ref"]
                assert self.claims.provider_id == expected["provider_id"]
                assert self.claims.operation_id == expected["operation_id"]
                assert self.claims.resource_ref == expected["resource_ref"]
                assert self.claims.arguments_digest_sha256 == expected["arguments_digest_sha256"]
            return self.claims

        def consume(
            self,
            grant: bytes,
            *,
            expected: dict[str, Any] | None = None,
        ) -> ConnectorGrantClaims:
            if self.consumed:
                raise AssertionError("one-use grant was consumed twice")
            self.consumed = True
            return self.inspect(grant, expected=expected)

    class _Computer:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def call_provider_tool(
            self, *, tool_id: str, payload: Mapping[str, object]
        ) -> dict[str, Any]:
            self.calls.append({"tool_id": tool_id, "payload": dict(payload)})
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_UNAVAILABLE",
                title="Computer runner unavailable",
                detail="Controlled transport loss after dispatch.",
                status=503,
                retryable=True,
            )

    authority = _Authority()
    grant_verifier = _GrantVerifier()
    computer = _Computer()
    dispatcher = ConnectorOperationDispatcher(
        store=store,
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
        computer=computer,
        computer_runner_profile=profile,
    )
    services = IntegrationServices(
        store=store,
        authorizer=None,
        accounts=SimpleNamespace(),  # type: ignore[arg-type]
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=principal,
        navigator_hmac_authenticator=NavigatorHmacAuthenticator(
            NavigatorHmacSettings(key_id="navigator-computer-v1", key_file=key_file),
            replay_guard=store,
        ),
        connector_grant_authority=authority,
        connector_grant_verifier=grant_verifier,
        connector_operation_dispatcher=dispatcher,
        computer_runner_client=computer,
        computer_runner_profile=profile,
    )
    app = create_app(database_path=tmp_path / "computer-gateway.sqlite3", integrations=services)
    arguments: dict[str, Any] = {
        "path": "src/assistant.txt",
        "content_base64": "YQ==",
        "overwrite": True,
    }
    request_id = "computer-file-write-unknown"
    target = {
        "workspace_ref": profile.connection_ref,
        "path": "src/assistant.txt",
    }
    resource_ref = _resource_ref(
        provider_id="computer",
        profile_ref=profile.profile_ref,
        operation_id="computer.file.write",
        target=target,
    )

    def navigator_headers(path: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        message = (
            b"POST\n" + path.encode("utf-8") + b"\n" + timestamp.encode("ascii") + b"\n" + body
        )
        return {
            "content-type": "application/json",
            "x-cyrene-navigator-key-id": "navigator-computer-v1",
            "x-cyrene-navigator-timestamp": timestamp,
            "x-cyrene-navigator-signature": hmac.new(key, message, hashlib.sha256).hexdigest(),
        }

    mint_path = "/internal/v1/connector-operation-grants"
    grant_request = {
        "request_id": request_id,
        "workspace_id": profile.workspace_id,
        "principal_issuer": issuer,
        "principal_subject": subject,
        "connection_ref": profile.connection_ref,
        "provider_id": "computer",
        "profile_ref": profile.profile_ref,
        "operation_id": "computer.file.write",
        "resource_ref": resource_ref,
        "arguments": arguments,
        "arguments_digest_sha256": digest_arguments(arguments),
    }
    raw_grant_request = json.dumps(
        grant_request,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    invoke_path = f"/internal/v1/connector-operations/{profile.connection_ref}"
    invoke_request = {
        "request_id": request_id,
        "provider_id": "computer",
        "profile_ref": profile.profile_ref,
        "operation_id": "computer.file.write",
        "resource_ref": resource_ref,
        "arguments": arguments,
    }

    with TestClient(app) as client:
        minted = client.post(
            mint_path,
            content=raw_grant_request,
            headers=navigator_headers(mint_path, raw_grant_request),
        )
        assert minted.status_code == 200, minted.text
        grant_bin = minted.json()["connectorGrantBin"]
        headers = {"x-cyrene-connector-grant-bin": grant_bin}
        first = client.post(invoke_path, json=invoke_request, headers=headers)
        assert first.status_code == 200, first.text
        assert first.json()["outcome"] == "uncertain"
        replay = client.post(invoke_path, json=invoke_request, headers=headers)
        assert replay.status_code == 200, replay.text
        assert replay.json()["outcome"] == "uncertain"
        assert len(authority.calls) == 1
        assert authority.calls[0]["provider_id"] == "computer"
        assert authority.calls[0]["operation_id"] == "computer.file.write"
        assert authority.calls[0]["connection_ref"] == profile.connection_ref
        assert len(computer.calls) == 1
        assert computer.calls[0] == {
            "tool_id": "computer.file.write",
            "payload": arguments,
        }
        row = store._connection.execute(
            "SELECT state FROM connector_invocations WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        assert row is not None and row["state"] == "UNKNOWN_RESULT"


def test_navigator_health_snapshot_is_owner_pinned_and_omits_authorization_refs(
    tmp_path: Path,
) -> None:
    key = b"h" * 32
    key_file = tmp_path / "navigator-health.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    owner = IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject="health-owner",
        organization_id="org-health",
        workspace_id="workspace-health",
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )
    intruder = IntegrationPrincipal(
        issuer=owner.issuer,
        subject="health-intruder",
        organization_id=owner.organization_id,
        workspace_id=owner.workspace_id,
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )
    store = IntegrationStore(tmp_path / "health-snapshot.sqlite3")
    connection = store.create_connection(
        owner,
        CreateIntegrationConnection(
            provider="azure",
            binding_ref="azure-health",
            target_ref="vm-health",
            display_name="Managed VM",
        ),
        idempotency_key="health-owner-connection",
    )
    now = datetime.now(UTC)
    claim = store.claim_authorization_checks("health-monitor", now=now)[0]
    expires_at = now + timedelta(days=3)
    store.complete_authorization_check(
        claim,
        AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref="opaque-useful-for-reauth",
            login_state=LoginState.PRESENT,
            authorization_state=AuthorizationState.REAUTHORIZATION_REQUIRED,
            checked_at=now,
            expires_at=expires_at,
            generation=9,
            capabilities=[
                AuthorizationCapabilityRecord(
                    capability_id="cloud.vm.read",
                    state=AuthorizationState.REAUTHORIZATION_REQUIRED,
                    last_verified_at=now,
                    expires_at=expires_at,
                    reason_code="auth_expired",
                )
            ],
            reason_code="auth_expired",
        ),
        [],
        now=now,
    )
    intruder_connection = store.create_connection(
        intruder,
        CreateIntegrationConnection(
            provider="azure",
            binding_ref="azure-health",
            target_ref="vm-health",
            display_name="Other owner's VM",
        ),
        idempotency_key="health-intruder-connection",
    )

    class Registry:
        def profile_for_connection(
            self,
            principal: IntegrationPrincipal,
            selected: IntegrationConnection,
            *,
            operation_id: str,
        ):
            if (
                operation_id != "integrationGetAuthorizationHealth"
                or principal.subject != owner.subject
                or selected.binding_ref != "azure-health"
            ):
                raise PermissionError("connection is outside configured health profile")
            return SimpleNamespace(), "vm-health"

    class CurrentContextResolver:
        def for_connection(
            self,
            selected: IntegrationConnection,
            *,
            operation_id: str,
        ) -> IntegrationPrincipal | None:
            if (
                selected.actor_subject != owner.subject
                or operation_id != "integrationGetAuthorizationHealth"
            ):
                return None
            return IntegrationPrincipal(
                issuer=owner.issuer,
                subject=owner.subject,
                organization_id=owner.organization_id,
                workspace_id=owner.workspace_id,
                allowed_operation_ids=frozenset({"integrationGetAuthorizationHealth"}),
            )

    authenticator = NavigatorHmacAuthenticator(
        NavigatorHmacSettings(key_id="navigator-health-v1", key_file=key_file),
        replay_guard=store,
    )
    services = IntegrationServices(
        store=store,
        authorizer=None,
        accounts=_Accounts(),  # type: ignore[arg-type]
        github=_GitHub(),  # type: ignore[arg-type]
        webhook_verifier=_WebhookVerifier(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=owner,
        navigator_hmac_authenticator=authenticator,
        authorization_profile_registry=Registry(),
        current_context_resolver=CurrentContextResolver(),
    )
    app = create_app(
        database_path=tmp_path / "health-snapshot-gateway.sqlite3",
        integrations=services,
    )

    def signed_request(request_id: str, connection_ids: list[str]) -> tuple[bytes, dict[str, str]]:
        body = json.dumps(
            {
                "requestId": request_id,
                "organizationId": owner.organization_id,
                "workspaceId": owner.workspace_id,
                "connectionIds": connection_ids,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        message = (
            b"POST\n/internal/v1/authorization-health/snapshots\n"
            + timestamp.encode("ascii")
            + b"\n"
            + body
        )
        headers = {
            "content-type": "application/json",
            "x-cyrene-navigator-key-id": "navigator-health-v1",
            "x-cyrene-navigator-timestamp": timestamp,
            "x-cyrene-navigator-signature": hmac.new(key, message, hashlib.sha256).hexdigest(),
        }
        return body, headers

    path = "/internal/v1/authorization-health/snapshots"
    body, headers = signed_request("snapshot-owner-1", [str(connection.id)])
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)
        denied_body, denied_headers = signed_request(
            "snapshot-owner-2", [str(intruder_connection.id)]
        )
        denied = client.post(path, content=denied_body, headers=denied_headers)

    assert response.status_code == 200, response.text
    snapshot = response.json()
    assert set(snapshot) == {"connections"}
    assert len(snapshot["connections"]) == 1
    item = snapshot["connections"][0]
    assert item["connectionId"] == str(connection.id)
    assert item["provider"] == "azure"
    assert item["loginState"] == "PRESENT"
    assert item["authorizationState"] == "REAUTHORIZATION_REQUIRED"
    assert item["generation"] == 9
    assert item["reasonCode"] == "auth_expired"
    assert item["capabilities"][0]["capabilityId"] == "cloud.vm.read"
    assert "authorizationRef" not in item
    assert "principalSubject" not in item
    assert denied.status_code == 403
    assert "snapshot_connection_scope_mismatch" in denied.text
    store.close()
