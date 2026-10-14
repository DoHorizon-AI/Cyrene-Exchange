"""Focused authentication tests for the opt-in Product integration REST API."""

from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import grpc
import pytest
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2 as authority_wire,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2_grpc as authority_grpc,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.product.v2 import (
    product_api_pb2 as product_wire,
)
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.auth import PlatformAuthorityIdentityVerifier
from cyrene_exchange_product.integrations.clients import DirectPluginHealthClient
from cyrene_exchange_product.integrations.models import (
    CreateActorBinding,
    CreateIntegrationConnection,
    CreateSyncBinding,
    IntegrationPrincipal,
    ResourceSnapshot,
    SnapshotFreshness,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


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
    body = b'{"repositoryId":"17","repositoryName":"owner/repository"}'
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
            assert idempotency_key == idem
            return {
                "id": "b7649d78-8daf-4be3-b429-e98d9d2d9c92",
                "provider": "github",
                "displayName": "owner/repository",
                "repositoryId": "17",
                "repositoryName": "owner/repository",
                "enabled": True,
                "createdAt": "2026-10-14T00:00:00Z",
                "updatedAt": "2026-10-14T00:00:00Z",
            }

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
