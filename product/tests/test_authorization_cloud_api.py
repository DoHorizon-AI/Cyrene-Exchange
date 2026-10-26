"""HTTP boundary checks for actor-scoped authorization, renewal and feed routes."""

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.models import (
    AuthorizationCapabilityRecord,
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudRefreshState,
    CloudResourceRecord,
    CloudResourceState,
    CreateIntegrationConnection,
    IntegrationNotificationDraft,
    IntegrationNotificationKind,
    IntegrationPrincipal,
    LoginState,
    NotificationSeverity,
    RenewalState,
    SnapshotFreshness,
)
from cyrene_exchange_product.integrations.store import IntegrationStore

_ISSUER = "https://identity.example.test"
_WORKSPACE = "workspace-api"
_ORG = "org-api"
_AUTH_REF = "wecom-authorization-native-1"


def _principal(subject: str, operations: set[str]) -> IntegrationPrincipal:
    """Create synthetic verified Directory output for API tests only."""

    return IntegrationPrincipal(
        issuer=_ISSUER,
        subject=subject,
        organization_id=_ORG,
        workspace_id=_WORKSPACE,
        allowed_operation_ids=frozenset(operations),
    )


class _Authorizer:
    def __init__(self, principals: dict[str, IntegrationPrincipal]) -> None:
        self._principals = principals

    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal:
        principal = self._principals[bearer_token]
        assert workspace_id == principal.workspace_id
        return principal


class _AuthorizationCloud:
    supports_durable_renewal_replay = True
    supports_request_id_status_lookup = True

    def __init__(self, *, fail_first_start: bool = False) -> None:
        self.fail_first_start = fail_first_start
        self.start_calls: list[tuple[str, str, str]] = []
        self.status_calls: list[tuple[str, str]] = []
        self.request_id_status_calls: list[tuple[str, str]] = []

    def start_renewal(
        self,
        principal: IntegrationPrincipal,
        connection: Any,
        authorization_ref: str,
        *,
        request_id: str,
    ) -> Any:
        assert principal.subject == connection.actor_subject
        self.start_calls.append((connection.binding_ref, authorization_ref, request_id))
        if self.fail_first_start and len(self.start_calls) == 1:
            raise TimeoutError("synthetic response loss")
        return SimpleNamespace(
            session_ref="provider-renewal-session-1",
            authorization_ref=authorization_ref,
            state=RenewalState.WAITING_USER,
            created_at=datetime(2026, 10, 14, 12, tzinfo=UTC),
            expires_at=datetime(2026, 10, 14, 13, tzinfo=UTC),
            authorization_url=(
                "https://work.weixin.qq.com/ai/qc/gen?source=wecom_cli_external&scode=abcdefgh12345678"
            ),
            qr_attachment_ref="wecom-qr-opaque-1",
            generation=2,
        )

    def renewal_status(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        provider_session_ref: str,
        *,
        request_id: str,
    ) -> Any:
        self.status_calls.append((authorization_ref, provider_session_ref))
        return SimpleNamespace(
            authorization_ref=authorization_ref,
            session_ref=provider_session_ref,
            state=RenewalState.SUCCEEDED,
            expires_at=None,
            authorization_url=None,
            qr_attachment_ref=None,
            generation=3,
        )

    def renewal_status_by_request_id(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        *,
        request_id: str,
        status_request_id: str,
    ) -> Any:
        del principal, status_request_id
        self.request_id_status_calls.append((authorization_ref, request_id))
        return SimpleNamespace(
            authorization_ref=authorization_ref,
            session_ref="provider-renewal-session-1",
            state=RenewalState.WAITING_USER,
            expires_at=datetime(2026, 10, 14, 13, tzinfo=UTC),
            authorization_url=(
                "https://work.weixin.qq.com/ai/qc/gen?source=wecom_cli_external&scode=abcdefgh12345678"
            ),
            qr_attachment_ref="wecom-qr-opaque-1",
            generation=2,
        )


class _UnusedAccounts:
    pass


class _UnusedGitHub:
    pass


class _UnusedWebhookVerifier:
    pass


class _UnusedDelegationAuthorizer:
    pass


def _services(
    store: IntegrationStore,
    actor: IntegrationPrincipal,
    *,
    other: IntegrationPrincipal | None = None,
    authorization_cloud: Any = None,
    email_delivery_recipient_resolver: Any = None,
) -> IntegrationServices:
    """Construct an API with only fixed synthetic capabilities."""

    principals = {"actor-token": actor}
    if other is not None:
        principals["other-token"] = other
    callback_principal = IntegrationPrincipal(
        issuer="urn:cyrene:exchange-service",
        subject="exchange-callback",
        organization_id=_ORG,
        workspace_id=_WORKSPACE,
        allowed_operation_ids=frozenset(),
    )
    return IntegrationServices(
        store=store,
        authorizer=_Authorizer(principals),  # type: ignore[arg-type]
        accounts=_UnusedAccounts(),  # type: ignore[arg-type]
        github=_UnusedGitHub(),  # type: ignore[arg-type]
        webhook_verifier=_UnusedWebhookVerifier(),  # type: ignore[arg-type]
        delegation_authorizer=_UnusedDelegationAuthorizer(),  # type: ignore[arg-type]
        callback_principal=callback_principal,
        authorization_cloud=authorization_cloud,
        email_delivery_recipient_resolver=email_delivery_recipient_resolver,
    )


def _connection(
    store: IntegrationStore,
    principal: IntegrationPrincipal,
    *,
    provider: str = "wecom",
    idempotency_key: str = "connection-api-1",
) -> Any:
    """Persist an owned provider connection with opaque server aliases."""

    return store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider=provider,
            binding_ref="wecom-prod" if provider == "wecom" else "azure-prod",
            target_ref="cloud-vm-1" if provider == "azure" else None,
            account_link_ref="account-center-link-1",
            repository_id="" if provider != "github" else "repo-1",
            repository_name="" if provider != "github" else "owner/repo",
            display_name="Production Integration",
        ),
        idempotency_key=idempotency_key,
    )


def _record_health(
    store: IntegrationStore,
    connection: Any,
    *,
    state: AuthorizationState,
    auth_ref: str | None,
    expires_at: datetime | None = None,
    capabilities: list[AuthorizationCapabilityRecord] | None = None,
    drafts: list[IntegrationNotificationDraft] | None = None,
    checked_at: datetime | None = None,
) -> None:
    """Commit a synthetic verified provider observation through the monitor fence."""

    now = checked_at or datetime(2026, 10, 14, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("api-monitor", now=now)[0]
    store.complete_authorization_check(
        claim,
        AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=auth_ref,
            login_state=(
                LoginState.MISSING
                if state == AuthorizationState.REAUTHORIZATION_REQUIRED
                else LoginState.PRESENT
            ),
            authorization_state=state,
            checked_at=now,
            expires_at=expires_at,
            generation=7,
            capabilities=capabilities or [],
        ),
        drafts or [],
        now=now,
    )


def _assert_http_utc_z(value: Any) -> None:
    """Validate an actual HTTP timestamp using the public Z-only contract."""

    assert isinstance(value, str)
    assert value.endswith("Z")
    assert datetime.fromisoformat(value).utcoffset() == timedelta(0)


def test_connection_list_and_unobserved_health_are_minimal_and_unknown(tmp_path: Path) -> None:
    operations = {
        "integrationCreateConnection",
        "integrationListConnections",
        "integrationGetAuthorizationHealth",
    }
    actor = _principal("actor-a", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    services = _services(store, actor)
    app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)

    with TestClient(app) as client:
        listed = client.get(
            f"/api/v1/integrations/connections?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )
        health = client.get(
            f"/api/v1/integrations/connections/{connection.id}/authorization-health"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )

    assert listed.status_code == 200
    listed_connection = listed.json()[0]
    assert listed_connection | {"createdAt": "", "updatedAt": ""} == {
        "id": str(connection.id),
        "provider": "wecom",
        "displayName": "Production Integration",
        "repositoryId": None,
        "repositoryName": None,
        "enabled": True,
        "createdAt": "",
        "updatedAt": "",
    }
    _assert_http_utc_z(listed_connection["createdAt"])
    _assert_http_utc_z(listed_connection["updatedAt"])
    assert set(listed_connection) == {
        "id",
        "provider",
        "displayName",
        "repositoryId",
        "repositoryName",
        "enabled",
        "createdAt",
        "updatedAt",
    }
    assert health.status_code == 200
    assert health.json()["authorizationRef"] is None
    assert health.json()["loginState"] == "UNKNOWN"
    assert health.json()["authorizationState"] == "UNKNOWN"
    assert health.json()["checkedAt"] is None
    assert health.json()["reasonCode"] == "not_observed"
    store.close()


def test_health_resources_feed_and_operation_serialize_utc_z_timestamps(tmp_path: Path) -> None:
    operations = {
        "integrationCreateConnection",
        "integrationGetAuthorizationHealth",
        "integrationListConnectionResources",
        "integrationRefreshConnectionResources",
        "integrationListNotifications",
        "integrationAcknowledgeNotification",
        "integrationGetOperation",
    }
    actor = _principal("actor-a", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    wecom_connection = _connection(store, actor)
    observed_at = datetime(2026, 10, 14, 12, tzinfo=UTC)
    provider_observed_at = observed_at.astimezone(timezone(timedelta(hours=5)))
    expires_at = provider_observed_at + timedelta(hours=2)
    _record_health(
        store,
        wecom_connection,
        state=AuthorizationState.VALID,
        auth_ref=_AUTH_REF,
        checked_at=provider_observed_at,
        expires_at=expires_at,
        capabilities=[
            AuthorizationCapabilityRecord(
                capability_id="wecom.message.aibot.sessions.list",
                state=AuthorizationState.VALID,
                last_verified_at=provider_observed_at,
                expires_at=expires_at,
            )
        ],
        drafts=[
            IntegrationNotificationDraft(
                connection_id=wecom_connection.id,
                kind=IntegrationNotificationKind.AUTHORIZATION_REQUIRED,
                severity=NotificationSeverity.WARNING,
                title="Authorization notice",
                description="Synthetic notification for timestamp serialization.",
                dedupe_key="utc-http-timestamp-notification",
            )
        ],
    )

    azure_connection = _connection(
        store,
        actor,
        provider="azure",
        idempotency_key="azure-timestamp-connection",
    )
    operation = store.enqueue_cloud_refresh(
        actor,
        azure_connection.id,
        idempotency_key="azure-timestamp-refresh",
        now=observed_at,
    )
    claim = store.claim_cloud_refresh("utc-timestamp-worker", now=observed_at)
    assert claim is not None
    store.complete_cloud_refresh(
        claim,
        [
            CloudResourceRecord(
                organization_id=azure_connection.organization_id,
                workspace_id=azure_connection.workspace_id,
                actor_issuer=azure_connection.actor_issuer,
                actor_subject=azure_connection.actor_subject,
                connection_id=azure_connection.id,
                provider="azure",
                source="azure",
                external_ref="vm-timestamp-1",
                kind="azure.vm",
                display_name="Synthetic VM",
                status=CloudResourceState.RUNNING,
                collected_at=provider_observed_at,
                observed_at=provider_observed_at,
                freshness=SnapshotFreshness.FRESH,
            )
        ],
        state=CloudRefreshState.SUCCEEDED,
        now=observed_at,
    )
    app = create_app(
        database_path=tmp_path / "gateway.sqlite3",
        integrations=_services(store, actor),
    )

    with TestClient(app) as client:
        health = client.get(
            f"/api/v1/integrations/connections/{wecom_connection.id}/authorization-health"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )
        resources = client.get(
            f"/api/v1/integrations/connections/{azure_connection.id}/resources"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )
        feed = client.get(
            f"/api/v1/integrations/notifications?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )
        notification = feed.json()["notifications"][0]
        acknowledged = client.post(
            f"/api/v1/integrations/notifications/{notification['id']}/ack?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "utc-ack-1"},
        )
        operation_status = client.get(
            f"/api/v1/integrations/operations/{operation.id}?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )

    assert health.status_code == 200
    _assert_http_utc_z(health.json()["checkedAt"])
    _assert_http_utc_z(health.json()["expiresAt"])
    _assert_http_utc_z(health.json()["capabilities"][0]["lastVerifiedAt"])
    _assert_http_utc_z(health.json()["capabilities"][0]["expiresAt"])
    assert resources.status_code == 200
    _assert_http_utc_z(resources.json()["checkedAt"])
    _assert_http_utc_z(resources.json()["resources"][0]["collectedAt"])
    _assert_http_utc_z(resources.json()["resources"][0]["observedAt"])
    assert feed.status_code == 200
    _assert_http_utc_z(notification["createdAt"])
    assert acknowledged.status_code == 200
    _assert_http_utc_z(acknowledged.json()["acknowledgedAt"])
    assert operation_status.status_code == 200
    _assert_http_utc_z(operation_status.json()["createdAt"])
    _assert_http_utc_z(operation_status.json()["updatedAt"])
    store.close()


def test_refresh_conflict_contains_server_derived_refs_and_no_identity_fields(
    tmp_path: Path,
) -> None:
    operations = {
        "integrationCreateConnection",
        "integrationListConnectionResources",
        "integrationRefreshConnectionResources",
    }
    actor = _principal("actor-a", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor, provider="azure")
    _record_health(
        store,
        connection,
        state=AuthorizationState.REAUTHORIZATION_REQUIRED,
        auth_ref="native-cloud-auth-1",
    )
    services = _services(store, actor)
    app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)

    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/integrations/connections/{connection.id}/actions/refresh"
            f"?workspaceId={_WORKSPACE}",
            headers={
                "Authorization": "Bearer actor-token",
                "Idempotency-Key": "refresh-blocked-1",
            },
        )
        blocked_read = client.get(
            f"/api/v1/integrations/connections/{connection.id}/resources?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )

    assert response.status_code == 409
    body = response.json()
    assert body["code"] == "EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED"
    assert body["context"] == {
        "connectionId": str(connection.id),
        "authorizationRef": "native-cloud-auth-1",
    }
    assert "actorSubject" not in body and "organizationId" not in body
    assert blocked_read.status_code == 409
    assert blocked_read.json()["context"] == body["context"]
    store.close()


def test_renewal_replays_same_product_session_and_rechecks_status(tmp_path: Path) -> None:
    operations = {
        "integrationCreateConnection",
        "accountBeginRenewalSession",
        "accountGetRenewalSession",
    }
    actor = _principal("actor-a", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    _record_health(store, connection, state=AuthorizationState.VALID, auth_ref=_AUTH_REF)
    provider = _AuthorizationCloud()
    app = create_app(
        database_path=tmp_path / "gateway.sqlite3",
        integrations=_services(store, actor, authorization_cloud=provider),
    )

    with TestClient(app) as client:
        first = client.post(
            f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "renewal-1"},
        )
        replay = client.post(
            f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "renewal-1"},
        )
        session_ref = first.json()["sessionRef"]
        stored = store.get_renewal_session(
            actor, _AUTH_REF, session_ref, authorization_operation_id="accountBeginRenewalSession"
        )
        polled = client.get(
            f"/api/v1/accounts/renewal-sessions/{session_ref}?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )

    assert first.status_code == 202
    assert first.headers["Location"].endswith(session_ref)
    _assert_http_utc_z(first.json()["createdAt"])
    _assert_http_utc_z(first.json()["expiresAt"])
    assert replay.status_code == 202
    assert replay.json()["sessionRef"] == session_ref
    _assert_http_utc_z(replay.json()["createdAt"])
    _assert_http_utc_z(replay.json()["expiresAt"])
    assert len(provider.start_calls) == 1
    assert provider.start_calls[0][2] == session_ref
    assert stored.provider_session_ref == "provider-renewal-session-1"
    assert stored.state == RenewalState.WAITING_USER
    assert app.state.integration_services.authorization_cloud is provider
    assert polled.status_code == 200
    _assert_http_utc_z(polled.json()["createdAt"])
    assert polled.json()["expiresAt"] is None
    assert provider.status_calls, (stored.state, stored.provider_session_ref, polled.json())
    assert polled.json()["state"] == "SUCCEEDED"
    assert provider.status_calls == [(_AUTH_REF, "provider-renewal-session-1")]
    store.close()


def test_huggingface_renewal_returns_device_code_and_tracks_recovery(tmp_path: Path) -> None:
    """HF owner reauthorization reuses Product's durable renewal session API."""

    profile_ref = "30000000-0000-4000-8000-000000000001"
    session_expiry = datetime(2026, 10, 14, 13, tzinfo=UTC)
    operations = {
        "integrationCreateConnection",
        "accountBeginRenewalSession",
        "accountGetRenewalSession",
    }
    actor = _principal("actor-hf", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = store.create_connection(
        actor,
        CreateIntegrationConnection(
            provider="hf",
            binding_ref="hf-primary",
            target_ref="selected-model",
            account_link_ref=profile_ref,
            display_name="Selected Hugging Face profile",
        ),
        idempotency_key="hf-renewal-connection",
    )
    _record_health(
        store,
        connection,
        state=AuthorizationState.REAUTHORIZATION_REQUIRED,
        auth_ref=profile_ref,
    )

    class _HuggingFaceRenewal:
        def __init__(self) -> None:
            self.start_calls: list[tuple[str, str]] = []
            self.poll_calls: list[tuple[str, str]] = []

        def start_renewal(
            self,
            _principal: IntegrationPrincipal,
            selected_connection: Any,
            authorization_ref: str,
            *,
            request_id: str,
        ) -> Any:
            assert selected_connection.provider == "hf"
            self.start_calls.append((authorization_ref, request_id))
            return SimpleNamespace(
                authorization_ref=authorization_ref,
                session_ref=request_id,
                state=RenewalState.WAITING_USER,
                created_at=datetime(2026, 10, 14, 12, tzinfo=UTC),
                expires_at=session_expiry,
                authorization_url="https://hf.co/oauth/device",
                user_code="ABCD-EFGH",
                qr_attachment_ref=None,
                generation=4,
            )

        def renewal_status(
            self,
            _principal: IntegrationPrincipal,
            authorization_ref: str,
            provider_session_ref: str,
            *,
            request_id: str,
        ) -> Any:
            self.poll_calls.append((authorization_ref, provider_session_ref))
            return SimpleNamespace(
                authorization_ref=authorization_ref,
                session_ref=provider_session_ref,
                state=RenewalState.SUCCEEDED,
                expires_at=None,
                authorization_url=None,
                user_code=None,
                qr_attachment_ref=None,
                generation=5,
            )

    provider = _HuggingFaceRenewal()
    app = create_app(
        database_path=tmp_path / "gateway.sqlite3",
        integrations=_services(store, actor, authorization_cloud=provider),
    )
    path = f"/api/v1/accounts/authorizations/{profile_ref}/renewal-sessions"
    with TestClient(app) as client:
        started = client.post(
            f"{path}?workspaceId={_WORKSPACE}",
            headers={
                "Authorization": "Bearer actor-token",
                "Idempotency-Key": "hf-renewal-1",
            },
        )
        session_ref = started.json()["sessionRef"]
        completed = client.get(
            f"/api/v1/accounts/renewal-sessions/{session_ref}?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )

    assert started.status_code == 202, started.text
    assert started.json()["authorizationUrl"] == "https://hf.co/oauth/device"
    assert started.json()["userCode"] == "ABCD-EFGH"
    assert started.json()["qrAttachmentRef"] is None
    assert "device_code" not in started.text
    assert "access_token" not in started.text
    assert completed.status_code == 200, completed.text
    assert completed.json()["state"] == "SUCCEEDED"
    assert completed.json()["userCode"] is None
    assert provider.start_calls == [(profile_ref, session_ref)]
    assert provider.poll_calls == [(profile_ref, session_ref)]
    store.close()


def test_ambiguous_renewal_start_replays_only_same_key_and_request_id(tmp_path: Path) -> None:
    operations = {"integrationCreateConnection", "accountBeginRenewalSession"}
    actor = _principal("actor-a", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    _record_health(store, connection, state=AuthorizationState.VALID, auth_ref=_AUTH_REF)
    provider = _AuthorizationCloud(fail_first_start=True)
    app = create_app(
        database_path=tmp_path / "gateway.sqlite3",
        integrations=_services(store, actor, authorization_cloud=provider),
    )

    with TestClient(app) as client:
        first = client.post(
            f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "renewal-unknown"},
        )
        replay = client.post(
            f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "renewal-unknown"},
        )

    assert first.status_code == replay.status_code == 202
    assert first.json()["state"] == "VERIFYING"
    assert first.json()["reasonCode"] == "provider_start_outcome_unknown"
    assert first.json()["authorizationUrl"] is None
    assert replay.json()["sessionRef"] == first.json()["sessionRef"]
    assert provider.start_calls[0][2] == provider.start_calls[1][2] == first.json()["sessionRef"]
    assert replay.json()["state"] == "WAITING_USER"
    store.close()


def test_unknown_start_get_uses_only_provider_read_status_lookup(tmp_path: Path) -> None:
    operations = {
        "integrationCreateConnection",
        "accountBeginRenewalSession",
        "accountGetRenewalSession",
    }
    actor = _principal("actor-a", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    _record_health(store, connection, state=AuthorizationState.VALID, auth_ref=_AUTH_REF)
    provider = _AuthorizationCloud(fail_first_start=True)
    app = create_app(
        database_path=tmp_path / "gateway.sqlite3",
        integrations=_services(store, actor, authorization_cloud=provider),
    )

    with TestClient(app) as client:
        started = client.post(
            f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "renewal-lookup"},
        )
        session_ref = started.json()["sessionRef"]
        status = client.get(
            f"/api/v1/accounts/renewal-sessions/{session_ref}?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )

    assert started.json()["state"] == "VERIFYING"
    assert status.json()["state"] == "WAITING_USER"
    assert len(provider.start_calls) == 1
    assert provider.request_id_status_calls == [(_AUTH_REF, session_ref)]
    restarted = IntegrationStore(tmp_path / "integrations.sqlite3")
    session = restarted.get_renewal_session(
        actor, _AUTH_REF, session_ref, authorization_operation_id="accountGetRenewalSession"
    )
    assert session.provider_session_ref == "provider-renewal-session-1"
    restarted.close()


def test_notification_feed_ack_and_sse_resume_are_actor_scoped(tmp_path: Path) -> None:
    operations = {
        "integrationCreateConnection",
        "integrationListNotifications",
        "integrationAcknowledgeNotification",
    }
    actor = _principal("actor-a", operations)
    other = _principal("actor-b", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("notify-worker", now=now)[0]
    health = AuthorizationHealthRecord(
        organization_id=connection.organization_id,
        workspace_id=connection.workspace_id,
        actor_issuer=connection.actor_issuer,
        actor_subject=connection.actor_subject,
        connection_id=connection.id,
        authorization_ref=_AUTH_REF,
        login_state=LoginState.PRESENT,
        authorization_state=AuthorizationState.VALID,
        checked_at=now,
        expires_at=None,
        generation=1,
    )
    store.complete_authorization_check(
        claim,
        health,
        [
            IntegrationNotificationDraft(
                connection_id=connection.id,
                kind=IntegrationNotificationKind.AUTHORIZATION_REQUIRED,
                severity=NotificationSeverity.ERROR,
                title="Reconnect required",
                description="The provider confirmed reauthorization is required.",
                action_ref=f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions",
                dedupe_key="api-notification-1",
                incident_key="api-incident-1",
                stage="required",
            )
        ],
        now=now,
    )

    class _UnexpectedExecutionVerifier:
        def verify(self, _credential: bytes) -> Any:
            raise AssertionError("SSE must not accept generic Product execution credentials")

    services = _services(store, actor, other=other)
    services.execution_authorization_verifier = _UnexpectedExecutionVerifier()
    app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)

    with TestClient(app) as client:
        feed = client.get(
            f"/api/v1/integrations/notifications?workspaceId={_WORKSPACE}&after=0",
            headers={"Authorization": "Bearer actor-token"},
        )
        event = feed.json()["notifications"][0]
        ack = client.post(
            f"/api/v1/integrations/notifications/{event['id']}/ack?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Idempotency-Key": "ack-1"},
        )
        recovered = client.get(
            f"/api/v1/integrations/notifications?workspaceId={_WORKSPACE}&after={event['sequence']}",
            headers={"Authorization": "Bearer actor-token"},
        )
        other_feed = client.get(
            f"/api/v1/integrations/notifications?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer other-token"},
        )
        with client.stream(
            "GET",
            f"/api/v1/integrations/notifications/events?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token", "Last-Event-ID": "0"},
        ) as stream:
            sse_lines = list(stream.iter_lines())
            sse_id = next(line for line in sse_lines if line.startswith("id:"))
            sse_event = json.loads(
                next(line for line in sse_lines if line.startswith("data: "))[len("data: ") :]
            )
        execution_credential = client.get(
            f"/api/v1/integrations/notifications/events?workspaceId={_WORKSPACE}",
            headers={"X-Cyrene-Execution-Credential-Bin": "opaque-signed-credential"},
        )

    assert feed.status_code == 200 and feed.json()["nextSequence"] == event["sequence"]
    _assert_http_utc_z(event["createdAt"])
    assert ack.status_code == 200 and ack.json()["acknowledgedAt"] is not None
    _assert_http_utc_z(ack.json()["acknowledgedAt"])
    assert recovered.status_code == 200 and recovered.json()["notifications"] == []
    assert other_feed.status_code == 200 and other_feed.json()["notifications"] == []
    assert sse_id == f"id: {event['sequence']}"
    _assert_http_utc_z(sse_event["createdAt"])
    assert execution_credential.status_code == 403
    assert execution_credential.json()["code"] == "EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH"
    store.close()


def test_dedicated_delivery_command_queues_one_actor_scoped_email_operation(
    tmp_path: Path,
) -> None:
    operations = {
        "integrationCreateConnection",
        "integrationGetAuthorizationHealth",
        "integrationListNotifications",
        "integrationDeliverNotification",
        "integrationGetOperation",
    }
    actor = _principal("actor-a", operations)
    other = _principal("actor-b", operations)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("mail-api-monitor", now=now)[0]
    store.complete_authorization_check(
        claim,
        AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=_AUTH_REF,
            login_state=LoginState.PRESENT,
            authorization_state=AuthorizationState.VALID,
            checked_at=now,
            expires_at=None,
            generation=1,
        ),
        [
            IntegrationNotificationDraft(
                connection_id=connection.id,
                kind=IntegrationNotificationKind.AUTHORIZATION_REQUIRED,
                severity=NotificationSeverity.ERROR,
                title="Reconnect WeCom",
                description="The provider requires authorization.",
                dedupe_key="explicit-mail-delivery",
            )
        ],
        now=now,
    )
    notification = store.list_notifications(actor)[0]
    services = _services(
        store,
        actor,
        other=other,
        email_delivery_recipient_resolver=lambda principal: (
            "oncall" if principal.subject == actor.subject else None
        ),
    )
    app = create_app(database_path=tmp_path / "gateway.sqlite3", integrations=services)

    with TestClient(app) as client:
        first = client.post(
            f"/api/v1/integrations/notifications/{notification.id}/actions/deliver"
            f"?workspaceId={_WORKSPACE}",
            headers={
                "Authorization": "Bearer actor-token",
                "Idempotency-Key": "deliver-one",
            },
        )
        replay = client.post(
            f"/api/v1/integrations/notifications/{notification.id}/actions/deliver"
            f"?workspaceId={_WORKSPACE}",
            headers={
                "Authorization": "Bearer actor-token",
                "Idempotency-Key": "deliver-one",
            },
        )
        status = client.get(
            f"{first.headers['location']}?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer actor-token"},
        )
        cross_actor = client.get(
            first.headers["location"],
            headers={
                "Authorization": "Bearer other-token",
                "X-Cyrene-Workspace-Id": _WORKSPACE,
            },
        )

    assert first.status_code == 202
    assert replay.status_code == 202
    assert replay.json()["operationId"] == first.json()["operationId"]
    assert first.headers["location"].endswith(first.json()["operationId"])
    assert status.status_code == 200
    assert status.json()["state"] == "QUEUED"
    assert status.json()["result"]["deliveryStatus"] == "READY"
    assert "recipientRef" not in status.text and "actorSubject" not in status.text
    assert cross_actor.status_code == 404
    restarted = IntegrationStore(tmp_path / "integrations.sqlite3")
    row = restarted._connection.execute(
        "SELECT COUNT(*) AS total FROM email_notification_outbox WHERE notification_id=?",
        (str(notification.id),),
    ).fetchone()
    assert row is not None and row["total"] == 1
    restarted.close()


def test_other_actor_cannot_reuse_authorization_ref_or_session(tmp_path: Path) -> None:
    actor = _principal("actor-a", {"integrationCreateConnection", "accountBeginRenewalSession"})
    other = _principal("actor-b", {"accountBeginRenewalSession"})
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, actor)
    _record_health(store, connection, state=AuthorizationState.VALID, auth_ref=_AUTH_REF)
    app = create_app(
        database_path=tmp_path / "gateway.sqlite3",
        integrations=_services(
            store, actor, other=other, authorization_cloud=_AuthorizationCloud()
        ),
    )

    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/accounts/authorizations/{_AUTH_REF}/renewal-sessions"
            f"?workspaceId={_WORKSPACE}",
            headers={"Authorization": "Bearer other-token", "Idempotency-Key": "cross-user"},
        )

    assert response.status_code == 404
    store.close()
