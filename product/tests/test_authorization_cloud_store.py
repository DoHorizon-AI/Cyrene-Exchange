"""Persistence checks for authorization observations and notification delivery."""

from datetime import UTC, datetime, timedelta

import pytest

from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudRefreshState,
    CloudResourceRecord,
    CloudResourceState,
    CreateIntegrationConnection,
    IntegrationConflict,
    IntegrationConnection,
    IntegrationNotFound,
    IntegrationNotificationDraft,
    IntegrationNotificationKind,
    IntegrationPrincipal,
    LoginState,
    NotificationSeverity,
    RenewalState,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


def _principal(subject: str = "actor-a") -> IntegrationPrincipal:
    """Return synthetic verified principal facts with the routes granted."""

    return IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject=subject,
        organization_id="org-a",
        workspace_id="workspace-a",
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationGetAuthorizationHealth",
                "integrationListNotifications",
                "integrationAcknowledgeNotification",
                "accountBeginRenewalSession",
                "accountGetRenewalSession",
                "integrationRefreshConnectionResources",
                "integrationListConnectionResources",
                "integrationGetOperation",
            }
        ),
    )


def _connection(store: IntegrationStore) -> tuple[IntegrationPrincipal, IntegrationConnection]:
    """Create one synthetic GitHub connection for scope and monitor tests."""

    principal = _principal()
    connection = store.create_connection(
        principal,
        CreateIntegrationConnection(repository_id="repo-1", repository_name="example/repo"),
        idempotency_key="connection-auth-health",
    )
    return principal, connection


def _health(
    connection: IntegrationConnection,
    *,
    state: AuthorizationState = AuthorizationState.VALID,
) -> AuthorizationHealthRecord:
    """Build one sanitized authorization observation from stored connection ownership."""

    return AuthorizationHealthRecord(
        organization_id=connection.organization_id,
        workspace_id=connection.workspace_id,
        actor_issuer=connection.actor_issuer,
        actor_subject=connection.actor_subject,
        connection_id=connection.id,
        authorization_ref="authorization:opaque-1",
        login_state=LoginState.PRESENT,
        authorization_state=state,
        checked_at=datetime(2026, 10, 14, 12, tzinfo=UTC),
        expires_at=datetime(2026, 10, 16, 12, tzinfo=UTC),
        generation=3,
    )


def _draft(connection: IntegrationConnection, dedupe_key: str) -> IntegrationNotificationDraft:
    """Build a bounded notification without identity or credential material."""

    return IntegrationNotificationDraft(
        connection_id=connection.id,
        kind=IntegrationNotificationKind.AUTHORIZATION_EXPIRING,
        severity=NotificationSeverity.WARNING,
        title="Authorization expires soon",
        description="Reconnect this provider before its known expiry.",
        action_ref="/integrations/connections/authorization",
        dedupe_key=dedupe_key,
        incident_key=f"authorization:{connection.id}:3",
        stage="24h",
    )


def _cloud_connection(
    store: IntegrationStore,
) -> tuple[IntegrationPrincipal, IntegrationConnection]:
    """Create one cloud connection through opaque host-configuration aliases."""

    actor = _principal()
    connection = store.create_connection(
        actor,
        CreateIntegrationConnection(
            provider="azure",
            binding_ref="azure-prod",
            target_ref="vm-prod-a",
            display_name="Production VM",
        ),
        idempotency_key="cloud-connection-1",
    )
    return actor, connection


def _cloud_observation(
    connection: IntegrationConnection,
    *,
    status: CloudResourceState = CloudResourceState.RUNNING,
    collected_at: datetime | None = None,
) -> CloudResourceRecord:
    """Build a bounded provider observation for store-only integration tests."""

    return CloudResourceRecord(
        organization_id=connection.organization_id,
        workspace_id=connection.workspace_id,
        actor_issuer=connection.actor_issuer,
        actor_subject=connection.actor_subject,
        connection_id=connection.id,
        provider=connection.provider,
        source=connection.provider,
        external_ref="azure-vm:opaque-1",
        kind="azure.vm",
        display_name="Production VM",
        status=status,
        provider_status=status.value,
        collected_at=collected_at or datetime(2026, 10, 14, 12, tzinfo=UTC),
        observed_at=collected_at or datetime(2026, 10, 14, 11, 59, tzinfo=UTC),
        freshness="FRESH",
        attributes={"region": "test-region", "size": "small"},
    )


def test_monitor_claim_is_fenced_and_observation_survives_restart(tmp_path) -> None:
    database = tmp_path / "integrations.sqlite3"
    store = IntegrationStore(database)
    principal, connection = _connection(store)
    start = datetime(2026, 10, 14, 12, tzinfo=UTC)

    first = store.claim_authorization_checks("monitor-a", now=start, lease_seconds=5)
    assert len(first) == 1
    assert store.claim_authorization_checks("monitor-b", now=start) == []
    expired = store.claim_authorization_checks(
        "monitor-b", now=start + timedelta(seconds=6), lease_seconds=5
    )
    assert len(expired) == 1
    assert expired[0].claim_fence == first[0].claim_fence + 1

    with pytest.raises(IntegrationConflict):
        store.complete_authorization_check(
            first[0],
            _health(connection),
            [],
            now=start + timedelta(seconds=6),
        )

    committed = store.complete_authorization_check(
        expired[0],
        _health(connection),
        [_draft(connection, "authorization:3:24h")],
        now=start + timedelta(seconds=6),
    )
    assert len(committed) == 1
    persisted = store.latest_authorization_health(principal, connection.id)
    assert persisted is not None
    assert persisted.generation == 3
    assert persisted.authorization_ref == "authorization:opaque-1"
    store.close()

    restarted = IntegrationStore(database)
    persisted = restarted.latest_authorization_health(principal, connection.id)
    feed = restarted.list_notifications(principal)
    assert persisted is not None
    assert persisted.authorization_state == AuthorizationState.VALID
    assert len(feed) == 1 and feed[0].sequence == 1
    restarted.close()


def test_monitor_restart_with_reused_worker_id_still_increments_claim_fence(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "monitor-restart.sqlite3")
    _principal, connection = _connection(store)
    start = datetime(2026, 10, 14, 12, tzinfo=UTC)
    worker_id = "exchange-connectors"

    before_restart = store.claim_authorization_checks(
        worker_id,
        now=start,
        lease_seconds=5,
    )[0]
    after_restart = store.claim_authorization_checks(
        worker_id,
        now=start + timedelta(seconds=6),
        lease_seconds=5,
    )[0]

    assert after_restart.worker_id == before_restart.worker_id
    assert after_restart.claim_fence == before_restart.claim_fence + 1
    with pytest.raises(IntegrationConflict):
        store.complete_authorization_check(
            before_restart,
            _health(connection),
            [],
            now=start + timedelta(seconds=6),
        )
    store.complete_authorization_check(
        after_restart,
        _health(connection),
        [],
        now=start + timedelta(seconds=6),
    )
    store.close()


def test_unknown_health_is_preserved_without_inventing_validity(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    principal, connection = _connection(store)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("monitor", now=now)[0]

    store.complete_authorization_check(
        claim,
        _health(connection, state=AuthorizationState.UNKNOWN).model_copy(
            update={"login_state": LoginState.UNKNOWN, "expires_at": None}
        ),
        [],
        now=now,
    )

    observed = store.latest_authorization_health(principal, connection.id)
    assert observed is not None
    assert observed.login_state == LoginState.UNKNOWN
    assert observed.authorization_state == AuthorizationState.UNKNOWN
    assert observed.expires_at is None
    store.close()


def test_notification_feed_ack_is_actor_scoped_and_idempotent(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    principal, connection = _connection(store)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("monitor", now=now)[0]
    store.complete_authorization_check(
        claim,
        _health(connection),
        [_draft(connection, "alert-1"), _draft(connection, "alert-2")],
        now=now,
    )

    first_page = store.list_notifications(principal, after_sequence=0, limit=1)
    second_page = store.list_notifications(principal, after_sequence=first_page[-1].sequence)
    assert len(first_page) == 1 and len(second_page) == 1
    first_ack = store.acknowledge_notification(
        principal, first_page[0].id, idempotency_key="ack-1", now=now
    )
    replay = store.acknowledge_notification(
        principal, first_page[0].id, idempotency_key="ack-1", now=now + timedelta(minutes=1)
    )
    assert replay.acknowledged_at == first_ack.acknowledged_at

    other = _principal("actor-b")
    assert store.list_notifications(other) == []
    with pytest.raises(IntegrationNotFound):
        store.acknowledge_notification(other, first_page[0].id, idempotency_key="cross-user")
    with pytest.raises(IntegrationConflict):
        store.acknowledge_notification(
            principal, second_page[0].id, idempotency_key="ack-1", now=now
        )
    store.close()


def test_email_sending_recovery_becomes_unknown_and_is_not_resent(tmp_path) -> None:
    database = tmp_path / "integrations.sqlite3"
    store = IntegrationStore(database)
    _, connection = _connection(store)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("monitor", now=now)[0]
    store.complete_authorization_check(
        claim,
        _health(connection),
        [_draft(connection, "email-alert")],
        now=now,
        email_recipient_ref="oncall-team",
    )

    email = store.claim_email_notification("mail-worker", now=now, lease_seconds=2)
    assert email is not None
    sending = store.mark_email_sending(email.job.id, claim_fence=email.claim_fence, now=now)
    assert sending.state.value == "SENDING"
    assert store.claim_email_notification("mail-worker-2", now=now + timedelta(seconds=3)) is None
    store.close()

    restarted = IntegrationStore(database)
    assert (
        restarted.claim_email_notification("mail-worker-3", now=now + timedelta(seconds=4)) is None
    )
    row = restarted._connection.execute(
        "SELECT document FROM email_notification_outbox WHERE id=?", (str(email.job.id),)
    ).fetchone()
    assert row is not None
    assert "UNKNOWN" in str(row["document"])
    restarted.close()


def test_renewal_session_intent_is_durable_before_provider_call(tmp_path) -> None:
    database = tmp_path / "integrations.sqlite3"
    store = IntegrationStore(database)
    principal = _principal()
    session, created = store.begin_renewal_session(
        principal,
        "authorization:opaque-1",
        idempotency_key="renewal-start-1",
        now=datetime(2026, 10, 14, 12, tzinfo=UTC),
    )
    assert created is True
    assert session.state == RenewalState.VERIFYING
    assert session.provider_session_ref is None

    # A crash after the provider call cannot replay the start: the durable intent wins.
    store.close()
    restarted = IntegrationStore(database)
    replay, created = restarted.begin_renewal_session(
        principal,
        "authorization:opaque-1",
        idempotency_key="renewal-start-1",
        now=datetime(2026, 10, 14, 12, 1, tzinfo=UTC),
    )
    assert created is False
    assert replay.session_ref == session.session_ref
    assert replay.state == RenewalState.VERIFYING
    assert replay.provider_session_ref is None

    saved = restarted.complete_renewal_session_start(
        principal,
        session.authorization_ref,
        session.session_ref,
        provider_session_ref="provider-session:opaque-1",
        state=RenewalState.WAITING_USER,
        expires_at=datetime(2026, 10, 14, 13, tzinfo=UTC),
        authorization_url="https://login.example.test/authorize?opaque=1",
        qr_attachment_ref=None,
        generation=3,
    )
    completed_replay = restarted.get_renewal_session_for_idempotency(
        principal, session.authorization_ref, idempotency_key="renewal-start-1"
    )
    assert completed_replay == saved
    assert (
        restarted.get_renewal_session(principal, session.authorization_ref, session.session_ref)
        == saved
    )

    other = _principal("actor-b")
    with pytest.raises(IntegrationNotFound):
        restarted.get_renewal_session(other, session.authorization_ref, session.session_ref)
    restarted.close()

    after_restart = IntegrationStore(database)
    assert (
        after_restart.get_renewal_session(principal, session.authorization_ref, session.session_ref)
        == saved
    )
    after_restart.close()


def test_cloud_refresh_is_scoped_deduplicated_and_compares_provider_state(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    principal, connection = _cloud_connection(store)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    queued = store.enqueue_cloud_refresh(
        principal, connection.id, idempotency_key="refresh-1", now=now
    )
    replay = store.enqueue_cloud_refresh(
        principal, connection.id, idempotency_key="refresh-1", now=now
    )
    assert replay.id == queued.id

    first_claim = store.claim_cloud_refresh("cloud-worker-a", now=now, lease_seconds=5)
    assert first_claim is not None
    assert first_claim.operation.state == CloudRefreshState.RUNNING
    _, first_events = store.complete_cloud_refresh(
        first_claim,
        [_cloud_observation(connection, collected_at=now)],
        state=CloudRefreshState.SUCCEEDED,
        now=now,
    )
    assert first_events == []
    listed = store.list_connection_resources(principal, connection.id, now=now)
    assert len(listed) == 1 and listed[0].freshness.value == "FRESH"

    changed_time = now + timedelta(minutes=1)
    next_operation = store.enqueue_cloud_refresh(
        principal, connection.id, idempotency_key="refresh-2", now=changed_time
    )
    second_claim = store.claim_cloud_refresh("cloud-worker-a", now=changed_time)
    assert second_claim is not None and second_claim.operation.id == next_operation.id
    _, change_events = store.complete_cloud_refresh(
        second_claim,
        [
            _cloud_observation(
                connection,
                status=CloudResourceState.STOPPED,
                collected_at=changed_time,
            )
        ],
        state=CloudRefreshState.SUCCEEDED,
        now=changed_time,
    )
    assert len(change_events) == 1
    assert change_events[0].kind == IntegrationNotificationKind.CLOUD_RESOURCE_CHANGED

    quiet_time = now + timedelta(minutes=2)
    third_operation = store.enqueue_cloud_refresh(
        principal, connection.id, idempotency_key="refresh-3", now=quiet_time
    )
    third_claim = store.claim_cloud_refresh("cloud-worker-a", now=quiet_time)
    assert third_claim is not None and third_claim.operation.id == third_operation.id
    _, quiet_events = store.complete_cloud_refresh(
        third_claim,
        [
            _cloud_observation(
                connection,
                status=CloudResourceState.STOPPED,
                collected_at=quiet_time,
            )
        ],
        state=CloudRefreshState.SUCCEEDED,
        now=quiet_time,
    )
    assert quiet_events == []
    assert len(store.list_notifications(principal)) == 1
    store.close()


def test_cloud_refresh_failure_preserves_stale_observation_and_fences_recovery(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    principal, connection = _cloud_connection(store)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    operation = store.enqueue_cloud_refresh(
        principal, connection.id, idempotency_key="refresh-fail-base", now=now
    )
    claimed = store.claim_cloud_refresh("cloud-worker-a", now=now, lease_seconds=2)
    assert claimed is not None
    store.complete_cloud_refresh(
        claimed,
        [_cloud_observation(connection, collected_at=now)],
        state=CloudRefreshState.SUCCEEDED,
        now=now,
    )

    failed_operation = store.enqueue_cloud_refresh(
        principal,
        connection.id,
        idempotency_key="refresh-fail-next",
        now=now + timedelta(minutes=1),
    )
    stale_claim = store.claim_cloud_refresh(
        "cloud-worker-a", now=now + timedelta(minutes=1), lease_seconds=2
    )
    assert stale_claim is not None and stale_claim.operation.id == failed_operation.id
    recovered = store.claim_cloud_refresh(
        "cloud-worker-b", now=now + timedelta(minutes=1, seconds=3), lease_seconds=2
    )
    assert recovered is not None
    assert recovered.operation.id == failed_operation.id
    assert recovered.claim_fence == stale_claim.claim_fence + 1
    with pytest.raises(IntegrationConflict):
        store.complete_cloud_refresh(
            stale_claim,
            [],
            state=CloudRefreshState.UNKNOWN,
            now=now + timedelta(minutes=1, seconds=3),
        )
    store.complete_cloud_refresh(
        recovered,
        [],
        state=CloudRefreshState.UNKNOWN,
        now=now + timedelta(minutes=1, seconds=3),
    )
    listed = store.list_connection_resources(
        principal, connection.id, now=now + timedelta(minutes=20)
    )
    assert len(listed) == 1
    assert listed[0].status == CloudResourceState.RUNNING
    assert listed[0].freshness.value == "STALE"
    assert store.get_cloud_refresh_operation(principal, failed_operation.id).state == (
        CloudRefreshState.UNKNOWN
    )
    with pytest.raises(IntegrationNotFound):
        store.get_cloud_refresh_operation(_principal("actor-b"), operation.id)
    store.close()
