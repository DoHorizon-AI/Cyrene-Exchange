"""Worker checks for fresh authority, scheduled monitoring, and closed-client email."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread

from cyrene_exchange_product.integrations.authorization_cloud import (
    AuthorizationCloudRunner,
    EmailSubmissionEvidence,
)
from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudRefreshState,
    CloudResourceRecord,
    CloudResourceState,
    CreateIntegrationConnection,
    IntegrationPrincipal,
    LoginState,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


class _Contexts:
    def __init__(self, principal: IntegrationPrincipal | None) -> None:
        self.principal = principal
        self.connection_calls: list[str] = []
        self.notification_calls: list[str] = []

    def for_connection(self, connection, *, operation_id: str):
        self.connection_calls.append(operation_id)
        return self.principal

    def for_claimed_notification(self, job, *, claim_fence: int, operation_id: str):
        assert job.claim_fence == claim_fence
        self.notification_calls.append(operation_id)
        return self.principal

    def for_sending_notification(self, job, *, claim_fence: int, operation_id: str):
        assert job.claim_fence == claim_fence
        self.notification_calls.append(operation_id)
        return self.principal


class _Provider:
    def __init__(
        self,
        *,
        health_state=AuthorizationState.VALID,
        expires_at: datetime | None = None,
    ) -> None:
        self.health_state = health_state
        self.expires_at = expires_at
        self.health_calls = 0
        self.cloud_calls = 0

    def authorization_health(self, principal, connection) -> AuthorizationHealthRecord:
        self.health_calls += 1
        now = datetime.now(UTC)
        return AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref="native-auth-ref-1",
            login_state=LoginState.PRESENT,
            authorization_state=self.health_state,
            checked_at=now,
            expires_at=self.expires_at or now + timedelta(hours=23),
            generation=4,
        )

    def cloud_resources(self, principal, connection) -> list[CloudResourceRecord]:
        self.cloud_calls += 1
        now = datetime.now(UTC)
        return [
            CloudResourceRecord(
                organization_id=connection.organization_id,
                workspace_id=connection.workspace_id,
                actor_issuer=connection.actor_issuer,
                actor_subject=connection.actor_subject,
                connection_id=connection.id,
                provider=connection.provider,
                source=connection.provider,
                external_ref="cloud-resource-opaque-1",
                kind="azure.vm",
                display_name="Production VM",
                status=CloudResourceState.RUNNING,
                provider_status="running",
                collected_at=now,
                observed_at=now,
                freshness="FRESH",
                attributes={"region": "test-region"},
            )
        ]


class _Email:
    def __init__(self, store: IntegrationStore, *, status: str = "ACCEPTED") -> None:
        self.store = store
        self.status = status
        self.calls: list[str] = []

    def send_notification(self, principal, job) -> EmailSubmissionEvidence:
        row = self.store._connection.execute(
            "SELECT state FROM email_notification_outbox WHERE id=?", (str(job.id),)
        ).fetchone()
        assert row is not None and row["state"] == "SENDING"
        assert principal.subject == job.actor_subject
        self.calls.append(job.request_ref)
        return EmailSubmissionEvidence(
            request_ref=job.request_ref,
            status=self.status,
            vendor_receipt_ref="mail-receipt-opaque-1" if self.status == "ACCEPTED" else None,
            delivery_confirmed=False,
        )


def _principal() -> IntegrationPrincipal:
    """Return current synthetic Directory output with exact worker operation grants."""

    return IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject="actor-worker-1",
        organization_id="org-worker-1",
        workspace_id="workspace-worker-1",
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationGetAuthorizationHealth",
                "integrationRefreshConnectionResources",
                "integrationListNotifications",
                "integrationDeliverNotification",
                "integrationGetOperation",
                "integrationListConnectionResources",
            }
        ),
    )


def _cloud_connection(store: IntegrationStore, principal: IntegrationPrincipal):
    return store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider="azure",
            binding_ref="azure-prod",
            target_ref="vm-prod-1",
            display_name="Production VM",
        ),
        idempotency_key="cloud-worker-connection",
    )


def test_monitor_uses_fresh_authority_and_15_minute_schedule(tmp_path: Path) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _cloud_connection(store, principal)
    contexts = _Contexts(principal)
    provider = _Provider()
    email = _Email(store)
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=contexts,
        provider=provider,
        email=email,
        worker_id="auth-cloud-worker",
        email_recipient_ref="oncall-team",
    )
    first_time = datetime.now(UTC)

    first = runner.run_once(now=first_time)
    second = runner.run_once(now=first_time + timedelta(minutes=1))

    assert first.authorization_checks == 1
    assert first.email_submissions == 1
    assert len(email.calls) == 1 and email.calls[0].startswith("notification:")
    assert provider.health_calls == 1
    assert second.authorization_checks == 0
    assert provider.health_calls == 1
    assert contexts.connection_calls == ["integrationGetAuthorizationHealth"]
    observed = store.latest_authorization_health(principal, connection.id)
    assert observed is not None and observed.authorization_state == AuthorizationState.VALID
    events = store.list_notifications(principal)
    assert len(events) == 1 and events[0].kind.value == "authorization.expiring"
    assert (
        store._connection.execute("SELECT state FROM email_notification_outbox").fetchone()["state"]
        == "ACCEPTED"
    )
    store.close()


def test_missing_current_authority_makes_no_provider_calls(tmp_path: Path) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _cloud_connection(store, principal)
    provider = _Provider()
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=_Contexts(None),
        provider=provider,
        email=None,
        worker_id="auth-cloud-worker",
    )

    result = runner.run_once(now=datetime(2026, 10, 14, 12, tzinfo=UTC))

    assert result.authorization_checks == 1
    assert provider.health_calls == 0
    observed = store.latest_authorization_health(principal, connection.id)
    assert observed is not None
    assert observed.login_state == LoginState.UNAVAILABLE
    assert observed.authorization_state == AuthorizationState.UNAVAILABLE
    assert observed.reason_code == "current_authority_unavailable"
    assert observed.expires_at is None
    store.close()


def test_runner_stops_after_inflight_monitor_without_starting_the_rest_of_the_batch(
    tmp_path: Path,
) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    first_connection = _cloud_connection(store, principal)
    second_connection = store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider="gcp",
            binding_ref="gcp-prod",
            target_ref="gcp-project-1",
            display_name="Production GCP project",
        ),
        idempotency_key="cloud-worker-connection-2",
    )
    refresh = store.enqueue_cloud_refresh(
        principal,
        first_connection.id,
        idempotency_key="shutdown-cloud-refresh",
        now=datetime.now(UTC),
    )

    class _SlowProvider(_Provider):
        def __init__(self) -> None:
            super().__init__(health_state=AuthorizationState.REAUTHORIZATION_REQUIRED)
            self.call_started = Event()
            self.finish_call = Event()
            self.checked_connections = []

        def authorization_health(self, principal, connection) -> AuthorizationHealthRecord:
            self.checked_connections.append(connection.id)
            self.call_started.set()
            if not self.finish_call.wait(timeout=5):
                raise TimeoutError("test provider call was not released")
            return super().authorization_health(principal, connection)

    provider = _SlowProvider()
    email = _Email(store)
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=_Contexts(principal),
        provider=provider,
        email=email,
        worker_id="auth-cloud-worker",
        email_recipient_ref="oncall-team",
    )
    stop_event = Event()
    worker = Thread(target=runner.run_forever, args=(stop_event,), daemon=True)
    worker.start()
    try:
        assert provider.call_started.wait(timeout=2)
        runner.begin_drain()
        stop_event.set()
    finally:
        provider.finish_call.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(provider.checked_connections) == 1
    assert provider.health_calls == 1
    completed_connection_id = provider.checked_connections[0]
    untouched_connection_id = (
        second_connection.id
        if completed_connection_id == first_connection.id
        else first_connection.id
    )
    assert store.latest_authorization_health(principal, completed_connection_id) is not None
    assert store.latest_authorization_health(principal, untouched_connection_id) is None
    assert (
        store.get_cloud_refresh_operation(principal, refresh.id).state == CloudRefreshState.QUEUED
    )
    email_state = store._connection.execute(
        "SELECT state FROM email_notification_outbox"
    ).fetchone()
    assert email_state is not None and email_state["state"] == "READY"
    assert email.calls == []
    store.close()


def test_runner_drain_barrier_prevents_new_claims_before_stop_event_is_set(
    tmp_path: Path,
) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _cloud_connection(store, principal)
    provider = _Provider()
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=_Contexts(principal),
        provider=provider,
        email=None,
        worker_id="auth-cloud-worker",
    )

    runner.begin_drain()
    result = runner.run_once()

    assert result.authorization_checks == 0
    assert result.cloud_refreshes == 0
    assert result.email_submissions == 0
    assert provider.health_calls == 0
    assert store.latest_authorization_health(principal, connection.id) is None
    store.close()


def test_expiry_alerts_have_distinct_24h_and_1h_stages_and_six_hour_reminders(
    tmp_path: Path,
) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    _cloud_connection(store, principal)
    start = datetime(2026, 10, 14, 12, tzinfo=UTC)
    expiration = start + timedelta(hours=25)
    provider = _Provider(expires_at=expiration)
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=_Contexts(principal),
        provider=provider,
        email=None,
        worker_id="auth-cloud-worker",
    )

    runner.run_once(now=start)
    assert store.list_notifications(principal) == []

    runner.run_once(now=start + timedelta(hours=2))
    runner.run_once(now=start + timedelta(hours=24, minutes=1))
    first_page = store.list_notifications(principal)
    assert [item.stage for item in first_page] == ["24h", "1h"]

    runner.run_once(now=start + timedelta(hours=30, minutes=1))
    all_notifications = store.list_notifications(principal)
    assert [item.stage for item in all_notifications] == ["24h", "1h", "1h-reminder-1"]
    store.close()


def test_cloud_refresh_is_independent_and_preserves_last_observation_on_failure(
    tmp_path: Path,
) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _cloud_connection(store, principal)
    operation = store.enqueue_cloud_refresh(
        principal,
        connection.id,
        idempotency_key="worker-cloud-refresh-1",
        now=datetime.now(UTC),
    )
    provider = _Provider()
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=_Contexts(principal),
        provider=provider,
        email=None,
        worker_id="auth-cloud-worker",
    )

    result = runner.run_once(now=datetime.now(UTC))

    assert result.cloud_refreshes == 1
    assert provider.cloud_calls == 1
    assert store.get_cloud_refresh_operation(principal, operation.id).state == (
        CloudRefreshState.SUCCEEDED
    )
    rows = store.list_connection_resources(principal, connection.id)
    assert len(rows) == 1 and rows[0].status == CloudResourceState.RUNNING
    store.close()


def test_email_unknown_is_persisted_and_never_automatically_resent(tmp_path: Path) -> None:
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    _cloud_connection(store, principal)
    provider = _Provider(health_state=AuthorizationState.REAUTHORIZATION_REQUIRED)
    email = _Email(store, status="UNKNOWN")
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=_Contexts(principal),
        provider=provider,
        email=email,
        worker_id="auth-cloud-worker",
        email_recipient_ref="oncall-team",
    )
    now = datetime.now(UTC)

    first = runner.run_once(now=now)
    second = runner.run_once(now=now + timedelta(minutes=1))

    assert first.email_submissions == 1 and first.unknown == 1
    assert second.email_submissions == 0
    assert len(email.calls) == 1
    assert (
        store._connection.execute("SELECT state FROM email_notification_outbox").fetchone()["state"]
        == "UNKNOWN"
    )
    store.close()
