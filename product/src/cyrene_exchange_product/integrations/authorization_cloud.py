"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 authorization_cloud.py                                         │
│  Module: cyrene_exchange_product.integrations.authorization_cloud   │
│  Role: Fixed authorization/cloud monitoring and email outbox worker. │
│                                                                      │
│  模块职责：运行固定 Provider 观察、授权监控与邮件发件箱。                  │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Event, Lock
from typing import Protocol

from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    ClaimedAuthorizationMonitor,
    CloudRefreshState,
    CloudResourceRecord,
    EmailNotificationJob,
    IntegrationConnection,
    IntegrationNotificationDraft,
    IntegrationNotificationKind,
    IntegrationPrincipal,
    LoginState,
    NotificationSeverity,
    RenewalState,
    utc_now,
)
from cyrene_exchange_product.integrations.store import IntegrationStore

_MONITOR_OPERATION = "integrationGetAuthorizationHealth"
_REFRESH_OPERATION = "integrationRefreshConnectionResources"
_DELIVER_OPERATION = "integrationDeliverNotification"
_MONITOR_INTERVAL_SECONDS = 15 * 60
_REMINDER_INTERVAL_SECONDS = 6 * 60 * 60
_EXPIRY_WARNING_SECONDS = 24 * 60 * 60
_EXPIRY_URGENT_SECONDS = 60 * 60
_OPAQUE_AUTHORIZATION_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,299}$")
_LOGGER = logging.getLogger(__name__)


class CurrentAuthorizationContextPort(Protocol):
    """Resolve fresh Directory/delegation evidence before each background call."""

    def for_connection(
        self,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> IntegrationPrincipal | None: ...

    def for_claimed_notification(
        self,
        job: EmailNotificationJob,
        *,
        claim_fence: int,
        operation_id: str,
    ) -> IntegrationPrincipal | None: ...

    def for_sending_notification(
        self,
        job: EmailNotificationJob,
        *,
        claim_fence: int,
        operation_id: str,
    ) -> IntegrationPrincipal | None: ...


class AuthorizationCloudProviderPort(Protocol):
    """Fixed provider calls mapped onto Product-owned typed observations."""

    supports_durable_renewal_replay: bool
    supports_request_id_status_lookup: bool

    def authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
    ) -> AuthorizationHealthRecord: ...

    def cloud_resources(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
    ) -> list[CloudResourceRecord]: ...

    def start_renewal(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        authorization_ref: str,
        *,
        request_id: str,
    ) -> ProviderRenewalSession: ...

    def renewal_status(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        provider_session_ref: str,
        *,
        request_id: str,
    ) -> ProviderRenewalSession: ...

    def renewal_status_by_request_id(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        *,
        request_id: str,
        status_request_id: str,
    ) -> ProviderRenewalSession: ...


@dataclass(frozen=True, slots=True)
class EmailSubmissionEvidence:
    """Sanitized result mapped from the fixed email notification tool."""

    request_ref: str
    status: str
    vendor_receipt_ref: str | None = None
    delivery_confirmed: bool = False


@dataclass(frozen=True, slots=True)
class ProviderRenewalSession:
    """Provider-session facts mapped from the shared SDK DTO."""

    authorization_ref: str
    session_ref: str
    state: RenewalState
    created_at: datetime
    expires_at: datetime | None
    authorization_url: str | None
    qr_attachment_ref: str | None
    generation: int
    user_code: str | None = None


class EmailNotificationPort(Protocol):
    """Send one configured recipient alias through the independent mail adapter."""

    def send_notification(
        self,
        principal: IntegrationPrincipal,
        job: EmailNotificationJob,
    ) -> EmailSubmissionEvidence: ...


class ProviderObservationUnavailable(RuntimeError):
    """A fixed provider read could not return a current observation."""


class EmailAuthorizationUnavailable(RuntimeError):
    """Current Platform delivery authority is missing before provider I/O."""


class EmailDeliveryRetryableError(RuntimeError):
    """Email provider confirms that a failure happened before its side effect."""


@dataclass(frozen=True, slots=True)
class AuthorizationCloudRunResult:
    """One worker cycle summary with only counts and sanitized outcome labels."""

    authorization_checks: int
    cloud_refreshes: int
    email_submissions: int
    deferred: int
    unknown: int


class AuthorizationCloudRunner:
    """Run fenced health checks, read-only cloud queries, and email outbox sends."""

    def __init__(
        self,
        *,
        store: IntegrationStore,
        contexts: CurrentAuthorizationContextPort,
        provider: AuthorizationCloudProviderPort,
        email: EmailNotificationPort | None,
        worker_id: str,
        email_recipient_ref: str | None = None,
        email_recipient_resolver: Callable[[IntegrationConnection], str | None] | None = None,
        monitor_interval_seconds: int = _MONITOR_INTERVAL_SECONDS,
        idle_delay_seconds: float = 1.0,
    ) -> None:
        if not worker_id.strip() or not 0.05 <= idle_delay_seconds <= 30:
            raise ValueError("authorization/cloud worker configuration is invalid")
        if not 60 <= monitor_interval_seconds <= 86_400:
            raise ValueError("authorization monitor interval is invalid")
        self._store = store
        self._contexts = contexts
        self._provider = provider
        self._email = email
        self._worker_id = worker_id
        self._email_recipient_ref = email_recipient_ref
        self._email_recipient_resolver = email_recipient_resolver
        self._monitor_interval_seconds = monitor_interval_seconds
        self._idle_delay_seconds = idle_delay_seconds
        self._claim_gate = Lock()
        self._draining = Event()

    @property
    def monitor_interval_seconds(self) -> int:
        """Expose the durable health cadence for host lifecycle validation."""

        return self._monitor_interval_seconds

    def begin_drain(self) -> None:
        """Fence new durable claims before the host begins waiting for this worker."""

        with self._claim_gate:
            self._draining.set()

    def _allow_provider_io(self, stop_event: Event | None) -> bool:
        """Linearize entry to one provider call against the host drain barrier."""

        with self._claim_gate:
            return not self._draining.is_set() and not _stop_requested(stop_event)

    def _drain_requested(self, stop_event: Event | None) -> bool:
        return self._draining.is_set() or _stop_requested(stop_event)

    def run_once(
        self,
        *,
        now: datetime | None = None,
        stop_event: Event | None = None,
    ) -> AuthorizationCloudRunResult:
        """Process due monitor checks, one refresh job, and one email job."""

        moment = now or utc_now()
        checks = self._run_authorization_checks(moment, stop_event=stop_event)
        refresh = email = refresh_deferred = email_deferred = 0
        refresh_unknown = email_unknown = 0
        if not self._drain_requested(stop_event):
            refresh, refresh_deferred, refresh_unknown = self._run_cloud_refresh(
                moment,
                stop_event=stop_event,
            )
        if not self._drain_requested(stop_event):
            email, email_deferred, email_unknown = self._run_email_notification(
                moment,
                stop_event=stop_event,
            )
        return AuthorizationCloudRunResult(
            authorization_checks=checks,
            cloud_refreshes=refresh,
            email_submissions=email,
            deferred=refresh_deferred + email_deferred,
            unknown=refresh_unknown + email_unknown,
        )

    def run_forever(self, stop_event: Event) -> None:
        """Poll durable jobs until the host signals shutdown."""

        while not self._drain_requested(stop_event):
            result = self.run_once(stop_event=stop_event)
            if (
                result.authorization_checks == 0
                and result.cloud_refreshes == 0
                and result.email_submissions == 0
            ):
                stop_event.wait(self._idle_delay_seconds)

    def _run_authorization_checks(self, now: datetime, *, stop_event: Event | None) -> int:
        if self._drain_requested(stop_event):
            return 0
        # Claim one row at a time so shutdown never leaves a batch of unstarted
        # monitors fenced to a worker that is already draining.
        with self._claim_gate:
            claims = (
                []
                if self._draining.is_set() or _stop_requested(stop_event)
                else self._store.claim_authorization_checks(
                    self._worker_id,
                    now=now,
                    limit=1,
                )
            )
        completed = 0
        for claim in claims:
            if self._drain_requested(stop_event):
                self._store.release_authorization_check(
                    claim,
                    now=now,
                    retry_delay_seconds=1,
                )
                break
            previous = self._store.latest_authorization_health_for_monitor(claim)
            principal = self._current_connection_principal(claim.connection, _MONITOR_OPERATION)
            if self._drain_requested(stop_event):
                self._store.release_authorization_check(
                    claim,
                    now=now,
                    retry_delay_seconds=1,
                )
                break
            if principal is None:
                observation = _unavailable_health(
                    claim.connection,
                    now=now,
                    previous=previous,
                    reason_code="current_authority_unavailable",
                )
            else:
                if not self._allow_provider_io(stop_event):
                    self._store.release_authorization_check(
                        claim,
                        now=now,
                        retry_delay_seconds=1,
                    )
                    break
                try:
                    observation = self._provider.authorization_health(principal, claim.connection)
                    _check_observation_scope(claim, principal, observation, _MONITOR_OPERATION)
                except ProviderObservationUnavailable:
                    observation = _unavailable_health(
                        claim.connection,
                        now=now,
                        previous=previous,
                        reason_code="provider_observation_unavailable",
                    )
                except Exception:
                    # Provider details can contain private data; persist only a stable reason.
                    observation = _unavailable_health(
                        claim.connection,
                        now=now,
                        previous=previous,
                        reason_code="provider_observation_failed",
                    )
            drafts = _authorization_notifications(
                self._store,
                claim,
                previous=previous,
                current=observation,
                now=now,
            )
            self._store.complete_authorization_check(
                claim,
                observation,
                drafts,
                now=now,
                interval_seconds=self._monitor_interval_seconds,
                email_recipient_ref=self._recipient_for_connection(claim.connection),
            )
            completed += 1
        return completed

    def _run_cloud_refresh(
        self,
        now: datetime,
        *,
        stop_event: Event | None,
    ) -> tuple[int, int, int]:
        if self._drain_requested(stop_event):
            return 0, 0, 0
        with self._claim_gate:
            claim = (
                None
                if self._draining.is_set() or _stop_requested(stop_event)
                else self._store.claim_cloud_refresh(self._worker_id, now=now)
            )
        if claim is None:
            return 0, 0, 0
        if self._drain_requested(stop_event):
            self._store.release_cloud_refresh_claim(
                claim,
                now=now,
                retry_delay_seconds=1,
            )
            return 0, 0, 0
        connection = self._store.connection_for_cloud_refresh(claim)
        principal = self._current_connection_principal(connection, _REFRESH_OPERATION)
        if self._drain_requested(stop_event):
            self._store.release_cloud_refresh_claim(
                claim,
                now=now,
                retry_delay_seconds=1,
            )
            return 0, 0, 0
        if principal is None:
            self._store.complete_cloud_refresh(
                claim,
                [],
                state=CloudRefreshState.FAILED,
                now=now,
                result={"reasonCode": "current_authority_unavailable"},
            )
            return 1, 0, 0
        latest_health = self._store.latest_authorization_health_for_connection(connection)
        if self._drain_requested(stop_event):
            self._store.release_cloud_refresh_claim(
                claim,
                now=now,
                retry_delay_seconds=1,
            )
            return 0, 0, 0
        if (
            latest_health is not None
            and latest_health.authorization_state == AuthorizationState.REAUTHORIZATION_REQUIRED
        ):
            self._store.complete_cloud_refresh(
                claim,
                [],
                state=CloudRefreshState.FAILED,
                now=now,
                result={"reasonCode": "connection_reauthorization_required"},
            )
            return 1, 0, 0
        if not self._allow_provider_io(stop_event):
            self._store.release_cloud_refresh_claim(
                claim,
                now=now,
                retry_delay_seconds=1,
            )
            return 0, 0, 0
        try:
            observations = self._provider.cloud_resources(principal, connection)
            if any(item.connection_id != connection.id for item in observations):
                raise ProviderObservationUnavailable("cloud observation scope mismatch")
        except ProviderObservationUnavailable:
            self._store.complete_cloud_refresh(
                claim,
                [],
                state=CloudRefreshState.UNKNOWN,
                now=now,
                result={"reasonCode": "provider_observation_unavailable"},
            )
            return 1, 0, 1
        except Exception:
            self._store.complete_cloud_refresh(
                claim,
                [],
                state=CloudRefreshState.UNKNOWN,
                now=now,
                result={"reasonCode": "provider_observation_failed"},
            )
            return 1, 0, 1
        self._store.complete_cloud_refresh(
            claim,
            observations,
            state=CloudRefreshState.SUCCEEDED,
            now=now,
            email_recipient_ref=self._recipient_for_connection(connection),
        )
        return 1, 0, 0

    def _run_email_notification(
        self,
        now: datetime,
        *,
        stop_event: Event | None,
    ) -> tuple[int, int, int]:
        if self._email is None:
            return 0, 0, 0
        if self._drain_requested(stop_event):
            return 0, 0, 0
        with self._claim_gate:
            claim = (
                None
                if self._draining.is_set() or _stop_requested(stop_event)
                else self._store.claim_email_notification(self._worker_id, now=now)
            )
        if claim is None:
            return 0, 0, 0
        if self._drain_requested(stop_event):
            self._store.release_email_claim(
                claim,
                now=now,
                retry_delay_seconds=1,
                failure_reason_code="shutdown_before_send",
            )
            return 0, 0, 0
        try:
            principal = self._contexts.for_claimed_notification(
                claim.job,
                claim_fence=claim.claim_fence,
                operation_id=_DELIVER_OPERATION,
            )
        except Exception:
            principal = None
        if self._drain_requested(stop_event):
            self._store.release_email_claim(
                claim,
                now=now,
                retry_delay_seconds=1,
                failure_reason_code="shutdown_before_send",
            )
            return 0, 0, 0
        if principal is None or not _principal_matches_notification(principal, claim.job):
            self._store.release_email_claim(
                claim,
                now=now,
                failure_reason_code="current_authority_unavailable",
            )
            return 0, 1, 0
        try:
            self._store.mark_email_sending(
                claim.job.id,
                claim_fence=claim.claim_fence,
                now=now,
            )
        except Exception:
            return 0, 0, 0
        if not self._allow_provider_io(stop_event):
            self._store.release_email_send_before_provider(
                claim.job.id,
                claim_fence=claim.claim_fence,
                now=now,
                failure_reason_code="shutdown_before_send",
                retry_delay_seconds=1,
            )
            return 0, 0, 0
        try:
            evidence = self._email.send_notification(principal, claim.job)
        except EmailAuthorizationUnavailable:
            self._store.release_email_send_before_provider(
                claim.job.id,
                claim_fence=claim.claim_fence,
                now=now,
                failure_reason_code="current_authority_unavailable",
            )
            return 0, 1, 0
        except EmailDeliveryRetryableError:
            self._store.release_email_send_before_provider(
                claim.job.id,
                claim_fence=claim.claim_fence,
                now=now,
                failure_reason_code="provider_retryable_pre_send",
            )
            return 0, 1, 0
        except Exception:
            self._store.finish_email_notification(
                claim.job.id,
                claim_fence=claim.claim_fence,
                status="UNKNOWN",
                vendor_receipt_ref=None,
                delivery_confirmed=False,
                now=now,
            )
            return 1, 0, 1
        if evidence.request_ref != claim.job.request_ref:
            self._store.finish_email_notification(
                claim.job.id,
                claim_fence=claim.claim_fence,
                status="UNKNOWN",
                vendor_receipt_ref=None,
                delivery_confirmed=False,
                now=now,
            )
            return 1, 0, 1
        self._store.finish_email_notification(
            claim.job.id,
            claim_fence=claim.claim_fence,
            status=evidence.status,
            vendor_receipt_ref=evidence.vendor_receipt_ref,
            delivery_confirmed=evidence.delivery_confirmed,
            now=now,
        )
        return 1, 0, int(evidence.status == "UNKNOWN")

    def _recipient_for_connection(self, connection: IntegrationConnection) -> str | None:
        """Select only the configured recipient for an explicitly allowed owner."""

        if self._email_recipient_resolver is not None:
            try:
                return self._email_recipient_resolver(connection)
            except Exception as exc:
                _LOGGER.info(
                    "Email recipient is unavailable for an authorization notification (%s)",
                    type(exc).__name__,
                )
                return None
        return self._email_recipient_ref

    def _current_connection_principal(
        self,
        connection: IntegrationConnection,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        try:
            principal = self._contexts.for_connection(connection, operation_id=operation_id)
        except Exception as exc:
            _LOGGER.info(
                "Current Platform authority is unavailable for integration work (%s)",
                type(exc).__name__,
            )
            return None
        if not _principal_matches_connection(principal, connection, operation_id):
            return None
        return principal


def _stop_requested(stop_event: Event | None) -> bool:
    """Return whether the host has begun draining this worker."""

    return stop_event is not None and stop_event.is_set()


def _principal_matches_connection(
    principal: IntegrationPrincipal | None,
    connection: IntegrationConnection,
    operation_id: str,
) -> bool:
    """Require freshly resolved identity, actor scope and exact operation grant."""

    if principal is None:
        return False
    try:
        principal.require(operation_id)
    except Exception:
        return False
    return (
        principal.issuer == connection.actor_issuer
        and principal.subject == connection.actor_subject
        and principal.organization_id == connection.organization_id
        and principal.workspace_id == connection.workspace_id
    )


def _principal_matches_notification(
    principal: IntegrationPrincipal | None,
    job: EmailNotificationJob,
) -> bool:
    """Require the current dedicated delivery grant and exact notification owner."""

    if principal is None:
        return False
    try:
        principal.require(_DELIVER_OPERATION)
    except Exception:
        return False
    return (
        principal.issuer == job.actor_issuer
        and principal.subject == job.actor_subject
        and principal.organization_id == job.organization_id
        and principal.workspace_id == job.workspace_id
    )


def _check_observation_scope(
    claim: ClaimedAuthorizationMonitor,
    principal: IntegrationPrincipal,
    observation: AuthorizationHealthRecord,
    operation_id: str,
) -> None:
    """Validate the fresh principal and provider result against the fenced row."""

    connection = claim.connection
    if not _principal_matches_connection(principal, connection, operation_id):
        raise ProviderObservationUnavailable("current authorization scope changed")
    if (
        observation.connection_id != connection.id
        or observation.organization_id != connection.organization_id
        or observation.workspace_id != connection.workspace_id
        or observation.actor_issuer != connection.actor_issuer
        or observation.actor_subject != connection.actor_subject
        or (
            observation.authorization_ref is not None
            and not _OPAQUE_AUTHORIZATION_REF.fullmatch(observation.authorization_ref)
        )
    ):
        raise ProviderObservationUnavailable("authorization observation scope changed")


def _unavailable_health(
    connection: IntegrationConnection,
    *,
    now: datetime,
    previous: AuthorizationHealthRecord | None,
    reason_code: str,
) -> AuthorizationHealthRecord:
    """Persist inability to observe without claiming validity or expiry."""

    return AuthorizationHealthRecord(
        organization_id=connection.organization_id,
        workspace_id=connection.workspace_id,
        actor_issuer=connection.actor_issuer,
        actor_subject=connection.actor_subject,
        connection_id=connection.id,
        authorization_ref=previous.authorization_ref if previous is not None else None,
        reason_code=reason_code,
        login_state=LoginState.UNAVAILABLE,
        authorization_state=AuthorizationState.UNAVAILABLE,
        checked_at=now,
        expires_at=None,
        generation=previous.generation if previous is not None else 0,
        capabilities=[],
    )


def _authorization_notifications(
    store: IntegrationStore,
    claim: ClaimedAuthorizationMonitor,
    *,
    previous: AuthorizationHealthRecord | None,
    current: AuthorizationHealthRecord,
    now: datetime,
) -> list[IntegrationNotificationDraft]:
    """Create only changed actionable stages and six-hour unacknowledged reminders."""

    connection = claim.connection
    drafts: list[IntegrationNotificationDraft] = []
    display_name = (connection.display_name or connection.provider)[:140]
    authorization_ref = current.authorization_ref
    action_ref = (
        f"/api/v1/accounts/authorizations/{authorization_ref}/renewal-sessions"
        if authorization_ref
        else None
    )
    invalidated = (
        current.authorization_state == AuthorizationState.REAUTHORIZATION_REQUIRED
        or current.login_state == LoginState.MISSING
    )
    incident = f"authorization:{connection.id}:{current.generation}"
    if invalidated:
        latest = store.latest_notification_for_monitor(claim, incident_key=incident)
        if latest is None:
            drafts.append(
                IntegrationNotificationDraft(
                    connection_id=connection.id,
                    kind=IntegrationNotificationKind.AUTHORIZATION_REQUIRED,
                    severity=NotificationSeverity.ERROR,
                    title=f"Reauthorization required: {display_name}",
                    description="The provider confirmed this authorization is no longer usable.",
                    action_ref=action_ref,
                    dedupe_key=f"{incident}:required",
                    incident_key=incident,
                    stage="required",
                )
            )
        elif latest.acknowledged_at is None and (
            now - latest.created_at >= timedelta(seconds=_REMINDER_INTERVAL_SECONDS)
        ):
            reminder_bucket = int(
                (now - latest.created_at).total_seconds() // _REMINDER_INTERVAL_SECONDS
            )
            drafts.append(
                IntegrationNotificationDraft(
                    connection_id=connection.id,
                    kind=IntegrationNotificationKind.AUTHORIZATION_REQUIRED,
                    severity=NotificationSeverity.ERROR,
                    title=f"Reauthorization still required: {display_name}",
                    description="This provider authorization remains blocked and unacknowledged.",
                    action_ref=action_ref,
                    dedupe_key=f"{incident}:required:reminder:{reminder_bucket}",
                    incident_key=incident,
                    stage=f"required-reminder-{reminder_bucket}",
                )
            )
        return drafts

    if (
        current.login_state == LoginState.UNAVAILABLE
        or current.authorization_state == AuthorizationState.UNAVAILABLE
    ):
        prior_unavailable = previous is not None and (
            previous.login_state == LoginState.UNAVAILABLE
            or previous.authorization_state == AuthorizationState.UNAVAILABLE
        )
        if not prior_unavailable:
            unavailable_incident = f"connection-unavailable:{connection.id}"
            drafts.append(
                IntegrationNotificationDraft(
                    connection_id=connection.id,
                    kind=IntegrationNotificationKind.CONNECTION_UNAVAILABLE,
                    severity=NotificationSeverity.WARNING,
                    title=f"Authorization status unavailable: {display_name}",
                    description="Exchange could not confirm current provider authorization status.",
                    dedupe_key=f"{unavailable_incident}:{current.generation}",
                    incident_key=unavailable_incident,
                    stage="unavailable",
                )
            )
        return drafts

    expires_at = current.expires_at
    if expires_at is None:
        return drafts
    remaining = (expires_at - now).total_seconds()
    if remaining > _EXPIRY_WARNING_SECONDS:
        return drafts
    stage = "1h" if remaining <= _EXPIRY_URGENT_SECONDS else "24h"
    expiry_incident = f"authorization-expiry:{connection.id}:{current.generation}"
    latest = store.latest_notification_for_monitor(
        claim,
        incident_key=expiry_incident,
        stage_prefix=stage,
    )
    if latest is None:
        drafts.append(
            IntegrationNotificationDraft(
                connection_id=connection.id,
                kind=IntegrationNotificationKind.AUTHORIZATION_EXPIRING,
                severity=NotificationSeverity.WARNING,
                title=f"Authorization expires within {stage}: {display_name}",
                description=f"The provider reported an expiry at {expires_at.isoformat()}.",
                action_ref=action_ref,
                dedupe_key=f"{expiry_incident}:{stage}",
                incident_key=expiry_incident,
                stage=stage,
            )
        )
    elif latest.acknowledged_at is None and (
        now - latest.created_at >= timedelta(seconds=_REMINDER_INTERVAL_SECONDS)
    ):
        reminder_bucket = int(
            (now - latest.created_at).total_seconds() // _REMINDER_INTERVAL_SECONDS
        )
        drafts.append(
            IntegrationNotificationDraft(
                connection_id=connection.id,
                kind=IntegrationNotificationKind.AUTHORIZATION_EXPIRING,
                severity=NotificationSeverity.WARNING,
                title=f"Authorization expiry still needs attention: {display_name}",
                description=f"The provider reported an expiry at {expires_at.isoformat()}.",
                action_ref=action_ref,
                dedupe_key=f"{expiry_incident}:{stage}:reminder:{reminder_bucket}",
                incident_key=expiry_incident,
                stage=f"{stage}-reminder-{reminder_bucket}",
            )
        )
    return drafts
