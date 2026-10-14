"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 store.py                                                        │
│  Module: cyrene_exchange_product.integrations.store                 │
│  Role: Durable, scoped inbox/outbox and operation authority.          │
│                                                                      │
│  模块职责：使用独立 SQLite WAL 持久化集成收件箱、发件箱与业务状态。        │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from cyrene_exchange_product.integrations.models import (
    ActorBinding,
    AuthorizationHealthRecord,
    ClaimedAuthorizationMonitor,
    ClaimedCloudRefresh,
    ClaimedEmailNotification,
    ClaimedJob,
    CloudRefreshOperation,
    CloudRefreshState,
    CloudResourceRecord,
    CreateActorBinding,
    CreateIntegrationConnection,
    CreateSyncBinding,
    DeliveryReceipt,
    EmailNotificationJob,
    EmailOutboxState,
    EnqueueIssueAction,
    IncomingEvent,
    IntegrationAuthorizationError,
    IntegrationConflict,
    IntegrationConnection,
    IntegrationNotFound,
    IntegrationNotification,
    IntegrationNotificationDraft,
    IntegrationNotificationKind,
    IntegrationPrincipal,
    IntegrationValidationError,
    JobState,
    NormalizedGitHubEvent,
    NotificationSeverity,
    Operation,
    OperationAudit,
    OperationState,
    OutboxJob,
    RenewalSessionRecord,
    RenewalState,
    ResourceSnapshot,
    SnapshotFreshness,
    SyncBinding,
    WeComEventState,
    WeComInboundEvent,
    utc_now,
)


def _json(value: Any) -> str:
    """Serialize JSON-compatible Product values deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _provider_arguments(
    request: EnqueueIssueAction, connection: IntegrationConnection
) -> tuple[str, dict[str, object]]:
    """Build the exact fixed GitHub argument digest saved with the intent."""

    arguments: dict[str, object] = {
        "repository_id": connection.repository_id,
        "repository": connection.repository_name,
        "issue_number": request.issue_number,
    }
    if request.operation_id == "integration.issue.comment":
        if request.body is None:
            raise IntegrationValidationError("comment body is required")
        arguments["body"] = request.body
        return "integrationExecuteIssueComment", arguments
    if request.operation_id in {"integration.issue.close", "integration.issue.reopen"}:
        arguments["state"] = (
            "CLOSED" if request.operation_id == "integration.issue.close" else "OPEN"
        )
        return "integrationExecuteIssueState", arguments
    return "integrationExecuteIssueQuery", arguments


def _dt(value: datetime) -> str:
    """Serialize aware datetimes in a comparable canonical UTC form."""

    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()


class IntegrationStore:
    """Independent WAL-backed Product state for external integrations.

    Account Center and Platform data are referenced only by opaque IDs; no
    provider credential or replicated grant state is stored here.
    中文：只保存 Account Center 和 Platform 的不透明引用，不复制凭据或授权状态。
    """

    _CONNECTION_CREATE = "integrationCreateConnection"
    _BINDING_CREATE = "integrationCreateBinding"

    def __init__(self, database_path: Path | str) -> None:
        """Open or create the separate integration database and its schema."""

        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None, timeout=10
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS integration_connections (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_integration_connections_scope
                    ON integration_connections(organization_id, workspace_id, id);
                CREATE TABLE IF NOT EXISTS sync_bindings (
                    id TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_sync_bindings_scope
                    ON sync_bindings(organization_id, workspace_id, connection_id, id);
                CREATE TABLE IF NOT EXISTS actor_bindings (
                    id TEXT PRIMARY KEY,
                    binding_id TEXT NOT NULL REFERENCES sync_bindings(id),
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(binding_id, organization_id, workspace_id, actor_issuer, actor_subject)
                );
                CREATE INDEX IF NOT EXISTS ix_actor_bindings_actor_scope
                    ON actor_bindings(organization_id, workspace_id, actor_issuer, actor_subject);
                CREATE TABLE IF NOT EXISTS incoming_events (
                    id TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    delivery_id TEXT NOT NULL,
                    payload_fingerprint TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(connection_id, delivery_id)
                );
                CREATE TABLE IF NOT EXISTS wecom_inbound_events (
                    id TEXT PRIMARY KEY,
                    binding_id TEXT NOT NULL REFERENCES sync_bindings(id),
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    payload_fingerprint TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(binding_id, source_event_id)
                );
                CREATE INDEX IF NOT EXISTS ix_wecom_inbound_events_scope
                    ON wecom_inbound_events(organization_id, workspace_id, binding_id);
                CREATE TABLE IF NOT EXISTS outbox_jobs (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    binding_id TEXT,
                    operation_id TEXT,
                    idempotency_key TEXT,
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    available_at TEXT NOT NULL,
                    claim_owner TEXT,
                    claim_fence INTEGER NOT NULL DEFAULT 0,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_outbox_jobs_claim
                    ON outbox_jobs(state, available_at, created_at, id);
                CREATE UNIQUE INDEX IF NOT EXISTS ix_outbox_jobs_idempotency
                    ON outbox_jobs(kind,idempotency_key) WHERE idempotency_key IS NOT NULL;
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(organization_id, workspace_id, actor_issuer, actor_subject,
                           connection_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    document TEXT NOT NULL,
                    PRIMARY KEY(organization_id,workspace_id,actor_issuer,actor_subject,
                                operation_id,idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS ix_operations_scope
                    ON operations(organization_id, workspace_id, actor_issuer, actor_subject, id);
                CREATE TABLE IF NOT EXISTS delivery_receipts (
                    id TEXT PRIMARY KEY,
                    operation_id TEXT,
                    job_id TEXT,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS resource_snapshots (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_resource_snapshots_lookup
                    ON resource_snapshots(organization_id, workspace_id, resource_type,
                                          resource_id, observed_at DESC);
                CREATE TABLE IF NOT EXISTS authorization_monitor_state (
                    connection_id TEXT PRIMARY KEY REFERENCES integration_connections(id),
                    next_check_at TEXT NOT NULL,
                    last_checked_at TEXT,
                    claim_owner TEXT,
                    claim_fence INTEGER NOT NULL DEFAULT 0,
                    lease_expires_at TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_authorization_monitor_due
                    ON authorization_monitor_state(next_check_at, lease_expires_at);
                CREATE TABLE IF NOT EXISTS authorization_observations (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    authorization_ref TEXT,
                    checked_at TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS integration_notifications (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT REFERENCES integration_connections(id),
                    kind TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL,
                    incident_key TEXT,
                    stage TEXT,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(organization_id, workspace_id, actor_issuer, actor_subject, dedupe_key)
                );
                CREATE INDEX IF NOT EXISTS ix_integration_notifications_feed
                    ON integration_notifications(organization_id, workspace_id,
                        actor_issuer, actor_subject, sequence);
                CREATE TABLE IF NOT EXISTS renewal_sessions (
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    authorization_ref TEXT NOT NULL,
                    session_ref TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    document TEXT NOT NULL,
                    PRIMARY KEY(organization_id, workspace_id, actor_issuer,
                                actor_subject, authorization_ref, session_ref)
                );
                CREATE TABLE IF NOT EXISTS cloud_resource_observations (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    external_ref TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(connection_id, external_ref, collected_at)
                );
                CREATE INDEX IF NOT EXISTS ix_cloud_resource_latest
                    ON cloud_resource_observations(organization_id, workspace_id,
                        actor_issuer, actor_subject, connection_id, collected_at DESC);
                CREATE TABLE IF NOT EXISTS cloud_refresh_operations (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT NOT NULL REFERENCES integration_connections(id),
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    document TEXT NOT NULL,
                    UNIQUE(organization_id, workspace_id, actor_issuer, actor_subject,
                           connection_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS cloud_refresh_outbox (
                    operation_id TEXT PRIMARY KEY REFERENCES cloud_refresh_operations(id),
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at TEXT NOT NULL,
                    claim_owner TEXT,
                    claim_fence INTEGER NOT NULL DEFAULT 0,
                    lease_expires_at TEXT,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_cloud_refresh_claim
                    ON cloud_refresh_outbox(state, available_at, operation_id);
                CREATE TABLE IF NOT EXISTS email_notification_outbox (
                    id TEXT PRIMARY KEY,
                    notification_id TEXT NOT NULL UNIQUE REFERENCES integration_notifications(id),
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor_issuer TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    connection_id TEXT REFERENCES integration_connections(id),
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at TEXT NOT NULL,
                    claim_owner TEXT,
                    claim_fence INTEGER NOT NULL DEFAULT 0,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_email_notification_claim
                    ON email_notification_outbox(state, created_at, id);
                CREATE TABLE IF NOT EXISTS operation_audits (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS job_evidence (
                    job_id TEXT NOT NULL REFERENCES outbox_jobs(id),
                    claim_fence INTEGER NOT NULL,
                    evidence TEXT NOT NULL,
                    PRIMARY KEY(job_id, claim_fence)
                );
                """
            )
            authorization_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(authorization_observations)"
                ).fetchall()
            }
            if "authorization_ref" not in authorization_columns:
                self._connection.execute(
                    "ALTER TABLE authorization_observations ADD COLUMN authorization_ref TEXT"
                )
            self._connection.execute("DROP INDEX IF EXISTS ix_authorization_observations_latest")
            self._connection.execute(
                """CREATE INDEX ix_authorization_observations_latest
                   ON authorization_observations(organization_id,workspace_id,actor_issuer,
                       actor_subject,connection_id,authorization_ref,checked_at DESC)"""
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        """Serialize local writers and use an explicit SQLite transaction."""

        with self._lock:
            cursor = self._connection.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
            finally:
                cursor.close()

    @staticmethod
    def _scope(principal: IntegrationPrincipal) -> tuple[str, str, str, str]:
        return (
            principal.organization_id,
            principal.workspace_id,
            principal.issuer,
            principal.subject,
        )

    @staticmethod
    def _decode(model: type[Any], row: sqlite3.Row) -> Any:
        return model.model_validate_json(str(row["document"]))

    @staticmethod
    def _idempotency_lookup(
        cursor: sqlite3.Cursor,
        *,
        principal: IntegrationPrincipal,
        operation_name: str,
        key: str,
        request_hash: str,
    ) -> sqlite3.Row | None:
        """Return an exact prior typed result or reject changed payload reuse."""

        row = cursor.execute(
            """SELECT request_hash,document FROM idempotency_records
               WHERE organization_id=? AND workspace_id=? AND actor_issuer=?
               AND actor_subject=? AND operation_id=? AND idempotency_key=?""",
            (
                principal.organization_id,
                principal.workspace_id,
                principal.issuer,
                principal.subject,
                operation_name,
                key,
            ),
        ).fetchone()
        row = cast(sqlite3.Row | None, row)
        if row is not None and str(row["request_hash"]) != request_hash:
            raise IntegrationConflict("idempotency key was reused for a different request")
        return row

    @staticmethod
    def _idempotency_save(
        cursor: sqlite3.Cursor,
        *,
        principal: IntegrationPrincipal,
        operation_name: str,
        key: str,
        request_hash: str,
        resource_id: UUID,
        document: str,
    ) -> None:
        """Save an idempotency result in the same transaction as its resource."""

        cursor.execute(
            "INSERT INTO idempotency_records VALUES(?,?,?,?,?,?,?,?,?)",
            (
                principal.organization_id,
                principal.workspace_id,
                principal.issuer,
                principal.subject,
                operation_name,
                key,
                request_hash,
                str(resource_id),
                document,
            ),
        )

    @staticmethod
    def _insert_job(cursor: sqlite3.Cursor, job: OutboxJob) -> None:
        cursor.execute(
            """INSERT INTO outbox_jobs(
                id,kind,organization_id,workspace_id,actor_issuer,actor_subject,
                connection_id,binding_id,operation_id,idempotency_key,
                state,attempts,available_at,claim_owner,claim_fence,lease_expires_at,
                created_at,updated_at,document
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(job.id),
                job.kind,
                job.organization_id,
                job.workspace_id,
                job.actor_issuer,
                job.actor_subject,
                str(job.connection_id),
                str(job.binding_id) if job.binding_id else None,
                str(job.operation_id) if job.operation_id else None,
                job.idempotency_key,
                job.state.value,
                job.attempts,
                _dt(job.available_at),
                job.claim_owner,
                job.claim_fence,
                _dt(job.lease_expires_at) if job.lease_expires_at else None,
                _dt(job.created_at),
                _dt(job.updated_at),
                job.model_dump_json(by_alias=True),
            ),
        )

    @staticmethod
    def _persist_job(cursor: sqlite3.Cursor, job: OutboxJob) -> None:
        cursor.execute(
            """UPDATE outbox_jobs SET state=?,attempts=?,available_at=?,claim_owner=?,
                claim_fence=?,lease_expires_at=?,updated_at=?,document=? WHERE id=?""",
            (
                job.state.value,
                job.attempts,
                _dt(job.available_at),
                job.claim_owner,
                job.claim_fence,
                _dt(job.lease_expires_at) if job.lease_expires_at else None,
                _dt(job.updated_at),
                job.model_dump_json(by_alias=True),
                str(job.id),
            ),
        )

    def close(self) -> None:
        """Close the SQLite connection. | 关闭 SQLite 连接。"""

        with self._lock:
            self._connection.close()

    def create_connection(
        self,
        principal: IntegrationPrincipal,
        request: CreateIntegrationConnection,
        *,
        idempotency_key: str,
    ) -> IntegrationConnection:
        """Create a group repository connection within the caller's workspace scope."""

        principal.require(self._CONNECTION_CREATE)
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        request_hash = hashlib.sha256(
            _json(request.model_dump(mode="json", by_alias=True)).encode("utf-8")
        ).hexdigest()
        now = utc_now()
        connection = IntegrationConnection(
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            account_link_ref=request.account_link_ref,
            provider=request.provider,
            binding_ref=request.binding_ref,
            target_ref=request.target_ref,
            display_name=request.display_name or request.repository_name or request.provider,
            repository_id=request.repository_id,
            repository_name=request.repository_name,
            created_at=now,
            updated_at=now,
        )
        with self._transaction() as cursor:
            existing = self._idempotency_lookup(
                cursor,
                principal=principal,
                operation_name=self._CONNECTION_CREATE,
                key=idempotency_key,
                request_hash=request_hash,
            )
            if existing is not None:
                return IntegrationConnection.model_validate_json(str(existing["document"]))
            cursor.execute(
                "INSERT INTO integration_connections VALUES(?,?,?,?,?,?,?)",
                (
                    str(connection.id),
                    connection.organization_id,
                    connection.workspace_id,
                    connection.actor_issuer,
                    connection.actor_subject,
                    int(connection.enabled),
                    connection.model_dump_json(by_alias=True),
                ),
            )
            self._idempotency_save(
                cursor,
                principal=principal,
                operation_name=self._CONNECTION_CREATE,
                key=idempotency_key,
                request_hash=request_hash,
                resource_id=connection.id,
                document=connection.model_dump_json(by_alias=True),
            )
        return connection

    def list_connections(self, principal: IntegrationPrincipal) -> list[IntegrationConnection]:
        """List only connections belonging to the exact actor and scope."""

        principal.require("integrationListConnections")
        with self._lock:
            rows = self._connection.execute(
                """SELECT document FROM integration_connections
                   WHERE organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=? ORDER BY id""",
                self._scope(principal),
            ).fetchall()
        return [IntegrationConnection.model_validate_json(str(row["document"])) for row in rows]

    def get_connection(
        self,
        principal: IntegrationPrincipal,
        connection_id: UUID,
        *,
        authorization_operation_id: str = "integrationListConnections",
    ) -> IntegrationConnection:
        """Read one connection without crossing organization, workspace, or actor."""

        principal.require(authorization_operation_id)
        return self._get_connection_scoped(principal, connection_id)

    def _get_connection_scoped(
        self, principal: IntegrationPrincipal, connection_id: UUID
    ) -> IntegrationConnection:
        """Load an actor-scoped connection after its owning operation was authorized."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM integration_connections WHERE id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (str(connection_id), *self._scope(principal)),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("integration connection not found")
        return IntegrationConnection.model_validate_json(str(row["document"]))

    def _get_connection_for_scope(
        self, principal: IntegrationPrincipal, connection_id: UUID
    ) -> IntegrationConnection:
        """Load a group's repository connection without using its creator's account ref."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM integration_connections WHERE id=?
                   AND organization_id=? AND workspace_id=? AND enabled=1""",
                (str(connection_id), principal.organization_id, principal.workspace_id),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("integration connection not found in workspace scope")
        return IntegrationConnection.model_validate_json(str(row["document"]))

    def _get_connection_for_scope_by_ids(
        self, connection_id: UUID, *, organization_id: str, workspace_id: str
    ) -> IntegrationConnection:
        """Load a group repository connection for a verified external sender scope."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM integration_connections WHERE id=?
                   AND organization_id=? AND workspace_id=? AND enabled=1""",
                (str(connection_id), organization_id, workspace_id),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("integration connection not found in sender scope")
        return IntegrationConnection.model_validate_json(str(row["document"]))

    def get_connection_for_binding(
        self,
        principal: IntegrationPrincipal,
        connection_id: UUID,
        binding_id: UUID,
        *,
        authorization_operation_id: str,
    ) -> IntegrationConnection:
        """Read a group repository connection through its scoped binding."""

        principal.require(authorization_operation_id)
        binding = self._get_binding_for_scope(principal, binding_id)
        if binding.connection_id != connection_id or not binding.enabled:
            raise IntegrationAuthorizationError("connection is not enabled for this binding")
        return self._get_connection_for_scope(principal, connection_id)

    def create_binding(
        self,
        principal: IntegrationPrincipal,
        request: CreateSyncBinding,
        *,
        idempotency_key: str,
    ) -> SyncBinding:
        """Create a group notification binding under the caller's workspace connection."""

        principal.require(self._BINDING_CREATE)
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        connection = self._get_connection_scoped(principal, request.connection_id)
        if request.account_link_ref is not None or request.delegation_ref is not None:
            raise IntegrationValidationError(
                "member account and delegation references belong in ActorBinding"
            )
        request_hash = hashlib.sha256(
            _json(request.model_dump(mode="json", by_alias=True)).encode("utf-8")
        ).hexdigest()
        now = utc_now()
        binding = SyncBinding(
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            connection_id=connection.id,
            account_link_ref=None,
            delegation_ref=None,
            notification_target_ref=request.notification_target_ref,
            created_at=now,
            updated_at=now,
        )
        with self._transaction() as cursor:
            existing = self._idempotency_lookup(
                cursor,
                principal=principal,
                operation_name=self._BINDING_CREATE,
                key=idempotency_key,
                request_hash=request_hash,
            )
            if existing is not None:
                return SyncBinding.model_validate_json(str(existing["document"]))
            cursor.execute(
                "INSERT INTO sync_bindings VALUES(?,?,?,?,?,?,?)",
                (
                    str(binding.id),
                    str(connection.id),
                    binding.organization_id,
                    binding.workspace_id,
                    principal.issuer,
                    principal.subject,
                    binding.model_dump_json(by_alias=True),
                ),
            )
            self._idempotency_save(
                cursor,
                principal=principal,
                operation_name=self._BINDING_CREATE,
                key=idempotency_key,
                request_hash=request_hash,
                resource_id=binding.id,
                document=binding.model_dump_json(by_alias=True),
            )
        return binding

    def create_actor_binding(
        self,
        principal: IntegrationPrincipal,
        request: CreateActorBinding,
        *,
        idempotency_key: str,
    ) -> ActorBinding:
        """Attach only this verified actor's own opaque account and delegation refs."""

        principal.require("integrationAttachActorBinding")
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        self._get_binding_for_scope(principal, request.binding_id)
        request_hash = hashlib.sha256(
            _json(request.model_dump(mode="json", by_alias=True)).encode("utf-8")
        ).hexdigest()
        now = utc_now()
        actor_binding = ActorBinding(
            binding_id=request.binding_id,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            account_link_ref=request.account_link_ref,
            delegation_ref=request.delegation_ref,
            created_at=now,
            updated_at=now,
        )
        with self._transaction() as cursor:
            replay = self._idempotency_lookup(
                cursor,
                principal=principal,
                operation_name="integrationAttachActorBinding",
                key=idempotency_key,
                request_hash=request_hash,
            )
            if replay is not None:
                return ActorBinding.model_validate_json(str(replay["document"]))
            existing = cursor.execute(
                """SELECT document FROM actor_bindings WHERE binding_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (
                    str(request.binding_id),
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                ),
            ).fetchone()
            if existing is not None:
                current = ActorBinding.model_validate_json(str(existing["document"]))
                if (
                    current.account_link_ref != actor_binding.account_link_ref
                    or current.delegation_ref != actor_binding.delegation_ref
                ):
                    raise IntegrationConflict("actor binding already has different authority refs")
                actor_binding = current
            else:
                cursor.execute(
                    "INSERT INTO actor_bindings VALUES(?,?,?,?,?,?,?)",
                    (
                        str(actor_binding.id),
                        str(actor_binding.binding_id),
                        actor_binding.organization_id,
                        actor_binding.workspace_id,
                        actor_binding.actor_issuer,
                        actor_binding.actor_subject,
                        actor_binding.model_dump_json(by_alias=True),
                    ),
                )
            self._idempotency_save(
                cursor,
                principal=principal,
                operation_name="integrationAttachActorBinding",
                key=idempotency_key,
                request_hash=request_hash,
                resource_id=actor_binding.id,
                document=actor_binding.model_dump_json(by_alias=True),
            )
        return actor_binding

    def list_actor_bindings(
        self, principal: IntegrationPrincipal, binding_id: UUID
    ) -> list[ActorBinding]:
        """List only the caller's own refs attached to the requested group binding."""

        principal.require("integrationListActorBindings")
        with self._lock:
            rows = self._connection.execute(
                """SELECT actor.document FROM actor_bindings AS actor
                   JOIN sync_bindings AS binding ON binding.id=actor.binding_id
                   WHERE actor.binding_id=? AND actor.organization_id=?
                   AND actor.workspace_id=? AND actor.actor_issuer=? AND actor.actor_subject=?
                   AND binding.organization_id=? AND binding.workspace_id=?""",
                (
                    str(binding_id),
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                    principal.organization_id,
                    principal.workspace_id,
                ),
            ).fetchall()
        return [ActorBinding.model_validate_json(str(row["document"])) for row in rows]

    def get_actor_binding_for_operation(
        self, principal: IntegrationPrincipal, binding_id: UUID, *, operation_id: str
    ) -> ActorBinding:
        """Require one active actor-owned binding before queueing a GitHub operation."""

        principal.require(operation_id)
        actor_binding = self._get_actor_binding_scoped(principal, binding_id)
        if not actor_binding.enabled:
            raise IntegrationAuthorizationError("actor binding is disabled")
        return actor_binding

    def list_bindings(
        self, principal: IntegrationPrincipal, *, connection_id: UUID | None = None
    ) -> list[SyncBinding]:
        """List bindings within caller scope, optionally for one owned connection."""

        principal.require("integrationListBindings")
        query = "SELECT document FROM sync_bindings WHERE organization_id=? AND workspace_id=?"
        params: tuple[str, ...] = (principal.organization_id, principal.workspace_id)
        if connection_id is not None:
            query += " AND connection_id=?"
            params += (str(connection_id),)
        query += " ORDER BY id"
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [SyncBinding.model_validate_json(str(row["document"])) for row in rows]

    def get_binding(
        self,
        principal: IntegrationPrincipal,
        binding_id: UUID,
        *,
        authorization_operation_id: str = "integrationListBindings",
    ) -> SyncBinding:
        """Read one shared binding within the caller's authorized workspace."""

        principal.require(authorization_operation_id)
        return self._get_binding_for_scope(principal, binding_id)

    def _get_binding_for_scope(
        self, principal: IntegrationPrincipal, binding_id: UUID
    ) -> SyncBinding:
        """Load a group binding by org/workspace after exact route authorization."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM sync_bindings WHERE id=? AND organization_id=?
                   AND workspace_id=?""",
                (str(binding_id), principal.organization_id, principal.workspace_id),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("sync binding not found")
        return SyncBinding.model_validate_json(str(row["document"]))

    def _get_actor_binding_scoped(
        self, principal: IntegrationPrincipal, binding_id: UUID
    ) -> ActorBinding:
        """Load the exact member attachment for a group binding."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM actor_bindings WHERE binding_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (
                    str(binding_id),
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                ),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("actor binding not found")
        return ActorBinding.model_validate_json(str(row["document"]))

    def ingest_github_event(
        self,
        connection_id: UUID,
        delivery_id: str,
        event: NormalizedGitHubEvent,
        *,
        verified: bool,
    ) -> IncomingEvent:
        """Atomically persist verified inbox data and eligible notification jobs."""

        if not verified:
            raise IntegrationAuthorizationError("GitHub signature was not verified")
        if not delivery_id or len(delivery_id) > 300:
            raise IntegrationValidationError("delivery_id must contain 1 to 300 characters")
        normalized = event.model_dump(mode="json", by_alias=True)
        fingerprint_payload = dict(normalized)
        fingerprint_payload.pop("observedAt", None)
        fingerprint = hashlib.sha256(_json(fingerprint_payload).encode("utf-8")).hexdigest()
        with self._transaction() as cursor:
            connection_row = cursor.execute(
                "SELECT document FROM integration_connections WHERE id=? AND enabled=1",
                (str(connection_id),),
            ).fetchone()
            if connection_row is None:
                raise IntegrationNotFound("integration connection not found")
            connection = IntegrationConnection.model_validate_json(str(connection_row["document"]))
            if event.repository_id != connection.repository_id:
                raise IntegrationAuthorizationError("event repository does not match connection")
            previous = cursor.execute(
                "SELECT document,payload_fingerprint FROM incoming_events "
                "WHERE connection_id=? AND delivery_id=?",
                (str(connection_id), delivery_id),
            ).fetchone()
            if previous is not None:
                if str(previous["payload_fingerprint"]) != fingerprint:
                    raise IntegrationConflict("delivery id was reused with a different payload")
                return IncomingEvent.model_validate_json(str(previous["document"]))
            incoming = IncomingEvent(
                connection_id=connection.id,
                organization_id=connection.organization_id,
                workspace_id=connection.workspace_id,
                delivery_id=delivery_id,
                payload_fingerprint=fingerprint,
                **normalized,
            )
            cursor.execute(
                "INSERT INTO incoming_events VALUES(?,?,?,?,?,?,?)",
                (
                    str(incoming.id),
                    str(connection.id),
                    delivery_id,
                    fingerprint,
                    connection.organization_id,
                    connection.workspace_id,
                    incoming.model_dump_json(by_alias=True),
                ),
            )
            if not incoming.self_authored:
                bindings = cursor.execute(
                    """SELECT id,document FROM sync_bindings WHERE connection_id=?
                       AND organization_id=? AND workspace_id=?""",
                    (str(connection.id), connection.organization_id, connection.workspace_id),
                ).fetchall()
                now = utc_now()
                for binding_row in bindings:
                    binding = SyncBinding.model_validate_json(str(binding_row["document"]))
                    if not binding.enabled:
                        continue
                    job = OutboxJob(
                        kind="NOTIFY",
                        organization_id=connection.organization_id,
                        workspace_id=connection.workspace_id,
                        actor_issuer=connection.actor_issuer,
                        actor_subject=connection.actor_subject,
                        connection_id=connection.id,
                        binding_id=binding.id,
                        idempotency_key=f"incoming:{incoming.id}:{binding.id}",
                        payload={
                            "eventId": str(incoming.id),
                            "targetRef": binding.notification_target_ref,
                            "issueNumber": incoming.issue_number,
                            "repositoryName": connection.repository_name,
                            "title": incoming.title,
                            "action": incoming.action,
                        },
                        available_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                    self._insert_job(cursor, job)
            return incoming

    def enqueue_issue_action(
        self,
        principal: IntegrationPrincipal,
        request: EnqueueIssueAction,
        *,
        authorization_operation_id: str | None = None,
    ) -> Operation:
        """Atomically create/reuse an operation and its one durable outbox job."""

        principal.require(authorization_operation_id or request.operation_id)
        if request.operation_id == "integration.issue.comment" and not request.body:
            raise IntegrationValidationError("comment body is required")
        if request.operation_id != "integration.issue.comment" and request.body is not None:
            raise IntegrationValidationError("body is only accepted for comment operations")
        binding = self._get_binding_for_scope(principal, request.binding_id)
        if not binding.enabled or binding.connection_id != request.connection_id:
            raise IntegrationAuthorizationError("issue action binding does not match connection")
        operation_permission = authorization_operation_id or request.operation_id
        actor_binding = self.get_actor_binding_for_operation(
            principal, binding.id, operation_id=operation_permission
        )
        connection = self._get_connection_for_scope(principal, request.connection_id)
        return self._persist_issue_action(
            request,
            binding=binding,
            actor_binding=actor_binding,
            connection=connection,
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
        )

    def persist_wecom_inbound(
        self,
        binding_id: UUID,
        source_event_id: str,
        *,
        expected_organization_id: str,
        expected_workspace_id: str,
        sender_id: str,
        conversation_ref: str,
        reply_message_id: str | None,
        reply_context_ref: str | None,
        message_text: str,
        verified: bool,
        payload_fingerprint: str | None = None,
        self_authored: bool = False,
        observed_at: datetime | None = None,
    ) -> tuple[WeComInboundEvent, bool]:
        """Deduplicate a verified normalized WeCom event before acknowledging it."""

        if not verified:
            raise IntegrationAuthorizationError("WeCom event was not authenticated")
        if not source_event_id or len(source_event_id) > 300:
            raise IntegrationValidationError("WeCom source event ID is invalid")
        if not expected_organization_id or not expected_workspace_id:
            raise IntegrationValidationError("WeCom source scope is not configured")
        if not sender_id or len(sender_id) > 200:
            raise IntegrationValidationError("WeCom sender ID is invalid")
        if not conversation_ref or len(conversation_ref) > 300:
            raise IntegrationValidationError("WeCom conversation reference is invalid")
        if reply_message_id is not None and len(reply_message_id) > 300:
            raise IntegrationValidationError("WeCom reply message ID is invalid")
        if reply_context_ref is not None and len(reply_context_ref) > 300:
            raise IntegrationValidationError("WeCom reply context reference is invalid")
        if len(message_text) > 4096:
            raise IntegrationValidationError("WeCom text exceeds the size limit")
        moment = observed_at or utc_now()
        if moment.tzinfo is None:
            raise IntegrationValidationError("WeCom observation time must be timezone-aware")
        with self._transaction() as cursor:
            binding_row = cursor.execute(
                "SELECT document FROM sync_bindings WHERE id=?",
                (str(binding_id),),
            ).fetchone()
            if binding_row is None:
                raise IntegrationNotFound("WeCom sync binding not found")
            binding = SyncBinding.model_validate_json(str(binding_row["document"]))
            if (
                binding.organization_id != expected_organization_id
                or binding.workspace_id != expected_workspace_id
            ):
                raise IntegrationAuthorizationError(
                    "WeCom source scope does not match the configured binding"
                )
            if not binding.enabled:
                raise IntegrationAuthorizationError("WeCom sync binding is disabled")
            payload = {
                "bindingId": str(binding.id),
                "senderId": sender_id,
                "conversationRef": conversation_ref,
                "replyMessageId": reply_message_id,
                "replyContextRef": reply_context_ref,
                "messageText": message_text,
                "selfAuthored": self_authored,
            }
            normalized_fingerprint = hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()
            fingerprint = payload_fingerprint or normalized_fingerprint
            if len(fingerprint) != 64 or any(
                character not in "0123456789abcdef" for character in fingerprint
            ):
                raise IntegrationValidationError("WeCom payload fingerprint must be SHA-256")
            previous = cursor.execute(
                "SELECT document,payload_fingerprint FROM wecom_inbound_events "
                "WHERE binding_id=? AND source_event_id=?",
                (str(binding_id), source_event_id),
            ).fetchone()
            if previous is not None:
                if str(previous["payload_fingerprint"]) != fingerprint:
                    raise IntegrationConflict(
                        "WeCom source event ID was reused with a different payload"
                    )
                return WeComInboundEvent.model_validate_json(str(previous["document"])), False
            event = WeComInboundEvent(
                binding_id=binding.id,
                organization_id=binding.organization_id,
                workspace_id=binding.workspace_id,
                source_event_id=source_event_id,
                payload_fingerprint=fingerprint,
                sender_id=sender_id,
                conversation_ref=conversation_ref,
                reply_message_id=reply_message_id,
                reply_context_ref=reply_context_ref,
                message_text=(
                    "/link [redacted]"
                    if message_text.lstrip().startswith("/link")
                    else message_text
                ),
                self_authored=self_authored,
                observed_at=moment,
                state=(WeComEventState.IGNORED_SELF if self_authored else WeComEventState.RECEIVED),
            )
            cursor.execute(
                "INSERT INTO wecom_inbound_events VALUES(?,?,?,?,?,?,?,?)",
                (
                    str(event.id),
                    str(binding.id),
                    event.organization_id,
                    event.workspace_id,
                    source_event_id,
                    fingerprint,
                    sender_id,
                    event.model_dump_json(by_alias=True),
                ),
            )
            return event, True

    def mark_wecom_inbound_processed(
        self,
        event_id: UUID,
        binding_id: UUID,
        *,
        state: WeComEventState,
        operation_id: UUID | None = None,
    ) -> WeComInboundEvent:
        """Link the durably admitted source event to its fixed command outcome."""

        if state not in {
            WeComEventState.IGNORED_NON_COMMAND,
            WeComEventState.IGNORED_SCOPE,
            WeComEventState.IGNORED_INVALID_COMMAND,
            WeComEventState.IGNORED_UNLINKED,
            WeComEventState.IGNORED_UNBOUND,
            WeComEventState.IGNORED_UNRELATED,
            WeComEventState.COMMAND_QUEUED,
            WeComEventState.CHALLENGE_REPLY_PENDING,
            WeComEventState.REPLY_ACCEPTED,
            WeComEventState.REPLIED,
            WeComEventState.UNKNOWN,
            WeComEventState.REJECTED,
        }:
            raise IntegrationValidationError(
                "WeCom processing state is not a terminal intake state"
            )
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM wecom_inbound_events WHERE id=? AND binding_id=?",
                (str(event_id), str(binding_id)),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("WeCom inbound event not found")
            event = WeComInboundEvent.model_validate_json(str(row["document"]))
            if event.state not in {WeComEventState.RECEIVED, state}:
                raise IntegrationConflict("WeCom inbound event already has a terminal disposition")
            if (
                event.state == state
                and event.operation_id is not None
                and event.operation_id != operation_id
            ):
                raise IntegrationConflict("WeCom event is linked to another operation")
            if state == WeComEventState.COMMAND_QUEUED:
                if operation_id is None:
                    raise IntegrationValidationError("queued command requires operation ID")
                op_row = cursor.execute(
                    "SELECT document FROM operations WHERE id=?",
                    (str(operation_id),),
                ).fetchone()
                if op_row is None:
                    raise IntegrationNotFound("WeCom command operation not found")
                operation = Operation.model_validate_json(str(op_row["document"]))
                if (
                    operation.binding_id != binding_id
                    or operation.source_event_ref != str(event_id)
                    or operation.organization_id != event.organization_id
                    or operation.workspace_id != event.workspace_id
                    or operation.actor_issuer is None
                    or operation.actor_subject is None
                ):
                    raise IntegrationAuthorizationError(
                        "command operation does not match source event"
                    )
            updated = event.model_copy(update={"state": state, "operation_id": operation_id})
            cursor.execute(
                "UPDATE wecom_inbound_events SET document=? WHERE id=? AND binding_id=?",
                (updated.model_dump_json(by_alias=True), str(event_id), str(binding_id)),
            )
            return updated

    def begin_wecom_challenge_observation(
        self, binding_id: UUID, source_event_ref: str
    ) -> tuple[WeComInboundEvent, bool]:
        """Claim the one Account Center challenge observation allowed for an event."""

        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM wecom_inbound_events WHERE id=? AND binding_id=?",
                (source_event_ref, str(binding_id)),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("WeCom challenge source event not found")
            event = WeComInboundEvent.model_validate_json(str(row["document"]))
            if event.state == WeComEventState.RECEIVED:
                updated = event.model_copy(update={"state": WeComEventState.CHALLENGE_OBSERVING})
                claimed = True
            elif event.state == WeComEventState.CHALLENGE_OBSERVING:
                updated = event.model_copy(update={"state": WeComEventState.CHALLENGE_UNKNOWN})
                claimed = False
            else:
                return event, False
            cursor.execute(
                "UPDATE wecom_inbound_events SET document=? WHERE id=? AND binding_id=?",
                (updated.model_dump_json(by_alias=True), str(event.id), str(binding_id)),
            )
            return updated, claimed

    def mark_wecom_challenge_unknown(
        self, binding_id: UUID, source_event_ref: str
    ) -> WeComInboundEvent:
        """Persist ambiguous Account Center observation without automatic replay."""

        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM wecom_inbound_events WHERE id=? AND binding_id=?",
                (source_event_ref, str(binding_id)),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("WeCom challenge source event not found")
            event = WeComInboundEvent.model_validate_json(str(row["document"]))
            if event.state not in {
                WeComEventState.CHALLENGE_OBSERVING,
                WeComEventState.CHALLENGE_UNKNOWN,
            }:
                raise IntegrationConflict("WeCom challenge observation is not in progress")
            updated = event.model_copy(update={"state": WeComEventState.CHALLENGE_UNKNOWN})
            cursor.execute(
                "UPDATE wecom_inbound_events SET document=? WHERE id=? AND binding_id=?",
                (updated.model_dump_json(by_alias=True), str(event.id), str(binding_id)),
            )
            return updated

    def enqueue_wecom_challenge_reply(
        self, binding_id: UUID, source_event_ref: str, challenge_id: str
    ) -> WeComInboundEvent:
        """Atomically persist the observed challenge and private reply outbox job."""

        if not challenge_id or len(challenge_id) > 300:
            raise IntegrationValidationError("WeCom challenge reference is invalid")
        with self._transaction() as cursor:
            event_row = cursor.execute(
                "SELECT document FROM wecom_inbound_events WHERE id=? AND binding_id=?",
                (source_event_ref, str(binding_id)),
            ).fetchone()
            if event_row is None:
                raise IntegrationNotFound("WeCom challenge source event not found")
            event = WeComInboundEvent.model_validate_json(str(event_row["document"]))
            if (
                event.self_authored
                or event.message_text != "/link [redacted]"
                or not event.reply_message_id
                or not event.reply_context_ref
                or event.state
                not in {
                    WeComEventState.CHALLENGE_OBSERVING,
                    WeComEventState.CHALLENGE_REPLY_PENDING,
                    WeComEventState.REPLY_ACCEPTED,
                    WeComEventState.UNKNOWN,
                }
            ):
                raise IntegrationAuthorizationError("WeCom challenge reply source is invalid")
            if event.challenge_id is not None and event.challenge_id != challenge_id:
                raise IntegrationConflict("WeCom source event already recorded another challenge")
            binding_row = cursor.execute(
                "SELECT document FROM sync_bindings WHERE id=?",
                (str(binding_id),),
            ).fetchone()
            if binding_row is None:
                raise IntegrationNotFound("WeCom source binding not found")
            binding = SyncBinding.model_validate_json(str(binding_row["document"]))
            if not binding.enabled:
                raise IntegrationAuthorizationError("WeCom reply target is not configured")
            idempotency_key = f"wecom-challenge:{event.id}:{challenge_id}"
            existing = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE kind='CHALLENGE_REPLY' "
                "AND idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                return event
            if event.state not in {
                WeComEventState.CHALLENGE_OBSERVING,
                WeComEventState.CHALLENGE_REPLY_PENDING,
            }:
                raise IntegrationConflict("WeCom challenge state requires explicit recovery")
            if existing is None:
                now = utc_now()
                job = OutboxJob(
                    kind="CHALLENGE_REPLY",
                    organization_id=event.organization_id,
                    workspace_id=event.workspace_id,
                    actor_issuer=f"urn:cyrene:wecom:{binding.id}",
                    actor_subject=event.sender_id,
                    connection_id=binding.connection_id,
                    binding_id=binding.id,
                    idempotency_key=idempotency_key,
                    payload={
                        "eventId": str(event.id),
                        "sourceBindingId": str(binding.id),
                        "senderId": event.sender_id,
                        "conversationRef": event.conversation_ref,
                        "replyMessageId": event.reply_message_id,
                        "replyContextRef": event.reply_context_ref,
                        "text": f"Link challenge ID: {challenge_id}. Confirm it in Exchange.",
                    },
                    available_at=now,
                    created_at=now,
                    updated_at=now,
                )
                self._insert_job(cursor, job)
            updated = event.model_copy(
                update={
                    "state": WeComEventState.CHALLENGE_REPLY_PENDING,
                    "challenge_id": challenge_id,
                }
            )
            cursor.execute(
                "UPDATE wecom_inbound_events SET document=? WHERE id=? AND binding_id=?",
                (updated.model_dump_json(by_alias=True), str(event.id), str(binding_id)),
            )
            return updated

    def enqueue_issue_command_for_actor(
        self,
        *,
        binding_id: UUID,
        actor_issuer: str,
        actor_subject: str,
        organization_id: str,
        workspace_id: str,
        source_event_ref: str,
        source_sender_id: str,
        idempotency_key: str,
        command_text: str,
    ) -> Operation:
        """Admit one verified WeCom command using the sender's own ActorBinding.

        Caller must obtain the identity tuple from the authenticated WeCom source and
        Account Center sender lookup; this method never constructs an IntegrationPrincipal.
        """

        from cyrene_exchange_product.integrations.commands import parse_issue_command

        if not all((actor_issuer, actor_subject, organization_id, workspace_id)):
            raise IntegrationValidationError("verified sender scope is incomplete")
        if not source_event_ref or len(source_event_ref) > 300:
            raise IntegrationValidationError("source event reference is invalid")
        if not source_sender_id or len(source_sender_id) > 200:
            raise IntegrationValidationError("verified sender source ID is invalid")
        parsed = parse_issue_command(command_text)
        with self._lock:
            binding_row = self._connection.execute(
                """SELECT document FROM sync_bindings WHERE id=? AND organization_id=?
                   AND workspace_id=?""",
                (str(binding_id), organization_id, workspace_id),
            ).fetchone()
            actor_row = self._connection.execute(
                """SELECT document FROM actor_bindings WHERE binding_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (str(binding_id), organization_id, workspace_id, actor_issuer, actor_subject),
            ).fetchone()
        if binding_row is None:
            raise IntegrationNotFound("sync binding not found for verified sender")
        if actor_row is None:
            raise IntegrationAuthorizationError("verified sender has no attached ActorBinding")
        binding = SyncBinding.model_validate_json(str(binding_row["document"]))
        with self._lock:
            event_row = self._connection.execute(
                "SELECT document FROM wecom_inbound_events WHERE id=? AND binding_id=?",
                (source_event_ref, str(binding_id)),
            ).fetchone()
        if event_row is None:
            raise IntegrationNotFound("durable WeCom source event was not found")
        source_event = WeComInboundEvent.model_validate_json(str(event_row["document"]))
        if (
            source_event.sender_id != source_sender_id
            or source_event.self_authored
            or source_event.state
            not in {
                WeComEventState.RECEIVED,
                WeComEventState.COMMAND_QUEUED,
            }
        ):
            raise IntegrationAuthorizationError("WeCom command source is not eligible")
        if not source_event.reply_context_ref or not source_event.reply_message_id:
            raise IntegrationValidationError("WeCom command has no trusted reply context")
        actor_binding = ActorBinding.model_validate_json(str(actor_row["document"]))
        if not binding.enabled or not actor_binding.enabled:
            raise IntegrationAuthorizationError("WeCom ActorBinding is disabled")
        connection = self._get_connection_for_scope_by_ids(
            binding.connection_id, organization_id=organization_id, workspace_id=workspace_id
        )
        request = EnqueueIssueAction(
            connection_id=connection.id,
            binding_id=binding.id,
            operation_id=cast(Any, parsed.operation_id),
            idempotency_key=idempotency_key,
            issue_number=parsed.issue_number,
            body=parsed.body,
        )
        return self._persist_issue_action(
            request,
            binding=binding,
            actor_binding=actor_binding,
            connection=connection,
            actor_issuer=actor_issuer,
            actor_subject=actor_subject,
            organization_id=organization_id,
            workspace_id=workspace_id,
            source_kind="WECOM_COMMAND",
            source_event_ref=source_event_ref,
            reply_binding_ref=str(binding.id),
            reply_sender_id=source_event.sender_id,
            reply_conversation_ref=source_event.conversation_ref,
            reply_message_id=source_event.reply_message_id,
            reply_context_ref=source_event.reply_context_ref,
        )

    def _persist_issue_action(
        self,
        request: EnqueueIssueAction,
        *,
        binding: SyncBinding,
        actor_binding: ActorBinding,
        connection: IntegrationConnection,
        actor_issuer: str,
        actor_subject: str,
        organization_id: str,
        workspace_id: str,
        source_kind: Literal["REST", "WECOM_COMMAND"] = "REST",
        source_event_ref: str | None = None,
        reply_binding_ref: str | None = None,
        reply_sender_id: str | None = None,
        reply_conversation_ref: str | None = None,
        reply_message_id: str | None = None,
        reply_context_ref: str | None = None,
    ) -> Operation:
        """Atomically create/reuse the durable operation and its Authority job."""

        canonical = {
            "connectionId": str(request.connection_id),
            "bindingId": str(binding.id),
            "operationId": request.operation_id,
            "issueNumber": request.issue_number,
            "body": request.body,
            "reconcilesOperationId": (
                str(request.reconciles_operation_id) if request.reconciles_operation_id else None
            ),
            "sourceKind": source_kind,
            "sourceEventRef": source_event_ref,
        }
        digest = hashlib.sha256(_json(canonical).encode("utf-8")).hexdigest()
        with self._transaction() as cursor:
            existing = cursor.execute(
                """SELECT document,request_hash FROM operations WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND connection_id=? AND idempotency_key=?""",
                (
                    organization_id,
                    workspace_id,
                    actor_issuer,
                    actor_subject,
                    str(connection.id),
                    request.idempotency_key,
                ),
            ).fetchone()
            if existing is not None:
                if str(existing["request_hash"]) != digest:
                    raise IntegrationConflict("idempotency key was reused for a different request")
                return Operation.model_validate_json(str(existing["document"]))
            execution_operation_id, provider_arguments = _provider_arguments(request, connection)
            argument_digest = hashlib.sha256(_json(provider_arguments).encode("utf-8")).hexdigest()
            now = utc_now()
            operation = Operation(
                organization_id=organization_id,
                workspace_id=workspace_id,
                actor_issuer=actor_issuer,
                actor_subject=actor_subject,
                connection_id=connection.id,
                binding_id=binding.id,
                actor_binding_id=actor_binding.id,
                account_link_ref=actor_binding.account_link_ref,
                delegation_ref=actor_binding.delegation_ref,
                execution_operation_id=execution_operation_id,
                argument_digest=argument_digest,
                reconciles_operation_id=request.reconciles_operation_id,
                source_kind=source_kind,
                source_event_ref=source_event_ref,
                reply_binding_ref=reply_binding_ref,
                reply_sender_id=reply_sender_id,
                reply_conversation_ref=reply_conversation_ref,
                reply_message_id=reply_message_id,
                reply_context_ref=reply_context_ref,
                operation_id=request.operation_id,
                idempotency_key=request.idempotency_key,
                request_hash=digest,
                issue_number=request.issue_number,
                body=request.body,
                created_at=now,
                updated_at=now,
            )
            cursor.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    str(operation.id),
                    operation.organization_id,
                    operation.workspace_id,
                    operation.actor_issuer,
                    operation.actor_subject,
                    str(connection.id),
                    request.idempotency_key,
                    digest,
                    operation.state.value,
                    operation.model_dump_json(by_alias=True),
                ),
            )
            job = OutboxJob(
                kind="ISSUE_ACTION",
                organization_id=operation.organization_id,
                workspace_id=operation.workspace_id,
                actor_issuer=actor_issuer,
                actor_subject=actor_subject,
                connection_id=connection.id,
                binding_id=binding.id,
                operation_id=operation.id,
                idempotency_key=f"operation:{operation.id}",
                payload=canonical,
                available_at=now,
                created_at=now,
                updated_at=now,
            )
            self._insert_job(cursor, job)
        return operation

    def get_operation(self, principal: IntegrationPrincipal, operation_id: UUID) -> Operation:
        return self.get_operation_for_principal(
            principal, operation_id, authorization_operation_id="integrationGetOperation"
        )

    def get_operation_for_principal(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        authorization_operation_id: str,
    ) -> Operation:
        """Read one operation under the initiating principal's scope."""

        principal.require(authorization_operation_id)
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM operations WHERE id=? AND organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?""",
                (str(operation_id), *self._scope(principal)),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("integration operation not found")
        return Operation.model_validate_json(str(row["document"]))

    def resolve_unknown_operation(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        succeeded: bool,
        result: dict[str, Any],
        authorization_operation_id: str = "integrationReconcile",
    ) -> Operation:
        """Record a read-only reconciliation result without resending the action."""

        principal.require(authorization_operation_id)
        now = utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM operations WHERE id=? AND organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND state='UNKNOWN'""",
                (str(operation_id), *self._scope(principal)),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("unknown integration operation not found")
            operation = Operation.model_validate_json(str(row["document"]))
            state = OperationState.SUCCEEDED if succeeded else OperationState.UNKNOWN
            updated = operation.model_copy(
                update={"state": state, "result": result, "updated_at": now}
            )
            cursor.execute(
                "UPDATE operations SET state=?,document=? WHERE id=? AND state='UNKNOWN'",
                (state.value, updated.model_dump_json(by_alias=True), str(operation_id)),
            )
            if succeeded:
                jobs = cursor.execute(
                    "SELECT document,claim_fence FROM outbox_jobs WHERE operation_id=? "
                    "AND state='UNKNOWN'",
                    (str(operation_id),),
                ).fetchall()
                for job_row in jobs:
                    job = OutboxJob.model_validate_json(str(job_row["document"]))
                    recovered = job.model_copy(
                        update={"state": JobState.SUCCEEDED, "updated_at": now}
                    )
                    self._persist_job(cursor, recovered)
                    cursor.execute(
                        "INSERT OR REPLACE INTO job_evidence VALUES(?,?,?)",
                        (
                            str(job.id),
                            int(job_row["claim_fence"]),
                            _json({"reconciledReadOnly": True, **result}),
                        ),
                    )
            audit = OperationAudit(
                organization_id=principal.organization_id,
                workspace_id=principal.workspace_id,
                actor_issuer=principal.issuer,
                actor_subject=principal.subject,
                resource_type="integration.operation",
                resource_id=str(operation_id),
                action="reconcile",
                outcome="SUCCEEDED" if succeeded else "UNKNOWN",
                observed_at=now,
                metadata={"readOnly": True},
            )
            cursor.execute(
                "INSERT INTO operation_audits VALUES(?,?,?,?,?)",
                (
                    str(audit.id),
                    audit.organization_id,
                    audit.workspace_id,
                    _dt(audit.observed_at),
                    audit.model_dump_json(by_alias=True),
                ),
            )
            return updated

    def enqueue_reconciliation_query(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        idempotency_key: str,
    ) -> Operation:
        """Create or reuse a separately Authority-approved read-only issue query."""

        principal.require("integrationReconcile")
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        original = self.get_operation_for_principal(
            principal,
            operation_id,
            authorization_operation_id="integrationReconcile",
        )
        if original.operation_id not in {
            "integration.issue.close",
            "integration.issue.reopen",
        }:
            raise IntegrationConflict("this operation cannot be reconciled automatically")
        if original.state != OperationState.UNKNOWN:
            with self._lock:
                existing = self._connection.execute(
                    """SELECT document FROM operations WHERE organization_id=?
                       AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                       AND connection_id=? AND idempotency_key=?""",
                    (
                        principal.organization_id,
                        principal.workspace_id,
                        principal.issuer,
                        principal.subject,
                        str(original.connection_id),
                        idempotency_key,
                    ),
                ).fetchone()
            if existing is not None:
                existing_operation = Operation.model_validate_json(str(existing["document"]))
                if existing_operation.reconciles_operation_id == original.id:
                    return existing_operation
            raise IntegrationConflict("only UNKNOWN operations can be reconciled")
        query = self.enqueue_issue_action(
            principal,
            EnqueueIssueAction(
                connection_id=original.connection_id,
                binding_id=original.binding_id,
                operation_id="integration.issue.query",
                idempotency_key=idempotency_key,
                issue_number=original.issue_number,
                reconciles_operation_id=original.id,
            ),
            authorization_operation_id="integrationReconcile",
        )
        return query

    def list_jobs(
        self, principal: IntegrationPrincipal, *, state: JobState | None = None
    ) -> list[OutboxJob]:
        """List durable jobs only in the caller's actor and workspace scope."""

        principal.require("integrationListJobs")
        query = """SELECT document FROM outbox_jobs WHERE organization_id=? AND workspace_id=?
            AND actor_issuer=? AND actor_subject=?"""
        params: tuple[str, ...] = (
            principal.organization_id,
            principal.workspace_id,
            principal.issuer,
            principal.subject,
        )
        if state is not None:
            query += " AND state=?"
            params += (state.value,)
        query += " ORDER BY created_at,id"
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [OutboxJob.model_validate_json(str(row["document"])) for row in rows]

    def list_delivery_receipts(self, principal: IntegrationPrincipal) -> list[DeliveryReceipt]:
        """List explicit delivery evidence for jobs in the caller's actor scope."""

        principal.require("integrationListJobs")
        with self._lock:
            rows = self._connection.execute(
                """SELECT receipt.document FROM delivery_receipts AS receipt
                   JOIN outbox_jobs AS job ON job.id=receipt.job_id
                   WHERE job.organization_id=? AND job.workspace_id=?
                   AND job.actor_issuer=? AND job.actor_subject=?
                   ORDER BY receipt.id""",
                (
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                ),
            ).fetchall()
        return [DeliveryReceipt.model_validate_json(str(row["document"])) for row in rows]

    def claim_job(self, worker_id: str, *, now: datetime, lease_seconds: int) -> ClaimedJob | None:
        """Claim one ready job with a CAS update and a monotonic fencing token."""

        if not worker_id or len(worker_id) > 200 or lease_seconds < 1 or lease_seconds > 300:
            raise ValueError("worker id or lease duration is invalid")
        self.recover_expired_claims(now=now)
        lease_expiry = now + timedelta(seconds=lease_seconds)
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM outbox_jobs
                   WHERE state IN ('READY','AWAITING_AUTHORITY') AND available_at<=?
                   ORDER BY available_at,created_at,id LIMIT 1""",
                (_dt(now),),
            ).fetchone()
            if row is None:
                return None
            job = OutboxJob.model_validate_json(str(row["document"]))
            claimed_from_state = job.state
            updated = job.model_copy(
                update={
                    "state": JobState.CLAIMED,
                    "claim_owner": worker_id,
                    "claim_fence": job.claim_fence + 1,
                    "lease_expires_at": lease_expiry,
                    "attempts": job.attempts + 1,
                    "updated_at": now,
                }
            )
            cursor.execute(
                """UPDATE outbox_jobs SET state='CLAIMED',claim_owner=?,claim_fence=?,
                   lease_expires_at=?,attempts=?,updated_at=?,document=?
                   WHERE id=? AND state=?""",
                (
                    worker_id,
                    updated.claim_fence,
                    _dt(lease_expiry),
                    updated.attempts,
                    _dt(now),
                    updated.model_dump_json(by_alias=True),
                    str(job.id),
                    claimed_from_state.value,
                ),
            )
            if cursor.rowcount != 1:
                return None
            return ClaimedJob(
                job=updated,
                claim_fence=updated.claim_fence,
                claimed_from_state=claimed_from_state,
            )

    def mark_sending(self, job_id: UUID, *, claim_fence: int, now: datetime) -> OutboxJob:
        """Persist the write boundary before any external provider call."""

        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='CLAIMED' "
                "AND claim_fence=? AND lease_expires_at>?",
                (str(job_id), claim_fence, _dt(now)),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("job claim is stale or expired")
            job = OutboxJob.model_validate_json(str(row["document"]))
            sending = job.model_copy(update={"state": JobState.SENDING, "updated_at": now})
            cursor.execute(
                "UPDATE outbox_jobs SET state='SENDING',updated_at=?,document=? "
                "WHERE id=? AND state='CLAIMED' AND claim_fence=?",
                (_dt(now), sending.model_dump_json(by_alias=True), str(job_id), claim_fence),
            )
            if job.operation_id is not None and job.kind == "ISSUE_ACTION":
                self._update_operation_state(cursor, job.operation_id, OperationState.RUNNING, now)
            return sending

    def fail_claimed_job(
        self, job_id: UUID, *, claim_fence: int, reason_code: str, now: datetime | None = None
    ) -> OutboxJob:
        """Fail a job before external effects when fresh authorization is denied."""

        moment = now or utc_now()
        safe_code = reason_code[:100]
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='CLAIMED' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("job claim is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            failed = job.model_copy(
                update={
                    "state": JobState.FAILED,
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "updated_at": moment,
                }
            )
            self._persist_job(cursor, failed)
            cursor.execute(
                "INSERT INTO job_evidence VALUES(?,?,?)",
                (str(job_id), claim_fence, _json({"reasonCode": safe_code})),
            )
            if job.operation_id is not None and job.kind == "ISSUE_ACTION":
                self._update_operation_state(
                    cursor,
                    job.operation_id,
                    OperationState.FAILED,
                    moment,
                    result={"reasonCode": safe_code},
                )
                self._enqueue_reply_for_operation(
                    cursor,
                    job.operation_id,
                    state=JobState.FAILED,
                    evidence={"reasonCode": safe_code},
                    now=moment,
                )
                operation_row = cursor.execute(
                    "SELECT document FROM operations WHERE id=?", (str(job.operation_id),)
                ).fetchone()
                if operation_row is not None:
                    operation = Operation.model_validate_json(str(operation_row["document"]))
                    self._enqueue_command_reply(
                        cursor,
                        operation=operation,
                        state=JobState.FAILED,
                        evidence={"reasonCode": safe_code},
                        now=moment,
                    )
            if job.kind in {"COMMAND_REPLY", "CHALLENGE_REPLY"}:
                event_ref = job.payload.get("eventId")
                if isinstance(event_ref, str):
                    event_row = cursor.execute(
                        "SELECT document FROM wecom_inbound_events WHERE id=?",
                        (event_ref,),
                    ).fetchone()
                    if event_row is not None:
                        event = WeComInboundEvent.model_validate_json(str(event_row["document"]))
                        event = event.model_copy(update={"state": WeComEventState.REJECTED})
                        cursor.execute(
                            "UPDATE wecom_inbound_events SET document=? WHERE id=?",
                            (event.model_dump_json(by_alias=True), event_ref),
                        )
            return failed

    def mark_awaiting_authority(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        invocation_id: str,
        authority_state: str,
        now: datetime | None = None,
    ) -> OutboxJob:
        """Persist an Authority invocation reference without treating it as a credential."""

        if not invocation_id or len(invocation_id) > 300:
            raise IntegrationValidationError("authority invocation reference is invalid")
        moment = now or utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='CLAIMED' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("job claim is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            if job.authority_invocation_id not in (None, invocation_id):
                raise IntegrationConflict("job already references a different Authority invocation")
            updated = job.model_copy(
                update={
                    "state": JobState.AWAITING_AUTHORITY,
                    "authority_invocation_id": invocation_id,
                    "authority_state": authority_state,
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "updated_at": moment,
                }
            )
            self._persist_job(cursor, updated)
            if job.operation_id is not None:
                operation_row = cursor.execute(
                    "SELECT document FROM operations WHERE id=?", (str(job.operation_id),)
                ).fetchone()
                if operation_row is None:
                    raise IntegrationNotFound("authorized operation not found")
                operation = Operation.model_validate_json(str(operation_row["document"]))
                operation_updated = operation.model_copy(
                    update={
                        "state": OperationState.AWAITING_AUTHORITY,
                        "authority_invocation_id": invocation_id,
                        "updated_at": moment,
                    }
                )
                cursor.execute(
                    "UPDATE operations SET state=?,document=? WHERE id=?",
                    (
                        OperationState.AWAITING_AUTHORITY.value,
                        operation_updated.model_dump_json(by_alias=True),
                        str(job.operation_id),
                    ),
                )
            return updated

    def prepare_authority_enqueue(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        candidate_idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[Operation, OutboxJob, str]:
        """Persist the exact Platform request key before calling its enqueue RPC."""

        if not candidate_idempotency_key or len(candidate_idempotency_key) > 300:
            raise IntegrationValidationError("Authority idempotency key is invalid")
        moment = now or utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='CLAIMED' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("job claim is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            if job.operation_id is None:
                raise IntegrationNotFound("Authority job has no operation")
            operation_row = cursor.execute(
                "SELECT document FROM operations WHERE id=?", (str(job.operation_id),)
            ).fetchone()
            if operation_row is None:
                raise IntegrationNotFound("Authority operation not found")
            operation = Operation.model_validate_json(str(operation_row["document"]))
            existing = job.authority_idempotency_key
            if existing != operation.authority_idempotency_key:
                raise IntegrationConflict("Authority idempotency records do not match")
            key = existing or candidate_idempotency_key
            prepared_job = job.model_copy(
                update={"authority_idempotency_key": key, "updated_at": moment}
            )
            prepared_operation = operation.model_copy(
                update={"authority_idempotency_key": key, "updated_at": moment}
            )
            self._persist_job(cursor, prepared_job)
            cursor.execute(
                "UPDATE operations SET document=? WHERE id=?",
                (prepared_operation.model_dump_json(by_alias=True), str(operation.id)),
            )
            return prepared_operation, prepared_job, key

    def update_authority_evidence(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        invocation_id: str,
        authority_state: str,
        now: datetime | None = None,
    ) -> OutboxJob:
        """Persist a poll result for the exact invocation already on the job."""

        moment = now or utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='CLAIMED' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("job claim is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            if job.authority_invocation_id != invocation_id:
                raise IntegrationConflict("Authority invocation does not match the durable intent")
            updated = job.model_copy(
                update={
                    "state": JobState.AWAITING_AUTHORITY,
                    "authority_state": authority_state,
                    "available_at": moment + timedelta(seconds=2),
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "updated_at": moment,
                }
            )
            self._persist_job(cursor, updated)
            if job.operation_id is not None:
                operation_row = cursor.execute(
                    "SELECT document FROM operations WHERE id=?", (str(job.operation_id),)
                ).fetchone()
                if operation_row is None:
                    raise IntegrationNotFound("authorized operation not found")
                operation = Operation.model_validate_json(str(operation_row["document"]))
                operation_updated = operation.model_copy(update={"updated_at": moment})
                cursor.execute(
                    "UPDATE operations SET document=? WHERE id=? AND state='AWAITING_AUTHORITY'",
                    (operation_updated.model_dump_json(by_alias=True), str(job.operation_id)),
                )
            return updated

    def mark_authority_result_unknown(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        invocation_id: str,
        now: datetime | None = None,
    ) -> OutboxJob:
        """Persist Authority UNKNOWN_RESULT without translating it to failure/success."""

        moment = now or utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='CLAIMED' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("Authority result claim is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            if job.authority_invocation_id != invocation_id:
                raise IntegrationConflict("Authority result invocation does not match intent")
            updated = job.model_copy(
                update={
                    "state": JobState.UNKNOWN,
                    "authority_state": "UNKNOWN_RESULT",
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "updated_at": moment,
                }
            )
            self._persist_job(cursor, updated)
            cursor.execute(
                "INSERT INTO job_evidence VALUES(?,?,?)",
                (str(job_id), claim_fence, _json({"authorityState": "UNKNOWN_RESULT"})),
            )
            if job.operation_id is not None:
                self._update_operation_state(
                    cursor,
                    job.operation_id,
                    OperationState.UNKNOWN,
                    moment,
                    result={"authorityState": "UNKNOWN_RESULT"},
                )
                self._enqueue_reply_for_operation(
                    cursor,
                    job.operation_id,
                    state=JobState.UNKNOWN,
                    evidence={"authorityState": "UNKNOWN_RESULT"},
                    now=moment,
                )
            return updated

    def begin_authorized_execution(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        binding_id: UUID,
        execution_operation_id: str,
        argument_digest: str,
        authority_invocation_id: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> tuple[Operation, OutboxJob, int]:
        """Recheck signed-execution intent and CAS it to SENDING before provider writes."""

        principal.require(execution_operation_id)
        moment = now or utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM operations WHERE id=? AND organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND state IN ('QUEUED','AWAITING_AUTHORITY')""",
                (str(operation_id), *self._scope(principal)),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("operation is not awaiting Authority execution")
            operation = Operation.model_validate_json(str(row["document"]))
            if (
                operation.binding_id != binding_id
                or operation.execution_operation_id != execution_operation_id
                or operation.argument_digest != argument_digest
                or operation.authority_invocation_id not in (None, authority_invocation_id)
            ):
                raise IntegrationAuthorizationError("approved invocation does not match intent")
            binding_row = cursor.execute(
                """SELECT document FROM sync_bindings WHERE id=? AND connection_id=?
                   AND organization_id=? AND workspace_id=?""",
                (
                    str(binding_id),
                    str(operation.connection_id),
                    principal.organization_id,
                    principal.workspace_id,
                ),
            ).fetchone()
            if binding_row is None:
                raise IntegrationNotFound("execution binding no longer exists in workspace scope")
            binding = SyncBinding.model_validate_json(str(binding_row["document"]))
            actor_binding_row = cursor.execute(
                """SELECT document FROM actor_bindings WHERE id=? AND binding_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (
                    str(operation.actor_binding_id),
                    str(binding_id),
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                ),
            ).fetchone()
            if actor_binding_row is None:
                raise IntegrationNotFound("member authority attachment no longer exists")
            actor_binding = ActorBinding.model_validate_json(str(actor_binding_row["document"]))
            connection_row = cursor.execute(
                """SELECT document FROM integration_connections WHERE id=?
                   AND organization_id=? AND workspace_id=? AND enabled=1""",
                (
                    str(operation.connection_id),
                    principal.organization_id,
                    principal.workspace_id,
                ),
            ).fetchone()
            if connection_row is None:
                raise IntegrationNotFound("execution connection no longer exists in actor scope")
            if (
                not binding.enabled
                or not actor_binding.enabled
                or actor_binding.delegation_ref != operation.delegation_ref
                or actor_binding.account_link_ref != operation.account_link_ref
            ):
                raise IntegrationAuthorizationError("execution binding is disabled or mismatched")
            job_row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE operation_id=? "
                "AND state IN ('AWAITING_AUTHORITY','CLAIMED')",
                (str(operation_id),),
            ).fetchone()
            if job_row is None:
                raise IntegrationConflict("operation has no awaiting outbox job")
            job = OutboxJob.model_validate_json(str(job_row["document"]))
            if (
                job.binding_id != binding_id
                or job.authority_invocation_id not in (None, authority_invocation_id)
                or job.actor_issuer != principal.issuer
                or job.actor_subject != principal.subject
                or job.organization_id != principal.organization_id
                or job.workspace_id != principal.workspace_id
            ):
                raise IntegrationAuthorizationError("approved invocation scope does not match")
            fence = job.claim_fence + 1
            sending = job.model_copy(
                update={
                    "state": JobState.SENDING,
                    "claim_owner": f"authority:{authority_invocation_id}",
                    "claim_fence": fence,
                    "lease_expires_at": moment + timedelta(seconds=lease_seconds),
                    "attempts": job.attempts + 1,
                    "updated_at": moment,
                }
            )
            running = operation.model_copy(
                update={
                    "state": OperationState.RUNNING,
                    "authority_invocation_id": authority_invocation_id,
                    "updated_at": moment,
                }
            )
            sending = sending.model_copy(
                update={"authority_invocation_id": authority_invocation_id}
            )
            self._persist_job(cursor, sending)
            cursor.execute(
                "UPDATE operations SET state=?,document=? WHERE id=? "
                "AND state IN ('QUEUED','AWAITING_AUTHORITY')",
                (
                    OperationState.RUNNING.value,
                    running.model_dump_json(by_alias=True),
                    str(operation_id),
                ),
            )
            if cursor.rowcount != 1:
                raise IntegrationConflict("operation execution was already claimed")
            return running, sending, fence

    @staticmethod
    def _update_operation_state(
        cursor: sqlite3.Cursor,
        operation_id: UUID,
        state: OperationState,
        now: datetime,
        *,
        result: dict[str, Any] | None = None,
    ) -> None:
        row = cursor.execute(
            "SELECT document FROM operations WHERE id=?", (str(operation_id),)
        ).fetchone()
        if row is None:
            return
        operation = Operation.model_validate_json(str(row["document"]))
        updated = operation.model_copy(update={"state": state, "result": result, "updated_at": now})
        cursor.execute(
            "UPDATE operations SET state=?,document=? WHERE id=?",
            (state.value, updated.model_dump_json(by_alias=True), str(operation_id)),
        )

    def finish_job(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        status: JobState,
        evidence: dict[str, object],
        receipt: DeliveryReceipt | None = None,
    ) -> OutboxJob:
        """Persist explicit provider evidence and terminal state under its fence."""

        if status not in {
            JobState.ACCEPTED,
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.UNKNOWN,
        }:
            raise ValueError("finish status must be an explicit terminal/evidence state")
        now = receipt.observed_at if receipt is not None else utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='SENDING' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("job send fence is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            finished = job.model_copy(
                update={
                    "state": status,
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "updated_at": now,
                }
            )
            self._persist_job(cursor, finished)
            cursor.execute(
                "INSERT INTO job_evidence VALUES(?,?,?)",
                (str(job_id), claim_fence, _json(evidence)),
            )
            operation_state = {
                JobState.ACCEPTED: OperationState.ACCEPTED,
                JobState.SUCCEEDED: OperationState.SUCCEEDED,
                JobState.FAILED: OperationState.FAILED,
                JobState.UNKNOWN: OperationState.UNKNOWN,
            }[status]
            if job.operation_id is not None and job.kind == "ISSUE_ACTION":
                self._update_operation_state(
                    cursor, job.operation_id, operation_state, now, result=evidence
                )
                operation_row = cursor.execute(
                    "SELECT document FROM operations WHERE id=?", (str(job.operation_id),)
                ).fetchone()
                if operation_row is not None:
                    operation = Operation.model_validate_json(str(operation_row["document"]))
                    self._enqueue_command_reply(
                        cursor, operation=operation, state=status, evidence=evidence, now=now
                    )
            if receipt is not None:
                bound_receipt = receipt.model_copy(
                    update={"job_id": job.id, "operation_id": job.operation_id}
                )
                cursor.execute(
                    "INSERT INTO delivery_receipts VALUES(?,?,?,?)",
                    (
                        str(bound_receipt.id),
                        str(bound_receipt.operation_id) if bound_receipt.operation_id else None,
                        str(bound_receipt.job_id) if bound_receipt.job_id else None,
                        bound_receipt.model_dump_json(by_alias=True),
                    ),
                )
            if job.kind in {"COMMAND_REPLY", "CHALLENGE_REPLY"}:
                event_ref = job.payload.get("eventId")
                if isinstance(event_ref, str):
                    event_row = cursor.execute(
                        "SELECT document FROM wecom_inbound_events WHERE id=? AND binding_id=?",
                        (event_ref, str(job.binding_id)),
                    ).fetchone()
                    if event_row is not None:
                        event = WeComInboundEvent.model_validate_json(str(event_row["document"]))
                        event_state = (
                            WeComEventState.REPLY_ACCEPTED
                            if status == JobState.ACCEPTED
                            else WeComEventState.UNKNOWN
                            if status == JobState.UNKNOWN
                            else WeComEventState.REJECTED
                        )
                        event = event.model_copy(update={"state": event_state})
                        cursor.execute(
                            "UPDATE wecom_inbound_events SET document=? WHERE id=?",
                            (event.model_dump_json(by_alias=True), event_ref),
                        )
            return finished

    def _enqueue_command_reply(
        self,
        cursor: sqlite3.Cursor,
        *,
        operation: Operation,
        state: JobState,
        evidence: dict[str, object],
        now: datetime,
    ) -> None:
        """Atomically enqueue a deterministic reply only for WeCom-origin operations."""

        if operation.source_kind != "WECOM_COMMAND":
            return
        if not all(
            (
                operation.source_event_ref,
                operation.reply_binding_ref,
                operation.reply_sender_id,
                operation.reply_conversation_ref,
                operation.reply_message_id,
                operation.reply_context_ref,
            )
        ):
            return
        connection_row = cursor.execute(
            "SELECT document FROM integration_connections WHERE id=? AND organization_id=? "
            "AND workspace_id=?",
            (str(operation.connection_id), operation.organization_id, operation.workspace_id),
        ).fetchone()
        if connection_row is None:
            raise IntegrationNotFound("reply repository connection not found")
        connection = IntegrationConnection.model_validate_json(str(connection_row["document"]))
        from cyrene_exchange_product.integrations.commands import render_issue_command_result

        reply = OutboxJob(
            kind="COMMAND_REPLY",
            organization_id=operation.organization_id,
            workspace_id=operation.workspace_id,
            actor_issuer=operation.actor_issuer,
            actor_subject=operation.actor_subject,
            connection_id=operation.connection_id,
            binding_id=operation.binding_id,
            operation_id=operation.id,
            idempotency_key=f"command-reply:{operation.source_event_ref}:{operation.id}",
            payload={
                "eventId": operation.source_event_ref,
                "sourceBindingId": operation.reply_binding_ref,
                "senderId": operation.reply_sender_id,
                "conversationRef": operation.reply_conversation_ref,
                "replyMessageId": operation.reply_message_id,
                "replyContextRef": operation.reply_context_ref,
                "text": render_issue_command_result(
                    operation,
                    repository_name=connection.repository_name,
                    state=state,
                    evidence=evidence,
                ),
            },
            available_at=now,
            created_at=now,
            updated_at=now,
        )
        self._insert_job(cursor, reply)

    def _enqueue_reply_for_operation(
        self,
        cursor: sqlite3.Cursor,
        operation_id: UUID,
        *,
        state: JobState,
        evidence: dict[str, object],
        now: datetime,
    ) -> None:
        """Load current durable intent and enqueue a WeCom result reply if applicable."""

        row = cursor.execute(
            "SELECT document FROM operations WHERE id=?", (str(operation_id),)
        ).fetchone()
        if row is None:
            return
        operation = Operation.model_validate_json(str(row["document"]))
        self._enqueue_command_reply(
            cursor,
            operation=operation,
            state=state,
            evidence=evidence,
            now=now,
        )

    def recover_expired_claims(self, *, now: datetime) -> int:
        """Release expired pre-send claims and mark expired sends UNKNOWN.

        A process crash after a write reaches SENDING leaves its result unknown.
        Only read-only issue queries can re-enter READY, under a new Authority attempt.
        中文：写操作过期后保持 UNKNOWN；只有只读查询可有限重试。
        """

        with self._transaction() as cursor:
            rows = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE state IN ('CLAIMED','SENDING') "
                "AND lease_expires_at<=?",
                (_dt(now),),
            ).fetchall()
            count = 0
            for row in rows:
                job = OutboxJob.model_validate_json(str(row["document"]))
                if job.state == JobState.CLAIMED:
                    updated = job.model_copy(
                        update={
                            "state": (
                                JobState.AWAITING_AUTHORITY
                                if job.authority_invocation_id
                                else JobState.READY
                            ),
                            "claim_owner": None,
                            "lease_expires_at": None,
                            "updated_at": now,
                        }
                    )
                else:
                    is_readonly_query = (
                        job.kind == "ISSUE_ACTION"
                        and job.payload.get("operationId") == "integration.issue.query"
                    )
                    if is_readonly_query and job.attempts < 4:
                        updated = job.model_copy(
                            update={
                                "state": JobState.READY,
                                "authority_invocation_id": None,
                                "authority_idempotency_key": None,
                                "authority_state": None,
                                "available_at": now
                                + timedelta(seconds=min(30, 2 ** (job.attempts - 1))),
                                "claim_owner": None,
                                "lease_expires_at": None,
                                "updated_at": now,
                            }
                        )
                        operation_state = OperationState.QUEUED
                    else:
                        updated = job.model_copy(
                            update={
                                "state": JobState.UNKNOWN
                                if not is_readonly_query
                                else JobState.FAILED,
                                "claim_owner": None,
                                "lease_expires_at": None,
                                "updated_at": now,
                            }
                        )
                        operation_state = (
                            OperationState.UNKNOWN
                            if not is_readonly_query
                            else OperationState.FAILED
                        )
                    if job.operation_id is not None:
                        if operation_state == OperationState.QUEUED:
                            operation_row = cursor.execute(
                                "SELECT document FROM operations WHERE id=?",
                                (str(job.operation_id),),
                            ).fetchone()
                            if operation_row is not None:
                                operation = Operation.model_validate_json(
                                    str(operation_row["document"])
                                )
                                operation = operation.model_copy(
                                    update={
                                        "authority_invocation_id": None,
                                        "authority_idempotency_key": None,
                                    }
                                )
                                cursor.execute(
                                    "UPDATE operations SET document=? WHERE id=?",
                                    (
                                        operation.model_dump_json(by_alias=True),
                                        str(job.operation_id),
                                    ),
                                )
                        self._update_operation_state(
                            cursor,
                            job.operation_id,
                            operation_state,
                            now,
                            result={
                                "reasonCode": (
                                    "readonly_query_retry_after_crash"
                                    if operation_state == OperationState.QUEUED
                                    else "send_outcome_unknown_after_lease_expiry"
                                    if operation_state == OperationState.UNKNOWN
                                    else "readonly_query_attempts_exhausted"
                                )
                            },
                        )
                        if operation_state in {
                            OperationState.UNKNOWN,
                            OperationState.FAILED,
                        }:
                            self._enqueue_reply_for_operation(
                                cursor,
                                job.operation_id,
                                state=(
                                    JobState.UNKNOWN
                                    if operation_state == OperationState.UNKNOWN
                                    else JobState.FAILED
                                ),
                                evidence={
                                    "reasonCode": (
                                        "send_outcome_unknown_after_lease_expiry"
                                        if operation_state == OperationState.UNKNOWN
                                        else "readonly_query_attempts_exhausted"
                                    )
                                },
                                now=now,
                            )
                self._persist_job(cursor, updated)
                count += 1
            return count

    def retry_readonly_job(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        now: datetime,
        retry_after_seconds: int | None = None,
    ) -> OutboxJob:
        """Retry only an issue query with bounded exponential/provider delay."""

        with self._transaction() as cursor:
            row = cursor.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND state='SENDING' AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("read retry fence is stale")
            job = OutboxJob.model_validate_json(str(row["document"]))
            if (
                job.kind != "ISSUE_ACTION"
                or job.payload.get("operationId") != "integration.issue.query"
            ):
                raise IntegrationAuthorizationError("only issue queries can be retried")
            if job.attempts >= 4:
                updated = job.model_copy(
                    update={
                        "state": JobState.FAILED,
                        "claim_owner": None,
                        "lease_expires_at": None,
                        "updated_at": now,
                    }
                )
                operation_state = OperationState.FAILED
            else:
                exponential = min(30, 2 ** (job.attempts - 1))
                delay = min(60, max(exponential, retry_after_seconds or 0))
                updated = job.model_copy(
                    update={
                        "state": JobState.READY,
                        "authority_invocation_id": None,
                        "authority_idempotency_key": None,
                        "authority_state": None,
                        "available_at": now + timedelta(seconds=delay),
                        "claim_owner": None,
                        "lease_expires_at": None,
                        "updated_at": now,
                    }
                )
                operation_state = OperationState.QUEUED
            self._persist_job(cursor, updated)
            cursor.execute(
                "INSERT INTO job_evidence VALUES(?,?,?)",
                (str(job_id), claim_fence, _json({"reasonCode": "readonly_provider_error"})),
            )
            if job.operation_id is not None:
                if operation_state == OperationState.QUEUED:
                    operation_row = cursor.execute(
                        "SELECT document FROM operations WHERE id=?",
                        (str(job.operation_id),),
                    ).fetchone()
                    if operation_row is not None:
                        operation = Operation.model_validate_json(str(operation_row["document"]))
                        operation = operation.model_copy(
                            update={
                                "authority_invocation_id": None,
                                "authority_idempotency_key": None,
                            }
                        )
                        cursor.execute(
                            "UPDATE operations SET document=? WHERE id=?",
                            (operation.model_dump_json(by_alias=True), str(job.operation_id)),
                        )
                self._update_operation_state(
                    cursor,
                    job.operation_id,
                    operation_state,
                    now,
                    result={"reasonCode": "readonly_provider_error"},
                )
                if operation_state == OperationState.FAILED:
                    self._enqueue_reply_for_operation(
                        cursor,
                        job.operation_id,
                        state=JobState.FAILED,
                        evidence={"reasonCode": "readonly_provider_error"},
                        now=now,
                    )
            return updated

    def save_snapshot(self, snapshot: ResourceSnapshot) -> None:
        """Persist a provider observation, including observation and freshness."""

        with self._transaction() as cursor:
            connection = cursor.execute(
                "SELECT organization_id,workspace_id FROM integration_connections WHERE id=?",
                (str(snapshot.connection_id),),
            ).fetchone()
            if connection is None or (
                connection["organization_id"] != snapshot.organization_id
                or connection["workspace_id"] != snapshot.workspace_id
            ):
                raise IntegrationNotFound("snapshot connection not found in scope")
            cursor.execute(
                "INSERT INTO resource_snapshots VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    str(snapshot.id),
                    snapshot.organization_id,
                    snapshot.workspace_id,
                    snapshot.actor_issuer,
                    snapshot.actor_subject,
                    str(snapshot.connection_id),
                    snapshot.resource_type,
                    snapshot.resource_id,
                    _dt(snapshot.observed_at),
                    snapshot.model_dump_json(by_alias=True),
                ),
            )

    def list_snapshots(
        self,
        principal: IntegrationPrincipal,
        resource_type: str,
        resource_id: str,
    ) -> list[ResourceSnapshot]:
        """Read snapshots only from the caller's organization and workspace."""

        principal.require("integrationGetIssue")
        with self._lock:
            rows = self._connection.execute(
                """SELECT snapshot.document FROM resource_snapshots AS snapshot
                   WHERE snapshot.organization_id=? AND snapshot.workspace_id=?
                   AND snapshot.actor_issuer=? AND snapshot.actor_subject=?
                   AND snapshot.resource_type=? AND snapshot.resource_id=?
                   ORDER BY snapshot.observed_at DESC""",
                (
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                    resource_type,
                    resource_id,
                ),
            ).fetchall()
        return [ResourceSnapshot.model_validate_json(str(row["document"])) for row in rows]

    def add_audit(self, audit: OperationAudit) -> None:
        """Append an audit record without recording secret or message content."""

        with self._transaction() as cursor:
            cursor.execute(
                "INSERT INTO operation_audits VALUES(?,?,?,?,?)",
                (
                    str(audit.id),
                    audit.organization_id,
                    audit.workspace_id,
                    _dt(audit.observed_at),
                    audit.model_dump_json(by_alias=True),
                ),
            )

    def get_claimed_job(self, job_id: UUID, *, claim_fence: int) -> OutboxJob:
        """Read a job only while its supplied current fencing token matches."""

        with self._lock:
            row = self._connection.execute(
                "SELECT document FROM outbox_jobs WHERE id=? AND claim_fence=?",
                (str(job_id), claim_fence),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("claimed job not found")
        return OutboxJob.model_validate_json(str(row["document"]))

    def get_connection_for_job(self, job: OutboxJob) -> IntegrationConnection:
        """Internal worker lookup constrained to the durable job scope."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM integration_connections WHERE id=?
                   AND organization_id=? AND workspace_id=? AND enabled=1""",
                (str(job.connection_id), job.organization_id, job.workspace_id),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("job connection is no longer available")
        return IntegrationConnection.model_validate_json(str(row["document"]))

    def get_binding_for_job(self, job: OutboxJob) -> SyncBinding:
        """Internal worker lookup constrained to the durable job scope."""

        if job.binding_id is None:
            raise IntegrationNotFound("notification job has no binding")
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM sync_bindings WHERE id=? AND connection_id=?
                   AND organization_id=? AND workspace_id=?""",
                (
                    str(job.binding_id),
                    str(job.connection_id),
                    job.organization_id,
                    job.workspace_id,
                ),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("job binding is no longer available")
        return SyncBinding.model_validate_json(str(row["document"]))

    def get_operation_for_job(self, job: OutboxJob) -> Operation:
        """Internal worker lookup constrained to the durable operation link."""

        if job.operation_id is None:
            raise IntegrationNotFound("issue job has no operation")
        with self._lock:
            row = self._connection.execute(
                "SELECT document FROM operations WHERE id=? AND connection_id=? "
                "AND organization_id=? AND workspace_id=?",
                (
                    str(job.operation_id),
                    str(job.connection_id),
                    job.organization_id,
                    job.workspace_id,
                ),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("job operation is no longer available")
        return Operation.model_validate_json(str(row["document"]))

    def claim_authorization_checks(
        self,
        worker_id: str,
        *,
        now: datetime,
        lease_seconds: int = 60,
        limit: int = 25,
    ) -> list[ClaimedAuthorizationMonitor]:
        """Claim due connection checks with a process-safe fencing token."""

        if not worker_id or len(worker_id) > 200 or not 1 <= lease_seconds <= 300:
            raise ValueError("authorization monitor worker or lease is invalid")
        if not 1 <= limit <= 100:
            raise ValueError("authorization monitor batch size is invalid")
        moment = _dt(now)
        lease_expiry = now + timedelta(seconds=lease_seconds)
        with self._transaction() as cursor:
            cursor.execute(
                """INSERT OR IGNORE INTO authorization_monitor_state(connection_id,next_check_at)
                   SELECT id,? FROM integration_connections WHERE enabled=1""",
                (_dt(datetime(1970, 1, 1, tzinfo=UTC)),),
            )
            rows = cursor.execute(
                """SELECT state.connection_id,state.claim_fence,connection.document
                   FROM authorization_monitor_state AS state
                   JOIN integration_connections AS connection
                     ON connection.id=state.connection_id
                   WHERE connection.enabled=1 AND state.next_check_at<=?
                     AND (state.claim_owner IS NULL OR state.lease_expires_at IS NULL
                          OR state.lease_expires_at<=?)
                   ORDER BY state.next_check_at,state.connection_id LIMIT ?""",
                (moment, moment, limit),
            ).fetchall()
            claimed: list[ClaimedAuthorizationMonitor] = []
            for row in rows:
                fence = int(row["claim_fence"]) + 1
                cursor.execute(
                    """UPDATE authorization_monitor_state SET claim_owner=?,claim_fence=?,
                       lease_expires_at=? WHERE connection_id=? AND claim_fence=?
                       AND (claim_owner IS NULL OR lease_expires_at IS NULL
                            OR lease_expires_at<=?)""",
                    (
                        worker_id,
                        fence,
                        _dt(lease_expiry),
                        str(row["connection_id"]),
                        int(row["claim_fence"]),
                        moment,
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                claimed.append(
                    ClaimedAuthorizationMonitor(
                        connection=IntegrationConnection.model_validate_json(str(row["document"])),
                        worker_id=worker_id,
                        claim_fence=fence,
                        lease_expires_at=lease_expiry,
                    )
                )
            return claimed

    def latest_authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection_id: UUID,
        *,
        authorization_operation_id: str = "integrationGetAuthorizationHealth",
    ) -> AuthorizationHealthRecord | None:
        """Read the newest health fact for the caller's exact connection owner."""

        principal.require(authorization_operation_id)
        self._get_connection_scoped(principal, connection_id)
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM authorization_observations WHERE connection_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   ORDER BY checked_at DESC,id DESC LIMIT 1""",
                (str(connection_id), *self._scope(principal)),
            ).fetchone()
        if row is None:
            return None
        return AuthorizationHealthRecord.model_validate_json(str(row["document"]))

    def complete_authorization_check(
        self,
        claim: ClaimedAuthorizationMonitor,
        health: AuthorizationHealthRecord,
        notifications: list[IntegrationNotificationDraft],
        *,
        now: datetime,
        interval_seconds: int = 900,
        email_recipient_ref: str | None = None,
    ) -> list[IntegrationNotification]:
        """Atomically persist health, deduplicated alerts and the next monitor time."""

        if interval_seconds < 60 or interval_seconds > 86_400:
            raise ValueError("authorization monitor interval is invalid")
        connection = claim.connection
        if (
            health.connection_id != connection.id
            or health.organization_id != connection.organization_id
            or health.workspace_id != connection.workspace_id
            or health.actor_issuer != connection.actor_issuer
            or health.actor_subject != connection.actor_subject
        ):
            raise IntegrationAuthorizationError("authorization observation scope does not match")
        saved: list[IntegrationNotification] = []
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT claim_owner,claim_fence,lease_expires_at FROM authorization_monitor_state
                   WHERE connection_id=?""",
                (str(connection.id),),
            ).fetchone()
            if (
                row is None
                or row["claim_owner"] != claim.worker_id
                or int(row["claim_fence"]) != claim.claim_fence
                or row["lease_expires_at"] is None
                or str(row["lease_expires_at"]) <= _dt(now)
            ):
                raise IntegrationConflict("authorization monitor claim is stale or expired")
            stored_connection = cursor.execute(
                """SELECT document FROM integration_connections WHERE id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=? AND enabled=1""",
                (
                    str(connection.id),
                    connection.organization_id,
                    connection.workspace_id,
                    connection.actor_issuer,
                    connection.actor_subject,
                ),
            ).fetchone()
            if stored_connection is None:
                raise IntegrationNotFound("authorization connection is no longer available")
            if any(item.connection_id not in (None, connection.id) for item in notifications):
                raise IntegrationAuthorizationError("authorization alert connection does not match")
            cursor.execute(
                """INSERT INTO authorization_observations(id,organization_id,workspace_id,
                   actor_issuer,actor_subject,connection_id,authorization_ref,checked_at,
                   generation,document) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(health.id),
                    health.organization_id,
                    health.workspace_id,
                    health.actor_issuer,
                    health.actor_subject,
                    str(health.connection_id),
                    health.authorization_ref,
                    _dt(health.checked_at),
                    health.generation,
                    health.model_dump_json(by_alias=True),
                ),
            )
            for draft in notifications:
                event = self._insert_notification(
                    cursor,
                    draft,
                    organization_id=connection.organization_id,
                    workspace_id=connection.workspace_id,
                    actor_issuer=connection.actor_issuer,
                    actor_subject=connection.actor_subject,
                    email_recipient_ref=email_recipient_ref,
                    now=now,
                )
                if event is not None:
                    saved.append(event)
            cursor.execute(
                """UPDATE authorization_monitor_state SET last_checked_at=?,next_check_at=?,
                   claim_owner=NULL,lease_expires_at=NULL WHERE connection_id=?
                   AND claim_owner=? AND claim_fence=?""",
                (
                    _dt(now),
                    _dt(now + timedelta(seconds=interval_seconds)),
                    str(connection.id),
                    claim.worker_id,
                    claim.claim_fence,
                ),
            )
            if cursor.rowcount != 1:
                raise IntegrationConflict("authorization monitor claim changed during commit")
        return saved

    def list_notifications(
        self,
        principal: IntegrationPrincipal,
        *,
        after_sequence: int = 0,
        limit: int = 100,
        authorization_operation_id: str = "integrationListNotifications",
    ) -> list[IntegrationNotification]:
        """List durable events only after the caller's recovered sequence cursor."""

        principal.require(authorization_operation_id)
        if not 0 <= after_sequence <= 9_223_372_036_854_775_000:
            raise IntegrationValidationError("notification sequence is out of range")
        if not 1 <= limit <= 200:
            raise IntegrationValidationError("notification page size is out of range")
        with self._lock:
            rows = self._connection.execute(
                """SELECT document FROM integration_notifications WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=? AND sequence>?
                   ORDER BY sequence LIMIT ?""",
                (*self._scope(principal), after_sequence, limit),
            ).fetchall()
        return [IntegrationNotification.model_validate_json(str(row["document"])) for row in rows]

    def acknowledge_notification(
        self,
        principal: IntegrationPrincipal,
        notification_id: UUID,
        *,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IntegrationNotification:
        """Acknowledge one actor-owned event with replay-safe exact payload binding."""

        principal.require("integrationAcknowledgeNotification")
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        request_hash = hashlib.sha256(
            _json({"notificationId": str(notification_id)}).encode("utf-8")
        ).hexdigest()
        moment = now or utc_now()
        with self._transaction() as cursor:
            previous = self._idempotency_lookup(
                cursor,
                principal=principal,
                operation_name="integrationAcknowledgeNotification",
                key=idempotency_key,
                request_hash=request_hash,
            )
            if previous is not None:
                return IntegrationNotification.model_validate_json(str(previous["document"]))
            row = cursor.execute(
                """SELECT document FROM integration_notifications WHERE id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (str(notification_id), *self._scope(principal)),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("notification not found")
            event = IntegrationNotification.model_validate_json(str(row["document"]))
            if event.acknowledged_at is None:
                event = event.model_copy(update={"acknowledged_at": moment})
                cursor.execute(
                    "UPDATE integration_notifications SET document=? WHERE id=?",
                    (event.model_dump_json(by_alias=True), str(notification_id)),
                )
            self._idempotency_save(
                cursor,
                principal=principal,
                operation_name="integrationAcknowledgeNotification",
                key=idempotency_key,
                request_hash=request_hash,
                resource_id=notification_id,
                document=event.model_dump_json(by_alias=True),
            )
            return event

    def get_renewal_session_for_idempotency(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        *,
        idempotency_key: str,
    ) -> RenewalSessionRecord | None:
        """Return an exact previously started renewal without repeating provider I/O."""

        principal.require("accountBeginRenewalSession")
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        request_hash = hashlib.sha256(
            _json({"authorizationRef": authorization_ref}).encode("utf-8")
        ).hexdigest()
        with self._lock:
            row = self._connection.execute(
                """SELECT request_hash,document FROM idempotency_records WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND operation_id='accountBeginRenewalSession' AND idempotency_key=?""",
                (*self._scope(principal), idempotency_key),
            ).fetchone()
        if row is None:
            return None
        if str(row["request_hash"]) != request_hash:
            raise IntegrationConflict("idempotency key was reused for a different request")
        return RenewalSessionRecord.model_validate_json(str(row["document"]))

    def begin_renewal_session(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        *,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[RenewalSessionRecord, bool]:
        """Commit a stable VERIFYING Product session before provider side effects."""

        principal.require("accountBeginRenewalSession")
        if not authorization_ref or len(authorization_ref) > 300:
            raise IntegrationValidationError("authorization reference is invalid")
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        request_hash = hashlib.sha256(
            _json({"authorizationRef": authorization_ref}).encode("utf-8")
        ).hexdigest()
        previous = self.get_renewal_session_for_idempotency(
            principal, authorization_ref, idempotency_key=idempotency_key
        )
        if previous is not None:
            return previous, False
        moment = now or utc_now()
        session = RenewalSessionRecord(
            session_ref=str(uuid4()),
            authorization_ref=authorization_ref,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            state=RenewalState.VERIFYING,
            created_at=moment,
            generation=0,
            reason_code="provider_start_pending",
        )
        document = session.model_dump_json(by_alias=True)
        with self._transaction() as cursor:
            replay = self._idempotency_lookup(
                cursor,
                principal=principal,
                operation_name="accountBeginRenewalSession",
                key=idempotency_key,
                request_hash=request_hash,
            )
            if replay is not None:
                return RenewalSessionRecord.model_validate_json(str(replay["document"])), False
            cursor.execute(
                "INSERT INTO renewal_sessions VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                    authorization_ref,
                    session.session_ref,
                    session.state.value,
                    _dt(moment),
                    document,
                ),
            )
            cursor.execute(
                "INSERT INTO idempotency_records VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    principal.organization_id,
                    principal.workspace_id,
                    principal.issuer,
                    principal.subject,
                    "accountBeginRenewalSession",
                    idempotency_key,
                    request_hash,
                    session.session_ref,
                    document,
                ),
            )
        return session, True

    def complete_renewal_session_start(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        session_ref: str,
        *,
        provider_session_ref: str,
        state: RenewalState,
        expires_at: datetime | None,
        authorization_url: str | None,
        qr_attachment_ref: str | None,
        generation: int,
    ) -> RenewalSessionRecord:
        """Commit a provider reply to its pre-existing actor-owned start intent."""

        principal.require("accountBeginRenewalSession")
        if not provider_session_ref or len(provider_session_ref) > 300:
            raise IntegrationValidationError("provider renewal session reference is invalid")
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM renewal_sessions WHERE organization_id=? AND workspace_id=?
                   AND actor_issuer=? AND actor_subject=? AND authorization_ref=?
                   AND session_ref=?""",
                (*self._scope(principal), authorization_ref, session_ref),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("renewal start intent not found")
            current = RenewalSessionRecord.model_validate_json(str(row["document"]))
            if current.provider_session_ref not in (None, provider_session_ref):
                raise IntegrationConflict(
                    "renewal session was completed by another provider result"
                )
            updated = current.model_copy(
                update={
                    "provider_session_ref": provider_session_ref,
                    "state": state,
                    "expires_at": expires_at,
                    "authorization_url": authorization_url,
                    "qr_attachment_ref": qr_attachment_ref,
                    "generation": generation,
                    "reason_code": None,
                }
            )
            document = updated.model_dump_json(by_alias=True)
            cursor.execute(
                """UPDATE renewal_sessions SET state=?,document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND authorization_ref=? AND session_ref=?""",
                (state.value, document, *self._scope(principal), authorization_ref, session_ref),
            )
            cursor.execute(
                """UPDATE idempotency_records SET document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND operation_id='accountBeginRenewalSession' AND resource_id=?""",
                (document, *self._scope(principal), session_ref),
            )
            return updated

    def mark_renewal_start_unknown(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        session_ref: str,
        *,
        reason_code: str,
    ) -> RenewalSessionRecord:
        """Record an ambiguous start without replaying its provider side effect."""

        principal.require("accountBeginRenewalSession")
        if not reason_code or len(reason_code) > 200:
            raise IntegrationValidationError("renewal outcome reason is invalid")
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM renewal_sessions WHERE organization_id=? AND workspace_id=?
                   AND actor_issuer=? AND actor_subject=? AND authorization_ref=?
                   AND session_ref=?""",
                (*self._scope(principal), authorization_ref, session_ref),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("renewal start intent not found")
            session = RenewalSessionRecord.model_validate_json(str(row["document"]))
            if session.provider_session_ref is not None:
                return session
            updated = session.model_copy(update={"reason_code": reason_code})
            document = updated.model_dump_json(by_alias=True)
            cursor.execute(
                """UPDATE renewal_sessions SET document=? WHERE organization_id=? AND workspace_id=?
                   AND actor_issuer=? AND actor_subject=? AND authorization_ref=?
                   AND session_ref=?""",
                (document, *self._scope(principal), authorization_ref, session_ref),
            )
            cursor.execute(
                """UPDATE idempotency_records SET document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND operation_id='accountBeginRenewalSession' AND resource_id=?""",
                (document, *self._scope(principal), session_ref),
            )
            return updated

    def update_renewal_session_status(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        session_ref: str,
        *,
        state: RenewalState,
        expires_at: datetime | None,
        authorization_url: str | None,
        qr_attachment_ref: str | None,
        generation: int,
        provider_session_ref: str | None = None,
        reason_code: str | None = None,
    ) -> RenewalSessionRecord:
        """Update a known session only after the provider status tool returns facts."""

        principal.require("accountGetRenewalSession")
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM renewal_sessions WHERE organization_id=? AND workspace_id=?
                   AND actor_issuer=? AND actor_subject=? AND authorization_ref=?
                   AND session_ref=?""",
                (*self._scope(principal), authorization_ref, session_ref),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("renewal session not found")
            session = RenewalSessionRecord.model_validate_json(str(row["document"]))
            if session.provider_session_ref is None and not provider_session_ref:
                raise IntegrationConflict("renewal status has no provider session reference")
            if provider_session_ref is not None and session.provider_session_ref not in (
                None,
                provider_session_ref,
            ):
                raise IntegrationConflict("renewal status returned a different provider session")
            updated = session.model_copy(
                update={
                    "state": state,
                    "provider_session_ref": (provider_session_ref or session.provider_session_ref),
                    "expires_at": expires_at,
                    "authorization_url": authorization_url,
                    "qr_attachment_ref": qr_attachment_ref,
                    "generation": generation,
                    "reason_code": reason_code,
                }
            )
            cursor.execute(
                """UPDATE renewal_sessions SET state=?,document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND authorization_ref=? AND session_ref=?""",
                (
                    state.value,
                    updated.model_dump_json(by_alias=True),
                    *self._scope(principal),
                    authorization_ref,
                    session_ref,
                ),
            )
            cursor.execute(
                """UPDATE idempotency_records SET document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND operation_id='accountBeginRenewalSession' AND resource_id=?""",
                (
                    updated.model_dump_json(by_alias=True),
                    *self._scope(principal),
                    session_ref,
                ),
            )
            return updated

    def mark_renewal_status_unavailable(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        session_ref: str,
        *,
        reason_code: str,
    ) -> RenewalSessionRecord:
        """Keep an unresolved start in VERIFYING when read-only lookup is unavailable."""

        principal.require("accountGetRenewalSession")
        if not reason_code or len(reason_code) > 200:
            raise IntegrationValidationError("renewal status reason is invalid")
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM renewal_sessions WHERE organization_id=? AND workspace_id=?
                   AND actor_issuer=? AND actor_subject=? AND authorization_ref=?
                   AND session_ref=?""",
                (*self._scope(principal), authorization_ref, session_ref),
            ).fetchone()
            if row is None:
                raise IntegrationNotFound("renewal session not found")
            session = RenewalSessionRecord.model_validate_json(str(row["document"]))
            updated = session.model_copy(update={"reason_code": reason_code})
            document = updated.model_dump_json(by_alias=True)
            cursor.execute(
                """UPDATE renewal_sessions SET document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND authorization_ref=? AND session_ref=?""",
                (document, *self._scope(principal), authorization_ref, session_ref),
            )
            cursor.execute(
                """UPDATE idempotency_records SET document=? WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   AND operation_id='accountBeginRenewalSession' AND resource_id=?""",
                (document, *self._scope(principal), session_ref),
            )
            return updated

    def get_renewal_session(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        session_ref: str,
        *,
        authorization_operation_id: str = "accountGetRenewalSession",
    ) -> RenewalSessionRecord:
        """Read a renewal session only for its exact actor and authorization ref."""

        principal.require(authorization_operation_id)
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM renewal_sessions WHERE organization_id=? AND workspace_id=?
                   AND actor_issuer=? AND actor_subject=? AND authorization_ref=?
                   AND session_ref=?""",
                (*self._scope(principal), authorization_ref, session_ref),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("renewal session not found")
        return RenewalSessionRecord.model_validate_json(str(row["document"]))

    def enqueue_cloud_refresh(
        self,
        principal: IntegrationPrincipal,
        connection_id: UUID,
        *,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CloudRefreshOperation:
        """Create one scoped, idempotent read-only refresh operation and outbox row."""

        principal.require("integrationRefreshConnectionResources")
        if not idempotency_key or len(idempotency_key) > 200:
            raise IntegrationValidationError("Idempotency-Key is required")
        connection = self._get_connection_scoped(principal, connection_id)
        if connection.provider not in {"azure", "gcp", "hf", "runpod", "tailscale"}:
            raise IntegrationValidationError("connection does not select a cloud resource provider")
        if not connection.binding_ref or not connection.target_ref:
            raise IntegrationAuthorizationError("cloud connection has no configured target binding")
        request_hash = hashlib.sha256(
            _json({"connectionId": str(connection_id), "targetRef": connection.target_ref}).encode(
                "utf-8"
            )
        ).hexdigest()
        moment = now or utc_now()
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT request_hash,document FROM cloud_refresh_operations
                   WHERE organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=? AND connection_id=?
                   AND idempotency_key=?""",
                (*self._scope(principal), str(connection_id), idempotency_key),
            ).fetchone()
            if row is not None:
                if str(row["request_hash"]) != request_hash:
                    raise IntegrationConflict("Idempotency-Key was reused for a different refresh")
                return CloudRefreshOperation.model_validate_json(str(row["document"]))
            operation = CloudRefreshOperation(
                organization_id=principal.organization_id,
                workspace_id=principal.workspace_id,
                actor_issuer=principal.issuer,
                actor_subject=principal.subject,
                connection_id=connection.id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                created_at=moment,
                updated_at=moment,
            )
            document = operation.model_dump_json(by_alias=True)
            cursor.execute(
                "INSERT INTO cloud_refresh_operations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(operation.id),
                    operation.organization_id,
                    operation.workspace_id,
                    operation.actor_issuer,
                    operation.actor_subject,
                    str(operation.connection_id),
                    operation.idempotency_key,
                    operation.request_hash,
                    operation.state.value,
                    _dt(operation.created_at),
                    _dt(operation.updated_at),
                    document,
                ),
            )
            cursor.execute(
                """INSERT INTO cloud_refresh_outbox(operation_id,state,attempts,claim_fence,
                   available_at,document) VALUES(?,?,?,?,?,?)""",
                (
                    str(operation.id),
                    operation.state.value,
                    0,
                    0,
                    _dt(moment),
                    document,
                ),
            )
        return operation

    def get_cloud_refresh_operation(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        authorization_operation_id: str = "integrationGetOperation",
    ) -> CloudRefreshOperation:
        """Read one cloud refresh Product operation only within its creator scope."""

        principal.require(authorization_operation_id)
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM cloud_refresh_operations WHERE id=? AND organization_id=?
                   AND workspace_id=? AND actor_issuer=? AND actor_subject=?""",
                (str(operation_id), *self._scope(principal)),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("cloud refresh operation not found")
        return CloudRefreshOperation.model_validate_json(str(row["document"]))

    def connection_for_cloud_refresh(self, claim: ClaimedCloudRefresh) -> IntegrationConnection:
        """Resolve a claimed operation to its enabled connection and exact stored owner."""

        operation = claim.operation
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM integration_connections WHERE id=? AND enabled=1
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (
                    str(operation.connection_id),
                    operation.organization_id,
                    operation.workspace_id,
                    operation.actor_issuer,
                    operation.actor_subject,
                ),
            ).fetchone()
        if row is None:
            raise IntegrationNotFound("cloud refresh connection is no longer available")
        return IntegrationConnection.model_validate_json(str(row["document"]))

    def latest_authorization_health_for_connection(
        self, connection: IntegrationConnection
    ) -> AuthorizationHealthRecord | None:
        """Load current health from the exact persisted connection scope."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM authorization_observations WHERE connection_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   ORDER BY checked_at DESC,id DESC LIMIT 1""",
                (
                    str(connection.id),
                    connection.organization_id,
                    connection.workspace_id,
                    connection.actor_issuer,
                    connection.actor_subject,
                ),
            ).fetchone()
        if row is None:
            return None
        return AuthorizationHealthRecord.model_validate_json(str(row["document"]))

    def connection_for_authorization(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        *,
        provider: str = "wecom",
        authorization_operation_id: str,
    ) -> IntegrationConnection:
        """Resolve an authorization only through the caller's stored connection ref."""

        principal.require(authorization_operation_id)
        with self._lock:
            rows = self._connection.execute(
                """SELECT connection.document AS connection_document,
                          observation.document AS observation_document
                   FROM integration_connections AS connection
                   JOIN authorization_observations AS observation
                     ON observation.connection_id=connection.id
                   WHERE observation.authorization_ref=? AND connection.enabled=1
                     AND connection.organization_id=?
                     AND connection.workspace_id=? AND connection.actor_issuer=?
                     AND connection.actor_subject=?
                     AND observation.id=(SELECT latest.id
                       FROM authorization_observations AS latest
                       WHERE latest.connection_id=connection.id
                       ORDER BY latest.checked_at DESC,latest.id DESC LIMIT 1)
                   ORDER BY connection.id""",
                (authorization_ref, *self._scope(principal)),
            ).fetchall()
        selected: list[tuple[IntegrationConnection, AuthorizationHealthRecord]] = []
        for row in rows:
            connection = IntegrationConnection.model_validate_json(str(row["connection_document"]))
            health = AuthorizationHealthRecord.model_validate_json(str(row["observation_document"]))
            if connection.provider == provider and health.authorization_ref == authorization_ref:
                selected.append((connection, health))
        if not selected:
            raise IntegrationNotFound("authorization is not attached to this actor's connection")
        if len(selected) != 1:
            raise IntegrationConflict("authorization reference matches multiple provider bindings")
        return selected[0][0]

    def latest_authorization_health_for_monitor(
        self, claim: ClaimedAuthorizationMonitor
    ) -> AuthorizationHealthRecord | None:
        """Load one monitor's prior result from its already fenced connection scope."""

        connection = claim.connection
        with self._lock:
            row = self._connection.execute(
                """SELECT document FROM authorization_observations WHERE connection_id=?
                   AND organization_id=? AND workspace_id=? AND actor_issuer=? AND actor_subject=?
                   ORDER BY checked_at DESC,id DESC LIMIT 1""",
                (
                    str(connection.id),
                    connection.organization_id,
                    connection.workspace_id,
                    connection.actor_issuer,
                    connection.actor_subject,
                ),
            ).fetchone()
        if row is None:
            return None
        return AuthorizationHealthRecord.model_validate_json(str(row["document"]))

    def latest_notification_for_monitor(
        self,
        claim: ClaimedAuthorizationMonitor,
        *,
        incident_key: str,
        stage_prefix: str | None = None,
    ) -> IntegrationNotification | None:
        """Read the newest notification for a monitor incident and optional stage."""

        connection = claim.connection
        with self._lock:
            if stage_prefix is None:
                row = self._connection.execute(
                    """SELECT document FROM integration_notifications WHERE organization_id=?
                       AND workspace_id=? AND actor_issuer=? AND actor_subject=? AND incident_key=?
                       ORDER BY sequence DESC LIMIT 1""",
                    (
                        connection.organization_id,
                        connection.workspace_id,
                        connection.actor_issuer,
                        connection.actor_subject,
                        incident_key,
                    ),
                ).fetchone()
            else:
                row = self._connection.execute(
                    """SELECT document FROM integration_notifications WHERE organization_id=?
                       AND workspace_id=? AND actor_issuer=? AND actor_subject=? AND incident_key=?
                       AND (stage=? OR stage LIKE ?) ORDER BY sequence DESC LIMIT 1""",
                    (
                        connection.organization_id,
                        connection.workspace_id,
                        connection.actor_issuer,
                        connection.actor_subject,
                        incident_key,
                        stage_prefix,
                        f"{stage_prefix}-reminder-%",
                    ),
                ).fetchone()
        if row is None:
            return None
        return IntegrationNotification.model_validate_json(str(row["document"]))

    def release_authorization_check(
        self,
        claim: ClaimedAuthorizationMonitor,
        *,
        now: datetime,
        retry_delay_seconds: int = 300,
    ) -> None:
        """Release a skipped check without recording false provider evidence."""

        if not 1 <= retry_delay_seconds <= 86_400:
            raise ValueError("authorization monitor retry delay is invalid")
        with self._transaction() as cursor:
            cursor.execute(
                """UPDATE authorization_monitor_state SET next_check_at=?,claim_owner=NULL,
                   lease_expires_at=NULL WHERE connection_id=? AND claim_owner=?
                   AND claim_fence=?""",
                (
                    _dt(now + timedelta(seconds=retry_delay_seconds)),
                    str(claim.connection.id),
                    claim.worker_id,
                    claim.claim_fence,
                ),
            )
            if cursor.rowcount != 1:
                raise IntegrationConflict("authorization monitor claim is stale")

    def release_cloud_refresh_claim(
        self,
        claim: ClaimedCloudRefresh,
        *,
        now: datetime,
        retry_delay_seconds: int = 60,
    ) -> CloudRefreshOperation:
        """Return a queued read job for later authorization without provider I/O."""

        if not 1 <= retry_delay_seconds <= 86_400:
            raise ValueError("cloud refresh retry delay is invalid")
        operation = claim.operation.model_copy(
            update={"state": CloudRefreshState.QUEUED, "updated_at": now}
        )
        document = operation.model_dump_json(by_alias=True)
        with self._transaction() as cursor:
            cursor.execute(
                """UPDATE cloud_refresh_outbox SET state='QUEUED',claim_owner=NULL,
                   lease_expires_at=NULL,available_at=?,document=? WHERE operation_id=?
                   AND claim_owner=? AND claim_fence=?""",
                (
                    _dt(now + timedelta(seconds=retry_delay_seconds)),
                    document,
                    str(operation.id),
                    claim.worker_id,
                    claim.claim_fence,
                ),
            )
            if cursor.rowcount != 1:
                raise IntegrationConflict("cloud refresh claim is stale")
            cursor.execute(
                "UPDATE cloud_refresh_operations SET state=?,updated_at=?,document=? WHERE id=?",
                (operation.state.value, _dt(now), document, str(operation.id)),
            )
        return operation

    def claim_cloud_refresh(
        self,
        worker_id: str,
        *,
        now: datetime,
        lease_seconds: int = 60,
    ) -> ClaimedCloudRefresh | None:
        """Claim a read-only provider query with a monotonic cross-process fence."""

        if not worker_id or len(worker_id) > 200 or not 1 <= lease_seconds <= 300:
            raise ValueError("cloud worker or lease is invalid")
        lease_expiry = now + timedelta(seconds=lease_seconds)
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT operation_id,claim_fence,document FROM cloud_refresh_outbox
                   WHERE state IN ('QUEUED','RUNNING') AND available_at<=?
                     AND (claim_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at<=?)
                   ORDER BY available_at,operation_id LIMIT 1""",
                (_dt(now), _dt(now)),
            ).fetchone()
            if row is None:
                return None
            current = CloudRefreshOperation.model_validate_json(str(row["document"]))
            fence = int(row["claim_fence"]) + 1
            running = current.model_copy(
                update={"state": CloudRefreshState.RUNNING, "updated_at": now}
            )
            cursor.execute(
                """UPDATE cloud_refresh_outbox SET state='RUNNING',attempts=attempts+1,
                   claim_owner=?,claim_fence=?,lease_expires_at=?,document=?
                   WHERE operation_id=? AND claim_fence=?
                      AND (claim_owner IS NULL OR lease_expires_at IS NULL
                           OR lease_expires_at<=?)""",
                (
                    worker_id,
                    fence,
                    _dt(lease_expiry),
                    running.model_dump_json(by_alias=True),
                    str(current.id),
                    int(row["claim_fence"]),
                    _dt(now),
                ),
            )
            if cursor.rowcount != 1:
                return None
            cursor.execute(
                "UPDATE cloud_refresh_operations SET state=?,updated_at=?,document=? WHERE id=?",
                (
                    running.state.value,
                    _dt(now),
                    running.model_dump_json(by_alias=True),
                    str(running.id),
                ),
            )
            return ClaimedCloudRefresh(
                operation=running,
                worker_id=worker_id,
                claim_fence=fence,
                lease_expires_at=lease_expiry,
            )

    def complete_cloud_refresh(
        self,
        claim: ClaimedCloudRefresh,
        observations: list[CloudResourceRecord],
        *,
        state: CloudRefreshState,
        now: datetime,
        result: dict[str, str | int | bool | None] | None = None,
        email_recipient_ref: str | None = None,
    ) -> tuple[CloudRefreshOperation, list[IntegrationNotification]]:
        """Commit one read result, transition alerts and the operation under its fence."""

        if state not in {
            CloudRefreshState.SUCCEEDED,
            CloudRefreshState.FAILED,
            CloudRefreshState.UNKNOWN,
        }:
            raise IntegrationValidationError("cloud refresh completion state is invalid")
        if state != CloudRefreshState.SUCCEEDED and observations:
            raise IntegrationValidationError("failed cloud refresh cannot replace observations")
        operation = claim.operation
        saved_notifications: list[IntegrationNotification] = []
        with self._transaction() as cursor:
            outbox = cursor.execute(
                """SELECT claim_owner,claim_fence,lease_expires_at FROM cloud_refresh_outbox
                   WHERE operation_id=?""",
                (str(operation.id),),
            ).fetchone()
            if (
                outbox is None
                or outbox["claim_owner"] != claim.worker_id
                or int(outbox["claim_fence"]) != claim.claim_fence
                or outbox["lease_expires_at"] is None
                or str(outbox["lease_expires_at"]) <= _dt(now)
            ):
                raise IntegrationConflict("cloud refresh claim is stale or expired")
            connection_row = cursor.execute(
                """SELECT document FROM integration_connections WHERE id=? AND enabled=1
                   AND organization_id=? AND workspace_id=? AND actor_issuer=?
                   AND actor_subject=?""",
                (
                    str(operation.connection_id),
                    operation.organization_id,
                    operation.workspace_id,
                    operation.actor_issuer,
                    operation.actor_subject,
                ),
            ).fetchone()
            if connection_row is None:
                raise IntegrationNotFound("cloud connection is no longer available")
            connection = IntegrationConnection.model_validate_json(str(connection_row["document"]))
            for observation in observations:
                if (
                    observation.connection_id != connection.id
                    or observation.organization_id != connection.organization_id
                    or observation.workspace_id != connection.workspace_id
                    or observation.actor_issuer != connection.actor_issuer
                    or observation.actor_subject != connection.actor_subject
                    or observation.provider != connection.provider
                    or observation.source != connection.provider
                ):
                    raise IntegrationAuthorizationError("cloud observation scope does not match")
                prior_row = cursor.execute(
                    """SELECT document FROM cloud_resource_observations WHERE connection_id=?
                       AND external_ref=? ORDER BY collected_at DESC,id DESC LIMIT 1""",
                    (str(connection.id), observation.external_ref),
                ).fetchone()
                prior = (
                    CloudResourceRecord.model_validate_json(str(prior_row["document"]))
                    if prior_row is not None
                    else None
                )
                cursor.execute(
                    "INSERT INTO cloud_resource_observations VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        str(observation.id),
                        observation.organization_id,
                        observation.workspace_id,
                        observation.actor_issuer,
                        observation.actor_subject,
                        str(observation.connection_id),
                        observation.external_ref,
                        _dt(observation.collected_at),
                        observation.model_dump_json(by_alias=True),
                    ),
                )
                if prior is not None and self._cloud_fingerprint(prior) != self._cloud_fingerprint(
                    observation
                ):
                    before = self._cloud_fingerprint(prior)
                    after = self._cloud_fingerprint(observation)
                    external_ref_hash = hashlib.sha256(
                        observation.external_ref.encode("utf-8")
                    ).hexdigest()
                    severity = (
                        NotificationSeverity.WARNING
                        if observation.status.value in {"STOPPED", "UNAVAILABLE", "DEGRADED"}
                        else NotificationSeverity.INFO
                    )
                    event = self._insert_notification(
                        cursor,
                        IntegrationNotificationDraft(
                            connection_id=connection.id,
                            kind=IntegrationNotificationKind.CLOUD_RESOURCE_CHANGED,
                            severity=severity,
                            title=f"Cloud resource changed: {observation.display_name}"[:200],
                            description=(
                                f"Observed status changed from {prior.status.value} to "
                                f"{observation.status.value}."
                            ),
                            action_ref=f"/api/v1/integrations/connections/{connection.id}/resources",
                            dedupe_key=(
                                f"cloud-change:{connection.id}:{external_ref_hash}:"
                                f"{hashlib.sha256(before.encode()).hexdigest()}:"
                                f"{hashlib.sha256(after.encode()).hexdigest()}"
                            ),
                            incident_key=f"cloud-resource:{connection.id}:{observation.external_ref}",
                            stage=hashlib.sha256(after.encode()).hexdigest()[:24],
                        ),
                        organization_id=connection.organization_id,
                        workspace_id=connection.workspace_id,
                        actor_issuer=connection.actor_issuer,
                        actor_subject=connection.actor_subject,
                        email_recipient_ref=email_recipient_ref,
                        now=now,
                    )
                    if event is not None:
                        saved_notifications.append(event)
            updated = operation.model_copy(
                update={"state": state, "updated_at": now, "result": result}
            )
            document = updated.model_dump_json(by_alias=True)
            cursor.execute(
                """UPDATE cloud_refresh_outbox SET state=?,claim_owner=NULL,lease_expires_at=NULL,
                   document=? WHERE operation_id=? AND claim_owner=? AND claim_fence=?""",
                (state.value, document, str(operation.id), claim.worker_id, claim.claim_fence),
            )
            if cursor.rowcount != 1:
                raise IntegrationConflict("cloud refresh claim changed during commit")
            cursor.execute(
                "UPDATE cloud_refresh_operations SET state=?,updated_at=?,document=? WHERE id=?",
                (state.value, _dt(now), document, str(operation.id)),
            )
        return updated, saved_notifications

    def list_connection_resources(
        self,
        principal: IntegrationPrincipal,
        connection_id: UUID,
        *,
        now: datetime | None = None,
    ) -> list[CloudResourceRecord]:
        """Read the newest provider observations for the exact actor-owned connection."""

        principal.require("integrationListConnectionResources")
        connection = self._get_connection_scoped(principal, connection_id)
        moment = now or utc_now()
        with self._lock:
            rows = self._connection.execute(
                """SELECT observation.document FROM cloud_resource_observations AS observation
                   WHERE observation.organization_id=? AND observation.workspace_id=?
                     AND observation.actor_issuer=? AND observation.actor_subject=?
                     AND observation.connection_id=?
                     AND observation.collected_at=(SELECT MAX(latest.collected_at)
                       FROM cloud_resource_observations AS latest
                       WHERE latest.connection_id=observation.connection_id
                         AND latest.external_ref=observation.external_ref)
                   ORDER BY observation.external_ref""",
                (*self._scope(principal), str(connection_id)),
            ).fetchall()
        if connection.provider not in {"azure", "gcp", "hf", "runpod", "tailscale"}:
            raise IntegrationValidationError("connection does not select a cloud resource provider")
        resources: list[CloudResourceRecord] = []
        for row in rows:
            record = CloudResourceRecord.model_validate_json(str(row["document"]))
            age = (moment - record.collected_at).total_seconds()
            freshness = (
                SnapshotFreshness.FRESH
                if 0 <= age <= 900
                else SnapshotFreshness.STALE
                if age > 900
                else SnapshotFreshness.UNKNOWN
            )
            resources.append(record.model_copy(update={"freshness": freshness}))
        return resources

    @staticmethod
    def _cloud_fingerprint(observation: CloudResourceRecord) -> str:
        """Compare only provider state and bounded metadata, not collection time."""

        fields = {
            "kind": observation.kind,
            "displayName": observation.display_name,
            "status": observation.status.value,
            "providerStatus": observation.provider_status,
            "attributes": observation.attributes,
            "platformResourceRef": observation.platform_resource_ref,
            "platformGeneration": observation.platform_generation,
        }
        return _json(fields)

    def _insert_notification(
        self,
        cursor: sqlite3.Cursor,
        draft: IntegrationNotificationDraft,
        *,
        organization_id: str,
        workspace_id: str,
        actor_issuer: str,
        actor_subject: str,
        email_recipient_ref: str | None,
        now: datetime,
    ) -> IntegrationNotification | None:
        """Insert one sequence event once and queue independent email atomically."""

        duplicate = cursor.execute(
            """SELECT document FROM integration_notifications WHERE organization_id=?
               AND workspace_id=? AND actor_issuer=? AND actor_subject=? AND dedupe_key=?""",
            (organization_id, workspace_id, actor_issuer, actor_subject, draft.dedupe_key),
        ).fetchone()
        if duplicate is not None:
            return None
        notification_id = uuid4()
        cursor.execute(
            """INSERT INTO integration_notifications(id,organization_id,workspace_id,
               actor_issuer,actor_subject,connection_id,kind,severity,dedupe_key,incident_key,
               stage,created_at,document) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(notification_id),
                organization_id,
                workspace_id,
                actor_issuer,
                actor_subject,
                str(draft.connection_id) if draft.connection_id else None,
                draft.kind.value,
                draft.severity.value,
                draft.dedupe_key,
                draft.incident_key,
                draft.stage,
                _dt(now),
                "",
            ),
        )
        if cursor.lastrowid is None:
            raise IntegrationConflict("notification sequence was not assigned")
        sequence = int(cursor.lastrowid)
        event = IntegrationNotification(
            id=notification_id,
            sequence=sequence,
            organization_id=organization_id,
            workspace_id=workspace_id,
            actor_issuer=actor_issuer,
            actor_subject=actor_subject,
            connection_id=draft.connection_id,
            kind=draft.kind,
            severity=draft.severity,
            title=draft.title,
            description=draft.description,
            created_at=now,
            action_ref=draft.action_ref,
            incident_key=draft.incident_key,
            stage=draft.stage,
        )
        document = event.model_dump_json(by_alias=True)
        cursor.execute(
            "UPDATE integration_notifications SET document=? WHERE sequence=?",
            (document, sequence),
        )
        if email_recipient_ref:
            email_job = EmailNotificationJob(
                notification_id=event.id,
                organization_id=organization_id,
                workspace_id=workspace_id,
                actor_issuer=actor_issuer,
                actor_subject=actor_subject,
                connection_id=draft.connection_id,
                recipient_ref=email_recipient_ref,
                subject=event.title[:200],
                text=(event.title + ("\n\n" + event.description if event.description else ""))[
                    :4000
                ],
                request_ref=f"notification:{event.id}",
                available_at=now,
                created_at=now,
                updated_at=now,
            )
            cursor.execute(
                """INSERT INTO email_notification_outbox(id,notification_id,organization_id,
                   workspace_id,actor_issuer,actor_subject,connection_id,state,attempts,
                   available_at,claim_fence,created_at,updated_at,document)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(email_job.id),
                    str(event.id),
                    organization_id,
                    workspace_id,
                    actor_issuer,
                    actor_subject,
                    str(draft.connection_id) if draft.connection_id else None,
                    email_job.state.value,
                    email_job.attempts,
                    _dt(email_job.available_at),
                    email_job.claim_fence,
                    _dt(now),
                    _dt(now),
                    email_job.model_dump_json(by_alias=True),
                ),
            )
        return event

    def claim_email_notification(
        self,
        worker_id: str,
        *,
        now: datetime,
        lease_seconds: int = 60,
    ) -> ClaimedEmailNotification | None:
        """Claim only READY email jobs; expired SENDING jobs become UNKNOWN."""

        if not worker_id or len(worker_id) > 200 or not 1 <= lease_seconds <= 300:
            raise ValueError("email worker or lease is invalid")
        lease_expiry = now + timedelta(seconds=lease_seconds)
        with self._transaction() as cursor:
            expired_claims = cursor.execute(
                """SELECT id,document FROM email_notification_outbox
                   WHERE state='CLAIMED' AND lease_expires_at<=?""",
                (_dt(now),),
            ).fetchall()
            for row in expired_claims:
                job = EmailNotificationJob.model_validate_json(str(row["document"]))
                ready = job.model_copy(
                    update={
                        "state": EmailOutboxState.READY,
                        "claim_owner": None,
                        "lease_expires_at": None,
                        "updated_at": now,
                    }
                )
                self._persist_email_job(cursor, ready)
            expired_sends = cursor.execute(
                """SELECT id,document FROM email_notification_outbox
                   WHERE state='SENDING' AND lease_expires_at<=?""",
                (_dt(now),),
            ).fetchall()
            for row in expired_sends:
                job = EmailNotificationJob.model_validate_json(str(row["document"]))
                unknown = job.model_copy(
                    update={
                        "state": EmailOutboxState.UNKNOWN,
                        "claim_owner": None,
                        "lease_expires_at": None,
                        "failure_reason_code": "send_result_unknown",
                        "updated_at": now,
                    }
                )
                self._persist_email_job(cursor, unknown)
            row = cursor.execute(
                """SELECT document FROM email_notification_outbox WHERE state='READY'
                   AND available_at<=? ORDER BY available_at,created_at,id LIMIT 1""",
                (_dt(now),),
            ).fetchone()
            if row is None:
                return None
            job = EmailNotificationJob.model_validate_json(str(row["document"]))
            fence = job.claim_fence + 1
            claimed = job.model_copy(
                update={
                    "state": EmailOutboxState.CLAIMED,
                    "claim_owner": worker_id,
                    "claim_fence": fence,
                    "lease_expires_at": lease_expiry,
                    "updated_at": now,
                }
            )
            self._persist_email_job(cursor, claimed)
            return ClaimedEmailNotification(job=claimed, claim_fence=fence)

    def release_email_claim(
        self,
        claim: ClaimedEmailNotification,
        *,
        now: datetime,
        retry_delay_seconds: int = 300,
    ) -> EmailNotificationJob:
        """Release a claimed email job when current authorization is unavailable."""

        if not 1 <= retry_delay_seconds <= 86_400:
            raise ValueError("email retry delay is invalid")
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM email_notification_outbox WHERE id=? AND state='CLAIMED'
                   AND claim_fence=?""",
                (str(claim.job.id), claim.claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("email claim is stale")
            job = EmailNotificationJob.model_validate_json(str(row["document"]))
            ready = job.model_copy(
                update={
                    "state": EmailOutboxState.READY,
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "available_at": now + timedelta(seconds=retry_delay_seconds),
                    "updated_at": now,
                }
            )
            self._persist_email_job(cursor, ready)
            return ready

    def mark_email_sending(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        now: datetime,
    ) -> EmailNotificationJob:
        """Persist SENDING before a network call so restarts never resend it."""

        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM email_notification_outbox WHERE id=? AND state='CLAIMED'
                   AND claim_fence=? AND lease_expires_at>?""",
                (str(job_id), claim_fence, _dt(now)),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("email claim is stale or expired")
            job = EmailNotificationJob.model_validate_json(str(row["document"]))
            sending = job.model_copy(
                update={
                    "state": EmailOutboxState.SENDING,
                    "attempts": job.attempts + 1,
                    "updated_at": now,
                }
            )
            self._persist_email_job(cursor, sending)
            return sending

    def finish_email_notification(
        self,
        job_id: UUID,
        *,
        claim_fence: int,
        status: str,
        vendor_receipt_ref: str | None,
        delivery_confirmed: bool,
        now: datetime,
    ) -> EmailNotificationJob:
        """Record provider evidence and a feed event for a confirmed send failure."""

        if status not in {"ACCEPTED", "UNKNOWN", "REJECTED"}:
            raise IntegrationValidationError("email provider status is invalid")
        if delivery_confirmed and status != "ACCEPTED":
            raise IntegrationValidationError("delivery confirmation requires accepted status")
        state = EmailOutboxState(status)
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT document FROM email_notification_outbox WHERE id=? AND state='SENDING'
                   AND claim_fence=?""",
                (str(job_id), claim_fence),
            ).fetchone()
            if row is None:
                raise IntegrationConflict("email send claim is stale")
            job = EmailNotificationJob.model_validate_json(str(row["document"]))
            updated = job.model_copy(
                update={
                    "state": state,
                    "claim_owner": None,
                    "lease_expires_at": None,
                    "vendor_receipt_ref": vendor_receipt_ref,
                    "delivery_confirmed": delivery_confirmed,
                    "failure_reason_code": None
                    if status == "ACCEPTED"
                    else ("send_result_unknown" if status == "UNKNOWN" else "provider_rejected"),
                    "updated_at": now,
                }
            )
            self._persist_email_job(cursor, updated)
            if status != "ACCEPTED":
                self._insert_notification(
                    cursor,
                    IntegrationNotificationDraft(
                        connection_id=job.connection_id,
                        kind=IntegrationNotificationKind.DELIVERY_FAILED,
                        severity=NotificationSeverity.ERROR,
                        title="Email notification delivery needs attention",
                        description=(
                            "The configured email sender rejected the notification."
                            if status == "REJECTED"
                            else "The configured email sender outcome could not be confirmed."
                        ),
                        dedupe_key=f"email-delivery:{job.id}:{status.lower()}",
                        incident_key=f"email-delivery:{job.id}",
                        stage=status.lower(),
                    ),
                    organization_id=job.organization_id,
                    workspace_id=job.workspace_id,
                    actor_issuer=job.actor_issuer,
                    actor_subject=job.actor_subject,
                    email_recipient_ref=None,
                    now=now,
                )
            return updated

    @staticmethod
    def _persist_email_job(cursor: sqlite3.Cursor, job: EmailNotificationJob) -> None:
        """Update all indexed email state and its typed durable document together."""

        cursor.execute(
            """UPDATE email_notification_outbox SET state=?,attempts=?,available_at=?,claim_owner=?,
               claim_fence=?,lease_expires_at=?,updated_at=?,document=? WHERE id=?""",
            (
                job.state.value,
                job.attempts,
                _dt(job.available_at),
                job.claim_owner,
                job.claim_fence,
                _dt(job.lease_expires_at) if job.lease_expires_at else None,
                _dt(job.updated_at),
                job.model_dump_json(by_alias=True),
                str(job.id),
            ),
        )
