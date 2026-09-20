"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 store.py                                                        │
│  Module: cyrene_exchange_product.store                              │
│  Role: SQLite endpoint/route authority and idempotency ledger.       │
│                                                                     │
│  模块职责：持久化网关端点、路由与幂等账本。                                │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from uuid import UUID

from cyrene_exchange.capabilities import ProviderUsage
from cyrene_exchange.gateway import (
    RequestMetadata,
    RequestPrincipal,
)

from cyrene_exchange_product.domain import (
    GatewayEndpoint,
    GatewayRoute,
    ProductPrincipal,
    RequestAuditRecord,
    RequestAuditStatus,
    RouteState,
    TenantQuota,
    UsageState,
)
from cyrene_exchange_product.errors import ExchangeProductError


class ExchangeStore:
    """Durable route authority independent of gateway process state. | 持久化路由权威。"""

    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS gateway_endpoints (
                    id TEXT PRIMARY KEY,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_routes (
                    id TEXT PRIMARY KEY,
                    endpoint_id TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    document TEXT NOT NULL,
                    FOREIGN KEY(endpoint_id) REFERENCES gateway_endpoints(id)
                );
                CREATE INDEX IF NOT EXISTS ix_gateway_routes_endpoint
                    ON gateway_routes(endpoint_id, priority, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    scope TEXT NOT NULL,
                    key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    PRIMARY KEY(scope, key)
                );
                CREATE TABLE IF NOT EXISTS api_credentials (
                    credential_ref TEXT PRIMARY KEY,
                    token_digest TEXT NOT NULL UNIQUE,
                    actor_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_quotas (
                    tenant_id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    monthly_token_quota INTEGER NOT NULL CHECK(monthly_token_quota > 0),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS request_audits (
                    request_id TEXT PRIMARY KEY,
                    route_id TEXT,
                    binding_id TEXT,
                    model TEXT,
                    stream INTEGER CHECK(stream IN (0, 1) OR stream IS NULL),
                    actor_id TEXT,
                    workspace_id TEXT,
                    credential_ref TEXT,
                    status TEXT NOT NULL CHECK(
                        status IN ('started', 'completed', 'failed', 'cancelled', 'rejected')
                    ),
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER,
                    usage_state TEXT NOT NULL CHECK(usage_state IN ('unknown', 'partial', 'final')),
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    total_tokens INTEGER,
                    usage_source TEXT,
                    error_type TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_request_audits_workspace_started
                    ON request_audits(workspace_id, started_at DESC, request_id);
                """
            )

    def close(self) -> None:
        """Close the database connection. | 关闭数据库连接。"""

        with self._lock:
            self._connection.close()

    def save_endpoint(self, endpoint: GatewayEndpoint) -> None:
        """Upsert a GatewayEndpoint. | 写入 GatewayEndpoint。"""

        document = endpoint.model_dump_json(by_alias=True, exclude_none=True)
        with self._mutation() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO gateway_endpoints(id, document) VALUES (?, ?)",
                (str(endpoint.id), document),
            )

    def get_endpoint(self, endpoint_id: UUID) -> GatewayEndpoint | None:
        """Read a GatewayEndpoint. | 读取 GatewayEndpoint。"""

        with self._lock:
            row = self._connection.execute(
                "SELECT document FROM gateway_endpoints WHERE id = ?", (str(endpoint_id),)
            ).fetchone()
        return GatewayEndpoint.model_validate_json(row["document"]) if row else None

    def save_route(self, route: GatewayRoute) -> None:
        """Upsert a GatewayRoute. | 写入 GatewayRoute。"""

        document = route.model_dump_json(by_alias=True, exclude_none=True)
        with self._mutation() as cursor:
            cursor.execute(
                """
                INSERT OR REPLACE INTO gateway_routes(id, endpoint_id, priority, state, document)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(route.id), str(route.endpoint_id), route.priority, route.state, document),
            )

    def get_route(self, route_id: UUID) -> GatewayRoute | None:
        """Read a GatewayRoute. | 读取 GatewayRoute。"""

        with self._lock:
            row = self._connection.execute(
                "SELECT document FROM gateway_routes WHERE id = ?", (str(route_id),)
            ).fetchone()
        return GatewayRoute.model_validate_json(row["document"]) if row else None

    def create_route_draft(self, route: GatewayRoute, key: str, digest: str) -> GatewayRoute:
        """Atomically retain the draft and Send to retry identity. | 原子保存草稿与幂等身份。"""
        with self._mutation() as cursor:
            replay = self.resolve_idempotency("create-route-draft", key, digest)
            if replay is not None:
                existing = self.get_route(UUID(replay))
                if existing is None:
                    raise RuntimeError("draft idempotency points to an absent route")
                return existing
            cursor.execute(
                "INSERT INTO gateway_routes(id, endpoint_id, priority, state, document) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    str(route.id),
                    str(route.endpoint_id),
                    route.priority,
                    route.state,
                    route.model_dump_json(exclude_none=True),
                ),
            )
            cursor.execute(
                "INSERT INTO idempotency(scope, key, request_hash, resource_id) "
                "VALUES ('create-route-draft', ?, ?, ?)",
                (key, digest, str(route.id)),
            )
        return route

    def replace_route_version(self, route: GatewayRoute, expected: int) -> GatewayRoute:
        """Commit a mutation only if the inspected draft still matches. | 版本一致时更新。"""
        with self._mutation() as cursor:
            current = self.get_route(route.id)
            if current is None or current.resource_version != expected:
                raise ExchangeProductError(
                    code="EXCHANGE_ROUTE_VERSION_CONFLICT",
                    title="Route changed",
                    detail="Refresh the route before editing or confirming it.",
                    status=409,
                )
            cursor.execute(
                "UPDATE gateway_routes SET priority=?, state=?, document=? WHERE id=?",
                (
                    route.priority,
                    route.state,
                    route.model_dump_json(exclude_none=True),
                    str(route.id),
                ),
            )
        return route

    def active_routes(self, endpoint_id: UUID) -> list[GatewayRoute]:
        """Return active routes in stable priority order. | 按稳定优先级返回活动路由。"""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT document FROM gateway_routes
                WHERE endpoint_id = ? AND state = ?
                ORDER BY priority ASC, id ASC
                """,
                (str(endpoint_id), RouteState.ACTIVE.value),
            ).fetchall()
        return [GatewayRoute.model_validate_json(row["document"]) for row in rows]

    def list_endpoints(self) -> list[GatewayEndpoint]:
        """Return every persisted gateway endpoint. | 返回全部网关端点。"""

        with self._lock:
            rows = self._connection.execute(
                "SELECT document FROM gateway_endpoints ORDER BY id ASC"
            ).fetchall()
        return [GatewayEndpoint.model_validate_json(row["document"]) for row in rows]

    def list_active_routes(self) -> list[GatewayRoute]:
        """Return every active route across endpoints. | 返回全部活动路由。"""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT document FROM gateway_routes
                WHERE state = ?
                ORDER BY priority ASC, id ASC
                """,
                (RouteState.ACTIVE.value,),
            ).fetchall()
        return [GatewayRoute.model_validate_json(row["document"]) for row in rows]

    def resolve_idempotency(self, scope: str, key: str | None, digest: str) -> str | None:
        """Resolve replay or reject conflicting key reuse. | 解析幂等重放。"""

        if key is None:
            return None
        with self._lock:
            row = self._connection.execute(
                "SELECT request_hash, resource_id FROM idempotency WHERE scope = ? AND key = ?",
                (scope, key),
            ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != digest:
            raise ExchangeProductError(
                code="EXCHANGE_IDEMPOTENCY_CONFLICT",
                title="Idempotency key conflict",
                detail="The Idempotency-Key was already used with a different request body.",
                status=409,
            )
        return str(row["resource_id"])

    def remember_idempotency(
        self, *, scope: str, key: str | None, digest: str, resource_id: UUID
    ) -> None:
        """Persist a successful request mapping. | 持久化成功请求映射。"""

        if key is None:
            return
        with self._mutation() as cursor:
            cursor.execute(
                "INSERT INTO idempotency(scope, key, request_hash, resource_id) "
                "VALUES (?, ?, ?, ?)",
                (scope, key, digest, str(resource_id)),
            )

    @contextmanager
    def _mutation(self) -> Iterator[sqlite3.Cursor]:
        """Run one durable mutation under SQLite's immediate write lock."""

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            cursor = self._connection.cursor()
            try:
                yield cursor
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def configure_credentials(self, credentials: Mapping[str, ProductPrincipal]) -> None:
        """Persist controlled token mappings without storing bearer secrets."""

        prepared: list[tuple[str, ProductPrincipal, str]] = []
        for token, principal in credentials.items():
            if not isinstance(token, str) or not token.strip():
                raise ValueError("credential token must be non-empty text")
            if not isinstance(principal, ProductPrincipal):
                raise TypeError("credentials must map bearer tokens to ProductPrincipal values")
            prepared.append((token, principal, hashlib.sha256(token.encode("utf-8")).hexdigest()))

        with self._mutation() as cursor:
            for _token, principal, digest in prepared:
                existing_ref = cursor.execute(
                    "SELECT token_digest FROM api_credentials WHERE credential_ref = ?",
                    (principal.credential_ref,),
                ).fetchone()
                if existing_ref is not None and existing_ref["token_digest"] != digest:
                    raise ValueError("credential_ref is already bound to a different token")
                existing_digest = cursor.execute(
                    "SELECT credential_ref FROM api_credentials WHERE token_digest = ?",
                    (digest,),
                ).fetchone()
                if (
                    existing_digest is not None
                    and existing_digest["credential_ref"] != principal.credential_ref
                ):
                    raise ValueError("token is already bound to a different credential_ref")
                cursor.execute(
                    """
                    INSERT INTO api_credentials(
                        credential_ref, token_digest, actor_id, workspace_id, enabled, created_at
                    ) VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(credential_ref) DO UPDATE SET
                        token_digest = excluded.token_digest,
                        actor_id = excluded.actor_id,
                        workspace_id = excluded.workspace_id,
                        enabled = 1
                    """,
                    (
                        principal.credential_ref,
                        digest,
                        principal.actor_id,
                        principal.workspace_id,
                        _unix_ms(),
                    ),
                )

    def disable_credential(self, credential_ref: str) -> bool:
        """Revoke one credential reference without deleting its audit trail."""

        with self._mutation() as cursor:
            cursor.execute(
                "UPDATE api_credentials SET enabled = 0 WHERE credential_ref = ? AND enabled = 1",
                (credential_ref,),
            )
            return cursor.rowcount > 0

    def resolve_credential(self, token: str) -> RequestPrincipal | None:
        """Resolve one bearer token to trusted identity metadata."""

        if not isinstance(token, str) or not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT actor_id, workspace_id, credential_ref
                FROM api_credentials
                WHERE token_digest = ? AND enabled = 1
                """,
                (digest,),
            ).fetchone()
        if row is None:
            return None
        return RequestPrincipal(
            actor_id=str(row["actor_id"]),
            workspace_id=str(row["workspace_id"]),
            credential_ref=str(row["credential_ref"]),
        )

    def save_tenant_quota(self, quota: TenantQuota) -> None:
        """Persist Product quota policy without duplicating usage totals."""

        with self._mutation() as cursor:
            cursor.execute(
                """
                INSERT INTO tenant_quotas(
                    tenant_id, workspace_id, monthly_token_quota, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    workspace_id = excluded.workspace_id,
                    monthly_token_quota = excluded.monthly_token_quota,
                    updated_at = excluded.updated_at
                """,
                (
                    quota.tenant_id,
                    quota.workspace_id,
                    quota.monthly_token_quota,
                    quota.updated_at.isoformat(),
                ),
            )

    def get_tenant_quota(self, tenant_id: str) -> TenantQuota | None:
        """Read Product quota policy; usage remains Plugins-owned."""

        with self._lock:
            row = self._connection.execute(
                """
                SELECT tenant_id, workspace_id, monthly_token_quota, updated_at
                FROM tenant_quotas WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchone()
        return TenantQuota.model_validate(dict(row)) if row is not None else None

    def begin_request(self, metadata: RequestMetadata) -> None:
        """Persist trusted request admission before provider invocation."""

        principal = metadata.principal
        try:
            with self._mutation() as cursor:
                cursor.execute(
                    """
                    INSERT INTO request_audits(
                        request_id, route_id, binding_id, model, stream,
                        actor_id, workspace_id, credential_ref, status, started_at,
                        usage_state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.request_id,
                        metadata.route_id,
                        metadata.provider_ref,
                        metadata.model,
                        int(metadata.stream),
                        principal.actor_id,
                        principal.workspace_id,
                        principal.credential_ref,
                        RequestAuditStatus.STARTED.value,
                        _unix_ms(),
                        UsageState.UNKNOWN.value,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_REQUEST_AUDIT_CONFLICT",
                title="Request audit conflict",
                detail="The request id is already present in the Exchange audit ledger.",
                status=409,
                resource_ref=metadata.request_id,
            ) from exc

    def record_rejection(
        self,
        *,
        request_id: str,
        principal: RequestPrincipal | None,
        status: str,
        error_type: str,
        model: str | None,
        stream: bool | None,
    ) -> None:
        """Persist an authenticated rejection without request content."""

        with self._mutation() as cursor:
            cursor.execute(
                """
                INSERT INTO request_audits(
                    request_id, model, stream, actor_id, workspace_id, credential_ref,
                    status, started_at, finished_at, usage_state, error_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO NOTHING
                """,
                (
                    request_id,
                    model,
                    None if stream is None else int(stream),
                    principal.actor_id if principal else None,
                    principal.workspace_id if principal else None,
                    principal.credential_ref if principal else None,
                    status,
                    _unix_ms(),
                    _unix_ms(),
                    UsageState.UNKNOWN.value,
                    error_type,
                ),
            )

    def finish_request(
        self,
        metadata: RequestMetadata,
        *,
        status: str,
        usage: ProviderUsage | None,
        error_type: str | None,
    ) -> None:
        """Record one terminal outcome; repeated callbacks cannot add usage."""

        usage_state, prompt_tokens, completion_tokens, total_tokens, source = _usage_values(usage)
        with self._mutation() as cursor:
            row = cursor.execute(
                "SELECT status FROM request_audits WHERE request_id = ?",
                (metadata.request_id,),
            ).fetchone()
            if row is None:
                raise ExchangeProductError(
                    code="EXCHANGE_REQUEST_AUDIT_NOT_FOUND",
                    title="Request audit not found",
                    detail="The request must be admitted before it can be completed.",
                    status=500,
                    resource_ref=metadata.request_id,
                )
            if row["status"] != RequestAuditStatus.STARTED.value:
                return
            cursor.execute(
                """
                UPDATE request_audits SET
                    status = ?, finished_at = ?, usage_state = ?,
                    prompt_tokens = ?, completion_tokens = ?, total_tokens = ?,
                    usage_source = ?, error_type = ?
                WHERE request_id = ? AND status = ?
                """,
                (
                    status,
                    _unix_ms(),
                    usage_state.value,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    source,
                    error_type,
                    metadata.request_id,
                    RequestAuditStatus.STARTED.value,
                ),
            )

    def get_request_audit(self, request_id: str) -> RequestAuditRecord | None:
        """Read one content-free durable request audit record."""

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM request_audits WHERE request_id = ?", (request_id,)
            ).fetchone()
        return _audit_from_row(row) if row is not None else None

    def list_request_audits(
        self,
        *,
        workspace_id: str | None = None,
        actor_id: str | None = None,
        limit: int = 100,
    ) -> list[RequestAuditRecord]:
        """List durable audit rows with bounded workspace/actor filters."""

        bounded_limit = max(1, min(limit, 500))
        clauses: list[str] = []
        values: list[str | int] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            values.append(workspace_id)
        if actor_id is not None:
            clauses.append("actor_id = ?")
            values.append(actor_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"SELECT * FROM request_audits{where} "
                "ORDER BY started_at DESC, request_id DESC LIMIT ?",
                (*values, bounded_limit),
            ).fetchall()
        return [_audit_from_row(row) for row in rows]


def _unix_ms() -> int:
    """Return current Unix wall-clock time in milliseconds."""

    import time

    return time.time_ns() // 1_000_000


def _usage_values(
    usage: ProviderUsage | None,
) -> tuple[UsageState, int | None, int | None, int | None, str | None]:
    """Classify only provider facts; never infer missing token counts."""

    if usage is None:
        return UsageState.UNKNOWN, None, None, None, None
    values = (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens)
    present = sum(value is not None for value in values)
    if present == 0:
        state = UsageState.UNKNOWN
    elif usage.prompt_tokens is not None and usage.completion_tokens is not None:
        state = UsageState.FINAL
    else:
        state = UsageState.PARTIAL
    return state, *values, usage.source


def _audit_from_row(row: sqlite3.Row) -> RequestAuditRecord:
    """Convert a SQLite row into the public content-free audit model."""

    values = dict(row)
    values["stream"] = None if values["stream"] is None else bool(values["stream"])
    return RequestAuditRecord.model_validate(values)
