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
import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import UUID

from cyrene_exchange.capabilities import ProviderUsage
from cyrene_exchange.gateway import (
    RequestMetadata,
    RequestPrincipal,
)

from cyrene_exchange_product.domain import (
    ApiKey,
    ApiKeyState,
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
            self._migrate_api_credentials()

    def _migrate_api_credentials(self) -> None:
        """Add the API-key metadata columns to the existing credential table.

        SQLite adds nullable columns in place; the operator-configured rows keep
        NULL api_key_id/name and therefore never appear in the API-key list.

        为既有凭据表就地补充 API Key 元数据列；操作者配置的行保持 NULL，
        不会出现在 API Key 列表中。
        """

        columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(api_credentials)")
        }
        additions = (
            ("api_key_id", "TEXT"),
            ("name", "TEXT"),
            ("expires_at", "INTEGER"),
            ("revoked_at", "INTEGER"),
            ("model_scope", "TEXT"),
            ("resource_version", "INTEGER NOT NULL DEFAULT 1"),
        )
        for name, definition in additions:
            if name not in columns:
                self._connection.execute(
                    f"ALTER TABLE api_credentials ADD COLUMN {name} {definition}"
                )
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_api_credentials_api_key_id "
            "ON api_credentials(api_key_id) WHERE api_key_id IS NOT NULL"
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

    def list_all_routes(self) -> list[GatewayRoute]:
        """Return every persisted route, including drafts. | 返回全部路由。"""

        with self._lock:
            rows = self._connection.execute(
                "SELECT document FROM gateway_routes ORDER BY priority ASC, id ASC"
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
        """Run one durable mutation under SQLite's immediate write lock.

        中文:在 SQLite 的 immediate 写锁下执行一次持久化变更。"""

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
        """Persist controlled token mappings without storing bearer secrets.

        中文:持久化受控令牌映射,不存储 bearer 密钥。"""

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
        """Revoke one credential reference without deleting its audit trail.

        中文:撤销一个凭据引用,但不删除其审计记录。"""

        with self._mutation() as cursor:
            cursor.execute(
                "UPDATE api_credentials SET enabled = 0 WHERE credential_ref = ? AND enabled = 1",
                (credential_ref,),
            )
            return cursor.rowcount > 0

    def create_api_key(
        self,
        api_key: ApiKey,
        secret_digest: str,
        key: str | None,
        request_digest: str,
    ) -> tuple[ApiKey, bool]:
        """Persist one server-generated key and its replay identity atomically.

        Returns the stored key and whether this call created it. A replay
        returns the existing metadata without the secret, which is only ever
        shown by the creation response.

        中文:原子持久化一个由服务器生成的密钥及其重放标识。

                中文:返回已存储的密钥及本次调用是否创建了该密钥。重放请求会返回现有元数据而不返回密钥;密钥只会在创建响应中展示一次。
        """

        with self._mutation() as cursor:
            replay = self.resolve_idempotency("create-api-key", key, request_digest)
            if replay is not None:
                existing = self.get_api_key(UUID(replay))
                if existing is None:
                    raise RuntimeError("api-key idempotency points to an absent key")
                return existing, False
            cursor.execute(
                """
                INSERT INTO api_credentials(
                    credential_ref, token_digest, actor_id, workspace_id, enabled, created_at,
                    api_key_id, name, expires_at, model_scope, resource_version
                ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    api_key.credential_ref,
                    secret_digest,
                    api_key.actor_id,
                    api_key.workspace_id,
                    _unix_ms(),
                    str(api_key.id),
                    api_key.name,
                    _to_unix_ms(api_key.expires_at),
                    json.dumps(api_key.model_scope, separators=(",", ":")),
                    api_key.resource_version,
                ),
            )
            if key is not None:
                cursor.execute(
                    "INSERT INTO idempotency(scope, key, request_hash, resource_id) "
                    "VALUES ('create-api-key', ?, ?, ?)",
                    (key, request_digest, str(api_key.id)),
                )
        return api_key, True

    def get_api_key(self, api_key_id: UUID) -> ApiKey | None:
        """Read one server-generated key by Product identity. | 按身份读取密钥。"""

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM api_credentials WHERE api_key_id = ?", (str(api_key_id),)
            ).fetchone()
        return _api_key_from_row(row) if row is not None else None

    def list_api_keys(self) -> list[ApiKey]:
        """List server-generated keys, newest first. | 列出服务端生成的密钥。"""

        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM api_credentials WHERE api_key_id IS NOT NULL "
                "ORDER BY created_at DESC, api_key_id DESC"
            ).fetchall()
        return [_api_key_from_row(row) for row in rows]

    def revoke_api_key(self, api_key_id: UUID) -> ApiKey | None:
        """Revoke one key and retain its metadata. | 撤销密钥并保留元数据。"""

        with self._mutation() as cursor:
            row = cursor.execute(
                "SELECT * FROM api_credentials WHERE api_key_id = ?", (str(api_key_id),)
            ).fetchone()
            if row is None:
                return None
            existing = _api_key_from_row(row)
            if existing.state == ApiKeyState.REVOKED:
                return existing
            now_ms = _unix_ms()
            cursor.execute(
                "UPDATE api_credentials SET enabled = 0, revoked_at = ?, "
                "resource_version = resource_version + 1 WHERE api_key_id = ?",
                (now_ms, str(api_key_id)),
            )
            updated = cursor.execute(
                "SELECT * FROM api_credentials WHERE api_key_id = ?", (str(api_key_id),)
            ).fetchone()
        return _api_key_from_row(updated)

    def resolve_credential(self, token: str) -> RequestPrincipal | None:
        """Resolve one bearer token to trusted identity metadata.

        中文:将一个 bearer token 解析为可信的身份元数据。"""

        if not isinstance(token, str) or not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT actor_id, workspace_id, credential_ref, model_scope
                FROM api_credentials
                WHERE token_digest = ? AND enabled = 1
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (digest, _unix_ms()),
            ).fetchone()
        if row is None:
            return None
        scope = json.loads(str(row["model_scope"])) if row["model_scope"] else []
        return RequestPrincipal(
            actor_id=str(row["actor_id"]),
            workspace_id=str(row["workspace_id"]),
            credential_ref=str(row["credential_ref"]),
            model_scope=frozenset(str(item) for item in scope),
        )

    def save_tenant_quota(self, quota: TenantQuota) -> None:
        """Persist Product quota policy without duplicating usage totals.

        中文:持久化 Product 配额策略,不重复存储用量总数。"""

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
        """Read Product quota policy; usage remains Plugins-owned.

        中文:读取 Product 配额策略;用量仍由 Plugins 所有。"""

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
        """Persist trusted request admission before provider invocation.

        中文:在调用提供方之前持久化可信的请求准入记录。"""

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
        """Persist an authenticated rejection without request content.

        中文:持久化经过认证的拒绝结果,不记录请求内容。"""

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
        """Record one terminal outcome; repeated callbacks cannot add usage.

        中文:记录一次最终结果;重复回调不能增加用量。"""

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
        """Read one content-free durable request audit record.

        中文:读取一条不含内容的持久化请求审计记录。"""

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
        """List durable audit rows with bounded workspace/actor filters.

        中文:使用有界的 workspace/actor 条件列出持久化审计记录。"""

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
    """Return current Unix wall-clock time in milliseconds.

    中文:返回当前 Unix 墙上时钟时间,单位为毫秒。"""

    import time

    return time.time_ns() // 1_000_000


def _to_unix_ms(value: datetime | None) -> int | None:
    """Convert an optional aware timestamp to Unix milliseconds.

    中文:将可选的带时区时间戳转换为 Unix 毫秒时间。"""

    return None if value is None else int(value.timestamp() * 1000)


def _from_unix_ms(value: int | None) -> datetime | None:
    """Convert optional Unix milliseconds to an aware UTC timestamp.

    中文:将可选的 Unix 毫秒时间转换为带时区的 UTC 时间戳。"""

    return None if value is None else datetime.fromtimestamp(value / 1000, tz=UTC)


def _api_key_from_row(row: sqlite3.Row) -> ApiKey:
    """Project one api_credentials row onto the public ApiKey metadata.

    中文:将一条 api_credentials 记录投影为公开 ApiKey 元数据。"""

    scope = json.loads(str(row["model_scope"])) if row["model_scope"] else []
    return ApiKey(
        id=UUID(str(row["api_key_id"])),
        name=str(row["name"]),
        credential_ref=str(row["credential_ref"]),
        actor_id=str(row["actor_id"]),
        workspace_id=str(row["workspace_id"]),
        state=ApiKeyState.REVOKED if row["revoked_at"] else ApiKeyState.ACTIVE,
        model_scope=[str(item) for item in scope],
        created_at=_from_unix_ms(int(row["created_at"])) or datetime.now(UTC),
        updated_at=_from_unix_ms(int(row["revoked_at"] or row["created_at"])) or datetime.now(UTC),
        expires_at=_from_unix_ms(row["expires_at"]),
        revoked_at=_from_unix_ms(row["revoked_at"]),
        resource_version=int(row["resource_version"]),
    )


def _usage_values(
    usage: ProviderUsage | None,
) -> tuple[UsageState, int | None, int | None, int | None, str | None]:
    """Classify only provider facts; never infer missing token counts.

    中文:只对提供方事实进行分类;绝不推断缺失的 token 计数。"""

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
    """Convert a SQLite row into the public content-free audit model.

    中文:将 SQLite 记录转换为公开的无内容审计模型。"""

    values = dict(row)
    values["stream"] = None if values["stream"] is None else bool(values["stream"])
    return RequestAuditRecord.model_validate(values)
