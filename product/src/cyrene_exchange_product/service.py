"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 service.py                                                      │
│  Module: cyrene_exchange_product.service                            │
│  Role: GatewayEndpoint and GatewayRoute Product authority.           │
│                                                                     │
│  模块职责：网关端点与路由产品状态权威。                                  │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from datetime import UTC
from uuid import UUID, uuid4

from cyrene_exchange_product.domain import (
    ApiKey,
    ApiKeyState,
    ContractModel,
    CreateApiKeyRequest,
    CreatedApiKey,
    CreateEndpointRequest,
    CreateRouteDraftRequest,
    CreateRouteRequest,
    EditRouteDraftRequest,
    EndpointState,
    GatewayEndpoint,
    GatewayRoute,
    ProductPrincipal,
    RouteState,
    utc_now,
)
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.store import ExchangeStore


def request_hash(command: ContractModel) -> str:
    """Hash a canonical request body for idempotency. | 生成幂等请求摘要。"""

    body = command.model_dump_json(by_alias=True, exclude_none=True)
    return hashlib.sha256(body.encode()).hexdigest()


class ExchangeProductService:
    """Own external publication and route policy resources. | 外部发布与路由资源权威。"""

    def __init__(self, store: ExchangeStore) -> None:
        self.store = store

    def create_endpoint(
        self, command: CreateEndpointRequest, idempotency_key: str | None
    ) -> GatewayEndpoint:
        """Create or replay a GatewayEndpoint. | 创建或重放 GatewayEndpoint。"""

        digest = request_hash(command)
        replay_id = self.store.resolve_idempotency("create-endpoint", idempotency_key, digest)
        if replay_id is not None:
            return self.get_endpoint(UUID(replay_id))
        now = utc_now()
        endpoint = GatewayEndpoint(
            id=uuid4(),
            name=command.name,
            public_base_url=command.public_base_url,
            auth_policy_ref=command.auth_policy_ref,
            created_at=now,
            updated_at=now,
            resource_version=1,
        )
        self.store.save_endpoint(endpoint)
        self.store.remember_idempotency(
            scope="create-endpoint",
            key=idempotency_key,
            digest=digest,
            resource_id=endpoint.id,
        )
        return endpoint

    def get_endpoint(self, endpoint_id: UUID) -> GatewayEndpoint:
        """Read a GatewayEndpoint. | 读取 GatewayEndpoint。"""

        endpoint = self.store.get_endpoint(endpoint_id)
        if endpoint is None:
            raise ExchangeProductError(
                code="EXCHANGE_ENDPOINT_NOT_FOUND",
                title="GatewayEndpoint not found",
                detail="No GatewayEndpoint exists with the requested id.",
                status=404,
            )
        return endpoint

    def list_endpoints(self) -> list[GatewayEndpoint]:
        """List persisted gateway endpoints. | 列出网关端点。"""

        return self.store.list_endpoints()

    def disable_endpoint(self, endpoint_id: UUID) -> GatewayEndpoint:
        """Disable publication without deleting route evidence. | 禁用发布但保留路由证据。"""

        endpoint = self.get_endpoint(endpoint_id)
        if endpoint.state == EndpointState.DISABLED:
            return endpoint
        disabled = endpoint.model_copy(
            update={
                "state": EndpointState.DISABLED,
                "updated_at": utc_now(),
                "resource_version": endpoint.resource_version + 1,
            }
        )
        self.store.save_endpoint(disabled)
        return disabled

    def create_route(
        self, command: CreateRouteRequest, idempotency_key: str | None
    ) -> GatewayRoute:
        """Create or replay a route to an opaque capability binding. | 创建或重放路由。"""

        self.get_endpoint(command.endpoint_id)
        digest = request_hash(command)
        replay_id = self.store.resolve_idempotency("create-route", idempotency_key, digest)
        if replay_id is not None:
            return self.get_route(UUID(replay_id))
        now = utc_now()
        route = GatewayRoute(
            id=uuid4(),
            endpoint_id=command.endpoint_id,
            model_pattern=command.model_pattern,
            target_binding_id=command.target_binding_id,
            target_model=command.target_model,
            priority=command.priority,
            created_at=now,
            updated_at=now,
            resource_version=1,
        )
        self.store.save_route(route)
        self.store.remember_idempotency(
            scope="create-route",
            key=idempotency_key,
            digest=digest,
            resource_id=route.id,
        )
        return route

    def get_route(self, route_id: UUID) -> GatewayRoute:
        """Read a GatewayRoute. | 读取 GatewayRoute。"""

        route = self.store.get_route(route_id)
        if route is None:
            raise ExchangeProductError(
                code="EXCHANGE_ROUTE_NOT_FOUND",
                title="GatewayRoute not found",
                detail="No GatewayRoute exists with the requested id.",
                status=404,
            )
        return route

    def list_routes(self) -> list[GatewayRoute]:
        """List persisted routes in stable priority order. | 列出路由。"""

        return self.store.list_all_routes()

    def create_route_draft(
        self, command: CreateRouteDraftRequest, key: str, principal: ProductPrincipal
    ) -> GatewayRoute:
        """Create an editable draft retaining immutable source evidence. | 创建路由草稿。"""
        self.get_endpoint(command.endpoint_id)
        now = utc_now()
        route = GatewayRoute(
            id=uuid4(),
            endpoint_id=command.endpoint_id,
            state=RouteState.DRAFT,
            model_pattern=command.model_pattern,
            target_binding_id=command.target_binding_id,
            target_model=command.target_model,
            priority=command.priority,
            created_at=now,
            updated_at=now,
            resource_version=1,
            source=command.source,
            created_by=principal.actor_id,
            workspace_id=principal.workspace_id,
        )
        digest = hashlib.sha256(
            (
                request_hash(command) + "\0" + principal.workspace_id + "\0" + principal.actor_id
            ).encode()
        ).hexdigest()
        return self.store.create_route_draft(route, key, digest)

    def edit_route_draft(
        self, route_id: UUID, command: EditRouteDraftRequest, principal: ProductPrincipal
    ) -> GatewayRoute:
        """Edit the receiving Product draft, preserving its source reference. | 修改接收方草稿。"""
        route = self._owned_draft(route_id, principal)
        edited = route.model_copy(
            update={
                "model_pattern": command.model_pattern,
                "target_binding_id": command.target_binding_id,
                "target_model": command.target_model,
                "priority": command.priority,
                "updated_at": utc_now(),
                "resource_version": command.resource_version + 1,
            }
        )
        return self.store.replace_route_version(edited, command.resource_version)

    def confirm_route_draft(
        self,
        route_id: UUID,
        version: int,
        principal: ProductPrincipal,
        validate_target: Callable[[GatewayRoute], None],
    ) -> GatewayRoute:
        """Recheck source/binding/inference then activate the exact draft version. | 校验后启用。"""
        route = self._owned_draft(route_id, principal)
        if route.resource_version != version:
            raise ExchangeProductError(
                code="EXCHANGE_ROUTE_VERSION_CONFLICT",
                title="Route changed",
                detail="Refresh and inspect the current draft before confirming.",
                status=409,
            )
        if self.get_endpoint(route.endpoint_id).state != EndpointState.ACTIVE:
            raise ExchangeProductError(
                code="EXCHANGE_ENDPOINT_DISABLED",
                title="Endpoint disabled",
                detail="Select an active gateway endpoint before confirming this route.",
                status=409,
            )
        validate_target(route)
        active = route.model_copy(
            update={
                "state": RouteState.ACTIVE,
                "updated_at": utc_now(),
                "resource_version": version + 1,
            }
        )
        return self.store.replace_route_version(active, version)

    def _owned_draft(self, route_id: UUID, principal: ProductPrincipal) -> GatewayRoute:
        route = self.get_route(route_id)
        if route.workspace_id != principal.workspace_id or route.created_by != principal.actor_id:
            raise ExchangeProductError(
                code="EXCHANGE_ROUTE_PERMISSION_DENIED",
                title="Route not permitted",
                detail="The draft belongs to another actor or workspace.",
                status=403,
            )
        if route.state != RouteState.DRAFT:
            raise ExchangeProductError(
                code="EXCHANGE_ROUTE_NOT_DRAFT",
                title="Route is not a draft",
                detail="Only DRAFT routes can be edited or confirmed through this action.",
                status=409,
            )
        return route

    # ── API keys ────────────────────────────────────────────────────────
    # 中文:API 密钥。

    def create_api_key(
        self,
        command: CreateApiKeyRequest,
        principal: ProductPrincipal,
        idempotency_key: str | None,
    ) -> tuple[CreatedApiKey, bool]:
        """Generate and persist one gateway key; the secret is shown once.

        生成并持久化网关密钥；明文只在创建响应中出现一次。
        """

        now = utc_now()
        expires_at = command.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at <= now:
                raise ExchangeProductError(
                    code="EXCHANGE_API_KEY_EXPIRY_INVALID",
                    title="API key expiry is invalid",
                    detail="Choose an expiry that is after the current time.",
                    status=422,
                )
        scope = [pattern.strip() for pattern in command.model_scope]
        if any(not pattern for pattern in scope):
            raise ExchangeProductError(
                code="EXCHANGE_API_KEY_SCOPE_INVALID",
                title="API key model scope is invalid",
                detail="Model scope patterns must be non-empty text.",
                status=422,
            )
        identifier = uuid4()
        api_key = ApiKey(
            id=identifier,
            name=command.name,
            credential_ref=f"api-key://{identifier}",
            actor_id=principal.actor_id,
            workspace_id=principal.workspace_id,
            state=ApiKeyState.ACTIVE,
            model_scope=scope,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            resource_version=1,
        )
        secret = "cyk_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(
            (
                request_hash(command) + "\0" + principal.workspace_id + "\0" + principal.actor_id
            ).encode()
        ).hexdigest()
        stored, created = self.store.create_api_key(
            api_key,
            hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            idempotency_key,
            digest,
        )
        response = CreatedApiKey(**stored.model_dump(), secret=secret if created else None)
        return response, created

    def list_api_keys(self, principal: ProductPrincipal) -> list[ApiKey]:
        """List this workspace's keys without any secret material.

        中文:列出当前 workspace 的 key,不包含任何 secret。
        """
    # 中文:列出此工作区的密钥,不返回任何秘密材料。

        return [
            key for key in self.store.list_api_keys() if key.workspace_id == principal.workspace_id
        ]

    def get_api_key(self, api_key_id: UUID, principal: ProductPrincipal) -> ApiKey:
        """Read one key owned by the caller's workspace.

        中文:读取一把由调用者 workspace 所有的 key。
        """
    # 中文:读取一条属于调用方工作区的密钥。

        return self._owned_api_key(api_key_id, principal)

    def revoke_api_key(self, api_key_id: UUID, principal: ProductPrincipal) -> ApiKey:
        """Revoke one key owned by the caller's workspace. | 撤销密钥。"""

        self._owned_api_key(api_key_id, principal)
        revoked = self.store.revoke_api_key(api_key_id)
        if revoked is None:
            raise ExchangeProductError(
                code="EXCHANGE_API_KEY_NOT_FOUND",
                title="API key not found",
                detail="No API key exists with the requested id.",
                status=404,
            )
        return revoked

    def _owned_api_key(self, api_key_id: UUID, principal: ProductPrincipal) -> ApiKey:
        api_key = self.store.get_api_key(api_key_id)
        if api_key is None or api_key.workspace_id != principal.workspace_id:
            raise ExchangeProductError(
                code="EXCHANGE_API_KEY_NOT_FOUND",
                title="API key not found",
                detail="No API key exists with the requested id in this workspace.",
                status=404,
            )
        return api_key
