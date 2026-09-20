"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 domain.py                                                       │
│  Module: cyrene_exchange_product.domain                             │
│  Role: Product-owned gateway endpoint and route boundary models.     │
│                                                                     │
│  模块职责：定义外部网关端点与路由策略的稳定产品契约。                       │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


def utc_now() -> datetime:
    """Return a timezone-aware timestamp. | 返回带时区时间。"""

    return datetime.now(UTC)


class ContractModel(BaseModel):
    """Stable camelCase wire model. | 稳定 camelCase 线格式模型。"""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        serialize_by_alias=True,
        extra="forbid",
    )


class EndpointState(StrEnum):
    """External GatewayEndpoint lifecycle. | 外部网关端点生命周期。"""

    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class RouteState(StrEnum):
    """Persisted GatewayRoute lifecycle. | 持久化网关路由生命周期。"""

    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    DRAFT = "DRAFT"


class RouteSource(ContractModel):
    """Versioned reference to an existing Reactor Endpoint. | 来源端点引用。"""

    product: Literal["reactor"] = "reactor"
    resource_uri: str = Field(pattern=r"^https?://", max_length=2000)
    resource_version: int = Field(ge=1)
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    model_version_id: str | None = Field(
        default=None,
        pattern=r"^model-version://sha256/[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )


class GatewayEndpoint(ContractModel):
    """Externally published model API surface. | 对外发布的模型 API 表面。"""

    id: UUID
    name: str = Field(min_length=1, max_length=200)
    state: EndpointState = EndpointState.ACTIVE
    public_base_url: str = Field(pattern=r"^https?://")
    auth_policy_ref: str = Field(pattern=r"^(policy|secret)://", max_length=500)
    created_at: datetime
    updated_at: datetime
    resource_version: int = Field(ge=1)


class GatewayRoute(ContractModel):
    """Product route to an opaque provider capability binding. | 指向不透明能力绑定的路由。"""

    id: UUID
    endpoint_id: UUID
    state: RouteState = RouteState.ACTIVE
    model_pattern: str = Field(min_length=1, max_length=200)
    target_binding_id: str = Field(min_length=1, max_length=300)
    target_capability_type: Literal["model.provider.v1"] = "model.provider.v1"
    target_model: str | None = Field(default=None, min_length=1, max_length=200)
    priority: int = Field(ge=0, le=10_000)
    created_at: datetime
    updated_at: datetime
    resource_version: int = Field(ge=1)
    source: RouteSource | None = Field(default=None, exclude_if=lambda value: value is None)
    created_by: str | None = Field(default=None, exclude_if=lambda value: value is None)
    workspace_id: str | None = Field(default=None, exclude_if=lambda value: value is None)


class CreateEndpointRequest(ContractModel):
    """Create-GatewayEndpoint command. | 创建网关端点请求。"""

    name: str = Field(min_length=1, max_length=200)
    public_base_url: str = Field(pattern=r"^https?://")
    auth_policy_ref: str = Field(pattern=r"^(policy|secret)://", max_length=500)


class CreateRouteRequest(ContractModel):
    """Create-GatewayRoute command. | 创建网关路由请求。"""

    endpoint_id: UUID
    model_pattern: str = Field(min_length=1, max_length=200)
    target_binding_id: str = Field(min_length=1, max_length=300)
    target_model: str | None = Field(default=None, min_length=1, max_length=200)
    priority: int = Field(ge=0, le=10_000)


class CreateRouteDraftRequest(CreateRouteRequest):
    """Explicit Send to creates a draft, never an active route. | 发送到只创建草稿。"""

    source: RouteSource
    target_model: str = Field(min_length=1, max_length=200)


class EditRouteDraftRequest(ContractModel):
    """Editable route intent with optimistic concurrency. | 草稿修改与版本检查。"""

    resource_version: int = Field(ge=1)
    model_pattern: str = Field(min_length=1, max_length=200)
    target_binding_id: str = Field(min_length=1, max_length=300)
    target_model: str = Field(min_length=1, max_length=200)
    priority: int = Field(ge=0, le=10_000)


class ConfirmRouteRequest(ContractModel):
    """Explicit confirmation of the exact inspected draft version. | 确认草稿版本。"""

    resource_version: int = Field(ge=1)


class ApiKeyState(StrEnum):
    """Gateway API key lifecycle. | 网关 API Key 生命周期。"""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class CreateApiKeyRequest(ContractModel):
    """Server-generated gateway key request. | 服务端生成网关密钥请求。"""

    name: str = Field(min_length=1, max_length=200)
    expires_at: datetime | None = Field(default=None, exclude_if=lambda value: value is None)
    model_scope: list[str] = Field(default_factory=list, max_length=100)


class ApiKey(ContractModel):
    """Gateway credential metadata; the secret is never persisted. | 密钥元数据。"""

    id: UUID
    name: str = Field(min_length=1, max_length=200)
    credential_ref: str = Field(pattern=r"^api-key://[0-9a-f-]{36}$")
    actor_id: str = Field(min_length=1, max_length=300)
    workspace_id: str = Field(min_length=1, max_length=300)
    state: ApiKeyState
    model_scope: list[str] = Field(default_factory=list, max_length=100)
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = Field(default=None, exclude_if=lambda value: value is None)
    revoked_at: datetime | None = Field(default=None, exclude_if=lambda value: value is None)
    resource_version: int = Field(ge=1)


class CreatedApiKey(ApiKey):
    """Creation response carrying the one-time secret. | 仅创建响应携带一次性密钥。"""

    secret: str | None = Field(default=None, exclude_if=lambda value: value is None)


class ProblemDetails(ContractModel):
    """RFC 9457 control response with stable extensions. | RFC 9457 控制面错误。"""

    type: str
    title: str
    status: int = Field(ge=400, le=599)
    detail: str
    instance: str
    code: str
    retryable: bool
    trace_id: str
    resource_ref: str | None = None


@dataclass(frozen=True)
class ProductPrincipal:
    """Configured Exchange identity bound to one credential reference."""

    actor_id: str
    workspace_id: str
    credential_ref: str

    def __post_init__(self) -> None:
        for field_name in ("actor_id", "workspace_id", "credential_ref"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"principal {field_name} must be non-empty text")


class TenantQuota(ContractModel):
    """Product-owned token quota policy for one tenant and workspace. | 租户配额策略。"""

    tenant_id: str = Field(min_length=1, max_length=300)
    workspace_id: str = Field(min_length=1, max_length=300)
    monthly_token_quota: int = Field(gt=0)
    updated_at: datetime


class RequestAuditStatus(StrEnum):
    """Durable request lifecycle state owned by Exchange Product."""

    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class UsageState(StrEnum):
    """Completeness of exact usage facts observed from a provider."""

    UNKNOWN = "unknown"
    PARTIAL = "partial"
    FINAL = "final"


class RequestAuditRecord(ContractModel):
    """Content-free persisted request, outcome, and provider usage record."""

    request_id: str = Field(min_length=1, max_length=200)
    route_id: str | None = Field(default=None, min_length=1, max_length=300)
    binding_id: str | None = Field(default=None, min_length=1, max_length=300)
    model: str | None = Field(default=None, min_length=1, max_length=300)
    stream: bool | None = None
    actor_id: str | None = Field(default=None, min_length=1, max_length=300)
    workspace_id: str | None = Field(default=None, min_length=1, max_length=300)
    credential_ref: str | None = Field(default=None, min_length=1, max_length=300)
    status: RequestAuditStatus
    started_at: int = Field(ge=0)
    finished_at: int | None = Field(default=None, ge=0)
    usage_state: UsageState = UsageState.UNKNOWN
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    usage_source: str | None = Field(default=None, min_length=1, max_length=200)
    error_type: str | None = Field(default=None, min_length=1, max_length=200)


# Keep the vocabulary explicit for callers that describe this record as usage
# audit rather than request audit. | 为 usage audit 调用方保留明确别名。
RequestUsageAudit = RequestAuditRecord
