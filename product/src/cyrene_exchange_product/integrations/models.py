"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 models.py                                                       │
│  Module: cyrene_exchange_product.integrations.models                │
│  Role: Typed, scoped models for Product integrations.                │
│                                                                      │
│  模块职责：定义集成业务实体及稳定 camelCase 请求模型。                    │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from cyrene_exchange_product.domain import ContractModel
from cyrene_exchange_product.errors import ExchangeProductError


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp. | 返回带时区的 UTC 时间。"""

    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class IntegrationPrincipal:
    """Verified Platform identity and exact Product-operation grants.

    Construct only from verified authorization evidence, never request JSON.
    中文：只可由已验证的授权证据构造，不能从请求身份字段创建。
    """

    issuer: str
    subject: str
    organization_id: str
    workspace_id: str
    allowed_operation_ids: frozenset[str]
    delegation_id: str | None = None
    delegation_generation: int | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        for name in ("issuer", "subject", "organization_id", "workspace_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty text")
        if not isinstance(self.allowed_operation_ids, frozenset):
            raise TypeError("allowed_operation_ids must be a frozenset")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")

    def require(self, operation_id: str, *, now: datetime | None = None) -> None:
        """Require a fresh exact-operation grant. | 校验精确操作授权及有效期。"""

        from cyrene_exchange_product.integrations.models import IntegrationAuthorizationError

        moment = now or utc_now()
        if self.expires_at is not None and moment >= self.expires_at:
            raise IntegrationAuthorizationError("authorization expired")
        if operation_id not in self.allowed_operation_ids:
            raise IntegrationAuthorizationError("operation is not granted")


class JobState(StrEnum):
    """Durable outbox lifecycle; UNKNOWN is never automatically resent."""

    READY = "READY"
    CLAIMED = "CLAIMED"
    AWAITING_AUTHORITY = "AWAITING_AUTHORITY"
    SENDING = "SENDING"
    ACCEPTED = "ACCEPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class OperationState(StrEnum):
    """Durable business-operation lifecycle. | 业务操作持久化状态。"""

    QUEUED = "QUEUED"
    AWAITING_AUTHORITY = "AWAITING_AUTHORITY"
    RUNNING = "RUNNING"
    ACCEPTED = "ACCEPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class SnapshotFreshness(StrEnum):
    """Freshness of the last observed external resource snapshot."""

    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class IntegrationError(ExchangeProductError):
    """Base for sanitized integration domain failures. | 集成领域错误基类。"""

    status = 500
    code = "INTEGRATION_ERROR"

    def __init__(self, detail: str) -> None:
        super().__init__(
            code=f"EXCHANGE_{self.code}",
            title=self.code.replace("_", " ").title(),
            detail=detail,
            status=self.status,
        )


class IntegrationNotFound(IntegrationError):
    """A scoped integration resource does not exist. | 找不到范围内资源。"""

    status = 404
    code = "INTEGRATION_NOT_FOUND"


class IntegrationAuthorizationError(IntegrationError):
    """The verified principal lacks the required exact grant. | 授权不足。"""

    status = 403
    code = "INTEGRATION_FORBIDDEN"


class IntegrationConflict(IntegrationError):
    """A request conflicts with durable state or an idempotency key. | 状态冲突。"""

    status = 409
    code = "INTEGRATION_CONFLICT"


class IntegrationValidationError(IntegrationError):
    """A bounded integration command or event is invalid. | 请求内容无效。"""

    status = 422
    code = "INTEGRATION_INVALID"


ProviderId = Literal[
    "github",
    "wecom",
    "azure",
    "azure_devops",
    "gcp",
    "hf",
    "microsoft_graph",
    "runpod",
    "tailscale",
]
ConnectorAccessMode = Literal["actor_owned", "workspace_operator"]


class IntegrationConnection(ContractModel):
    """Provider-discriminated connection scoped to its verified creator."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str = Field(min_length=1, max_length=200)
    workspace_id: str = Field(min_length=1, max_length=200)
    actor_issuer: str = Field(min_length=1, max_length=1000)
    actor_subject: str = Field(min_length=1, max_length=1000)
    account_link_ref: str | None = Field(default=None, max_length=300)
    provider: ProviderId = "github"
    binding_ref: str | None = Field(default=None, max_length=300)
    target_ref: str | None = Field(default=None, max_length=300)
    display_name: str | None = Field(default=None, min_length=1, max_length=300)
    repository_id: str = Field(default="", max_length=200, exclude_if=lambda value: not value)
    repository_name: str = Field(default="", max_length=300, exclude_if=lambda value: not value)
    access_mode: ConnectorAccessMode = "actor_owned"
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_provider_shape(self) -> IntegrationConnection:
        """Keep legacy repository connections distinct from cloud selectors."""

        if self.provider == "github":
            if not self.repository_id or not self.repository_name:
                raise ValueError("GitHub connections require repositoryId and repositoryName")
        elif self.repository_id or self.repository_name:
            raise ValueError("non-GitHub connections cannot include repository fields")
        if self.provider in {"azure", "azure_devops", "gcp", "hf", "runpod", "tailscale"}:
            if not self.binding_ref or not self.target_ref:
                raise ValueError("cloud connections require configured bindingRef and targetRef")
        elif self.target_ref is not None:
            raise ValueError("targetRef is only valid for cloud resource connections")
        if self.provider == "wecom" and not self.binding_ref:
            raise ValueError("WeCom authorization connections require bindingRef")
        if self.provider == "microsoft_graph" and (
            not self.account_link_ref or not self.binding_ref or self.target_ref is not None
        ):
            raise ValueError(
                "Microsoft Graph connections require an Account Center profile and host binding"
            )
        if self.provider == "microsoft_graph" and self.access_mode != "actor_owned":
            raise ValueError("Microsoft Graph connections must remain actor owned")
        if self.provider == "azure_devops" and (
            not self.account_link_ref or self.access_mode != "actor_owned"
        ):
            raise ValueError(
                "Azure DevOps connections must use one actor-owned Account Center profile"
            )
        if self.access_mode == "workspace_operator" and self.provider not in {
            "github",
            "hf",
            "azure",
            "gcp",
            "runpod",
        }:
            raise ValueError("workspace_operator access is valid only for connector providers")
        return self


class CreateIntegrationConnection(ContractModel):
    """Create one provider connection using only opaque configured selectors."""

    provider: ProviderId = "github"
    binding_ref: str | None = Field(default=None, max_length=300)
    target_ref: str | None = Field(default=None, max_length=300)
    account_link_ref: str | None = Field(default=None, max_length=300)
    display_name: str | None = Field(default=None, min_length=1, max_length=300)
    repository_id: str = Field(default="", max_length=200, exclude_if=lambda value: not value)
    repository_name: str = Field(default="", max_length=300, exclude_if=lambda value: not value)

    @model_validator(mode="after")
    def validate_provider_shape(self) -> CreateIntegrationConnection:
        """Reject incomplete provider aliases before they reach persistent state."""

        if self.provider == "github":
            if not self.repository_id or not self.repository_name:
                raise ValueError("GitHub connections require repositoryId and repositoryName")
        elif self.repository_id or self.repository_name:
            raise ValueError("non-GitHub connections cannot include repository fields")
        if self.provider in {"azure", "azure_devops", "gcp", "hf", "runpod", "tailscale"}:
            if not self.binding_ref or not self.target_ref:
                raise ValueError("cloud connections require configured bindingRef and targetRef")
        elif self.target_ref is not None:
            raise ValueError("targetRef is only valid for cloud resource connections")
        if self.provider == "wecom" and not self.binding_ref:
            raise ValueError("WeCom authorization connections require bindingRef")
        if self.provider == "microsoft_graph" and (
            not self.account_link_ref or not self.binding_ref or self.target_ref is not None
        ):
            raise ValueError(
                "Microsoft Graph connections require an Account Center profile and host binding"
            )
        if self.provider == "azure_devops" and not self.account_link_ref:
            raise ValueError("Azure DevOps connections require this actor's Account Center profile")
        return self


class SyncBinding(ContractModel):
    """Shared group rule linking GitHub events to a fixed notification target."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str = Field(min_length=1, max_length=200)
    workspace_id: str = Field(min_length=1, max_length=200)
    connection_id: UUID
    account_link_ref: str | None = Field(default=None, max_length=300)
    delegation_ref: str | None = Field(default=None, max_length=300)
    notification_target_ref: str = Field(min_length=1, max_length=300)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class CreateSyncBinding(ContractModel):
    """Create a group notification binding without any member credentials or grants."""

    connection_id: UUID
    account_link_ref: str | None = Field(default=None, max_length=300)
    delegation_ref: str | None = Field(default=None, max_length=300)
    notification_target_ref: str = Field(min_length=1, max_length=300)


class ActorBinding(ContractModel):
    """One member's exact Account Center and Platform refs for a group binding."""

    id: UUID = Field(default_factory=uuid4)
    binding_id: UUID
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    account_link_ref: str = Field(min_length=1, max_length=300)
    delegation_ref: str = Field(min_length=1, max_length=300)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class CreateActorBinding(ContractModel):
    """Attach the verified caller's own account and delegation refs."""

    binding_id: UUID
    account_link_ref: str = Field(min_length=1, max_length=300)
    delegation_ref: str = Field(min_length=1, max_length=300)


class NormalizedGitHubEvent(ContractModel):
    """Allowlisted webhook fields normalized after signature verification."""

    event_type: Literal["issues", "issue_comment"]
    action: str = Field(min_length=1, max_length=40)
    repository_id: str = Field(min_length=1, max_length=200)
    issue_number: int = Field(ge=1)
    sender_id: str = Field(min_length=1, max_length=200)
    sender_login: str = Field(min_length=1, max_length=200)
    title: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=4000)
    self_authored: bool = False
    observed_at: datetime = Field(default_factory=utc_now)


class IncomingEvent(ContractModel):
    """Verified event persisted to inbox before notification dispatch."""

    id: UUID = Field(default_factory=uuid4)
    connection_id: UUID
    organization_id: str
    workspace_id: str
    delivery_id: str
    payload_fingerprint: str
    event_type: str
    action: str
    repository_id: str
    issue_number: int
    sender_id: str
    sender_login: str
    title: str
    body: str
    self_authored: bool
    observed_at: datetime
    state: str = "RECEIVED"


class WeComEventState(StrEnum):
    """Durable state of an authenticated WeCom message admission."""

    RECEIVED = "RECEIVED"
    IGNORED_SELF = "IGNORED_SELF"
    IGNORED_NON_COMMAND = "IGNORED_NON_COMMAND"
    IGNORED_SCOPE = "IGNORED_SCOPE"
    IGNORED_INVALID_COMMAND = "IGNORED_INVALID_COMMAND"
    IGNORED_UNLINKED = "IGNORED_UNLINKED"
    IGNORED_UNBOUND = "IGNORED_UNBOUND"
    IGNORED_UNRELATED = "IGNORED_UNRELATED"
    COMMAND_QUEUED = "COMMAND_QUEUED"
    CHALLENGE_OBSERVING = "CHALLENGE_OBSERVING"
    CHALLENGE_OBSERVED = "CHALLENGE_OBSERVED"
    CHALLENGE_UNKNOWN = "CHALLENGE_UNKNOWN"
    CHALLENGE_REPLY_PENDING = "CHALLENGE_REPLY_PENDING"
    REPLY_ACCEPTED = "REPLY_ACCEPTED"
    REPLIED = "REPLIED"
    UNKNOWN = "UNKNOWN"
    REJECTED = "REJECTED"


class WeComInboundEvent(ContractModel):
    """Normalized WeCom source facts durably admitted before acknowledgment."""

    id: UUID = Field(default_factory=uuid4)
    binding_id: UUID
    organization_id: str
    workspace_id: str
    source_event_id: str = Field(min_length=1, max_length=300)
    payload_fingerprint: str
    sender_id: str = Field(min_length=1, max_length=200)
    conversation_ref: str = Field(min_length=1, max_length=300)
    reply_message_id: str | None = Field(default=None, max_length=300)
    reply_context_ref: str | None = Field(default=None, max_length=300)
    message_text: str = Field(max_length=4096)
    self_authored: bool = False
    observed_at: datetime = Field(default_factory=utc_now)
    state: WeComEventState = WeComEventState.RECEIVED
    challenge_id: str | None = Field(default=None, max_length=300)
    operation_id: UUID | None = None


class OutboxJob(ContractModel):
    """Durable inbox notification or business-operation work item."""

    id: UUID = Field(default_factory=uuid4)
    kind: Literal["NOTIFY", "ISSUE_ACTION", "COMMAND_REPLY", "CHALLENGE_REPLY"]
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID
    binding_id: UUID | None = None
    operation_id: UUID | None = None
    idempotency_key: str | None = Field(default=None, max_length=300)
    authority_invocation_id: str | None = Field(default=None, max_length=300)
    authority_idempotency_key: str | None = Field(default=None, max_length=300)
    authority_state: str | None = Field(default=None, max_length=40)
    payload: dict[str, Any]
    state: JobState = JobState.READY
    attempts: int = 0
    available_at: datetime = Field(default_factory=utc_now)
    claim_owner: str | None = None
    claim_fence: int = 0
    lease_expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ClaimedJob(ContractModel):
    """A CAS claim paired with its monotonically increasing fencing token."""

    job: OutboxJob
    claim_fence: int
    claimed_from_state: JobState


class Operation(ContractModel):
    """Idempotent issue action request and its durable observed state."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID
    binding_id: UUID
    actor_binding_id: UUID
    account_link_ref: str = Field(min_length=1, max_length=300)
    delegation_ref: str | None = None
    execution_operation_id: str
    authority_invocation_id: str | None = Field(default=None, max_length=300)
    authority_idempotency_key: str | None = Field(default=None, max_length=300)
    argument_digest: str
    reconciles_operation_id: UUID | None = None
    operation_id: Literal[
        "integration.issue.query",
        "integration.issue.comment",
        "integration.issue.close",
        "integration.issue.reopen",
    ]
    idempotency_key: str = Field(min_length=1, max_length=200)
    request_hash: str
    source_kind: Literal["REST", "WECOM_COMMAND"] = "REST"
    source_event_ref: str | None = Field(default=None, max_length=300)
    reply_binding_ref: str | None = Field(default=None, max_length=300)
    reply_sender_id: str | None = Field(default=None, max_length=200)
    reply_conversation_ref: str | None = Field(default=None, max_length=300)
    reply_message_id: str | None = Field(default=None, max_length=300)
    reply_context_ref: str | None = Field(default=None, max_length=300)
    issue_number: int = Field(ge=1)
    body: str | None = Field(default=None, max_length=4000)
    state: OperationState = OperationState.QUEUED
    result: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class EnqueueIssueAction(ContractModel):
    """Bounded issue operation payload used by REST and command paths."""

    connection_id: UUID
    binding_id: UUID
    operation_id: Literal[
        "integration.issue.query",
        "integration.issue.comment",
        "integration.issue.close",
        "integration.issue.reopen",
    ]
    idempotency_key: str = Field(min_length=1, max_length=200)
    issue_number: int = Field(ge=1)
    body: str | None = Field(default=None, max_length=4000)
    reconciles_operation_id: UUID | None = None


class DeliveryReceipt(ContractModel):
    """Transport evidence distinguishing acceptance from delivery proof."""

    id: UUID = Field(default_factory=uuid4)
    operation_id: UUID | None = None
    job_id: UUID | None = None
    status: str = Field(min_length=1, max_length=40)
    accepted: bool
    vendor_message_id: str | None = Field(default=None, max_length=300)
    transport_request_id: str | None = Field(default=None, max_length=300)
    observed_at: datetime = Field(default_factory=utc_now)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ResourceSnapshot(ContractModel):
    """Read-only provider observation with freshness and observation time."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID
    resource_type: str = Field(min_length=1, max_length=100)
    resource_id: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=200)
    observed_at: datetime
    freshness: SnapshotFreshness = SnapshotFreshness.FRESH
    document: dict[str, Any]


class LoginState(StrEnum):
    """Observed provider login presence; it does not establish validity."""

    PRESENT = "PRESENT"
    MISSING = "MISSING"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class AuthorizationState(StrEnum):
    """Provider authorization fact, kept distinct from Platform grants."""

    VALID = "VALID"
    REAUTHORIZATION_REQUIRED = "REAUTHORIZATION_REQUIRED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class RenewalState(StrEnum):
    """Provider reauthorization flow state. | Provider 重新授权流程状态。"""

    WAITING_USER = "WAITING_USER"
    VERIFYING = "VERIFYING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class IntegrationNotificationKind(StrEnum):
    """Stable in-app notification categories for scoped integrations."""

    AUTHORIZATION_EXPIRING = "authorization.expiring"
    AUTHORIZATION_REQUIRED = "authorization.required"
    CONNECTION_UNAVAILABLE = "connection.unavailable"
    CLOUD_RESOURCE_CHANGED = "cloud.resource.changed"
    DELIVERY_FAILED = "delivery.failed"


class NotificationSeverity(StrEnum):
    """Bounded severity values shown in the Product notification feed."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class IntegrationNotification(ContractModel):
    """Durable actor-scoped event with a monotonic feed sequence."""

    id: UUID = Field(default_factory=uuid4)
    sequence: int = Field(ge=1)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID | None = None
    kind: IntegrationNotificationKind
    severity: NotificationSeverity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    created_at: datetime = Field(default_factory=utc_now)
    action_ref: str | None = Field(default=None, max_length=300)
    acknowledged_at: datetime | None = None
    incident_key: str | None = Field(default=None, max_length=500)
    stage: str | None = Field(default=None, max_length=80)


class IntegrationNotificationDraft(ContractModel):
    """Notification content and incident key before SQLite assigns sequence."""

    connection_id: UUID | None = None
    kind: IntegrationNotificationKind
    severity: NotificationSeverity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    action_ref: str | None = Field(default=None, max_length=300)
    dedupe_key: str = Field(min_length=1, max_length=500)
    incident_key: str | None = Field(default=None, max_length=500)
    stage: str | None = Field(default=None, max_length=80)


class ClaimedAuthorizationMonitor(ContractModel):
    """Due connection and fencing token owned by one monitor worker."""

    connection: IntegrationConnection
    worker_id: str = Field(min_length=1, max_length=200)
    claim_fence: int = Field(ge=1)
    lease_expires_at: datetime


class AuthorizationCapabilityRecord(ContractModel):
    """Product projection of one capability authorization observation."""

    capability_id: str = Field(min_length=1, max_length=200)
    state: AuthorizationState
    last_verified_at: datetime | None = None
    expires_at: datetime | None = None
    reason_code: str | None = Field(default=None, max_length=200)


class AuthorizationHealthRecord(ContractModel):
    """Persisted provider observation scoped to one owned connection."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID
    authorization_ref: str | None = Field(default=None, max_length=300)
    reason_code: str | None = Field(default=None, max_length=200)
    login_state: LoginState
    authorization_state: AuthorizationState
    checked_at: datetime
    expires_at: datetime | None = None
    generation: int = Field(ge=0)
    capabilities: list[AuthorizationCapabilityRecord] = Field(default_factory=list)


class RenewalSessionRecord(ContractModel):
    """Actor-scoped durable projection of one fixed provider renewal session."""

    session_ref: str = Field(min_length=1, max_length=300)
    authorization_ref: str = Field(min_length=1, max_length=300)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    state: RenewalState
    created_at: datetime
    provider_session_ref: str | None = Field(default=None, max_length=300)
    expires_at: datetime | None = None
    authorization_url: str | None = Field(default=None, max_length=2000)
    user_code: str | None = Field(
        default=None,
        min_length=4,
        max_length=32,
        pattern=r"^[A-Z0-9]{4}-[A-Z0-9]{4}$",
    )
    qr_attachment_ref: str | None = Field(default=None, max_length=300)
    generation: int = Field(ge=0)
    reason_code: str | None = Field(default=None, max_length=200)


class CloudResourceState(StrEnum):
    """Provider-reported state for a fixed cloud resource observation."""

    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


class CloudResourceRecord(ContractModel):
    """Sanitized Product resource projection with provider and freshness facts."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID
    provider: str = Field(min_length=1, max_length=80)
    source: str = Field(min_length=1, max_length=120)
    external_ref: str = Field(min_length=1, max_length=500)
    kind: str = Field(min_length=1, max_length=120)
    display_name: str = Field(min_length=1, max_length=300)
    status: CloudResourceState
    provider_status: str | None = Field(default=None, max_length=300)
    collected_at: datetime
    observed_at: datetime | None = None
    freshness: SnapshotFreshness = SnapshotFreshness.UNKNOWN
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    platform_resource_ref: str | None = Field(default=None, max_length=300)
    platform_generation: int | None = Field(default=None, ge=0)


class CloudRefreshState(StrEnum):
    """Durable read-only cloud refresh lifecycle."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class CloudRefreshOperation(ContractModel):
    """Product operation reference for one idempotent cloud refresh request."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=200)
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: CloudRefreshState = CloudRefreshState.QUEUED
    result: dict[str, str | int | bool | None] | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ClaimedCloudRefresh(ContractModel):
    """A refresh operation and its current worker fencing token."""

    operation: CloudRefreshOperation
    worker_id: str = Field(min_length=1, max_length=200)
    claim_fence: int = Field(ge=1)
    lease_expires_at: datetime


class EmailOutboxState(StrEnum):
    """Email side-effect state; UNKNOWN and SENDING are never auto-resendable."""

    READY = "READY"
    CLAIMED = "CLAIMED"
    SENDING = "SENDING"
    ACCEPTED = "ACCEPTED"
    UNKNOWN = "UNKNOWN"
    REJECTED = "REJECTED"


class EmailNotificationJob(ContractModel):
    """Durable, deduplicated email request generated from a notification."""

    id: UUID = Field(default_factory=uuid4)
    notification_id: UUID
    organization_id: str
    workspace_id: str
    actor_issuer: str
    actor_subject: str
    connection_id: UUID | None = None
    recipient_ref: str = Field(min_length=1, max_length=200)
    subject: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=4000)
    request_ref: str = Field(min_length=1, max_length=300)
    state: EmailOutboxState = EmailOutboxState.READY
    attempts: int = Field(default=0, ge=0)
    available_at: datetime = Field(default_factory=utc_now)
    claim_owner: str | None = None
    claim_fence: int = Field(default=0, ge=0)
    lease_expires_at: datetime | None = None
    vendor_receipt_ref: str | None = Field(default=None, max_length=300)
    delivery_confirmed: bool = False
    failure_reason_code: str | None = Field(default=None, max_length=200)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ClaimedEmailNotification(ContractModel):
    """Email claim and monotonically increasing fencing value."""

    job: EmailNotificationJob
    claim_fence: int = Field(ge=1)


class OperationAudit(ContractModel):
    """Append-only audit fact without tokens, prompts, or response content."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str
    workspace_id: str
    actor_issuer: str | None = None
    actor_subject: str | None = None
    resource_type: str = Field(min_length=1, max_length=100)
    resource_id: str = Field(min_length=1, max_length=300)
    action: str = Field(min_length=1, max_length=100)
    outcome: str = Field(min_length=1, max_length=40)
    observed_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)
