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

from pydantic import Field

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


class IntegrationConnection(ContractModel):
    """Scoped GitHub repository connection, independent of member Account Center links."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: str = Field(min_length=1, max_length=200)
    workspace_id: str = Field(min_length=1, max_length=200)
    actor_issuer: str = Field(min_length=1, max_length=1000)
    actor_subject: str = Field(min_length=1, max_length=1000)
    account_link_ref: str | None = Field(default=None, max_length=300)
    provider: Literal["github"] = "github"
    repository_id: str = Field(min_length=1, max_length=200)
    repository_name: str = Field(min_length=1, max_length=300)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class CreateIntegrationConnection(ContractModel):
    """Create a group repository connection without member account references."""

    repository_id: str = Field(min_length=1, max_length=200)
    repository_name: str = Field(min_length=1, max_length=300)


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
