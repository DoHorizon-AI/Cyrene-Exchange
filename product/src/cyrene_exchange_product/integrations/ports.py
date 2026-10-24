"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 ports.py                                                        │
│  Module: cyrene_exchange_product.integrations.ports                  │
│  Role: Typed boundaries to Account Center, providers, and grants.     │
│                                                                      │
│  模块职责：定义 dispatcher 可调用的类型化外部端口。                       │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from cyrene_exchange_product.integrations.models import (
    IntegrationPrincipal,
    NormalizedGitHubEvent,
    ResourceSnapshot,
)


class RetryableReadError(RuntimeError):
    """A safe provider read failure with optional bounded Retry-After seconds."""

    def __init__(self, message: str, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class ProviderRejectedError(RuntimeError):
    """A typed provider response explicitly confirms that a write had no effect."""

    def __init__(self, reason_code: str) -> None:
        if not reason_code or len(reason_code) > 100:
            raise ValueError("provider rejection reason code is invalid")
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class AccountAuthorization:
    """Short-lived provider authorization handle; contains no token material."""

    actor_issuer: str
    actor_subject: str
    organization_id: str
    workspace_id: str
    account_link_ref: str
    provider: str
    repository_id: str
    repository_name: str
    operation_id: str
    arguments_sha256: str
    expires_at: datetime
    lease_ref: str


@dataclass(frozen=True, slots=True)
class ProviderCredentialLeaseEvidence:
    """Opaque one-use lease metadata; provider tokens never enter Exchange."""

    lease_ref: str
    profile_ref: str
    provider: str
    operation_id: str
    target: dict[str, object]
    arguments_sha256: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class LinkedSender:
    """Account Center verified mapping from a vendor sender to a Cyrene actor."""

    issuer: str
    subject: str
    organization_id: str
    workspace_id: str | None
    account_link_ref: str
    external_sender_id: str


@dataclass(frozen=True, slots=True)
class IssueSnapshot:
    """Read-only issue observation returned by the GitHub provider port."""

    repository_id: str
    issue_number: int
    state: str
    title: str
    body: str
    version: str
    observed_at: datetime

    def as_resource_snapshot(
        self,
        *,
        organization_id: str,
        workspace_id: str,
        actor_issuer: str,
        actor_subject: str,
        connection_id: object,
    ) -> ResourceSnapshot:
        """Convert provider observation to the durable freshness model."""

        from uuid import UUID

        from cyrene_exchange_product.integrations.models import SnapshotFreshness

        if not isinstance(connection_id, UUID):
            raise TypeError("connection_id must be a UUID")
        return ResourceSnapshot(
            organization_id=organization_id,
            workspace_id=workspace_id,
            actor_issuer=actor_issuer,
            actor_subject=actor_subject,
            connection_id=connection_id,
            resource_type="github.issue",
            resource_id=f"{self.repository_id}#{self.issue_number}",
            version=self.version,
            observed_at=self.observed_at,
            freshness=SnapshotFreshness.FRESH,
            document={
                "repositoryId": self.repository_id,
                "issueNumber": self.issue_number,
                "state": self.state,
                "title": self.title,
                "body": self.body,
            },
        )


@dataclass(frozen=True, slots=True)
class WriteEvidence:
    """Explicit provider write result, never inferred from missing fields."""

    accepted: bool
    succeeded: bool
    vendor_resource_id: str | None
    observed_at: datetime
    evidence: dict[str, object]


@dataclass(frozen=True, slots=True)
class MessageEvidence:
    """Message transport acknowledgement with separate vendor and request IDs."""

    accepted: bool
    vendor_message_id: str | None
    transport_request_id: str | None
    observed_at: datetime
    evidence: dict[str, object]


@dataclass(frozen=True, slots=True)
class PluginHealthObservation:
    """Read-only health facts returned by one resolved Plugin runtime RPC."""

    status: str
    observed_at: datetime
    plugin_id: str | None = None
    plugin_version: str | None = None
    capabilities: tuple[str, ...] = ()
    error_code: str | None = None


class PluginHealthPort(Protocol):
    """Probe the fixed DirectPluginRuntime Health RPC for one resolved endpoint."""

    def observe(self) -> PluginHealthObservation: ...


class AuthorityInvocationState(StrEnum):
    """Observable Platform Authority invocation state; IDs are not credentials."""

    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    DISPATCHED = "DISPATCHED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    COMPLETED = "COMPLETED"
    UNKNOWN_RESULT = "UNKNOWN_RESULT"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class AuthorityEnqueueEvidence:
    """Durable Authority invocation reference and observed enqueue state."""

    invocation_id: str
    state: AuthorityInvocationState


@dataclass(frozen=True, slots=True)
class AuthorityInvocationEvidence:
    """Read-only poll result from Platform Authority for one persisted invocation."""

    invocation_id: str
    state: AuthorityInvocationState
    observed_at: datetime
    result_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ValidatedExecutionProof:
    """Immutable proof projected from Authority's verified ApprovedInvocation."""

    invocation_id: str
    owner: str
    issuer: str
    subject: str
    organization_id: str
    workspace_id: str
    http_method: str
    path: str
    content_type: str
    idempotency_key: str
    execution_operation_id: str
    operation_id: str
    binding_id: str
    argument_digest: str
    raw_body: bytes
    raw_body_sha256: str


class AccountCenterPort(Protocol):
    """Account Center references and verified external identity lookups."""

    def get_authorization(
        self,
        principal: IntegrationPrincipal,
        *,
        account_link_ref: str,
        operation_id: str,
        repository_id: str,
        repository_name: str,
        issue_number: int,
        arguments: Mapping[str, object],
        arguments_sha256: str,
    ) -> AccountAuthorization: ...

    def resolve_linked_sender(
        self,
        service_principal: IntegrationPrincipal,
        *,
        source_authority: str,
        bot_namespace: str,
        stable_subject: str,
    ) -> LinkedSender | None: ...


class GitHubPort(Protocol):
    """Fixed GitHub issue operations; implementations use actor-scoped leases."""

    def get_issue(
        self, authorization: AccountAuthorization, *, repository_id: str, issue_number: int
    ) -> IssueSnapshot: ...

    def create_comment(
        self,
        authorization: AccountAuthorization,
        *,
        repository_id: str,
        issue_number: int,
        body: str,
    ) -> WriteEvidence: ...

    def update_state(
        self,
        authorization: AccountAuthorization,
        *,
        repository_id: str,
        issue_number: int,
        state: str,
    ) -> WriteEvidence: ...


class MessagePort(Protocol):
    """Send one fixed notification and return explicit transport evidence."""

    def send_notification(
        self,
        *,
        target_ref: str,
        text: str,
        idempotency_key: str,
    ) -> MessageEvidence: ...

    def send_command_reply(
        self,
        *,
        source_binding_id: str,
        sender_id: str,
        conversation_ref: str,
        reply_message_id: str,
        reply_context_ref: str,
        text: str,
        idempotency_key: str,
    ) -> MessageEvidence: ...

    def send_wecom_challenge_reply(
        self,
        *,
        source_binding_id: str,
        sender_id: str,
        conversation_ref: str,
        reply_message_id: str,
        reply_context_ref: str,
        text: str,
        idempotency_key: str,
    ) -> MessageEvidence: ...


class DelegationPort(Protocol):
    """Submit/poll fixed Authority work; never manufacture execution credentials."""

    def enqueue_authorized_action(
        self,
        *,
        delegation_ref: str,
        workspace_id: str,
        binding_id: str,
        execution_operation_id: str,
        operation_id: str,
        argument_digest: str,
        idempotency_key: str,
    ) -> AuthorityEnqueueEvidence: ...

    def poll_invocation(self, invocation_id: str) -> AuthorityInvocationEvidence: ...


def normalized_event_to_sender_key(event: NormalizedGitHubEvent) -> str:
    """Return the normalized stable sender identifier used by Account Center."""

    return event.sender_id
