"""Versioned HTTP facade for linked accounts and fixed GitHub workflows.

Public identity is derived only from Platform verification. Webhook bytes are
verified by the configured GitHub capability before Exchange persists events.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Query, Request
from fastapi import Path as ApiPath
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.clients import AccountCenterClient, GitHubIssuesClient
from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudRefreshOperation,
    CreateIntegrationConnection,
    CreateSyncBinding,
    EnqueueIssueAction,
    IntegrationAuthorizationError,
    IntegrationNotFound,
    IntegrationNotification,
    IntegrationPrincipal,
    LoginState,
    ProviderId,
    RenewalSessionRecord,
    RenewalState,
)
from cyrene_exchange_product.integrations.ports import (
    PluginHealthObservation,
    ValidatedExecutionProof,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


class IntegrationRequestBody(BaseModel):
    """Closed public JSON DTOs use camelCase while retaining internal field names."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
    )


class BeginLinkBody(IntegrationRequestBody):
    """Fixed external account provider selector."""

    provider: str = Field(pattern="^(github|wecom)$")


class ConfirmWeComBody(IntegrationRequestBody):
    """Challenge confirmation tied to an Account Center link session."""

    link_session_ref: UUID
    challenge_id: UUID
    challenge_value: str = Field(min_length=16, max_length=128)


class CreateConnectionBody(IntegrationRequestBody):
    """Create a fixed provider connection using only configured opaque aliases."""

    provider: ProviderId = "github"
    binding_ref: str | None = Field(default=None, min_length=1, max_length=300)
    target_ref: str | None = Field(default=None, min_length=1, max_length=300)
    account_link_ref: str | None = Field(default=None, min_length=1, max_length=300)
    repository_id: str = Field(default="", max_length=200)
    repository_name: str = Field(default="", max_length=300)

    @staticmethod
    def _is_opaque_alias(value: str | None) -> bool:
        return value is None or (
            len(value) <= 300
            and value[0].isalnum()
            and all(character.isalnum() or character in "._:-" for character in value)
            and "://" not in value
        )

    @model_validator(mode="after")
    def validate_provider_shape(self) -> CreateConnectionBody:
        """Reject URL-like selectors and provider fields outside their discriminator."""

        if not all(
            self._is_opaque_alias(value)
            for value in (self.binding_ref, self.target_ref, self.account_link_ref)
        ):
            raise ValueError("provider refs must be configured opaque aliases")
        if self.provider == "github":
            if not self.repository_id or not self.repository_name:
                raise ValueError("GitHub connections require repositoryId and repositoryName")
            if self.target_ref is not None:
                raise ValueError("GitHub connections do not accept cloud targetRef")
        elif self.repository_id or self.repository_name:
            raise ValueError("provider connections cannot include GitHub repository fields")
        elif self.provider in {"azure", "gcp", "hf", "runpod", "tailscale"}:
            if self.binding_ref is None or self.target_ref is None:
                raise ValueError("cloud connections require bindingRef and targetRef")
        elif self.provider == "wecom" and self.binding_ref is None:
            raise ValueError("WeCom authorization connections require bindingRef")
        return self


class CreateBindingBody(IntegrationRequestBody):
    """Create a group notification rule without attaching member credentials."""

    connection_id: UUID
    notification_target_ref: str = Field(min_length=1, max_length=300)


class AttachActorBindingBody(IntegrationRequestBody):
    """Attach only the authenticated member's external account and grant refs."""

    account_link_ref: str = Field(min_length=1, max_length=300)
    delegation_ref: str = Field(min_length=1, max_length=300)


class CommentBody(IntegrationRequestBody):
    """One bounded GitHub issue comment."""

    issue_number: int = Field(ge=1)
    body: str = Field(min_length=1, max_length=4000)


class StateBody(IntegrationRequestBody):
    """One fixed GitHub issue state transition."""

    issue_number: int = Field(ge=1)
    state: Literal["OPEN", "CLOSED"]


class QueryIssueBody(IntegrationRequestBody):
    """One fixed read-only GitHub issue selector."""

    issue_number: int = Field(ge=1)


class OperationStatusResponse(BaseModel):
    """Sanitized polling projection for one persisted Product operation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    operation_id: str = Field(alias="operationId")
    action: str
    state: Literal[
        "QUEUED",
        "AWAITING_AUTHORITY",
        "RUNNING",
        "ACCEPTED",
        "SUCCEEDED",
        "FAILED",
        "UNKNOWN",
    ]
    issue_number: int | None = Field(default=None, alias="issueNumber")
    connection_id: str | None = Field(
        default=None, alias="connectionId", exclude_if=lambda value: value is None
    )
    created_at: str = Field(alias="createdAt")
    updated_at: str = Field(alias="updatedAt")
    result: dict[str, Any] | None


class IssueSnapshotResponse(BaseModel):
    """Actor-scoped cached issue snapshot after an approved query succeeds."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    issue_number: int = Field(alias="issueNumber")
    state: Literal["OPEN", "CLOSED"]
    title: str
    version: str
    freshness: Literal["FRESH", "STALE", "UNKNOWN"]
    observed_at: str = Field(alias="observedAt")


class ConnectionHealthResponse(BaseModel):
    """Read-only DirectPluginRuntime Health observation for a fixed connection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: Literal["SERVING", "NOT_SERVING", "UNKNOWN"]
    observed_at: datetime = Field(alias="observedAt")
    plugin_id: str | None = Field(default=None, alias="pluginId")
    plugin_version: str | None = Field(default=None, alias="pluginVersion")
    capabilities: list[str]
    error_code: str | None = Field(default=None, alias="errorCode")


class IntegrationConnectionResponse(BaseModel):
    """Safe connection list row without tenant or actor identity fields."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    provider: ProviderId
    display_name: str = Field(alias="displayName")
    repository_id: str | None = Field(default=None, alias="repositoryId")
    repository_name: str | None = Field(default=None, alias="repositoryName")
    enabled: bool
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")


class AuthorizationCapabilityResponse(BaseModel):
    """Actor-safe projection of one provider capability authorization state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    capability_id: str = Field(alias="capabilityId")
    state: Literal[
        "VALID", "REAUTHORIZATION_REQUIRED", "PERMISSION_DENIED", "UNKNOWN", "UNAVAILABLE"
    ]
    last_verified_at: datetime | None = Field(default=None, alias="lastVerifiedAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    reason_code: str | None = Field(default=None, alias="reasonCode")


class AuthorizationHealthResponse(BaseModel):
    """Latest durable authorization observation or explicit UNKNOWN before first check."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    connection_id: str = Field(alias="connectionId")
    provider: ProviderId
    authorization_ref: str | None = Field(default=None, alias="authorizationRef")
    login_state: Literal["PRESENT", "MISSING", "UNKNOWN", "UNAVAILABLE"] = Field(alias="loginState")
    authorization_state: Literal[
        "VALID", "REAUTHORIZATION_REQUIRED", "PERMISSION_DENIED", "UNKNOWN", "UNAVAILABLE"
    ] = Field(alias="authorizationState")
    checked_at: datetime | None = Field(default=None, alias="checkedAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    generation: int = Field(ge=0)
    capabilities: list[AuthorizationCapabilityResponse]
    reason_code: str | None = Field(default=None, alias="reasonCode")


class RenewalSessionResponse(BaseModel):
    """Pollable Product session; provider credentials and internal refs are omitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    session_ref: str = Field(alias="sessionRef")
    authorization_ref: str = Field(alias="authorizationRef")
    state: Literal["WAITING_USER", "VERIFYING", "SUCCEEDED", "FAILED", "EXPIRED", "CANCELLED"]
    created_at: datetime = Field(alias="createdAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    authorization_url: str | None = Field(default=None, alias="authorizationUrl")
    qr_attachment_ref: str | None = Field(default=None, alias="qrAttachmentRef")
    generation: int = Field(ge=0)
    reason_code: str | None = Field(default=None, alias="reasonCode")


class CloudResourceResponse(BaseModel):
    """Safe cloud observation projection with explicit source and cache freshness."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    external_ref: str = Field(alias="externalRef")
    kind: str
    display_name: str = Field(alias="displayName")
    status: Literal["RUNNING", "STOPPED", "AVAILABLE", "UNAVAILABLE", "DEGRADED", "UNKNOWN"]
    provider_status: str | None = Field(default=None, alias="providerStatus")
    collected_at: datetime = Field(alias="collectedAt")
    observed_at: datetime | None = Field(default=None, alias="observedAt")
    source: str
    freshness: Literal["FRESH", "STALE", "UNKNOWN"]
    attributes: dict[str, str | int | float | bool | None]
    platform_resource_ref: str | None = Field(default=None, alias="platformResourceRef")
    platform_generation: int | None = Field(default=None, alias="platformGeneration")


class ConnectionResourcesResponse(BaseModel):
    """Latest cached resource projections for one scoped connection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    connection_id: str = Field(alias="connectionId")
    provider: ProviderId
    checked_at: datetime | None = Field(default=None, alias="checkedAt")
    resources: list[CloudResourceResponse]


class NotificationResponse(BaseModel):
    """Durable in-app event without internal actor identity or delivery payload."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    sequence: int = Field(ge=1)
    connection_id: str | None = Field(default=None, alias="connectionId")
    kind: str
    severity: Literal["INFO", "WARNING", "ERROR"]
    title: str
    description: str
    created_at: datetime = Field(alias="createdAt")
    action_ref: str | None = Field(default=None, alias="actionRef")
    acknowledged_at: datetime | None = Field(default=None, alias="acknowledgedAt")


class NotificationFeedResponse(BaseModel):
    """Sequence-backed notification page for gap recovery."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    notifications: list[NotificationResponse]
    next_sequence: int = Field(alias="nextSequence", ge=0)


class IntegrationJobResponse(IntegrationRequestBody):
    """Sanitized job metadata without payload, actor, credential, or grant refs."""

    job_id: str
    kind: str
    state: str
    attempts: int
    operation_id: str | None
    created_at: datetime
    updated_at: datetime
    available_at: datetime


class ExecuteIssueBody(IntegrationRequestBody):
    """Authority-dispatched execution selector with no caller identity claims."""

    operation_id: UUID
    argument_digest: str = Field(pattern="^[0-9a-f]{64}$")


class IntegrationAuthorizer(Protocol):
    """Host-resolved current Platform identity verifier."""

    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal: ...


class GitHubWebhookVerifier(Protocol):
    """Fixed GitHub capability that validates original webhook bytes."""

    def verify_and_normalize(
        self,
        *,
        delivery_id: str,
        event_name: str,
        signature: str,
        body: bytes,
    ) -> Mapping[str, Any]: ...


class DelegationAuthorizer(Protocol):
    """Validate a current actor-owned Platform grant before attachment."""

    def validate_binding(
        self,
        principal: IntegrationPrincipal,
        *,
        bearer_token: str | None,
        execution_credential: bytes | None,
        delegation_ref: str,
        binding_id: UUID,
        account_link_ref: str,
    ) -> None: ...


class IntegrationServices:
    """Resolved production capabilities and independent integration store."""

    def __init__(
        self,
        *,
        store: IntegrationStore,
        authorizer: IntegrationAuthorizer,
        accounts: AccountCenterClient,
        github: GitHubIssuesClient,
        webhook_verifier: GitHubWebhookVerifier,
        delegation_authorizer: DelegationAuthorizer,
        callback_principal: IntegrationPrincipal,
        plugin_health: Any = None,
        dispatcher: Any = None,
        dispatcher_runner: Any = None,
        execution_authorization_verifier: Any = None,
        message: Any = None,
        wecom_sources: Mapping[str, Any] | None = None,
        wecom_source_principal: Any = None,
        account_center: Any = None,
        connection_profile_resolver: Callable[
            [IntegrationPrincipal, CreateIntegrationConnection], str
        ]
        | None = None,
        email_delivery_recipient_resolver: Callable[[IntegrationPrincipal], str | None]
        | None = None,
        authorization_cloud: Any = None,
        current_context_resolver: Any = None,
        email_notifications: Any = None,
        authorization_cloud_runner: Any = None,
        transport_clients: tuple[Any, ...] = (),
    ) -> None:
        self.store = store
        self.authorizer = authorizer
        self.accounts = accounts
        self.github = github
        self.webhook_verifier = webhook_verifier
        self.delegation_authorizer = delegation_authorizer
        self.callback_principal = callback_principal
        self.plugin_health = plugin_health
        self.dispatcher = dispatcher
        self.dispatcher_runner = dispatcher_runner
        self.execution_authorization_verifier = execution_authorization_verifier
        self.message = message
        self.wecom_sources = dict(wecom_sources or {})
        self.wecom_source_principal = wecom_source_principal
        self.account_center = account_center
        self.connection_profile_resolver = connection_profile_resolver
        self.email_delivery_recipient_resolver = email_delivery_recipient_resolver
        self.authorization_cloud = authorization_cloud
        self.current_context_resolver = current_context_resolver
        self.email_notifications = email_notifications
        self.authorization_cloud_runner = authorization_cloud_runner
        self.transport_clients = transport_clients

    def display_name_for_connection(
        self,
        principal: IntegrationPrincipal,
        request: CreateIntegrationConnection,
    ) -> str:
        """Authorize aliases for this current principal and resolve display metadata."""

        if self.connection_profile_resolver is not None:
            try:
                display_name = self.connection_profile_resolver(principal, request)
            except PermissionError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_PROVIDER_SCOPE_FORBIDDEN",
                    title="Provider profile is not available to this actor",
                    detail=(
                        "The selected provider profile or target is outside "
                        "the current actor scope."
                    ),
                    status=403,
                ) from exc
            except Exception as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_PROVIDER_CONFIGURATION_UNAVAILABLE",
                    title="Provider connection is not configured",
                    detail="The selected provider profile is unavailable in trusted host settings.",
                    status=503,
                    retryable=True,
                ) from exc
            if not display_name.strip() or len(display_name) > 300:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_PROVIDER_CONFIGURATION_INVALID",
                    title="Provider connection is not configured",
                    detail="The configured provider profile does not expose a display name.",
                    status=503,
                )
            return display_name
        if (
            request.provider == "github"
            and request.binding_ref is None
            and request.target_ref is None
            and request.account_link_ref is None
        ):
            return request.repository_name
        raise ExchangeProductError(
            code="EXCHANGE_INTEGRATION_PROVIDER_CONFIGURATION_UNAVAILABLE",
            title="Provider connection is not configured",
            detail="Configure the selected binding and target aliases in trusted host settings.",
            status=503,
            retryable=True,
        )

    def close(self) -> None:
        """Close this Product store and the resolved capability channels."""

        close_store = getattr(self.store, "close", None)
        if callable(close_store):
            close_store()
        for client in self.transport_clients:
            close = getattr(client, "close", None)
            if callable(close):
                close()


def _operation_status(operation: Any) -> dict[str, Any]:
    """Expose only polling fields; omit intent text, actor, account, and grant refs."""

    result = getattr(operation, "result", None)
    summary: dict[str, Any] | None = None
    if isinstance(result, Mapping):
        allowed = {
            "accepted",
            "observedAt",
            "observedState",
            "reasonCode",
            "reconciledReadOnly",
            "state",
            "status",
            "succeeded",
            "version",
        }
        summary = {key: result[key] for key in allowed if key in result}
        if not summary:
            summary = None
    state = getattr(operation, "state", "")
    return {
        "operationId": str(operation.id),
        "action": str(operation.operation_id),
        "state": getattr(state, "value", str(state)),
        "issueNumber": int(operation.issue_number),
        "createdAt": operation.created_at.isoformat(),
        "updatedAt": operation.updated_at.isoformat(),
        "result": summary,
    }


def _cloud_operation_status(operation: CloudRefreshOperation) -> dict[str, Any]:
    """Map one cloud refresh onto the existing Product operation reference shape."""

    return {
        "operationId": str(operation.id),
        "action": "cloud.resources.refresh",
        "state": operation.state.value,
        "issueNumber": None,
        "connectionId": str(operation.connection_id),
        "createdAt": operation.created_at.isoformat(),
        "updatedAt": operation.updated_at.isoformat(),
        "result": operation.result,
    }


def _email_delivery_operation_status(job: Any) -> dict[str, Any]:
    """Expose only durable delivery state, never email addresses or content."""

    state = getattr(getattr(job, "state", ""), "value", str(getattr(job, "state", "")))
    public_state = {
        "READY": "QUEUED",
        "CLAIMED": "QUEUED",
        "SENDING": "RUNNING",
        "ACCEPTED": "SUCCEEDED",
        "UNKNOWN": "UNKNOWN",
        "REJECTED": "FAILED",
    }.get(state, "UNKNOWN")
    result = {
        "deliveryStatus": state,
        "deliveryConfirmed": bool(getattr(job, "delivery_confirmed", False)),
    }
    reason_code = getattr(job, "failure_reason_code", None)
    if reason_code:
        result["reasonCode"] = str(reason_code)
    return {
        "operationId": str(job.id),
        "action": "integration.notification.deliver",
        "state": public_state,
        "issueNumber": None,
        "connectionId": str(job.connection_id) if job.connection_id else None,
        "createdAt": job.created_at.isoformat(),
        "updatedAt": job.updated_at.isoformat(),
        "result": result,
    }


def _notification_response(event: IntegrationNotification) -> dict[str, Any]:
    """Project the public feed fields while omitting its internal actor scope."""

    return {
        "id": str(event.id),
        "sequence": event.sequence,
        "connectionId": str(event.connection_id) if event.connection_id else None,
        "kind": event.kind.value,
        "severity": event.severity.value,
        "title": event.title,
        "description": event.description,
        "createdAt": event.created_at,
        "actionRef": event.action_ref,
        "acknowledgedAt": event.acknowledged_at,
    }


def _connection_response(connection: Any) -> dict[str, Any]:
    """Project one connection without actor, tenant, account, or target aliases."""

    if isinstance(connection, Mapping):
        source = dict(connection)
        return {
            "id": str(source.get("id") or source.get("connectionId") or ""),
            "provider": source.get("provider", "github"),
            "displayName": source.get("displayName")
            or source.get("repositoryName")
            or source.get("provider")
            or "Integration",
            "repositoryId": source.get("repositoryId"),
            "repositoryName": source.get("repositoryName"),
            "enabled": source.get("enabled", True),
            "createdAt": source.get("createdAt"),
            "updatedAt": source.get("updatedAt"),
        }
    return {
        "id": str(connection.id),
        "provider": connection.provider,
        "displayName": connection.display_name or connection.repository_name or connection.provider,
        "repositoryId": connection.repository_id or None,
        "repositoryName": connection.repository_name or None,
        "enabled": connection.enabled,
        "createdAt": connection.created_at,
        "updatedAt": connection.updated_at,
    }


def _renewal_response(session: RenewalSessionRecord) -> dict[str, Any]:
    """Expose only the Product session ref and user-action fields."""

    return {
        "sessionRef": session.session_ref,
        "authorizationRef": session.authorization_ref,
        "state": session.state.value,
        "createdAt": session.created_at,
        "expiresAt": session.expires_at,
        "authorizationUrl": session.authorization_url,
        "qrAttachmentRef": session.qr_attachment_ref,
        "generation": session.generation,
        "reasonCode": session.reason_code,
    }


def _reauthorization_required(
    connection_id: UUID, health: AuthorizationHealthRecord
) -> ExchangeProductError:
    """Build a structured conflict from confirmed provider facts and exact stored scope."""

    if (
        health.authorization_state != AuthorizationState.REAUTHORIZATION_REQUIRED
        and health.login_state != LoginState.MISSING
    ):
        raise ValueError("reauthorization error requires confirmed provider invalidation")
    if not health.authorization_ref:
        return ExchangeProductError(
            code="EXCHANGE_INTEGRATION_AUTHORIZATION_UNAVAILABLE",
            title="Provider authorization reference unavailable",
            detail="Exchange cannot identify the actor-owned provider authorization to renew.",
            status=503,
            retryable=True,
        )
    return ExchangeProductError(
        code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
        title="Provider reauthorization required",
        detail="The provider confirmed that this connection requires user reauthorization.",
        status=409,
        resource_ref=str(connection_id),
        context={
            "connectionId": str(connection_id),
            "authorizationRef": health.authorization_ref,
        },
    )


def create_router(services: IntegrationServices) -> APIRouter:
    """Build all fixed Account Center and GitHub integration routes."""

    router = APIRouter()

    def bearer_token(request: Request) -> str:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_REQUIRED",
                title="Verified identity required",
                detail="Provide a first-party credential for Platform Authority verification.",
                status=401,
            )
        return token.strip()

    async def principal(
        request: Request,
        workspace_id: str | None,
        *,
        operation_id: str,
        resource_id: str | None = None,
    ) -> IntegrationPrincipal:
        token = request.headers.get("authorization", "")
        scheme, _, bearer = token.partition(" ")
        if token.strip() and request.headers.get("x-cyrene-execution-credential-bin"):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Integration authentication is ambiguous",
                detail=(
                    "Use either a first-party bearer or an approved Product execution credential."
                ),
                status=401,
            )
        token = bearer.strip() if scheme.lower() == "bearer" and bearer.strip() else ""
        if "workspace_id" in request.query_params:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_WORKSPACE_PARAMETER_INVALID",
                title="Workspace parameter name is invalid",
                detail=(
                    "Use the canonical workspaceId query parameter or X-Cyrene-Workspace-Id header."
                ),
                status=400,
            )
        header_workspace = request.headers.get("x-cyrene-workspace-id", "").strip()
        if workspace_id and header_workspace and workspace_id != header_workspace:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_WORKSPACE_MISMATCH",
                title="Workspace scope is ambiguous",
                detail="The workspaceId query parameter and workspace header must match.",
                status=400,
            )
        selected_workspace = workspace_id or header_workspace
        if token:
            if not selected_workspace:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_WORKSPACE_REQUIRED",
                    title="Workspace required",
                    detail="Select a workspace for Platform Authority verification.",
                    status=400,
                )
            return services.authorizer.principal_for(
                bearer_token=token, workspace_id=selected_workspace
            )

        encoded_credential = request.headers.get("x-cyrene-execution-credential-bin", "")
        if not encoded_credential or services.execution_authorization_verifier is None:
            if not encoded_credential:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_AUTH_REQUIRED",
                    title="Verified identity required",
                    detail=(
                        "Provide a first-party credential or a Platform-approved Product "
                        "execution credential."
                    ),
                    status=401,
                )
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_EXECUTION_UNAVAILABLE",
                title="Approved execution unavailable",
                detail="Configure the registered ProductWorkload Authority channel.",
                status=503,
                retryable=True,
            )
        try:
            credential_bytes = base64.b64decode(encoded_credential, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_AUTH_INVALID",
                title="Approved execution required",
                detail="The Platform execution credential is malformed.",
                status=403,
            ) from exc
        approved = services.execution_authorization_verifier.verify(credential_bytes)
        envelope = approved.canonical_envelope
        invocation = envelope.invocation
        target = envelope.target
        raw_body = await request.body()
        idempotency_key = request.headers.get("idempotency-key", "")
        query_keys = set(request.query_params.keys())
        query_workspace = request.query_params.get("workspaceId")
        if query_keys - {"workspaceId"} or len(request.query_params.getlist("workspaceId")) > 1:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail="The approved Product request cannot contain unbound query selectors.",
                status=403,
            )
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if raw_body and content_type != "application/json":
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail="The approved Product request must use application/json.",
                status=403,
            )
        required_resource = resource_id or ""
        if (
            approved.invocation_id != envelope.invocation_id
            or invocation.owner_id != "exchange"
            or invocation.operation_id != operation_id
            or invocation.resource_id != required_resource
            or target.resource_id != required_resource
            or target.http_method != request.method
            or target.endpoint != request.url.path
            or target.idempotency_key != idempotency_key
            or invocation.idempotency_key != idempotency_key
            or bytes(invocation.json_body) != raw_body
            or not envelope.organization_id
            or not envelope.workspace_id
            or not envelope.principal_issuer
            or not envelope.principal_subject
            or (selected_workspace and selected_workspace != envelope.workspace_id)
            or (query_workspace and query_workspace != envelope.workspace_id)
            or (header_workspace and header_workspace != envelope.workspace_id)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail=(
                    "The Platform approval does not bind this method, path, body, key, resource, "
                    "actor, and workspace."
                ),
                status=403,
            )
        actor = IntegrationPrincipal(
            issuer=envelope.principal_issuer,
            subject=envelope.principal_subject,
            organization_id=envelope.organization_id,
            workspace_id=envelope.workspace_id,
            allowed_operation_ids=frozenset({operation_id}),
            delegation_id=envelope.delegation_id or None,
            delegation_generation=envelope.delegation_generation or None,
            expires_at=envelope.expires_at.ToDatetime(tzinfo=UTC),
        )
        request.state.approved_execution_credential = credential_bytes
        require(actor, operation_id)
        return actor

    def require(actor: IntegrationPrincipal, operation_id: str) -> None:
        try:
            actor.require(operation_id)
        except IntegrationAuthorizationError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_PERMISSION_DENIED",
                title="Integration operation not permitted",
                detail="The verified Platform identity lacks this exact operation grant.",
                status=403,
            ) from exc

    def account_links(actor: IntegrationPrincipal) -> list[Mapping[str, Any]]:
        response = services.accounts.list_links(actor, workspace_id=actor.workspace_id)
        links = response.get("links")
        if not isinstance(links, list):
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned an invalid link projection.",
                status=502,
            )
        return [item for item in links if isinstance(item, Mapping)]

    @router.post("/api/v1/accounts/link-sessions", status_code=201, operation_id="accountBeginLink")
    async def begin_link(
        body: BeginLinkBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(request, workspace_id, operation_id="accountBeginLink")
        require(actor, "accountBeginLink")
        return services.accounts.begin_link(
            actor,
            provider=body.provider,
            workspace_id=actor.workspace_id,
            idempotency_key=idempotency_key,
        )

    @router.get("/api/v1/accounts/links", operation_id="accountListLinks")
    async def list_links(
        request: Request, workspace_id: str | None = Query(default=None, alias="workspaceId")
    ) -> dict[str, Any]:
        actor = await principal(request, workspace_id, operation_id="accountListLinks")
        require(actor, "accountListLinks")
        return {"links": account_links(actor)}

    @router.get(
        "/api/v1/accounts/github/callback",
        status_code=200,
        operation_id="accountCompleteGitHubLink",
    )
    def complete_github_link(
        state: str = Query(min_length=1, max_length=256),
        code: str = Query(min_length=1, max_length=4096),
    ) -> dict[str, Any]:
        # Account Center looks up the short-lived session by its private state digest;
        # the callback URI never accepts an actor, account, or session reference.
        return services.accounts.complete_github_link(
            services.callback_principal,
            state=state,
            code=code,
        )

    @router.post(
        "/api/v1/accounts/link-sessions/wecom/confirm",
        operation_id="accountConfirmWeComLink",
    )
    async def confirm_wecom_link(
        body: ConfirmWeComBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(request, workspace_id, operation_id="accountConfirmWeComLink")
        require(actor, "accountConfirmWeComLink")
        return services.accounts.confirm_wecom_link(
            actor,
            link_session_ref=str(body.link_session_ref),
            challenge_id=str(body.challenge_id),
            challenge_value=body.challenge_value,
            idempotency_key=idempotency_key,
        )

    @router.post(
        "/api/v1/accounts/links/{account_ref}/actions/unlink",
        operation_id="accountUnlink",
    )
    async def unlink(
        account_ref: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request, workspace_id, operation_id="accountUnlink", resource_id=str(account_ref)
        )
        require(actor, "accountUnlink")
        return services.accounts.unlink(
            actor,
            account_ref=str(account_ref),
            idempotency_key=idempotency_key,
        )

    @router.post(
        "/api/v1/integrations/connections",
        status_code=201,
        operation_id="integrationCreateConnection",
        response_model=IntegrationConnectionResponse,
    )
    async def create_connection(
        body: CreateConnectionBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> Any:
        actor = await principal(request, workspace_id, operation_id="integrationCreateConnection")
        require(actor, "integrationCreateConnection")
        create_request = CreateIntegrationConnection(
            provider=body.provider,
            binding_ref=body.binding_ref,
            target_ref=body.target_ref,
            account_link_ref=body.account_link_ref,
            repository_id=body.repository_id,
            repository_name=body.repository_name,
        )
        create_request = create_request.model_copy(
            update={"display_name": services.display_name_for_connection(actor, create_request)}
        )
        connection = services.store.create_connection(
            actor,
            create_request,
            idempotency_key=idempotency_key,
        )
        return _connection_response(connection)

    @router.get(
        "/api/v1/integrations/connections",
        operation_id="integrationListConnections",
        response_model=list[IntegrationConnectionResponse],
    )
    async def list_connections(
        request: Request, workspace_id: str | None = Query(default=None, alias="workspaceId")
    ) -> list[dict[str, Any]]:
        actor = await principal(request, workspace_id, operation_id="integrationListConnections")
        require(actor, "integrationListConnections")
        return [
            _connection_response(connection)
            for connection in services.store.list_connections(actor)
        ]

    @router.get(
        "/api/v1/integrations/connections/{connection_id}/authorization-health",
        operation_id="integrationGetAuthorizationHealth",
        response_model=AuthorizationHealthResponse,
    )
    async def get_authorization_health(
        connection_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationGetAuthorizationHealth",
            resource_id=str(connection_id),
        )
        require(actor, "integrationGetAuthorizationHealth")
        connection = services.store.get_connection(
            actor,
            connection_id,
            authorization_operation_id="integrationGetAuthorizationHealth",
        )
        health = services.store.latest_authorization_health(
            actor,
            connection_id,
            authorization_operation_id="integrationGetAuthorizationHealth",
        )
        if health is None:
            return {
                "connectionId": str(connection.id),
                "provider": connection.provider,
                "authorizationRef": None,
                "loginState": LoginState.UNKNOWN.value,
                "authorizationState": AuthorizationState.UNKNOWN.value,
                "checkedAt": None,
                "expiresAt": None,
                "generation": 0,
                "capabilities": [],
                "reasonCode": "not_observed",
            }
        return {
            "connectionId": str(connection.id),
            "provider": connection.provider,
            "authorizationRef": health.authorization_ref,
            "loginState": health.login_state.value,
            "authorizationState": health.authorization_state.value,
            "checkedAt": health.checked_at,
            "expiresAt": health.expires_at,
            "generation": health.generation,
            "capabilities": [
                capability.model_dump(mode="json", by_alias=True)
                for capability in health.capabilities
            ],
            "reasonCode": health.reason_code,
        }

    @router.post(
        "/api/v1/accounts/authorizations/{authorization_id}/renewal-sessions",
        status_code=202,
        operation_id="accountBeginRenewalSession",
        response_model=RenewalSessionResponse,
        responses={
            202: {
                "description": "Renewal session accepted; Location polls the Product session.",
                "headers": {
                    "Location": {
                        "description": "URI reference for the Product renewal session.",
                        "schema": {"type": "string", "format": "uri-reference"},
                    }
                },
            }
        },
    )
    async def begin_renewal_session(
        authorization_id: str,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> JSONResponse:
        actor = await principal(
            request,
            workspace_id,
            operation_id="accountBeginRenewalSession",
            resource_id=authorization_id,
        )
        require(actor, "accountBeginRenewalSession")
        if not CreateConnectionBody._is_opaque_alias(authorization_id):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                title="Authorization reference is invalid",
                detail="Select a server-owned opaque provider authorization reference.",
                status=422,
            )
        connection = services.store.connection_for_authorization(
            actor,
            authorization_id,
            provider="wecom",
            authorization_operation_id="accountBeginRenewalSession",
        )
        session, created = services.store.begin_renewal_session(
            actor,
            authorization_id,
            idempotency_key=idempotency_key,
        )
        can_replay_unknown = bool(
            services.authorization_cloud is not None
            and getattr(services.authorization_cloud, "supports_durable_renewal_replay", False)
        )
        should_start = (
            created
            or session.reason_code == "provider_binding_unavailable"
            or (
                not created
                and session.state == RenewalState.VERIFYING
                and session.reason_code
                in {
                    "provider_start_pending",
                    "provider_start_outcome_unknown",
                    "provider_status_lookup_unavailable",
                }
                and can_replay_unknown
            )
        )
        if should_start:
            if services.authorization_cloud is None:
                services.store.mark_renewal_start_unknown(
                    actor,
                    authorization_id,
                    session.session_ref,
                    reason_code="provider_binding_unavailable",
                )
            else:
                try:
                    provider_session = services.authorization_cloud.start_renewal(
                        actor,
                        connection,
                        authorization_id,
                        request_id=session.session_ref,
                    )
                    provider_authorization_ref = str(
                        getattr(provider_session, "authorization_ref", "")
                    )
                    if provider_authorization_ref != authorization_id:
                        raise RuntimeError("provider renewal response scope does not match")
                    session = services.store.complete_renewal_session_start(
                        actor,
                        authorization_id,
                        session.session_ref,
                        provider_session_ref=str(provider_session.session_ref),
                        state=RenewalState(provider_session.state),
                        expires_at=provider_session.expires_at,
                        authorization_url=provider_session.authorization_url,
                        qr_attachment_ref=provider_session.qr_attachment_ref,
                        generation=provider_session.generation,
                    )
                except Exception:
                    services.store.mark_renewal_start_unknown(
                        actor,
                        authorization_id,
                        session.session_ref,
                        reason_code="provider_start_outcome_unknown",
                    )
            session = services.store.get_renewal_session(
                actor,
                authorization_id,
                session.session_ref,
                authorization_operation_id="accountBeginRenewalSession",
            )
        location = f"/api/v1/accounts/renewal-sessions/{session.session_ref}"
        return JSONResponse(
            status_code=202,
            content=jsonable_encoder(_renewal_response(session)),
            headers={"Location": location},
        )

    @router.get(
        "/api/v1/accounts/renewal-sessions/{session_id}",
        operation_id="accountGetRenewalSession",
        response_model=RenewalSessionResponse,
    )
    async def get_renewal_session(
        session_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="accountGetRenewalSession",
            resource_id=str(session_id),
        )
        require(actor, "accountGetRenewalSession")
        session = services.store.get_renewal_session_by_id(
            actor,
            str(session_id),
            authorization_operation_id="accountGetRenewalSession",
        )
        services.store.connection_for_authorization(
            actor,
            session.authorization_ref,
            provider="wecom",
            authorization_operation_id="accountGetRenewalSession",
        )
        authorization_id = session.authorization_ref
        has_provider_session = session.provider_session_ref is not None
        can_lookup_unknown_start = bool(
            services.authorization_cloud is not None
            and getattr(services.authorization_cloud, "supports_request_id_status_lookup", False)
            and session.state == RenewalState.VERIFYING
            and session.reason_code == "provider_start_outcome_unknown"
        )
        if (
            (has_provider_session or can_lookup_unknown_start)
            and session.state in {RenewalState.WAITING_USER, RenewalState.VERIFYING}
            and services.authorization_cloud is not None
        ):
            try:
                status_request_id = str(uuid4())
                if session.provider_session_ref is not None:
                    provider_session = services.authorization_cloud.renewal_status(
                        actor,
                        authorization_id,
                        session.provider_session_ref,
                        request_id=status_request_id,
                    )
                else:
                    provider_session = services.authorization_cloud.renewal_status_by_request_id(
                        actor,
                        authorization_id,
                        request_id=session.session_ref,
                        status_request_id=status_request_id,
                    )
                if (
                    provider_session.authorization_ref != authorization_id
                    or not provider_session.session_ref
                    or (
                        session.provider_session_ref is not None
                        and provider_session.session_ref != session.provider_session_ref
                    )
                ):
                    raise RuntimeError("provider renewal status scope does not match")
                session = services.store.update_renewal_session_status(
                    actor,
                    authorization_id,
                    session.session_ref,
                    state=RenewalState(provider_session.state),
                    expires_at=provider_session.expires_at,
                    authorization_url=provider_session.authorization_url,
                    qr_attachment_ref=provider_session.qr_attachment_ref,
                    generation=provider_session.generation,
                    provider_session_ref=provider_session.session_ref,
                )
            except Exception:
                if session.provider_session_ref is None:
                    session = services.store.mark_renewal_status_unavailable(
                        actor,
                        authorization_id,
                        session.session_ref,
                        reason_code="provider_status_lookup_unavailable",
                    )
                else:
                    session = services.store.update_renewal_session_status(
                        actor,
                        authorization_id,
                        session.session_ref,
                        state=session.state,
                        expires_at=session.expires_at,
                        authorization_url=session.authorization_url,
                        qr_attachment_ref=session.qr_attachment_ref,
                        generation=session.generation,
                        reason_code="provider_status_unavailable",
                    )
        return _renewal_response(session)

    @router.get(
        "/api/v1/integrations/connections/{connection_id}/resources",
        operation_id="integrationListConnectionResources",
        response_model=ConnectionResourcesResponse,
        responses={409: {"$ref": "#/components/responses/Problem"}},
    )
    async def get_connection_resources(
        connection_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationListConnectionResources",
            resource_id=str(connection_id),
        )
        require(actor, "integrationListConnectionResources")
        connection = services.store.get_connection(
            actor,
            connection_id,
            authorization_operation_id="integrationListConnectionResources",
        )
        health = services.store.latest_authorization_health(
            actor,
            connection_id,
            authorization_operation_id="integrationListConnectionResources",
        )
        if health is not None and (
            health.authorization_state == AuthorizationState.REAUTHORIZATION_REQUIRED
            or health.login_state == LoginState.MISSING
        ):
            raise _reauthorization_required(connection.id, health)
        resources = services.store.list_connection_resources(actor, connection_id)
        checked_at = max((item.collected_at for item in resources), default=None)
        return {
            "connectionId": str(connection.id),
            "provider": connection.provider,
            "checkedAt": checked_at,
            "resources": [
                {
                    "externalRef": item.external_ref,
                    "kind": item.kind,
                    "displayName": item.display_name,
                    "status": item.status.value,
                    "providerStatus": item.provider_status,
                    "collectedAt": item.collected_at,
                    "observedAt": item.observed_at,
                    "source": item.source,
                    "freshness": item.freshness.value,
                    "attributes": item.attributes,
                    "platformResourceRef": item.platform_resource_ref,
                    "platformGeneration": item.platform_generation,
                }
                for item in resources
            ],
        }

    @router.post(
        "/api/v1/integrations/connections/{connection_id}/actions/refresh",
        status_code=202,
        operation_id="integrationRefreshConnectionResources",
        response_model=OperationStatusResponse,
        responses={
            202: {
                "description": "Read-only refresh accepted; Location polls the Product operation.",
                "headers": {
                    "Location": {
                        "description": "URI reference for the Product operation.",
                        "schema": {"type": "string", "format": "uri-reference"},
                    }
                },
            }
        },
    )
    async def refresh_connection_resources(
        connection_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> JSONResponse:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationRefreshConnectionResources",
            resource_id=str(connection_id),
        )
        require(actor, "integrationRefreshConnectionResources")
        connection = services.store.get_connection(
            actor,
            connection_id,
            authorization_operation_id="integrationRefreshConnectionResources",
        )
        if connection.provider not in {"azure", "gcp", "hf", "runpod", "tailscale"}:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_PROVIDER_OPERATION_UNAVAILABLE",
                title="Cloud resource refresh is unavailable",
                detail="This connection does not select a supported cloud resource provider.",
                status=422,
            )
        health = services.store.latest_authorization_health(
            actor,
            connection_id,
            authorization_operation_id="integrationRefreshConnectionResources",
        )
        if health is not None and (
            health.authorization_state == AuthorizationState.REAUTHORIZATION_REQUIRED
            or health.login_state == LoginState.MISSING
        ):
            raise _reauthorization_required(connection.id, health)
        operation = services.store.enqueue_cloud_refresh(
            actor,
            connection_id,
            idempotency_key=idempotency_key,
        )
        location = f"/api/v1/integrations/operations/{operation.id}"
        return JSONResponse(
            status_code=202,
            content=_cloud_operation_status(operation),
            headers={"Location": location},
        )

    @router.get(
        "/api/v1/integrations/notifications",
        operation_id="integrationListNotifications",
        response_model=NotificationFeedResponse,
    )
    async def list_notifications(
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=200),
    ) -> dict[str, Any]:
        actor = await principal(request, workspace_id, operation_id="integrationListNotifications")
        require(actor, "integrationListNotifications")
        events = services.store.list_notifications(
            actor,
            after_sequence=after,
            limit=limit,
            authorization_operation_id="integrationListNotifications",
        )
        return {
            "notifications": [_notification_response(event) for event in events],
            "nextSequence": events[-1].sequence if events else after,
        }

    # Direct HTTP SSE reuses the notification-feed READ grant; it has no generic JSON RPC mapping.
    @router.get(
        "/api/v1/integrations/notifications/events",
        operation_id="integrationStreamNotifications",
        response_class=StreamingResponse,
    )
    async def stream_notifications(
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        after: int = Query(default=0, ge=0),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> StreamingResponse:
        if request.headers.get("x-cyrene-execution-credential-bin"):
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Product execution credentials are not supported for notification SSE",
                detail=(
                    "The event-stream endpoint is direct Product HTTP and requires a "
                    "first-party bearer with the integrationListNotifications grant."
                ),
                status=403,
            )
        actor = await principal(request, workspace_id, operation_id="integrationListNotifications")
        require(actor, "integrationListNotifications")
        if last_event_id is not None:
            try:
                cursor = int(last_event_id)
            except ValueError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                    title="Last-Event-ID is invalid",
                    detail="Last-Event-ID must be a non-negative notification sequence.",
                    status=400,
                ) from exc
            if cursor < 0 or (after not in (0, cursor)):
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                    title="Notification cursor is ambiguous",
                    detail="Use either after or Last-Event-ID, or provide matching values.",
                    status=400,
                )
        else:
            cursor = after

        events = services.store.list_notifications(
            actor,
            after_sequence=cursor,
            limit=100,
            authorization_operation_id="integrationListNotifications",
        )

        async def event_stream() -> AsyncIterator[str]:
            yield "retry: 3000\n"
            if not events:
                yield ": keep-alive\n\n"
                return
            for event in events:
                event_json = NotificationResponse.model_validate(
                    _notification_response(event)
                ).model_dump_json(by_alias=True)
                yield f"id: {event.sequence}\nevent: notification\ndata: {event_json}\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @router.post(
        "/api/v1/integrations/notifications/{notification_id}/ack",
        operation_id="integrationAcknowledgeNotification",
        response_model=NotificationResponse,
    )
    async def acknowledge_notification(
        notification_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationAcknowledgeNotification",
            resource_id=str(notification_id),
        )
        require(actor, "integrationAcknowledgeNotification")
        event = services.store.acknowledge_notification(
            actor, notification_id, idempotency_key=idempotency_key
        )
        return _notification_response(event)

    @router.post(
        "/api/v1/integrations/notifications/{notification_id}/actions/deliver",
        status_code=202,
        operation_id="integrationDeliverNotification",
        response_model=OperationStatusResponse,
        responses={
            202: {
                "description": (
                    "Durable email delivery accepted; Location polls its Product operation."
                ),
                "headers": {
                    "Location": {
                        "description": "URI reference for the Product delivery operation.",
                        "schema": {"type": "string", "format": "uri-reference"},
                    }
                },
            }
        },
    )
    async def deliver_notification_email(
        notification_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> JSONResponse:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationDeliverNotification",
            resource_id=str(notification_id),
        )
        require(actor, "integrationDeliverNotification")
        recipient_resolver = services.email_delivery_recipient_resolver
        if recipient_resolver is None:
            raise ExchangeProductError(
                code="EXCHANGE_EMAIL_DELIVERY_UNAVAILABLE",
                title="Email delivery is not configured",
                detail=(
                    "Configure an enabled email profile and actor allowlist "
                    "before requesting delivery."
                ),
                status=503,
                retryable=True,
            )
        recipient_ref = recipient_resolver(actor)
        if not recipient_ref:
            raise ExchangeProductError(
                code="EXCHANGE_EMAIL_DELIVERY_FORBIDDEN",
                title="Email delivery is not enabled for this actor",
                detail="The current actor is not in the configured email delivery allowlist.",
                status=403,
            )
        job, _created = services.store.request_notification_email_delivery(
            actor,
            notification_id,
            recipient_ref=recipient_ref,
            idempotency_key=idempotency_key,
        )
        location = f"/api/v1/integrations/operations/{job.id}"
        return JSONResponse(
            status_code=202,
            content=_email_delivery_operation_status(job),
            headers={"Location": location},
        )

    @router.post(
        "/api/v1/integrations/sync-bindings",
        status_code=201,
        operation_id="integrationCreateBinding",
    )
    async def create_binding(
        body: CreateBindingBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> Any:
        actor = await principal(request, workspace_id, operation_id="integrationCreateBinding")
        require(actor, "integrationCreateBinding")
        services.store.get_connection(
            actor, body.connection_id, authorization_operation_id="integrationCreateBinding"
        )
        return services.store.create_binding(
            actor,
            CreateSyncBinding(
                connection_id=body.connection_id,
                notification_target_ref=body.notification_target_ref,
            ),
            idempotency_key=idempotency_key,
        )

    @router.get("/api/v1/integrations/sync-bindings", operation_id="integrationListBindings")
    async def list_bindings(
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        connection_id: UUID | None = None,
    ) -> list[Any]:
        actor = await principal(request, workspace_id, operation_id="integrationListBindings")
        require(actor, "integrationListBindings")
        return services.store.list_bindings(actor, connection_id=connection_id)

    @router.post(
        "/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings",
        status_code=201,
        operation_id="integrationAttachActorBinding",
    )
    async def attach_actor_binding(
        binding_id: UUID,
        body: AttachActorBindingBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> Any:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationAttachActorBinding",
            resource_id=str(binding_id),
        )
        require(actor, "integrationAttachActorBinding")
        services.store.get_binding(
            actor, binding_id, authorization_operation_id="integrationAttachActorBinding"
        )
        linked_account = next(
            (
                item
                for item in account_links(actor)
                if str(item.get("account_ref")) == body.account_link_ref
                and item.get("provider") == "github"
                and item.get("status") == "active"
                and item.get("workspace_id") in (None, actor.workspace_id)
            ),
            None,
        )
        if linked_account is None:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_LINK_INVALID",
                title="GitHub account link unavailable",
                detail="Attach an active GitHub account owned by the verified member.",
                status=403,
            )
        authority_bearer: str | None = None
        authority_execution_credential = getattr(
            request.state, "approved_execution_credential", None
        )
        if authority_execution_credential is None:
            authority_bearer = bearer_token(request)
        try:
            services.delegation_authorizer.validate_binding(
                actor,
                bearer_token=authority_bearer,
                execution_credential=authority_execution_credential,
                delegation_ref=body.delegation_ref,
                binding_id=binding_id,
                account_link_ref=body.account_link_ref,
            )
        except PermissionError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_DELEGATION_INVALID",
                title="Platform delegation is not valid for this binding",
                detail="Attach an active grant owned by this member and scoped to this binding.",
                status=403,
            ) from exc
        from cyrene_exchange_product.integrations.models import CreateActorBinding

        return services.store.create_actor_binding(
            actor,
            CreateActorBinding(
                binding_id=binding_id,
                account_link_ref=body.account_link_ref,
                delegation_ref=body.delegation_ref,
            ),
            idempotency_key=idempotency_key,
        )

    @router.get(
        "/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings",
        operation_id="integrationListActorBindings",
    )
    async def list_actor_bindings(
        binding_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> list[Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationListActorBindings",
            resource_id=str(binding_id),
        )
        require(actor, "integrationListActorBindings")
        return services.store.list_actor_bindings(actor, binding_id)

    @router.get(
        "/api/v1/integrations/jobs",
        operation_id="integrationListJobs",
        response_model=list[IntegrationJobResponse],
    )
    async def list_jobs(
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        from cyrene_exchange_product.integrations.models import JobState

        actor = await principal(request, workspace_id, operation_id="integrationListJobs")
        require(actor, "integrationListJobs")
        try:
            selected_state = JobState(state) if state is not None else None
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                title="Invalid job state",
                detail="Select a supported integration job state.",
                status=422,
            ) from exc
        return [
            {
                "jobId": str(job.id),
                "kind": job.kind,
                "state": job.state.value,
                "attempts": job.attempts,
                "operationId": str(job.operation_id) if job.operation_id else None,
                "createdAt": job.created_at,
                "updatedAt": job.updated_at,
                "availableAt": job.available_at,
            }
            for job in services.store.list_jobs(actor, state=selected_state)
        ]

    @router.get(
        "/api/v1/integrations/connections/{connection_id}/health",
        operation_id="integrationGetConnectionHealth",
        response_model=ConnectionHealthResponse,
    )
    async def get_connection_health(
        connection_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationGetConnectionHealth",
            resource_id=str(connection_id),
        )
        require(actor, "integrationGetConnectionHealth")
        services.store.get_connection(
            actor,
            connection_id,
            authorization_operation_id="integrationGetConnectionHealth",
        )
        try:
            observation = (
                services.plugin_health.observe()
                if services.plugin_health is not None
                else PluginHealthObservation(
                    status="UNKNOWN",
                    observed_at=datetime.now(UTC),
                    error_code="plugin_health_unavailable",
                )
            )
        except Exception:
            observation = PluginHealthObservation(
                status="UNKNOWN",
                observed_at=datetime.now(UTC),
                error_code="plugin_health_unavailable",
            )
        status = observation.status
        if status not in {"SERVING", "NOT_SERVING", "UNKNOWN"}:
            status = "UNKNOWN"
        return {
            "status": status,
            "observedAt": observation.observed_at,
            "pluginId": observation.plugin_id,
            "pluginVersion": observation.plugin_version,
            "capabilities": list(observation.capabilities),
            "errorCode": observation.error_code,
        }

    @router.get(
        "/api/v1/integrations/operations/{operation_id}",
        operation_id="integrationGetOperation",
        response_model=OperationStatusResponse,
    )
    async def get_operation(
        operation_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> Any:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationGetOperation",
            resource_id=str(operation_id),
        )
        require(actor, "integrationGetOperation")
        try:
            operation = services.store.get_operation(actor, operation_id)
        except IntegrationNotFound:
            try:
                cloud_operation = services.store.get_cloud_refresh_operation(actor, operation_id)
            except IntegrationNotFound:
                return _email_delivery_operation_status(
                    services.store.get_email_notification_job(actor, operation_id)
                )
            return _cloud_operation_status(cloud_operation)
        return _operation_status(operation)

    @router.post(
        "/api/v1/integrations/operations/{operation_id}/actions/reconcile",
        operation_id="integrationReconcile",
        response_model=OperationStatusResponse,
    )
    async def reconcile_operation(
        operation_id: UUID,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> Any:
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationReconcile",
            resource_id=str(operation_id),
        )
        require(actor, "integrationReconcile")
        if services.dispatcher is None:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_RECONCILER_UNAVAILABLE",
                title="Integration reconciliation unavailable",
                detail=(
                    "Configure the production Platform and provider clients before reconciliation."
                ),
                status=503,
                retryable=True,
            )
        return _operation_status(
            services.dispatcher.reconcile_operation(
                actor,
                operation_id,
                idempotency_key=idempotency_key,
            )
        )

    def execute_authorized(
        *,
        action: str,
        binding_id: UUID,
        body: ExecuteIssueBody,
        request: Request,
        raw_body: bytes,
        execution_credential: str | None,
        idempotency_key: str | None,
    ) -> Any:
        if services.execution_authorization_verifier is None or services.dispatcher is None:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_EXECUTION_UNAVAILABLE",
                title="Approved execution unavailable",
                detail="Configure the registered ProductWorkload Authority channel and dispatcher.",
                status=503,
                retryable=True,
            )
        if not execution_credential or not idempotency_key:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_AUTH_REQUIRED",
                title="Approved execution required",
                detail=(
                    "Platform must dispatch this operation with its signed execution credential."
                ),
                status=401,
            )
        if request.headers.get("authorization", "").strip():
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Integration authentication is ambiguous",
                detail="The Authority execution route accepts only its approved credential.",
                status=401,
            )
        try:
            credential_bytes = base64.b64decode(execution_credential, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_AUTH_INVALID",
                title="Approved execution required",
                detail="The Platform execution credential is malformed.",
                status=403,
            ) from exc
        approved = services.execution_authorization_verifier.verify(credential_bytes)
        envelope = approved.canonical_envelope
        invocation = envelope.invocation
        target = envelope.target
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if (
            content_type != "application/json"
            or request.url.query
            or bytes(invocation.json_body) != raw_body
        ):
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail=(
                    "The request content type, path, or raw body does not match Platform approval."
                ),
                status=403,
            )
        operation_map = {
            "comment": "integrationExecuteIssueComment",
            "state": "integrationExecuteIssueState",
            "query": "integrationExecuteIssueQuery",
        }
        execution_operation_id = operation_map[action]
        expected_path = request.url.path
        if (
            approved.invocation_id != envelope.invocation_id
            or invocation.owner_id != "exchange"
            or invocation.operation_id != execution_operation_id
            or invocation.resource_id != str(binding_id)
            or target.resource_id != str(binding_id)
            or target.http_method != "POST"
            or target.endpoint != expected_path
            or target.idempotency_key != idempotency_key
            or invocation.idempotency_key != idempotency_key
            or not envelope.organization_id
            or not envelope.workspace_id
            or not envelope.principal_issuer
            or not envelope.principal_subject
        ):
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail=(
                    "The Platform approval does not bind this method, path, body, key, and "
                    "resource."
                ),
                status=403,
            )
        actor = IntegrationPrincipal(
            issuer=envelope.principal_issuer,
            subject=envelope.principal_subject,
            organization_id=envelope.organization_id,
            workspace_id=envelope.workspace_id,
            allowed_operation_ids=frozenset({execution_operation_id}),
            delegation_id=envelope.delegation_id or None,
            delegation_generation=envelope.delegation_generation or None,
            expires_at=envelope.expires_at.ToDatetime(tzinfo=UTC),
        )
        require(actor, execution_operation_id)
        try:
            body_document = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail="The approved Product execution body is not valid JSON.",
                status=403,
            ) from exc
        if body_document != {
            "operationId": str(body.operation_id),
            "argumentDigest": body.argument_digest,
        }:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_BINDING_MISMATCH",
                title="Approved execution does not match request",
                detail=(
                    "The approved Product execution body does not match the stored operation "
                    "selector."
                ),
                status=403,
            )
        proof = ValidatedExecutionProof(
            invocation_id=str(approved.invocation_id),
            owner=str(invocation.owner_id),
            issuer=str(envelope.principal_issuer),
            subject=str(envelope.principal_subject),
            organization_id=str(envelope.organization_id),
            workspace_id=str(envelope.workspace_id),
            http_method=str(target.http_method),
            path=str(target.endpoint),
            content_type="application/json",
            idempotency_key=str(target.idempotency_key),
            execution_operation_id=str(invocation.operation_id),
            operation_id=str(body.operation_id),
            binding_id=str(invocation.resource_id),
            argument_digest=body.argument_digest,
            raw_body=raw_body,
            raw_body_sha256=hashlib.sha256(raw_body).hexdigest(),
        )
        try:
            return services.dispatcher.execute_authorized_action(
                actor,
                body.operation_id,
                binding_id=binding_id,
                execution_operation_id=execution_operation_id,
                argument_digest=body.argument_digest,
                authority_invocation_id=approved.invocation_id,
                authority_evidence=proof,
            )
        except TypeError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_ADAPTER_INVALID",
                title="Execution adapter configuration invalid",
                detail="The configured dispatcher does not accept validated Authority evidence.",
                status=503,
            ) from exc

    @router.post(
        "/api/v1/integrations/sync-bindings/{bindingId}/execute-issue-comment",
        operation_id="integrationExecuteIssueComment",
    )
    async def execute_issue_comment(
        body: ExecuteIssueBody,
        request: Request,
        binding_id: Annotated[UUID, ApiPath(alias="bindingId")],
        execution_credential: str | None = Header(
            default=None, alias="x-cyrene-execution-credential-bin"
        ),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> Any:
        raw_body = await request.body()
        return execute_authorized(
            action="comment",
            binding_id=binding_id,
            body=body,
            request=request,
            raw_body=raw_body,
            execution_credential=execution_credential,
            idempotency_key=idempotency_key,
        )

    @router.post(
        "/api/v1/integrations/sync-bindings/{bindingId}/execute-issue-state",
        operation_id="integrationExecuteIssueState",
    )
    async def execute_issue_state(
        body: ExecuteIssueBody,
        request: Request,
        binding_id: Annotated[UUID, ApiPath(alias="bindingId")],
        execution_credential: str | None = Header(
            default=None, alias="x-cyrene-execution-credential-bin"
        ),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> Any:
        raw_body = await request.body()
        return execute_authorized(
            action="state",
            binding_id=binding_id,
            body=body,
            request=request,
            raw_body=raw_body,
            execution_credential=execution_credential,
            idempotency_key=idempotency_key,
        )

    @router.post(
        "/api/v1/integrations/sync-bindings/{bindingId}/execute-issue-query",
        operation_id="integrationExecuteIssueQuery",
    )
    async def execute_issue_query(
        body: ExecuteIssueBody,
        request: Request,
        binding_id: Annotated[UUID, ApiPath(alias="bindingId")],
        execution_credential: str | None = Header(
            default=None, alias="x-cyrene-execution-credential-bin"
        ),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
    ) -> Any:
        raw_body = await request.body()
        return execute_authorized(
            action="query",
            binding_id=binding_id,
            body=body,
            request=request,
            raw_body=raw_body,
            execution_credential=execution_credential,
            idempotency_key=idempotency_key,
        )

    @router.post(
        "/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/comment",
        status_code=202,
        operation_id="integrationCreateIssueComment",
        response_model=OperationStatusResponse,
        responses={
            202: {
                "description": "Operation accepted; Location identifies the Product operation.",
                "headers": {
                    "Location": {
                        "description": "URI reference for polling the Product operation.",
                        "schema": {"type": "string", "format": "uri-reference"},
                    }
                },
            }
        },
    )
    async def create_issue_comment(
        binding_id: UUID,
        body: CommentBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> JSONResponse:
        issue_number = body.issue_number
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationCreateIssueComment",
            resource_id=str(binding_id),
        )
        require(actor, "integrationCreateIssueComment")
        binding = services.store.get_binding(
            actor, binding_id, authorization_operation_id="integrationCreateIssueComment"
        )
        operation = services.store.enqueue_issue_action(
            actor,
            EnqueueIssueAction(
                connection_id=binding.connection_id,
                binding_id=binding_id,
                operation_id="integration.issue.comment",
                idempotency_key=idempotency_key,
                issue_number=issue_number,
                body=body.body,
            ),
            authorization_operation_id="integrationCreateIssueComment",
        )
        location = f"/api/v1/integrations/operations/{operation.id}"
        return JSONResponse(
            status_code=202,
            content=_operation_status(operation),
            headers={"Location": location},
        )

    @router.post(
        "/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/state",
        status_code=202,
        operation_id="integrationUpdateIssueState",
        response_model=OperationStatusResponse,
        responses={
            202: {
                "description": "Operation accepted; Location identifies the Product operation.",
                "headers": {
                    "Location": {
                        "description": "URI reference for polling the Product operation.",
                        "schema": {"type": "string", "format": "uri-reference"},
                    }
                },
            }
        },
    )
    async def update_issue_state(
        binding_id: UUID,
        body: StateBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> JSONResponse:
        issue_number = body.issue_number
        actor = await principal(
            request,
            workspace_id,
            operation_id="integrationUpdateIssueState",
            resource_id=str(binding_id),
        )
        require(actor, "integrationUpdateIssueState")
        binding = services.store.get_binding(
            actor, binding_id, authorization_operation_id="integrationUpdateIssueState"
        )
        operation_id: Literal["integration.issue.close", "integration.issue.reopen"] = (
            "integration.issue.close" if body.state == "CLOSED" else "integration.issue.reopen"
        )
        operation = services.store.enqueue_issue_action(
            actor,
            EnqueueIssueAction(
                connection_id=binding.connection_id,
                binding_id=binding_id,
                operation_id=operation_id,
                idempotency_key=idempotency_key,
                issue_number=issue_number,
            ),
            authorization_operation_id="integrationUpdateIssueState",
        )
        location = f"/api/v1/integrations/operations/{operation.id}"
        return JSONResponse(
            status_code=202,
            content=_operation_status(operation),
            headers={"Location": location},
        )

    @router.post(
        "/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/snapshot",
        operation_id="integrationGetIssue",
        response_model=IssueSnapshotResponse,
    )
    async def get_issue_snapshot(
        binding_id: UUID,
        body: QueryIssueBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
    ) -> dict[str, Any]:
        issue_number = body.issue_number
        actor = await principal(
            request, workspace_id, operation_id="integrationGetIssue", resource_id=str(binding_id)
        )
        require(actor, "integrationGetIssue")
        binding = services.store.get_binding(
            actor, binding_id, authorization_operation_id="integrationGetIssue"
        )
        connection = services.store.get_connection(
            actor, binding.connection_id, authorization_operation_id="integrationGetIssue"
        )
        snapshots = services.store.list_snapshots(
            actor,
            "github.issue",
            f"{connection.repository_id}#{issue_number}",
        )
        if not snapshots:
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_ISSUE_SNAPSHOT_NOT_FOUND",
                title="GitHub issue snapshot unavailable",
                detail="Request an Authority-approved issue query before reading this issue.",
                status=404,
            )
        snapshot = snapshots[0]
        state = snapshot.document.get("state")
        title = snapshot.document.get("title")
        if state not in {"OPEN", "CLOSED"} or not isinstance(title, str):
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_PROVIDER_RESPONSE_INVALID",
                title="GitHub issue snapshot invalid",
                detail="The stored issue snapshot has an invalid public projection.",
                status=502,
            )
        return {
            "issueNumber": issue_number,
            "state": state,
            "title": title,
            "version": snapshot.version,
            "freshness": snapshot.freshness.value,
            "observedAt": snapshot.observed_at.isoformat(),
        }

    @router.post(
        "/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/query",
        status_code=202,
        operation_id="integrationQueryIssue",
        response_model=OperationStatusResponse,
        responses={
            202: {
                "description": "Operation accepted; Location identifies the Product operation.",
                "headers": {
                    "Location": {
                        "description": "URI reference for polling the Product operation.",
                        "schema": {"type": "string", "format": "uri-reference"},
                    }
                },
            }
        },
    )
    async def query_issue(
        binding_id: UUID,
        body: QueryIssueBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> JSONResponse:
        issue_number = body.issue_number
        actor = await principal(
            request, workspace_id, operation_id="integrationQueryIssue", resource_id=str(binding_id)
        )
        require(actor, "integrationQueryIssue")
        binding = services.store.get_binding(
            actor, binding_id, authorization_operation_id="integrationQueryIssue"
        )
        operation = services.store.enqueue_issue_action(
            actor,
            EnqueueIssueAction(
                connection_id=binding.connection_id,
                binding_id=binding_id,
                operation_id="integration.issue.query",
                idempotency_key=idempotency_key,
                issue_number=issue_number,
            ),
            authorization_operation_id="integrationQueryIssue",
        )
        location = f"/api/v1/integrations/operations/{operation.id}"
        return JSONResponse(
            status_code=202,
            content=_operation_status(operation),
            headers={"Location": location},
        )

    @router.post(
        "/api/v1/integrations/hooks/github/{connection_id}",
        status_code=202,
        operation_id="integrationReceiveGitHubWebhook",
    )
    async def receive_github_webhook(
        connection_id: UUID,
        request: Request,
        delivery_id: str = Header(alias="X-GitHub-Delivery", min_length=1, max_length=200),
        event_name: str = Header(alias="X-GitHub-Event", min_length=1, max_length=50),
        signature: str = Header(alias="X-Hub-Signature-256", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        raw_body = await request.body()
        if len(raw_body) > 1_000_000:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                title="Webhook payload too large",
                detail="GitHub webhook body exceeds the configured size limit.",
                status=413,
            )
        if event_name not in {"issues", "issue_comment"}:
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_WEBHOOK_INVALID",
                title="GitHub webhook event unsupported",
                detail="Only issue and issue-comment webhook events are accepted.",
                status=400,
            )
        try:
            normalized = services.webhook_verifier.verify_and_normalize(
                delivery_id=delivery_id,
                event_name=event_name,
                signature=signature,
                body=raw_body,
            )
            event_model = _normalized_event(normalized)
            event = services.store.ingest_github_event(
                connection_id,
                delivery_id,
                event_model,
                verified=True,
            )
        except ExchangeProductError:
            raise
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_WEBHOOK_INVALID",
                title="GitHub webhook rejected",
                detail="GitHub webhook verification or normalization failed.",
                status=401,
            ) from exc
        return {"eventId": str(event.id), "state": event.state}

    if services.wecom_sources:
        from cyrene_exchange_product.integrations.intake import register_wecom_routes

        register_wecom_routes(router, services)
    execution_only = {
        "integrationExecuteIssueComment",
        "integrationExecuteIssueState",
        "integrationExecuteIssueQuery",
    }
    native_auth = {
        "accountCompleteGitHubLink",
        "integrationAdmitWeComInbound",
        "integrationReceiveGitHubWebhook",
        "integrationReceiveWeComWebhook",
    }
    for route in router.routes:
        if not isinstance(route, APIRoute) or route.operation_id in native_auth:
            continue
        extra = dict(route.openapi_extra or {})
        extra["security"] = (
            [{"ProductExecutionCredential": []}]
            if route.operation_id in execution_only
            else [
                {"IntegrationBearer": []},
                {"ProductExecutionCredential": []},
            ]
        )
        if route.operation_id not in execution_only:
            parameters = list(extra.get("parameters", []))
            if not any(
                isinstance(parameter, Mapping) and parameter.get("name") == "X-Cyrene-Workspace-Id"
                for parameter in parameters
            ):
                parameters.append(
                    {
                        "name": "X-Cyrene-Workspace-Id",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "Workspace scope for first-party bearer requests.",
                    }
                )
            extra["parameters"] = parameters
        route.openapi_extra = extra
    return router


def _normalized_event(value: Mapping[str, Any]) -> Any:
    """Validate the allowlisted normalized webhook shape before persistence."""

    from cyrene_exchange_product.integrations.models import NormalizedGitHubEvent

    try:
        return NormalizedGitHubEvent.model_validate(value)
    except Exception as exc:
        raise ExchangeProductError(
            code="EXCHANGE_GITHUB_WEBHOOK_INVALID",
            title="GitHub webhook rejected",
            detail="The GitHub capability returned an invalid normalized event.",
            status=400,
        ) from exc
