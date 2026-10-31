"""Versioned HTTP facade for linked accounts and fixed connector operations.

Public identity is derived only from Platform verification. Webhook bytes are
verified by the configured GitHub capability before Exchange persists events;
host runner operations remain tied to one private binding and exact grant.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import UTC, datetime
from functools import partial
from math import floor
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import parse_qsl, urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from fastapi import APIRouter, Header, Query, Request
from fastapi import Path as ApiPath
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    model_validator,
)
from pydantic.alias_generators import to_camel

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    microsoft_graph_office_v2_scope,
)
from cyrene_exchange_product.integrations.azure_devops import (
    public_profile_scope as azure_devops_public_profile_scope,
)
from cyrene_exchange_product.integrations.azure_devops import (
    scope_for_authorized_source as azure_devops_scope_for_authorized_source,
)
from cyrene_exchange_product.integrations.azure_devops import (
    validate_profile_identity as validate_azure_devops_profile_identity,
)
from cyrene_exchange_product.integrations.clients import AccountCenterClient, GitHubIssuesClient
from cyrene_exchange_product.integrations.connector_operations import (
    teams_personal_resource_ref,
)
from cyrene_exchange_product.integrations.connector_profiles import (
    validate_teams_root_thread_id,
    validate_teams_service_url,
)
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    connector_canonical_json,
    digest_arguments,
    navigator_hmac_body_limit,
    parse_signed_json_object,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    OFFICE_V2_REDIRECT_URI,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    profile_scope_metadata as microsoft_graph_profile_scope_metadata,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    public_profile_scope as microsoft_graph_public_profile_scope,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    validate_profile_identity as validate_microsoft_graph_profile_identity,
)
from cyrene_exchange_product.integrations.microsoft_identity import (
    MicrosoftActorMismatch,
    microsoft_identity_for_principal,
)
from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudRefreshOperation,
    CreateIntegrationConnection,
    CreateSyncBinding,
    EnqueueIssueAction,
    IntegrationAuthorizationError,
    IntegrationConflict,
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
    TeamsMessagePort,
    ValidatedExecutionProof,
)
from cyrene_exchange_product.integrations.store import (
    ConnectorInvocationLedgerFull,
    ConnectorInvocationReservation,
    IntegrationStore,
)

_MAX_NAVIGATOR_REQUEST_BYTES = 128 * 1024
_SAFE_HEALTH_REASON_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")


def _safe_health_reason_code(value: object) -> str | None:
    """Expose only bounded code-shaped health reasons, never provider prose."""

    if isinstance(value, str) and _SAFE_HEALTH_REASON_CODE.fullmatch(value):
        return value
    return None


def _connection_for_renewal(
    store: IntegrationStore,
    principal: IntegrationPrincipal,
    authorization_ref: str,
    *,
    operation_id: str,
) -> Any:
    """Resolve one actor-owned WeCom or HF connection for its stored auth ref."""

    selected = []
    for provider in ("wecom", "hf"):
        try:
            selected.append(
                store.connection_for_authorization(
                    principal,
                    authorization_ref,
                    provider=provider,
                    authorization_operation_id=operation_id,
                )
            )
        except IntegrationNotFound:
            continue
    if not selected:
        raise IntegrationNotFound("authorization is not attached to this actor's connection")
    if len(selected) != 1:
        raise IntegrationConflict("authorization reference matches multiple provider bindings")
    return selected[0]


def _require_supported_renewal_profile(
    services: Any,
    principal: IntegrationPrincipal,
    connection: Any,
    *,
    operation_id: str,
) -> None:
    """Reject HF renewal before persisting intent unless the host profile is device OAuth."""

    if connection.provider != "hf":
        return
    registry = services.authorization_profile_registry
    if registry is None:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_RENEWAL_UNAVAILABLE",
            title="Hugging Face renewal is unavailable",
            detail="The fixed Hugging Face authorization profile is not configured.",
            status=503,
            context={"reasonCode": "huggingface_host_profile_unavailable"},
        )
    try:
        profile, _target_ref = registry.profile_for_connection(
            principal,
            connection,
            operation_id=operation_id,
        )
    except PermissionError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Hugging Face profile is unavailable",
            detail="The selected Hugging Face profile is outside this verified actor scope.",
            status=403,
            context={"reasonCode": "huggingface_profile_scope_mismatch"},
        ) from exc
    if profile.provider != "hf" or profile.auth_mode != "device_oauth":
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_RENEWAL_UNSUPPORTED",
            title="Hugging Face renewal is unsupported",
            detail="Only a linked Hugging Face device OAuth profile can start device renewal.",
            status=409,
            context={"reasonCode": "huggingface_device_oauth_required"},
        )


def _ensure_cloud_identity_profile(
    services: Any,
    principal: IntegrationPrincipal,
    *,
    connection: Any,
    profile: Any,
    target_alias: str,
) -> None:
    """Idempotently register/read back one host-owned non-secret cloud profile."""

    target = profile.targets.get(target_alias)
    if target is None:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Cloud profile is not configured",
            detail="The selected cloud target is not in trusted host settings.",
            status=403,
        )
    profile_ref = connection.account_link_ref
    if not isinstance(profile_ref, str) or not profile_ref:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center profile reference is unavailable",
            detail="The fixed cloud identity profile reference is invalid.",
            status=502,
        )
    expected = {
        "profile_ref": profile_ref,
        "provider": connection.provider,
        "identity_ref": profile.identity_ref or profile.profile_ref,
        "target_scope": {
            "target_ref": target_alias,
            "provider_target_ref": target.target_ref,
        },
        "access_mode": connection.access_mode,
    }

    def readback() -> Mapping[str, Any] | None:
        response = services.accounts.list_provider_profiles(principal)
        rows = response.get("profiles") if isinstance(response, Mapping) else None
        if not isinstance(rows, list):
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned malformed cloud profile metadata.",
                status=502,
            )
        matches = [
            row
            for row in rows
            if isinstance(row, Mapping) and row.get("profile_ref") == profile_ref
        ]
        if len(matches) > 1:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned duplicate cloud profile metadata.",
                status=502,
            )
        if not matches:
            return None
        row = matches[0]
        if (
            any(row.get(key) != value for key, value in expected.items())
            or row.get("auth_mode") != "host_identity"
            or row.get("auth_status") not in {"unknown", "configured", "healthy"}
            or row.get("external_subject") is not None
            or row.get("expires_at") is not None
        ):
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned a mismatched cloud identity profile.",
                status=502,
                context={"reasonCode": "cloud_identity_profile_scope_mismatch"},
            )
        return row

    if readback() is None:
        services.accounts.register_host_identity_profile(
            principal,
            profile_ref=profile_ref,
            provider=connection.provider,
            identity_ref=str(expected["identity_ref"]),
            target_scope=expected["target_scope"],
            idempotency_key=f"connection-profile:{connection.id}",
        )
        if readback() is None:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center profile readback is unavailable",
                detail="Account Center did not persist the host cloud identity profile.",
                status=502,
            )


async def _invoke_connector_dispatcher(
    dispatcher: Any,
    prepared: Any,
    *,
    principal: IntegrationPrincipal,
    claims: ConnectorGrantClaims,
) -> dict[str, Any]:
    """Run blocking provider RPCs on FastAPI's bounded worker pool.

    Provider calls can span Account Center lease minting and vendor HTTPS I/O.
    Keeping that synchronous chain off the event loop lets chat and health
    requests continue while the fixed RPC deadline is in flight.
    中文：连接器调用会串行访问租约服务与供应商 API，不能阻塞聊天事件循环。
    """

    invoke = partial(dispatcher.invoke, prepared, principal=principal, claims=claims)
    return await run_in_threadpool(invoke)


def _http_utc_timestamp(value: datetime | None) -> str | None:
    """Serialize an aware timestamp in the public UTC-Z wire form."""

    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("HTTP timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _http_utc_timestamp_text(value: str | None) -> str | None:
    """Normalize one stored RFC3339 timestamp without changing persistence."""

    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return _http_utc_timestamp(parsed)


def _http_timestamp_value(value: datetime | str | None) -> str | None:
    """Normalize one known timestamp value from a model or stored string."""

    if isinstance(value, datetime):
        return _http_utc_timestamp(value)
    if isinstance(value, str):
        return _http_utc_timestamp_text(value)
    return None


async def _read_bounded_request_body(
    request: Request,
    *,
    max_bytes: int = _MAX_NAVIGATOR_REQUEST_BYTES,
) -> bytes:
    """Read a request stream with a fixed upper bound before parsing JSON."""

    content_length = request.headers.get("content-length")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdecimal():
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="The internal request Content-Length is invalid.",
                status=400,
            )
        if int(content_length) > max_bytes:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_TOO_LARGE",
                title="Connector request is too large",
                detail="The signed connector request exceeds the configured size limit.",
                status=413,
            )
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_TOO_LARGE",
                title="Connector request is too large",
                detail="The signed connector request exceeds the configured size limit.",
                status=413,
            )
        chunks.append(chunk)
    return b"".join(chunks)


class _HttpResponseModel(BaseModel):
    """Serialize typed datetime values to the Product HTTP UTC-Z convention."""

    @field_serializer("*", when_used="json", check_fields=False)
    def _serialize_datetime_utc(self, value: Any) -> Any:
        if isinstance(value, datetime):
            return _http_utc_timestamp(value)
        return value


class IntegrationRequestBody(_HttpResponseModel):
    """Closed public JSON DTOs use camelCase while retaining internal field names."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
    )


class BeginLinkBody(IntegrationRequestBody):
    """Fixed external account provider selector."""

    provider: str = Field(pattern="^(github|wecom)$")


class GitHubInstallationRepositoryBody(IntegrationRequestBody):
    """One selected repository in a verified GitHub App installation."""

    repository_id: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=300)
    name: str = Field(min_length=1, max_length=300)


class LinkGitHubInstallationBody(IntegrationRequestBody):
    """Non-secret App installation selector and bounded repository scope."""

    installation_id: str = Field(min_length=1, max_length=100)
    repositories: list[GitHubInstallationRepositoryBody] = Field(min_length=1, max_length=200)


class LinkHuggingFaceProfileBody(IntegrationRequestBody):
    """Select only a host-defined HF profile alias; token and scopes stay host-owned."""

    profile_alias: str = Field(min_length=1, max_length=300)


class BeginMicrosoftGraphLinkBody(IntegrationRequestBody):
    """Select one fixed host Graph binding whose plan IDs Exchange controls."""

    binding_ref: str = Field(min_length=1, max_length=300)


class BeginAzureDevOpsLinkBody(IntegrationRequestBody):
    """Select one fixed host binding/source alias for delegated ADO consent."""

    binding_ref: str = Field(min_length=1, max_length=300)
    source_id: str = Field(min_length=1, max_length=300)


class SelectMicrosoftGraphSharePointScopeBody(IntegrationRequestBody):
    """Select only a host binding whose site/list allowlist is fixed."""

    binding_ref: str = Field(min_length=1, max_length=300)


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
        elif self.provider in {"azure", "azure_devops", "gcp", "hf", "runpod", "tailscale"}:
            if self.binding_ref is None or self.target_ref is None:
                raise ValueError("cloud connections require bindingRef and targetRef")
        elif self.provider == "wecom" and self.binding_ref is None:
            raise ValueError("WeCom authorization connections require bindingRef")
        elif self.provider == "microsoft_graph":
            if not self.account_link_ref or not self.binding_ref or self.target_ref is not None:
                raise ValueError(
                    "Microsoft Graph connections require an Account Center profile and host binding"
                )
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


class OperationStatusResponse(_HttpResponseModel):
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


class IssueSnapshotResponse(_HttpResponseModel):
    """Actor-scoped cached issue snapshot after an approved query succeeds."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    issue_number: int = Field(alias="issueNumber")
    state: Literal["OPEN", "CLOSED"]
    title: str
    version: str
    freshness: Literal["FRESH", "STALE", "UNKNOWN"]
    observed_at: str = Field(alias="observedAt")


class ConnectionHealthResponse(_HttpResponseModel):
    """Read-only DirectPluginRuntime Health observation for a fixed connection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: Literal["SERVING", "NOT_SERVING", "UNKNOWN"]
    observed_at: datetime = Field(alias="observedAt")
    plugin_id: str | None = Field(default=None, alias="pluginId")
    plugin_version: str | None = Field(default=None, alias="pluginVersion")
    capabilities: list[str]
    error_code: str | None = Field(default=None, alias="errorCode")


class IntegrationConnectionResponse(_HttpResponseModel):
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


class AuthorizationCapabilityResponse(_HttpResponseModel):
    """Actor-safe projection of one provider capability authorization state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    capability_id: str = Field(alias="capabilityId")
    state: Literal[
        "VALID", "REAUTHORIZATION_REQUIRED", "PERMISSION_DENIED", "UNKNOWN", "UNAVAILABLE"
    ]
    last_verified_at: datetime | None = Field(default=None, alias="lastVerifiedAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    reason_code: str | None = Field(default=None, alias="reasonCode")


class AuthorizationHealthResponse(_HttpResponseModel):
    """Latest durable authorization observation or explicit UNKNOWN before first check."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    connection_id: str = Field(alias="connectionId")
    provider: ProviderId
    external_subject: str | None = Field(default=None, alias="externalSubject")
    authorization_ref: str | None = Field(default=None, alias="authorizationRef")
    login_state: Literal["PRESENT", "MISSING", "UNKNOWN", "UNAVAILABLE"] = Field(alias="loginState")
    authorization_state: Literal[
        "VALID", "REAUTHORIZATION_REQUIRED", "PERMISSION_DENIED", "UNKNOWN", "UNAVAILABLE"
    ] = Field(alias="authorizationState")
    checked_at: datetime | None = Field(default=None, alias="checkedAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    refresh_expires_at: datetime | None = Field(default=None, alias="refreshExpiresAt")
    generation: int = Field(ge=0)
    capabilities: list[AuthorizationCapabilityResponse]
    reason_code: str | None = Field(default=None, alias="reasonCode")
    scope_schema_version: int | None = Field(default=None, alias="scopeSchemaVersion")
    enabled_features: list[str] = Field(default_factory=list, alias="enabledFeatures")
    required_oauth_scopes: list[str] = Field(default_factory=list, alias="requiredOAuthScopes")
    target_ref_count: int = Field(default=0, ge=0, alias="targetRefCount")
    reauth_required: bool = Field(default=False, alias="reauthRequired")
    reauth_reason_code: str | None = Field(default=None, alias="reauthReasonCode")


class AuthorizationHealthSnapshotConnectionResponse(_HttpResponseModel):
    """Host-safe snapshot without owner identity or a renewable authorization ref."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    connection_id: UUID = Field(alias="connectionId")
    provider: ProviderId
    external_subject: str | None = Field(default=None, alias="externalSubject")
    login_state: Literal["PRESENT", "MISSING", "UNKNOWN", "UNAVAILABLE"] = Field(alias="loginState")
    authorization_state: Literal[
        "VALID", "REAUTHORIZATION_REQUIRED", "PERMISSION_DENIED", "UNKNOWN", "UNAVAILABLE"
    ] = Field(alias="authorizationState")
    checked_at: datetime | None = Field(default=None, alias="checkedAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    refresh_expires_at: datetime | None = Field(default=None, alias="refreshExpiresAt")
    generation: int = Field(ge=0)
    capabilities: list[AuthorizationCapabilityResponse] = Field(max_length=100)
    reason_code: str | None = Field(default=None, alias="reasonCode")
    scope_schema_version: int | None = Field(default=None, alias="scopeSchemaVersion")
    enabled_features: list[str] = Field(default_factory=list, alias="enabledFeatures")
    required_oauth_scopes: list[str] = Field(default_factory=list, alias="requiredOAuthScopes")
    target_ref_count: int = Field(default=0, ge=0, alias="targetRefCount")
    reauth_required: bool = Field(default=False, alias="reauthRequired")
    reauth_reason_code: str | None = Field(default=None, alias="reauthReasonCode")


class AuthorizationHealthSnapshotResponse(_HttpResponseModel):
    """Bounded page of snapshots for connections pinned by the host."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    connections: list[AuthorizationHealthSnapshotConnectionResponse] = Field(
        min_length=1, max_length=100
    )


class RenewalSessionResponse(_HttpResponseModel):
    """Pollable Product session; provider credentials and internal refs are omitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    session_ref: str = Field(alias="sessionRef")
    authorization_ref: str = Field(alias="authorizationRef")
    state: Literal["WAITING_USER", "VERIFYING", "SUCCEEDED", "FAILED", "EXPIRED", "CANCELLED"]
    created_at: datetime = Field(alias="createdAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    authorization_url: str | None = Field(default=None, alias="authorizationUrl")
    user_code: str | None = Field(
        default=None,
        alias="userCode",
        min_length=4,
        max_length=32,
        pattern=r"^[A-Z0-9]{4}-[A-Z0-9]{4}$",
    )
    qr_attachment_ref: str | None = Field(default=None, alias="qrAttachmentRef")
    generation: int = Field(ge=0)
    reason_code: str | None = Field(default=None, alias="reasonCode")


class CloudResourceResponse(_HttpResponseModel):
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


class ConnectionResourcesResponse(_HttpResponseModel):
    """Latest cached resource projections for one scoped connection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    connection_id: str = Field(alias="connectionId")
    provider: ProviderId
    checked_at: datetime | None = Field(default=None, alias="checkedAt")
    resources: list[CloudResourceResponse]


class NotificationResponse(_HttpResponseModel):
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


class NotificationFeedResponse(_HttpResponseModel):
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


class ConnectorOperationGrantBody(IntegrationRequestBody):
    """HMAC-authenticated request to mint one exact provider-operation grant."""

    request_id: str = Field(min_length=1, max_length=200)
    workspace_id: str = Field(min_length=1, max_length=200)
    principal_issuer: str = Field(min_length=1, max_length=1000)
    principal_subject: str = Field(min_length=1, max_length=1000)
    connection_ref: str = Field(min_length=1, max_length=300)
    provider_id: str = Field(min_length=1, max_length=100)
    profile_ref: str = Field(min_length=1, max_length=300)
    operation_id: str = Field(min_length=1, max_length=200)
    resource_ref: str = Field(min_length=1, max_length=1000)
    arguments: dict[str, Any]
    arguments_digest_sha256: str = Field(pattern="^[0-9a-f]{64}$")


class AuthorizationHealthSnapshotBody(IntegrationRequestBody):
    """Navigator HMAC selector for one bounded set of host-pinned connections."""

    request_id: str = Field(min_length=1, max_length=200)
    organization_id: str = Field(min_length=1, max_length=200)
    workspace_id: str = Field(min_length=1, max_length=200)
    connection_ids: list[UUID] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_connection_ids(self) -> AuthorizationHealthSnapshotBody:
        if len(self.connection_ids) != len(set(self.connection_ids)):
            raise ValueError("connectionIds must be unique")
        return self


class ConnectorOperationBody(IntegrationRequestBody):
    """One exact connector operation whose authority proof is in a separate header."""

    request_id: str = Field(min_length=1, max_length=200)
    provider_id: str = Field(min_length=1, max_length=100)
    profile_ref: str = Field(min_length=1, max_length=300)
    operation_id: str = Field(min_length=1, max_length=200)
    resource_ref: str = Field(min_length=1, max_length=1000)
    arguments: dict[str, Any]


class TeamsConversationBody(IntegrationRequestBody):
    """One canonical Teams channel/thread route copied from the admitted activity."""

    tenant_id: str = Field(min_length=1, max_length=100)
    team_id: str = Field(min_length=1, max_length=300)
    channel_id: str = Field(min_length=1, max_length=300)
    conversation_id: str = Field(min_length=1, max_length=1000)
    root_thread_id: str = Field(min_length=1, max_length=512, pattern="^[0-9]+$")
    service_url: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_root_message_id(self) -> TeamsConversationBody:
        """Ensure Bot Framework can address the numeric root activity id."""

        validate_teams_root_thread_id(self.root_thread_id)
        return self


class TeamsPrivateConversationBody(IntegrationRequestBody):
    """One host-resolved owner-private chat tuple with its original Entra actor."""

    tenant_id: str = Field(min_length=1, max_length=100)
    bot_app_id: str = Field(min_length=1, max_length=300)
    actor_aad_object_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    conversation_id: str = Field(min_length=3, max_length=512, pattern=r"^a:.+$")
    service_url: str = Field(min_length=1, max_length=512)


class TeamsMessageBody(IntegrationRequestBody):
    """One exact Teams thread reply sent via the host-configured message provider."""

    request_id: str = Field(min_length=1, max_length=200)
    provider_id: Literal["msteams"] | None = None
    conversation: TeamsConversationBody
    text: str = Field(min_length=1, max_length=24_000)


class TeamsPrivateMessageBody(IntegrationRequestBody):
    """One exact, closed owner-private Teams send through the existing connector path."""

    request_id: str = Field(min_length=1, max_length=200)
    provider_id: Literal["msteams"]
    target_kind: Literal["owner_private"]
    conversation: TeamsPrivateConversationBody
    text: str = Field(min_length=1, max_length=24_000)


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
        authorizer: IntegrationAuthorizer | None,
        accounts: AccountCenterClient,
        github: GitHubIssuesClient,
        webhook_verifier: GitHubWebhookVerifier,
        delegation_authorizer: DelegationAuthorizer | None,
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
        navigator_hmac_authenticator: Any = None,
        connector_grant_authority: Any = None,
        connector_grant_verifier: Any = None,
        connector_operation_dispatcher: Any = None,
        teams_message_client: TeamsMessagePort | None = None,
        teams_message_profile: Any = None,
        computer_runner_client: Any = None,
        computer_runner_profile: Any = None,
        authorization_profile_registry: Any = None,
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
        self.navigator_hmac_authenticator = navigator_hmac_authenticator
        self.connector_grant_authority = connector_grant_authority
        self.connector_grant_verifier = connector_grant_verifier
        self.connector_operation_dispatcher = connector_operation_dispatcher
        self.teams_message_client = teams_message_client
        self.teams_message_profile = teams_message_profile
        self.computer_runner_client = computer_runner_client
        self.computer_runner_profile = computer_runner_profile
        self.authorization_profile_registry = authorization_profile_registry
        self.transport_clients = transport_clients

    def display_name_for_connection(
        self,
        principal: IntegrationPrincipal,
        request: CreateIntegrationConnection,
    ) -> str:
        """Authorize aliases for this current principal and resolve display metadata."""

        if request.provider == "microsoft_graph":
            if (
                not request.account_link_ref
                or not request.binding_ref
                or request.target_ref is not None
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                    title="Microsoft Graph profile is not configured",
                    detail="Select this actor's linked Graph profile and the fixed host binding.",
                    status=403,
                )
            registry = self.authorization_profile_registry
            host_profile = (
                registry.settings.profiles.get(request.binding_ref)
                if registry is not None
                else None
            )
            if (
                host_profile is None
                or host_profile.provider != "microsoft_graph"
                or host_profile.access_mode != "actor_owned"
                or not host_profile.microsoft_graph_plan_ids
                or not registry.principal_allowed_for_profile(principal, host_profile)
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_UNAVAILABLE",
                    title="Microsoft Graph provider is not configured",
                    detail="The fixed Graph binding has no authorized Planner plan targets.",
                    status=503,
                    retryable=True,
                )
            _microsoft_graph_profile_for_actor(
                self.accounts,
                principal,
                request.account_link_ref,
                expected_plan_ids=host_profile.microsoft_graph_plan_ids,
                expected_sharepoint_targets=(
                    host_profile.microsoft_graph_sharepoint_site_id,
                    host_profile.microsoft_graph_sharepoint_list_ids,
                ),
            )
        elif request.provider == "azure_devops":
            registry = self.authorization_profile_registry
            host_profile = (
                registry.settings.profiles.get(request.binding_ref or "")
                if registry is not None
                else None
            )
            source = (
                (host_profile.authorized_sources or {}).get(request.target_ref or "")
                if host_profile is not None
                else None
            )
            if (
                host_profile is None
                or host_profile.provider != "azure_devops"
                or source is None
                or request.account_link_ref != source.profile_ref
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                    title="Azure DevOps source is not configured",
                    detail="Select only a source in the fixed host authorized_sources profile.",
                    status=403,
                )
            _azure_devops_profile_for_actor(self.accounts, principal, host_profile, source)

        if (
            request.provider == "github"
            and request.account_link_ref is None
            and request.binding_ref is None
            and request.target_ref is None
        ):
            principal.require("integrationCreateConnection")
            return request.repository_name

        if request.provider in {"github", "hf"}:
            account_provider = "huggingface" if request.provider == "hf" else request.provider
            if not request.account_link_ref:
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_REQUIRED",
                    title="Provider profile required",
                    detail="Link a verified provider profile before creating this connection.",
                    status=403,
                )
            response = self.accounts.list_provider_profiles(principal)
            profiles = response.get("profiles")
            profile = (
                next(
                    (
                        item
                        for item in profiles
                        if isinstance(item, Mapping)
                        and item.get("profile_ref") == request.account_link_ref
                        and item.get("provider") == account_provider
                    ),
                    None,
                )
                if isinstance(profiles, list)
                else None
            )
            if profile is None:
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
                    title="Provider profile unavailable",
                    detail="The selected provider profile does not belong to the verified actor.",
                    status=403,
                )
            auth_status = profile.get("auth_status")
            if auth_status not in {"configured", "healthy"}:
                raise ExchangeProductError(
                    code=(
                        "EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED"
                        if auth_status in {"reauthorization_required", "revoked"}
                        else "EXCHANGE_ACCOUNT_PROVIDER_PROFILE_UNAVAILABLE"
                    ),
                    title="Provider profile is not ready",
                    detail="The provider profile must be healthy before connecting a resource.",
                    status=409 if auth_status in {"reauthorization_required", "revoked"} else 503,
                    retryable=auth_status in {"unknown", "unavailable"},
                )
            scope = profile.get("target_scope")
            if request.provider == "github":
                repositories = scope.get("repositories") if isinstance(scope, Mapping) else None
                if not isinstance(repositories, list) or not any(
                    isinstance(repository, Mapping)
                    and str(repository.get("repository_id", repository.get("repositoryId", "")))
                    == request.repository_id
                    and str(repository.get("owner", ""))
                    == request.repository_name.partition("/")[0]
                    and str(repository.get("name", "")) == request.repository_name.partition("/")[2]
                    for repository in repositories
                ):
                    raise ExchangeProductError(
                        code="EXCHANGE_ACCOUNT_PROVIDER_RESOURCE_FORBIDDEN",
                        title="Repository is outside the linked installation",
                        detail=(
                            "The selected GitHub repository is not in this App installation scope."
                        ),
                        status=403,
                    )
                return request.repository_name
            registry = self.authorization_profile_registry
            host_profile = (
                registry.settings.profiles.get(request.binding_ref or "")
                if registry is not None
                else None
            )
            target = (
                host_profile.targets.get(request.target_ref or "")
                if host_profile is not None
                else None
            )
            repositories = scope.get("repositories") if isinstance(scope, Mapping) else None
            if (
                host_profile is None
                or host_profile.provider != "hf"
                or target is None
                or not isinstance(repositories, list)
                or not any(
                    isinstance(repository, Mapping)
                    and repository.get("repo_id") == target.target_ref
                    for repository in repositories
                )
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_PROVIDER_RESOURCE_FORBIDDEN",
                    title="HF repository is outside the linked token scope",
                    detail=(
                        "The selected Hugging Face resource is not in this token's "
                        "configured scope."
                    ),
                    status=403,
                )

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

    def access_mode_for_connection(
        self,
        principal: IntegrationPrincipal,
        request: CreateIntegrationConnection,
    ) -> str:
        """Resolve sharing only from Account Center or immutable host profile metadata."""

        if request.provider == "microsoft_graph":
            if (
                not request.account_link_ref
                or not request.binding_ref
                or request.target_ref is not None
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                    title="Microsoft Graph profile is not configured",
                    detail="Select this actor's linked Graph profile and the fixed host binding.",
                    status=403,
                )
            registry = self.authorization_profile_registry
            host_profile = (
                registry.settings.profiles.get(request.binding_ref)
                if registry is not None
                else None
            )
            if (
                host_profile is None
                or host_profile.provider != "microsoft_graph"
                or host_profile.access_mode != "actor_owned"
                or not host_profile.microsoft_graph_plan_ids
                or not registry.principal_allowed_for_profile(principal, host_profile)
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_UNAVAILABLE",
                    title="Microsoft Graph provider is not configured",
                    detail="The fixed Graph binding has no authorized Planner plan targets.",
                    status=503,
                    retryable=True,
                )
            row, _scope = _microsoft_graph_profile_for_actor(
                self.accounts,
                principal,
                request.account_link_ref,
                expected_plan_ids=host_profile.microsoft_graph_plan_ids,
                expected_sharepoint_targets=(
                    host_profile.microsoft_graph_sharepoint_site_id,
                    host_profile.microsoft_graph_sharepoint_list_ids,
                ),
            )
            if row.get("access_mode", "actor_owned") != "actor_owned":
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Microsoft Graph credentials cannot be shared across actor identities.",
                    status=502,
                )
            return "actor_owned"

        if request.provider == "azure_devops":
            registry = self.authorization_profile_registry
            host_profile = (
                registry.settings.profiles.get(request.binding_ref or "")
                if registry is not None
                else None
            )
            source = (
                (host_profile.authorized_sources or {}).get(request.target_ref or "")
                if host_profile is not None
                else None
            )
            if (
                host_profile is None
                or host_profile.provider != "azure_devops"
                or source is None
                or request.account_link_ref != source.profile_ref
                or host_profile.access_mode != "actor_owned"
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                    title="Azure DevOps source is not configured",
                    detail="The selected source/profile is outside the actor-owned host binding.",
                    status=403,
                )
            _azure_devops_profile_for_actor(self.accounts, principal, host_profile, source)
            return "actor_owned"

        if (
            request.provider == "github"
            and request.account_link_ref is None
            and request.binding_ref is None
            and request.target_ref is None
        ):
            principal.require("integrationCreateConnection")
            return "actor_owned"

        if request.provider in {"github", "hf"}:
            account_provider = "huggingface" if request.provider == "hf" else request.provider
            response = self.accounts.list_provider_profiles(principal)
            profiles = response.get("profiles")
            selected = (
                next(
                    (
                        item
                        for item in profiles
                        if isinstance(item, Mapping)
                        and item.get("profile_ref") == request.account_link_ref
                        and item.get("provider") == account_provider
                    ),
                    None,
                )
                if isinstance(profiles, list)
                else None
            )
            if selected is None:
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
                    title="Provider profile unavailable",
                    detail="The selected provider profile is not available to this actor.",
                    status=403,
                )
            access_mode = selected.get("access_mode", "actor_owned")
            if not isinstance(access_mode, str) or access_mode not in {
                "actor_owned",
                "workspace_operator",
            }:
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Account Center returned an unsupported provider access mode.",
                    status=502,
                )
            if request.provider == "hf":
                registry = self.authorization_profile_registry
                host_profile = (
                    registry.settings.profiles.get(request.binding_ref or "")
                    if registry is not None
                    else None
                )
                if host_profile is None or host_profile.access_mode != access_mode:
                    raise ExchangeProductError(
                        code="EXCHANGE_CONNECTOR_PROFILE_MODE_MISMATCH",
                        title="Provider profile access mode mismatch",
                        detail="Account Center and the host HF profile access modes differ.",
                        status=503,
                    )
            return str(access_mode)
        if request.provider in {"azure", "gcp", "runpod"}:
            registry = self.authorization_profile_registry
            host_profile = (
                registry.settings.profiles.get(request.binding_ref or "")
                if registry is not None
                else None
            )
            if host_profile is None or host_profile.provider != request.provider:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_UNAVAILABLE",
                    title="Provider connection is not configured",
                    detail="The selected cloud profile is not present in trusted host settings.",
                    status=503,
                    retryable=True,
                )
            return str(host_profile.access_mode)
        return "actor_owned"

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
        if "observedAt" in summary:
            summary["observedAt"] = _http_timestamp_value(summary["observedAt"])
        if not summary:
            summary = None
    state = getattr(operation, "state", "")
    return {
        "operationId": str(operation.id),
        "action": str(operation.operation_id),
        "state": getattr(state, "value", str(state)),
        "issueNumber": int(operation.issue_number),
        "createdAt": _http_utc_timestamp(operation.created_at),
        "updatedAt": _http_utc_timestamp(operation.updated_at),
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
        "createdAt": _http_utc_timestamp(operation.created_at),
        "updatedAt": _http_utc_timestamp(operation.updated_at),
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
        "createdAt": _http_utc_timestamp(job.created_at),
        "updatedAt": _http_utc_timestamp(job.updated_at),
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
        "createdAt": _http_timestamp_value(event.created_at),
        "actionRef": event.action_ref,
        "acknowledgedAt": _http_timestamp_value(event.acknowledged_at),
    }


def _teams_resource_ref(conversation: Mapping[str, Any]) -> str:
    """Bind a Teams grant to one canonical tenant/team/channel/root-thread route."""

    encoded = connector_canonical_json(dict(conversation))
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _connector_operation_response(
    request_id: str,
    result: Mapping[str, Any],
    *,
    is_mutating: bool = False,
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Project provider business state into the stable Navigator invocation envelope."""

    raw_state = result.get("state", result.get("status"))
    state = str(raw_state).strip().upper() if raw_state is not None else ""
    remote_state = result.get("remote_state", result.get("remoteState"))
    remote_state_value = str(remote_state).strip().upper() if remote_state is not None else ""
    provider_error = result.get("isError", result.get("is_error", False)) is True or isinstance(
        result.get("error"), Mapping
    )
    unknown_mutation_state = state in {
        "UNKNOWN",
        "UNKNOWN_RESULT",
        "UNCERTAIN",
        "REMOTE_STATE_UNVERIFIED",
        "COMMAND_INTERRUPTED",
        "COMMAND_CANCELLED",
    } or remote_state_value in {"UNKNOWN", "UNKNOWN_RESULT", "UNVERIFIED"}
    if is_mutating and unknown_mutation_state:
        outcome = "uncertain"
    elif (
        is_mutating and operation_id == "microsoft_graph.mail.message.send" and state == "ACCEPTED"
    ):
        # Graph's 202 confirms provider acceptance only; the nested result keeps
        # `status=ACCEPTED` and does not claim mailbox delivery.
        outcome = "verified"
    elif state == "COMMAND_FAILED" and remote_state_value in {"", "NOT_APPLICABLE"}:
        outcome = "failed"
    elif is_mutating and state in {"PENDING", "RUNNING", "SUBMITTED", "ACCEPTED"}:
        outcome = "pending"
    elif provider_error:
        outcome = "failed"
    elif is_mutating and (state in {"FAILED", "REJECTED", "ERROR"} or not state):
        outcome = "failed" if state else "uncertain"
    else:
        outcome = "verified"
    operation_ref = result.get("operation_ref", result.get("operationRef"))
    if outcome == "pending" and not (isinstance(operation_ref, str) and operation_ref):
        outcome = "uncertain"
    response: dict[str, Any] = {
        "requestId": request_id,
        "outcome": outcome,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": connector_canonical_json(dict(result)).decode("utf-8"),
                }
            ],
            "isError": outcome in {"failed", "uncertain"},
        },
    }
    if isinstance(operation_ref, str) and operation_ref:
        response["operationRef"] = operation_ref
    return response


def _connector_envelope_sha256(
    *,
    connection_ref: str,
    provider_id: str,
    profile_ref: str,
    operation_id: str,
    resource_ref: str,
    arguments_sha256: str,
) -> str:
    """Hash the exact host-bound action envelope without storing provider input."""

    envelope = {
        "connectionRef": connection_ref,
        "providerId": provider_id,
        "profileRef": profile_ref,
        "operationId": operation_id,
        "resourceRef": resource_ref,
        "argumentsDigestSha256": arguments_sha256,
    }
    return hashlib.sha256(connector_canonical_json(envelope)).hexdigest()


def _connector_exception_result(
    error: ExchangeProductError,
    *,
    is_mutating: bool,
) -> dict[str, Any]:
    """Keep typed 4xx provider refusals definite; preserve uncertainty for 5xx writes."""

    unknown_mutation = is_mutating and error.status >= 500
    return {
        "state": "UNKNOWN_RESULT" if unknown_mutation else "FAILED",
        "error": {"code": error.code, "retryable": error.retryable},
    }


def _connector_replay_response(
    *,
    request_id: str,
    reservation: ConnectorInvocationReservation,
) -> dict[str, Any]:
    """Return an exact cached receipt or a conservative unresolved receipt."""

    if reservation.response is not None:
        return reservation.response
    state = reservation.state or "UNKNOWN_RESULT"
    outcome = (
        "pending"
        if state == "PENDING"
        else "uncertain"
        if state == "UNKNOWN_RESULT" or state == "IN_PROGRESS"
        else "failed"
        if state in {"FAILED", "REJECTED"}
        else "verified"
    )
    fresh_request_required = not reservation.is_mutating and state in {"SUCCEEDED", "FAILED"}
    summary: dict[str, Any] = {
        "state": state,
        "receiptOnly": True,
        "reasonCode": "connector_attempt_already_started",
        "freshRequestRequired": fresh_request_required,
        "replayPolicy": (
            "fresh-read"
            if fresh_request_required
            else "status-reconciliation"
            if state in {"PENDING", "UNKNOWN_RESULT", "IN_PROGRESS"}
            else "do-not-repeat"
        ),
    }
    if reservation.operation_ref:
        summary["operation_ref"] = reservation.operation_ref
    return {
        "requestId": request_id,
        "outcome": outcome,
        **({"operationRef": reservation.operation_ref} if reservation.operation_ref else {}),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": connector_canonical_json(summary).decode("utf-8"),
                }
            ],
            "isError": outcome in {"failed", "uncertain"},
        },
    }


def _connector_operation_state(result: Mapping[str, Any]) -> str | None:
    raw_state = result.get("state", result.get("status"))
    if not isinstance(raw_state, str):
        return None
    return raw_state.strip().upper()


def _connector_operation_ref(result: Mapping[str, Any]) -> str | None:
    raw_ref = result.get("operation_ref", result.get("operationRef"))
    return raw_ref if isinstance(raw_ref, str) and raw_ref else None


def _provider_profile_ref(principal: IntegrationPrincipal, idempotency_key: str) -> str:
    """Generate a stable opaque profile idempotency reference for one actor request."""

    if not idempotency_key or len(idempotency_key) > 200:
        raise ExchangeProductError(
            code="EXCHANGE_IDEMPOTENCY_KEY_REQUIRED",
            title="Idempotency key required",
            detail="Provider profile linking requires an Idempotency-Key.",
            status=400,
        )
    seed = "\n".join(
        (
            principal.issuer,
            principal.subject,
            principal.organization_id,
            principal.workspace_id,
            idempotency_key,
        )
    )
    return str(uuid5(NAMESPACE_URL, f"cyrene-provider-profile:{seed}"))


def _microsoft_graph_profile_for_actor(
    accounts: AccountCenterClient,
    principal: IntegrationPrincipal,
    profile_ref: str,
    *,
    require_healthy: bool = True,
    expected_plan_ids: tuple[str, ...] | None = None,
    expected_sharepoint_targets: tuple[str | None, tuple[str, ...]] | None = None,
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    """Resolve one live, actor-owned Graph profile and classify its current auth state."""

    try:
        microsoft_identity_for_principal(principal)
    except ValueError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Microsoft account identity required",
            detail="Use the original verified Entra actor to access this Microsoft profile.",
            status=403,
        ) from exc
    response = accounts.list_provider_profiles(principal)
    rows = response.get("profiles") if isinstance(response, Mapping) else None
    if not isinstance(rows, list):
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned invalid Microsoft Graph profile metadata.",
            status=502,
        )
    matches = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("profile_ref") == profile_ref
        and row.get("provider") == "microsoft_graph"
    ]
    if len(matches) != 1:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Microsoft Graph profile unavailable",
            detail="The selected Microsoft Graph profile does not belong to this verified actor.",
            status=403,
        )
    row = matches[0]
    try:
        scope = validate_microsoft_graph_profile_identity(
            row,
            profile_ref=profile_ref,
            principal=principal,
        )
    except MicrosoftActorMismatch as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Microsoft Graph profile belongs to another actor",
            detail="The linked Graph identity does not match the original verified Entra actor.",
            status=403,
        ) from exc
    except ValueError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned a mismatched Microsoft Graph identity or scope.",
            status=502,
        ) from exc
    if expected_plan_ids is not None and tuple(scope["planner"]["plan_ids"]) != expected_plan_ids:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Microsoft Graph profile does not match its host plan targets",
            detail="The Account Center Planner plan set differs from the fixed host binding.",
            status=403,
            context={"reasonCode": "microsoft_graph_plan_scope_mismatch"},
        )
    if scope["sharepoint"]["enabled"] and (
        expected_sharepoint_targets is None
        or scope["sharepoint"]["site_id"] != expected_sharepoint_targets[0]
        or tuple(scope["sharepoint"]["list_ids"]) != expected_sharepoint_targets[1]
    ):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Microsoft Graph profile does not match its host SharePoint targets",
            detail="The Account Center site/list scope differs from the fixed host binding.",
            status=403,
            context={"reasonCode": "microsoft_graph_sharepoint_scope_mismatch"},
        )
    auth_status = row.get("auth_status")
    if require_healthy and int(row["expires_at"]) <= int(datetime.now(UTC).timestamp()):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
            title="Microsoft Graph reauthorization required",
            detail="The actor's delegated Graph access token has expired.",
            status=409,
            context={"reasonCode": "microsoft_graph_token_expired"},
        )
    if require_healthy and auth_status in {"reauthorization_required", "revoked"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
            title="Microsoft Graph reauthorization required",
            detail="Account Center reports that this actor's Microsoft Graph link needs consent.",
            status=409,
            context={"reasonCode": "microsoft_graph_reauthorization_required"},
        )
    if require_healthy and auth_status in {"unknown", "unavailable"}:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_UNAVAILABLE",
            title="Microsoft Graph authorization is unavailable",
            detail="Account Center could not confirm the current Microsoft Graph profile.",
            status=503,
            retryable=True,
            context={"reasonCode": "microsoft_graph_profile_unavailable"},
        )
    if require_healthy and auth_status != "healthy":
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_AUTHORIZATION_NOT_READY",
            title="Microsoft Graph authorization is not ready",
            detail="Complete and verify Microsoft Graph consent before using this profile.",
            status=409,
            context={"reasonCode": "microsoft_graph_profile_not_healthy"},
        )
    return row, scope


def _azure_devops_profile_for_actor(
    accounts: AccountCenterClient,
    principal: IntegrationPrincipal,
    host_profile: Any,
    source: Any,
    *,
    require_healthy: bool = True,
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    """Require the actor-owned ADO profile to match one closed host source row."""

    profile_ref = getattr(source, "profile_ref", None)
    tenant_id = getattr(host_profile, "azure_devops_tenant_id", None)
    organization = getattr(host_profile, "azure_devops_organization", None)
    if (
        not isinstance(profile_ref, str)
        or not profile_ref
        or not isinstance(tenant_id, str)
        or not tenant_id
        or not isinstance(organization, str)
        or not organization
    ):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_INVALID",
            title="Azure DevOps source binding is invalid",
            detail=(
                "The fixed host source row is missing its actor profile or organization binding."
            ),
            status=503,
        )
    source_config = {
        "source_id": getattr(source, "source_id", None),
        "kind": getattr(source, "kind", None),
        "project_id": getattr(source, "project_id", None),
        "project_name": getattr(source, "project_name", None),
        "profile_ref": profile_ref,
        **({"pipeline_id": source.pipeline_id} if source.pipeline_id is not None else {}),
        **({"definition_id": source.definition_id} if source.definition_id is not None else {}),
        **(
            {"definition_environment_id": source.definition_environment_id}
            if source.definition_environment_id is not None
            else {}
        ),
    }
    try:
        actor_tenant, _object_id, _subject = microsoft_identity_for_principal(principal)
    except ValueError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Microsoft account identity required",
            detail="Use the original verified Entra actor to access this Azure DevOps profile.",
            status=403,
        ) from exc
    if actor_tenant != tenant_id:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Azure DevOps tenant differs from the signed actor",
            detail="The selected ADO source is outside the original actor's Entra tenant.",
            status=403,
        )
    try:
        expected_scope = azure_devops_scope_for_authorized_source(
            tenant_id=tenant_id,
            organization=organization,
            source=source_config,
        )
    except ValueError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_INVALID",
            title="Azure DevOps source binding is invalid",
            detail="The fixed host source row does not match the closed provider schema.",
            status=503,
        ) from exc
    result = accounts.list_provider_profiles(principal)
    rows = result.get("profiles") if isinstance(result, Mapping) else None
    if not isinstance(rows, list):
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned invalid Azure DevOps profile metadata.",
            status=502,
        )
    matches = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("profile_ref") == profile_ref
        and row.get("provider") == "azure_devops"
    ]
    if len(matches) != 1:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Azure DevOps profile unavailable",
            detail="The selected Account Center profile does not belong to this verified actor.",
            status=403,
        )
    row = matches[0]
    try:
        scope = validate_azure_devops_profile_identity(
            row,
            profile_ref=profile_ref,
            principal=principal,
        )
    except MicrosoftActorMismatch as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
            title="Azure DevOps profile belongs to another actor",
            detail="The linked Entra identity does not match the original verified actor.",
            status=403,
        ) from exc
    except ValueError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned a mismatched Azure DevOps identity or OAuth scope.",
            status=502,
        ) from exc
    if scope != expected_scope:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps profile does not match its configured source",
            detail="The actor-owned Account Center profile differs from the fixed host source row.",
            status=403,
            context={"reasonCode": "azure_devops_profile_scope_mismatch"},
        )
    auth_status = row.get("auth_status")
    if require_healthy and int(row["expires_at"]) <= int(datetime.now(UTC).timestamp()):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
            title="Azure DevOps reauthorization required",
            detail="The actor's delegated Azure DevOps token has expired.",
            status=409,
            context={"reasonCode": "azure_devops_token_expired"},
        )
    if require_healthy and auth_status in {"reauthorization_required", "revoked"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
            title="Azure DevOps reauthorization required",
            detail="Account Center reports that this actor's Entra link needs reauthorization.",
            status=409,
            context={"reasonCode": "azure_devops_reauthorization_required"},
        )
    if require_healthy and auth_status in {"unknown", "unavailable"}:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_UNAVAILABLE",
            title="Azure DevOps authorization is unavailable",
            detail="Account Center could not confirm the current Azure DevOps profile.",
            status=503,
            retryable=True,
            context={"reasonCode": "azure_devops_profile_unavailable"},
        )
    if require_healthy and auth_status != "healthy":
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_AUTHORIZATION_NOT_READY",
            title="Azure DevOps authorization is not ready",
            detail="Complete and verify the actor-owned Entra consent before using this profile.",
            status=409,
            context={"reasonCode": "azure_devops_profile_not_healthy"},
        )
    return row, scope


def _microsoft_graph_oauth_session_response(
    result: Mapping[str, Any],
    *,
    profile_ref: str | None = None,
    expected_redirect_uri: str | None = None,
) -> dict[str, Any]:
    """Project one Account Center Graph OAuth session after URL and expiry checks."""

    session_ref = result.get("link_session_ref")
    authorization_url = result.get("authorization_url")
    expires_at = result.get("expires_at")
    if (
        not isinstance(session_ref, str)
        or not session_ref
        or not isinstance(authorization_url, str)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= int(datetime.now(UTC).timestamp())
    ):
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned an invalid Microsoft Graph OAuth session.",
            status=502,
        )
    try:
        UUID(session_ref)
        parsed = urlsplit(authorization_url)
        port = parsed.port
        path_parts = parsed.path.split("/", maxsplit=2)
        if len(path_parts) < 2:
            raise ValueError("authorization path is incomplete")
        valid_authority = re.fullmatch(
            r"/(?:common|organizations|[0-9a-fA-F-]{36})/oauth2/v2\.0/authorize",
            parsed.path,
        )
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        valid_tenant = path_parts[1]
        if valid_tenant not in {"common", "organizations"}:
            UUID(valid_tenant)
    except (IndexError, ValueError) as exc:
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned a Microsoft authorization URL outside the fixed route.",
            status=502,
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "login.microsoftonline.com"
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or authorization_url.strip() != authorization_url
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in authorization_url)
        or valid_authority is None
    ):
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned a Microsoft authorization URL outside the fixed route.",
            status=502,
        )
    if expected_redirect_uri is not None:
        redirect_values = [value for key, value in query_pairs if key == "redirect_uri"]
        response_modes = [value for key, value in query_pairs if key == "response_mode"]
        if (
            redirect_values != [expected_redirect_uri]
            or len(response_modes) > 1
            or (response_modes and response_modes[0] != "query")
        ):
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail=(
                    "Account Center returned a Microsoft authorization URL outside the fixed route."
                ),
                status=502,
            )
    return {
        "linkSessionRef": session_ref,
        **({"profileRef": profile_ref} if profile_ref is not None else {}),
        "authorizationUrl": authorization_url,
        "expiresAt": _http_utc_timestamp(datetime.fromtimestamp(expires_at, UTC)),
    }


def _linked_provider_profile_response(
    result: Mapping[str, Any],
    *,
    expected_profile_ref: str | None,
    expected_provider: str,
) -> dict[str, Any]:
    """Validate and project a non-secret Account Center profile link result."""

    profile_ref = result.get("profile_ref")
    provider = result.get("provider")
    auth_status = result.get("auth_status")
    external_subject = result.get("external_subject")
    expires_at = result.get("expires_at")
    refresh_expires_at = result.get("refresh_expires_at")
    credential_revision = result.get("credential_revision")
    auth_mode = result.get("auth_mode")
    access_mode = result.get("access_mode", "actor_owned")
    if (
        (expected_profile_ref is not None and profile_ref != expected_profile_ref)
        or not isinstance(profile_ref, str)
        or not profile_ref
        or provider != expected_provider
        or not isinstance(auth_status, str)
        or auth_status
        not in {
            "unknown",
            "configured",
            "healthy",
            "unavailable",
            "reauthorization_required",
            "revoked",
        }
        or not isinstance(external_subject, str)
        or not external_subject
        or (
            expires_at is not None
            and (isinstance(expires_at, bool) or not isinstance(expires_at, int))
        )
        or (
            refresh_expires_at is not None
            and (
                isinstance(refresh_expires_at, bool)
                or not isinstance(refresh_expires_at, int)
                or refresh_expires_at <= 0
            )
        )
        or (
            credential_revision is not None
            and (
                isinstance(credential_revision, bool)
                or not isinstance(credential_revision, int)
                or credential_revision < 0
            )
        )
        or not isinstance(access_mode, str)
        or access_mode not in {"actor_owned", "workspace_operator"}
        or (
            auth_mode is not None
            and (
                (expected_provider not in {"huggingface", "microsoft_graph", "azure_devops"})
                or not isinstance(auth_mode, str)
                or (
                    expected_provider == "huggingface"
                    and auth_mode not in {"fine_grained_token", "device_oauth"}
                )
                or (expected_provider == "microsoft_graph" and auth_mode != "delegated_oauth")
                or (expected_provider == "azure_devops" and auth_mode != "delegated_oauth")
            )
        )
    ):
        raise ExchangeProductError(
            code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
            title="Account Center response invalid",
            detail="Account Center returned invalid or mismatched provider profile metadata.",
            status=502,
        )
    projection = {
        "profileRef": profile_ref,
        "provider": provider,
        "authStatus": auth_status,
        "accessMode": access_mode,
        "externalSubject": external_subject,
        "expiresAt": (
            _http_utc_timestamp(datetime.fromtimestamp(expires_at, UTC))
            if expires_at is not None
            else None
        ),
    }
    if isinstance(auth_mode, str):
        projection["authMode"] = auth_mode
    if expected_provider == "microsoft_graph":
        if auth_status != "healthy" or access_mode != "actor_owned":
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center did not confirm an actor-owned Graph link.",
                status=502,
            )
        try:
            scope = validate_microsoft_graph_profile_identity(result, profile_ref=str(profile_ref))
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned an invalid Microsoft Graph scope or identity.",
                status=502,
            ) from exc
        projection["targetScope"] = microsoft_graph_public_profile_scope(scope)
        metadata = microsoft_graph_profile_scope_metadata(result, scope)
        projection.update(
            {
                "scopeSchemaVersion": metadata["scope_schema_version"],
                "enabledFeatures": metadata["enabled_features"],
                "requiredOAuthScopes": metadata["required_oauth_scopes"],
                "targetRefCount": metadata["target_ref_count"],
                "credentialExpiresAt": projection["expiresAt"],
                "refreshExpiresAt": (
                    _http_utc_timestamp(datetime.fromtimestamp(refresh_expires_at, UTC))
                    if refresh_expires_at is not None
                    else None
                ),
                "reauthRequired": metadata["reauth_required"],
                "reauthReasonCode": metadata["reauth_reason_code"],
                "credentialRevision": credential_revision,
            }
        )
    elif expected_provider == "azure_devops":
        if auth_status != "healthy" or access_mode != "actor_owned":
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center did not confirm an actor-owned Azure DevOps link.",
                status=502,
            )
        try:
            scope = validate_azure_devops_profile_identity(
                result,
                profile_ref=str(profile_ref),
            )
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned an invalid Azure DevOps scope or identity.",
                status=502,
            ) from exc
        projection["targetScope"] = azure_devops_public_profile_scope(scope)
    return projection


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
            "createdAt": _http_timestamp_value(source.get("createdAt")),
            "updatedAt": _http_timestamp_value(source.get("updatedAt")),
        }
    return {
        "id": str(connection.id),
        "provider": connection.provider,
        "displayName": connection.display_name or connection.repository_name or connection.provider,
        "repositoryId": connection.repository_id or None,
        "repositoryName": connection.repository_name or None,
        "enabled": connection.enabled,
        "createdAt": _http_timestamp_value(connection.created_at),
        "updatedAt": _http_timestamp_value(connection.updated_at),
    }


def _renewal_response(session: RenewalSessionRecord) -> dict[str, Any]:
    """Expose only the Product session ref and user-action fields."""

    return {
        "sessionRef": session.session_ref,
        "authorizationRef": session.authorization_ref,
        "state": session.state.value,
        "createdAt": _http_timestamp_value(session.created_at),
        "expiresAt": _http_timestamp_value(session.expires_at),
        "authorizationUrl": session.authorization_url,
        "userCode": session.user_code,
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
            if services.authorizer is None:
                raise ExchangeProductError(
                    code="EXCHANGE_INTEGRATION_IDENTITY_NOT_CONFIGURED",
                    title="First-party identity verification is unavailable",
                    detail="This Exchange profile has no Platform identity verification channel.",
                    status=503,
                    retryable=True,
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

    async def signed_navigator_body(request: Request, body_type: Any) -> Any:
        """Validate an internal request's exact raw body with the Navigator service key."""

        authenticator = services.navigator_hmac_authenticator
        if authenticator is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Connector authorization is not configured",
                detail="Exchange has no Navigator service authentication binding.",
                status=503,
                retryable=True,
                context={"reasonCode": "navigator_hmac_not_configured"},
            )
        if request.url.query:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="Internal connector requests do not accept query selectors.",
                status=400,
            )
        if request.headers.get("authorization") or request.headers.get(
            "x-cyrene-execution-credential-bin"
        ):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Connector authentication is ambiguous",
                detail="The internal connector route accepts only the configured Navigator HMAC.",
                status=401,
            )
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="Internal connector requests require application/json.",
                status=415,
            )
        raw_body = await _read_bounded_request_body(
            request,
            max_bytes=navigator_hmac_body_limit(request.method, request.url.path),
        )
        timestamp = authenticator.verify(
            method=request.method,
            path=request.url.path,
            headers=request.headers,
            raw_body=raw_body,
        )
        payload = parse_signed_json_object(raw_body)
        try:
            body = body_type.model_validate(payload)
        except ValidationError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="The signed connector request does not match its closed schema.",
                status=400,
            ) from exc
        authenticator.consume_request_id(
            key_id=request.headers.get("x-cyrene-navigator-key-id", ""),
            request_id=body.request_id,
            timestamp=timestamp,
        )
        return body

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

    @router.post(
        "/api/v1/accounts/provider-profiles/microsoft-graph/link-sessions",
        status_code=201,
        operation_id="accountBeginMicrosoftGraphLink",
    )
    async def begin_microsoft_graph_link(
        body: BeginMicrosoftGraphLinkBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        try:
            microsoft_identity_for_principal(actor)
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
                title="Microsoft account identity required",
                detail="Link Microsoft profiles only from the matching verified Entra actor.",
                status=403,
            ) from exc
        registry = services.authorization_profile_registry
        host_profile = (
            registry.settings.profiles.get(body.binding_ref) if registry is not None else None
        )
        office_v2_scope = None
        if host_profile is not None and host_profile.microsoft_graph_office_v2 is not None:
            try:
                office_v2_scope = microsoft_graph_office_v2_scope(host_profile, actor)
            except (PermissionError, ValueError) as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_UNAVAILABLE",
                    title="Microsoft Graph provider is not configured",
                    detail="The fixed Graph v2 owner and Workspace scope is invalid.",
                    status=503,
                    retryable=True,
                ) from exc
        if (
            host_profile is None
            or host_profile.provider != "microsoft_graph"
            or host_profile.access_mode != "actor_owned"
            or (not host_profile.microsoft_graph_plan_ids and office_v2_scope is None)
            or not registry.principal_allowed_for_profile(actor, host_profile)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_UNAVAILABLE",
                title="Microsoft Graph provider is not configured",
                detail="Select a fixed actor-owned Microsoft Graph v1 or v2 binding.",
                status=503,
                retryable=True,
            )
        profile_ref = _provider_profile_ref(actor, idempotency_key)
        result = services.accounts.begin_microsoft_graph_link(
            actor,
            profile_ref=profile_ref,
            planner_plan_ids=(
                list(office_v2_scope["planner"]["plan_ids"])
                if office_v2_scope is not None
                else list(host_profile.microsoft_graph_plan_ids)
            ),
            idempotency_key=idempotency_key,
            office_v2_scope=office_v2_scope,
        )
        return _microsoft_graph_oauth_session_response(
            result,
            profile_ref=profile_ref,
            expected_redirect_uri=(OFFICE_V2_REDIRECT_URI if office_v2_scope is not None else None),
        )

    @router.post(
        "/api/v1/accounts/provider-profiles/azure-devops/link-sessions",
        status_code=201,
        operation_id="accountBeginAzureDevOpsLink",
    )
    async def begin_azure_devops_link(
        body: BeginAzureDevOpsLinkBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        registry = services.authorization_profile_registry
        host_profile = (
            registry.settings.profiles.get(body.binding_ref) if registry is not None else None
        )
        source = (
            (host_profile.authorized_sources or {}).get(body.source_id)
            if host_profile is not None
            else None
        )
        if (
            host_profile is None
            or host_profile.provider != "azure_devops"
            or host_profile.access_mode != "actor_owned"
            or source is None
            or source.source_id != body.source_id
            or not registry.principal_allowed_for_profile(actor, host_profile)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="Azure DevOps source is not configured",
                detail="Select a source from the fixed host authorized_sources profile.",
                status=403,
            )
        try:
            actor_tenant, _object_id, _subject = microsoft_identity_for_principal(actor)
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_PROVIDER_PROFILE_FORBIDDEN",
                title="Microsoft account identity required",
                detail="Link Azure DevOps from the original verified Entra actor.",
                status=403,
            ) from exc
        try:
            target_scope = azure_devops_scope_for_authorized_source(
                tenant_id=str(host_profile.azure_devops_tenant_id),
                organization=str(host_profile.azure_devops_organization),
                source={
                    "source_id": source.source_id,
                    "kind": source.kind,
                    "project_id": source.project_id,
                    "project_name": source.project_name,
                    "profile_ref": source.profile_ref,
                    **(
                        {"pipeline_id": source.pipeline_id}
                        if source.pipeline_id is not None
                        else {}
                    ),
                    **(
                        {"definition_id": source.definition_id}
                        if source.definition_id is not None
                        else {}
                    ),
                    **(
                        {"definition_environment_id": source.definition_environment_id}
                        if source.definition_environment_id is not None
                        else {}
                    ),
                },
            )
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_INVALID",
                title="Azure DevOps source binding is invalid",
                detail="The selected source does not match the closed host profile schema.",
                status=503,
            ) from exc
        if actor_tenant != target_scope["tenant_id"]:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="Azure DevOps tenant differs from the signed actor",
                detail="Link an Azure DevOps source in the original Entra actor's tenant.",
                status=403,
            )
        result = services.accounts.begin_azure_devops_link(
            actor,
            profile_ref=source.profile_ref,
            tenant_id=target_scope["tenant_id"],
            organization=target_scope["organization"],
            project_id=target_scope["project_id"],
            source_id=target_scope["source_id"],
            source_kind=target_scope["source_kind"],
            pipeline_id=target_scope.get("pipeline_id"),
            definition_id=target_scope.get("definition_id"),
            definition_environment_id=target_scope.get("definition_environment_id"),
            idempotency_key=idempotency_key,
        )
        return _microsoft_graph_oauth_session_response(result)

    @router.get(
        "/api/v1/accounts/azure-devops/callback",
        operation_id="accountCompleteAzureDevOpsLink",
    )
    def complete_azure_devops_link(
        state: str = Query(min_length=32, max_length=512),
        code: str = Query(min_length=1, max_length=4096),
    ) -> dict[str, Any]:
        result = services.accounts.complete_azure_devops_link(
            services.callback_principal,
            state=state,
            code=code,
        )
        return _linked_provider_profile_response(
            result,
            expected_profile_ref=None,
            expected_provider="azure_devops",
        )

    @router.get(
        "/api/v1/accounts/microsoft-graph/callback",
        operation_id="accountCompleteMicrosoftGraphLink",
    )
    def complete_microsoft_graph_link(
        state: str = Query(min_length=32, max_length=512),
        code: str = Query(min_length=1, max_length=4096),
    ) -> dict[str, Any]:
        result = services.accounts.complete_microsoft_graph_link(
            services.callback_principal,
            state=state,
            code=code,
        )
        return _linked_provider_profile_response(
            result,
            expected_profile_ref=None,
            expected_provider="microsoft_graph",
        )

    @router.post(
        "/api/v1/accounts/provider-profiles/microsoft-graph/{profile_ref}/actions/enable-planner-write",
        status_code=201,
        operation_id="accountBeginMicrosoftGraphPlannerWriteUpgrade",
    )
    async def begin_microsoft_graph_planner_write_upgrade(
        profile_ref: str,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        _microsoft_graph_profile_for_actor(services.accounts, actor, profile_ref)
        result = services.accounts.begin_microsoft_graph_scope_upgrade(
            actor,
            profile_ref=profile_ref,
            permission="planner_tasks_write",
            idempotency_key=idempotency_key,
        )
        return _microsoft_graph_oauth_session_response(result)

    @router.post(
        "/api/v1/accounts/provider-profiles/microsoft-graph/{profile_ref}/actions/select-sharepoint-target",
        status_code=201,
        operation_id="accountBeginMicrosoftGraphSharePointScopeUpgrade",
    )
    async def begin_microsoft_graph_sharepoint_scope_upgrade(
        profile_ref: str,
        body: SelectMicrosoftGraphSharePointScopeBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        registry = services.authorization_profile_registry
        host_profile = (
            registry.settings.profiles.get(body.binding_ref) if registry is not None else None
        )
        if (
            host_profile is None
            or host_profile.provider != "microsoft_graph"
            or host_profile.access_mode != "actor_owned"
            or not host_profile.microsoft_graph_plan_ids
            or host_profile.microsoft_graph_sharepoint_site_id is None
            or not host_profile.microsoft_graph_sharepoint_list_ids
            or not registry.principal_allowed_for_profile(actor, host_profile)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_CONFIGURATION_UNAVAILABLE",
                title="SharePoint target is not configured",
                detail="The selected Graph binding has no fixed SharePoint site/list allowlist.",
                status=503,
                retryable=True,
            )
        _microsoft_graph_profile_for_actor(
            services.accounts,
            actor,
            profile_ref,
            expected_plan_ids=host_profile.microsoft_graph_plan_ids,
            expected_sharepoint_targets=(
                host_profile.microsoft_graph_sharepoint_site_id,
                host_profile.microsoft_graph_sharepoint_list_ids,
            ),
        )
        result = services.accounts.begin_microsoft_graph_scope_upgrade(
            actor,
            profile_ref=profile_ref,
            permission="sharepoint_selected",
            site_id=host_profile.microsoft_graph_sharepoint_site_id,
            list_ids=list(host_profile.microsoft_graph_sharepoint_list_ids),
            idempotency_key=idempotency_key,
        )
        return _microsoft_graph_oauth_session_response(result)

    @router.get(
        "/api/v1/accounts/microsoft-graph/scope-upgrade/callback",
        operation_id="accountCompleteMicrosoftGraphScopeUpgrade",
    )
    def complete_microsoft_graph_scope_upgrade(
        state: str = Query(min_length=32, max_length=512),
        code: str = Query(min_length=1, max_length=4096),
    ) -> dict[str, Any]:
        result = services.accounts.complete_microsoft_graph_scope_upgrade(
            services.callback_principal,
            state=state,
            code=code,
        )
        return _linked_provider_profile_response(
            result,
            expected_profile_ref=None,
            expected_provider="microsoft_graph",
        )

    @router.get("/api/v1/accounts/links", operation_id="accountListLinks")
    async def list_links(
        request: Request, workspace_id: str | None = Query(default=None, alias="workspaceId")
    ) -> dict[str, Any]:
        actor = await principal(request, workspace_id, operation_id="accountListLinks")
        require(actor, "accountListLinks")
        return {"links": account_links(actor)}

    @router.get(
        "/api/v1/accounts/provider-profiles",
        operation_id="accountListProviderProfiles",
    )
    async def list_provider_profiles(
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        provider_filter: str | None = Query(default=None, alias="provider"),
        profile_ref_filter: str | None = Query(default=None, alias="profileRef"),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        if provider_filter is not None and provider_filter not in {
            "huggingface",
            "microsoft_graph",
            "azure_devops",
        }:
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                title="Provider selector is invalid",
                detail="Select a supported provider profile type.",
                status=422,
            )
        if profile_ref_filter is not None and (
            not isinstance(profile_ref_filter, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,299}", profile_ref_filter)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_REQUEST_INVALID",
                title="Profile selector is invalid",
                detail="Select one opaque provider profile reference.",
                status=422,
            )
        result = services.accounts.list_provider_profiles(actor)
        profiles = result.get("profiles") if isinstance(result, Mapping) else None
        if not isinstance(profiles, list):
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                title="Account Center response invalid",
                detail="Account Center returned an invalid provider profile projection.",
                status=502,
            )
        projected: list[dict[str, Any]] = []
        for item in profiles:
            if not isinstance(item, Mapping):
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Account Center returned malformed provider profile metadata.",
                    status=502,
                )
            profile_ref = item.get("profile_ref")
            provider = item.get("provider")
            if provider_filter is not None and provider != provider_filter:
                continue
            if profile_ref_filter is not None and profile_ref != profile_ref_filter:
                continue
            identity_ref = item.get("identity_ref")
            auth_status = item.get("auth_status")
            auth_mode = item.get("auth_mode")
            access_mode = item.get("access_mode", "actor_owned")
            if not all(
                isinstance(value, str) and value for value in (profile_ref, provider, auth_status)
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Account Center returned incomplete provider profile metadata.",
                    status=502,
                )
            if auth_mode is not None and (
                provider not in {"huggingface", "microsoft_graph", "azure_devops"}
                or not isinstance(auth_mode, str)
                or (
                    provider == "huggingface"
                    and auth_mode not in {"fine_grained_token", "device_oauth"}
                )
                or (provider == "microsoft_graph" and auth_mode != "delegated_oauth")
                or (provider == "azure_devops" and auth_mode != "delegated_oauth")
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Account Center returned an unsupported provider auth mode.",
                    status=502,
                )
            if not isinstance(access_mode, str) or access_mode not in {
                "actor_owned",
                "workspace_operator",
            }:
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Account Center returned an unsupported provider access mode.",
                    status=502,
                )
            if provider == "microsoft_graph" and access_mode != "actor_owned":
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Microsoft Graph provider profiles must remain bound to one actor.",
                    status=502,
                )
            if provider == "microsoft_graph":
                try:
                    graph_scope = validate_microsoft_graph_profile_identity(
                        item,
                        profile_ref=str(profile_ref),
                        principal=actor,
                    )
                    target_scope = microsoft_graph_public_profile_scope(graph_scope)
                    scope_metadata = microsoft_graph_profile_scope_metadata(item, graph_scope)
                except ValueError as exc:
                    raise ExchangeProductError(
                        code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                        title="Account Center response invalid",
                        detail="Account Center returned an invalid Microsoft Graph profile.",
                        status=502,
                    ) from exc
            elif provider == "azure_devops":
                if access_mode != "actor_owned":
                    raise ExchangeProductError(
                        code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                        title="Account Center response invalid",
                        detail="Azure DevOps provider profiles must remain bound to one actor.",
                        status=502,
                    )
                try:
                    ado_scope = validate_azure_devops_profile_identity(
                        item,
                        profile_ref=str(profile_ref),
                        principal=actor,
                    )
                    target_scope = azure_devops_public_profile_scope(ado_scope)
                except ValueError as exc:
                    raise ExchangeProductError(
                        code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                        title="Account Center response invalid",
                        detail="Account Center returned an invalid Azure DevOps profile.",
                        status=502,
                    ) from exc
            else:
                target_scope = (
                    dict(item["target_scope"])
                    if isinstance(item.get("target_scope"), Mapping)
                    else {}
                )
            projected.append(
                {
                    "profileRef": profile_ref,
                    "provider": provider,
                    "identityRef": identity_ref if isinstance(identity_ref, str) else None,
                    "targetScope": target_scope,
                    "authStatus": auth_status,
                    "accessMode": access_mode,
                    "externalSubject": item.get("external_subject")
                    if isinstance(item.get("external_subject"), str)
                    else None,
                    "expiresAt": (
                        _http_utc_timestamp(datetime.fromtimestamp(item["expires_at"], UTC))
                        if provider == "microsoft_graph" and isinstance(item.get("expires_at"), int)
                        else item.get("expires_at")
                        if isinstance(item.get("expires_at"), int)
                        else None
                    ),
                    **({"authMode": auth_mode} if isinstance(auth_mode, str) else {}),
                    **(
                        {
                            "scopeSchemaVersion": scope_metadata["scope_schema_version"],
                            "enabledFeatures": scope_metadata["enabled_features"],
                            "requiredOAuthScopes": scope_metadata["required_oauth_scopes"],
                            "targetRefCount": scope_metadata["target_ref_count"],
                            "credentialExpiresAt": (
                                _http_utc_timestamp(datetime.fromtimestamp(item["expires_at"], UTC))
                                if isinstance(item.get("expires_at"), int)
                                and not isinstance(item.get("expires_at"), bool)
                                else None
                            ),
                            "refreshExpiresAt": (
                                _http_utc_timestamp(
                                    datetime.fromtimestamp(item["refresh_expires_at"], UTC)
                                )
                                if isinstance(item.get("refresh_expires_at"), int)
                                and not isinstance(item.get("refresh_expires_at"), bool)
                                else None
                            ),
                            "reauthRequired": scope_metadata["reauth_required"],
                            "reauthReasonCode": scope_metadata["reauth_reason_code"],
                            "credentialRevision": item.get("credential_revision"),
                        }
                        if provider == "microsoft_graph"
                        else {}
                    ),
                }
            )
        return {"profiles": projected}

    @router.post(
        "/api/v1/accounts/provider-profiles/github/app-installations",
        status_code=201,
        operation_id="accountLinkGitHubAppInstallation",
    )
    async def link_github_app_installation(
        body: LinkGitHubInstallationBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        profile_ref = _provider_profile_ref(actor, idempotency_key)
        linked = services.accounts.link_github_app_installation(
            actor,
            profile_ref=profile_ref,
            installation_id=body.installation_id,
            repositories=[
                repository.model_dump(by_alias=False) for repository in body.repositories
            ],
            idempotency_key=idempotency_key,
        )
        return _linked_provider_profile_response(
            linked,
            expected_profile_ref=profile_ref,
            expected_provider="github",
        )

    @router.post(
        "/api/v1/accounts/provider-profiles/huggingface/{profile_alias}",
        status_code=201,
        operation_id="accountLinkHuggingFaceProfile",
    )
    async def link_huggingface_profile(
        profile_alias: str,
        request: Request,
        body: LinkHuggingFaceProfileBody,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        if body.profile_alias != profile_alias:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROFILE_MISMATCH",
                title="Provider profile selector mismatch",
                detail="The body profile alias must match the route selector.",
                status=400,
            )
        registry = services.authorization_profile_registry
        profile = registry.settings.profiles.get(profile_alias) if registry is not None else None
        if (
            profile is None
            or profile.provider != "hf"
            or profile.credential_secret_ref is None
            or profile.account_scopes is None
            or profile.organization_id != actor.organization_id
            or profile.workspace_id != actor.workspace_id
            or profile.expected_issuer != actor.issuer
            or not registry.principal_allowed_for_profile(actor, profile)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="HF profile is not configured for this actor",
                detail=(
                    "The selected HF profile or its host secret reference is unavailable "
                    "to this actor."
                ),
                status=403,
            )
        profile_ref = _provider_profile_ref(actor, idempotency_key)
        linked = services.accounts.link_huggingface_profile(
            actor,
            profile_ref=profile_ref,
            credential_secret_ref=profile.credential_secret_ref,
            scopes=profile.account_scopes,
            auth_mode=profile.auth_mode,
            idempotency_key=idempotency_key,
        )
        return _linked_provider_profile_response(
            linked,
            expected_profile_ref=profile_ref,
            expected_provider="huggingface",
        )

    @router.post(
        "/api/v1/accounts/provider-profiles/huggingface/{profile_alias}/{profile_ref}/actions/rotate",
        operation_id="accountRotateHuggingFaceProfile",
    )
    async def rotate_huggingface_profile(
        profile_alias: str,
        profile_ref: str,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> dict[str, Any]:
        actor = await principal(
            request,
            workspace_id,
            operation_id="navigator.connector.operator.v1",
        )
        require(actor, "navigator.connector.operator.v1")
        registry = services.authorization_profile_registry
        profile = registry.settings.profiles.get(profile_alias) if registry is not None else None
        if (
            profile is None
            or profile.provider != "hf"
            or profile.credential_secret_ref is None
            or profile.organization_id != actor.organization_id
            or profile.workspace_id != actor.workspace_id
            or profile.expected_issuer != actor.issuer
            or not registry.principal_allowed_for_profile(actor, profile)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="HF profile is not configured for this actor",
                detail=(
                    "The selected HF profile or its host secret reference is unavailable "
                    "to this actor."
                ),
                status=403,
            )
        current_profiles = services.accounts.list_provider_profiles(actor).get("profiles")
        existing = (
            next(
                (
                    item
                    for item in current_profiles
                    if isinstance(item, Mapping)
                    and item.get("profile_ref") == profile_ref
                    and item.get("provider") == "huggingface"
                ),
                None,
            )
            if isinstance(current_profiles, list)
            else None
        )
        if existing is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_PROFILE_NOT_FOUND",
                title="HF provider profile not found",
                detail="The selected HF profile does not belong to this verified actor.",
                status=404,
            )
        linked = services.accounts.rotate_huggingface_profile(
            actor,
            profile_ref=profile_ref,
            credential_secret_ref=profile.credential_secret_ref,
            idempotency_key=idempotency_key,
        )
        return _linked_provider_profile_response(
            linked,
            expected_profile_ref=profile_ref,
            expected_provider="huggingface",
        )

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
        cloud_profile = None
        if create_request.provider in {"azure", "gcp", "runpod"}:
            registry = services.authorization_profile_registry
            cloud_profile = (
                registry.settings.profiles.get(create_request.binding_ref or "")
                if registry is not None
                else None
            )
            if (
                cloud_profile is None
                or cloud_profile.provider != create_request.provider
                or create_request.target_ref not in cloud_profile.targets
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                    title="Cloud profile is not configured",
                    detail="The selected cloud profile or target is not in trusted host settings.",
                    status=403,
                )
            account_profile_ref = registry.account_center_profile_ref(
                actor,
                cloud_profile,
                target_alias=str(create_request.target_ref),
            )
            if create_request.account_link_ref not in {None, account_profile_ref}:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                    title="Cloud profile reference is invalid",
                    detail="The Account Center profile reference is fixed by host configuration.",
                    status=403,
                    context={"reasonCode": "cloud_account_profile_ref_mismatch"},
                )
            create_request = create_request.model_copy(
                update={"account_link_ref": account_profile_ref}
            )
        create_request = create_request.model_copy(
            update={"display_name": services.display_name_for_connection(actor, create_request)}
        )
        access_mode = services.access_mode_for_connection(actor, create_request)
        if access_mode == "workspace_operator":
            require(actor, "navigator.connector.operator.v1")
        if access_mode == "workspace_operator":
            connection = services.store.create_connection(
                actor,
                create_request,
                idempotency_key=idempotency_key,
                access_mode="workspace_operator",
            )
        else:
            connection = services.store.create_connection(
                actor,
                create_request,
                idempotency_key=idempotency_key,
            )
        if cloud_profile is not None:
            _ensure_cloud_identity_profile(
                services,
                actor,
                connection=connection,
                profile=cloud_profile,
                target_alias=str(connection.target_ref),
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

    @router.post(
        "/internal/v1/connector-operation-grants",
        operation_id="internalMintConnectorOperationGrant",
    )
    async def mint_connector_operation_grant(request: Request) -> dict[str, Any]:
        """Mint one fresh Directory proof for a signed Navigator provider request."""

        body = await signed_navigator_body(request, ConnectorOperationGrantBody)
        authority = services.connector_grant_authority
        verifier = services.connector_grant_verifier
        dispatcher = services.connector_operation_dispatcher
        if authority is None or verifier is None or dispatcher is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Connector authorization is not configured",
                detail="Exchange has no complete Authority, grant verifier, or provider adapter.",
                status=503,
                retryable=True,
                context={"reasonCode": "connector_authority_not_configured"},
            )
        try:
            teams_root_profile = services.teams_message_profile
            if body.connection_ref == getattr(teams_root_profile, "connection_ref", None):
                profile = (
                    teams_root_profile.profile_for_ref(body.profile_ref)
                    if teams_root_profile is not None
                    else None
                )
                if profile is None:
                    raise PermissionError("Teams message profile is not configured")
                principal_value = IntegrationPrincipal(
                    issuer=body.principal_issuer,
                    subject=body.principal_subject,
                    organization_id=profile.organization_id,
                    workspace_id=body.workspace_id,
                    allowed_operation_ids=frozenset({body.operation_id}),
                )
                prepared = dispatcher.prepare_teams_reply(
                    principal=principal_value,
                    profile=profile,
                    provider_id=body.provider_id,
                    profile_ref=body.profile_ref,
                    operation_id=body.operation_id,
                    resource_ref=body.resource_ref,
                    arguments=body.arguments,
                    request_id=body.request_id,
                )
            elif body.connection_ref == getattr(
                services.computer_runner_profile, "connection_ref", None
            ):
                profile = services.computer_runner_profile
                if profile is None:
                    raise PermissionError("computer runner profile is not configured")
                if body.workspace_id != profile.workspace_id:
                    raise PermissionError("computer runner workspace is outside the host binding")
                principal_value = IntegrationPrincipal(
                    issuer=body.principal_issuer,
                    subject=body.principal_subject,
                    organization_id=profile.organization_id,
                    workspace_id=profile.workspace_id,
                    allowed_operation_ids=frozenset({body.operation_id}),
                )
                prepared = dispatcher.prepare_computer_operation(
                    principal=principal_value,
                    profile=profile,
                    connection_ref=body.connection_ref,
                    provider_id=body.provider_id,
                    profile_ref=body.profile_ref,
                    operation_id=body.operation_id,
                    resource_ref=body.resource_ref,
                    arguments=body.arguments,
                    request_id=body.request_id,
                )
            else:
                connection_id = UUID(body.connection_ref)
                connection = services.store.connector_connection_for_actor(
                    connection_id,
                    issuer=body.principal_issuer,
                    subject=body.principal_subject,
                    workspace_id=body.workspace_id,
                )
                principal_value = IntegrationPrincipal(
                    issuer=body.principal_issuer,
                    subject=body.principal_subject,
                    organization_id=connection.organization_id,
                    workspace_id=connection.workspace_id,
                    allowed_operation_ids=frozenset({body.operation_id}),
                )
                prepared = dispatcher.prepare_connection_operation(
                    principal=principal_value,
                    connection=connection,
                    provider_id=body.provider_id,
                    profile_ref=body.profile_ref,
                    operation_id=body.operation_id,
                    resource_ref=body.resource_ref,
                    arguments=body.arguments,
                    request_id=body.request_id,
                )
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail=(
                    "The selected connection or operation does not match its fixed provider "
                    "profile."
                ),
                status=422,
            ) from exc
        except PermissionError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Connector authorization denied",
                detail="The connector operation is outside the verified actor or host binding.",
                status=403,
                context={"reasonCode": "connector_scope_mismatch"},
            ) from exc
        calculated_digest = digest_arguments(prepared.arguments)
        if (
            prepared.provider_id != body.provider_id
            or prepared.profile_ref != body.profile_ref
            or prepared.operation_id != body.operation_id
            or prepared.resource_ref != body.resource_ref
            or calculated_digest != body.arguments_digest_sha256
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_ARGUMENTS_MISMATCH",
                title="Connector request does not match its signed scope",
                detail=(
                    "Exchange recomputed a different profile, resource, operation, or arguments "
                    "digest."
                ),
                status=403,
            )
        expected = {
            "request_id": body.request_id,
            "organization_id": prepared.expected_organization_id,
            "workspace_id": prepared.expected_workspace_id,
            "principal_issuer": body.principal_issuer,
            "principal_subject": body.principal_subject,
            "connection_ref": prepared.connection_ref,
            "provider_id": prepared.provider_id,
            "profile_ref": prepared.profile_ref,
            "operation_id": prepared.operation_id,
            "resource_ref": prepared.resource_ref,
            "arguments_digest_sha256": bytes.fromhex(calculated_digest),
        }
        grant_bytes = authority.authorize_connector_operation(
            workspace_id=body.workspace_id,
            principal_issuer=body.principal_issuer,
            principal_subject=body.principal_subject,
            connection_ref=body.connection_ref,
            provider_id=prepared.provider_id,
            profile_ref=prepared.profile_ref,
            operation_id=prepared.operation_id,
            resource_ref=prepared.resource_ref,
            arguments_digest_sha256=bytes.fromhex(calculated_digest),
            request_id=body.request_id,
        )
        claims: ConnectorGrantClaims = verifier.validate_authority_response(
            grant_bytes,
            expected=expected,
        )
        # Navigator's private JSON uses integer Unix seconds.
        # Flooring never extends the signed grant window.
        # Navigator 私有 JSON 契约采用整数 Unix 秒。向下取整不会延长签名授权窗口。
        return {
            "connectorGrantBin": base64.b64encode(grant_bytes).decode("ascii"),
            "grantRef": claims.grant_ref,
            "audience": claims.audience,
            "issuedAt": floor(claims.issued_at_epoch),
            "expiresAt": floor(claims.expires_at_epoch),
            "claims": {
                "requestId": claims.request_id,
                "organizationId": claims.organization_id,
                "workspaceId": claims.workspace_id,
                "principalIssuer": claims.principal_issuer,
                "principalSubject": claims.principal_subject,
                "connectionRef": claims.connection_ref,
                "providerId": claims.provider_id,
                "profileRef": claims.profile_ref,
                "operationId": claims.operation_id,
                "resourceRef": claims.resource_ref,
                "argumentsDigestSha256": claims.arguments_digest_sha256.hex(),
            },
        }

    @router.post(
        "/internal/v1/connector-operations/{connection_ref}",
        operation_id="internalExecuteConnectorOperation",
    )
    async def execute_connector_operation(
        connection_ref: str,
        request: Request,
    ) -> dict[str, Any]:
        """Verify one fresh signed grant and invoke a provider operation exactly once."""

        if request.url.query or request.headers.get("authorization"):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Connector authentication is ambiguous",
                detail="Connector invocation accepts only X-Cyrene-Connector-Grant-Bin.",
                status=401,
            )
        if request.headers.get("x-cyrene-execution-credential-bin"):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Connector authentication is ambiguous",
                detail="Product execution credentials cannot authorize connector operations.",
                status=401,
            )
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="Connector invocation requires application/json.",
                status=415,
            )
        raw_body = await _read_bounded_request_body(request, max_bytes=1_500_000)
        payload = parse_signed_json_object(raw_body)
        try:
            body = ConnectorOperationBody.model_validate(payload)
        except ValidationError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="The provider operation does not match its closed Exchange schema.",
                status=400,
            ) from exc
        verifier = services.connector_grant_verifier
        dispatcher = services.connector_operation_dispatcher
        if verifier is None or dispatcher is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Connector authorization is not configured",
                detail="Exchange has no connector grant verifier or provider adapter.",
                status=503,
                retryable=True,
                context={"reasonCode": "connector_dispatch_not_configured"},
            )
        encoded = request.headers.get("x-cyrene-connector-grant-bin", "")
        try:
            grant_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Connector authorization denied",
                detail="The connector grant header is malformed.",
                status=403,
            ) from exc
        if request.url.path != f"/internal/v1/connector-operations/{connection_ref}":
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Connector authorization denied",
                detail="The connector grant does not target this route.",
                status=403,
            )
        provisional = verifier.inspect(grant_bytes)
        principal_value = IntegrationPrincipal(
            issuer=provisional.principal_issuer,
            subject=provisional.principal_subject,
            organization_id=provisional.organization_id,
            workspace_id=provisional.workspace_id,
            allowed_operation_ids=frozenset({body.operation_id}),
        )
        computer_profile = services.computer_runner_profile
        if computer_profile is not None and connection_ref == computer_profile.connection_ref:
            try:
                prepared = dispatcher.prepare_computer_operation(
                    principal=principal_value,
                    profile=computer_profile,
                    connection_ref=connection_ref,
                    provider_id=body.provider_id,
                    profile_ref=body.profile_ref,
                    operation_id=body.operation_id,
                    resource_ref=body.resource_ref,
                    arguments=body.arguments,
                    request_id=body.request_id,
                )
            except PermissionError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Connector authorization denied",
                    detail="The computer operation is outside the verified host workspace.",
                    status=403,
                    context={"reasonCode": "computer_scope_mismatch"},
                ) from exc
            except ValueError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Connector request is invalid",
                    detail="The computer operation does not match its fixed argument schema.",
                    status=422,
                ) from exc
            connection = None
        else:
            try:
                connection_id = UUID(connection_ref)
            except ValueError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_NOT_FOUND",
                    title="Connector connection not found",
                    detail="The requested connector connection does not exist.",
                    status=404,
                ) from exc
            connection = services.store.connector_connection_for_actor(
                connection_id,
                issuer=provisional.principal_issuer,
                subject=provisional.principal_subject,
                workspace_id=provisional.workspace_id,
                organization_id=provisional.organization_id,
            )
            try:
                prepared = dispatcher.prepare_connection_operation(
                    principal=principal_value,
                    connection=connection,
                    provider_id=body.provider_id,
                    profile_ref=body.profile_ref,
                    operation_id=body.operation_id,
                    resource_ref=body.resource_ref,
                    arguments=body.arguments,
                    request_id=body.request_id,
                )
            except PermissionError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Connector authorization denied",
                    detail="The connector operation is outside the verified actor or host binding.",
                    status=403,
                    context={"reasonCode": "connector_scope_mismatch"},
                ) from exc
            except ValueError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Connector request is invalid",
                    detail="The provider operation does not match its fixed argument schema.",
                    status=422,
                ) from exc
        calculated_digest = digest_arguments(prepared.arguments)
        expected = {
            "request_id": body.request_id,
            "organization_id": prepared.expected_organization_id,
            "workspace_id": prepared.expected_workspace_id,
            "principal_issuer": provisional.principal_issuer,
            "principal_subject": provisional.principal_subject,
            "connection_ref": prepared.connection_ref,
            "provider_id": prepared.provider_id,
            "profile_ref": prepared.profile_ref,
            "operation_id": prepared.operation_id,
            "resource_ref": prepared.resource_ref,
            "arguments_digest_sha256": bytes.fromhex(calculated_digest),
        }
        claims = verifier.inspect(
            grant_bytes,
            expected=expected,
        )
        envelope_sha256 = _connector_envelope_sha256(
            connection_ref=prepared.connection_ref,
            provider_id=prepared.provider_id,
            profile_ref=prepared.profile_ref,
            operation_id=prepared.operation_id,
            resource_ref=prepared.resource_ref,
            arguments_sha256=calculated_digest,
        )
        try:
            reservation = services.store.reserve_connector_invocation(
                principal_value,
                request_id=body.request_id,
                connection_ref=prepared.connection_ref,
                provider_id=prepared.provider_id,
                profile_ref=prepared.profile_ref,
                operation_id=prepared.operation_id,
                resource_ref=prepared.resource_ref,
                arguments_sha256=calculated_digest,
                envelope_sha256=envelope_sha256,
                grant_ref=claims.grant_ref,
                is_mutating=prepared.is_mutating,
                now_epoch=int(datetime.now(UTC).timestamp()),
            )
        except ConnectorInvocationLedgerFull as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_RECEIPT_CAPACITY_EXCEEDED",
                title="Connector receipt capacity reached",
                detail=(
                    "Exchange cannot safely admit another provider attempt until receipts are "
                    "reconciled or expire."
                ),
                status=503,
                retryable=True,
            ) from exc
        if reservation.disposition != "NEW":
            if reservation.grant_ref != claims.grant_ref:
                claims = verifier.consume(grant_bytes, expected=expected)
                services.store.attach_connector_invocation_grant(
                    principal_value,
                    request_id=body.request_id,
                    envelope_sha256=envelope_sha256,
                    grant_ref=claims.grant_ref,
                )
            return _connector_replay_response(
                request_id=body.request_id,
                reservation=reservation,
            )
        try:
            claims = verifier.consume(grant_bytes, expected=expected)
        except ExchangeProductError:
            services.store.discard_connector_invocation(
                principal_value,
                request_id=body.request_id,
                envelope_sha256=envelope_sha256,
            )
            raise
        services.store.attach_connector_invocation_grant(
            principal_value,
            request_id=body.request_id,
            envelope_sha256=envelope_sha256,
            grant_ref=claims.grant_ref,
        )
        try:
            result = await _invoke_connector_dispatcher(
                dispatcher,
                prepared,
                principal=principal_value,
                claims=claims,
            )
        except ExchangeProductError as exc:
            result = _connector_exception_result(exc, is_mutating=prepared.is_mutating)
        except Exception:
            result = {
                "state": "UNKNOWN_RESULT" if prepared.is_mutating else "FAILED",
                "error": {"code": "PROVIDER_UNAVAILABLE", "retryable": True},
            }
        response = _connector_operation_response(
            claims.request_id,
            result,
            is_mutating=prepared.is_mutating,
            operation_id=prepared.operation_id,
        )
        outcome = response["outcome"]
        receipt_state = {
            "verified": "SUCCEEDED",
            "pending": "PENDING",
            "uncertain": "UNKNOWN_RESULT",
            "failed": "FAILED",
        }[str(outcome)]
        operation_ref = _connector_operation_ref(result)
        services.store.complete_connector_invocation(
            principal_value,
            request_id=body.request_id,
            envelope_sha256=envelope_sha256,
            state=receipt_state,  # type: ignore[arg-type]
            response=response,
            operation_ref=operation_ref,
            response_status=200,
            now_epoch=int(datetime.now(UTC).timestamp()),
        )
        if prepared.operation_id == "cloud.operation.status.read" and _connector_operation_state(
            result
        ) in {"SUCCEEDED", "FAILED"}:
            requested_ref = body.arguments.get("operation_ref")
            reconciled_ref = operation_ref or (
                requested_ref if isinstance(requested_ref, str) else None
            )
            if reconciled_ref:
                services.store.reconcile_connector_invocations(
                    principal_value,
                    profile_ref=prepared.profile_ref,
                    operation_ref=reconciled_ref,
                    terminal_state=_connector_operation_state(result),  # type: ignore[arg-type]
                    now_epoch=int(datetime.now(UTC).timestamp()),
                )
        return response

    @router.post(
        "/internal/v1/teams/messages",
        operation_id="internalSendTeamsMessage",
        response_model=None,
    )
    async def send_teams_message(
        request: Request,
    ) -> dict[str, Any] | JSONResponse:
        """Deliver one fixed Teams channel or owner-private message under a fresh grant."""

        if request.url.query or request.headers.get("authorization"):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Connector authentication is ambiguous",
                detail="Teams egress accepts only X-Cyrene-Connector-Grant-Bin.",
                status=401,
            )
        if request.headers.get("x-cyrene-execution-credential-bin"):
            raise ExchangeProductError(
                code="EXCHANGE_INTEGRATION_AUTH_AMBIGUOUS",
                title="Connector authentication is ambiguous",
                detail="Product execution credentials cannot authorize Teams egress.",
                status=401,
            )
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="Teams egress requires application/json.",
                status=415,
            )
        raw_body = await _read_bounded_request_body(request, max_bytes=64 * 1024)
        payload = parse_signed_json_object(raw_body)
        is_owner_private = payload.get("targetKind") == "owner_private"
        try:
            body = (
                TeamsPrivateMessageBody.model_validate(payload)
                if is_owner_private
                else TeamsMessageBody.model_validate(payload)
            )
        except ValidationError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                title="Connector request is invalid",
                detail="The Teams message does not match its closed Exchange schema.",
                status=400,
            ) from exc
        verifier = services.connector_grant_verifier
        profile = services.teams_message_profile
        client = services.teams_message_client
        if verifier is None or profile is None or client is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Teams connector is not configured",
                detail="Exchange has no complete Teams provider binding or grant verifier.",
                status=503,
                retryable=True,
                context={"reasonCode": "teams_provider_not_configured"},
            )
        if body.provider_id is not None and body.provider_id != "msteams":
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_MISMATCH",
                title="Teams provider mismatch",
                detail="The egress request must use the configured msteams provider.",
                status=403,
            )
        encoded = request.headers.get("x-cyrene-connector-grant-bin", "")
        try:
            grant_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Teams connector authorization denied",
                detail="The connector grant header is malformed.",
                status=403,
            ) from exc
        try:
            provisional = verifier.inspect(grant_bytes)
        except PermissionError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Teams connector authorization denied",
                detail="The signed Teams actor grant is invalid.",
                status=403,
            ) from exc
        teams_root_profile = services.teams_message_profile
        profile = (
            teams_root_profile.profile_for_ref(provisional.profile_ref)
            if teams_root_profile is not None
            else None
        )
        if profile is None or profile.connection_ref != provisional.connection_ref:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Teams connector authorization denied",
                detail="The signed grant does not select a configured Teams profile.",
                status=403,
                context={"reasonCode": "teams_profile_mismatch"},
            )
        if provisional.principal_issuer != profile.expected_issuer:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Teams connector authorization denied",
                detail="The signed Teams actor issuer does not match the configured tenant.",
                status=403,
            )
        if (
            profile.fixed_owner_subject is not None
            and provisional.principal_subject != profile.fixed_owner_subject
        ):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                title="Teams connector authorization denied",
                detail="The signed Teams actor does not match the fixed notification owner.",
                status=403,
                context={"reasonCode": "teams_notification_owner_mismatch"},
            )
        if is_owner_private:
            if not isinstance(body, TeamsPrivateMessageBody):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Teams connector request is invalid",
                    detail="The private Teams target does not match its closed request schema.",
                    status=400,
                )
            private_conversation = body.conversation
            if provisional.principal_subject != private_conversation.actor_aad_object_id:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Teams connector authorization denied",
                    detail="The signed grant actor does not match the personal chat recipient.",
                    status=403,
                    context={"reasonCode": "teams_private_actor_mismatch"},
                )
            try:
                profile.authorize_personal_target(
                    principal_subject=provisional.principal_subject,
                    tenant_id=private_conversation.tenant_id,
                    bot_app_id=private_conversation.bot_app_id,
                    actor_aad_object_id=private_conversation.actor_aad_object_id,
                    conversation_id=private_conversation.conversation_id,
                    service_url=private_conversation.service_url,
                )
            except PermissionError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Teams connector authorization denied",
                    detail="The owner-private Teams target is outside its host actor allowlist.",
                    status=403,
                    context={"reasonCode": "teams_private_actor_scope_mismatch"},
                ) from exc
            except ValueError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Teams private route is invalid",
                    detail="The owner-private Teams route is outside fixed Bot Framework routes.",
                    status=400,
                    context={"reasonCode": "teams_private_route_invalid"},
                ) from exc
            conversation: dict[str, Any] = {
                "tenantId": private_conversation.tenant_id,
                "botAppId": private_conversation.bot_app_id,
                "actorAadObjectId": private_conversation.actor_aad_object_id,
                "conversationId": private_conversation.conversation_id,
                "serviceUrl": private_conversation.service_url,
            }
            arguments = {
                "targetKind": "owner_private",
                "conversation": conversation,
                "text": body.text,
            }
            resource_ref = teams_personal_resource_ref(conversation)
        else:
            if not isinstance(body, TeamsMessageBody):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Teams connector request is invalid",
                    detail="The channel Teams target does not match its closed request schema.",
                    status=400,
                )
            try:
                profile.authorize_conversation(
                    tenant_id=body.conversation.tenant_id,
                    team_id=body.conversation.team_id,
                    channel_id=body.conversation.channel_id,
                    conversation_id=body.conversation.conversation_id,
                    root_thread_id=body.conversation.root_thread_id,
                    service_url=body.conversation.service_url,
                )
                validate_teams_service_url(
                    body.conversation.service_url,
                    tenant_id=body.conversation.tenant_id,
                )
            except PermissionError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Teams connector authorization denied",
                    detail="The requested Teams channel is outside the host-configured allowlist.",
                    status=403,
                    context={"reasonCode": "teams_channel_scope_mismatch"},
                ) from exc
            except ValueError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Teams service URL is invalid",
                    detail=(
                        "The Teams serviceUrl is outside the fixed official Bot Framework routes."
                    ),
                    status=400,
                ) from exc
            arguments = {
                "conversation": {
                    "tenantId": body.conversation.tenant_id,
                    "teamId": body.conversation.team_id,
                    "channelId": body.conversation.channel_id,
                    "conversationId": body.conversation.conversation_id,
                    "rootThreadId": body.conversation.root_thread_id,
                    "serviceUrl": body.conversation.service_url,
                },
                "text": body.text,
            }
            channel_conversation = arguments["conversation"]
            if not isinstance(channel_conversation, Mapping):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Teams connector request is invalid",
                    detail="The Teams conversation route must be a structured object.",
                    status=400,
                )
            resource_ref = _teams_resource_ref(channel_conversation)
        expected = {
            "request_id": body.request_id,
            "organization_id": profile.organization_id,
            "workspace_id": profile.workspace_id,
            "principal_issuer": profile.expected_issuer,
            "principal_subject": provisional.principal_subject,
            "connection_ref": profile.connection_ref,
            "provider_id": "msteams",
            "profile_ref": profile.profile_ref,
            "operation_id": "msteams.message.reply",
            "resource_ref": resource_ref,
            "arguments_digest_sha256": bytes.fromhex(digest_arguments(arguments)),
        }
        claims = verifier.inspect(
            grant_bytes,
            expected=expected,
        )
        principal_value = IntegrationPrincipal(
            issuer=claims.principal_issuer,
            subject=claims.principal_subject,
            organization_id=profile.organization_id,
            workspace_id=profile.workspace_id,
            allowed_operation_ids=frozenset({"msteams.message.reply"}),
        )
        arguments_sha256 = digest_arguments(arguments)
        envelope_sha256 = _connector_envelope_sha256(
            connection_ref=profile.connection_ref,
            provider_id="msteams",
            profile_ref=profile.profile_ref,
            operation_id="msteams.message.reply",
            resource_ref=resource_ref,
            arguments_sha256=arguments_sha256,
        )
        try:
            reservation = services.store.reserve_connector_invocation(
                principal_value,
                request_id=body.request_id,
                connection_ref=profile.connection_ref,
                provider_id="msteams",
                profile_ref=profile.profile_ref,
                operation_id="msteams.message.reply",
                resource_ref=resource_ref,
                arguments_sha256=arguments_sha256,
                envelope_sha256=envelope_sha256,
                grant_ref=claims.grant_ref,
                is_mutating=True,
                now_epoch=int(datetime.now(UTC).timestamp()),
            )
        except ConnectorInvocationLedgerFull as exc:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_RECEIPT_CAPACITY_EXCEEDED",
                title="Connector receipt capacity reached",
                detail=(
                    "Exchange cannot safely admit another Teams delivery attempt until prior "
                    "receipts expire."
                ),
                status=503,
                retryable=True,
            ) from exc
        if reservation.disposition != "NEW":
            if reservation.grant_ref != claims.grant_ref:
                claims = verifier.consume(grant_bytes, expected=expected)
                services.store.attach_connector_invocation_grant(
                    principal_value,
                    request_id=body.request_id,
                    envelope_sha256=envelope_sha256,
                    grant_ref=claims.grant_ref,
                )
            response = reservation.response or {
                "requestId": body.request_id,
                "status": ("rate_limited" if reservation.state == "RATE_LIMITED" else "uncertain"),
                "reasonCode": "teams_delivery_receipt_unavailable",
                **({"retryAfterSeconds": 1} if reservation.state == "RATE_LIMITED" else {}),
            }
            if reservation.http_status == 429:
                retry_after = response.get("retryAfterSeconds", 1)
                retry_after_seconds = (
                    retry_after if isinstance(retry_after, int) and retry_after > 0 else 1
                )
                return JSONResponse(
                    status_code=429,
                    content=response,
                    headers={"Retry-After": str(retry_after_seconds)},
                )
            return response
        try:
            claims = verifier.consume(grant_bytes, expected=expected)
        except ExchangeProductError:
            services.store.discard_connector_invocation(
                principal_value,
                request_id=body.request_id,
                envelope_sha256=envelope_sha256,
            )
            raise
        services.store.attach_connector_invocation_grant(
            principal_value,
            request_id=body.request_id,
            envelope_sha256=envelope_sha256,
            grant_ref=claims.grant_ref,
        )
        try:
            if isinstance(body, TeamsPrivateMessageBody):
                evidence = await run_in_threadpool(
                    client.send_private,
                    bot_app_id=body.conversation.bot_app_id,
                    tenant_id=body.conversation.tenant_id,
                    actor_aad_object_id=body.conversation.actor_aad_object_id,
                    conversation_id=body.conversation.conversation_id,
                    service_url=body.conversation.service_url,
                    text=body.text,
                    request_id=body.request_id,
                )
            else:
                evidence = await run_in_threadpool(
                    client.send_reply,
                    bot_app_id=profile.bot_app_id,
                    tenant_id=body.conversation.tenant_id,
                    team_id=body.conversation.team_id,
                    channel_id=body.conversation.channel_id,
                    conversation_id=body.conversation.conversation_id,
                    root_thread_id=body.conversation.root_thread_id,
                    service_url=body.conversation.service_url,
                    text=body.text,
                    request_id=body.request_id,
                )
        except ExchangeProductError as exc:
            known_rejection = {
                "EXCHANGE_TEAMS_AUTH_EXPIRED": "auth_expired",
                "EXCHANGE_TEAMS_PERMISSION_DENIED": "permission_denied",
            }.get(exc.code)
            if known_rejection is not None:
                response = {
                    "requestId": claims.request_id,
                    "status": "rejected",
                    "reasonCode": known_rejection,
                }
                services.store.complete_connector_invocation(
                    principal_value,
                    request_id=body.request_id,
                    envelope_sha256=envelope_sha256,
                    state="REJECTED",
                    response=response,
                    operation_ref=None,
                    response_status=200,
                    now_epoch=int(datetime.now(UTC).timestamp()),
                )
                return response
            response = {
                "requestId": claims.request_id,
                "status": "uncertain",
                "reasonCode": "teams_delivery_outcome_unknown",
            }
            services.store.complete_connector_invocation(
                principal_value,
                request_id=body.request_id,
                envelope_sha256=envelope_sha256,
                state="UNKNOWN_RESULT",
                response=response,
                operation_ref=None,
                response_status=200,
                now_epoch=int(datetime.now(UTC).timestamp()),
            )
            return response
        except Exception:
            response = {
                "requestId": claims.request_id,
                "status": "uncertain",
                "reasonCode": "teams_delivery_outcome_unknown",
            }
            services.store.complete_connector_invocation(
                principal_value,
                request_id=body.request_id,
                envelope_sha256=envelope_sha256,
                state="UNKNOWN_RESULT",
                response=response,
                operation_ref=None,
                response_status=200,
                now_epoch=int(datetime.now(UTC).timestamp()),
            )
            return response
        status_by_proto = {
            "ACCEPTED": "accepted",
            "REJECTED": "rejected",
            "RATE_LIMITED": "rate_limited",
        }
        status = (
            "accepted"
            if evidence.accepted
            else status_by_proto.get(str(evidence.evidence.get("status", "REJECTED")), "rejected")
        )
        response = {
            "requestId": claims.request_id,
            "status": status,
            "vendorMessageId": evidence.vendor_message_id,
            "reasonCode": evidence.evidence.get("reasonCode"),
        }
        retry_after = evidence.evidence.get("retryAfterSeconds")
        retry_after_seconds = 1
        if status == "rate_limited":
            retry_after_seconds = (
                min(retry_after, 300)
                if (
                    isinstance(retry_after, int)
                    and not isinstance(retry_after, bool)
                    and retry_after > 0
                )
                else 1
            )
            response["retryAfterSeconds"] = retry_after_seconds
        state = {
            "accepted": "SUCCEEDED",
            "rejected": "REJECTED",
            "rate_limited": "RATE_LIMITED",
        }[status]
        status_code = 429 if status == "rate_limited" else 200
        services.store.complete_connector_invocation(
            principal_value,
            request_id=body.request_id,
            envelope_sha256=envelope_sha256,
            state=state,  # type: ignore[arg-type]
            response=response,
            operation_ref=None,
            response_status=status_code,
            now_epoch=int(datetime.now(UTC).timestamp()),
        )
        if status == "rate_limited":
            return JSONResponse(
                status_code=429,
                content=response,
                headers={"Retry-After": str(retry_after_seconds)},
            )
        return response

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
                "externalSubject": None,
                "loginState": LoginState.UNKNOWN.value,
                "authorizationState": AuthorizationState.UNKNOWN.value,
                "checkedAt": None,
                "expiresAt": None,
                "refreshExpiresAt": None,
                "generation": 0,
                "capabilities": [],
                "reasonCode": "not_observed",
                "scopeSchemaVersion": None,
                "enabledFeatures": [],
                "requiredOAuthScopes": [],
                "targetRefCount": 0,
                "reauthRequired": False,
                "reauthReasonCode": None,
            }
        return {
            "connectionId": str(connection.id),
            "provider": connection.provider,
            "authorizationRef": health.authorization_ref,
            "externalSubject": health.external_subject,
            "loginState": health.login_state.value,
            "authorizationState": health.authorization_state.value,
            "checkedAt": health.checked_at,
            "expiresAt": health.expires_at,
            "refreshExpiresAt": health.refresh_expires_at,
            "generation": health.generation,
            "capabilities": [
                capability.model_dump(mode="python", by_alias=True)
                for capability in health.capabilities
            ],
            "reasonCode": health.reason_code,
            "scopeSchemaVersion": health.scope_schema_version,
            "enabledFeatures": health.enabled_features,
            "requiredOAuthScopes": health.required_oauth_scopes,
            "targetRefCount": health.target_ref_count,
            "reauthRequired": health.reauth_required,
            "reauthReasonCode": health.reauth_reason_code,
        }

    @router.post(
        "/internal/v1/authorization-health/snapshots",
        operation_id="internalReadAuthorizationHealthSnapshots",
        response_model=AuthorizationHealthSnapshotResponse,
    )
    async def read_authorization_health_snapshots(request: Request) -> dict[str, Any]:
        """Project only pinned-owner health metadata to the signed Navigator workload."""

        body = await signed_navigator_body(request, AuthorizationHealthSnapshotBody)
        registry = services.authorization_profile_registry
        if registry is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Authorization snapshot is not configured",
                detail="Exchange has no host-owned authorization profile registry.",
                status=503,
                retryable=True,
                context={"reasonCode": "authorization_profile_registry_unavailable"},
            )

        snapshots: list[dict[str, Any]] = []
        for connection_id in body.connection_ids:
            connection = services.store.current_connection_for_provider_call(connection_id)
            if (
                connection is None
                or connection.organization_id != body.organization_id
                or connection.workspace_id != body.workspace_id
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_RESOURCE_NOT_FOUND",
                    title="Authorization connection not found",
                    detail="The requested configured connection is unavailable in this workspace.",
                    status=404,
                )
            try:
                # The owner comes from the persisted row and is then checked against
                # the fixed host profile. No principal or destination is accepted in
                # the Navigator request body. Static cloud profiles use the same
                # fresh connector-only Directory grant as Navigator operations.
                resolver = services.current_context_resolver
                owner = (
                    resolver.for_connection(
                        connection,
                        operation_id="integrationGetAuthorizationHealth",
                    )
                    if resolver is not None
                    else None
                )
                if owner is None:
                    raise PermissionError("current Directory authorization is unavailable")
                registry.profile_for_connection(
                    owner,
                    connection,
                    operation_id="integrationGetAuthorizationHealth",
                )
                services.store.get_connection(
                    owner,
                    connection_id,
                    authorization_operation_id="integrationGetAuthorizationHealth",
                )
                health = services.store.latest_authorization_health(
                    owner,
                    connection_id,
                    authorization_operation_id="integrationGetAuthorizationHealth",
                )
            except PermissionError as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Authorization snapshot denied",
                    detail="The connection owner is outside its fixed host profile.",
                    status=403,
                    context={"reasonCode": "snapshot_connection_scope_mismatch"},
                ) from exc
            except IntegrationNotFound as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_RESOURCE_NOT_FOUND",
                    title="Authorization connection not found",
                    detail="The requested configured connection is unavailable in this workspace.",
                    status=404,
                ) from exc

            if health is None:
                snapshots.append(
                    {
                        "connectionId": connection.id,
                        "provider": connection.provider,
                        "loginState": LoginState.UNKNOWN.value,
                        "authorizationState": AuthorizationState.UNKNOWN.value,
                        "checkedAt": None,
                        "expiresAt": None,
                        "refreshExpiresAt": None,
                        "generation": 0,
                        "capabilities": [],
                        "reasonCode": "not_observed",
                        "externalSubject": None,
                        "scopeSchemaVersion": None,
                        "enabledFeatures": [],
                        "requiredOAuthScopes": [],
                        "targetRefCount": 0,
                        "reauthRequired": False,
                        "reauthReasonCode": None,
                    }
                )
                continue

            snapshots.append(
                {
                    "connectionId": connection.id,
                    "provider": connection.provider,
                    "externalSubject": health.external_subject,
                    "loginState": health.login_state.value,
                    "authorizationState": health.authorization_state.value,
                    "checkedAt": health.checked_at,
                    "expiresAt": health.expires_at,
                    "refreshExpiresAt": health.refresh_expires_at,
                    "generation": health.generation,
                    "capabilities": [
                        {
                            "capabilityId": capability.capability_id,
                            "state": capability.state.value,
                            "lastVerifiedAt": capability.last_verified_at,
                            "expiresAt": capability.expires_at,
                            "reasonCode": _safe_health_reason_code(capability.reason_code),
                        }
                        for capability in health.capabilities
                    ],
                    "reasonCode": _safe_health_reason_code(health.reason_code),
                    "scopeSchemaVersion": health.scope_schema_version,
                    "enabledFeatures": health.enabled_features,
                    "requiredOAuthScopes": health.required_oauth_scopes,
                    "targetRefCount": health.target_ref_count,
                    "reauthRequired": health.reauth_required,
                    "reauthReasonCode": _safe_health_reason_code(health.reauth_reason_code),
                }
            )
        return {"connections": snapshots}

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
        connection = _connection_for_renewal(
            services.store,
            actor,
            authorization_id,
            operation_id="accountBeginRenewalSession",
        )
        _require_supported_renewal_profile(
            services,
            actor,
            connection,
            operation_id="accountBeginRenewalSession",
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
                        user_code=getattr(provider_session, "user_code", None),
                        qr_attachment_ref=provider_session.qr_attachment_ref,
                        generation=provider_session.generation,
                    )
                except PermissionError as exc:
                    services.store.fail_renewal_session_start(
                        actor,
                        authorization_id,
                        session.session_ref,
                    )
                    raise ExchangeProductError(
                        code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                        title="Renewal authorization denied",
                        detail="The provider rejected the exact renewal profile scope.",
                        status=403,
                        context={"reasonCode": "provider_start_rejected"},
                    ) from exc
                except ExchangeProductError as exc:
                    if (
                        exc.status < 500
                        and not exc.retryable
                        and exc.status
                        not in {
                            408,
                            409,
                            425,
                            429,
                        }
                    ):
                        services.store.fail_renewal_session_start(
                            actor,
                            authorization_id,
                            session.session_ref,
                        )
                        raise
                    services.store.mark_renewal_start_unknown(
                        actor,
                        authorization_id,
                        session.session_ref,
                        reason_code="provider_start_outcome_unknown",
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
        connection = _connection_for_renewal(
            services.store,
            actor,
            session.authorization_ref,
            operation_id="accountGetRenewalSession",
        )
        _require_supported_renewal_profile(
            services,
            actor,
            connection,
            operation_id="accountGetRenewalSession",
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
                    user_code=getattr(provider_session, "user_code", None),
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
                        user_code=session.user_code,
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
        if services.delegation_authorizer is None:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_DELEGATION_UNAVAILABLE",
                title="Platform delegation is unavailable",
                detail="This Exchange profile has no ProductWorkload delegation channel.",
                status=503,
                retryable=True,
            )
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
            "observedAt": _http_utc_timestamp(snapshot.observed_at),
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
