"""Versioned HTTP facade for linked accounts and fixed GitHub workflows.

Public identity is derived only from Platform verification. Webhook bytes are
verified by the configured GitHub capability before Exchange persists events.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from fastapi import Path as ApiPath
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.clients import AccountCenterClient, GitHubIssuesClient
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    CreateSyncBinding,
    EnqueueIssueAction,
    IntegrationAuthorizationError,
    IntegrationPrincipal,
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
    """Create one fixed GitHub repository connection without member credentials."""

    repository_id: str = Field(min_length=1, max_length=200)
    repository_name: str = Field(min_length=1, max_length=300)


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
    issue_number: int = Field(alias="issueNumber")
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
        self.transport_clients = transport_clients

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
    )
    async def create_connection(
        body: CreateConnectionBody,
        request: Request,
        workspace_id: str | None = Query(default=None, alias="workspaceId"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=200),
    ) -> Any:
        actor = await principal(request, workspace_id, operation_id="integrationCreateConnection")
        require(actor, "integrationCreateConnection")
        return services.store.create_connection(
            actor,
            CreateIntegrationConnection(
                repository_id=body.repository_id,
                repository_name=body.repository_name,
            ),
            idempotency_key=idempotency_key,
        )

    @router.get("/api/v1/integrations/connections", operation_id="integrationListConnections")
    async def list_connections(
        request: Request, workspace_id: str | None = Query(default=None, alias="workspaceId")
    ) -> list[Any]:
        actor = await principal(request, workspace_id, operation_id="integrationListConnections")
        require(actor, "integrationListConnections")
        return services.store.list_connections(actor)

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
        return _operation_status(services.store.get_operation(actor, operation_id))

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
