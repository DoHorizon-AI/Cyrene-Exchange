"""Signed DirectPlugin adapters for configured authorization, cloud, and email tools.

Module: cyrene_exchange_product.integrations.authorization_cloud_provider
Role: Recheck current authority, sign fixed provider calls, and sanitize results.
模块职责：重验当前权限、签名固定 Provider 调用并净化返回结果。
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.authorization_cloud import (
    EmailAuthorizationUnavailable,
    EmailDeliveryRetryableError,
    EmailSubmissionEvidence,
    ProviderObservationUnavailable,
    ProviderRenewalSession,
)
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    AuthorizationCloudProfileRegistry,
    AuthorizationProviderProfile,
    DirectPluginEndpointConfig,
    EmailNotificationProfile,
    validate_microsoft_graph_office_v2_scope,
)
from cyrene_exchange_product.integrations.azure_devops import (
    ADO_OBSERVATION_OPERATIONS,
    scope_for_authorized_source,
)
from cyrene_exchange_product.integrations.azure_devops import (
    validate_profile_identity as validate_azure_devops_profile_identity,
)
from cyrene_exchange_product.integrations.clients import (
    PROVIDER_CAPABILITY,
    DirectInvoker,
    ProviderToolDefinition,
    _direct_payload,
    _raise_provider_error,
    list_provider_tool_catalog,
)
from cyrene_exchange_product.integrations.connector_operations import (
    _account_center_grant_proof,
    _resource_projection,
    _resource_ref,
)
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    digest_arguments,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    GRAPH_MUTATING_OPERATIONS,
    GRAPH_OPERATIONS,
    SHAREPOINT_READ_OPERATIONS,
    SHAREPOINT_V2_READ_OPERATIONS,
    profile_scope_metadata,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    lease_arguments_for_operation as microsoft_graph_lease_arguments,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    validate_profile_identity as validate_microsoft_graph_profile_identity,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    validate_scope_digest as validate_microsoft_graph_scope_digest,
)
from cyrene_exchange_product.integrations.microsoft_identity import (
    microsoft_identity_for_principal,
)
from cyrene_exchange_product.integrations.models import (
    AuthorizationCapabilityRecord,
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudResourceRecord,
    CloudResourceState,
    EmailNotificationJob,
    IntegrationConflict,
    IntegrationConnection,
    IntegrationNotFound,
    IntegrationPrincipal,
    LoginState,
    RenewalState,
    SnapshotFreshness,
)
from cyrene_exchange_product.integrations.store import IntegrationStore

EXCHANGE_SERVICE_CALLER_ID = "exchange-service"


class PlatformCurrentAuthorizationContextResolver:
    """Reverify bearer or one-use Directory proof before every worker call."""

    def __init__(
        self,
        *,
        store: IntegrationStore,
        identity_verifier: Any,
        registry: AuthorizationCloudProfileRegistry,
        bearer_token: Callable[[str], str | None],
        connector_grant_authority: Any = None,
        connector_grant_verifier: Any = None,
    ) -> None:
        self._store = store
        self._identity_verifier = identity_verifier
        self._registry = registry
        self._bearer_token = bearer_token
        self._connector_grant_authority = connector_grant_authority
        self._connector_grant_verifier = connector_grant_verifier

    def for_connection(
        self,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        """Reload the connection and reverify its owner before each provider call."""

        try:
            current, profile, principal, used_static_owner = self._resolve_connection_principal(
                connection,
                operation_id=operation_id,
            )
            if used_static_owner:
                provider_operation_id, arguments = _health_grant_scope(
                    current,
                    profile,
                    product_operation_id=operation_id,
                )
                if provider_operation_id is None or arguments is None:
                    return None
                principal, _claims = self._mint_connector_grant(
                    current,
                    profile,
                    principal,
                    operation_id=provider_operation_id,
                    arguments=arguments,
                    product_operation_id=operation_id,
                )
            return principal
        except Exception as exc:
            _LOGGER.info(
                "Current authorization is unavailable for an integration connection (%s)",
                type(exc).__name__,
            )
            return None

    def for_connection_with_connector_grant(
        self,
        connection: IntegrationConnection,
        *,
        operation_id: str,
        provider_operation_id: str,
        arguments: Mapping[str, object],
    ) -> tuple[IntegrationPrincipal | None, ConnectorGrantClaims | None]:
        """Return a fresh principal plus one verified shared-profile proof.

        Account Center consumes the projected claims when minting a shared HF lease.
        The signed grant itself is verified and consumed by Exchange first.
        中文：HF 共享租约同时交由 Account Center 按原 claims 消费。
        """

        try:
            if operation_id != "integrationGetAuthorizationHealth":
                return None, None
            current, profile, principal, _used_static_owner = self._resolve_connection_principal(
                connection,
                operation_id=operation_id,
            )
            if current.access_mode != "workspace_operator":
                return principal, None
            if provider_operation_id not in {
                "cloud.provider.health.read",
                "huggingface.repo.get",
            }:
                return None, None
            return self._mint_connector_grant(
                current,
                profile,
                principal,
                operation_id=provider_operation_id,
                arguments=arguments,
                product_operation_id=operation_id,
            )
        except Exception as exc:
            _LOGGER.info(
                "Current connector grant is unavailable for an integration connection (%s)",
                type(exc).__name__,
            )
            return None, None

    def _resolve_connection_principal(
        self,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> tuple[IntegrationConnection, AuthorizationProviderProfile, IntegrationPrincipal, bool]:
        """Resolve a live bearer principal or a static owner awaiting Authority proof."""

        current = self._store.current_connection_for_provider_call(connection.id)
        if current is None or current != connection:
            raise PermissionError("connection changed before current authorization")
        try:
            context, _profile = self._registry.context_for_connection(current)
            principal = self._verified_principal(context, operation_id=operation_id)
            profile, _target = self._registry.profile_for_connection(
                principal,
                current,
                operation_id=operation_id,
            )
            return current, profile, principal, False
        except PermissionError:
            profile, _target = self._registry.profile_for_static_workspace_operator_connection(
                current
            )
            principal = IntegrationPrincipal(
                issuer=current.actor_issuer,
                subject=current.actor_subject,
                organization_id=current.organization_id,
                workspace_id=current.workspace_id,
                allowed_operation_ids=frozenset({operation_id}),
            )
            self._registry.profile_for_connection(
                principal,
                current,
                operation_id=operation_id,
            )
            return current, profile, principal, True

    def _mint_connector_grant(
        self,
        connection: IntegrationConnection,
        profile: AuthorizationProviderProfile,
        principal: IntegrationPrincipal,
        *,
        operation_id: str,
        arguments: Mapping[str, object],
        product_operation_id: str,
    ) -> tuple[IntegrationPrincipal, ConnectorGrantClaims]:
        """Mint, validate, and consume one exact live Directory connector proof."""

        authority = self._connector_grant_authority
        verifier = self._connector_grant_verifier
        if authority is None or verifier is None or not verifier.configured:
            raise PermissionError("Platform connector-grant authority is unavailable")
        if profile.provider != connection.provider:
            raise PermissionError("provider profile does not match the persisted connection")
        provider_id = "huggingface" if connection.provider == "hf" else connection.provider
        profile_ref = (
            connection.account_link_ref if connection.provider == "hf" else connection.binding_ref
        )
        if not profile_ref:
            raise PermissionError("provider profile reference is unavailable")
        payload = dict(arguments)
        arguments_digest = digest_arguments(payload)
        target = _resource_projection(
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            arguments=payload,
        )
        resource_ref = _resource_ref(
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            target=target,
        )
        request_id = str(uuid4())
        expected = {
            "request_id": request_id,
            "organization_id": connection.organization_id,
            "workspace_id": connection.workspace_id,
            "principal_issuer": connection.actor_issuer,
            "principal_subject": connection.actor_subject,
            "connection_ref": str(connection.id),
            "provider_id": provider_id,
            "profile_ref": profile_ref,
            "operation_id": operation_id,
            "resource_ref": resource_ref,
            "arguments_digest_sha256": bytes.fromhex(arguments_digest),
        }
        grant_bytes = authority.authorize_connector_operation(
            workspace_id=connection.workspace_id,
            principal_issuer=connection.actor_issuer,
            principal_subject=connection.actor_subject,
            connection_ref=str(connection.id),
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments_digest_sha256=bytes.fromhex(arguments_digest),
            request_id=request_id,
        )
        verifier.validate_authority_response(grant_bytes, expected=expected)
        claims = verifier.consume(grant_bytes, expected=expected)
        verified_principal = IntegrationPrincipal(
            issuer=claims.principal_issuer,
            subject=claims.principal_subject,
            organization_id=claims.organization_id,
            workspace_id=claims.workspace_id,
            allowed_operation_ids=frozenset({product_operation_id, operation_id}),
        )
        self._registry.profile_for_connection(
            verified_principal,
            connection,
            operation_id=product_operation_id,
        )
        return verified_principal, claims

    def for_claimed_notification(
        self,
        job: EmailNotificationJob,
        *,
        claim_fence: int,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        """Verify the exact fenced CLAIMED row before SENDING is persisted."""

        try:
            if operation_id != "integrationDeliverNotification":
                return None
            current = self._store.current_claimed_email_job_for_authority(
                job.id,
                claim_fence=claim_fence,
            )
            return self._current_notification_principal(
                current,
                job,
                claim_fence=claim_fence,
                operation_id=operation_id,
            )
        except Exception as exc:
            _LOGGER.info(
                "Current authorization is unavailable for an email notification (%s)",
                type(exc).__name__,
            )
            return None

    def for_sending_notification(
        self,
        job: EmailNotificationJob,
        *,
        claim_fence: int,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        """Reverify the exact fenced SENDING row immediately before provider signing."""

        try:
            if operation_id != "integrationDeliverNotification":
                return None
            current = self._store.current_sending_email_job_for_provider_call(
                job.id,
                claim_fence=claim_fence,
            )
            return self._current_notification_principal(
                current,
                job,
                claim_fence=claim_fence,
                operation_id=operation_id,
            )
        except Exception as exc:
            _LOGGER.info(
                "Current authorization is unavailable for an email notification (%s)",
                type(exc).__name__,
            )
            return None

    def _current_notification_principal(
        self,
        current: EmailNotificationJob | None,
        requested: EmailNotificationJob,
        *,
        claim_fence: int,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        """Bind one explicit outbox state read to its immutable actor and claim."""

        if (
            current is None
            or requested.claim_fence != claim_fence
            or current.claim_fence != claim_fence
            or not _same_email_request(current, requested)
        ):
            return None
        context = self._registry.email_context_for_job(current)
        return self._verified_principal(context, operation_id=operation_id)

    def email_recipient_for_connection(
        self,
        connection: IntegrationConnection,
    ) -> str | None:
        """Return the fixed recipient alias only for an explicitly configured owner."""

        return self._registry.email_recipient_for_connection(connection)

    def email_recipient_for_principal(
        self,
        principal: IntegrationPrincipal,
    ) -> str | None:
        """Resolve the host-fixed mail alias for the already Platform-verified HTTP actor."""

        return self._registry.email_recipient_for_principal(principal)

    def _verified_principal(
        self,
        context: Any,
        *,
        operation_id: str,
    ) -> IntegrationPrincipal:
        # Resolve the environment variable on every call. The bearer and returned
        # principal are never retained on this long-lived resolver instance.
        bearer = self._bearer_token(context.bearer_token_env_ref)
        if not isinstance(bearer, str) or not bearer.strip():
            raise PermissionError("current Platform bearer is unavailable")
        principal = self._identity_verifier.principal_for(
            bearer_token=bearer,
            workspace_id=context.workspace_id,
        )
        if not isinstance(principal, IntegrationPrincipal):
            raise PermissionError("Platform identity verifier returned an invalid principal")
        if (
            principal.issuer != context.issuer
            or principal.subject != context.subject
            or principal.organization_id != context.organization_id
            or principal.workspace_id != context.workspace_id
        ):
            raise PermissionError("Platform identity does not match configured actor pins")
        principal.require(operation_id)
        return principal


def _health_grant_scope(
    connection: IntegrationConnection,
    profile: AuthorizationProviderProfile,
    *,
    product_operation_id: str,
) -> tuple[str | None, dict[str, object] | None]:
    """Build one host-selected read target for a background health probe."""

    if product_operation_id != "integrationGetAuthorizationHealth":
        return None, None
    if connection.provider == "hf":
        target = profile.targets.get(connection.target_ref or "")
        repositories = (profile.account_scopes or {}).get("repositories")
        if target is None or not isinstance(repositories, list):
            return None, None
        selected = [
            item
            for item in repositories
            if isinstance(item, Mapping)
            and item.get("repo_id") == target.target_ref
            and "read" in item.get("permissions", [])
        ]
        if len(selected) != 1:
            return None, None
        row = selected[0]
        repo_type = row.get("repo_type")
        repo_id = row.get("repo_id")
        if repo_type not in {"model", "dataset", "space"} or not isinstance(repo_id, str):
            return None, None
        return "huggingface.repo.get", {"repo_type": repo_type, "repo_id": repo_id}
    if connection.provider in {"azure", "gcp", "runpod"}:
        return "cloud.provider.health.read", {"profile_ref": profile.profile_ref}
    return None, None


_OFFICIAL_WECOM_QR_URL = re.compile(
    r"^https://work\.weixin\.qq\.com/ai/qc/gen\?source=wecom_cli_external&scode=[A-Za-z0-9_-]{8,256}$"
)
_WECOM_MANAGEMENT_PATH = "/ai/aiHelper/authorizationList"
_WECOM_MANAGEMENT_QUERY_KEYS = (
    "aibotid",
    "bar_style_type",
    "for_native",
    "forceInnerBrowser",
    "from",
    "hide_more_btn",
    "pc_bar_bg",
    "str_aibotid",
    "type",
    "ww_vh",
    "ww_vw",
)
_OPAQUE_PROVIDER_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,299}$")
_LOGGER = logging.getLogger(__name__)


class IntegrationToolCallUnavailable(RuntimeError):
    """A fixed DirectPlugin tool did not return a valid typed result."""

    def __init__(self, *, retryable: bool = False) -> None:
        super().__init__("configured integration provider did not complete the fixed tool")
        self.retryable = retryable


def _huggingface_health_record(
    connection: IntegrationConnection,
    *,
    checked_at: datetime,
    login_state: LoginState,
    authorization_state: AuthorizationState,
    generation: int = 0,
    reason_code: str | None = None,
    expires_at: datetime | None = None,
    capabilities: list[AuthorizationCapabilityRecord] | None = None,
) -> AuthorizationHealthRecord:
    """Build one sanitized HF profile observation from the Account Center lease path."""

    return AuthorizationHealthRecord(
        organization_id=connection.organization_id,
        workspace_id=connection.workspace_id,
        actor_issuer=connection.actor_issuer,
        actor_subject=connection.actor_subject,
        connection_id=connection.id,
        authorization_ref=connection.account_link_ref,
        reason_code=reason_code,
        login_state=login_state,
        authorization_state=authorization_state,
        checked_at=checked_at,
        expires_at=expires_at,
        generation=generation,
        capabilities=capabilities or [],
    )


def _provider_timestamp(value: object) -> datetime | None:
    """Parse one RFC3339 provider timestamp without accepting naive local time."""

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None  # diagnostic-allow: malformed optional expiry has no safe deadline.
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


class AuthorizationCloudDirectProvider:
    """Invoke only SDK-whitelisted tools through trusted DirectPlugin bindings."""

    supports_durable_renewal_replay = True
    supports_request_id_status_lookup = True

    def __init__(
        self,
        *,
        store: IntegrationStore,
        registry: AuthorizationCloudProfileRegistry,
        provider_clients: Mapping[str, DirectInvoker],
        email_client: DirectInvoker | None,
        account_center: Any = None,
        current_context_resolver: Any,
        context_key: Callable[[str], bytes],
    ) -> None:
        self._store = store
        self._registry = registry
        self._provider_clients = dict(provider_clients)
        self._email_client = email_client
        self._account_center = account_center
        self._current_context_resolver = current_context_resolver
        self._context_key = context_key

    def list_tool_catalog(self, profile_ref: str) -> tuple[ProviderToolDefinition, ...]:
        """Read catalog metadata from one configured tool-provider profile endpoint."""

        profile = self._registry.settings.profiles.get(profile_ref)
        client = self._provider_clients.get(profile_ref)
        if (
            profile is None
            or profile.provider
            not in {"hf", "microsoft_graph", "azure_devops", "azure", "gcp", "runpod"}
            or client is None
        ):
            raise ProviderObservationUnavailable("provider tool catalog binding is unavailable")
        return list_provider_tool_catalog(
            client,
            binding_id=profile.endpoint.binding_id,
        )

    def authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
    ) -> AuthorizationHealthRecord:
        principal, profile, target_ref = self._verified_connection(
            principal, connection, operation_id="integrationGetAuthorizationHealth"
        )
        if profile.provider == "hf":
            return self._huggingface_authorization_health(
                principal,
                connection,
                profile,
                target_ref=target_ref,
            )
        if profile.provider == "microsoft_graph":
            return self._microsoft_graph_authorization_health(principal, connection, profile)
        if profile.provider == "azure_devops":
            return self._azure_devops_authorization_health(principal, connection, profile)
        if profile.provider in {"azure", "gcp", "runpod"}:
            return self._cloud_management_authorization_health(
                principal,
                connection,
                profile,
            )
        if profile.provider == "wecom":
            tool_id = "wecom_authorization_health"
            arguments = {"authorization_ref": profile.authorization_ref}
        else:
            tool_id = "cloud_authorization_health"
            arguments = {"target_ref": target_ref}
        result = self._call_profile(
            profile,
            principal,
            tool_id=tool_id,
            arguments=arguments,
            request_id=str(uuid4()),
        )
        sdk = _sdk()
        try:
            observed = sdk.parse_authorization_health(result)
        except Exception as exc:
            raise ProviderObservationUnavailable("authorization DTO is invalid") from exc
        expected_ref = (
            profile.authorization_ref
            if profile.provider == "wecom"
            else profile.endpoint.binding_id
        )
        if observed.authorization_ref != expected_ref:
            raise ProviderObservationUnavailable("authorization reference did not match binding")
        access_token_expiry = observed.expires_at
        capability_expiry = {item.capability_id: item.expires_at for item in observed.capabilities}
        if profile.provider in {"azure", "gcp"}:
            # These profiles reacquire short-lived bearer tokens during every
            # health check; their token TTL is not the lifetime of the identity.
            access_token_expiry = None
            capability_expiry = {item.capability_id: None for item in observed.capabilities}
        return AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=(observed.authorization_ref if profile.provider == "wecom" else None),
            reason_code=(
                observed.capabilities[0].reason_code
                if observed.capabilities and len(observed.capabilities) == 1
                else None
            ),
            login_state=LoginState(observed.login_state.value),
            authorization_state=AuthorizationState(observed.authorization_state.value),
            checked_at=observed.checked_at,
            expires_at=access_token_expiry,
            generation=observed.generation,
            capabilities=[
                AuthorizationCapabilityRecord(
                    capability_id=item.capability_id,
                    state=AuthorizationState(item.state.value),
                    last_verified_at=item.last_verified_at,
                    expires_at=capability_expiry[item.capability_id],
                    reason_code=item.reason_code,
                )
                for item in observed.capabilities
            ],
        )

    def _microsoft_graph_authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        profile: AuthorizationProviderProfile,
    ) -> AuthorizationHealthRecord:
        """Project current Account Center Graph auth and per-operation scope facts."""

        profile_ref = connection.account_link_ref
        if self._account_center is None or not profile_ref:
            raise ProviderObservationUnavailable("Microsoft Graph Account Center is unavailable")
        response = self._account_center.list_provider_profiles(principal)
        rows = response.get("profiles") if isinstance(response, Mapping) else None
        matching = (
            [
                row
                for row in rows
                if isinstance(row, Mapping)
                and row.get("provider") == "microsoft_graph"
                and row.get("profile_ref") == profile_ref
            ]
            if isinstance(rows, list)
            else []
        )
        if len(matching) != 1:
            raise ProviderObservationUnavailable(
                "Microsoft Graph Account Center profile is missing"
            )
        row = matching[0]
        try:
            scope = validate_microsoft_graph_profile_identity(
                row,
                profile_ref=profile_ref,
                principal=principal,
            )
        except ValueError as exc:
            raise ProviderObservationUnavailable(
                "Microsoft Graph Account Center profile is invalid"
            ) from exc
        if getattr(profile, "microsoft_graph_office_v2", None) is not None:
            try:
                scope = validate_microsoft_graph_office_v2_scope(profile, scope, principal)
            except (PermissionError, ValueError) as exc:
                raise ProviderObservationUnavailable(
                    "Microsoft Graph Office v2 scope differs from host configuration"
                ) from exc
        else:
            if tuple(scope["planner"]["plan_ids"]) != profile.microsoft_graph_plan_ids:
                raise ProviderObservationUnavailable(
                    "Microsoft Graph Account Center plan scope differs from host configuration"
                )
            if scope["sharepoint"]["enabled"] and (
                scope["sharepoint"]["site_id"] != profile.microsoft_graph_sharepoint_site_id
                or tuple(scope["sharepoint"]["list_ids"])
                != profile.microsoft_graph_sharepoint_list_ids
            ):
                raise ProviderObservationUnavailable(
                    "Microsoft Graph SharePoint scope differs from host configuration"
                )
        checked_at = datetime.now(UTC)
        expires_at = datetime.fromtimestamp(row["expires_at"], UTC)
        refresh_expires_at = (
            datetime.fromtimestamp(row["refresh_expires_at"], UTC)
            if isinstance(row.get("refresh_expires_at"), int)
            and not isinstance(row.get("refresh_expires_at"), bool)
            else None
        )
        auth_status = row.get("auth_status")
        if not isinstance(auth_status, str):
            auth_status = "unknown"
        account_state = {
            "healthy": AuthorizationState.VALID,
            "reauthorization_required": AuthorizationState.REAUTHORIZATION_REQUIRED,
            "revoked": AuthorizationState.REAUTHORIZATION_REQUIRED,
            "unavailable": AuthorizationState.UNAVAILABLE,
            "unknown": AuthorizationState.UNKNOWN,
        }.get(auth_status, AuthorizationState.UNKNOWN)
        if refresh_expires_at is not None and refresh_expires_at <= checked_at:
            account_state = AuthorizationState.REAUTHORIZATION_REQUIRED
        planner = scope["planner"]
        sharepoint = scope["sharepoint"]

        def capability_state(enabled: bool) -> AuthorizationState:
            if account_state != AuthorizationState.VALID:
                return account_state
            return AuthorizationState.VALID if enabled else AuthorizationState.PERMISSION_DENIED

        capabilities = [
            AuthorizationCapabilityRecord(
                capability_id="microsoft_graph.planner.tasks.read",
                state=capability_state(planner["tasks_read"]),
                last_verified_at=checked_at if planner["tasks_read"] else None,
                expires_at=expires_at,
                reason_code=(None if planner["tasks_read"] else "planner_tasks_read_not_enabled"),
            ),
            AuthorizationCapabilityRecord(
                capability_id="microsoft_graph.planner.tasks.write",
                state=capability_state(planner["tasks_write"]),
                last_verified_at=checked_at if planner["tasks_write"] else None,
                expires_at=expires_at,
                reason_code=(
                    None if planner["tasks_write"] else "planner_tasks_write_consent_required"
                ),
            ),
            AuthorizationCapabilityRecord(
                capability_id="microsoft_graph.sharepoint.selected_metadata.read",
                state=capability_state(sharepoint["enabled"]),
                last_verified_at=checked_at if sharepoint["enabled"] else None,
                expires_at=expires_at,
                reason_code=(
                    None if sharepoint["enabled"] else "sharepoint_selected_target_consent_required"
                ),
            ),
        ]
        if scope.get("schema_version") == 2:
            todo = scope["todo"]
            calendar = scope["calendar"]
            capabilities.extend(
                [
                    AuthorizationCapabilityRecord(
                        capability_id="microsoft_graph.todo.tasks.read",
                        state=capability_state(todo["tasks_read"]),
                        last_verified_at=checked_at if todo["tasks_read"] else None,
                        expires_at=expires_at,
                        reason_code=(None if todo["tasks_read"] else "todo_tasks_read_not_enabled"),
                    ),
                    AuthorizationCapabilityRecord(
                        capability_id="microsoft_graph.todo.tasks.write",
                        state=capability_state(todo["tasks_write"]),
                        last_verified_at=checked_at if todo["tasks_write"] else None,
                        expires_at=expires_at,
                        reason_code=(
                            None if todo["tasks_write"] else "todo_tasks_write_not_enabled"
                        ),
                    ),
                    AuthorizationCapabilityRecord(
                        capability_id="microsoft_graph.calendar.events.read",
                        state=capability_state(calendar["events_read"]),
                        last_verified_at=checked_at if calendar["events_read"] else None,
                        expires_at=expires_at,
                        reason_code=(
                            None if calendar["events_read"] else "calendar_events_read_not_enabled"
                        ),
                    ),
                    AuthorizationCapabilityRecord(
                        capability_id="microsoft_graph.calendar.events.write",
                        state=capability_state(calendar["events_write"]),
                        last_verified_at=checked_at if calendar["events_write"] else None,
                        expires_at=expires_at,
                        reason_code=(
                            None
                            if calendar["events_write"]
                            else "calendar_events_write_not_enabled"
                        ),
                    ),
                    AuthorizationCapabilityRecord(
                        capability_id="microsoft_graph.calendar.freebusy.read",
                        state=capability_state(calendar["freebusy_read"]),
                        last_verified_at=checked_at if calendar["freebusy_read"] else None,
                        expires_at=expires_at,
                        reason_code=(
                            None if calendar["freebusy_read"] else "calendar_freebusy_not_enabled"
                        ),
                    ),
                ]
            )
        scope_metadata = profile_scope_metadata(row, scope)
        generation = row.get("credential_revision", 0)
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            generation = 0
        return AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            external_subject=(
                str(row["external_subject"])
                if isinstance(row.get("external_subject"), str)
                else None
            ),
            connection_id=connection.id,
            authorization_ref=profile_ref,
            reason_code=(
                "microsoft_graph_reauthorization_required"
                if account_state == AuthorizationState.REAUTHORIZATION_REQUIRED
                else "microsoft_graph_profile_unavailable"
                if account_state == AuthorizationState.UNAVAILABLE
                else None
            ),
            login_state=LoginState.PRESENT,
            authorization_state=account_state,
            checked_at=checked_at,
            expires_at=expires_at,
            refresh_expires_at=refresh_expires_at,
            generation=generation,
            capabilities=capabilities,
            scope_schema_version=scope_metadata["scope_schema_version"],
            enabled_features=list(scope_metadata["enabled_features"]),
            required_oauth_scopes=list(scope_metadata["required_oauth_scopes"]),
            target_ref_count=int(scope_metadata["target_ref_count"]),
            reauth_required=bool(scope_metadata["reauth_required"]),
            reauth_reason_code=scope_metadata["reauth_reason_code"],
        )

    def _azure_devops_authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        profile: AuthorizationProviderProfile,
    ) -> AuthorizationHealthRecord:
        """Report OAuth health while leaving actual project rights to ADO source calls."""

        profile_ref = connection.account_link_ref
        source = (profile.authorized_sources or {}).get(connection.target_ref or "")
        if self._account_center is None or not profile_ref or source is None:
            raise ProviderObservationUnavailable(
                "Azure DevOps Account Center profile is unavailable"
            )
        response = self._account_center.list_provider_profiles(principal)
        rows = response.get("profiles") if isinstance(response, Mapping) else None
        matching = (
            [
                row
                for row in rows
                if isinstance(row, Mapping)
                and row.get("provider") == "azure_devops"
                and row.get("profile_ref") == profile_ref
            ]
            if isinstance(rows, list)
            else []
        )
        if len(matching) != 1:
            raise ProviderObservationUnavailable("Azure DevOps Account Center profile is missing")
        row = matching[0]
        try:
            scope = validate_azure_devops_profile_identity(
                row,
                profile_ref=profile_ref,
                principal=principal,
            )
            source_config = {
                "source_id": source.source_id,
                "kind": source.kind,
                "project_id": source.project_id,
                "project_name": source.project_name,
                "profile_ref": source.profile_ref,
                **({"pipeline_id": source.pipeline_id} if source.pipeline_id is not None else {}),
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
            }
            expected_scope = scope_for_authorized_source(
                tenant_id=str(profile.azure_devops_tenant_id),
                organization=str(profile.azure_devops_organization),
                source=source_config,
            )
        except ValueError as exc:
            raise ProviderObservationUnavailable(
                "Azure DevOps profile identity is invalid"
            ) from exc
        if scope != expected_scope:
            raise ProviderObservationUnavailable(
                "Azure DevOps profile scope differs from its source"
            )
        checked_at = datetime.now(UTC)
        expires_at = datetime.fromtimestamp(row["expires_at"], UTC)
        auth_status = row.get("auth_status")
        if not isinstance(auth_status, str):
            auth_status = "unknown"
        account_state = {
            "healthy": AuthorizationState.VALID,
            "reauthorization_required": AuthorizationState.REAUTHORIZATION_REQUIRED,
            "revoked": AuthorizationState.REAUTHORIZATION_REQUIRED,
            "unavailable": AuthorizationState.UNAVAILABLE,
            "unknown": AuthorizationState.UNKNOWN,
        }.get(auth_status, AuthorizationState.UNKNOWN)
        if expires_at <= checked_at:
            account_state = AuthorizationState.REAUTHORIZATION_REQUIRED
        generation = row.get("credential_revision", 0)
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            generation = 0
        reason_code = {
            AuthorizationState.REAUTHORIZATION_REQUIRED: "azure_devops_reauthorization_required",
            AuthorizationState.UNAVAILABLE: "azure_devops_profile_unavailable",
            AuthorizationState.UNKNOWN: "azure_devops_profile_unknown",
        }.get(account_state)
        capabilities = [
            AuthorizationCapabilityRecord(
                capability_id=operation_id,
                state=account_state,
                expires_at=expires_at,
                reason_code=reason_code,
            )
            for operation_id in sorted(ADO_OBSERVATION_OPERATIONS)
        ]
        return AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=profile_ref,
            reason_code=reason_code,
            login_state=LoginState.PRESENT,
            authorization_state=account_state,
            checked_at=checked_at,
            expires_at=expires_at,
            generation=generation,
            capabilities=capabilities,
        )

    def _cloud_management_authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        profile: AuthorizationProviderProfile,
    ) -> AuthorizationHealthRecord:
        """Normalize the cloud-management health DTO for this live binding.

        Plugin ``PERMISSION_DENIED`` keeps the login present and reports an insufficient
        provider scope; ``REAUTHORIZATION_REQUIRED`` signals that the credential needs
        owner action. ``UNKNOWN`` remains non-actionable so retryable provider outages do
        not become revocation notices.

        中文：权限拒绝保留登录有效状态；只有明确需重授权才触发失效通知。
        """

        result = self._call_profile(
            profile,
            principal,
            tool_id="cloud_provider_health",
            arguments={"profile_ref": profile.profile_ref},
            request_id=str(uuid4()),
        )
        if (
            result.get("profile_ref") != profile.profile_ref
            or result.get("provider") != connection.provider
        ):
            raise ProviderObservationUnavailable("cloud profile health scope did not match")
        authentication = result.get("authentication_state")
        authorization = result.get("authorization_state")
        if authentication not in {
            "VALID",
            "MISSING",
            "INVALID",
            "UNKNOWN",
        } or authorization not in {
            "VALID",
            "REAUTHORIZATION_REQUIRED",
            "PERMISSION_DENIED",
            "UNKNOWN",
        }:
            raise ProviderObservationUnavailable("cloud profile health state is invalid")
        checked_at = _provider_timestamp(result.get("checked_at"))
        if checked_at is None:
            raise ProviderObservationUnavailable("cloud profile health timestamp is invalid")
        if authentication == "MISSING":
            login_state = LoginState.MISSING
        elif authentication in {"VALID", "INVALID"}:
            login_state = LoginState.PRESENT
        else:
            login_state = LoginState.UNKNOWN
        if authorization == "PERMISSION_DENIED":
            authorization_state = AuthorizationState.PERMISSION_DENIED
        elif authorization == "REAUTHORIZATION_REQUIRED" or authentication == "INVALID":
            authorization_state = AuthorizationState.REAUTHORIZATION_REQUIRED
        elif authorization == "VALID" and authentication == "VALID":
            authorization_state = AuthorizationState.VALID
        else:
            authorization_state = AuthorizationState.UNKNOWN

        raw_scopes = result.get("scope_refs")
        if not isinstance(raw_scopes, list) or len(raw_scopes) > 100:
            raise ProviderObservationUnavailable("cloud profile health scopes are invalid")
        capability_ids = [
            scope
            for scope in raw_scopes
            if isinstance(scope, str)
            and 1 <= len(scope) <= 200
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", scope)
        ]
        if len(capability_ids) != len(raw_scopes):
            raise ProviderObservationUnavailable("cloud profile health scopes are invalid")
        reason_code = result.get("reason_code")
        if not isinstance(reason_code, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}", reason_code
        ):
            reason_code = None
        generation_value = result.get("generation", 0)
        generation = (
            generation_value
            if isinstance(generation_value, int)
            and not isinstance(generation_value, bool)
            and generation_value >= 0
            else 0
        )
        expires_at = _provider_timestamp(result.get("expires_at"))
        if connection.provider in {"azure", "gcp"}:
            # Managed identity and WIF token expiry is renewed automatically by
            # the native cloud provider and is not the identity's lifetime.
            expires_at = None
        if not capability_ids:
            capability_ids = ["cloud.provider.health.read"]
        return AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=None,
            reason_code=reason_code,
            login_state=login_state,
            authorization_state=authorization_state,
            checked_at=checked_at,
            expires_at=expires_at,
            generation=generation,
            capabilities=[
                AuthorizationCapabilityRecord(
                    capability_id=scope,
                    state=authorization_state,
                    last_verified_at=checked_at,
                    expires_at=expires_at,
                    reason_code=reason_code,
                )
                for scope in capability_ids
            ],
        )

    def _huggingface_authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        profile: AuthorizationProviderProfile,
        *,
        target_ref: str | None,
    ) -> AuthorizationHealthRecord:
        """Probe only this connection's HF repository through an Account Center lease."""

        checked_at = datetime.now(UTC)
        profile_ref = connection.account_link_ref
        if self._account_center is None or not profile_ref:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.UNAVAILABLE,
                authorization_state=AuthorizationState.UNAVAILABLE,
                reason_code="account_center_unavailable",
            )

        try:
            account_profiles = self._account_center.list_provider_profiles(principal)
        except Exception:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.UNAVAILABLE,
                authorization_state=AuthorizationState.UNAVAILABLE,
                reason_code="account_center_unavailable",
            )
        rows = account_profiles.get("profiles") if isinstance(account_profiles, Mapping) else None
        account_profile = (
            next(
                (
                    item
                    for item in rows
                    if isinstance(item, Mapping)
                    and item.get("profile_ref") == profile_ref
                    and item.get("provider") == "huggingface"
                ),
                None,
            )
            if isinstance(rows, list)
            else None
        )
        if account_profile is None:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.MISSING,
                authorization_state=AuthorizationState.REAUTHORIZATION_REQUIRED,
                reason_code="account_profile_missing",
            )

        revision = account_profile.get("credential_revision", 0)
        generation = 0
        if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0:
            generation = revision
        configured_auth_mode = profile.auth_mode or "fine_grained_token"
        auth_mode = account_profile.get("auth_mode", "fine_grained_token")
        account_scope = account_profile.get("target_scope")
        if (
            auth_mode != configured_auth_mode
            or not isinstance(account_scope, Mapping)
            or dict(account_scope) != dict(profile.account_scopes or {})
        ):
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.PRESENT,
                authorization_state=AuthorizationState.UNKNOWN,
                generation=generation,
                reason_code="account_profile_scope_mismatch",
            )

        auth_status = account_profile.get("auth_status")
        if auth_status in {"reauthorization_required", "revoked"}:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.PRESENT,
                authorization_state=AuthorizationState.REAUTHORIZATION_REQUIRED,
                generation=generation,
                reason_code="credential_reauthorization_required",
            )
        if auth_status != "healthy":
            status = (
                AuthorizationState.UNAVAILABLE
                if auth_status == "unavailable"
                else AuthorizationState.UNKNOWN
            )
            login = LoginState.UNAVAILABLE if auth_status == "unavailable" else LoginState.UNKNOWN
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=login,
                authorization_state=status,
                generation=generation,
                reason_code="account_profile_unavailable",
            )

        repositories = account_scope.get("repositories")
        selected_scope = (
            [
                item
                for item in repositories
                if isinstance(item, Mapping) and item.get("repo_id") == target_ref
            ]
            if isinstance(repositories, list) and isinstance(target_ref, str)
            else []
        )
        read_scope = selected_scope[0] if len(selected_scope) == 1 else None
        if (
            read_scope is None
            or read_scope.get("repo_type") not in {"model", "dataset", "space"}
            or not isinstance(read_scope.get("repo_id"), str)
            or "read" not in read_scope.get("permissions", [])
        ):
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.PRESENT,
                authorization_state=AuthorizationState.PERMISSION_DENIED,
                generation=generation,
                reason_code="huggingface_target_read_scope_missing",
                capabilities=[
                    AuthorizationCapabilityRecord(
                        capability_id="huggingface.repository.read",
                        state=AuthorizationState.PERMISSION_DENIED,
                        last_verified_at=checked_at,
                        reason_code="huggingface_target_read_scope_missing",
                    )
                ],
            )

        target = {
            "repo_type": read_scope["repo_type"],
            "repo_id": read_scope["repo_id"],
        }
        arguments_sha256 = digest_arguments(target)
        operation_id = "huggingface.repo.get"
        connector_grant: Mapping[str, object] | None = None
        if self._current_context_resolver is None:
            lease_principal = None
        elif connection.access_mode == "workspace_operator":
            for_grant = getattr(
                self._current_context_resolver,
                "for_connection_with_connector_grant",
                None,
            )
            lease_principal, claims = (
                for_grant(
                    connection,
                    operation_id="integrationGetAuthorizationHealth",
                    provider_operation_id=operation_id,
                    arguments=target,
                )
                if callable(for_grant)
                else (None, None)
            )
            if claims is not None:
                connector_grant = _account_center_grant_proof(
                    claims,
                    arguments_sha256=arguments_sha256,
                )
        else:
            lease_principal = self._current_context_resolver.for_connection(
                connection,
                operation_id="integrationGetAuthorizationHealth",
            )
        if lease_principal is None:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.UNKNOWN,
                authorization_state=AuthorizationState.UNKNOWN,
                generation=generation,
                reason_code="current_authority_unavailable",
            )

        try:
            lease_arguments: dict[str, object] = {
                "profile_ref": profile_ref,
                "operation_id": operation_id,
                "target": target,
                "arguments_sha256": arguments_sha256,
            }
            if connector_grant is not None:
                lease_arguments["connector_grant"] = connector_grant
            lease = self._account_center.create_provider_credential_lease(
                lease_principal,
                **lease_arguments,
            )
            lease_ref = lease.get("lease_ref") if isinstance(lease, Mapping) else None
            if (
                not isinstance(lease_ref, str)
                or not lease_ref
                or lease.get("profile_ref") != profile_ref
                or lease.get("provider") != "huggingface"
                or lease.get("operation_id") != operation_id
                or lease.get("target") != target
                or lease.get("arguments_sha256") != arguments_sha256
            ):
                raise ProviderObservationUnavailable("Account Center lease scope is invalid")
            result = self.invoke_connector_tool(
                lease_principal,
                connection,
                operation_id=operation_id,
                tool_id=operation_id,
                arguments={
                    "profile_ref": profile_ref,
                    "lease_ref": lease_ref,
                    "payload": target,
                },
                request_id=str(uuid4()),
            )
        except ExchangeProductError as exc:
            if exc.code == "EXCHANGE_CONNECTOR_AUTH_EXPIRED":
                state = AuthorizationState.REAUTHORIZATION_REQUIRED
                reason = "credential_reauthorization_required"
            elif exc.code == "EXCHANGE_CONNECTOR_PERMISSION_DENIED":
                state = AuthorizationState.PERMISSION_DENIED
                reason = "permission_denied"
            elif exc.code == "EXCHANGE_ACCOUNT_CENTER_AUTHORIZATION_DENIED":
                state = AuthorizationState.PERMISSION_DENIED
                reason = "account_center_authorization_denied"
            else:
                state = AuthorizationState.UNAVAILABLE
                reason = "provider_observation_unavailable"
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.PRESENT,
                authorization_state=state,
                generation=generation,
                reason_code=reason,
                capabilities=[
                    AuthorizationCapabilityRecord(
                        capability_id="huggingface.repository.read",
                        state=state,
                        last_verified_at=checked_at,
                        reason_code=reason,
                    )
                ],
            )
        except Exception:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.UNAVAILABLE,
                authorization_state=AuthorizationState.UNAVAILABLE,
                generation=generation,
                reason_code="provider_observation_unavailable",
            )

        if not isinstance(result, Mapping) or result.get("repo_id") != target["repo_id"]:
            return _huggingface_health_record(
                connection,
                checked_at=checked_at,
                login_state=LoginState.UNKNOWN,
                authorization_state=AuthorizationState.UNKNOWN,
                generation=generation,
                reason_code="provider_observation_invalid",
            )
        try:
            refreshed_profiles = self._account_center.list_provider_profiles(principal)
            refreshed_rows = (
                refreshed_profiles.get("profiles")
                if isinstance(refreshed_profiles, Mapping)
                else None
            )
            refreshed_profile = (
                next(
                    (
                        item
                        for item in refreshed_rows
                        if isinstance(item, Mapping)
                        and item.get("profile_ref") == profile_ref
                        and item.get("provider") == "huggingface"
                    ),
                    account_profile,
                )
                if isinstance(refreshed_rows, list)
                else account_profile
            )
        except Exception:
            refreshed_profile = account_profile
        refreshed_revision = refreshed_profile.get("credential_revision", generation)
        generation = (
            refreshed_revision
            if isinstance(refreshed_revision, int)
            and not isinstance(refreshed_revision, bool)
            and refreshed_revision >= 0
            else generation
        )
        credential_expiry = refreshed_profile.get("expires_at")
        expires_at = None
        if (
            auth_mode != "device_oauth"
            and isinstance(credential_expiry, int)
            and not isinstance(credential_expiry, bool)
        ):
            expires_at = datetime.fromtimestamp(credential_expiry, UTC)
        return _huggingface_health_record(
            connection,
            checked_at=checked_at,
            login_state=LoginState.PRESENT,
            authorization_state=AuthorizationState.VALID,
            generation=generation,
            expires_at=expires_at,
            capabilities=[
                AuthorizationCapabilityRecord(
                    capability_id="huggingface.repository.read",
                    state=AuthorizationState.VALID,
                    last_verified_at=checked_at,
                    expires_at=expires_at,
                )
            ],
        )

    def invoke_connector_tool(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        *,
        operation_id: str,
        tool_id: str,
        arguments: Mapping[str, object],
        request_id: str,
    ) -> dict[str, Any]:
        """Sign and invoke one fixed cloud or HF tool after exact connection checks."""

        principal.require(operation_id)
        current = self._store.current_connection_for_provider_call(connection.id)
        if current is None or current != connection or not current.enabled:
            raise PermissionError("connection changed before connector provider call")
        if current.provider not in {
            "azure",
            "azure_devops",
            "gcp",
            "hf",
            "microsoft_graph",
            "runpod",
        }:
            raise PermissionError("connection provider has no cloud connector tool binding")
        profile, _target_ref = self._registry.profile_for_connection(
            principal,
            current,
            operation_id=operation_id,
        )
        if profile.provider != current.provider:
            raise PermissionError("provider profile does not match the connection")
        expected_profile_ref = (
            current.account_link_ref
            if current.provider in {"hf", "microsoft_graph", "azure_devops"}
            else current.binding_ref
        )
        if arguments.get("profile_ref") != expected_profile_ref:
            raise PermissionError("provider profile argument does not match the connection")
        if current.provider == "hf":
            return _invoke_signed_huggingface_tool(
                self._provider_clients.get(profile.profile_ref),
                endpoint=profile.endpoint,
                principal=principal,
                profile=profile,
                context_key=self._context_key(profile.context_key_ref),
                tool_id=tool_id,
                operation_id=operation_id,
                arguments=arguments,
                request_id=request_id,
            )
        if current.provider == "microsoft_graph":
            if current.access_mode != "actor_owned":
                raise PermissionError("Microsoft Graph account profile cannot be shared")
            return _invoke_signed_microsoft_graph_tool(
                self._provider_clients.get(profile.profile_ref),
                endpoint=profile.endpoint,
                principal=principal,
                profile=profile,
                context_key=self._context_key(profile.context_key_ref),
                tool_id=tool_id,
                operation_id=operation_id,
                arguments=arguments,
                request_id=request_id,
            )
        if current.provider == "azure_devops":
            if current.access_mode != "actor_owned":
                raise PermissionError("Azure DevOps account profile cannot be shared")
            return _invoke_signed_azure_devops_tool(
                self._provider_clients.get(profile.profile_ref),
                endpoint=profile.endpoint,
                principal=principal,
                profile=profile,
                context_key=self._context_key(profile.context_key_ref),
                tool_id=tool_id,
                operation_id=operation_id,
                arguments=arguments,
                request_id=request_id,
            )
        return self._call_profile(
            profile,
            principal,
            tool_id=tool_id,
            arguments=arguments,
            request_id=request_id,
        )

    def cloud_resources(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
    ) -> list[CloudResourceRecord]:
        principal, profile, target_ref = self._verified_connection(
            principal,
            connection,
            operation_id="integrationRefreshConnectionResources",
        )
        if profile.provider == "wecom":
            raise ProviderObservationUnavailable("WeCom is not a cloud resource provider")
        result = self._call_profile(
            profile,
            principal,
            tool_id="cloud_resources_query",
            arguments={"target_ref": target_ref},
            request_id=str(uuid4()),
        )
        try:
            query = _sdk().parse_cloud_query_result(result)
        except Exception as exc:
            raise ProviderObservationUnavailable("cloud resource DTO is invalid") from exc
        if query.provider != connection.provider:
            raise ProviderObservationUnavailable("cloud result provider did not match binding")
        valid_kinds = {
            "azure": {"azure.vm"},
            "gcp": {"gcp.instance"},
            "hf": {"hf.model", "hf.dataset", "hf.space"},
            "runpod": {"runpod.pod"},
            "tailscale": {"tailscale.device"},
        }.get(connection.provider, set())
        observations: list[CloudResourceRecord] = []
        for item in query.resources:
            if item.kind.value not in valid_kinds or not _OPAQUE_PROVIDER_REF.fullmatch(
                item.external_ref
            ):
                raise ProviderObservationUnavailable(
                    "cloud resource escaped its fixed kind/ref scope"
                )
            observations.append(
                CloudResourceRecord(
                    organization_id=connection.organization_id,
                    workspace_id=connection.workspace_id,
                    actor_issuer=connection.actor_issuer,
                    actor_subject=connection.actor_subject,
                    connection_id=connection.id,
                    provider=connection.provider,
                    source=connection.provider,
                    external_ref=item.external_ref,
                    kind=item.kind.value,
                    display_name=item.display_name,
                    status=CloudResourceState(item.status.value),
                    provider_status=item.provider_status,
                    collected_at=item.collected_at,
                    observed_at=item.observed_at,
                    freshness=SnapshotFreshness.UNKNOWN,
                    attributes=dict(item.attributes),
                    platform_resource_ref=item.platform_resource_ref,
                    platform_generation=item.platform_generation,
                )
            )
        return observations

    def start_renewal(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        authorization_ref: str,
        *,
        request_id: str,
    ) -> ProviderRenewalSession:
        if connection.provider == "hf":
            principal, profile, _ = self._verified_request_connection(
                principal,
                connection,
                operation_id="accountBeginRenewalSession",
            )
        else:
            principal, profile, _ = self._verified_connection(
                principal,
                connection,
                operation_id="accountBeginRenewalSession",
            )
        if not _OPAQUE_PROVIDER_REF.fullmatch(authorization_ref):
            raise PermissionError("renewal authorization is not selected by the verified binding")
        if profile.provider == "hf":
            if (
                profile.auth_mode != "device_oauth"
                or connection.account_link_ref != authorization_ref
                or self._account_center is None
            ):
                raise PermissionError("HF renewal is not selected by the linked OAuth profile")
            result = self._account_center.begin_huggingface_renewal(
                principal,
                profile_ref=authorization_ref,
                session_ref=request_id,
            )
            return _huggingface_renewal_session(
                result,
                expected_profile_ref=authorization_ref,
                expected_session_ref=request_id,
            )
        if profile.provider != "wecom" or authorization_ref != profile.authorization_ref:
            raise PermissionError("renewal authorization is not selected by the verified binding")
        result = self._call_profile(
            profile,
            principal,
            tool_id="wecom_reauthorization_start",
            arguments={"authorization_ref": authorization_ref},
            request_id=request_id,
        )
        return _renewal_session(result, expected_authorization_ref=authorization_ref)

    def renewal_status(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        provider_session_ref: str,
        *,
        request_id: str,
    ) -> ProviderRenewalSession:
        connection = _renewal_connection_for_provider(
            self._store,
            principal,
            authorization_ref,
            operation_id="accountGetRenewalSession",
        )
        if connection.provider == "hf":
            principal, profile, _ = self._verified_request_connection(
                principal,
                connection,
                operation_id="accountGetRenewalSession",
            )
        else:
            principal, profile, _ = self._verified_connection(
                principal,
                connection,
                operation_id="accountGetRenewalSession",
            )
        if profile.provider == "hf":
            if (
                profile.auth_mode != "device_oauth"
                or self._account_center is None
                or connection.account_link_ref != authorization_ref
            ):
                raise PermissionError("HF renewal profile is not available in Account Center")
            result = self._account_center.poll_huggingface_renewal(
                principal,
                profile_ref=authorization_ref,
                session_ref=provider_session_ref,
            )
            return _huggingface_renewal_session(
                result,
                expected_profile_ref=authorization_ref,
                expected_session_ref=provider_session_ref,
            )
        result = self._call_profile(
            profile,
            principal,
            tool_id="wecom_reauthorization_status",
            arguments={"session_ref": provider_session_ref},
            request_id=request_id,
        )
        return _renewal_session(result, expected_authorization_ref=authorization_ref)

    def renewal_status_by_request_id(
        self,
        principal: IntegrationPrincipal,
        authorization_ref: str,
        *,
        request_id: str,
        status_request_id: str,
    ) -> ProviderRenewalSession:
        connection = _renewal_connection_for_provider(
            self._store,
            principal,
            authorization_ref,
            operation_id="accountGetRenewalSession",
        )
        if connection.provider == "hf":
            principal, profile, _ = self._verified_request_connection(
                principal,
                connection,
                operation_id="accountGetRenewalSession",
            )
        else:
            principal, profile, _ = self._verified_connection(
                principal,
                connection,
                operation_id="accountGetRenewalSession",
            )
        if profile.provider == "hf":
            if (
                profile.auth_mode != "device_oauth"
                or self._account_center is None
                or connection.account_link_ref != authorization_ref
            ):
                raise PermissionError("HF renewal profile is not available in Account Center")
            result = self._account_center.poll_huggingface_renewal(
                principal,
                profile_ref=authorization_ref,
                session_ref=request_id,
            )
            return _huggingface_renewal_session(
                result,
                expected_profile_ref=authorization_ref,
                expected_session_ref=request_id,
            )
        result = self._call_profile(
            profile,
            principal,
            tool_id="wecom_reauthorization_status",
            arguments={"session_ref": request_id},
            request_id=status_request_id,
        )
        return _renewal_session(result, expected_authorization_ref=authorization_ref)

    def send_notification(
        self,
        principal: IntegrationPrincipal,
        job: EmailNotificationJob,
    ) -> EmailSubmissionEvidence:
        try:
            fresh_principal = self._current_context_resolver.for_sending_notification(
                job,
                claim_fence=job.claim_fence,
                operation_id="integrationDeliverNotification",
            )
        except Exception as exc:
            raise EmailAuthorizationUnavailable(
                "current email authority could not be refreshed"
            ) from exc
        if fresh_principal is None or not _same_actor(principal, fresh_principal):
            raise EmailAuthorizationUnavailable("current email authority changed before signing")
        principal = fresh_principal
        principal.require("integrationDeliverNotification")
        if self._email_client is None:
            raise EmailAuthorizationUnavailable("email notification binding is disabled")
        current = self._store.get_email_notification_job(
            principal,
            job.id,
            authorization_operation_id="integrationDeliverNotification",
        )
        if (
            not _same_email_request(current, job)
            or current.state.value != "SENDING"
            or current.claim_fence != job.claim_fence
        ):
            raise PermissionError("email job changed before provider call")
        email_profile = self._registry.settings.email
        context = self._registry.email_context_for_job(current)
        if (
            context.issuer != principal.issuer
            or context.subject != principal.subject
            or context.organization_id != principal.organization_id
            or context.workspace_id != principal.workspace_id
            or email_profile.expected_issuer != principal.issuer
        ):
            raise EmailAuthorizationUnavailable("email job owner does not match current authority")
        arguments = {
            "recipient_ref": current.recipient_ref,
            "subject": current.subject,
            "text": current.text,
            "request_ref": current.request_ref,
        }
        try:
            result = self._call_email(
                principal,
                email_profile,
                arguments=arguments,
                request_id=str(current.id),
            )
        except (EmailDeliveryRetryableError, IntegrationToolCallUnavailable):
            raise
        except Exception as exc:
            # Profile/key and envelope construction fail before DirectPlugin I/O.
            raise EmailAuthorizationUnavailable(
                "email signing configuration is unavailable"
            ) from exc
        try:
            submission = _sdk().parse_email_submission(result)
        except Exception as exc:
            raise RuntimeError("email submission DTO is invalid") from exc
        if submission.request_ref != current.request_ref:
            raise RuntimeError("email submission request reference changed")
        return EmailSubmissionEvidence(
            request_ref=submission.request_ref,
            status=submission.status.value,
            vendor_receipt_ref=submission.vendor_receipt_ref,
            delivery_confirmed=submission.delivery_confirmed,
        )

    def _verified_connection(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> tuple[IntegrationPrincipal, AuthorizationProviderProfile, str | None]:
        principal.require(operation_id)
        current = self._store.current_connection_for_provider_call(connection.id)
        if current is None or current != connection or not current.enabled:
            raise PermissionError("connection changed before provider call")
        fresh = self._current_context_resolver.for_connection(
            current,
            operation_id=operation_id,
        )
        if fresh is None or not _same_actor(principal, fresh):
            raise PermissionError("current Platform grant is unavailable before provider call")
        profile, target_ref = self._registry.profile_for_connection(
            fresh,
            current,
            operation_id=operation_id,
        )
        return fresh, profile, target_ref

    def _verified_request_connection(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> tuple[IntegrationPrincipal, AuthorizationProviderProfile, str | None]:
        """Validate one current user request without requiring a stored bearer context."""

        principal.require(operation_id)
        current = self._store.current_connection_for_provider_call(connection.id)
        if current is None or current != connection or not current.enabled:
            raise PermissionError("connection changed before provider call")
        profile, target_ref = self._registry.profile_for_connection(
            principal,
            current,
            operation_id=operation_id,
        )
        return principal, profile, target_ref

    def _call_profile(
        self,
        profile: AuthorizationProviderProfile,
        principal: IntegrationPrincipal,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        request_id: str,
    ) -> dict[str, Any]:
        client = self._provider_clients.get(profile.profile_ref)
        if client is None:
            raise ProviderObservationUnavailable("provider DirectPlugin binding is unavailable")
        return _invoke_signed_tool(
            client,
            endpoint=profile.endpoint,
            principal=principal,
            caller_workload=profile.caller_workload,
            audience=profile.audience,
            expected_issuer=profile.expected_issuer,
            key=self._context_key(profile.context_key_ref),
            tool_id=tool_id,
            arguments=arguments,
            request_id=request_id,
        )

    def _call_email(
        self,
        principal: IntegrationPrincipal,
        profile: EmailNotificationProfile,
        *,
        arguments: Mapping[str, object],
        request_id: str,
    ) -> dict[str, Any]:
        if (
            not profile.enabled
            or profile.endpoint is None
            or profile.caller_workload is None
            or profile.audience is None
            or profile.expected_issuer is None
            or profile.context_key_ref is None
            or principal.issuer != profile.expected_issuer
        ):
            raise PermissionError("email notification profile is disabled or outside actor scope")
        if self._email_client is None:
            raise PermissionError("email DirectPlugin binding is unavailable")
        return _invoke_signed_tool(
            self._email_client,
            endpoint=profile.endpoint,
            principal=principal,
            caller_workload=profile.caller_workload,
            audience=profile.audience,
            expected_issuer=profile.expected_issuer,
            key=self._context_key(profile.context_key_ref),
            tool_id="email_notification_send",
            arguments=arguments,
            request_id=request_id,
        )


def _renewal_session(
    result: Mapping[str, Any],
    *,
    expected_authorization_ref: str,
) -> ProviderRenewalSession:
    try:
        session = _sdk().parse_renewal_session(result)
    except Exception as exc:
        raise RuntimeError("renewal session DTO is invalid") from exc
    safe_url = (
        _safe_vendor_url(session.authorization_url)
        if session.authorization_url is not None
        else None
    )
    if (
        session.authorization_ref != expected_authorization_ref
        or not _OPAQUE_PROVIDER_REF.fullmatch(session.session_ref)
        or not _OPAQUE_PROVIDER_REF.fullmatch(session.authorization_ref)
        or (
            session.qr_attachment_ref is not None
            and not _OPAQUE_PROVIDER_REF.fullmatch(session.qr_attachment_ref)
        )
        or (session.authorization_url is not None and safe_url is None)
    ):
        raise RuntimeError("provider renewal session escaped its configured scope")
    return ProviderRenewalSession(
        authorization_ref=session.authorization_ref,
        session_ref=session.session_ref,
        state=RenewalState(session.state.value),
        created_at=session.created_at,
        expires_at=session.expires_at,
        authorization_url=safe_url,
        qr_attachment_ref=session.qr_attachment_ref,
        generation=session.generation,
    )


def _renewal_connection_for_provider(
    store: IntegrationStore,
    principal: IntegrationPrincipal,
    authorization_ref: str,
    *,
    operation_id: str,
) -> IntegrationConnection:
    """Resolve exactly one attached WeCom or Hugging Face renewal connection."""

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


def _huggingface_renewal_session(
    result: Mapping[str, Any],
    *,
    expected_profile_ref: str,
    expected_session_ref: str,
) -> ProviderRenewalSession:
    """Validate Account Center device-flow metadata before Product persistence."""

    states = {
        "starting": RenewalState.VERIFYING,
        "waiting_user": RenewalState.WAITING_USER,
        "succeeded": RenewalState.SUCCEEDED,
        "failed": RenewalState.FAILED,
        "expired": RenewalState.EXPIRED,
        "cancelled": RenewalState.CANCELLED,
        "unknown": RenewalState.VERIFYING,
    }
    status = result.get("state")
    session_ref = result.get("session_ref")
    profile_ref = result.get("profile_ref")
    if (
        profile_ref != expected_profile_ref
        or session_ref != expected_session_ref
        or not isinstance(profile_ref, str)
        or not _OPAQUE_PROVIDER_REF.fullmatch(profile_ref)
        or not isinstance(session_ref, str)
        or not _OPAQUE_PROVIDER_REF.fullmatch(session_ref)
        or not isinstance(status, str)
        or status not in states
    ):
        raise RuntimeError("Account Center renewal session escaped its fixed profile scope")
    raw_user_code = result.get("user_code")
    user_code = None
    if raw_user_code is not None:
        if (
            not isinstance(raw_user_code, str)
            or re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", raw_user_code) is None
        ):
            raise RuntimeError("Account Center renewal user code is invalid")
        user_code = raw_user_code
    raw_url = result.get("verification_uri")
    authorization_url = None
    if raw_url is not None:
        if raw_url not in {
            "https://hf.co/oauth/device",
            "https://huggingface.co/oauth/device",
        }:
            raise RuntimeError("Account Center renewal URL is outside the fixed HF route")
        authorization_url = raw_url
    if states[status] == RenewalState.WAITING_USER and (
        user_code is None or authorization_url is None
    ):
        raise RuntimeError("Account Center waiting session has no user action metadata")
    raw_expiry = result.get("expires_at")
    if raw_expiry is not None and (
        isinstance(raw_expiry, bool) or not isinstance(raw_expiry, int) or raw_expiry <= 0
    ):
        raise RuntimeError("Account Center renewal expiry is invalid")
    raw_interval = result.get("interval_seconds")
    if raw_interval is not None and (
        isinstance(raw_interval, bool)
        or not isinstance(raw_interval, int)
        or not 1 <= raw_interval <= 300
    ):
        raise RuntimeError("Account Center polling interval is invalid")
    generation = result.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise RuntimeError("Account Center profile generation is invalid")
    reason_code = result.get("reason_code")
    if reason_code is not None and (
        not isinstance(reason_code, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}", reason_code) is None
    ):
        raise RuntimeError("Account Center renewal reason code is invalid")
    return ProviderRenewalSession(
        authorization_ref=profile_ref,
        session_ref=session_ref,
        state=states[status],
        created_at=datetime.now(UTC),
        expires_at=(datetime.fromtimestamp(raw_expiry, UTC) if raw_expiry is not None else None),
        authorization_url=authorization_url,
        qr_attachment_ref=None,
        generation=generation,
        user_code=user_code,
    )


def _safe_vendor_url(value: str) -> str | None:
    """Accept only the fixed onboarding QR or verified profile management URL."""

    if _OFFICIAL_WECOM_QR_URL.fullmatch(value):
        return value
    if value != value.strip() or "#" in value or any(ord(character) < 0x20 for character in value):
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "work.weixin.qq.com"
            or parsed.path != _WECOM_MANAGEMENT_PATH
            or parsed.fragment
            or not parsed.query
        ):
            return None
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=len(_WECOM_MANAGEMENT_QUERY_KEYS),
            encoding="utf-8",
            errors="strict",
        )
    except (ValueError, UnicodeError) as exc:
        _LOGGER.info(
            "Malformed WeCom navigation URI was rejected (%s)",
            type(exc).__name__,
        )
        return None
    if len(pairs) != len(_WECOM_MANAGEMENT_QUERY_KEYS):
        return None
    parameters = dict(pairs)
    if (
        len(parameters) != len(pairs)
        or set(parameters) != set(_WECOM_MANAGEMENT_QUERY_KEYS)
        or not re.fullmatch(r"[0-9]{17}", parameters["aibotid"])
        or parameters["bar_style_type"] != "3"
        or parameters["for_native"] != "true"
        or parameters["forceInnerBrowser"] != "1"
        or parameters["from"] != "chat"
        or parameters["hide_more_btn"] != "true"
        or not re.fullmatch(r"[0-9A-Fa-f]{6},[0-9A-Fa-f]{6}", parameters["pc_bar_bg"])
        or not re.fullmatch(r"[A-Za-z0-9_-]{35}", parameters["str_aibotid"])
        or parameters["type"] != "6"
    ):
        return None
    for dimension in ("ww_vh", "ww_vw"):
        if not re.fullmatch(r"[0-9]+", parameters[dimension]):
            return None
        normalized_dimension = int(parameters[dimension])
        if not 1 <= normalized_dimension <= 4096:
            return None
        parameters[dimension] = str(normalized_dimension)

    canonical_query = urlencode([(key, parameters[key]) for key in _WECOM_MANAGEMENT_QUERY_KEYS])
    return urlunsplit(("https", "work.weixin.qq.com", _WECOM_MANAGEMENT_PATH, canonical_query, ""))


def _invoke_signed_tool(
    client: DirectInvoker,
    *,
    endpoint: DirectPluginEndpointConfig,
    principal: IntegrationPrincipal,
    caller_workload: str,
    audience: str,
    expected_issuer: str,
    key: bytes,
    tool_id: str,
    arguments: Mapping[str, object],
    request_id: str,
) -> dict[str, Any]:
    """Sign the exact inner argument object with only live verified identity fields."""

    if (
        len(key) != 32
        or not request_id
        or principal.issuer != expected_issuer
        or not all(
            (
                principal.issuer,
                principal.subject,
                principal.organization_id,
                principal.workspace_id,
            )
        )
    ):
        raise PermissionError("current provider signing context is incomplete")
    try:
        sdk = _sdk()
        operation_id = sdk.TOOL_OPERATIONS.get(tool_id)
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("shared provider operation map has no fixed tool")
        typed_arguments = _typed_arguments(sdk, tool_id, arguments)
        trusted_context = sdk.sign_context(
            method=tool_id,
            operation_id=operation_id,
            payload=typed_arguments,
            caller_workload=caller_workload,
            audience=audience,
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            binding_id=endpoint.binding_id,
            request_id=request_id,
            key=key,
        )
        argument_envelope = sdk.serialize_tool_envelope(
            sdk.ToolEnvelope(
                caller_context=trusted_context,
                arguments=typed_arguments,
            )
        )
    except Exception as exc:
        raise RuntimeError("cannot construct the fixed signed provider envelope") from exc
    from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
        tool_provider_pb2 as tool_wire,
    )

    request = tool_wire.CallToolRequest(
        binding_id=endpoint.binding_id,
        provider_tool_id=tool_id,
        arguments_json=json.dumps(argument_envelope, separators=(",", ":"), ensure_ascii=False),
    )
    try:
        response = client.invoke(
            capability=PROVIDER_CAPABILITY,
            interface_version="1",
            method="call_tool",
            request=_direct_payload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                request.SerializeToString(deterministic=True),
            ),
            deadline_seconds=10.0,
            request_id=request_id,
        )
    except Exception as exc:
        # A transport exception can happen after the provider side effect; only
        # an explicit typed Plugin response may prove a safe pre-send retry.
        raise IntegrationToolCallUnavailable() from exc
    expected_type = "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse"
    if response.type_url != expected_type:
        raise IntegrationToolCallUnavailable()
    try:
        typed_response = tool_wire.CallToolResponse.FromString(response.value)
    except Exception as exc:
        raise IntegrationToolCallUnavailable() from exc
    result_kind = typed_response.WhichOneof("result")
    if result_kind == "error":
        if tool_id == "email_notification_send" and typed_response.error.retryable:
            raise EmailDeliveryRetryableError(
                "email provider confirmed a retryable pre-send failure"
            )
        try:
            code = tool_wire.ToolProviderErrorCode.Name(typed_response.error.code)
        except ValueError:
            code = "PROVIDER_UNAVAILABLE"
        _raise_provider_error(code, retryable=typed_response.error.retryable)
    if result_kind != "outcome" or typed_response.outcome.is_error:
        error_value: Mapping[str, Any] | None = None
        for part in typed_response.outcome.content:
            if part.WhichOneof("content") != "json":
                continue
            try:
                decoded = json.loads(part.json.json)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, Mapping) and isinstance(decoded.get("error"), Mapping):
                error_value = decoded["error"]
                break
        if error_value is None or not isinstance(error_value.get("code"), str):
            raise IntegrationToolCallUnavailable()
        _raise_provider_error(
            str(error_value["code"]),
            retryable=error_value.get("retryable") is True,
            unknown=(
                error_value.get("outcome") == "UNKNOWN"
                or error_value.get("state") == "UNKNOWN_RESULT"
            ),
        )
    values: list[dict[str, Any]] = []
    for part in typed_response.outcome.content:
        if part.WhichOneof("content") != "json":
            continue
        try:
            decoded = json.loads(part.json.json)
        except json.JSONDecodeError as exc:
            raise IntegrationToolCallUnavailable() from exc
        if isinstance(decoded, Mapping):
            values.append(dict(decoded))
    if len(values) != 1:
        raise IntegrationToolCallUnavailable()
    return values[0]


def _invoke_signed_huggingface_tool(
    client: DirectInvoker | None,
    *,
    endpoint: DirectPluginEndpointConfig,
    principal: IntegrationPrincipal,
    profile: AuthorizationProviderProfile,
    context_key: bytes,
    tool_id: str,
    operation_id: str,
    arguments: Mapping[str, object],
    request_id: str,
) -> dict[str, Any]:
    """Use the Hugging Face Plugin's lease envelope without serializing credentials."""

    operation_for_tool = {
        "huggingface.models.list": "huggingface.models.list",
        "huggingface.datasets.list": "huggingface.datasets.list",
        "huggingface.spaces.list": "huggingface.spaces.list",
        "huggingface.repo.get": "huggingface.repo.get",
        "huggingface.file.download": "huggingface.file.download",
        "huggingface.file.upload": "huggingface.file.upload",
    }
    if (
        client is None
        or operation_for_tool.get(tool_id) != operation_id
        or len(context_key) != 32
        or not request_id
        or principal.issuer != profile.expected_issuer
    ):
        raise PermissionError("Hugging Face provider binding is incomplete")
    try:
        from cyrene_account_center_contracts import sign_context

        from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
            tool_provider_pb2 as tool_wire,
        )

        profile_ref = arguments.get("profile_ref")
        lease_ref = arguments.get("lease_ref")
        payload = arguments.get("payload")
        if (
            not isinstance(profile_ref, str)
            or not profile_ref
            or not isinstance(lease_ref, str)
            or not lease_ref
            or not isinstance(payload, Mapping)
        ):
            raise ValueError("Hugging Face lease envelope is invalid")
        signed_payload = {
            "payload": dict(payload),
            "profile_ref": profile_ref,
            "lease_ref": lease_ref,
        }
        trusted_context = sign_context(
            method="call_tool",
            payload=signed_payload,
            caller_id=profile.caller_workload,
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            binding_id=endpoint.binding_id,
            request_id=request_id,
            operation_id=operation_id,
            key=context_key,
        )
        envelope = {
            **signed_payload,
            "trusted_context": trusted_context.as_dict(),
        }
        request = tool_wire.CallToolRequest(
            binding_id=endpoint.binding_id,
            provider_tool_id=tool_id,
            arguments_json=json.dumps(
                envelope,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        )
    except Exception as exc:
        raise ProviderObservationUnavailable("Hugging Face signed lease is invalid") from exc

    try:
        response = client.invoke(
            capability=PROVIDER_CAPABILITY,
            interface_version="1",
            method="call_tool",
            request=_direct_payload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                request.SerializeToString(deterministic=True),
            ),
            deadline_seconds=10.0,
            request_id=request_id,
        )
    except Exception as exc:
        raise IntegrationToolCallUnavailable(retryable=True) from exc
    if response.type_url != "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse":
        raise IntegrationToolCallUnavailable()
    try:
        typed_response = tool_wire.CallToolResponse.FromString(response.value)
    except Exception as exc:
        raise IntegrationToolCallUnavailable() from exc
    if typed_response.WhichOneof("result") != "outcome":
        raise IntegrationToolCallUnavailable()
    values: list[dict[str, Any]] = []
    for part in typed_response.outcome.content:
        if part.WhichOneof("content") != "json":
            continue
        try:
            decoded = json.loads(part.json.json)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            values.append(decoded)
    if typed_response.outcome.is_error:
        error = next(
            (value.get("error") for value in values if isinstance(value.get("error"), Mapping)),
            None,
        )
        if error is None:
            raise IntegrationToolCallUnavailable()
        code = error.get("code")
        if not isinstance(code, str) or not code:
            raise IntegrationToolCallUnavailable()
        _raise_provider_error(
            code,
            retryable=error.get("retryable") is True,
            unknown=error.get("outcome") == "UNKNOWN",
        )
    if len(values) != 1:
        raise IntegrationToolCallUnavailable()
    return values[0]


def _invoke_signed_microsoft_graph_tool(
    client: DirectInvoker | None,
    *,
    endpoint: DirectPluginEndpointConfig,
    principal: IntegrationPrincipal,
    profile: AuthorizationProviderProfile,
    context_key: bytes,
    tool_id: str,
    operation_id: str,
    arguments: Mapping[str, object],
    request_id: str,
) -> dict[str, Any]:
    """Send one Account Center lease envelope to the fixed Graph provider Plugin."""

    payload = arguments.get("payload")
    target = arguments.get("target")
    profile_ref = arguments.get("profile_ref")
    lease_ref = arguments.get("lease_ref")
    arguments_sha256 = arguments.get("arguments_sha256")
    raw_scope_sha256 = arguments.get("profile_scope_sha256")
    office_v2_profile = profile.microsoft_graph_office_v2
    try:
        scope_sha256 = validate_microsoft_graph_scope_digest(raw_scope_sha256, required=True)
        tenant_id, _object_id, _subject = microsoft_identity_for_principal(principal)
    except ValueError as exc:
        raise PermissionError("Microsoft Graph profile scope digest is invalid") from exc
    if (
        client is None
        or operation_id not in GRAPH_OPERATIONS
        or tool_id != operation_id
        or profile.provider != "microsoft_graph"
        or profile.caller_workload != "microsoft-graph-provider"
        or len(context_key) != 32
        or not request_id
        or principal.issuer != profile.expected_issuer
        or principal.organization_id != profile.organization_id
        or principal.workspace_id != profile.workspace_id
        or not isinstance(profile_ref, str)
        or not profile_ref
        or not isinstance(lease_ref, str)
        or not lease_ref
        or not isinstance(target, Mapping)
        or target.get("tenant_id") != tenant_id
        or (
            operation_id.startswith("microsoft_graph.planner.")
            and operation_id != "microsoft_graph.planner.plans.list"
            and profile.microsoft_graph_plan_ids
            and target.get("plan_id") not in profile.microsoft_graph_plan_ids
        )
        or (
            operation_id in SHAREPOINT_READ_OPERATIONS | SHAREPOINT_V2_READ_OPERATIONS
            and (
                target.get("site_id") != profile.microsoft_graph_sharepoint_site_id
                or (
                    "list_id" in target
                    and profile.microsoft_graph_sharepoint_list_ids
                    and target.get("list_id") not in profile.microsoft_graph_sharepoint_list_ids
                )
                or (
                    "drive_id" in target
                    and office_v2_profile is not None
                    and office_v2_profile.targets["sharePointDriveIds"]
                    and target.get("drive_id")
                    not in office_v2_profile.targets["sharePointDriveIds"]
                )
            )
        )
        or not isinstance(payload, Mapping)
        or not isinstance(arguments_sha256, str)
        or arguments_sha256
        != digest_arguments(microsoft_graph_lease_arguments(operation_id, payload))
        or not scope_sha256
    ):
        raise PermissionError("Microsoft Graph provider lease binding is incomplete")
    signed_payload = {
        "payload": dict(payload),
        "profile_ref": profile_ref,
        "lease_ref": lease_ref,
        "target": dict(target),
        "arguments_sha256": arguments_sha256,
        "profile_scope_sha256": scope_sha256,
    }
    try:
        from cyrene_account_center_contracts import sign_context

        from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
            tool_provider_pb2 as tool_wire,
        )

        trusted_context = sign_context(
            method="call_tool",
            payload=signed_payload,
            caller_id=EXCHANGE_SERVICE_CALLER_ID,
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            binding_id=endpoint.binding_id,
            request_id=request_id,
            operation_id=operation_id,
            key=context_key,
        )
        envelope = {**signed_payload, "trusted_context": trusted_context.as_dict()}
        request = tool_wire.CallToolRequest(
            binding_id=endpoint.binding_id,
            provider_tool_id=tool_id,
            arguments_json=json.dumps(
                envelope,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        )
    except Exception as exc:
        raise ProviderObservationUnavailable("Microsoft Graph signed lease is invalid") from exc

    try:
        response = client.invoke(
            capability=PROVIDER_CAPABILITY,
            interface_version="1",
            method="call_tool",
            request=_direct_payload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                request.SerializeToString(deterministic=True),
            ),
            deadline_seconds=10.0,
            request_id=request_id,
        )
    except Exception as exc:
        if operation_id in GRAPH_MUTATING_OPERATIONS:
            _raise_provider_error("PROVIDER_OUTCOME_UNKNOWN", retryable=False, unknown=True)
        raise IntegrationToolCallUnavailable(retryable=True) from exc
    if response.type_url != "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse":
        if operation_id in GRAPH_MUTATING_OPERATIONS:
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
        raise IntegrationToolCallUnavailable()
    try:
        typed_response = tool_wire.CallToolResponse.FromString(response.value)
    except Exception as exc:
        if operation_id in GRAPH_MUTATING_OPERATIONS:
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
        raise IntegrationToolCallUnavailable() from exc
    result_kind = typed_response.WhichOneof("result")
    if result_kind == "error":
        try:
            code = tool_wire.ToolProviderErrorCode.Name(typed_response.error.code)
        except ValueError:
            code = "PROVIDER_UNAVAILABLE"
        if code in {"AUTH_EXPIRED", "REFRESH_TOKEN_EXPIRED", "CONSENT_REVOKED"}:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
                title="Microsoft Graph reauthorization required",
                detail="Account Center could not refresh this actor's delegated Graph consent.",
                status=409,
                context={"reasonCode": "microsoft_graph_reauthorization_required"},
            )
        _raise_provider_error(code, retryable=typed_response.error.retryable)
    if result_kind != "outcome":
        if operation_id in GRAPH_MUTATING_OPERATIONS:
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
        raise IntegrationToolCallUnavailable()
    values: list[dict[str, Any]] = []
    for part in typed_response.outcome.content:
        if part.WhichOneof("content") != "json":
            continue
        try:
            decoded = json.loads(part.json.json)
        except json.JSONDecodeError as exc:
            if operation_id in GRAPH_MUTATING_OPERATIONS:
                _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
            raise IntegrationToolCallUnavailable() from exc
        if isinstance(decoded, Mapping):
            values.append(dict(decoded))
    if typed_response.outcome.is_error:
        error = next(
            (value.get("error") for value in values if isinstance(value.get("error"), Mapping)),
            None,
        )
        if error is None or not isinstance(error.get("code"), str):
            if operation_id in GRAPH_MUTATING_OPERATIONS:
                _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
            raise IntegrationToolCallUnavailable()
        code = str(error["code"])
        if code.upper() in {"AUTH_EXPIRED", "REFRESH_TOKEN_EXPIRED", "CONSENT_REVOKED"}:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED",
                title="Microsoft Graph reauthorization required",
                detail="Account Center could not refresh this actor's delegated Graph consent.",
                status=409,
                context={"reasonCode": "microsoft_graph_reauthorization_required"},
            )
        _raise_provider_error(
            code,
            retryable=error.get("retryable") is True,
            unknown=(error.get("outcome") == "UNKNOWN" or error.get("state") == "UNKNOWN_RESULT"),
        )
    if len(values) != 1:
        if operation_id in GRAPH_MUTATING_OPERATIONS:
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
        raise IntegrationToolCallUnavailable()
    result = values[0]
    if operation_id.startswith("microsoft_graph.mail.") and (
        "error" in result
        or "isError" in result
        or "is_error" in result
        or _contains_forbidden_mail_content(result)
    ):
        if operation_id in GRAPH_MUTATING_OPERATIONS:
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
        raise IntegrationToolCallUnavailable()
    if operation_id in GRAPH_MUTATING_OPERATIONS:
        expected_status = (
            "ACCEPTED"
            if operation_id == "microsoft_graph.mail.message.send"
            else "CONFIRMED"
            if operation_id.startswith("microsoft_graph.mail.")
            else None
        )
        if expected_status is not None and result.get("status") not in {
            expected_status,
            "UNKNOWN",
        }:
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
        if operation_id.startswith("microsoft_graph.mail.") and not _valid_mail_mutation_result(
            operation_id,
            result,
            target,
        ):
            _raise_provider_error("PROVIDER_RESPONSE_INVALID", retryable=False, unknown=True)
    return result


def _contains_forbidden_mail_content(value: object) -> bool:
    """Reject bodies and attachments if a provider ever violates metadata-only Mail reads."""

    forbidden = {"body", "bodypreview", "body_preview", "bodytext", "body_text", "attachments"}
    if isinstance(value, Mapping):
        return any(
            str(key).replace("_", "").casefold() in forbidden
            or _contains_forbidden_mail_content(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_mail_content(item) for item in value)
    return False


def _valid_mail_mutation_result(
    operation_id: str,
    result: Mapping[str, Any],
    target: object,
) -> bool:
    """Require the fixed confirmation/uncertainty shape for Mail writes."""

    if not isinstance(target, Mapping):
        return False
    status = result.get("status")
    if status not in {"CONFIRMED", "ACCEPTED", "UNKNOWN"}:
        return False
    target_message_id = target.get("message_id")
    if status == "UNKNOWN":
        if not isinstance(result.get("reconciliation"), str) or not result["reconciliation"]:
            return False
        if operation_id == "microsoft_graph.mail.draft.create":
            return "message" in result and result.get("message") is None
        return isinstance(target_message_id, str) and result.get("message_id") == target_message_id
    if operation_id == "microsoft_graph.mail.message.send":
        return status == "ACCEPTED" and result.get("message_id") == target_message_id
    if status != "CONFIRMED":
        return False
    if operation_id == "microsoft_graph.mail.draft.delete":
        return result.get("message_id") == target_message_id
    message = result.get("message")
    if not isinstance(message, Mapping):
        return False
    if operation_id == "microsoft_graph.mail.draft.create":
        return isinstance(message.get("message_id"), str) and message.get("is_draft") is True
    return (
        operation_id == "microsoft_graph.mail.draft.update"
        and isinstance(target_message_id, str)
        and message.get("message_id") == target_message_id
        and message.get("is_draft") is True
    )


def _invoke_signed_azure_devops_tool(
    client: DirectInvoker | None,
    *,
    endpoint: DirectPluginEndpointConfig,
    principal: IntegrationPrincipal,
    profile: AuthorizationProviderProfile,
    context_key: bytes,
    tool_id: str,
    operation_id: str,
    arguments: Mapping[str, object],
    request_id: str,
) -> dict[str, Any]:
    """Send one exact actor-bound Account Center lease to the ADO provider."""

    payload = arguments.get("payload")
    target = arguments.get("target")
    profile_ref = arguments.get("profile_ref")
    lease_ref = arguments.get("lease_ref")
    arguments_sha256 = arguments.get("arguments_sha256")
    try:
        scope_sha256 = validate_microsoft_graph_scope_digest(
            arguments.get("profile_scope_sha256"),
            required=True,
        )
        tenant_id, _object_id, _subject = microsoft_identity_for_principal(principal)
    except ValueError as exc:
        raise PermissionError("Azure DevOps actor or profile scope binding is invalid") from exc
    if (
        client is None
        or operation_id not in ADO_OBSERVATION_OPERATIONS
        or tool_id != operation_id
        or profile.provider != "azure_devops"
        or profile.caller_workload != "azure-devops-observation-provider"
        or profile.access_mode != "actor_owned"
        or len(context_key) != 32
        or not request_id
        or principal.issuer != profile.expected_issuer
        or principal.organization_id != profile.organization_id
        or principal.workspace_id != profile.workspace_id
        or not isinstance(profile_ref, str)
        or not profile_ref
        or not isinstance(lease_ref, str)
        or not lease_ref
        or not isinstance(target, Mapping)
        or target.get("tenant_id") != tenant_id
        or not isinstance(payload, Mapping)
        or not isinstance(arguments_sha256, str)
        or arguments_sha256 != digest_arguments(payload)
        or not scope_sha256
    ):
        raise PermissionError("Azure DevOps provider lease binding is incomplete")
    signed_payload = {
        "payload": dict(payload),
        "profile_ref": profile_ref,
        "lease_ref": lease_ref,
        "target": dict(target),
        "arguments_sha256": arguments_sha256,
        "profile_scope_sha256": scope_sha256,
    }
    try:
        from cyrene_account_center_contracts import sign_context

        from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
            tool_provider_pb2 as tool_wire,
        )

        trusted_context = sign_context(
            method="call_tool",
            payload=signed_payload,
            caller_id=profile.caller_workload,
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            binding_id=endpoint.binding_id,
            request_id=request_id,
            operation_id=operation_id,
            key=context_key,
        )
        envelope = {**signed_payload, "trusted_context": trusted_context.as_dict()}
        request = tool_wire.CallToolRequest(
            binding_id=endpoint.binding_id,
            provider_tool_id=tool_id,
            arguments_json=json.dumps(envelope, separators=(",", ":"), ensure_ascii=False),
        )
    except Exception as exc:
        raise ProviderObservationUnavailable("Azure DevOps signed lease is invalid") from exc
    try:
        response = client.invoke(
            capability=PROVIDER_CAPABILITY,
            interface_version="1",
            method="call_tool",
            request=_direct_payload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                request.SerializeToString(deterministic=True),
            ),
            deadline_seconds=10.0,
            request_id=request_id,
        )
    except Exception as exc:
        raise IntegrationToolCallUnavailable(retryable=True) from exc
    if response.type_url != "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse":
        raise IntegrationToolCallUnavailable()
    try:
        typed_response = tool_wire.CallToolResponse.FromString(response.value)
    except Exception as exc:
        raise IntegrationToolCallUnavailable() from exc
    if typed_response.WhichOneof("result") != "outcome":
        raise IntegrationToolCallUnavailable()
    values: list[dict[str, Any]] = []
    for part in typed_response.outcome.content:
        if part.WhichOneof("content") != "json":
            continue
        try:
            value = json.loads(part.json.json)
        except json.JSONDecodeError:
            continue
        if isinstance(value, Mapping):
            values.append(dict(value))
    if typed_response.outcome.is_error:
        error = next(
            (value.get("error") for value in values if isinstance(value.get("error"), Mapping)),
            None,
        )
        if error is None or not isinstance(error.get("code"), str):
            raise IntegrationToolCallUnavailable()
        _raise_azure_devops_provider_error(
            str(error["code"]),
            retryable=error.get("retryable") is True,
            unknown=error.get("outcome") == "UNKNOWN" or error.get("state") == "UNKNOWN_RESULT",
        )
    if len(values) != 1:
        raise IntegrationToolCallUnavailable()
    return values[0]


def _raise_azure_devops_provider_error(
    code: str,
    *,
    retryable: bool,
    unknown: bool = False,
) -> None:
    """Preserve the ADO provider's auth, source, cursor, and availability classes."""

    normalized = code.upper()
    if unknown:
        _raise_provider_error(code, retryable=retryable, unknown=True)
    if normalized in {"AUTHENTICATION_DENIED", "SOURCE_SCOPE_DENIED", "PROFILE_SCOPE_MISMATCH"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps source is outside the authorized profile",
            detail="The selected source or actor does not match its Account Center profile.",
            status=403,
            context={"reasonCode": normalized.lower()},
        )
    if normalized in {"AUTHORIZATION_DENIED", "PERMISSION_DENIED", "RESOURCE_SCOPE_MISMATCH"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PERMISSION_DENIED",
            title="Azure DevOps permission denied",
            detail="Azure DevOps denied access to the selected project or resource.",
            status=403,
            context={"reasonCode": normalized.lower()},
        )
    if normalized == "INVALID_CURSOR":
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
            title="Azure DevOps page cursor is invalid",
            detail="The supplied cursor is not valid for this authorized source.",
            status=422,
            context={"reasonCode": "invalid_cursor"},
        )
    if normalized == "AUTHORIZATION_UNAVAILABLE":
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_UNAVAILABLE",
            title="Azure DevOps authorization is unavailable",
            detail="The provider could not verify access to the selected source.",
            status=503,
            retryable=True,
            context={"reasonCode": "authorization_unavailable"},
        )
    _raise_provider_error(code, retryable=retryable)


def _sdk() -> Any:
    try:
        import cyrene_integration_contracts
    except ImportError as exc:
        raise RuntimeError(
            "cyrene-integration-contracts integration dependency is unavailable"
        ) from exc
    return cyrene_integration_contracts


def _typed_arguments(
    sdk: Any,
    tool_id: str,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    """Round-trip one fixed tool argument DTO before hashing or signing it."""

    pairs = {
        "wecom_authorization_health": (
            sdk.parse_wecom_authorization_health_arguments,
            sdk.serialize_wecom_authorization_health_arguments,
        ),
        "wecom_reauthorization_start": (
            sdk.parse_wecom_reauthorization_start_arguments,
            sdk.serialize_wecom_reauthorization_start_arguments,
        ),
        "wecom_reauthorization_status": (
            sdk.parse_wecom_reauthorization_status_arguments,
            sdk.serialize_wecom_reauthorization_status_arguments,
        ),
        "cloud_resources_query": (
            sdk.parse_cloud_resources_query_arguments,
            sdk.serialize_cloud_resources_query_arguments,
        ),
        "cloud_authorization_health": (
            sdk.parse_cloud_authorization_health_arguments,
            sdk.serialize_cloud_authorization_health_arguments,
        ),
        "email_notification_send": (
            sdk.parse_email_notification_send_arguments,
            sdk.serialize_email_notification_send_arguments,
        ),
    }
    parser_serializer = pairs.get(tool_id)
    if parser_serializer is None:
        if tool_id not in sdk.TOOL_OPERATIONS:
            raise ValueError("provider tool is not allowlisted")
        value = dict(arguments)
        _validate_generic_connector_arguments(value)
        return value
    parser, serializer = parser_serializer
    value = serializer(parser(arguments))
    if not isinstance(value, Mapping):
        raise ValueError("provider arguments did not serialize to an object")
    return cast(dict[str, object], dict(value))


def _validate_generic_connector_arguments(arguments: Mapping[str, object]) -> None:
    """Bound the shared Plugin DTO and reject caller-supplied credential fields."""

    encoded = json.dumps(
        dict(arguments),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > 64 * 1024:
        raise ValueError("connector provider arguments exceed the configured size limit")
    forbidden_keys = {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "password",
        "secret",
        "token",
    }

    def inspect(value: object) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if isinstance(key, str) and key.lower() in forbidden_keys:
                    raise ValueError("provider arguments cannot carry credential fields")
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect(arguments)


def _same_email_request(current: EmailNotificationJob, requested: EmailNotificationJob) -> bool:
    """Compare immutable owner and content fields while allowing CLAIMED→SENDING."""

    return all(
        getattr(current, field) == getattr(requested, field)
        for field in (
            "id",
            "notification_id",
            "organization_id",
            "workspace_id",
            "actor_issuer",
            "actor_subject",
            "connection_id",
            "recipient_ref",
            "subject",
            "text",
            "request_ref",
        )
    )


def _same_actor(left: IntegrationPrincipal, right: IntegrationPrincipal) -> bool:
    """Require an immediate authority recheck to preserve the same scoped actor."""

    return (
        left.issuer == right.issuer
        and left.subject == right.subject
        and left.organization_id == right.organization_id
        and left.workspace_id == right.workspace_id
    )
