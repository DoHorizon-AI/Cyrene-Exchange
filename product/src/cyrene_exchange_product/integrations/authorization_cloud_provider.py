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
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

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
)
from cyrene_exchange_product.integrations.clients import (
    PROVIDER_CAPABILITY,
    DirectInvoker,
    _direct_payload,
)
from cyrene_exchange_product.integrations.models import (
    AuthorizationCapabilityRecord,
    AuthorizationHealthRecord,
    AuthorizationState,
    CloudResourceRecord,
    CloudResourceState,
    EmailNotificationJob,
    IntegrationConnection,
    IntegrationPrincipal,
    LoginState,
    RenewalState,
    SnapshotFreshness,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


class PlatformCurrentAuthorizationContextResolver:
    """Reverify a host-owned live bearer and current catalog grant on every worker call."""

    def __init__(
        self,
        *,
        store: IntegrationStore,
        identity_verifier: Any,
        registry: AuthorizationCloudProfileRegistry,
        bearer_token: Callable[[str], str | None],
    ) -> None:
        self._store = store
        self._identity_verifier = identity_verifier
        self._registry = registry
        self._bearer_token = bearer_token

    def for_connection(
        self,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        """Reload the connection and reverify its owner before each provider call."""

        try:
            current = self._store.current_connection_for_provider_call(connection.id)
            if current is None or current != connection:
                return None
            context, _profile = self._registry.context_for_connection(current)
            principal = self._verified_principal(context, operation_id=operation_id)
            self._registry.profile_for_connection(
                principal,
                current,
                operation_id=operation_id,
            )
            return principal
        except Exception as exc:
            _LOGGER.info(
                "Current authorization is unavailable for an integration connection (%s)",
                type(exc).__name__,
            )
            return None

    def for_notification(
        self,
        job: EmailNotificationJob,
        *,
        operation_id: str,
    ) -> IntegrationPrincipal | None:
        """Reverify the email owner and the dedicated delivery grant for each send."""

        try:
            if operation_id != "integrationDeliverNotification":
                return None
            current = self._store.current_email_job_for_provider_call(job.id)
            if current is None or not _same_email_request(current, job):
                return None
            context = self._registry.email_context_for_job(current)
            return self._verified_principal(context, operation_id=operation_id)
        except Exception as exc:
            _LOGGER.info(
                "Current authorization is unavailable for an email notification (%s)",
                type(exc).__name__,
            )
            return None

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


_TOOL_OPERATIONS = {
    "wecom_authorization_health": "wecom.authorization.health.read",
    "wecom_reauthorization_start": "wecom.authorization.renewal.start",
    "wecom_reauthorization_status": "wecom.authorization.renewal.status",
    "cloud_resources_query": "cloud.resources.query",
    "cloud_authorization_health": "cloud.authorization.health.read",
    "email_notification_send": "email.notification.send",
}
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
        current_context_resolver: Any,
        context_key: Callable[[str], bytes],
    ) -> None:
        self._store = store
        self._registry = registry
        self._provider_clients = dict(provider_clients)
        self._email_client = email_client
        self._current_context_resolver = current_context_resolver
        self._context_key = context_key

    def authorization_health(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
    ) -> AuthorizationHealthRecord:
        principal, profile, target_ref = self._verified_connection(
            principal, connection, operation_id="integrationGetAuthorizationHealth"
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
            expires_at=observed.expires_at,
            generation=observed.generation,
            capabilities=[
                AuthorizationCapabilityRecord(
                    capability_id=item.capability_id,
                    state=AuthorizationState(item.state.value),
                    last_verified_at=item.last_verified_at,
                    expires_at=item.expires_at,
                    reason_code=item.reason_code,
                )
                for item in observed.capabilities
            ],
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
        principal, profile, _ = self._verified_connection(
            principal, connection, operation_id="accountBeginRenewalSession"
        )
        if (
            profile.provider != "wecom"
            or authorization_ref != profile.authorization_ref
            or not _OPAQUE_PROVIDER_REF.fullmatch(authorization_ref)
        ):
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
        connection = self._store.connection_for_authorization(
            principal,
            authorization_ref,
            provider="wecom",
            authorization_operation_id="accountGetRenewalSession",
        )
        principal, profile, _ = self._verified_connection(
            principal,
            connection,
            operation_id="accountGetRenewalSession",
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
        connection = self._store.connection_for_authorization(
            principal,
            authorization_ref,
            provider="wecom",
            authorization_operation_id="accountGetRenewalSession",
        )
        principal, profile, _ = self._verified_connection(
            principal,
            connection,
            operation_id="accountGetRenewalSession",
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
            fresh_principal = self._current_context_resolver.for_notification(
                job,
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
        if not _same_email_request(current, job) or current.state.value != "SENDING":
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
        operation_id = _TOOL_OPERATIONS[tool_id]
        if sdk.TOOL_OPERATIONS.get(tool_id) != operation_id:
            raise ValueError("shared provider operation map changed")
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
        raise IntegrationToolCallUnavailable(retryable=typed_response.error.retryable)
    if result_kind != "outcome" or typed_response.outcome.is_error:
        raise IntegrationToolCallUnavailable()
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
        raise ValueError("provider tool is not allowlisted")
    parser, serializer = parser_serializer
    value = serializer(parser(arguments))
    if not isinstance(value, Mapping):
        raise ValueError("provider arguments did not serialize to an object")
    return cast(dict[str, object], dict(value))


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
