"""Private Office setup bridge for Account Center OAuth and scoped target selection.

Module: cyrene_exchange_product.integrations.office_setup
Role: Run fixed owner-bound Office setup actions from a loopback UI.
模块职责：通过固定 CLI 桥接 Office OAuth、只读资源发现与目标范围 CAS。
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cyrene_exchange_product.integrations.api import (
    _microsoft_graph_oauth_session_response,
    _provider_profile_ref,
)
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    microsoft_graph_office_v2_scope,
    validate_microsoft_graph_office_v2_scope,
)
from cyrene_exchange_product.integrations.bootstrap import (
    _stable_connection_id,
    authorize_connector_operator,
)
from cyrene_exchange_product.integrations.connector_operations import _resource_ref
from cyrene_exchange_product.integrations.connector_security import digest_arguments
from cyrene_exchange_product.integrations.microsoft_graph import (
    OFFICE_V2_REDIRECT_URI,
    profile_scope_metadata,
    public_profile_scope,
    required_oauth_scopes,
    target_for_operation,
    validate_profile_identity,
    validate_profile_scope,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationPrincipal,
)

_MAX_PRIVATE_CONFIG_BYTES = 64 * 1024
_MAX_REQUEST_BYTES = 32 * 1024
_RESOURCE_TYPES = frozenset(
    {
        "planner_plans",
        "todo_lists",
        "sharepoint_drives",
        "calendars",
        "mail_folders",
        "freebusy_subjects",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "plannerPlanIds",
        "sharePointListIds",
        "sharePointDriveIds",
        "toDoTaskListIds",
        "calendarIds",
        "mailFolderIds",
        "freebusySubjects",
    }
)
_RESOURCE_OPERATIONS = {
    "planner_plans": "microsoft_graph.planner.plans.list",
    "todo_lists": "microsoft_graph.todo.lists.list",
    "sharepoint_drives": "microsoft_graph.sharepoint.drives.list",
    "calendars": "microsoft_graph.calendar.calendars.list",
    "mail_folders": "microsoft_graph.mail.folders.list",
}


class OfficeSetupError(RuntimeError):
    """Sanitized failure surfaced by the private Office setup CLI."""

    def __init__(self, reason_code: str, *, state: str = "FAILED") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.state = state


def execute_office_setup(
    services: Any,
    *,
    action: str,
    private_config: Path | str,
    request_payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one closed Office setup action for the configured Directory owner.

    The private file fixes the actor and host binding. Browser JSON selects only
    from the closed action schemas below; OAuth codes are accepted only by
    ``complete`` and are passed directly to Account Center. 中文：身份和凭据均由服务端固定。
    """

    if action not in {
        "begin",
        "complete",
        "begin-mail-scope-upgrade",
        "complete-scope-upgrade",
        "status",
        "discover",
        "select-targets",
    }:
        raise OfficeSetupError("office_setup_action_invalid")
    config = _operator_config(Path(private_config))
    payload = _request_object({} if request_payload is None else request_payload)
    principal, host_profile, profile_ref = _operator_context(services, config)

    if action == "begin":
        return _begin_link(
            services,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
            payload=payload,
        )
    if action == "begin-mail-scope-upgrade":
        return _begin_mail_scope_upgrade(
            services,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
            payload=payload,
        )
    if action == "complete":
        return _complete_link(
            services,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
            payload=payload,
        )
    if action == "complete-scope-upgrade":
        return _complete_mail_scope_upgrade(
            services,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
            payload=payload,
        )
    profile = _read_profile(services, principal, host_profile, profile_ref)
    if action == "status":
        if profile is None:
            return _not_linked_snapshot(host_profile, profile_ref, principal)
        snapshot = _profile_snapshot(profile_ref, profile, host_profile=host_profile)
        if snapshot["authStatus"] == "healthy" and not snapshot["reauthRequired"]:
            _ensure_connection(services, principal, host_profile, profile_ref)
        return snapshot
    if profile is None:
        raise OfficeSetupError("office_graph_profile_not_linked", state="AUTHORIZATION_REQUIRED")
    snapshot = _profile_snapshot(profile_ref, profile, host_profile=host_profile)
    if snapshot["authStatus"] != "healthy" or snapshot["reauthRequired"]:
        raise OfficeSetupError(
            "office_graph_authorization_required",
            state="AUTHORIZATION_REQUIRED",
        )
    _ensure_connection(services, principal, host_profile, profile_ref)
    if action == "discover":
        return _discover_targets(
            services,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
            profile=profile,
            payload=payload,
        )
    return _select_targets(
        services,
        principal=principal,
        host_profile=host_profile,
        profile_ref=profile_ref,
        profile=profile,
        payload=payload,
    )


def _operator_context(
    services: Any,
    config: Mapping[str, Any],
) -> tuple[IntegrationPrincipal, Any, str]:
    """Reverify the trusted operator and bind it to one fixed Graph host profile."""

    actor = config["actor"]
    issuer = str(actor["issuer"])
    subject = str(actor["subject"])
    organization_id = str(actor["organizationId"])
    workspace_id = str(actor["workspaceId"])
    proof_actor = IntegrationPrincipal(
        issuer=issuer,
        subject=subject,
        organization_id=organization_id,
        workspace_id=workspace_id,
        allowed_operation_ids=frozenset(),
    )
    proof_profile_ref = _provider_profile_ref(
        proof_actor,
        f"office-directory-role-proof:{config['profileIdempotencyKey']}",
    )
    proof_connection = _stable_connection_id(
        issuer=issuer,
        subject=subject,
        workspace_id=workspace_id,
        provider="github",
        profile_ref=proof_profile_ref,
        target="office-directory-role-proof",
    )
    specification = {"actor": dict(actor)}
    principal = authorize_connector_operator(
        services,
        specification=specification,
        proof_profile_ref=proof_profile_ref,
        proof_connection_ref=str(proof_connection),
    )
    registry = services.authorization_profile_registry
    profile = (
        registry.settings.profiles.get(str(config["bindingRef"])) if registry is not None else None
    )
    if (
        profile is None
        or profile.provider != "microsoft_graph"
        or profile.access_mode != "actor_owned"
        or profile.microsoft_graph_office_v2 is None
        or not registry.principal_allowed_for_profile(principal, profile)
    ):
        raise OfficeSetupError("office_graph_host_binding_unavailable")
    profile_ref = _provider_profile_ref(principal, str(config["profileIdempotencyKey"]))
    return principal, profile, profile_ref


def _begin_link(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Start one fixed OAuth scope and return only Microsoft authorization metadata."""

    _exact_fields(payload, required=set(), optional={"requestId"})
    existing = _read_profile(services, principal, host_profile, profile_ref)
    if existing is not None:
        existing_scope = validate_profile_scope(existing.get("target_scope"))
        if (
            existing.get("auth_status") == "healthy"
            and not profile_scope_metadata(existing, existing_scope)["reauth_required"]
        ):
            _ensure_connection(services, principal, host_profile, profile_ref)
            return _profile_snapshot(profile_ref, existing, host_profile=host_profile)
    raw_request_id = payload.get("requestId")
    request_id = (
        _uuid_text(raw_request_id, "requestId") if raw_request_id is not None else str(uuid4())
    )
    office_scope = microsoft_graph_office_v2_scope(host_profile, principal)
    try:
        result = services.accounts.begin_microsoft_graph_link(
            principal,
            profile_ref=profile_ref,
            planner_plan_ids=list(office_scope["planner"]["plan_ids"]),
            idempotency_key=f"office-graph-link:{profile_ref}:{request_id}",
            office_v2_scope=office_scope,
        )
        session = _microsoft_graph_oauth_session_response(
            result,
            profile_ref=profile_ref,
            expected_redirect_uri=OFFICE_V2_REDIRECT_URI,
        )
    except Exception as exc:
        raise OfficeSetupError("office_graph_link_start_failed") from exc
    return {
        "state": "AUTHORIZATION_REQUIRED",
        "provider": "microsoft_graph",
        "flowKind": "link",
        **session,
    }


def _begin_mail_scope_upgrade(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Explicitly request one host-derived Mail scope upgrade for an existing profile."""

    _exact_fields(payload, required=set(), optional={"requestId"})
    office_scope = microsoft_graph_office_v2_scope(host_profile, principal)
    mail = office_scope["mail"]
    mail_features = {
        "metadata_read": mail["metadata_read"],
        "drafts_write": mail["drafts_write"],
        "send": mail["send_enabled"],
    }
    if not any(mail_features.values()):
        raise OfficeSetupError("office_graph_mail_upgrade_not_configured")
    existing = _read_profile(services, principal, host_profile, profile_ref)
    if existing is None:
        raise OfficeSetupError("office_graph_profile_not_linked", state="AUTHORIZATION_REQUIRED")
    existing_scope = validate_profile_scope(existing.get("target_scope"))
    existing_meta = profile_scope_metadata(existing, existing_scope)
    if existing.get("auth_status") != "healthy" or existing_meta["reauth_required"]:
        raise OfficeSetupError(
            "office_graph_authorization_required", state="AUTHORIZATION_REQUIRED"
        )
    if _mail_authorization_state(host_profile, existing_scope, existing) == "READY":
        _ensure_connection(services, principal, host_profile, profile_ref)
        return _profile_snapshot(profile_ref, existing, host_profile=host_profile)
    raw_request_id = payload.get("requestId")
    request_id = (
        _uuid_text(raw_request_id, "requestId") if raw_request_id is not None else str(uuid4())
    )
    try:
        result = services.accounts.begin_microsoft_graph_scope_upgrade(
            principal,
            profile_ref=profile_ref,
            permission="mail",
            mail_features=mail_features,
            idempotency_key=f"office-graph-mail-upgrade:{profile_ref}:{request_id}",
        )
        session = _microsoft_graph_oauth_session_response(
            result,
            profile_ref=profile_ref,
            expected_redirect_uri=OFFICE_V2_REDIRECT_URI,
        )
    except Exception as exc:
        raise OfficeSetupError("office_graph_mail_upgrade_start_failed") from exc
    return {
        "state": "AUTHORIZATION_REQUIRED",
        "provider": "microsoft_graph",
        "flowKind": "scope_upgrade",
        **session,
    }


def _complete_link(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Complete one PKCE callback server-side, reconcile uncertain completion by readback."""

    _exact_fields(payload, required={"state", "code"}, optional=set())
    state = _bounded_text(payload["state"], "state", minimum=32, maximum=512)
    code = _bounded_text(payload["code"], "code", minimum=1, maximum=4096)
    callback_principal = getattr(services, "callback_principal", None)
    if not isinstance(callback_principal, IntegrationPrincipal):
        raise OfficeSetupError("office_graph_callback_service_unavailable")
    try:
        result = services.accounts.complete_microsoft_graph_link(
            callback_principal,
            state=state,
            code=code,
        )
        profile = _validate_graph_profile(
            result,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
        )
    except Exception as exc:
        # A lost response is reconciled by a fresh Account Center read, never by replaying code.
        try:
            readback_profile = _read_profile(services, principal, host_profile, profile_ref)
        except Exception as read_error:
            raise OfficeSetupError(
                "office_graph_completion_unknown", state="UNKNOWN"
            ) from read_error
        if readback_profile is None or readback_profile.get("auth_status") != "healthy":
            raise OfficeSetupError(
                "office_graph_completion_unknown",
                state="UNKNOWN",
            ) from exc
        profile = readback_profile
    scope = validate_profile_scope(profile.get("target_scope"))
    if (
        profile.get("auth_status") != "healthy"
        or profile_scope_metadata(profile, scope)["reauth_required"]
    ):
        raise OfficeSetupError("office_graph_authorization_not_healthy")
    _ensure_connection(services, principal, host_profile, profile_ref)
    return {
        "state": "LINKED",
        **_profile_snapshot(profile_ref, profile, host_profile=host_profile),
    }


def _complete_mail_scope_upgrade(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Complete only an OAuth scope-upgrade flow chosen from server-side pending state."""

    _exact_fields(payload, required={"state", "code"}, optional=set())
    state = _bounded_text(payload["state"], "state", minimum=32, maximum=512)
    code = _bounded_text(payload["code"], "code", minimum=1, maximum=4096)
    callback_principal = getattr(services, "callback_principal", None)
    if not isinstance(callback_principal, IntegrationPrincipal):
        raise OfficeSetupError("office_graph_callback_service_unavailable")
    try:
        result = services.accounts.complete_microsoft_graph_scope_upgrade(
            callback_principal,
            state=state,
            code=code,
        )
        profile = _validate_graph_profile(
            result,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
        )
        scope = validate_profile_scope(profile.get("target_scope"))
        if _mail_authorization_state(host_profile, scope, profile) != "READY":
            raise OfficeSetupError("office_graph_mail_upgrade_not_effective")
    except Exception as exc:
        # A lost response is reconciled once; never replay the authorization code.
        try:
            readback_profile = _read_profile(services, principal, host_profile, profile_ref)
        except Exception as read_error:
            raise OfficeSetupError(
                "office_graph_completion_unknown", state="UNKNOWN"
            ) from read_error
        if (
            readback_profile is None
            or readback_profile.get("auth_status") != "healthy"
            or _mail_authorization_state(
                host_profile,
                validate_profile_scope(readback_profile.get("target_scope")),
                readback_profile,
            )
            != "READY"
        ):
            raise OfficeSetupError("office_graph_completion_unknown", state="UNKNOWN") from exc
        profile = readback_profile
    _ensure_connection(services, principal, host_profile, profile_ref)
    return {
        "state": "LINKED",
        **_profile_snapshot(profile_ref, profile, host_profile=host_profile),
    }


def _read_profile(
    services: Any,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
) -> dict[str, Any] | None:
    """Read and validate one Account Center Graph profile owned by the fixed actor."""

    try:
        response = services.accounts.list_provider_profiles(principal)
    except Exception as exc:
        raise OfficeSetupError("office_graph_profile_read_failed") from exc
    rows = response.get("profiles") if isinstance(response, Mapping) else None
    if not isinstance(rows, list):
        raise OfficeSetupError("account_center_profile_list_invalid")
    matches = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("profile_ref") == profile_ref
        and row.get("provider") == "microsoft_graph"
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise OfficeSetupError("account_center_profile_duplicate")
    return _validate_graph_profile(
        matches[0],
        principal=principal,
        host_profile=host_profile,
        profile_ref=profile_ref,
    )


def _validate_graph_profile(
    value: Mapping[str, Any],
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
) -> dict[str, Any]:
    """Require the exact actor-owned v2 identity, permissions, and host target scope."""

    try:
        scope = validate_profile_identity(value, profile_ref=profile_ref, principal=principal)
        scope = validate_microsoft_graph_office_v2_scope(host_profile, scope, principal)
    except (PermissionError, ValueError) as exc:
        raise OfficeSetupError("office_graph_profile_scope_mismatch") from exc
    if value.get("access_mode", "actor_owned") != "actor_owned":
        raise OfficeSetupError("office_graph_profile_access_mode_invalid")
    auth_status = value.get("auth_status")
    if not isinstance(auth_status, str) or auth_status not in {
        "unknown",
        "configured",
        "healthy",
        "unavailable",
        "reauthorization_required",
        "revoked",
    }:
        raise OfficeSetupError("office_graph_profile_auth_status_invalid")
    return dict(value)


def _ensure_connection(
    services: Any,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
) -> Any:
    """Create or read back one actor-owned Exchange connection idempotently."""

    request = CreateIntegrationConnection(
        provider="microsoft_graph",
        binding_ref=host_profile.profile_ref,
        account_link_ref=profile_ref,
        display_name="Microsoft Graph Office",
    )
    try:
        connection = services.store.create_connection(
            principal,
            request,
            idempotency_key=f"office-setup/graph/{profile_ref}",
            access_mode="actor_owned",
        )
    except Exception as exc:
        raise OfficeSetupError("office_graph_connection_persist_failed") from exc
    if (
        connection.provider != "microsoft_graph"
        or connection.binding_ref != host_profile.profile_ref
        or connection.account_link_ref != profile_ref
        or connection.target_ref is not None
        or connection.access_mode != "actor_owned"
        or connection.workspace_id != principal.workspace_id
        or connection.actor_issuer != principal.issuer
        or connection.actor_subject != principal.subject
    ):
        raise OfficeSetupError("office_graph_connection_readback_mismatch")
    return connection


def _profile_snapshot(
    profile_ref: str,
    profile: Mapping[str, Any],
    *,
    host_profile: Any,
    state: str = "LINKED",
) -> dict[str, Any]:
    """Return only safe profile status and bounded scope metadata to the loopback UI."""

    scope = validate_profile_scope(profile.get("target_scope"))
    meta = profile_scope_metadata(profile, scope)
    expires_at = profile.get("expires_at")
    refresh_expires_at = profile.get("refresh_expires_at")
    revision = profile.get("credential_revision")
    enabled_features = {
        "plannerEnabled": bool(scope["planner"]["tasks_read"]),
        "todoEnabled": bool(scope["todo"]["enabled"]),
        "calendarEnabled": bool(scope["calendar"]["enabled"]),
        "mailMetadataEnabled": bool(scope["mail"]["metadata_read"]),
        "mailDraftsEnabled": bool(scope["mail"]["drafts_write"]),
        "mailSendEnabled": bool(scope["mail"]["send_enabled"]),
        "sharePointDriveMetadataEnabled": bool(scope["sharepoint"]["enabled"]),
    }
    return {
        "state": state,
        "profileRef": profile_ref,
        "provider": "microsoft_graph",
        "authStatus": str(profile.get("auth_status", "unknown")),
        "accessMode": "actor_owned",
        "externalSubject": str(profile.get("external_subject")),
        "scopeSchemaVersion": meta["scope_schema_version"],
        "targetScope": public_profile_scope(scope),
        "requiredOAuthScopes": list(meta["required_oauth_scopes"]),
        "enabledFeatures": enabled_features,
        "targetRefCount": int(meta["target_ref_count"]),
        "selectedCounts": {"mailFolders": len(scope["mail"]["folder_ids"])},
        "credentialExpiresAt": _epoch_text(expires_at),
        "refreshExpiresAt": _epoch_text(refresh_expires_at),
        "credentialRevision": revision,
        "reauthRequired": bool(meta["reauth_required"]),
        "reauthReasonCode": meta["reauth_reason_code"],
        "mailAuthorizationState": _mail_authorization_state(host_profile, scope, profile),
    }


def _mail_authorization_state(
    host_profile: Any,
    scope: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> str:
    """Project mail-only readiness without turning an upgrade need into link failure."""

    requested = host_profile.microsoft_graph_office_v2.enabled_features
    required = {
        "metadata_read": bool(requested["mailMetadataEnabled"]),
        "drafts_write": bool(requested["mailDraftsEnabled"]),
        "send_enabled": bool(requested["mailSendEnabled"]),
    }
    if not any(required.values()):
        return "DISABLED"
    mail = scope["mail"]
    if (
        profile.get("auth_status") != "healthy"
        or profile_scope_metadata(profile, scope)["reauth_required"]
        or any(flag and not mail[name] for name, flag in required.items())
    ):
        return "REAUTHORIZATION_REQUIRED"
    return "READY"


def _not_linked_snapshot(
    host_profile: Any,
    profile_ref: str,
    principal: IntegrationPrincipal,
) -> dict[str, Any]:
    """Expose host-approved features without disclosing the private operator file."""

    office = host_profile.microsoft_graph_office_v2
    features = office.enabled_features
    return {
        "state": "NOT_LINKED",
        "profileRef": profile_ref,
        "provider": "microsoft_graph",
        "authStatus": "unknown",
        "accessMode": "actor_owned",
        "externalSubject": None,
        "scopeSchemaVersion": 2,
        "targetScope": None,
        "requiredOAuthScopes": list(
            required_oauth_scopes(microsoft_graph_office_v2_scope(host_profile, principal))
        ),
        "enabledFeatures": dict(features),
        "targetRefCount": sum(len(values) for values in office.targets.values()),
        "selectedCounts": {"mailFolders": len(office.targets["mailFolderIds"])},
        "credentialExpiresAt": None,
        "refreshExpiresAt": None,
        "credentialRevision": None,
        "reauthRequired": False,
        "reauthReasonCode": None,
        "mailAuthorizationState": (
            "REAUTHORIZATION_REQUIRED"
            if any(
                features[name]
                for name in ("mailMetadataEnabled", "mailDraftsEnabled", "mailSendEnabled")
            )
            else "DISABLED"
        ),
    }


def _discover_targets(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
    profile: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Read metadata from one fixed provider discovery operation."""

    _exact_fields(payload, required={"resourceType"}, optional={"pageCursor"})
    resource_type = payload.get("resourceType")
    if str(resource_type) not in _RESOURCE_TYPES:
        raise OfficeSetupError("office_graph_resource_type_invalid")
    scope = validate_profile_scope(profile.get("target_scope"))
    if (
        profile.get("auth_status") != "healthy"
        or profile_scope_metadata(profile, scope)["reauth_required"]
    ):
        raise OfficeSetupError(
            "office_graph_authorization_required", state="AUTHORIZATION_REQUIRED"
        )
    if resource_type == "freebusy_subjects":
        items = [
            {"freebusy_subject": subject, "display_name": subject}
            for subject in scope["calendar"]["freebusy_subjects"]
        ]
        host_allowlist = _host_allowlist(host_profile, str(resource_type))
        return {
            "state": "DISCOVERED",
            "resourceType": resource_type,
            "items": [
                _discovery_item(str(resource_type), item)
                for item in items
                if item["freebusy_subject"] in host_allowlist
            ],
            "pageCursor": payload.get("pageCursor"),
            "nextCursor": None,
            "complete": True,
            "truncated": False,
            "credentialRevision": profile.get("credential_revision"),
        }
    operation_id = _RESOURCE_OPERATIONS.get(str(resource_type))
    if operation_id is None:
        raise OfficeSetupError("office_graph_resource_type_invalid")
    arguments: dict[str, object] = {"page_size": 50}
    if payload.get("pageCursor") is not None:
        arguments["page_cursor"] = _bounded_text(
            payload["pageCursor"], "pageCursor", minimum=1, maximum=12_000
        )
    if resource_type == "sharepoint_drives":
        site_id = scope["sharepoint"]["site_id"]
        if not isinstance(site_id, str):
            raise OfficeSetupError("office_graph_sharepoint_site_not_configured")
        arguments["site_id"] = site_id
    result = _invoke_read_operation(
        services,
        principal=principal,
        profile_ref=profile_ref,
        operation_id=operation_id,
        arguments=arguments,
    )
    raw_items = result.get("items")
    if not isinstance(raw_items, list) or len(raw_items) > 100:
        raise OfficeSetupError("office_graph_discovery_response_invalid")
    projected = [_discovery_item(str(resource_type), row) for row in raw_items]
    host_allowlist = _host_allowlist(host_profile, str(resource_type))
    if host_allowlist:
        projected = [item for item in projected if item["id"] in host_allowlist]
    response = {
        "state": "DISCOVERED",
        "resourceType": resource_type,
        "items": projected,
        "pageCursor": payload.get("pageCursor"),
        "nextCursor": result.get("next_cursor"),
        "complete": result.get("complete") is True,
        "truncated": result.get("truncated") is True,
        "credentialRevision": profile.get("credential_revision"),
    }
    if resource_type == "sharepoint_drives":
        response["siteId"] = scope["sharepoint"]["site_id"]
    return response


def _select_targets(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    host_profile: Any,
    profile_ref: str,
    profile: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """CAS only discovered target IDs; permission flags and OAuth scopes stay fixed."""

    _exact_fields(
        payload,
        required={"expectedCredentialRevision", "targets"},
        optional=set(),
    )
    expected_revision = payload["expectedCredentialRevision"]
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise OfficeSetupError("office_graph_revision_invalid")
    current_revision = profile.get("credential_revision")
    if isinstance(current_revision, bool) or not isinstance(current_revision, int):
        raise OfficeSetupError("office_graph_revision_unavailable")
    if (
        profile.get("auth_status") != "healthy"
        or profile_scope_metadata(
            profile,
            validate_profile_scope(profile.get("target_scope")),
        )["reauth_required"]
    ):
        raise OfficeSetupError(
            "office_graph_authorization_required",
            state="AUTHORIZATION_REQUIRED",
        )
    if current_revision != expected_revision:
        return _profile_snapshot(profile_ref, profile, host_profile=host_profile, state="CONFLICT")
    selected = _target_selection(payload["targets"])
    old_scope = validate_profile_scope(profile.get("target_scope"))
    if old_scope.get("schema_version") != 2:
        raise OfficeSetupError("office_graph_v2_scope_required")
    if old_scope["calendar"]["freebusy_read"] and not selected["freebusySubjects"]:
        raise OfficeSetupError("office_graph_target_selection_invalid")

    discovery_map = {
        "plannerPlanIds": ("planner_plans", "plan_id"),
        "toDoTaskListIds": ("todo_lists", "task_list_id"),
        "calendarIds": ("calendars", "calendar_id"),
        "mailFolderIds": ("mail_folders", "folder_id"),
        "sharePointDriveIds": ("sharepoint_drives", "drive_id"),
        "freebusySubjects": ("freebusy_subjects", "freebusy_subject"),
    }
    for target_name, (resource_type, resource_id_field) in discovery_map.items():
        chosen = selected[target_name]
        if not chosen:
            continue
        discovered = _discover_all_ids(
            services,
            principal=principal,
            profile_ref=profile_ref,
            host_profile=host_profile,
            profile=profile,
            resource_type=resource_type,
            id_field=resource_id_field,
        )
        if not set(chosen) <= discovered:
            raise OfficeSetupError("office_graph_target_not_discovered")
    host = host_profile.microsoft_graph_office_v2.targets
    for target_name in ("sharePointListIds", "freebusySubjects"):
        allowed = host[
            "sharePointListIds" if target_name == "sharePointListIds" else "freebusySubjects"
        ]
        if selected[target_name] and (
            not allowed or not set(selected[target_name]) <= set(allowed)
        ):
            raise OfficeSetupError("office_graph_target_outside_host_allowlist")
    for target_name in (
        "plannerPlanIds",
        "sharePointDriveIds",
        "toDoTaskListIds",
        "calendarIds",
    ):
        allowed = host[target_name]
        if allowed and not set(selected[target_name]) <= set(allowed):
            raise OfficeSetupError("office_graph_target_outside_host_allowlist")

    new_scope = {
        **old_scope,
        "planner": {**old_scope["planner"], "plan_ids": selected["plannerPlanIds"]},
        "sharepoint": {
            **old_scope["sharepoint"],
            "list_ids": selected["sharePointListIds"],
            "drive_ids": selected["sharePointDriveIds"],
        },
        "todo": {**old_scope["todo"], "task_list_ids": selected["toDoTaskListIds"]},
        "calendar": {
            **old_scope["calendar"],
            "calendar_ids": selected["calendarIds"],
            "freebusy_subjects": selected["freebusySubjects"],
        },
        "mail": {**old_scope["mail"], "folder_ids": selected["mailFolderIds"]},
    }
    new_scope = validate_profile_scope(new_scope)
    if new_scope["sharepoint"]["site_id"] != old_scope["sharepoint"]["site_id"]:
        raise OfficeSetupError("office_graph_site_scope_change_denied")
    scope_digest = digest_arguments(new_scope)
    idempotency_key = f"office-targets:{profile_ref}:{expected_revision}:{scope_digest}"
    try:
        services.accounts.update_microsoft_graph_v2_scope(
            principal,
            profile_ref=profile_ref,
            workspace_id=principal.workspace_id,
            expected_credential_revision=expected_revision,
            target_scope=new_scope,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        # The CAS may have committed before a transport failure; read back once.
        try:
            current = _read_profile(services, principal, host_profile, profile_ref)
        except Exception as read_error:
            raise OfficeSetupError(
                "office_graph_target_update_unknown", state="UNKNOWN"
            ) from read_error
        if current is not None and _same_target_scope(current.get("target_scope"), new_scope):
            current_revision = current.get("credential_revision")
            if current_revision == expected_revision + 1:
                return _profile_snapshot(
                    profile_ref, current, host_profile=host_profile, state="UPDATED"
                )
        raise OfficeSetupError("office_graph_target_update_unknown", state="UNKNOWN") from exc
    current = _read_profile(services, principal, host_profile, profile_ref)
    if current is None:
        raise OfficeSetupError("office_graph_target_update_unknown", state="UNKNOWN")
    if current.get("credential_revision") != expected_revision + 1:
        raise OfficeSetupError("office_graph_target_update_unknown", state="UNKNOWN")
    if not _same_target_scope(current.get("target_scope"), new_scope):
        raise OfficeSetupError("office_graph_target_update_readback_mismatch", state="UNKNOWN")
    return _profile_snapshot(profile_ref, current, host_profile=host_profile, state="UPDATED")


def _discover_all_ids(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    profile_ref: str,
    host_profile: Any,
    profile: Mapping[str, Any],
    resource_type: str,
    id_field: str,
) -> set[str]:
    """Read enough bounded provider pages to verify every selected target ID."""

    found: set[str] = set()
    cursor: str | None = None
    for _ in range(20):
        request: dict[str, Any] = {"resourceType": resource_type}
        if cursor is not None:
            request["pageCursor"] = cursor
        page = _discover_targets(
            services,
            principal=principal,
            host_profile=host_profile,
            profile_ref=profile_ref,
            profile=profile,
            payload=request,
        )
        for item in page["items"]:
            identifier = item.get("id")
            if isinstance(identifier, str):
                found.add(identifier)
        if page["complete"]:
            return found
        next_cursor = page.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            break
        cursor = next_cursor
    raise OfficeSetupError("office_graph_discovery_incomplete")


def _invoke_read_operation(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    profile_ref: str,
    operation_id: str,
    arguments: Mapping[str, object],
) -> dict[str, Any]:
    """Run one fixed Graph read through the normal Directory grant and AC lease path."""

    if operation_id not in _RESOURCE_OPERATIONS.values():
        raise OfficeSetupError("office_graph_discovery_operation_invalid")
    if services.connector_operation_dispatcher is None:
        raise OfficeSetupError("office_graph_dispatch_unavailable")
    matches = [
        item
        for item in services.store.connector_bindings_for_actor(
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
        )
        if item.provider == "microsoft_graph"
        and item.account_link_ref == profile_ref
        and item.binding_ref is not None
        and item.enabled
    ]
    if len(matches) != 1:
        raise OfficeSetupError("office_graph_connection_missing")
    connection = matches[0]
    connection, _row, scope = _current_graph_connection_scope(
        services,
        principal=principal,
        connection=connection,
        profile_ref=profile_ref,
        operation_id=operation_id,
    )
    selected = dict(arguments)
    target = target_for_operation(operation_id, selected, scope)
    resource_ref = _resource_ref(
        provider_id="microsoft_graph",
        profile_ref=profile_ref,
        operation_id=operation_id,
        target=target,
    )
    request_id = str(uuid4())
    operation_principal = IntegrationPrincipal(
        issuer=principal.issuer,
        subject=principal.subject,
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        allowed_operation_ids=frozenset({operation_id}),
    )
    dispatcher = services.connector_operation_dispatcher
    prepared = dispatcher.prepare_connection_operation(
        principal=operation_principal,
        connection=connection,
        provider_id="microsoft_graph",
        profile_ref=profile_ref,
        operation_id=operation_id,
        resource_ref=resource_ref,
        arguments=selected,
        request_id=request_id,
    )
    if prepared.is_mutating:
        raise OfficeSetupError("office_setup_discovery_must_be_read_only")
    authority = services.connector_grant_authority
    verifier = services.connector_grant_verifier
    if authority is None or verifier is None:
        raise OfficeSetupError("office_graph_directory_authority_unavailable")
    arguments_digest = bytes.fromhex(digest_arguments(prepared.arguments))
    grant_bytes = authority.authorize_connector_operation(
        workspace_id=prepared.expected_workspace_id,
        principal_issuer=operation_principal.issuer,
        principal_subject=operation_principal.subject,
        connection_ref=prepared.connection_ref,
        provider_id=prepared.provider_id,
        profile_ref=prepared.profile_ref,
        operation_id=prepared.operation_id,
        resource_ref=prepared.resource_ref,
        arguments_digest_sha256=arguments_digest,
        request_id=prepared.request_id,
    )
    expected = {
        "request_id": request_id,
        "organization_id": prepared.expected_organization_id,
        "workspace_id": prepared.expected_workspace_id,
        "principal_issuer": operation_principal.issuer,
        "principal_subject": operation_principal.subject,
        "connection_ref": prepared.connection_ref,
        "provider_id": prepared.provider_id,
        "profile_ref": prepared.profile_ref,
        "operation_id": prepared.operation_id,
        "resource_ref": prepared.resource_ref,
        "arguments_digest_sha256": arguments_digest,
    }
    verifier.validate_authority_response(grant_bytes, expected=expected)
    claims = verifier.consume(grant_bytes, expected=expected)
    try:
        result = dispatcher.invoke(
            prepared,
            principal=operation_principal,
            claims=claims,
        )
    except Exception as exc:
        raise OfficeSetupError("office_graph_provider_read_failed") from exc
    if not isinstance(result, Mapping):
        raise OfficeSetupError("office_graph_provider_response_invalid")
    if result.get("status") in {"UNKNOWN", "FAILED", "REJECTED"}:
        raise OfficeSetupError("office_graph_provider_read_failed")
    return dict(result)


def _current_graph_connection_scope(
    services: Any,
    *,
    principal: IntegrationPrincipal,
    connection: Any,
    profile_ref: str,
    operation_id: str,
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Read the live owner profile before preparing a setup discovery operation."""

    if operation_id not in _RESOURCE_OPERATIONS.values():
        raise OfficeSetupError("office_graph_discovery_operation_invalid")
    registry = services.authorization_profile_registry
    host_profile = (
        registry.settings.profiles.get(connection.binding_ref or "")
        if registry is not None
        else None
    )
    if (
        host_profile is None
        or host_profile.provider != "microsoft_graph"
        or host_profile.microsoft_graph_office_v2 is None
        or connection.account_link_ref != profile_ref
        or connection.access_mode != "actor_owned"
        or connection.target_ref is not None
    ):
        raise OfficeSetupError("office_graph_connection_scope_invalid")
    try:
        response = services.accounts.list_provider_profiles(principal)
    except Exception as exc:
        raise OfficeSetupError("office_graph_profile_read_failed") from exc
    rows = response.get("profiles") if isinstance(response, Mapping) else None
    matches = (
        [
            row
            for row in rows
            if isinstance(row, Mapping)
            and row.get("profile_ref") == profile_ref
            and row.get("provider") == "microsoft_graph"
        ]
        if isinstance(rows, list)
        else []
    )
    if len(matches) != 1:
        raise OfficeSetupError("office_graph_profile_readback_invalid")
    row = dict(matches[0])
    try:
        scope = validate_profile_identity(row, profile_ref=profile_ref, principal=principal)
        scope = validate_microsoft_graph_office_v2_scope(host_profile, scope, principal)
    except (PermissionError, ValueError) as exc:
        raise OfficeSetupError("office_graph_profile_scope_mismatch") from exc
    if row.get("auth_status") != "healthy":
        raise OfficeSetupError(
            "office_graph_authorization_required", state="AUTHORIZATION_REQUIRED"
        )
    return connection, row, scope


def _discovery_item(resource_type: str, value: object) -> dict[str, str]:
    """Project only target selector and display metadata, never content or tokens."""

    if not isinstance(value, Mapping):
        raise OfficeSetupError("office_graph_discovery_item_invalid")
    identifiers = {
        "planner_plans": ("plan_id", "title", "planner_plan"),
        "todo_lists": ("task_list_id", "display_name", "todo_list"),
        "sharepoint_drives": ("drive_id", "name", "sharepoint_drive"),
        "calendars": ("calendar_id", "name", "calendar"),
        "mail_folders": ("folder_id", "display_name", "mail_folder"),
        "freebusy_subjects": ("freebusy_subject", "display_name", "person"),
    }
    fields = identifiers.get(resource_type)
    if fields is None:
        raise OfficeSetupError("office_graph_resource_type_invalid")
    id_field, label_field, kind = fields
    identifier = value.get(id_field)
    label = value.get(label_field)
    if not isinstance(identifier, str) or not identifier or len(identifier) > 512:
        raise OfficeSetupError("office_graph_discovery_item_invalid")
    if not isinstance(label, str) or not label or len(label) > 255:
        label = identifier
    result = {"id": identifier, "displayName": label, "kind": kind}
    if resource_type == "sharepoint_drives":
        site_id = value.get("site_id")
        if not isinstance(site_id, str) or len(site_id) > 600:
            raise OfficeSetupError("office_graph_discovery_item_invalid")
        result["siteId"] = site_id
        drive_type = value.get("drive_type")
        if isinstance(drive_type, str) and len(drive_type) <= 40:
            result["driveType"] = drive_type
    return result


def _target_selection(value: object) -> dict[str, list[str]]:
    """Validate the exact resource-ID selection shape; permission flags are absent."""

    item = _object(
        value, required=set(_TARGET_FIELDS), optional=set(), label="Office target selection"
    )
    selected: dict[str, list[str]] = {}
    for field in sorted(_TARGET_FIELDS):
        raw = item[field]
        maximum = 100
        if not isinstance(raw, list) or len(raw) > maximum:
            raise OfficeSetupError("office_graph_target_selection_invalid")
        if any(
            not isinstance(entry, str)
            or not entry
            or entry.strip() != entry
            or len(entry) > 512
            or "*" in entry
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in entry)
            for entry in raw
        ):
            raise OfficeSetupError("office_graph_target_selection_invalid")
        if len(raw) != len(set(raw)):
            raise OfficeSetupError("office_graph_target_selection_duplicate")
        selected[field] = list(raw)
    return selected


def _host_allowlist(host_profile: Any, resource_type: str) -> set[str]:
    """Return only a non-empty root-owned target allowlist for one discovery category."""

    office = host_profile.microsoft_graph_office_v2
    field = {
        "planner_plans": "plannerPlanIds",
        "todo_lists": "toDoTaskListIds",
        "sharepoint_drives": "sharePointDriveIds",
        "calendars": "calendarIds",
        "mail_folders": "mailFolderIds",
        "freebusy_subjects": "freebusySubjects",
    }.get(resource_type)
    return set(office.targets[field]) if field is not None else set()


def _same_target_scope(left: object, right: Mapping[str, Any]) -> bool:
    """Compare one provider's exact canonical target scope for CAS reconciliation."""

    try:
        return validate_profile_scope(left) == validate_profile_scope(right)
    except ValueError:
        return False


def _epoch_text(value: object) -> str | None:
    """Serialize one validated Account Center Unix expiry as UTC text."""

    from datetime import UTC, datetime

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise OfficeSetupError("account_center_expiry_invalid")
    return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")


def _operator_config(path: Path) -> dict[str, Any]:
    """Read the owner-only Office operator config without logging its contents."""

    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or not 0 < info.st_size <= _MAX_PRIVATE_CONFIG_BYTES
        ):
            raise ValueError("private owner file is not safe")
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise OfficeSetupError("office_operator_config_invalid") from exc
    item = _object(
        value,
        required={"schemaVersion", "actor", "bindingRef", "profileIdempotencyKey"},
        optional=set(),
        label="Office operator config",
    )
    if item["schemaVersion"] != 1 or isinstance(item["schemaVersion"], bool):
        raise OfficeSetupError("office_operator_config_version_invalid")
    actor = _object(
        item["actor"],
        required={"issuer", "subject", "organizationId", "workspaceId"},
        optional=set(),
        label="Office operator actor",
    )
    for key in ("issuer", "subject", "organizationId", "workspaceId"):
        actor[key] = _bounded_text(actor[key], key, minimum=1, maximum=1024)
    try:
        UUID(actor["subject"])
        UUID(actor["workspaceId"])
    except ValueError as exc:
        raise OfficeSetupError("office_operator_identity_invalid") from exc
    item["actor"] = actor
    item["bindingRef"] = _bounded_text(item["bindingRef"], "bindingRef", minimum=1, maximum=300)
    item["profileIdempotencyKey"] = _bounded_text(
        item["profileIdempotencyKey"], "profileIdempotencyKey", minimum=16, maximum=200
    )
    return item


def _request_object(value: object) -> dict[str, Any]:
    """Validate one bounded, closed JSON request from the loopback setup page."""

    if isinstance(value, Mapping):
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise OfficeSetupError("office_setup_request_too_large")
        return dict(value)
    raise OfficeSetupError("office_setup_request_invalid")


def _read_request_stdin(stream: Any) -> dict[str, Any]:
    """Read one small JSON object from stdin, keeping authorization codes off argv."""

    raw = stream.buffer.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        raise OfficeSetupError("office_setup_request_too_large")
    try:
        value = json.loads(raw or b"{}", object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as exc:
        raise OfficeSetupError("office_setup_request_invalid") from exc
    return _request_object(value)


def _object(
    value: object,
    *,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or set(value) - required - optional
    ):
        raise OfficeSetupError(f"{label.replace(' ', '_').lower()}_invalid")
    return dict(value)


def _exact_fields(value: Mapping[str, Any], *, required: set[str], optional: set[str]) -> None:
    if not required <= set(value) or set(value) - required - optional:
        raise OfficeSetupError("office_setup_request_fields_invalid")


def _bounded_text(value: object, label: str, *, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or value.strip() != value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise OfficeSetupError(f"office_setup_{label}_invalid")
    return value


def _uuid_text(value: object, label: str) -> str:
    try:
        parsed = UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise OfficeSetupError(f"office_setup_{label}_invalid") from exc
    if str(parsed) != value:
        raise OfficeSetupError(f"office_setup_{label}_invalid")
    return str(parsed)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result
