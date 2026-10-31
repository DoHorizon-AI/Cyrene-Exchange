"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 microsoft_graph.py                                              │
│  Module: cyrene_exchange_product.integrations.microsoft_graph       │
│  Role: Validate Account Center scopes and fixed Graph targets.       │
│                                                                      │
│  模块职责：校验 Account Center Graph scope 与固定资源目标。             │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.microsoft_identity import require_microsoft_profile_actor

_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_PLANNER_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_OPAQUE_RESOURCE_ID = re.compile(r"[A-Za-z0-9._!~+=-]{1,512}\Z")
_SITE_ID = re.compile(r"[A-Za-z0-9.-]{1,255},[0-9a-fA-F-]{36},[0-9a-fA-F-]{36}\Z")
_PAGE_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,12000}={0,2}\Z")
_PROFILE_SCOPE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OFFICE_V2_REDIRECT_URI = "http://localhost:52191/oauth/callback"

_V1_PROFILE_SCOPE_FIELDS = frozenset({"tenant_id", "planner", "sharepoint"})
_V2_PROFILE_SCOPE_FIELDS = frozenset(
    {
        "schema_version",
        "tenant_id",
        "workspace_id",
        "planner",
        "sharepoint",
        "todo",
        "calendar",
        "mail",
    }
)

PLANNER_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.planner.plan.get",
        "microsoft_graph.planner.plans.list",
        "microsoft_graph.planner.tasks.list",
        "microsoft_graph.planner.task.get",
    }
)
PLANNER_WRITE_OPERATIONS = frozenset(
    {
        "microsoft_graph.planner.task.create",
        "microsoft_graph.planner.task.update",
    }
)
SHAREPOINT_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.sharepoint.site.get",
        "microsoft_graph.sharepoint.list.get",
        "microsoft_graph.sharepoint.list.items.delta",
    }
)
TODO_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.todo.lists.list",
        "microsoft_graph.todo.tasks.list",
        "microsoft_graph.todo.task.get",
    }
)
TODO_WRITE_OPERATIONS = frozenset(
    {
        "microsoft_graph.todo.task.create",
        "microsoft_graph.todo.task.update",
        "microsoft_graph.todo.task.delete",
    }
)
CALENDAR_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.calendar.calendars.list",
        "microsoft_graph.calendar.events.list",
        "microsoft_graph.calendar.event.get",
        "microsoft_graph.calendar.freebusy.get",
    }
)
CALENDAR_WRITE_OPERATIONS = frozenset(
    {
        "microsoft_graph.calendar.event.create",
        "microsoft_graph.calendar.event.update",
        "microsoft_graph.calendar.event.delete",
    }
)
MAIL_FOLDER_READ_OPERATIONS = frozenset({"microsoft_graph.mail.folders.list"})
MAIL_MESSAGE_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.mail.messages.list",
        "microsoft_graph.mail.message.get",
    }
)
MAIL_DRAFT_READ_OPERATIONS = frozenset({"microsoft_graph.mail.drafts.list"})
MAIL_DRAFT_WRITE_OPERATIONS = frozenset(
    {
        "microsoft_graph.mail.draft.create",
        "microsoft_graph.mail.draft.update",
        "microsoft_graph.mail.draft.delete",
        "microsoft_graph.mail.message.send",
    }
)
MAIL_OPERATIONS = (
    MAIL_FOLDER_READ_OPERATIONS
    | MAIL_MESSAGE_READ_OPERATIONS
    | MAIL_DRAFT_READ_OPERATIONS
    | MAIL_DRAFT_WRITE_OPERATIONS
)
MAIL_MUTATING_OPERATIONS = MAIL_DRAFT_WRITE_OPERATIONS
SHAREPOINT_V2_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.sharepoint.drives.list",
        "microsoft_graph.sharepoint.drive.items.list",
    }
)
V2_GRAPH_OPERATIONS = (
    {"microsoft_graph.planner.plans.list"}
    | TODO_READ_OPERATIONS
    | TODO_WRITE_OPERATIONS
    | CALENDAR_READ_OPERATIONS
    | CALENDAR_WRITE_OPERATIONS
    | MAIL_OPERATIONS
    | SHAREPOINT_V2_READ_OPERATIONS
)
GRAPH_OPERATIONS = (
    PLANNER_READ_OPERATIONS
    | PLANNER_WRITE_OPERATIONS
    | SHAREPOINT_READ_OPERATIONS
    | TODO_READ_OPERATIONS
    | TODO_WRITE_OPERATIONS
    | CALENDAR_READ_OPERATIONS
    | CALENDAR_WRITE_OPERATIONS
    | MAIL_OPERATIONS
    | SHAREPOINT_V2_READ_OPERATIONS
)
GRAPH_MUTATING_OPERATIONS = (
    PLANNER_WRITE_OPERATIONS
    | TODO_WRITE_OPERATIONS
    | CALENDAR_WRITE_OPERATIONS
    | MAIL_MUTATING_OPERATIONS
)


def validate_profile_scope(value: object) -> dict[str, Any]:
    """Validate the exact legacy or Office v2 non-secret scope from Account Center.

    v1 remains a closed legacy contract. v2 adds actor workspace and selected
    To Do, Calendar, and SharePoint drive targets while retaining the same
    tenant and actor-owned identity checks. 中文：保留v1严格校验，v2增加显式目标范围。
    """

    if not isinstance(value, Mapping):
        raise ValueError("Account Center returned an invalid Microsoft Graph profile scope")
    fields = set(value)
    if fields == _V1_PROFILE_SCOPE_FIELDS:
        return _validate_v1_profile_scope(value)
    if fields == _V2_PROFILE_SCOPE_FIELDS:
        return _validate_v2_profile_scope(value)
    raise ValueError("Account Center returned an invalid Microsoft Graph profile scope")


def _validate_v1_profile_scope(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the unchanged schema v1 target scope."""

    tenant_id = value.get("tenant_id")
    if not isinstance(tenant_id, str) or _GUID.fullmatch(tenant_id) is None:
        raise ValueError("Account Center returned an invalid Microsoft Graph tenant")

    planner = value.get("planner")
    if not isinstance(planner, Mapping) or set(planner) != {
        "plan_ids",
        "tasks_read",
        "tasks_write",
    }:
        raise ValueError("Account Center returned an invalid Planner profile scope")
    plan_ids = _unique_planner_ids(planner.get("plan_ids"), "Planner plan IDs", maximum=100)
    tasks_read = planner.get("tasks_read")
    tasks_write = planner.get("tasks_write")
    if not isinstance(tasks_read, bool) or not isinstance(tasks_write, bool):
        raise ValueError("Account Center returned invalid Planner permission flags")
    if not plan_ids or not tasks_read or (tasks_write and not tasks_read):
        raise ValueError("Account Center returned an incomplete Planner consent scope")

    sharepoint = value.get("sharepoint")
    if not isinstance(sharepoint, Mapping) or set(sharepoint) != {
        "enabled",
        "site_id",
        "list_ids",
    }:
        raise ValueError("Account Center returned an invalid SharePoint profile scope")
    enabled = sharepoint.get("enabled")
    site_id = sharepoint.get("site_id")
    raw_list_ids = sharepoint.get("list_ids")
    if not isinstance(raw_list_ids, list) or len(raw_list_ids) > 100:
        raise ValueError("Account Center returned invalid SharePoint list IDs")
    list_ids = [validate_sharepoint_list_id(item) for item in raw_list_ids]
    if len(list_ids) != len(set(list_ids)):
        raise ValueError("Account Center returned duplicate SharePoint list IDs")
    if not isinstance(enabled, bool):
        raise ValueError("Account Center returned an invalid SharePoint permission flag")
    if enabled:
        if not isinstance(site_id, str) or not is_valid_sharepoint_site_id(site_id) or not list_ids:
            raise ValueError("Account Center returned an incomplete selected SharePoint scope")
    elif site_id is not None or list_ids:
        raise ValueError("Account Center returned SharePoint targets while access is disabled")

    return {
        "tenant_id": tenant_id.lower(),
        "planner": {
            "plan_ids": plan_ids,
            "tasks_read": tasks_read,
            "tasks_write": tasks_write,
        },
        "sharepoint": {"enabled": enabled, "site_id": site_id, "list_ids": list_ids},
    }


def _validate_v2_profile_scope(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate exact selected Office resources and per-feature grants for v2."""

    schema_version = value.get("schema_version")
    tenant_id = _canonical_uuid(value.get("tenant_id"), "Microsoft Graph tenant")
    workspace_id = _canonical_uuid(value.get("workspace_id"), "Microsoft Graph workspace")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 2
    ):
        raise ValueError("Account Center returned an unsupported Microsoft Graph scope version")

    planner_value = value.get("planner")
    planner = _validate_planner_scope(planner_value, allow_disabled=True)
    sharepoint_value = value.get("sharepoint")
    sharepoint = _validate_sharepoint_v2_scope(sharepoint_value)
    todo = _validate_todo_scope(value.get("todo"))
    calendar = _validate_calendar_scope(value.get("calendar"))
    mail = _validate_mail_scope(value.get("mail"))

    return {
        "schema_version": 2,
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "planner": planner,
        "sharepoint": sharepoint,
        "todo": todo,
        "calendar": calendar,
        "mail": mail,
    }


def _validate_planner_scope(value: object, *, allow_disabled: bool) -> dict[str, Any]:
    """Normalize the Planner v1 shape and optionally permit a disabled v2 feature."""

    planner = value
    if not isinstance(planner, Mapping) or set(planner) != {
        "plan_ids",
        "tasks_read",
        "tasks_write",
    }:
        raise ValueError("Account Center returned an invalid Planner profile scope")
    plan_ids = _unique_planner_ids(planner.get("plan_ids"), "Planner plan IDs", maximum=100)
    tasks_read = planner.get("tasks_read")
    tasks_write = planner.get("tasks_write")
    if not isinstance(tasks_read, bool) or not isinstance(tasks_write, bool):
        raise ValueError("Account Center returned invalid Planner permission flags")
    if tasks_write and not tasks_read:
        raise ValueError("Account Center returned an incomplete Planner consent scope")
    if plan_ids and not tasks_read:
        raise ValueError("Account Center returned Planner targets without read permission")
    if not allow_disabled and (not plan_ids or not tasks_read):
        raise ValueError("Account Center returned an incomplete Planner consent scope")
    return {"plan_ids": plan_ids, "tasks_read": tasks_read, "tasks_write": tasks_write}


def _validate_sharepoint_v2_scope(value: object) -> dict[str, Any]:
    """Require the v2 SharePoint profile to select only metadata targets."""

    if not isinstance(value, Mapping) or set(value) != {
        "enabled",
        "site_id",
        "list_ids",
        "drive_ids",
        "metadata_read",
        "content_read",
    }:
        raise ValueError("Account Center returned an invalid SharePoint profile scope")
    enabled = value.get("enabled")
    metadata_read = value.get("metadata_read")
    content_read = value.get("content_read")
    raw_list_ids = value.get("list_ids")
    raw_drive_ids = value.get("drive_ids")
    if not isinstance(enabled, bool) or not isinstance(metadata_read, bool):
        raise ValueError("Account Center returned invalid SharePoint permission flags")
    if content_read is not False:
        raise ValueError("SharePoint content reads are disabled for this Exchange scope")
    list_ids = _unique_sharepoint_ids(raw_list_ids, "SharePoint list IDs")
    drive_ids = _unique_resource_ids(raw_drive_ids, "SharePoint drive IDs")
    site_id = value.get("site_id")
    if enabled:
        if (
            not metadata_read
            or not isinstance(site_id, str)
            or not is_valid_sharepoint_site_id(site_id)
        ):
            raise ValueError("Account Center returned an incomplete selected SharePoint scope")
    elif site_id is not None or list_ids or drive_ids or metadata_read:
        raise ValueError("Account Center returned SharePoint targets while access is disabled")
    return {
        "enabled": enabled,
        "site_id": site_id,
        "list_ids": list_ids,
        "drive_ids": drive_ids,
        "metadata_read": metadata_read,
        "content_read": False,
    }


def _validate_todo_scope(value: object) -> dict[str, Any]:
    """Validate the actor-owned To Do list and task permissions."""

    if not isinstance(value, Mapping) or set(value) != {
        "enabled",
        "task_list_ids",
        "tasks_read",
        "tasks_write",
    }:
        raise ValueError("Account Center returned an invalid To Do profile scope")
    enabled = value.get("enabled")
    tasks_read = value.get("tasks_read")
    tasks_write = value.get("tasks_write")
    list_ids = _unique_resource_ids(value.get("task_list_ids"), "To Do task list IDs")
    if not all(isinstance(flag, bool) for flag in (enabled, tasks_read, tasks_write)):
        raise ValueError("Account Center returned invalid To Do permission flags")
    if tasks_write and not tasks_read:
        raise ValueError("Account Center returned To Do write permission without read permission")
    if enabled:
        if not tasks_read:
            raise ValueError("Account Center returned an incomplete To Do scope")
    elif list_ids or tasks_read or tasks_write:
        raise ValueError("Account Center returned To Do targets while access is disabled")
    return {
        "enabled": enabled,
        "task_list_ids": list_ids,
        "tasks_read": tasks_read,
        "tasks_write": tasks_write,
    }


def _validate_calendar_scope(value: object) -> dict[str, Any]:
    """Validate calendar IDs, event permissions, and exact free/busy subjects."""

    if not isinstance(value, Mapping) or set(value) != {
        "enabled",
        "calendar_ids",
        "events_read",
        "events_write",
        "freebusy_read",
        "freebusy_subjects",
        "attendees_write",
    }:
        raise ValueError("Account Center returned an invalid Calendar profile scope")
    flags = {
        name: value.get(name)
        for name in ("enabled", "events_read", "events_write", "freebusy_read", "attendees_write")
    }
    if not all(isinstance(flag, bool) for flag in flags.values()):
        raise ValueError("Account Center returned invalid Calendar permission flags")
    calendar_ids = _unique_resource_ids(value.get("calendar_ids"), "Calendar IDs")
    subjects = _validate_subjects(value.get("freebusy_subjects"))
    if flags["attendees_write"]:
        raise ValueError("Calendar attendee writes are disabled for this Exchange delivery")
    if flags["enabled"]:
        if not any(flags[name] for name in ("events_read", "events_write", "freebusy_read")):
            raise ValueError("Account Center returned an enabled Calendar with no capability")
        if flags["freebusy_read"] and not subjects:
            raise ValueError(
                "Account Center returned free/busy permission without selected subjects"
            )
    elif (
        calendar_ids
        or subjects
        or any(
            flags[name]
            for name in ("events_read", "events_write", "freebusy_read", "attendees_write")
        )
    ):
        raise ValueError("Account Center returned Calendar targets while access is disabled")
    return {
        "enabled": flags["enabled"],
        "calendar_ids": calendar_ids,
        "events_read": flags["events_read"],
        "events_write": flags["events_write"],
        "freebusy_read": flags["freebusy_read"],
        "freebusy_subjects": subjects,
        "attendees_write": flags["attendees_write"],
    }


def _validate_mail_scope(value: object) -> dict[str, Any]:
    """Validate the v2 Mail schema while always excluding message body reads."""

    if not isinstance(value, Mapping) or set(value) != {
        "enabled",
        "folder_ids",
        "metadata_read",
        "body_read",
        "drafts_write",
        "send_enabled",
    }:
        raise ValueError("Account Center returned an invalid Mail profile scope")
    flags = {
        name: value.get(name)
        for name in ("enabled", "metadata_read", "body_read", "drafts_write", "send_enabled")
    }
    if not all(isinstance(flag, bool) for flag in flags.values()):
        raise ValueError("Account Center returned invalid Mail permission flags")
    if flags["body_read"]:
        raise ValueError("Microsoft Graph Mail body reads are disabled for this Exchange delivery")
    folder_ids = _unique_resource_ids(value.get("folder_ids"), "Mail folder IDs")
    if flags["enabled"]:
        if not any(flags[name] for name in ("metadata_read", "drafts_write", "send_enabled")):
            raise ValueError("Account Center returned an enabled Mail profile without a capability")
        if folder_ids and not flags["metadata_read"]:
            raise ValueError("Account Center returned Mail folder targets without metadata access")
    elif folder_ids or any(
        flags[name] for name in ("metadata_read", "drafts_write", "send_enabled")
    ):
        raise ValueError("Account Center returned Mail targets while access is disabled")
    return {
        "enabled": flags["enabled"],
        "folder_ids": folder_ids,
        "metadata_read": flags["metadata_read"],
        "body_read": False,
        "drafts_write": flags["drafts_write"],
        "send_enabled": flags["send_enabled"],
    }


def required_oauth_scopes(profile_scope: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the exact delegated OAuth scopes required by a validated profile."""

    scope = validate_profile_scope(profile_scope)
    required = set(required_graph_permissions(scope))
    if scope.get("schema_version", 1) == 1:
        return tuple(sorted(required))
    return tuple(sorted((*required, "offline_access")))


def required_graph_permissions(profile_scope: Mapping[str, Any]) -> tuple[str, ...]:
    """Return only Graph resource permissions persisted in Account Center metadata."""

    scope = validate_profile_scope(profile_scope)
    required = {"User.Read"}
    if scope.get("schema_version", 1) == 1:
        required.add("Tasks.Read")
        if scope["planner"]["tasks_write"]:
            required.add("Tasks.ReadWrite")
        if scope["sharepoint"]["enabled"]:
            required.add("Sites.Selected")
        return tuple(sorted(required))

    planner = scope["planner"]
    todo = scope["todo"]
    sharepoint = scope["sharepoint"]
    calendar = scope["calendar"]
    if planner["tasks_write"] or todo["tasks_write"]:
        required.add("Tasks.ReadWrite")
    elif planner["tasks_read"] or todo["tasks_read"]:
        required.add("Tasks.Read")
    if sharepoint["enabled"]:
        required.add("Sites.Selected")
    if calendar["events_write"]:
        required.add("Calendars.ReadWrite")
    elif calendar["events_read"] or calendar["freebusy_read"]:
        required.add("Calendars.ReadBasic")
    mail = scope["mail"]
    if mail["drafts_write"]:
        required.add("Mail.ReadWrite")
    elif mail["metadata_read"] or mail["send_enabled"]:
        # Sending an existing draft requires a metadata preflight. ReadBasic is
        # the narrowest delegated permission when draft writes are not enabled.
        required.add("Mail.ReadBasic")
    if mail["send_enabled"]:
        required.add("Mail.Send")
    return tuple(sorted(required))


def validate_profile_identity(
    row: Mapping[str, Any],
    *,
    profile_ref: str,
    principal: Any | None = None,
) -> dict[str, Any]:
    """Require the immutable Graph identity to agree with its Account Center scope."""

    external_subject = row.get("external_subject")
    identity_ref = row.get("identity_ref")
    scope = validate_profile_scope(row.get("target_scope"))
    if (
        row.get("profile_ref") != profile_ref
        or row.get("provider") != "microsoft_graph"
        or row.get("auth_mode") != "delegated_oauth"
        or row.get("access_mode", "actor_owned") != "actor_owned"
        or not isinstance(external_subject, str)
        or not isinstance(identity_ref, str)
        or external_subject != identity_ref
    ):
        raise ValueError("Account Center returned a mismatched Microsoft Graph identity")
    identity_parts = external_subject.split(":", maxsplit=1)
    if (
        len(identity_parts) != 2
        or identity_parts[0] != scope["tenant_id"]
        or _GUID.fullmatch(identity_parts[1]) is None
    ):
        raise ValueError("Account Center returned an invalid Microsoft Graph subject")
    try:
        canonical_object_id = str(UUID(identity_parts[1]))
    except ValueError as exc:
        raise ValueError("Account Center returned an invalid Microsoft Graph object ID") from exc
    if identity_parts[1] != canonical_object_id:
        raise ValueError("Account Center returned a non-canonical Microsoft Graph object ID")
    if principal is not None:
        require_microsoft_profile_actor(
            principal,
            external_subject=external_subject,
            tenant_id=scope["tenant_id"],
        )
    if scope.get("schema_version") == 2:
        workspace_id = scope["workspace_id"]
        row_workspace_id = row.get("workspace_id")
        if row_workspace_id is not None and row_workspace_id != workspace_id:
            raise ValueError(
                "Account Center Microsoft Graph profile workspace does not match scope"
            )
        if principal is not None and getattr(principal, "workspace_id", None) != workspace_id:
            raise ValueError("Microsoft Graph profile belongs to another workspace")
    oauth_scopes = row.get("oauth_scopes")
    expected_oauth_scopes = set(required_graph_permissions(scope))
    if (
        not isinstance(oauth_scopes, list)
        or any(not isinstance(item, str) for item in oauth_scopes)
        or len(oauth_scopes) != len(set(oauth_scopes))
        or set(oauth_scopes) != expected_oauth_scopes
    ):
        raise ValueError("Account Center returned unsupported Microsoft Graph OAuth scopes")
    refresh_expires_at = row.get("refresh_expires_at")
    if refresh_expires_at is not None and (
        isinstance(refresh_expires_at, bool)
        or not isinstance(refresh_expires_at, int)
        or refresh_expires_at <= 0
    ):
        raise ValueError("Account Center returned an invalid Microsoft Graph refresh expiry")
    expires_at = row.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
        raise ValueError("Account Center returned an invalid Microsoft Graph expiry")
    return scope


def public_profile_scope(value: object) -> dict[str, Any]:
    """Return the stable camelCase HTTP projection of a validated Graph scope."""

    scope = validate_profile_scope(value)
    if scope.get("schema_version") == 2:
        return {
            "schemaVersion": 2,
            "tenantId": scope["tenant_id"],
            "workspaceId": scope["workspace_id"],
            "planner": {
                "planIds": list(scope["planner"]["plan_ids"]),
                "tasksRead": scope["planner"]["tasks_read"],
                "tasksWrite": scope["planner"]["tasks_write"],
            },
            "sharepoint": {
                "enabled": scope["sharepoint"]["enabled"],
                "siteId": scope["sharepoint"]["site_id"],
                "listIds": list(scope["sharepoint"]["list_ids"]),
                "driveIds": list(scope["sharepoint"]["drive_ids"]),
                "metadataRead": scope["sharepoint"]["metadata_read"],
                "contentRead": False,
            },
            "todo": {
                "enabled": scope["todo"]["enabled"],
                "taskListIds": list(scope["todo"]["task_list_ids"]),
                "tasksRead": scope["todo"]["tasks_read"],
                "tasksWrite": scope["todo"]["tasks_write"],
            },
            "calendar": {
                "enabled": scope["calendar"]["enabled"],
                "calendarIds": list(scope["calendar"]["calendar_ids"]),
                "eventsRead": scope["calendar"]["events_read"],
                "eventsWrite": scope["calendar"]["events_write"],
                "freebusyRead": scope["calendar"]["freebusy_read"],
                "freebusySubjects": list(scope["calendar"]["freebusy_subjects"]),
                "attendeesWrite": scope["calendar"]["attendees_write"],
            },
            "mail": {
                "enabled": scope["mail"]["enabled"],
                "folderIds": list(scope["mail"]["folder_ids"]),
                "metadataRead": scope["mail"]["metadata_read"],
                "bodyRead": False,
                "draftsWrite": scope["mail"]["drafts_write"],
                "sendEnabled": scope["mail"]["send_enabled"],
            },
        }
    return {
        "tenantId": scope["tenant_id"],
        "planner": {
            "planIds": list(scope["planner"]["plan_ids"]),
            "tasksRead": scope["planner"]["tasks_read"],
            "tasksWrite": scope["planner"]["tasks_write"],
        },
        "sharepoint": {
            "enabled": scope["sharepoint"]["enabled"],
            "siteId": scope["sharepoint"]["site_id"],
            "listIds": list(scope["sharepoint"]["list_ids"]),
        },
    }


def profile_scope_metadata(
    row: Mapping[str, Any],
    scope: Mapping[str, Any],
) -> dict[str, Any]:
    """Project non-secret feature and expiry facts for readiness and auth health."""

    normalized = validate_profile_scope(scope)
    schema_version = int(normalized.get("schema_version", 1))
    planner = normalized["planner"]
    sharepoint = normalized["sharepoint"]
    enabled_features: list[str] = []
    target_ref_count = len(planner["plan_ids"])
    if planner["tasks_read"]:
        enabled_features.append("planner_read")
    if planner["tasks_write"]:
        enabled_features.append("planner_write")
    if schema_version == 2:
        todo = normalized["todo"]
        calendar = normalized["calendar"]
        mail = normalized["mail"]
        if todo["enabled"]:
            enabled_features.append("todo")
        if calendar["enabled"]:
            enabled_features.append("calendar")
        target_ref_count += len(todo["task_list_ids"]) + len(calendar["calendar_ids"])
        target_ref_count += len(calendar["freebusy_subjects"])
        if sharepoint["enabled"]:
            enabled_features.append("sharepoint_drive_metadata")
            target_ref_count += len(sharepoint["list_ids"]) + len(sharepoint["drive_ids"])
        if mail["enabled"]:
            if mail["metadata_read"]:
                enabled_features.append("mail_metadata")
            if mail["drafts_write"]:
                enabled_features.append("mail_drafts")
            if mail["send_enabled"]:
                enabled_features.append("mail_send")
            target_ref_count += len(mail["folder_ids"])
    elif sharepoint["enabled"]:
        enabled_features.append("sharepoint_selected_metadata_read")
        target_ref_count += len(sharepoint["list_ids"])
    refresh_expires_at = row.get("refresh_expires_at")
    credential_expires_at = row.get("expires_at")
    auth_status = row.get("auth_status")
    reauth_required = auth_status in {"reauthorization_required", "revoked"} or (
        isinstance(refresh_expires_at, int)
        and not isinstance(refresh_expires_at, bool)
        and refresh_expires_at <= int(datetime.now(UTC).timestamp())
    )
    return {
        "scope_schema_version": schema_version,
        "enabled_features": enabled_features,
        "required_oauth_scopes": list(required_oauth_scopes(normalized)),
        "target_ref_count": target_ref_count,
        "credential_expires_at": credential_expires_at,
        "refresh_expires_at": refresh_expires_at,
        "reauth_required": reauth_required,
        "auth_status": auth_status if isinstance(auth_status, str) else "unknown",
        "reauth_reason_code": (
            "microsoft_graph_reauthorization_required" if reauth_required else None
        ),
    }


def target_for_operation(
    operation_id: str,
    arguments: Mapping[str, object],
    profile_scope: Mapping[str, Any],
) -> dict[str, object]:
    """Validate one fixed Graph operation and derive its scoped lease target."""

    scope = validate_profile_scope(profile_scope)
    tenant_id = scope["tenant_id"]
    if operation_id not in GRAPH_OPERATIONS:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_OPERATION_INVALID",
            title="Microsoft Graph operation is not enabled",
            detail="The requested Microsoft Graph operation is outside Exchange's fixed allowlist.",
            status=422,
            context={"reasonCode": "microsoft_graph_operation_not_allowlisted"},
        )
    if operation_id in V2_GRAPH_OPERATIONS and scope.get("schema_version") != 2:
        raise _permission_denied(
            "microsoft_graph_v2_scope_required",
            "This operation requires an actor-owned Microsoft Graph v2 profile.",
        )

    if operation_id in PLANNER_READ_OPERATIONS | PLANNER_WRITE_OPERATIONS:
        planner = scope["planner"]
        if operation_id in PLANNER_WRITE_OPERATIONS and not planner["tasks_write"]:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PERMISSION_DENIED",
                title="Planner write consent is required",
                detail="Explicitly authorize Tasks.ReadWrite for this Microsoft Graph profile.",
                status=403,
                context={"reasonCode": "planner_tasks_write_consent_required"},
            )
        if operation_id in PLANNER_READ_OPERATIONS and not planner["tasks_read"]:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PERMISSION_DENIED",
                title="Planner read consent is required",
                detail="The Microsoft Graph profile has no Tasks.Read consent.",
                status=403,
                context={"reasonCode": "planner_tasks_read_consent_required"},
            )
        _validate_planner_arguments(operation_id, arguments)
        if operation_id == "microsoft_graph.planner.plans.list":
            return {"tenant_id": tenant_id}
        plan_id = _planner_id(arguments.get("plan_id"), "plan_id")
        if plan_id not in planner["plan_ids"]:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="Planner plan is outside the linked profile scope",
                detail="Select a Planner plan explicitly linked to this actor-owned profile.",
                status=403,
                context={"reasonCode": "microsoft_graph_plan_scope_mismatch"},
            )
        target: dict[str, object] = {"tenant_id": tenant_id, "plan_id": plan_id}
        if operation_id in {
            "microsoft_graph.planner.task.get",
            "microsoft_graph.planner.task.update",
        }:
            target["task_id"] = _planner_id(arguments.get("task_id"), "task_id")
        elif operation_id == "microsoft_graph.planner.task.create":
            target["bucket_id"] = _planner_id(arguments.get("bucket_id"), "bucket_id")
        return target

    if (
        scope.get("schema_version") == 2
        and operation_id in TODO_READ_OPERATIONS | TODO_WRITE_OPERATIONS
    ):
        todo = scope["todo"]
        if not todo["enabled"] or not todo["tasks_read"]:
            raise _permission_denied(
                "todo_tasks_read_consent_required", "To Do read consent is required"
            )
        if operation_id in TODO_WRITE_OPERATIONS and not todo["tasks_write"]:
            raise _permission_denied(
                "todo_tasks_write_consent_required", "To Do write consent is required"
            )
        _validate_todo_arguments(operation_id, arguments)
        target = {"tenant_id": tenant_id}
        if operation_id == "microsoft_graph.todo.lists.list":
            target["task_list_ids"] = list(todo["task_list_ids"])
            return target
        task_list_id = _opaque_resource_id(arguments.get("task_list_id"), "task_list_id")
        if task_list_id not in todo["task_list_ids"]:
            raise _scope_forbidden(
                "microsoft_graph_todo_list_scope_mismatch",
                "To Do list is outside the linked profile scope",
            )
        target["task_list_id"] = task_list_id
        if operation_id in {
            "microsoft_graph.todo.task.get",
            "microsoft_graph.todo.task.update",
            "microsoft_graph.todo.task.delete",
        }:
            target["task_id"] = _opaque_resource_id(arguments.get("task_id"), "task_id")
        return target

    if (
        scope.get("schema_version") == 2
        and operation_id in CALENDAR_READ_OPERATIONS | CALENDAR_WRITE_OPERATIONS
    ):
        calendar = scope["calendar"]
        if not calendar["enabled"]:
            raise _permission_denied("calendar_feature_not_enabled", "Calendar access is disabled")
        if operation_id in CALENDAR_READ_OPERATIONS:
            if operation_id == "microsoft_graph.calendar.freebusy.get":
                if not calendar["freebusy_read"]:
                    raise _permission_denied(
                        "calendar_freebusy_consent_required", "Free/busy read consent is required"
                    )
            elif not calendar["events_read"]:
                raise _permission_denied(
                    "calendar_events_read_consent_required",
                    "Calendar event read consent is required",
                )
        if operation_id in CALENDAR_WRITE_OPERATIONS and not calendar["events_write"]:
            raise _permission_denied(
                "calendar_events_write_consent_required", "Calendar event write consent is required"
            )
        _validate_calendar_arguments(operation_id, arguments)
        target = {"tenant_id": tenant_id}
        if operation_id == "microsoft_graph.calendar.calendars.list":
            target["calendar_ids"] = list(calendar["calendar_ids"])
        elif operation_id == "microsoft_graph.calendar.freebusy.get":
            selected = arguments["schedules"]
            if not isinstance(selected, list):
                raise ValueError("schedules must be a list")
            selected_subjects = sorted({_validate_subject(item) for item in selected})
            if set(selected_subjects) - set(calendar["freebusy_subjects"]):
                raise _scope_forbidden(
                    "microsoft_graph_freebusy_subject_scope_mismatch",
                    "Free/busy subject is outside the linked profile scope",
                )
            target["schedule_ids"] = selected_subjects
        else:
            calendar_id = _opaque_resource_id(arguments.get("calendar_id"), "calendar_id")
            if calendar_id not in calendar["calendar_ids"]:
                raise _scope_forbidden(
                    "microsoft_graph_calendar_scope_mismatch",
                    "Calendar is outside the linked profile scope",
                )
            target["calendar_id"] = calendar_id
            if operation_id in {
                "microsoft_graph.calendar.event.get",
                "microsoft_graph.calendar.event.update",
                "microsoft_graph.calendar.event.delete",
            }:
                target["event_id"] = _opaque_resource_id(arguments.get("event_id"), "event_id")
            elif operation_id == "microsoft_graph.calendar.event.create":
                target["transaction_id"] = _canonical_uuid(
                    arguments.get("transaction_id"), "Calendar transaction_id"
                )
        return target

    if scope.get("schema_version") == 2 and operation_id in MAIL_OPERATIONS:
        mail = scope["mail"]
        if not mail["enabled"]:
            raise _permission_denied("mail_feature_not_enabled", "Mail access is disabled")
        _validate_mail_arguments(operation_id, arguments)
        if operation_id == "microsoft_graph.mail.folders.list":
            if not mail["metadata_read"]:
                raise _permission_denied(
                    "mail_metadata_read_consent_required",
                    "Mail metadata consent is required to discover folders",
                )
            return {"tenant_id": tenant_id}
        if operation_id in MAIL_MESSAGE_READ_OPERATIONS:
            if not mail["metadata_read"]:
                raise _permission_denied(
                    "mail_metadata_read_consent_required",
                    "Mail metadata consent is required",
                )
            folder_id = _opaque_resource_id(arguments.get("folder_id"), "folder_id")
            if folder_id not in mail["folder_ids"]:
                raise _scope_forbidden(
                    "microsoft_graph_mail_folder_scope_mismatch",
                    "Mail folder is outside the linked profile scope",
                )
            mail_target: dict[str, object] = {"tenant_id": tenant_id, "folder_id": folder_id}
            if operation_id == "microsoft_graph.mail.message.get":
                mail_target["message_id"] = _opaque_resource_id(
                    arguments.get("message_id"), "message_id"
                )
            return mail_target
        if operation_id in MAIL_DRAFT_READ_OPERATIONS:
            if not mail["drafts_write"]:
                raise _permission_denied(
                    "mail_draft_metadata_consent_required",
                    "Mail draft consent is required to list Drafts",
                )
            return {"tenant_id": tenant_id, "folder_id": "drafts"}
        if operation_id in MAIL_DRAFT_WRITE_OPERATIONS:
            if operation_id == "microsoft_graph.mail.message.send":
                if not mail["send_enabled"]:
                    raise _permission_denied(
                        "mail_send_consent_required", "Mail send consent is required"
                    )
                # The delegated permission derivation includes Mail.ReadBasic
                # for send-only profiles so the provider can preflight Drafts.
            elif not mail["drafts_write"]:
                raise _permission_denied(
                    "mail_draft_write_consent_required", "Mail draft write consent is required"
                )
            mail_target = {"tenant_id": tenant_id, "folder_id": "drafts"}
            if operation_id != "microsoft_graph.mail.draft.create":
                mail_target["message_id"] = _opaque_resource_id(
                    arguments.get("message_id"), "message_id"
                )
            return mail_target
        raise _permission_denied("mail_operation_not_enabled", "Mail operation is disabled")

    sharepoint = scope["sharepoint"]
    is_v2 = scope.get("schema_version") == 2
    if not sharepoint["enabled"] or (is_v2 and not sharepoint["metadata_read"]):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PERMISSION_DENIED",
            title="SharePoint selected-target consent is required",
            detail="Select a SharePoint site and list and complete the separate consent step.",
            status=403,
            context={"reasonCode": "sharepoint_selected_target_consent_required"},
        )
    site_id = arguments.get("site_id")
    if not is_valid_sharepoint_site_id(site_id):
        raise ValueError("site_id must be an exact compound SharePoint site ID")
    if site_id != sharepoint["site_id"]:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="SharePoint site is outside the linked profile scope",
            detail="Select only the SharePoint site recorded in this actor's profile.",
            status=403,
            context={"reasonCode": "microsoft_graph_site_scope_mismatch"},
        )
    _validate_sharepoint_arguments(operation_id, arguments)
    target = {"tenant_id": tenant_id, "site_id": site_id}
    if operation_id in SHAREPOINT_V2_READ_OPERATIONS:
        if not is_v2:
            raise _permission_denied(
                "sharepoint_drive_metadata_requires_scope_v2",
                "SharePoint drive metadata requires scope v2",
            )
        if operation_id == "microsoft_graph.sharepoint.drives.list":
            target["drive_ids"] = list(sharepoint["drive_ids"])
            return target
        drive_id = _opaque_resource_id(arguments.get("drive_id"), "drive_id")
        if drive_id not in sharepoint["drive_ids"]:
            raise _scope_forbidden(
                "microsoft_graph_drive_scope_mismatch",
                "SharePoint drive is outside the linked profile scope",
            )
        target["drive_id"] = drive_id
        parent_item_id = arguments.get("parent_item_id")
        if parent_item_id is not None:
            target["parent_item_id"] = _opaque_resource_id(parent_item_id, "parent_item_id")
        return target
    if operation_id != "microsoft_graph.sharepoint.site.get":
        list_id = validate_sharepoint_list_id(arguments.get("list_id"))
        if list_id not in sharepoint["list_ids"]:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="SharePoint list is outside the linked profile scope",
                detail="Select only a SharePoint list recorded in this actor's profile.",
                status=403,
                context={"reasonCode": "microsoft_graph_list_scope_mismatch"},
            )
        target["list_id"] = list_id
    return target


def _permission_denied(reason_code: str, detail: str) -> ExchangeProductError:
    """Build a sanitized permission error for one fixed Office feature gate."""

    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_PERMISSION_DENIED",
        title="Microsoft Graph permission is required",
        detail=detail,
        status=403,
        context={"reasonCode": reason_code},
    )


def _scope_forbidden(reason_code: str, detail: str) -> ExchangeProductError:
    """Build a sanitized error when a selected resource is outside its profile."""

    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
        title="Microsoft Graph target is outside the linked profile scope",
        detail=detail,
        status=403,
        context={"reasonCode": reason_code},
    )


def lease_arguments_for_operation(
    operation_id: str,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    """Remove exact resource IDs that Account Center binds in the lease target."""

    excluded = {
        "microsoft_graph.planner.plans.list": set(),
        "microsoft_graph.planner.plan.get": {"plan_id"},
        "microsoft_graph.planner.tasks.list": {"plan_id"},
        "microsoft_graph.planner.task.get": {"plan_id", "task_id"},
        "microsoft_graph.planner.task.create": {"plan_id", "bucket_id"},
        "microsoft_graph.planner.task.update": {"plan_id", "task_id"},
        "microsoft_graph.sharepoint.site.get": {"site_id"},
        "microsoft_graph.sharepoint.list.get": {"site_id", "list_id"},
        "microsoft_graph.sharepoint.list.items.delta": {"site_id", "list_id"},
        "microsoft_graph.todo.lists.list": set(),
        "microsoft_graph.todo.tasks.list": {"task_list_id"},
        "microsoft_graph.todo.task.get": {"task_list_id", "task_id"},
        "microsoft_graph.todo.task.create": {"task_list_id"},
        "microsoft_graph.todo.task.update": {"task_list_id", "task_id"},
        "microsoft_graph.todo.task.delete": {"task_list_id", "task_id"},
        "microsoft_graph.calendar.calendars.list": set(),
        "microsoft_graph.calendar.events.list": {"calendar_id"},
        "microsoft_graph.calendar.event.get": {"calendar_id", "event_id"},
        "microsoft_graph.calendar.event.create": {"calendar_id", "transaction_id"},
        "microsoft_graph.calendar.event.update": {"calendar_id", "event_id"},
        "microsoft_graph.calendar.event.delete": {"calendar_id", "event_id"},
        "microsoft_graph.calendar.freebusy.get": {"schedules"},
        "microsoft_graph.sharepoint.drives.list": {"site_id"},
        "microsoft_graph.sharepoint.drive.items.list": {
            "site_id",
            "drive_id",
        },
        "microsoft_graph.mail.folders.list": set(),
        "microsoft_graph.mail.messages.list": {"folder_id"},
        "microsoft_graph.mail.message.get": {"folder_id", "message_id"},
        "microsoft_graph.mail.drafts.list": set(),
        "microsoft_graph.mail.draft.create": set(),
        "microsoft_graph.mail.draft.update": {"message_id"},
        "microsoft_graph.mail.draft.delete": {"message_id"},
        "microsoft_graph.mail.message.send": {"message_id"},
    }.get(operation_id)
    if excluded is None or not isinstance(arguments, Mapping):
        raise ValueError("Microsoft Graph operation is outside the fixed lease digest map")
    return {key: value for key, value in arguments.items() if key not in excluded}


def validate_scope_digest(value: object, *, required: bool) -> str | None:
    """Validate the scope snapshot returned with one Account Center lease."""

    if value is None and not required:
        return None
    if not isinstance(value, str) or _PROFILE_SCOPE_SHA256.fullmatch(value) is None:
        raise ValueError("Account Center returned an invalid Microsoft Graph scope digest")
    return value


def validate_resource_id(value: object, label: str) -> str:
    """Expose the common bounded Graph resource-ID check to HTTP DTO validators."""

    return _planner_id(value, label)


def is_valid_sharepoint_site_id(value: object) -> bool:
    """Check hostname, site collection UUID, and web UUID in a Graph site ID."""

    if not isinstance(value, str) or _SITE_ID.fullmatch(value) is None:
        return False
    _host, site_collection_id, web_id = value.split(",", maxsplit=2)
    return _GUID.fullmatch(site_collection_id) is not None and _GUID.fullmatch(web_id) is not None


def validate_sharepoint_list_id(value: object) -> str:
    """Require the provider's canonical lowercase UUID list ID form."""

    if not isinstance(value, str) or _GUID.fullmatch(value) is None:
        raise ValueError("SharePoint list IDs must be UUIDs")
    if value != value.lower():
        raise ValueError("SharePoint list IDs must use lowercase canonical UUIDs")
    return value


def _validate_planner_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    if operation_id == "microsoft_graph.planner.plans.list":
        _exact_fields(arguments, required=set(), optional={"page_size", "page_cursor"})
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.planner.plan.get":
        _exact_fields(arguments, required={"plan_id"})
    elif operation_id == "microsoft_graph.planner.tasks.list":
        _exact_fields(
            arguments,
            required={"plan_id"},
            optional={"page_size", "page_cursor"},
        )
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.planner.task.get":
        _exact_fields(arguments, required={"plan_id", "task_id"})
    elif operation_id == "microsoft_graph.planner.task.create":
        _exact_fields(
            arguments,
            required={"plan_id", "bucket_id", "title"},
            optional={"due_date_time"},
        )
        _bounded_text(arguments["title"], "title", maximum=500)
        if "due_date_time" in arguments:
            _timestamp(arguments["due_date_time"], "due_date_time")
    elif operation_id == "microsoft_graph.planner.task.update":
        _exact_fields(
            arguments,
            required={"plan_id", "task_id", "if_match", "changes"},
        )
        _bounded_text(arguments["if_match"], "if_match", maximum=512)
        changes = arguments["changes"]
        if not isinstance(changes, Mapping) or not changes:
            raise ValueError("changes must be a non-empty object")
        allowed = {
            "title",
            "due_date_time",
            "start_date_time",
            "percent_complete",
            "priority",
        }
        if set(changes) - allowed:
            raise ValueError("changes contains an unsupported Planner field")
        for field in ("title",):
            if field in changes:
                _bounded_text(changes[field], field, maximum=500)
        for field in ("due_date_time", "start_date_time"):
            if field in changes:
                _timestamp(changes[field], field)
        if "percent_complete" in changes:
            _bounded_integer(changes["percent_complete"], "percent_complete", 0, 100)
        if "priority" in changes:
            _bounded_integer(changes["priority"], "priority", 0, 10)


def _validate_sharepoint_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    if operation_id == "microsoft_graph.sharepoint.site.get":
        _exact_fields(arguments, required={"site_id"})
    elif operation_id == "microsoft_graph.sharepoint.drives.list":
        _exact_fields(
            arguments,
            required={"site_id"},
            optional={"page_size", "page_cursor"},
        )
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.sharepoint.drive.items.list":
        _exact_fields(
            arguments,
            required={"site_id", "drive_id"},
            optional={"parent_item_id", "page_size", "page_cursor"},
        )
        _opaque_resource_id(arguments["drive_id"], "drive_id")
        if "parent_item_id" in arguments:
            _opaque_resource_id(arguments["parent_item_id"], "parent_item_id")
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.sharepoint.list.get":
        _exact_fields(arguments, required={"site_id", "list_id"})
    else:
        _exact_fields(
            arguments,
            required={"site_id", "list_id"},
            optional={"page_size", "page_cursor"},
        )
        _validate_page_options(arguments)


def _validate_todo_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    """Validate To Do payload fields before building the signed resource target."""

    if operation_id == "microsoft_graph.todo.lists.list":
        _exact_fields(arguments, required=set(), optional={"page_size", "page_cursor"})
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.todo.tasks.list":
        _exact_fields(
            arguments,
            required={"task_list_id"},
            optional={"page_size", "page_cursor"},
        )
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.todo.task.get":
        _exact_fields(arguments, required={"task_list_id", "task_id"})
    elif operation_id == "microsoft_graph.todo.task.create":
        _exact_fields(
            arguments,
            required={"task_list_id", "title"},
            optional={"due_date_time", "importance"},
        )
        _bounded_text(arguments["title"], "title", maximum=500)
        if "due_date_time" in arguments:
            _timestamp(arguments["due_date_time"], "due_date_time")
        if "importance" in arguments and arguments["importance"] not in (
            "low",
            "normal",
            "high",
        ):
            raise ValueError("importance is outside the fixed To Do schema")
    elif operation_id == "microsoft_graph.todo.task.update":
        _exact_fields(
            arguments,
            required={"task_list_id", "task_id", "if_match", "changes"},
        )
        _bounded_text(arguments["if_match"], "if_match", maximum=512)
        changes = arguments["changes"]
        if not isinstance(changes, Mapping) or not changes:
            raise ValueError("changes must be a non-empty object")
        allowed = {"title", "due_date_time", "status", "importance"}
        if set(changes) - allowed:
            raise ValueError("changes contains an unsupported To Do field")
        if "title" in changes:
            _bounded_text(changes["title"], "title", maximum=500)
        if "due_date_time" in changes:
            _timestamp(changes["due_date_time"], "due_date_time")
        if "status" in changes and changes["status"] not in (
            "notStarted",
            "inProgress",
            "completed",
            "waitingOnOthers",
            "deferred",
        ):
            raise ValueError("status is outside the fixed To Do schema")
        if "importance" in changes and changes["importance"] not in ("low", "normal", "high"):
            raise ValueError("importance is outside the fixed To Do schema")
    elif operation_id == "microsoft_graph.todo.task.delete":
        _exact_fields(arguments, required={"task_list_id", "task_id", "if_match"})
        _bounded_text(arguments["if_match"], "if_match", maximum=512)


def _validate_calendar_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    """Validate Calendar operation fields while excluding arbitrary recipients."""

    if operation_id == "microsoft_graph.calendar.calendars.list":
        _exact_fields(arguments, required=set(), optional={"page_size", "page_cursor"})
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.calendar.events.list":
        _exact_fields(
            arguments,
            required={"calendar_id", "start_date_time", "end_date_time"},
            optional={"page_size", "page_cursor"},
        )
        _validate_page_options(arguments)
        for field in ("start_date_time", "end_date_time"):
            if field in arguments:
                _timestamp(arguments[field], field)
        if (
            "start_date_time" in arguments
            and "end_date_time" in arguments
            and _timestamp_datetime(arguments["start_date_time"])
            >= _timestamp_datetime(arguments["end_date_time"])
        ):
            raise ValueError("Calendar event time range is invalid")
    elif operation_id == "microsoft_graph.calendar.event.get":
        _exact_fields(arguments, required={"calendar_id", "event_id"})
    elif operation_id == "microsoft_graph.calendar.freebusy.get":
        _exact_fields(
            arguments,
            required={"schedules", "start_date_time", "end_date_time", "interval_minutes"},
        )
        schedules = arguments["schedules"]
        if not isinstance(schedules, list) or not 1 <= len(schedules) <= 20:
            raise ValueError("schedules must contain 1..20 exact subjects")
        normalized = [_validate_subject(item) for item in schedules]
        if len(normalized) != len(set(normalized)):
            raise ValueError("schedules contains duplicate subjects")
        start = _timestamp_datetime(arguments["start_date_time"])
        end = _timestamp_datetime(arguments["end_date_time"])
        if start >= end or end - start > timedelta(days=31):
            raise ValueError("free/busy time range is outside the fixed schema")
        _bounded_integer(arguments["interval_minutes"], "interval_minutes", 5, 60)
    elif operation_id == "microsoft_graph.calendar.event.create":
        _exact_fields(
            arguments,
            required={
                "calendar_id",
                "subject",
                "start_date_time",
                "end_date_time",
                "transaction_id",
            },
            optional={"location"},
        )
        _bounded_text(arguments["subject"], "subject", maximum=500)
        start = _timestamp_datetime(arguments["start_date_time"])
        end = _timestamp_datetime(arguments["end_date_time"])
        if start >= end:
            raise ValueError("Calendar event end must follow its start")
        _canonical_uuid(arguments["transaction_id"], "Calendar transaction_id")
        if "location" in arguments:
            _bounded_text(arguments["location"], "location", maximum=500)
    elif operation_id == "microsoft_graph.calendar.event.update":
        _exact_fields(
            arguments,
            required={"calendar_id", "event_id", "if_match", "changes"},
        )
        _bounded_text(arguments["if_match"], "if_match", maximum=512)
        changes = arguments["changes"]
        if not isinstance(changes, Mapping) or not changes:
            raise ValueError("changes must be a non-empty object")
        allowed = {"subject", "start_date_time", "end_date_time", "location"}
        if set(changes) - allowed:
            raise ValueError("changes contains an unsupported Calendar field")
        if "subject" in changes:
            _bounded_text(changes["subject"], "subject", maximum=500)
        for field in ("start_date_time", "end_date_time"):
            if field in changes:
                _timestamp(changes[field], field)
        if (
            "start_date_time" in changes
            and "end_date_time" in changes
            and _timestamp_datetime(changes["start_date_time"])
            >= _timestamp_datetime(changes["end_date_time"])
        ):
            raise ValueError("Calendar event end must follow its start")
        if "location" in changes:
            _bounded_text(changes["location"], "location", maximum=500)
    elif operation_id == "microsoft_graph.calendar.event.delete":
        _exact_fields(arguments, required={"calendar_id", "event_id", "if_match"})
        _bounded_text(arguments["if_match"], "if_match", maximum=512)


def _validate_mail_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    """Validate fixed Mail metadata and draft inputs without accepting arbitrary Graph paths."""

    if operation_id in {
        "microsoft_graph.mail.folders.list",
        "microsoft_graph.mail.drafts.list",
    }:
        _exact_fields(arguments, required=set(), optional={"page_size", "page_cursor"})
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.mail.messages.list":
        _exact_fields(
            arguments,
            required={"folder_id"},
            optional={"page_size", "page_cursor"},
        )
        _opaque_resource_id(arguments["folder_id"], "folder_id")
        _validate_page_options(arguments)
    elif operation_id == "microsoft_graph.mail.message.get":
        _exact_fields(arguments, required={"folder_id", "message_id"})
        _opaque_resource_id(arguments["folder_id"], "folder_id")
        _opaque_resource_id(arguments["message_id"], "message_id")
    elif operation_id == "microsoft_graph.mail.draft.create":
        _exact_fields(
            arguments,
            required={"subject", "body_text"},
            optional={"to_recipients", "cc_recipients"},
        )
        _bounded_text(arguments["subject"], "subject", maximum=255)
        _validate_mail_body(arguments["body_text"])
        for field in ("to_recipients", "cc_recipients"):
            if field in arguments:
                _validate_mail_recipients(arguments[field], field)
    elif operation_id == "microsoft_graph.mail.draft.update":
        _exact_fields(arguments, required={"message_id", "if_match", "changes"})
        _opaque_resource_id(arguments["message_id"], "message_id")
        _bounded_text(arguments["if_match"], "if_match", maximum=512)
        changes = arguments["changes"]
        allowed = {"subject", "body_text", "to_recipients", "cc_recipients"}
        if not isinstance(changes, Mapping) or not changes or set(changes) - allowed:
            raise ValueError("changes contains an unsupported Mail draft field")
        if "subject" in changes:
            _bounded_text(changes["subject"], "subject", maximum=255)
        if "body_text" in changes:
            _validate_mail_body(changes["body_text"])
        for field in ("to_recipients", "cc_recipients"):
            if field in changes:
                _validate_mail_recipients(changes[field], field)
    elif operation_id == "microsoft_graph.mail.draft.delete":
        _exact_fields(arguments, required={"message_id", "if_match"})
        _opaque_resource_id(arguments["message_id"], "message_id")
        _bounded_text(arguments["if_match"], "if_match", maximum=512)
    elif operation_id == "microsoft_graph.mail.message.send":
        _exact_fields(arguments, required={"message_id"})
        _opaque_resource_id(arguments["message_id"], "message_id")
    else:
        raise ValueError("Microsoft Graph Mail operation is outside the fixed argument schema")


def _validate_mail_recipients(value: object, label: str) -> None:
    """Accept only a bounded list of exact email addresses for draft recipient fields."""

    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        raise ValueError(f"{label} must be a bounded list of email addresses")
    for address in value:
        if (
            not isinstance(address, str)
            or not 3 <= len(address) <= 320
            or address.strip() != address
            or re.fullmatch(r"[^\s<>@]+@[^\s<>@]+", address) is None
        ):
            raise ValueError(f"{label} contains an invalid email address")


def _validate_mail_body(value: object) -> None:
    """Accept bounded plain text, preserving newlines while rejecting controls."""

    if (
        not isinstance(value, str)
        or len(value) > 65_536
        or any(
            (ord(character) < 0x20 and character not in "\t\n\r") or ord(character) == 0x7F
            for character in value
        )
    ):
        raise ValueError("body_text is outside the fixed Microsoft Graph schema")


def _validate_subjects(value: object) -> list[str]:
    """Validate an exact bounded subject allowlist from the actor profile."""

    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("Account Center returned invalid free/busy subjects")
    subjects = [_validate_subject(item) for item in value]
    if len(subjects) != len(set(subjects)):
        raise ValueError("Account Center returned duplicate free/busy subjects")
    return subjects


def _validate_subject(value: object) -> str:
    """Return one canonical exact email/UPN used by Graph free/busy selectors."""

    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 320
        or value.strip() != value
        or re.fullmatch(r"[^\s@]+@[^\s@]+", value) is None
    ):
        raise ValueError("free/busy subject is outside the fixed profile schema")
    return value.casefold()


def _unique_resource_ids(value: object, label: str) -> list[str]:
    """Validate a bounded list of provider IDs and reject duplicates."""

    if not isinstance(value, list) or len(value) > 100:
        raise ValueError(f"Account Center returned invalid {label}")
    identifiers = [_opaque_resource_id(item, label) for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Account Center returned duplicate {label}")
    return identifiers


def _unique_sharepoint_ids(value: object, label: str) -> list[str]:
    """Validate the provider's canonical UUID identifiers for selected lists."""

    if not isinstance(value, list) or len(value) > 100:
        raise ValueError(f"Account Center returned invalid {label}")
    identifiers = [validate_sharepoint_list_id(item) for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Account Center returned duplicate {label}")
    return identifiers


def _canonical_uuid(value: object, label: str) -> str:
    """Require one canonical lower-case UUID for tenant/workspace identity."""

    if not isinstance(value, str) or _GUID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a UUID")
    canonical = str(UUID(value))
    if value != canonical:
        raise ValueError(f"{label} must use lower-case canonical UUID form")
    return canonical


def _opaque_resource_id(value: object, label: str) -> str:
    """Validate an opaque Graph resource ID without parsing it as a URL or path."""

    if not isinstance(value, str) or _OPAQUE_RESOURCE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} is outside the bounded Graph resource identifier schema")
    return value


def _validate_page_options(arguments: Mapping[str, object]) -> None:
    if "page_size" in arguments:
        _bounded_integer(arguments["page_size"], "page_size", 1, 100)
    if "page_cursor" in arguments:
        cursor = arguments["page_cursor"]
        if not isinstance(cursor, str) or _PAGE_CURSOR.fullmatch(cursor) is None:
            raise ValueError("page_cursor must be a bounded provider cursor")


def _exact_fields(
    value: Mapping[str, object], *, required: set[str], optional: set[str] | None = None
) -> None:
    allowed_optional = optional or set()
    if not required <= set(value) or set(value) - required - allowed_optional:
        raise ValueError("Microsoft Graph arguments do not match the fixed operation schema")


def _planner_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _PLANNER_ID.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded Planner resource identifier")
    return value


def _unique_planner_ids(value: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"Account Center returned invalid {label}")
    identifiers = [_planner_id(item, label) for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Account Center returned duplicate {label}")
    return identifiers


def _bounded_text(value: object, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError(f"{label} is outside the fixed Microsoft Graph schema")
    return value


def _bounded_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the fixed Microsoft Graph schema")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _timestamp_datetime(value: object) -> datetime:
    """Parse one timestamp after validating its explicit UTC offset."""

    normalized = _timestamp(value, "timestamp").replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)
