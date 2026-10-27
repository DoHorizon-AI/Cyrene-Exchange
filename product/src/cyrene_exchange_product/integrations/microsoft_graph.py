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
from datetime import datetime
from typing import Any
from uuid import UUID

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.microsoft_identity import require_microsoft_profile_actor

_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_PLANNER_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_SITE_ID = re.compile(r"[A-Za-z0-9.-]{1,255},[0-9a-fA-F-]{36},[0-9a-fA-F-]{36}\Z")
_PAGE_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,4096}={0,2}\Z")
_PROFILE_SCOPE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

PLANNER_READ_OPERATIONS = frozenset(
    {
        "microsoft_graph.planner.plan.get",
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
GRAPH_OPERATIONS = PLANNER_READ_OPERATIONS | PLANNER_WRITE_OPERATIONS | SHAREPOINT_READ_OPERATIONS


def validate_profile_scope(value: object) -> dict[str, Any]:
    """Validate and copy the exact non-secret scope returned by Account Center.

    The tenant and selected resource IDs are authority-owned. Callers may choose
    a fixed target, but cannot introduce a tenant, plan, site, list, or permission.
    中文：租户与资源范围必须由 Account Center 绑定，调用参数不能扩权。
    """

    if not isinstance(value, Mapping) or set(value) != {"tenant_id", "planner", "sharepoint"}:
        raise ValueError("Account Center returned an invalid Microsoft Graph profile scope")
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
    oauth_scopes = row.get("oauth_scopes")
    expected_oauth_scopes = {"User.Read", "Tasks.Read"}
    if scope["planner"]["tasks_write"]:
        expected_oauth_scopes.add("Tasks.ReadWrite")
    if scope["sharepoint"]["enabled"]:
        expected_oauth_scopes.add("Sites.Selected")
    if (
        not isinstance(oauth_scopes, list)
        or any(not isinstance(item, str) for item in oauth_scopes)
        or len(oauth_scopes) != len(set(oauth_scopes))
        or set(oauth_scopes) != expected_oauth_scopes
    ):
        raise ValueError("Account Center returned unsupported Microsoft Graph OAuth scopes")
    expires_at = row.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
        raise ValueError("Account Center returned an invalid Microsoft Graph expiry")
    return scope


def public_profile_scope(value: object) -> dict[str, Any]:
    """Return the stable camelCase HTTP projection of a validated Graph scope."""

    scope = validate_profile_scope(value)
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


def target_for_operation(
    operation_id: str,
    arguments: Mapping[str, object],
    profile_scope: Mapping[str, Any],
) -> dict[str, object]:
    """Validate one fixed Graph argument shape and derive its Account Center target."""

    scope = validate_profile_scope(profile_scope)
    tenant_id = scope["tenant_id"]
    target: dict[str, object]
    if operation_id not in GRAPH_OPERATIONS:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_OPERATION_INVALID",
            title="Microsoft Graph operation is not enabled",
            detail="The requested Microsoft Graph operation is outside Exchange's fixed allowlist.",
            status=422,
            context={"reasonCode": "microsoft_graph_operation_not_allowlisted"},
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
        plan_id = _planner_id(arguments.get("plan_id"), "plan_id")
        if plan_id not in planner["plan_ids"]:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
                title="Planner plan is outside the linked profile scope",
                detail="Select a Planner plan explicitly linked to this actor-owned profile.",
                status=403,
                context={"reasonCode": "microsoft_graph_plan_scope_mismatch"},
            )
        _validate_planner_arguments(operation_id, arguments)
        target = {"tenant_id": tenant_id, "plan_id": plan_id}
        if operation_id in {
            "microsoft_graph.planner.task.get",
            "microsoft_graph.planner.task.update",
        }:
            target["task_id"] = _planner_id(arguments.get("task_id"), "task_id")
        elif operation_id == "microsoft_graph.planner.task.create":
            target["bucket_id"] = _planner_id(arguments.get("bucket_id"), "bucket_id")
        return target

    sharepoint = scope["sharepoint"]
    if not sharepoint["enabled"]:
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


def lease_arguments_for_operation(
    operation_id: str,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    """Remove exact resource IDs that Account Center binds in the lease target."""

    excluded = {
        "microsoft_graph.planner.plan.get": {"plan_id"},
        "microsoft_graph.planner.tasks.list": {"plan_id"},
        "microsoft_graph.planner.task.get": {"plan_id", "task_id"},
        "microsoft_graph.planner.task.create": {"plan_id", "bucket_id"},
        "microsoft_graph.planner.task.update": {"plan_id", "task_id"},
        "microsoft_graph.sharepoint.site.get": {"site_id"},
        "microsoft_graph.sharepoint.list.get": {"site_id", "list_id"},
        "microsoft_graph.sharepoint.list.items.delta": {"site_id", "list_id"},
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
    """Check the exact compound Graph site ID structure used by SharePoint."""

    if not isinstance(value, str) or _SITE_ID.fullmatch(value) is None:
        return False
    _host, tenant_id, site_id = value.split(",", maxsplit=2)
    return _GUID.fullmatch(tenant_id) is not None and _GUID.fullmatch(site_id) is not None


def validate_sharepoint_list_id(value: object) -> str:
    """Require the provider's canonical lowercase UUID list ID form."""

    if not isinstance(value, str) or _GUID.fullmatch(value) is None:
        raise ValueError("SharePoint list IDs must be UUIDs")
    if value != value.lower():
        raise ValueError("SharePoint list IDs must use lowercase canonical UUIDs")
    return value


def _validate_planner_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    if operation_id == "microsoft_graph.planner.plan.get":
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
    elif operation_id == "microsoft_graph.sharepoint.list.get":
        _exact_fields(arguments, required={"site_id", "list_id"})
    else:
        _exact_fields(
            arguments,
            required={"site_id", "list_id"},
            optional={"page_size", "page_cursor"},
        )
        _validate_page_options(arguments)


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
