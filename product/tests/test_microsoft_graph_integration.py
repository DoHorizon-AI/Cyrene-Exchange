"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_microsoft_graph_integration.py                              │
│  Module: tests.test_microsoft_graph_integration                      │
│  Role: Verify Graph profile isolation, exact targets, and lease flow. │
│                                                                      │
│  模块职责：验证 Graph Profile 隔离、精确目标与租约调用路径。             │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.clients import IntegrationAccountCenterPort
from cyrene_exchange_product.integrations.connector_operations import (
    ConnectorOperationDispatcher,
    _account_lease_target,
    _resource_ref,
)
from cyrene_exchange_product.integrations.connector_security import digest_arguments
from cyrene_exchange_product.integrations.microsoft_graph import (
    GRAPH_OPERATIONS,
    lease_arguments_for_operation,
    profile_scope_metadata,
    public_profile_scope,
    required_graph_permissions,
    required_oauth_scopes,
    target_for_operation,
    validate_profile_identity,
    validate_profile_scope,
)
from cyrene_exchange_product.integrations.models import (
    IntegrationConnection,
    IntegrationPrincipal,
)
from cyrene_exchange_product.integrations.ports import ProviderCredentialLeaseEvidence

TENANT_ID = "11111111-2222-4333-8444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa"
PROFILE_REF = "66666666-7777-4888-8999-aaaaaaaaaaaa"
CONNECTION_ID = UUID("99999999-aaaa-4bbb-8ccc-dddddddddddd")
WORKSPACE_ID = "graph-workspace"
V2_WORKSPACE_ID = "33333333-4444-4555-8666-777777777777"
ORGANIZATION_ID = "graph-organization"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
PLAN_ID = "xqQg5FS2LkCp935s-FIFm2QAFkHM"
OFFICE_V2_SITE_ID = (
    "contoso.sharepoint.com,22222222-3333-4444-8555-666666666666,"
    "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
)
OFFICE_V2_LIST_ID = "dddddddd-eeee-4fff-8000-111111111111"


def _profile_scope(
    *,
    tasks_write: bool = False,
    sharepoint_enabled: bool = False,
) -> dict[str, object]:
    return {
        "tenant_id": TENANT_ID,
        "planner": {
            "plan_ids": [PLAN_ID],
            "tasks_read": True,
            "tasks_write": tasks_write,
        },
        "sharepoint": {
            "enabled": sharepoint_enabled,
            "site_id": (
                "contoso.sharepoint.com,11111111-2222-4333-8444-555555555555,"
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            )
            if sharepoint_enabled
            else None,
            "list_ids": ["bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"] if sharepoint_enabled else [],
        },
    }


def _office_v2_scope() -> dict[str, object]:
    return {
        "schema_version": 2,
        "tenant_id": TENANT_ID,
        "workspace_id": V2_WORKSPACE_ID,
        "planner": {"plan_ids": [], "tasks_read": True, "tasks_write": True},
        "sharepoint": {
            "enabled": True,
            "site_id": OFFICE_V2_SITE_ID,
            "list_ids": [],
            "drive_ids": [],
            "metadata_read": True,
            "content_read": False,
        },
        "todo": {
            "enabled": True,
            "task_list_ids": [],
            "tasks_read": True,
            "tasks_write": True,
        },
        "calendar": {
            "enabled": True,
            "calendar_ids": [],
            "events_read": True,
            "events_write": True,
            "freebusy_read": False,
            "freebusy_subjects": [],
            "attendees_write": False,
        },
        "mail": {
            "enabled": False,
            "folder_ids": [],
            "metadata_read": False,
            "body_read": False,
            "drafts_write": False,
            "send_enabled": False,
        },
    }


def _account_profile(
    *,
    auth_status: str = "healthy",
    scope: dict[str, object] | None = None,
    expires_at: int | None = None,
    refresh_expires_at: int | None = None,
) -> dict[str, object]:
    subject = f"{TENANT_ID}:{OBJECT_ID}"
    selected_scope = scope or _profile_scope()
    oauth_scopes = ["User.Read", "Tasks.Read"]
    if selected_scope["planner"]["tasks_write"]:
        oauth_scopes.append("Tasks.ReadWrite")
    if selected_scope["sharepoint"]["enabled"]:
        oauth_scopes.append("Sites.Selected")
    return {
        "profile_ref": PROFILE_REF,
        "provider": "microsoft_graph",
        "identity_ref": subject,
        "external_subject": subject,
        "auth_status": auth_status,
        "auth_mode": "delegated_oauth",
        "access_mode": "actor_owned",
        "expires_at": expires_at or int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "refresh_expires_at": refresh_expires_at,
        "oauth_scopes": oauth_scopes,
        "target_scope": selected_scope,
    }


def _connection() -> IntegrationConnection:
    return IntegrationConnection(
        id=CONNECTION_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        actor_issuer=ISSUER,
        actor_subject=OBJECT_ID,
        account_link_ref=PROFILE_REF,
        provider="microsoft_graph",
        binding_ref="graph-provider",
        target_ref=None,
        display_name="Microsoft Graph",
        access_mode="actor_owned",
    )


def _principal(subject: str = OBJECT_ID, *, operation_id: str) -> IntegrationPrincipal:
    return IntegrationPrincipal(
        issuer=ISSUER,
        subject=subject,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        allowed_operation_ids=frozenset({operation_id}),
    )


class _Store:
    def __init__(self, connection: IntegrationConnection) -> None:
        self.connection = connection

    def current_connection_for_provider_call(self, connection_id: UUID):
        return self.connection if connection_id == self.connection.id else None


class _Accounts:
    def __init__(self, profile: dict[str, object]) -> None:
        self.profile = profile
        self.profile_reads = 0
        self.lease_requests: list[dict[str, object]] = []

    def list_provider_profiles(self, _principal: IntegrationPrincipal):
        self.profile_reads += 1
        return {"profiles": [self.profile]}

    def create_provider_credential_lease(self, _principal: IntegrationPrincipal, **request):
        self.lease_requests.append(dict(request))
        return ProviderCredentialLeaseEvidence(
            lease_ref="lease-one-use",
            profile_ref=str(request["profile_ref"]),
            provider="microsoft_graph",
            operation_id=str(request["operation_id"]),
            target=dict(request["target"]),
            arguments_sha256=str(request["arguments_sha256"]),
            expires_at=datetime.now(UTC) + timedelta(seconds=30),
            profile_scope_sha256="a" * 64,
        )


class _GraphProvider:
    def __init__(self) -> None:
        self.arguments: dict[str, object] | None = None

    def invoke_connector_tool(self, _principal, _connection, **request):
        self.arguments = dict(request["arguments"])
        return {"complete": True, "items": []}


def _dispatcher(
    profile: dict[str, object],
    *,
    sharepoint_targets: bool = False,
):
    connection = _connection()
    accounts = _Accounts(profile)
    graph = _GraphProvider()
    host_profile = SimpleNamespace(
        provider="microsoft_graph",
        access_mode="actor_owned",
        microsoft_graph_plan_ids=(PLAN_ID,),
        microsoft_graph_sharepoint_site_id=(
            "contoso.sharepoint.com,11111111-2222-4333-8444-555555555555,"
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            if sharepoint_targets
            else None
        ),
        microsoft_graph_sharepoint_list_ids=(
            ("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",) if sharepoint_targets else ()
        ),
        targets={},
    )
    dispatcher = ConnectorOperationDispatcher(
        store=_Store(connection),
        accounts=accounts,
        github=None,
        authorization_cloud=graph,
        registry=SimpleNamespace(
            settings=SimpleNamespace(profiles={"graph-provider": host_profile})
        ),
    )
    return connection, accounts, graph, dispatcher


def test_graph_profile_scope_is_exact_and_planner_write_requires_separate_consent() -> None:
    scope = validate_profile_scope(_profile_scope())
    arguments = {"plan_id": PLAN_ID, "page_size": 25}

    assert target_for_operation("microsoft_graph.planner.tasks.list", arguments, scope) == {
        "tenant_id": TENANT_ID,
        "plan_id": PLAN_ID,
    }
    underscore_scope = validate_profile_scope(
        {
            **_profile_scope(),
            "planner": {
                "plan_ids": ["plan_01"],
                "tasks_read": True,
                "tasks_write": False,
            },
        }
    )
    assert target_for_operation(
        "microsoft_graph.planner.plan.get",
        {"plan_id": "plan_01"},
        underscore_scope,
    ) == {"tenant_id": TENANT_ID, "plan_id": "plan_01"}

    with pytest.raises(ExchangeProductError) as outside_scope:
        target_for_operation(
            "microsoft_graph.planner.tasks.list",
            {"plan_id": "another-plan"},
            scope,
        )
    assert outside_scope.value.code == "EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN"
    assert outside_scope.value.context["reasonCode"] == "microsoft_graph_plan_scope_mismatch"

    with pytest.raises(ExchangeProductError) as write_denied:
        target_for_operation(
            "microsoft_graph.planner.task.create",
            {"plan_id": PLAN_ID, "bucket_id": "bucket-1", "title": "Review report"},
            scope,
        )
    assert write_denied.value.code == "EXCHANGE_CONNECTOR_PERMISSION_DENIED"
    assert write_denied.value.context["reasonCode"] == "planner_tasks_write_consent_required"

    sharepoint_scope = validate_profile_scope(_profile_scope(sharepoint_enabled=True))
    site_id = str(sharepoint_scope["sharepoint"]["site_id"])
    list_id = str(sharepoint_scope["sharepoint"]["list_ids"][0])
    assert target_for_operation(
        "microsoft_graph.sharepoint.list.items.delta",
        {"site_id": site_id, "list_id": list_id, "page_size": 40},
        sharepoint_scope,
    ) == {"tenant_id": TENANT_ID, "site_id": site_id, "list_id": list_id}
    with pytest.raises(ExchangeProductError) as other_list:
        target_for_operation(
            "microsoft_graph.sharepoint.list.get",
            {
                "site_id": site_id,
                "list_id": "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa",
            },
            sharepoint_scope,
        )
    assert other_list.value.context["reasonCode"] == "microsoft_graph_list_scope_mismatch"


def test_office_v2_discovery_is_limited_to_safe_selected_account_metadata() -> None:
    scope = validate_profile_scope(_office_v2_scope())
    site_id = str(scope["sharepoint"]["site_id"])

    assert target_for_operation("microsoft_graph.planner.plans.list", {}, scope) == {
        "tenant_id": TENANT_ID
    }
    assert target_for_operation("microsoft_graph.todo.lists.list", {}, scope) == {
        "tenant_id": TENANT_ID,
        "task_list_ids": [],
    }
    assert target_for_operation("microsoft_graph.calendar.calendars.list", {}, scope) == {
        "tenant_id": TENANT_ID,
        "calendar_ids": [],
    }
    assert target_for_operation(
        "microsoft_graph.sharepoint.drives.list",
        {"site_id": site_id},
        scope,
    ) == {"tenant_id": TENANT_ID, "site_id": site_id, "drive_ids": []}
    assert required_graph_permissions(scope) == (
        "Calendars.ReadWrite",
        "Sites.Selected",
        "Tasks.ReadWrite",
        "User.Read",
    )
    assert required_oauth_scopes(scope) == (
        "Calendars.ReadWrite",
        "Sites.Selected",
        "Tasks.ReadWrite",
        "User.Read",
        "offline_access",
    )

    with pytest.raises(ExchangeProductError) as outside_list:
        target_for_operation(
            "microsoft_graph.todo.tasks.list",
            {"task_list_id": "list-not-yet-selected"},
            scope,
        )
    assert outside_list.value.context["reasonCode"] == "microsoft_graph_todo_list_scope_mismatch"
    with pytest.raises(ExchangeProductError) as mail_denied:
        target_for_operation("microsoft_graph.mail.message.send", {"message_id": "m1"}, scope)
    assert mail_denied.value.context["reasonCode"] == "microsoft_graph_operation_not_allowlisted"


def test_office_v2_selected_targets_gate_writes_and_bind_their_lease_digest() -> None:
    scope = _office_v2_scope()
    scope["todo"] = {
        "enabled": True,
        "task_list_ids": ["AAMkList-opaque=="],
        "tasks_read": True,
        "tasks_write": True,
    }
    scope["calendar"] = {
        **scope["calendar"],
        "calendar_ids": ["AAMkCalendar-opaque=="],
    }
    scope["sharepoint"] = {
        **scope["sharepoint"],
        "drive_ids": ["b!drive-opaque=="],
    }
    normalized = validate_profile_scope(scope)
    todo_args = {"task_list_id": "AAMkList-opaque==", "title": "Prepare review"}
    todo_target = target_for_operation("microsoft_graph.todo.task.create", todo_args, normalized)
    assert todo_target == {"tenant_id": TENANT_ID, "task_list_id": "AAMkList-opaque=="}
    assert lease_arguments_for_operation("microsoft_graph.todo.task.create", todo_args) == {
        "title": "Prepare review"
    }

    event_args = {
        "calendar_id": "AAMkCalendar-opaque==",
        "subject": "Design review",
        "start_date_time": "2026-11-02T10:00:00-05:00",
        "end_date_time": "2026-11-02T10:30:00-05:00",
        "transaction_id": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
    }
    event_target = target_for_operation(
        "microsoft_graph.calendar.event.create", event_args, normalized
    )
    assert event_target == {
        "tenant_id": TENANT_ID,
        "calendar_id": "AAMkCalendar-opaque==",
        "transaction_id": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
    }
    assert lease_arguments_for_operation("microsoft_graph.calendar.event.create", event_args) == {
        "subject": "Design review",
        "start_date_time": "2026-11-02T10:00:00-05:00",
        "end_date_time": "2026-11-02T10:30:00-05:00",
    }
    with pytest.raises(ValueError, match="arguments do not match"):
        target_for_operation(
            "microsoft_graph.calendar.event.create",
            {**event_args, "attendees": ["coworker@example.com"]},
            normalized,
        )

    sharepoint_target = target_for_operation(
        "microsoft_graph.sharepoint.drive.items.list",
        {"site_id": normalized["sharepoint"]["site_id"], "drive_id": "b!drive-opaque=="},
        normalized,
    )
    assert sharepoint_target["drive_id"] == "b!drive-opaque=="


def test_all_graph_operations_project_exact_account_center_lease_targets() -> None:
    scope = _office_v2_scope()
    scope["planner"]["plan_ids"] = [PLAN_ID]
    scope["sharepoint"]["list_ids"] = [OFFICE_V2_LIST_ID]
    scope["sharepoint"]["drive_ids"] = ["b!drive-opaque=="]
    scope["todo"]["task_list_ids"] = ["AAMkList-opaque=="]
    scope["calendar"].update(
        {
            "calendar_ids": ["AAMkCalendar-opaque=="],
            "freebusy_read": True,
            "freebusy_subjects": ["Person@DoHorizon.com"],
        }
    )
    site_id = scope["sharepoint"]["site_id"]
    list_id = OFFICE_V2_LIST_ID
    task_list_id = "AAMkList-opaque=="
    calendar_id = "AAMkCalendar-opaque=="
    transaction_id = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    event_window = {
        "start_date_time": "2026-11-02T10:00:00-05:00",
        "end_date_time": "2026-11-02T10:30:00-05:00",
    }
    cases = {
        "microsoft_graph.planner.plan.get": (
            {"plan_id": PLAN_ID},
            {"tenant_id": TENANT_ID, "plan_id": PLAN_ID},
        ),
        "microsoft_graph.planner.plans.list": (
            {"page_size": 10},
            {"tenant_id": TENANT_ID},
        ),
        "microsoft_graph.planner.tasks.list": (
            {"plan_id": PLAN_ID, "page_size": 10},
            {"tenant_id": TENANT_ID, "plan_id": PLAN_ID},
        ),
        "microsoft_graph.planner.task.get": (
            {"plan_id": PLAN_ID, "task_id": "task_A2b"},
            {"tenant_id": TENANT_ID, "plan_id": PLAN_ID, "task_id": "task_A2b"},
        ),
        "microsoft_graph.planner.task.create": (
            {"plan_id": PLAN_ID, "bucket_id": "bucket_936w-A2b", "title": "Review"},
            {"tenant_id": TENANT_ID, "plan_id": PLAN_ID, "bucket_id": "bucket_936w-A2b"},
        ),
        "microsoft_graph.planner.task.update": (
            {
                "plan_id": PLAN_ID,
                "task_id": "task_A2b",
                "if_match": "etag-1",
                "changes": {"title": "Updated"},
            },
            {"tenant_id": TENANT_ID, "plan_id": PLAN_ID, "task_id": "task_A2b"},
        ),
        "microsoft_graph.sharepoint.site.get": (
            {"site_id": site_id},
            {"tenant_id": TENANT_ID, "site_id": site_id},
        ),
        "microsoft_graph.sharepoint.list.get": (
            {"site_id": site_id, "list_id": list_id},
            {"tenant_id": TENANT_ID, "site_id": site_id, "list_id": list_id},
        ),
        "microsoft_graph.sharepoint.list.items.delta": (
            {"site_id": site_id, "list_id": list_id, "page_size": 10},
            {"tenant_id": TENANT_ID, "site_id": site_id, "list_id": list_id},
        ),
        "microsoft_graph.todo.lists.list": (
            {"page_size": 10},
            {"tenant_id": TENANT_ID},
        ),
        "microsoft_graph.todo.tasks.list": (
            {"task_list_id": task_list_id, "page_size": 10},
            {"tenant_id": TENANT_ID, "task_list_id": task_list_id},
        ),
        "microsoft_graph.todo.task.get": (
            {"task_list_id": task_list_id, "task_id": "AAMkTask-opaque=="},
            {"tenant_id": TENANT_ID, "task_list_id": task_list_id, "task_id": "AAMkTask-opaque=="},
        ),
        "microsoft_graph.todo.task.create": (
            {"task_list_id": task_list_id, "title": "Prepare review"},
            {"tenant_id": TENANT_ID, "task_list_id": task_list_id},
        ),
        "microsoft_graph.todo.task.update": (
            {
                "task_list_id": task_list_id,
                "task_id": "AAMkTask-opaque==",
                "if_match": "etag-1",
                "changes": {"title": "Updated"},
            },
            {"tenant_id": TENANT_ID, "task_list_id": task_list_id, "task_id": "AAMkTask-opaque=="},
        ),
        "microsoft_graph.todo.task.delete": (
            {
                "task_list_id": task_list_id,
                "task_id": "AAMkTask-opaque==",
                "if_match": "etag-1",
            },
            {"tenant_id": TENANT_ID, "task_list_id": task_list_id, "task_id": "AAMkTask-opaque=="},
        ),
        "microsoft_graph.calendar.calendars.list": (
            {"page_size": 10},
            {"tenant_id": TENANT_ID},
        ),
        "microsoft_graph.calendar.events.list": (
            {"calendar_id": calendar_id, **event_window, "page_size": 10},
            {"tenant_id": TENANT_ID, "calendar_id": calendar_id},
        ),
        "microsoft_graph.calendar.event.get": (
            {"calendar_id": calendar_id, "event_id": "AAMkEvent-opaque=="},
            {"tenant_id": TENANT_ID, "calendar_id": calendar_id, "event_id": "AAMkEvent-opaque=="},
        ),
        "microsoft_graph.calendar.event.create": (
            {
                "calendar_id": calendar_id,
                "subject": "Design review",
                **event_window,
                "transaction_id": transaction_id,
            },
            {
                "tenant_id": TENANT_ID,
                "calendar_id": calendar_id,
                "transaction_id": transaction_id,
            },
        ),
        "microsoft_graph.calendar.event.update": (
            {
                "calendar_id": calendar_id,
                "event_id": "AAMkEvent-opaque==",
                "if_match": "etag-1",
                "changes": {"subject": "Updated"},
            },
            {"tenant_id": TENANT_ID, "calendar_id": calendar_id, "event_id": "AAMkEvent-opaque=="},
        ),
        "microsoft_graph.calendar.event.delete": (
            {
                "calendar_id": calendar_id,
                "event_id": "AAMkEvent-opaque==",
                "if_match": "etag-1",
            },
            {"tenant_id": TENANT_ID, "calendar_id": calendar_id, "event_id": "AAMkEvent-opaque=="},
        ),
        "microsoft_graph.calendar.freebusy.get": (
            {
                "schedules": ["PERSON@DOHORIZON.COM"],
                "start_date_time": "2026-11-02T10:00:00-05:00",
                "end_date_time": "2026-11-02T10:30:00-05:00",
                "interval_minutes": 15,
            },
            {"tenant_id": TENANT_ID, "schedule_ids": ["person@dohorizon.com"]},
        ),
        "microsoft_graph.sharepoint.drives.list": (
            {"site_id": site_id, "page_size": 10},
            {"tenant_id": TENANT_ID, "site_id": site_id},
        ),
        "microsoft_graph.sharepoint.drive.items.list": (
            {
                "site_id": site_id,
                "drive_id": "b!drive-opaque==",
                "parent_item_id": "folder!opaque==",
                "page_size": 10,
            },
            {"tenant_id": TENANT_ID, "site_id": site_id, "drive_id": "b!drive-opaque=="},
        ),
    }

    assert set(cases) == GRAPH_OPERATIONS
    for operation_id, (arguments, expected_lease_target) in cases.items():
        resource_projection = target_for_operation(operation_id, arguments, scope)
        assert set(expected_lease_target) <= set(resource_projection)
        resource_ref = _resource_ref(
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            target=resource_projection,
        )
        assert resource_ref.startswith("sha256:")
        lease_target = _account_lease_target(
            "microsoft_graph",
            operation_id,
            resource_projection,
            arguments,
        )
        assert lease_target == expected_lease_target, operation_id

    assert cases["microsoft_graph.todo.lists.list"][1] == {"tenant_id": TENANT_ID}
    assert cases["microsoft_graph.calendar.calendars.list"][1] == {"tenant_id": TENANT_ID}
    assert cases["microsoft_graph.sharepoint.drives.list"][1] == {
        "tenant_id": TENANT_ID,
        "site_id": site_id,
    }
    assert target_for_operation(
        "microsoft_graph.todo.lists.list",
        cases["microsoft_graph.todo.lists.list"][0],
        scope,
    ) == {"tenant_id": TENANT_ID, "task_list_ids": [task_list_id]}
    assert target_for_operation(
        "microsoft_graph.calendar.calendars.list",
        cases["microsoft_graph.calendar.calendars.list"][0],
        scope,
    ) == {"tenant_id": TENANT_ID, "calendar_ids": [calendar_id]}
    assert target_for_operation(
        "microsoft_graph.sharepoint.drives.list",
        cases["microsoft_graph.sharepoint.drives.list"][0],
        scope,
    ) == {
        "tenant_id": TENANT_ID,
        "site_id": site_id,
        "drive_ids": ["b!drive-opaque=="],
    }
    drive_arguments = cases["microsoft_graph.sharepoint.drive.items.list"][0]
    assert (
        target_for_operation(
            "microsoft_graph.sharepoint.drive.items.list",
            drive_arguments,
            scope,
        )["parent_item_id"]
        == "folder!opaque=="
    )
    assert (
        lease_arguments_for_operation(
            "microsoft_graph.sharepoint.drive.items.list",
            drive_arguments,
        )["parent_item_id"]
        == "folder!opaque=="
    )


def test_office_v2_identity_is_pinned_to_tenant_owner_and_workspace() -> None:
    scope = _office_v2_scope()
    profile = {
        "profile_ref": PROFILE_REF,
        "provider": "microsoft_graph",
        "identity_ref": f"{TENANT_ID}:{OBJECT_ID}",
        "external_subject": f"{TENANT_ID}:{OBJECT_ID}",
        "auth_status": "healthy",
        "auth_mode": "delegated_oauth",
        "access_mode": "actor_owned",
        "expires_at": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "refresh_expires_at": None,
        "oauth_scopes": list(required_graph_permissions(scope)),
        "target_scope": scope,
    }
    principal = IntegrationPrincipal(
        issuer=ISSUER,
        subject=OBJECT_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=V2_WORKSPACE_ID,
        allowed_operation_ids=frozenset({"microsoft_graph.todo.lists.list"}),
    )
    validated = validate_profile_scope(scope)
    assert public_profile_scope(validated)["workspaceId"] == V2_WORKSPACE_ID
    assert validate_profile_identity(profile, profile_ref=PROFILE_REF, principal=principal)
    metadata = profile_scope_metadata(profile, validated)
    assert metadata["scope_schema_version"] == 2
    assert metadata["refresh_expires_at"] is None
    assert metadata["reauth_required"] is False

    wrong_workspace = IntegrationPrincipal(
        issuer=ISSUER,
        subject=OBJECT_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id="44444444-5555-4666-8777-888888888888",
        allowed_operation_ids=frozenset({"microsoft_graph.todo.lists.list"}),
    )
    with pytest.raises(ValueError, match="another workspace"):
        validate_profile_identity(profile, profile_ref=PROFILE_REF, principal=wrong_workspace)

    profile["oauth_scopes"] = [
        "User.Read",
        "Mail.Send",
        "Tasks.ReadWrite",
        "Sites.Selected",
        "Calendars.ReadWrite",
    ]
    with pytest.raises(ValueError, match="OAuth scopes"):
        validate_profile_identity(profile, profile_ref=PROFILE_REF, principal=principal)


def test_office_v2_profile_never_accepts_mail_body_reads() -> None:
    scope = _office_v2_scope()
    scope["mail"]["body_read"] = True

    with pytest.raises(ValueError, match="Mail body reads are disabled"):
        validate_profile_scope(scope)


def test_office_v2_write_scope_covers_read_on_other_enabled_task_feature() -> None:
    scope = _office_v2_scope()
    scope["planner"]["tasks_write"] = False
    scope["todo"]["tasks_write"] = True

    assert set(required_graph_permissions(scope)) == {
        "User.Read",
        "Tasks.ReadWrite",
        "Sites.Selected",
        "Calendars.ReadWrite",
    }


@pytest.mark.parametrize(
    ("operation_id", "arguments", "expected", "mutated_key", "mutated_value"),
    [
        (
            "microsoft_graph.planner.plan.get",
            {"plan_id": PLAN_ID},
            {},
            None,
            None,
        ),
        (
            "microsoft_graph.planner.tasks.list",
            {"plan_id": PLAN_ID, "page_size": 25, "page_cursor": "cursor-1"},
            {"page_size": 25, "page_cursor": "cursor-1"},
            "page_size",
            26,
        ),
        (
            "microsoft_graph.planner.task.get",
            {"plan_id": PLAN_ID, "task_id": "task-1"},
            {},
            None,
            None,
        ),
        (
            "microsoft_graph.planner.task.create",
            {
                "plan_id": PLAN_ID,
                "bucket_id": "bucket-1",
                "title": "New task",
                "due_date_time": "2026-11-01T00:00:00Z",
            },
            {"title": "New task", "due_date_time": "2026-11-01T00:00:00Z"},
            "title",
            "Changed task",
        ),
        (
            "microsoft_graph.planner.task.update",
            {
                "plan_id": PLAN_ID,
                "task_id": "task-1",
                "if_match": 'W/"etag-1"',
                "changes": {"percent_complete": 50},
            },
            {"if_match": 'W/"etag-1"', "changes": {"percent_complete": 50}},
            "changes",
            {"percent_complete": 75},
        ),
        (
            "microsoft_graph.sharepoint.site.get",
            {"site_id": "contoso.sharepoint.com,tenant,site"},
            {},
            None,
            None,
        ),
        (
            "microsoft_graph.sharepoint.list.get",
            {"site_id": "contoso.sharepoint.com,tenant,site", "list_id": "list-1"},
            {},
            None,
            None,
        ),
        (
            "microsoft_graph.sharepoint.list.items.delta",
            {
                "site_id": "contoso.sharepoint.com,tenant,site",
                "list_id": "list-1",
                "page_size": 25,
                "page_cursor": "cursor-1",
            },
            {"page_size": 25, "page_cursor": "cursor-1"},
            "page_cursor",
            "cursor-2",
        ),
    ],
)
def test_graph_lease_digest_excludes_exact_targets_and_keeps_other_parameters(
    operation_id: str,
    arguments: dict[str, object],
    expected: dict[str, object],
    mutated_key: str | None,
    mutated_value: object,
) -> None:
    lease_arguments = lease_arguments_for_operation(operation_id, arguments)
    assert lease_arguments == expected

    target_changed = dict(arguments)
    for key in set(arguments) - set(expected):
        target_changed[key] = f"changed-{key}"
    assert digest_arguments(lease_arguments_for_operation(operation_id, target_changed)) == (
        digest_arguments(expected)
    )
    assert digest_arguments(target_changed) != digest_arguments(arguments)

    if mutated_key is not None:
        non_target_changed = {**arguments, mutated_key: mutated_value}
        changed_digest = digest_arguments(
            lease_arguments_for_operation(operation_id, non_target_changed)
        )
        assert changed_digest != digest_arguments(lease_arguments)


def test_graph_dispatch_uses_actor_profile_scope_and_provider_only_lease_metadata() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    connection, accounts, provider, dispatcher = _dispatcher(_account_profile())
    arguments: dict[str, object] = {"plan_id": PLAN_ID, "page_size": 20}
    target = target_for_operation(operation_id, arguments, _profile_scope())
    resource_ref = _resource_ref(
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        target=target,
    )

    prepared = dispatcher.prepare_connection_operation(
        principal=principal,
        connection=connection,
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        resource_ref=resource_ref,
        arguments=arguments,
        request_id="request-graph-1",
    )
    digest = digest_arguments(arguments)
    lease_digest = digest_arguments(lease_arguments_for_operation(operation_id, arguments))
    claims = SimpleNamespace(
        grant_ref="grant-graph-1",
        request_id="request-graph-1",
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        principal_issuer=ISSUER,
        principal_subject=OBJECT_ID,
        connection_ref=str(CONNECTION_ID),
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        resource_ref=resource_ref,
        arguments_digest_sha256=bytes.fromhex(digest),
    )

    result = dispatcher.invoke(prepared, principal=principal, claims=claims)

    assert result == {"complete": True, "items": []}
    assert accounts.lease_requests == [
        {
            "profile_ref": PROFILE_REF,
            "operation_id": operation_id,
            "target": target,
            "arguments_sha256": lease_digest,
            "connector_grant": None,
        }
    ]
    assert provider.arguments == {
        "profile_ref": PROFILE_REF,
        "lease_ref": "lease-one-use",
        "target": target,
        "arguments_sha256": lease_digest,
        "profile_scope_sha256": "a" * 64,
        "payload": arguments,
    }
    assert "access_token" not in provider.arguments


def test_graph_connection_rejects_another_actor_before_profile_or_lease_lookup() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    connection, accounts, _provider, dispatcher = _dispatcher(_account_profile())
    other_actor = _principal(OTHER_OBJECT_ID, operation_id=operation_id)
    arguments: dict[str, object] = {"plan_id": PLAN_ID, "page_size": 20}
    resource_ref = "sha256:" + "0" * 64

    with pytest.raises(PermissionError):
        dispatcher.prepare_connection_operation(
            principal=other_actor,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=arguments,
            request_id="request-graph-other-actor",
        )

    assert accounts.profile_reads == 0
    assert accounts.lease_requests == []


def test_graph_profile_subject_must_match_the_original_signed_entra_actor() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    mismatched_profile = _account_profile()
    other_subject = f"{TENANT_ID}:{OTHER_OBJECT_ID}"
    mismatched_profile["external_subject"] = other_subject
    mismatched_profile["identity_ref"] = other_subject
    connection, accounts, _provider, dispatcher = _dispatcher(mismatched_profile)
    arguments: dict[str, object] = {"plan_id": PLAN_ID}
    target = target_for_operation(operation_id, arguments, _profile_scope())
    resource_ref = _resource_ref(
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        target=target,
    )

    with pytest.raises(PermissionError, match="different Entra actor"):
        dispatcher.prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=arguments,
            request_id="request-graph-profile-owner-mismatch",
        )

    assert accounts.lease_requests == []


def test_graph_profile_rejects_extra_oauth_scopes_before_lease_creation() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    profile = _account_profile()
    profile["oauth_scopes"] = ["User.Read", "Tasks.Read", "Mail.Read"]
    connection, accounts, _provider, dispatcher = _dispatcher(profile)
    arguments: dict[str, object] = {"plan_id": PLAN_ID}
    target = target_for_operation(operation_id, arguments, _profile_scope())

    with pytest.raises(ExchangeProductError) as denied:
        dispatcher.prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            resource_ref=_resource_ref(
                provider_id="microsoft_graph",
                profile_ref=PROFILE_REF,
                operation_id=operation_id,
                target=target,
            ),
            arguments=arguments,
            request_id="request-graph-extra-scope",
        )

    assert denied.value.code == "EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID"
    assert accounts.lease_requests == []


def test_graph_sharepoint_scope_requires_exact_host_site_and_list_allowlist() -> None:
    operation_id = "microsoft_graph.sharepoint.list.get"
    principal = _principal(operation_id=operation_id)
    profile = _account_profile(scope=_profile_scope(sharepoint_enabled=True))
    connection, accounts, _provider, dispatcher = _dispatcher(profile)
    scope = validate_profile_scope(profile["target_scope"])
    site_id = str(scope["sharepoint"]["site_id"])
    list_id = str(scope["sharepoint"]["list_ids"][0])
    arguments: dict[str, object] = {"site_id": site_id, "list_id": list_id}
    target = target_for_operation(operation_id, arguments, scope)

    with pytest.raises(PermissionError, match="SharePoint scope"):
        dispatcher.prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            resource_ref=_resource_ref(
                provider_id="microsoft_graph",
                profile_ref=PROFILE_REF,
                operation_id=operation_id,
                target=target,
            ),
            arguments=arguments,
            request_id="request-graph-sharepoint-outside-host",
        )
    assert accounts.lease_requests == []

    _connection, allowed_accounts, _allowed_provider, allowed_dispatcher = _dispatcher(
        profile,
        sharepoint_targets=True,
    )
    allowed = allowed_dispatcher.prepare_connection_operation(
        principal=principal,
        connection=_connection,
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        resource_ref=_resource_ref(
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            target=target,
        ),
        arguments=arguments,
        request_id="request-graph-sharepoint-host-approved",
    )
    assert allowed.target_projection == target
    assert allowed_accounts.lease_requests == []


def test_graph_reauthorization_state_is_a_conflict_before_lease_creation() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    connection, accounts, _provider, dispatcher = _dispatcher(
        _account_profile(auth_status="reauthorization_required")
    )
    arguments: dict[str, object] = {"plan_id": PLAN_ID}
    target = target_for_operation(operation_id, arguments, _profile_scope())
    resource_ref = _resource_ref(
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        target=target,
    )

    with pytest.raises(ExchangeProductError) as reauthorization:
        dispatcher.prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=arguments,
            request_id="request-graph-reauth",
        )

    assert reauthorization.value.code == "EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED"
    assert reauthorization.value.status == 409
    assert accounts.lease_requests == []


def test_graph_expired_access_token_remains_usable_when_account_center_can_refresh() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    expired_at = int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())
    connection, accounts, _provider, dispatcher = _dispatcher(
        _account_profile(expires_at=expired_at)
    )
    arguments: dict[str, object] = {"plan_id": PLAN_ID}
    target = target_for_operation(operation_id, arguments, _profile_scope())

    prepared = dispatcher.prepare_connection_operation(
        principal=principal,
        connection=connection,
        provider_id="microsoft_graph",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        resource_ref=_resource_ref(
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            target=target,
        ),
        arguments=arguments,
        request_id="request-graph-expired-access-refreshable",
    )

    assert prepared.operation_id == operation_id
    assert accounts.lease_requests == []


def test_graph_expired_refresh_token_requires_reauthorization_before_lease() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    expired_refresh = int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())
    connection, accounts, _provider, dispatcher = _dispatcher(
        _account_profile(refresh_expires_at=expired_refresh)
    )
    arguments: dict[str, object] = {"plan_id": PLAN_ID}
    target = target_for_operation(operation_id, arguments, _profile_scope())

    with pytest.raises(ExchangeProductError) as expired:
        dispatcher.prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=PROFILE_REF,
            operation_id=operation_id,
            resource_ref=_resource_ref(
                provider_id="microsoft_graph",
                profile_ref=PROFILE_REF,
                operation_id=operation_id,
                target=target,
            ),
            arguments=arguments,
            request_id="request-graph-expired-refresh",
        )

    assert expired.value.code == "EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED"
    assert expired.value.context["reasonCode"] == "microsoft_graph_reauthorization_required"
    assert accounts.lease_requests == []


def test_graph_task_update_requires_conditional_etag_and_closed_fields() -> None:
    scope = validate_profile_scope(_profile_scope(tasks_write=True))

    with pytest.raises(ValueError):
        target_for_operation(
            "microsoft_graph.planner.task.update",
            {
                "plan_id": PLAN_ID,
                "task_id": "task-1",
                "if_match": "etag-1",
                "changes": {"title": "Change title", "assigned_to": "person"},
            },
            scope,
        )

    target = target_for_operation(
        "microsoft_graph.planner.task.update",
        {
            "plan_id": PLAN_ID,
            "task_id": "task-1",
            "if_match": 'W/"etag-1"',
            "changes": {"percent_complete": 50},
        },
        scope,
    )
    assert target == {"tenant_id": TENANT_ID, "plan_id": PLAN_ID, "task_id": "task-1"}


def test_graph_account_center_lease_expiry_is_not_accepted() -> None:
    class ExpiredLeaseClient:
        def create_provider_credential_lease(self, _principal, **request):
            return {
                **request,
                "lease_ref": "lease-expired",
                "provider": "microsoft_graph",
                "expires_at": int((datetime.now(UTC) - timedelta(minutes=1)).timestamp()),
                "profile_scope_sha256": "b" * 64,
            }

    port = IntegrationAccountCenterPort(ExpiredLeaseClient())
    principal = _principal(operation_id="microsoft_graph.planner.tasks.list")

    with pytest.raises(ExchangeProductError) as expired:
        port.create_provider_credential_lease(
            principal,
            profile_ref=PROFILE_REF,
            operation_id="microsoft_graph.planner.tasks.list",
            target={"tenant_id": TENANT_ID, "plan_id": PLAN_ID},
            arguments_sha256="c" * 64,
        )

    assert expired.value.code == "EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID"
    assert expired.value.status == 502


def test_account_center_port_forwards_profile_reads_for_dispatcher_isolation() -> None:
    profile = _account_profile()

    class ProfileClient:
        def __init__(self) -> None:
            self.principal = None

        def list_provider_profiles(self, principal: IntegrationPrincipal):
            self.principal = principal
            return {"profiles": [profile]}

    client = ProfileClient()
    principal = _principal(operation_id="microsoft_graph.planner.tasks.list")
    result = IntegrationAccountCenterPort(client).list_provider_profiles(principal)

    assert client.principal is principal
    assert result == {"profiles": [profile]}
