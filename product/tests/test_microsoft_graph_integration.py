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
    _resource_ref,
)
from cyrene_exchange_product.integrations.connector_security import digest_arguments
from cyrene_exchange_product.integrations.microsoft_graph import (
    lease_arguments_for_operation,
    target_for_operation,
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
ORGANIZATION_ID = "graph-organization"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
PLAN_ID = "xqQg5FS2LkCp935s-FIFm2QAFkHM"


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


def _account_profile(
    *,
    auth_status: str = "healthy",
    scope: dict[str, object] | None = None,
    expires_at: int | None = None,
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


def test_graph_expired_profile_is_reauthorization_required_before_lease_creation() -> None:
    operation_id = "microsoft_graph.planner.tasks.list"
    principal = _principal(operation_id=operation_id)
    expired_at = int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())
    connection, accounts, _provider, dispatcher = _dispatcher(
        _account_profile(expires_at=expired_at)
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
            request_id="request-graph-expired-profile",
        )

    assert expired.value.code == "EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED"
    assert expired.value.context["reasonCode"] == "microsoft_graph_token_expired"
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
