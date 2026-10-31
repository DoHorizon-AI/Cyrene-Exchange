"""Private Office setup bridge validation tests.

Module: tests.test_office_setup
Role: Verify the loopback setup boundary keeps operator pins and credentials private.
模块职责：验证 Office setup 桥接的闭合输入及凭据脱敏边界。
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import ModuleType, SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.api import _microsoft_graph_oauth_session_response
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    validate_microsoft_graph_office_v2_scope,
)
from cyrene_exchange_product.integrations.clients import (
    AccountCenterClient,
    _typed_account_payload,
)
from cyrene_exchange_product.integrations.microsoft_graph import (
    required_graph_permissions,
)
from cyrene_exchange_product.integrations.models import IntegrationPrincipal
from cyrene_exchange_product.integrations.office_setup import (
    OfficeSetupError,
    _discovery_item,
    _operator_config,
    _profile_snapshot,
    _target_selection,
    execute_office_setup,
)

TENANT_ID = "11111111-2222-4333-8444-555555555555"
WORKSPACE_ID = "33333333-4444-4555-8666-777777777777"
OBJECT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
PROFILE_REF = "66666666-7777-4888-8999-aaaaaaaaaaaa"
SITE_ID = (
    "contoso.sharepoint.com,22222222-3333-4444-8555-666666666666,"
    "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
)


def _operator_value() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "actor": {
            "issuer": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            "subject": OBJECT_ID,
            "organizationId": "office-test-org",
            "workspaceId": WORKSPACE_ID,
        },
        "bindingRef": "office-owner-graph",
        "profileIdempotencyKey": "office-test-profile-key-0001",
    }


def _office_v2_scope() -> dict[str, object]:
    return {
        "schema_version": 2,
        "tenant_id": TENANT_ID,
        "workspace_id": WORKSPACE_ID,
        "planner": {"plan_ids": [], "tasks_read": True, "tasks_write": True},
        "sharepoint": {
            "enabled": True,
            "site_id": SITE_ID,
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
            "freebusy_read": True,
            "freebusy_subjects": ["person@dohorizon.com"],
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


def _office_host_profile() -> SimpleNamespace:
    office = SimpleNamespace(
        tenant_id=TENANT_ID,
        workspace_id=WORKSPACE_ID,
        enabled_features={
            "plannerEnabled": True,
            "todoEnabled": True,
            "calendarEnabled": True,
            "mailMetadataEnabled": False,
            "mailDraftsEnabled": False,
            "mailSendEnabled": False,
            "sharePointDriveMetadataEnabled": True,
        },
        targets={
            "plannerPlanIds": (),
            "sharePointSiteIds": (SITE_ID,),
            "sharePointListIds": (),
            "sharePointDriveIds": (),
            "toDoTaskListIds": (),
            "calendarIds": (),
            "mailFolderIds": (),
            "freebusySubjects": ("person@dohorizon.com",),
        },
    )
    return SimpleNamespace(
        profile_ref="office-owner-graph",
        provider="microsoft_graph",
        access_mode="actor_owned",
        expected_issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        organization_id="office-test-org",
        workspace_id=WORKSPACE_ID,
        microsoft_graph_office_v2=office,
    )


def _principal() -> IntegrationPrincipal:
    return IntegrationPrincipal(
        issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        subject=OBJECT_ID,
        organization_id="office-test-org",
        workspace_id=WORKSPACE_ID,
        allowed_operation_ids=frozenset(),
    )


def test_operator_config_requires_current_user_private_exact_file(tmp_path) -> None:
    config_path = tmp_path / "office-operator.json"
    config_path.write_text(json.dumps(_operator_value()), encoding="utf-8")
    config_path.chmod(0o600)

    parsed = _operator_config(config_path)

    assert parsed["schemaVersion"] == 1
    assert parsed["actor"]["subject"] == OBJECT_ID
    config_path.chmod(0o640)
    with pytest.raises(OfficeSetupError, match="office_operator_config_invalid"):
        _operator_config(config_path)


def test_operator_config_rejects_unknown_fields_and_symlinks(tmp_path) -> None:
    config_path = tmp_path / "office-operator.json"
    value = {**_operator_value(), "accessToken": "must-never-be-configured"}
    config_path.write_text(json.dumps(value), encoding="utf-8")
    config_path.chmod(0o600)
    with pytest.raises(OfficeSetupError, match="office_operator_config_invalid"):
        _operator_config(config_path)

    target = tmp_path / "real.json"
    target.write_text(json.dumps(_operator_value()), encoding="utf-8")
    target.chmod(0o600)
    config_path.unlink()
    config_path.symlink_to(target)
    with pytest.raises(OfficeSetupError, match="office_operator_config_invalid"):
        _operator_config(config_path)


def test_target_selection_is_exact_and_rejects_duplicates() -> None:
    selection = {
        "plannerPlanIds": [],
        "sharePointListIds": [],
        "sharePointDriveIds": [],
        "toDoTaskListIds": ["AAMk-list"],
        "calendarIds": [],
        "mailFolderIds": [],
        "freebusySubjects": [],
    }
    assert _target_selection(selection)["toDoTaskListIds"] == ["AAMk-list"]
    assert _target_selection({"mailFolderIds": []}) == {"mailFolderIds": []}

    with pytest.raises(OfficeSetupError, match="office_graph_target_selection_duplicate"):
        _target_selection({**selection, "toDoTaskListIds": ["AAMk-list", "AAMk-list"]})
    with pytest.raises(OfficeSetupError, match="office_graph_target_selection_invalid"):
        _target_selection({**selection, "calendarIds": ["*"]})
    with pytest.raises(OfficeSetupError, match="office_graph_target_selection_invalid"):
        _target_selection({})


def test_discovery_projection_never_returns_urls_or_content() -> None:
    projected = _discovery_item(
        "sharepoint_drives",
        {
            "drive_id": "b!opaque-drive-id",
            "name": "Documents",
            "site_id": SITE_ID,
            "drive_type": "documentLibrary",
            "web_url": "https://contoso.sharepoint.com/secret",
            "description": "private metadata must not leak",
        },
    )

    assert projected == {
        "id": "b!opaque-drive-id",
        "displayName": "Documents",
        "kind": "sharepoint_drive",
        "siteId": SITE_ID,
        "driveType": "documentLibrary",
    }

    folder = _discovery_item(
        "mail_folders",
        {
            "folder_id": "AAMkFolder-opaque==",
            "display_name": "Inbox",
            "parent_folder_id": "AAMkParent==",
            "total_item_count": 12,
            "web_url": "https://outlook.office.com/secret",
        },
    )
    assert folder == {
        "id": "AAMkFolder-opaque==",
        "displayName": "Inbox",
        "kind": "mail_folder",
    }


def test_mail_folder_scope_stays_inside_nonempty_host_allowlist() -> None:
    host_profile = _office_host_profile()
    host_profile.microsoft_graph_office_v2.enabled_features["mailMetadataEnabled"] = True
    host_profile.microsoft_graph_office_v2.targets["mailFolderIds"] = ("AAMkAllowed==",)
    scope = _office_v2_scope()
    scope["mail"] = {
        "enabled": True,
        "folder_ids": ["AAMkOther=="],
        "metadata_read": True,
        "body_read": False,
        "drafts_write": False,
        "send_enabled": False,
    }
    with pytest.raises(PermissionError, match="Mail folder target is outside host policy"):
        validate_microsoft_graph_office_v2_scope(host_profile, scope, _principal())


def test_profile_snapshot_exposes_health_and_scope_without_credentials() -> None:
    scope = _office_v2_scope()
    row = {
        "profile_ref": PROFILE_REF,
        "provider": "microsoft_graph",
        "auth_status": "healthy",
        "access_mode": "actor_owned",
        "external_subject": f"{TENANT_ID}:{OBJECT_ID}",
        "oauth_scopes": list(required_graph_permissions(scope)),
        "target_scope": scope,
        "credential_revision": 4,
        "expires_at": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "refresh_expires_at": int((datetime.now(UTC) + timedelta(days=60)).timestamp()),
        "access_token": "never-project-this",
        "refresh_token": "never-project-this-either",
    }

    snapshot = _profile_snapshot(PROFILE_REF, row, host_profile=_office_host_profile())

    assert snapshot["authStatus"] == "healthy"
    assert snapshot["scopeSchemaVersion"] == 2
    assert snapshot["credentialRevision"] == 4
    assert snapshot["reauthRequired"] is False
    assert snapshot["mailAuthorizationState"] == "DISABLED"
    assert snapshot["selectedTargets"]["mailFolderIds"] == []
    assert "access_token" not in snapshot and "refresh_token" not in snapshot
    assert "never-project-this" not in json.dumps(snapshot)


def test_v2_begin_payload_uses_exact_account_center_xor_contract() -> None:
    client = AccountCenterClient(None, exchange_signer=object(), binding_id="office-test")
    captured: list[tuple[str, dict[str, object]]] = []
    client._invoke_user = lambda method, _principal, payload: (
        captured.append((method, dict(payload))) or {}
    )

    client.begin_microsoft_graph_link(
        _principal(),
        profile_ref=PROFILE_REF,
        planner_plan_ids=[],
        idempotency_key="office-begin-test-key",
        office_v2_scope=_office_v2_scope(),
    )
    assert captured[-1][1] == {
        "profile_ref": PROFILE_REF,
        "idempotency_key": "office-begin-test-key",
        "office_v2_scope": _office_v2_scope(),
    }

    client.begin_microsoft_graph_link(
        _principal(),
        profile_ref=PROFILE_REF,
        planner_plan_ids=["plan-1"],
        idempotency_key="office-v1-test-key",
    )
    assert captured[-1][1] == {
        "profile_ref": PROFILE_REF,
        "idempotency_key": "office-v1-test-key",
        "planner_plan_ids": ["plan-1"],
    }


def test_account_center_mail_scope_upgrade_uses_fixed_features_only() -> None:
    client = AccountCenterClient(None, exchange_signer=object(), binding_id="office-test")
    captured: list[tuple[str, dict[str, object]]] = []
    client._invoke_user = lambda method, _principal, payload: (
        captured.append((method, dict(payload))) or {}
    )
    client.begin_microsoft_graph_scope_upgrade(
        _principal(),
        profile_ref=PROFILE_REF,
        permission="mail",
        mail_features={"metadata_read": True, "drafts_write": False, "send": True},
        idempotency_key="office-mail-upgrade-test",
    )
    assert captured == [
        (
            "begin_microsoft_graph_scope_upgrade",
            {
                "profile_ref": PROFILE_REF,
                "permission": "mail",
                "idempotency_key": "office-mail-upgrade-test",
                "mail_features": {"metadata_read": True, "drafts_write": False, "send": True},
            },
        )
    ]
    with pytest.raises(ValueError, match="features are invalid"):
        client.begin_microsoft_graph_scope_upgrade(
            _principal(),
            profile_ref=PROFILE_REF,
            permission="planner_tasks_write",
            mail_features={"metadata_read": True, "drafts_write": False, "send": False},
            idempotency_key="invalid-mail-feature-upgrade",
        )


def test_typed_account_mail_upgrade_builds_nested_pinned_sdk_dto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = ModuleType("cyrene_account_center_contracts")

    @dataclass
    class MailFeatures:
        metadata_read: bool
        drafts_write: bool
        send: bool

    class Permission(StrEnum):
        MAIL = "mail"

    @dataclass
    class BeginScopeUpgrade:
        profile_ref: str
        permission: Permission
        idempotency_key: str
        mail_features: MailFeatures | None = None

    module.BeginMicrosoftGraphScopeUpgradeRequest = BeginScopeUpgrade
    module.MicrosoftGraphMailFeatures = MailFeatures
    module.MicrosoftGraphPermissionUpgrade = Permission
    for name in (
        "BeginLinkRequest",
        "CompleteGitHubLinkRequest",
        "ConfirmWeComLinkRequest",
        "CreateCredentialLeaseRequest",
        "GetAuthorizationRequest",
        "ListLinksRequest",
        "ObserveWeComChallengeRequest",
        "ResolveLinkedSenderRequest",
        "UnlinkRequest",
    ):
        setattr(module, name, object)
    module.Resource = object
    monkeypatch.setitem(sys.modules, "cyrene_account_center_contracts", module)

    payload = _typed_account_payload(
        "begin_microsoft_graph_scope_upgrade",
        {
            "profile_ref": PROFILE_REF,
            "permission": "mail",
            "idempotency_key": "office-mail-upgrade-test",
            "mail_features": {"metadata_read": True, "drafts_write": False, "send": True},
        },
    )
    assert payload == {
        "profile_ref": PROFILE_REF,
        "permission": "mail",
        "idempotency_key": "office-mail-upgrade-test",
        "mail_features": {"metadata_read": True, "drafts_write": False, "send": True},
    }


def test_installed_account_center_sdk_serializes_exact_graph_v1_v2_and_cas_requests() -> None:
    v1 = _typed_account_payload(
        "begin_microsoft_graph_link",
        {
            "profile_ref": PROFILE_REF,
            "planner_plan_ids": ["plan-1"],
            "idempotency_key": "office-v1-test-key",
        },
    )
    assert v1 == {
        "profile_ref": PROFILE_REF,
        "planner_plan_ids": ["plan-1"],
        "idempotency_key": "office-v1-test-key",
    }

    v2 = _typed_account_payload(
        "begin_microsoft_graph_link",
        {
            "profile_ref": PROFILE_REF,
            "office_v2_scope": _office_v2_scope(),
            "idempotency_key": "office-v2-test-key",
        },
    )
    assert v2 == {
        "profile_ref": PROFILE_REF,
        "office_v2_scope": _office_v2_scope(),
        "idempotency_key": "office-v2-test-key",
    }

    cas = _typed_account_payload(
        "update_microsoft_graph_v2_scope",
        {
            "profile_ref": PROFILE_REF,
            "workspace_id": WORKSPACE_ID,
            "expected_credential_revision": 0,
            "target_scope": _office_v2_scope(),
            "idempotency_key": "office-v2-cas-test-key",
        },
    )
    assert cas == {
        "profile_ref": PROFILE_REF,
        "workspace_id": WORKSPACE_ID,
        "expected_credential_revision": 0,
        "target_scope": _office_v2_scope(),
        "idempotency_key": "office-v2-cas-test-key",
    }


def test_office_v2_authorization_url_requires_registered_loopback_callback() -> None:
    expires_at = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    session = {
        "link_session_ref": str(uuid4()),
        "expires_at": expires_at,
        "authorization_url": (
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize?"
            "response_type=code&redirect_uri=https%3A%2F%2Fexchange.example%2Fcallback"
        ),
    }

    with pytest.raises(ExchangeProductError, match="outside the fixed route"):
        _microsoft_graph_oauth_session_response(
            session,
            profile_ref=PROFILE_REF,
            expected_redirect_uri="http://localhost:52191/oauth/callback",
        )


def test_synthetic_office_setup_begin_complete_discover_cas_status_chain(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_profile = _office_host_profile()
    principal = _principal()
    profile_ref = PROFILE_REF
    scope = _office_v2_scope()
    graph_scopes = list(required_graph_permissions(scope))
    profile: dict[str, object] | None = None
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeAccounts:
        def begin_microsoft_graph_link(self, _principal, **kwargs):
            assert kwargs["office_v2_scope"] == scope
            assert kwargs["planner_plan_ids"] == []
            calls.append(("begin", dict(kwargs)))
            query = urlencode(
                {
                    "client_id": "office-test-client",
                    "response_type": "code",
                    "response_mode": "query",
                    "redirect_uri": "http://localhost:52191/oauth/callback",
                    "scope": "openid profile offline_access " + " ".join(graph_scopes),
                    "state": "synthetic-office-state-1234567890",
                    "code_challenge": "A" * 43,
                    "code_challenge_method": "S256",
                }
            )
            return {
                "link_session_ref": str(uuid4()),
                "authorization_url": (
                    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize?{query}"
                ),
                "expires_at": int((datetime.now(UTC) + timedelta(minutes=10)).timestamp()),
            }

        def complete_microsoft_graph_link(self, _principal, *, state, code):
            nonlocal profile
            assert state == "synthetic-office-state-1234567890"
            assert code == "synthetic-office-code"
            calls.append(("complete", {"state": state, "code": code}))
            profile = {
                "profile_ref": profile_ref,
                "provider": "microsoft_graph",
                "identity_ref": f"{TENANT_ID}:{OBJECT_ID}",
                "external_subject": f"{TENANT_ID}:{OBJECT_ID}",
                "auth_status": "healthy",
                "auth_mode": "delegated_oauth",
                "access_mode": "actor_owned",
                "workspace_id": WORKSPACE_ID,
                "expires_at": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
                "refresh_expires_at": None,
                "oauth_scopes": graph_scopes,
                "credential_revision": 0,
                "target_scope": scope,
                "access_token": "never-return-this",
                "refresh_token": "never-return-this-either",
            }
            raise RuntimeError("simulated lost completion acknowledgement")

        def list_provider_profiles(self, _principal):
            return {"profiles": [profile] if profile is not None else []}

        def update_microsoft_graph_v2_scope(
            self,
            _principal,
            *,
            profile_ref,
            workspace_id,
            expected_credential_revision,
            target_scope,
            idempotency_key,
        ):
            nonlocal profile
            assert profile is not None
            assert profile_ref == PROFILE_REF
            assert workspace_id == WORKSPACE_ID
            assert expected_credential_revision == 0
            assert idempotency_key.startswith("office-targets:")
            calls.append(("select-targets", {"revision": expected_credential_revision}))
            profile["target_scope"] = target_scope
            profile["credential_revision"] = 1
            raise RuntimeError("simulated lost CAS acknowledgement")

    accounts = FakeAccounts()
    services = SimpleNamespace(
        accounts=accounts,
        callback_principal=principal,
    )
    monkeypatch.setattr(
        "cyrene_exchange_product.integrations.office_setup._operator_context",
        lambda *_args: (principal, host_profile, profile_ref),
    )
    monkeypatch.setattr(
        "cyrene_exchange_product.integrations.office_setup._ensure_connection",
        lambda *_args: None,
    )

    discovery = {
        "microsoft_graph.planner.plans.list": [{"plan_id": "plan-selected", "title": "Operations"}],
        "microsoft_graph.todo.lists.list": [
            {"task_list_id": "todo-selected", "display_name": "My tasks"}
        ],
        "microsoft_graph.calendar.calendars.list": [
            {"calendar_id": "calendar-selected", "name": "Calendar"}
        ],
        "microsoft_graph.sharepoint.drives.list": [
            {
                "drive_id": "drive-selected",
                "name": "Documents",
                "site_id": host_profile.microsoft_graph_office_v2.targets["sharePointSiteIds"][0],
                "drive_type": "documentLibrary",
            }
        ],
    }
    monkeypatch.setattr(
        "cyrene_exchange_product.integrations.office_setup._invoke_read_operation",
        lambda _services, *, operation_id, **_kwargs: {
            "items": discovery[operation_id],
            "page_cursor": None,
            "next_cursor": None,
            "complete": True,
            "truncated": False,
        },
    )

    config_path = tmp_path / "office-operator.json"
    config_path.write_text(json.dumps(_operator_value()), encoding="utf-8")
    config_path.chmod(0o600)

    unlinked = execute_office_setup(
        services,
        action="status",
        private_config=config_path,
    )
    assert unlinked["state"] == "NOT_LINKED"
    assert unlinked["targetScope"] is None
    assert set(unlinked["selectedTargets"]) == {
        "plannerPlanIds",
        "sharePointListIds",
        "sharePointDriveIds",
        "toDoTaskListIds",
        "calendarIds",
        "freebusySubjects",
        "mailFolderIds",
    }
    assert unlinked["selectedTargets"]["mailFolderIds"] == []
    assert unlinked["enabledFeatures"]["mailSendEnabled"] is False

    begun = execute_office_setup(
        services,
        action="begin",
        private_config=config_path,
        request_payload={"requestId": str(uuid4())},
    )
    assert begun["state"] == "AUTHORIZATION_REQUIRED"
    assert begun["profileRef"] == PROFILE_REF

    completed = execute_office_setup(
        services,
        action="complete",
        private_config=config_path,
        request_payload={
            "state": "synthetic-office-state-1234567890",
            "code": "synthetic-office-code",
        },
    )
    assert completed["state"] == "LINKED"
    assert completed["credentialRevision"] == 0
    assert "never-return-this" not in json.dumps(completed)

    for resource_type in (
        "planner_plans",
        "todo_lists",
        "sharepoint_drives",
        "calendars",
        "freebusy_subjects",
    ):
        page = execute_office_setup(
            services,
            action="discover",
            private_config=config_path,
            request_payload={"resourceType": resource_type},
        )
        assert page["state"] == "DISCOVERED"
        assert page["complete"] is True
        assert page["credentialRevision"] == 0
        if resource_type == "sharepoint_drives":
            assert (
                page["siteId"]
                == host_profile.microsoft_graph_office_v2.targets["sharePointSiteIds"][0]
            )

    selected = execute_office_setup(
        services,
        action="select-targets",
        private_config=config_path,
        request_payload={
            "expectedCredentialRevision": 0,
            "targets": {
                "plannerPlanIds": ["plan-selected"],
                "sharePointListIds": [],
                "sharePointDriveIds": ["drive-selected"],
                "toDoTaskListIds": ["todo-selected"],
                "calendarIds": ["calendar-selected"],
                "mailFolderIds": [],
                "freebusySubjects": ["person@dohorizon.com"],
            },
        },
    )
    assert selected["state"] == "UPDATED"
    assert selected["credentialRevision"] == 1

    final = execute_office_setup(
        services,
        action="status",
        private_config=config_path,
    )
    assert final["state"] == "LINKED"
    assert final["credentialRevision"] == 1
    assert final["targetScope"]["planner"]["planIds"] == ["plan-selected"]
    assert final["targetScope"]["todo"]["taskListIds"] == ["todo-selected"]
    assert final["targetScope"]["calendar"]["calendarIds"] == ["calendar-selected"]
    assert "never-return-this" not in json.dumps(final)
    assert [name for name, _ in calls] == ["begin", "complete", "select-targets"]


def test_mail_upgrade_is_explicit_host_derived_and_keeps_old_profile_until_complete(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_profile = _office_host_profile()
    host_profile.microsoft_graph_office_v2.enabled_features.update(
        {
            "mailMetadataEnabled": True,
            "mailDraftsEnabled": True,
            "mailSendEnabled": True,
        }
    )
    principal = _principal()
    old_scope = _office_v2_scope()
    current_scope = {
        **old_scope,
        "mail": {
            "enabled": True,
            "folder_ids": [],
            "metadata_read": True,
            "body_read": False,
            "drafts_write": True,
            "send_enabled": True,
        },
    }
    profile: dict[str, object] = {
        "profile_ref": PROFILE_REF,
        "provider": "microsoft_graph",
        "identity_ref": f"{TENANT_ID}:{OBJECT_ID}",
        "external_subject": f"{TENANT_ID}:{OBJECT_ID}",
        "auth_status": "healthy",
        "auth_mode": "delegated_oauth",
        "access_mode": "actor_owned",
        "workspace_id": WORKSPACE_ID,
        "expires_at": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "refresh_expires_at": None,
        "credential_revision": 4,
        "oauth_scopes": list(required_graph_permissions(old_scope)),
        "target_scope": old_scope,
        "access_token": "never-return-this",
        "refresh_token": "never-return-this-either",
    }
    old_scope_before = json.loads(json.dumps(profile["target_scope"]))
    old_scopes_before = list(profile["oauth_scopes"])
    calls: list[tuple[str, object]] = []

    class FakeAccounts:
        def list_provider_profiles(self, _principal):
            return {"profiles": [profile]}

        def begin_microsoft_graph_scope_upgrade(self, _principal, **kwargs):
            assert kwargs["profile_ref"] == PROFILE_REF
            assert kwargs["permission"] == "mail"
            assert kwargs["mail_features"] == {
                "metadata_read": True,
                "drafts_write": True,
                "send": True,
            }
            assert kwargs["idempotency_key"].startswith("office-graph-mail-upgrade:")
            calls.append(("begin-upgrade", kwargs))
            query = urlencode(
                {
                    "client_id": "office-test-client",
                    "response_type": "code",
                    "response_mode": "query",
                    "redirect_uri": "http://localhost:52191/oauth/callback",
                    "scope": "openid profile offline_access "
                    + " ".join(required_graph_permissions(current_scope)),
                    "state": "synthetic-mail-upgrade-state-1234567890",
                    "code_challenge": "A" * 43,
                    "code_challenge_method": "S256",
                }
            )
            return {
                "link_session_ref": str(uuid4()),
                "authorization_url": (
                    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize?{query}"
                ),
                "expires_at": int((datetime.now(UTC) + timedelta(minutes=10)).timestamp()),
            }

        def complete_microsoft_graph_scope_upgrade(self, _principal, *, state, code):
            assert state == "synthetic-mail-upgrade-state-1234567890"
            assert code == "synthetic-mail-upgrade-code"
            calls.append(("complete-upgrade", {"state": state, "code": code}))
            profile["target_scope"] = current_scope
            profile["oauth_scopes"] = list(required_graph_permissions(current_scope))
            profile["credential_revision"] = 5
            return profile

        def update_microsoft_graph_v2_scope(
            self,
            _principal,
            *,
            profile_ref,
            workspace_id,
            expected_credential_revision,
            target_scope,
            idempotency_key,
        ):
            assert profile_ref == PROFILE_REF
            assert workspace_id == WORKSPACE_ID
            assert expected_credential_revision == profile["credential_revision"]
            assert idempotency_key.startswith("office-targets:")
            calls.append(("select-targets", {"revision": expected_credential_revision}))
            profile["target_scope"] = target_scope
            profile["credential_revision"] = expected_credential_revision + 1
            return profile

    services = SimpleNamespace(accounts=FakeAccounts(), callback_principal=principal)
    monkeypatch.setattr(
        "cyrene_exchange_product.integrations.office_setup._operator_context",
        lambda *_args: (principal, host_profile, PROFILE_REF),
    )
    monkeypatch.setattr(
        "cyrene_exchange_product.integrations.office_setup._ensure_connection",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        "cyrene_exchange_product.integrations.office_setup._invoke_read_operation",
        lambda _services, *, operation_id, **_kwargs: {
            "items": (
                [{"folder_id": "AAMkInbox-opaque==", "display_name": "Inbox"}]
                if operation_id == "microsoft_graph.mail.folders.list"
                else []
            ),
            "page_cursor": None,
            "next_cursor": None,
            "complete": True,
            "truncated": False,
        },
    )
    config_path = tmp_path / "office-operator.json"
    config_path.write_text(json.dumps(_operator_value()), encoding="utf-8")
    config_path.chmod(0o600)

    before = execute_office_setup(services, action="status", private_config=config_path)
    assert before["state"] == "LINKED"
    assert before["mailAuthorizationState"] == "REAUTHORIZATION_REQUIRED"
    assert before["enabledFeatures"]["mailMetadataEnabled"] is False

    with pytest.raises(OfficeSetupError, match="office_setup_request_fields_invalid"):
        execute_office_setup(
            services,
            action="begin-mail-scope-upgrade",
            private_config=config_path,
            request_payload={"permission": "mail", "mail_features": {"send": True}},
        )
    begun = execute_office_setup(
        services,
        action="begin-mail-scope-upgrade",
        private_config=config_path,
        request_payload={"requestId": str(uuid4())},
    )
    assert begun["state"] == "AUTHORIZATION_REQUIRED"
    assert begun["flowKind"] == "scope_upgrade"
    assert begun["profileRef"] == PROFILE_REF
    assert "never-return-this" not in json.dumps(begun)
    assert profile["target_scope"] == old_scope_before
    assert profile["oauth_scopes"] == old_scopes_before

    completed = execute_office_setup(
        services,
        action="complete-scope-upgrade",
        private_config=config_path,
        request_payload={
            "state": "synthetic-mail-upgrade-state-1234567890",
            "code": "synthetic-mail-upgrade-code",
        },
    )
    assert completed["state"] == "LINKED"
    assert completed["mailAuthorizationState"] == "READY"
    assert completed["credentialRevision"] == 5
    discovered = execute_office_setup(
        services,
        action="discover",
        private_config=config_path,
        request_payload={"resourceType": "mail_folders"},
    )
    assert discovered["items"] == [
        {"id": "AAMkInbox-opaque==", "displayName": "Inbox", "kind": "mail_folder"}
    ]
    selected = execute_office_setup(
        services,
        action="select-targets",
        private_config=config_path,
        request_payload={
            "expectedCredentialRevision": 5,
            "targets": {"mailFolderIds": ["AAMkInbox-opaque=="]},
        },
    )
    assert selected["state"] == "UPDATED"
    assert selected["selectedCounts"]["mailFolders"] == 1
    assert selected["selectedTargets"]["mailFolderIds"] == ["AAMkInbox-opaque=="]
    assert selected["selectedTargets"]["freebusySubjects"] == ["person@dohorizon.com"]
    assert selected["credentialRevision"] == 6

    cleared = execute_office_setup(
        services,
        action="select-targets",
        private_config=config_path,
        request_payload={
            "expectedCredentialRevision": 6,
            "targets": {"mailFolderIds": []},
        },
    )
    assert cleared["state"] == "UPDATED"
    assert cleared["selectedCounts"]["mailFolders"] == 0
    assert cleared["selectedTargets"]["mailFolderIds"] == []
    assert cleared["selectedTargets"]["freebusySubjects"] == ["person@dohorizon.com"]
    assert cleared["credentialRevision"] == 7
    assert [name for name, _ in calls] == [
        "begin-upgrade",
        "complete-upgrade",
        "select-targets",
        "select-targets",
    ]
