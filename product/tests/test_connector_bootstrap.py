"""Private host-side bootstrap behavior without live provider credentials."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cyrene_exchange_product.cli import parser
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.bootstrap import (
    _verify_profile_readback,
    provision_connector_profiles,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationConflict,
    IntegrationNotFound,
    IntegrationPrincipal,
)
from cyrene_exchange_product.integrations.store import IntegrationStore

ISSUER = "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0"
SUBJECT = "11111111-1111-4111-8111-111111111111"


class _Authority:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def authorize_connector_operation(self, **kwargs: Any) -> bytes:
        self.requests.append(kwargs)
        return b"signed-directory-role-proof"


class _Verifier:
    def __init__(self, *, deny: bool = False) -> None:
        self.deny = deny
        self.expected: dict[str, Any] | None = None
        self.consumed = 0

    def validate_authority_response(
        self,
        _grant: bytes,
        *,
        expected: dict[str, Any],
    ) -> None:
        self.expected = expected
        if self.deny:
            raise PermissionError("Directory role missing")

    def consume(self, _grant: bytes, *, expected: dict[str, Any]) -> Any:
        assert self.expected == expected
        self.consumed += 1
        return SimpleNamespace(
            principal_issuer=expected["principal_issuer"],
            principal_subject=expected["principal_subject"],
            organization_id=expected["organization_id"],
            workspace_id=expected["workspace_id"],
        )


class _AccountCenter:
    def __init__(self, *, access_mode: str = "workspace_operator") -> None:
        self.links: dict[str, dict[str, str]] = {}
        self.github_repositories: list[dict[str, str]] = []
        self.hf_credential_ref: str | None = None
        self.access_mode = access_mode

    def link_github_app_installation(
        self,
        _principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        installation_id: str,
        repositories: list[dict[str, str]],
        idempotency_key: str,
    ) -> dict[str, str]:
        assert installation_id == "12345678"
        assert idempotency_key == "phase1-github-installation"
        self.github_repositories = repositories
        self.links[profile_ref] = {
            "profile_ref": profile_ref,
            "provider": "github",
            "auth_status": "healthy",
            "access_mode": self.access_mode,
        }
        return self.links[profile_ref]

    def link_huggingface_profile(
        self,
        _principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        credential_secret_ref: str,
        scopes: dict[str, Any],
        idempotency_key: str,
        auth_mode: str | None = None,
    ) -> dict[str, str]:
        assert credential_secret_ref == "huggingface/connector-token"
        assert idempotency_key == "phase1-huggingface-primary"
        assert scopes["repositories"][0]["repo_id"] == "example-org/private-model"
        self.hf_credential_ref = credential_secret_ref
        self.links[profile_ref] = {
            "profile_ref": profile_ref,
            "provider": "huggingface",
            "auth_status": "healthy",
            "access_mode": self.access_mode,
        }
        if auth_mode is not None:
            self.links[profile_ref]["auth_mode"] = auth_mode
        return self.links[profile_ref]

    def list_provider_profiles(self, _principal: IntegrationPrincipal) -> dict[str, Any]:
        return {"profiles": list(self.links.values())}


def _private_specification() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "actor": {
            "issuer": ISSUER,
            "subject": SUBJECT,
            "organizationId": "org-test",
            "workspaceId": "workspace-test",
        },
        "github": {
            "installationId": "12345678",
            "expectedAccessMode": "workspace_operator",
            "profileIdempotencyKey": "phase1-github-installation",
            "repositories": [
                {"repositoryId": "123", "owner": "example-org", "name": "private-repo"}
            ],
        },
        "huggingface": {
            "profileAlias": "hf-primary",
            "targetAlias": "hf-primary-target",
            "expectedAccessMode": "workspace_operator",
            "profileIdempotencyKey": "phase1-huggingface-primary",
            "credentialSecretRef": "huggingface/connector-token",
        },
    }


def _services(
    tmp_path: Path,
    *,
    deny: bool = False,
) -> tuple[Any, IntegrationStore, _Authority, _Verifier, _AccountCenter]:
    store = IntegrationStore(tmp_path / "bootstrap.sqlite3")
    authority = _Authority()
    verifier = _Verifier(deny=deny)
    accounts = _AccountCenter()
    hf_profile = SimpleNamespace(
        provider="hf",
        credential_secret_ref="huggingface/connector-token",
        account_scopes={
            "repositories": [
                {
                    "repo_type": "model",
                    "repo_id": "example-org/private-model",
                    "permissions": ["read", "write"],
                }
            ]
        },
        targets={"hf-primary-target": SimpleNamespace(display_name="Private model scope")},
        organization_id="org-test",
        workspace_id="workspace-test",
        expected_issuer=ISSUER,
        allowed_actors=frozenset({(ISSUER, SUBJECT)}),
        auth_mode=None,
        access_mode="workspace_operator",
    )
    services = SimpleNamespace(
        store=store,
        connector_grant_authority=authority,
        connector_grant_verifier=verifier,
        authorization_profile_registry=SimpleNamespace(
            settings=SimpleNamespace(profiles={"hf-primary": hf_profile})
        ),
        accounts=accounts,
        teams_message_profile=SimpleNamespace(
            expected_issuer=ISSUER,
            organization_id="org-test",
            workspace_id="workspace-test",
        ),
    )
    return services, store, authority, verifier, accounts


def test_private_bootstrap_verifies_directory_role_and_is_idempotent(tmp_path: Path) -> None:
    specification_path = tmp_path / "bootstrap.json"
    specification_path.write_text(json.dumps(_private_specification()), encoding="utf-8")
    specification_path.chmod(0o600)
    services, store, authority, verifier, accounts = _services(tmp_path)
    try:
        first = provision_connector_profiles(services, specification_path)
        second = provision_connector_profiles(services, specification_path)

        assert first == second
        assert first["directoryRoleVerified"] is True
        assert len(first["github"]["connections"]) == 1
        assert first["github"]["connections"][0]["connectionRef"]
        assert first["huggingface"]["connectionRef"]
        assert verifier.consumed == 2
        assert len(authority.requests) == 2
        assert authority.requests[0]["operation_id"] == "github.repository.list"
        assert authority.requests[0]["provider_id"] == "github"
        connections = store.connector_bindings_for_actor(
            issuer=ISSUER,
            subject=SUBJECT,
            workspace_id="workspace-test",
        )
        assert len(connections) == 2
        assert {connection.access_mode for connection in connections} == {"workspace_operator"}
        shared = store.connector_connection_for_actor(
            connections[0].id,
            issuer=ISSUER,
            subject="another-directory-operator",
            workspace_id="workspace-test",
            organization_id="org-test",
        )
        assert shared.id == connections[0].id
        with pytest.raises(IntegrationNotFound):
            store.connector_connection_for_actor(
                connections[0].id,
                issuer="https://login.microsoftonline.com/another-tenant/v2.0",
                subject="another-directory-operator",
                workspace_id="workspace-test",
                organization_id="org-test",
            )
        with pytest.raises(IntegrationNotFound):
            store.connector_connection_for_actor(
                connections[0].id,
                issuer=ISSUER,
                subject="another-directory-operator",
                workspace_id="workspace-test",
                organization_id="another-org",
            )
        with pytest.raises(IntegrationNotFound):
            store.connector_connection_for_actor(
                connections[0].id,
                issuer=ISSUER,
                subject="another-directory-operator",
                workspace_id="other-workspace",
                organization_id="org-test",
            )
        assert accounts.hf_credential_ref == "huggingface/connector-token"
        encoded_result = json.dumps(first).lower()
        assert "credentialsecretref" not in encoded_result
        assert "access_token" not in encoded_result
        assert first["huggingface"]["authMode"] == "fine_grained_token"
    finally:
        store.close()


def test_plan_only_verifies_role_without_linking_profiles_or_saving_connections(
    tmp_path: Path,
) -> None:
    specification_path = tmp_path / "bootstrap-plan.json"
    specification_path.write_text(json.dumps(_private_specification()), encoding="utf-8")
    specification_path.chmod(0o600)
    services, store, authority, verifier, accounts = _services(tmp_path)
    try:
        result = provision_connector_profiles(services, specification_path, plan_only=True)

        assert result["directoryRoleVerified"] is True
        assert result["profiles"]["github"]["expectedAccessMode"] == "workspace_operator"
        assert result["profiles"]["github"]["connections"][0]["connectionRef"]
        assert result["profiles"]["huggingface"]["expectedAccessMode"] == "workspace_operator"
        assert result["profiles"]["huggingface"]["connectionRef"]
        assert verifier.consumed == 1
        assert len(authority.requests) == 1
        assert accounts.links == {}
        assert (
            store.connector_bindings_for_actor(
                issuer=ISSUER,
                subject=SUBJECT,
                workspace_id="workspace-test",
            )
            == []
        )
    finally:
        store.close()


def test_bootstrap_cli_exposes_private_plan_only_mode() -> None:
    arguments = parser().parse_args(
        [
            "integrations",
            "bootstrap-connectors",
            "--integration-database",
            "/tmp/exchange.sqlite3",
            "--private-config",
            "/tmp/private-bootstrap.json",
            "--plan-only",
        ]
    )

    assert arguments.plan_only is True


def test_profile_readback_requires_configured_access_mode() -> None:
    response = {
        "profiles": [
            {
                "profile_ref": "gh-profile",
                "provider": "github",
                "auth_status": "healthy",
                "access_mode": "workspace_operator",
            }
        ]
    }

    assert (
        _verify_profile_readback(
            response,
            profile_ref="gh-profile",
            provider="github",
            expected_access_mode="workspace_operator",
        )
        == "workspace_operator"
    )
    with pytest.raises(ExchangeProductError):
        _verify_profile_readback(
            response,
            profile_ref="gh-profile",
            provider="github",
            expected_access_mode="actor_owned",
        )


def test_connection_idempotency_cannot_reuse_a_different_access_mode(
    tmp_path: Path,
) -> None:
    store = IntegrationStore(tmp_path / "access-mode-idempotency.sqlite3")
    principal = IntegrationPrincipal(
        issuer=ISSUER,
        subject=SUBJECT,
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )
    request = CreateIntegrationConnection(
        provider="github",
        account_link_ref="gh-profile",
        repository_id="123",
        repository_name="example-org/shared-repo",
    )
    try:
        store.create_connection(
            principal,
            request,
            idempotency_key="same-profile-mode-key",
        )
        with pytest.raises(IntegrationConflict, match="access mode changed"):
            store.create_connection(
                principal,
                request,
                idempotency_key="same-profile-mode-key",
                access_mode="workspace_operator",
            )
    finally:
        store.close()


def test_legacy_github_issue_connection_remains_actor_owned_and_outside_app_profiles() -> None:
    services = object.__new__(IntegrationServices)
    principal = IntegrationPrincipal(
        issuer=ISSUER,
        subject=SUBJECT,
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )
    legacy = CreateIntegrationConnection(
        provider="github",
        repository_id="123",
        repository_name="example-org/legacy-repository",
    )

    assert services.display_name_for_connection(principal, legacy) == legacy.repository_name
    assert services.access_mode_for_connection(principal, legacy) == "actor_owned"

    app_profile_request = legacy.model_copy(update={"binding_ref": "github-app-profile"})
    with pytest.raises(ExchangeProductError) as captured:
        services.display_name_for_connection(principal, app_profile_request)
    assert captured.value.code == "EXCHANGE_ACCOUNT_PROVIDER_PROFILE_REQUIRED"


def test_huggingface_access_mode_uses_account_centers_canonical_provider_id() -> None:
    class Accounts:
        def list_provider_profiles(self, _principal: IntegrationPrincipal) -> dict[str, Any]:
            return {
                "profiles": [
                    {
                        "profile_ref": "hf-profile",
                        "provider": "huggingface",
                        "auth_status": "healthy",
                        "access_mode": "workspace_operator",
                        "target_scope": {
                            "repositories": [{"repo_id": "example-org/private-model"}]
                        },
                    }
                ]
            }

    principal = IntegrationPrincipal(
        issuer=ISSUER,
        subject=SUBJECT,
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )
    services = IntegrationServices(
        store=None,
        authorizer=None,
        accounts=Accounts(),
        github=None,
        webhook_verifier=None,
        delegation_authorizer=None,
        callback_principal=principal,
        connection_profile_resolver=lambda _principal, _request: "Private model",
        authorization_profile_registry=SimpleNamespace(
            settings=SimpleNamespace(
                profiles={
                    "hf-primary": SimpleNamespace(
                        access_mode="workspace_operator",
                        provider="hf",
                        targets={
                            "hf-scope": SimpleNamespace(
                                target_ref="example-org/private-model",
                                display_name="Private model",
                            )
                        },
                    )
                }
            )
        ),
    )
    request = CreateIntegrationConnection(
        provider="hf",
        binding_ref="hf-primary",
        target_ref="hf-scope",
        account_link_ref="hf-profile",
    )

    assert services.display_name_for_connection(principal, request) == "Private model"
    assert services.access_mode_for_connection(principal, request) == "workspace_operator"


def test_private_bootstrap_fails_before_account_center_side_effect_without_directory_role(
    tmp_path: Path,
) -> None:
    specification_path = tmp_path / "bootstrap.json"
    specification_path.write_text(json.dumps(_private_specification()), encoding="utf-8")
    specification_path.chmod(0o600)
    services, store, _authority, _verifier, accounts = _services(tmp_path, deny=True)
    try:
        with pytest.raises(PermissionError):
            provision_connector_profiles(services, specification_path)
        assert accounts.links == {}
        assert (
            store.connector_bindings_for_actor(
                issuer=ISSUER,
                subject=SUBJECT,
                workspace_id="workspace-test",
            )
            == []
        )
    finally:
        store.close()


def test_private_bootstrap_can_provision_github_only_while_hf_oauth_is_pending(
    tmp_path: Path,
) -> None:
    specification = _private_specification()
    specification.pop("huggingface")
    specification_path = tmp_path / "bootstrap-github-only.json"
    specification_path.write_text(json.dumps(specification), encoding="utf-8")
    specification_path.chmod(0o600)
    services, store, _authority, _verifier, accounts = _services(tmp_path)
    services.authorization_profile_registry = None
    try:
        result = provision_connector_profiles(services, specification_path)
        assert "huggingface" not in result
        assert result["github"]["connections"]
        assert accounts.hf_credential_ref is None
    finally:
        store.close()


def test_private_bootstrap_rejects_group_readable_operator_files(tmp_path: Path) -> None:
    specification_path = tmp_path / "bootstrap.json"
    specification_path.write_text(json.dumps(_private_specification()), encoding="utf-8")
    specification_path.chmod(0o644)
    services, store, _authority, _verifier, accounts = _services(tmp_path)
    try:
        with pytest.raises(ExchangeProductError):
            provision_connector_profiles(services, specification_path)
        assert accounts.links == {}
    finally:
        store.close()
