"""Focused isolation and lease tests for fixed Azure DevOps reads."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.authorization_cloud_provider import (
    _raise_azure_devops_provider_error,
)
from cyrene_exchange_product.integrations.azure_devops import (
    targets_for_operation,
    validate_profile_identity,
)
from cyrene_exchange_product.integrations.clients import IntegrationAccountCenterPort
from cyrene_exchange_product.integrations.connector_operations import (
    ConnectorOperationDispatcher,
    _resource_ref,
)
from cyrene_exchange_product.integrations.connector_security import digest_arguments
from cyrene_exchange_product.integrations.models import IntegrationConnection, IntegrationPrincipal
from cyrene_exchange_product.integrations.ports import ProviderCredentialLeaseEvidence

TENANT_ID = "11111111-2222-4333-8444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa"
PROFILE_REF = "66666666-7777-4888-8999-aaaaaaaaaaaa"
CONNECTION_ID = UUID("99999999-aaaa-4bbb-8ccc-dddddddddddd")
SOURCE_ID = "pipeline-source-a"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
ORGANIZATION_ID = "ado-org"
WORKSPACE_ID = "ado-workspace"
BINDING_ID = "ado-provider-binding"
OPERATION_ID = "azure_devops.pipeline_runs.list"


def _scope(*, source_id: str = SOURCE_ID) -> dict[str, object]:
    return {
        "tenant_id": TENANT_ID,
        "organization": "contoso",
        "project_id": "22222222-3333-4444-8555-666666666666",
        "source_id": source_id,
        "source_kind": "pipeline_runs",
        "pipeline_id": 31,
    }


def _release_scope() -> dict[str, object]:
    return {
        "tenant_id": TENANT_ID,
        "organization": "contoso",
        "project_id": "22222222-3333-4444-8555-666666666666",
        "source_id": "release-source-a",
        "source_kind": "release_deployments",
        "definition_id": 51,
        "definition_environment_id": 6,
    }


def _source(*, profile_ref: str = PROFILE_REF):
    return SimpleNamespace(
        source_id=SOURCE_ID,
        kind="pipeline_runs",
        project_id="22222222-3333-4444-8555-666666666666",
        project_name="Builds",
        profile_ref=profile_ref,
        pipeline_id=31,
        definition_id=None,
        definition_environment_id=None,
    )


def _profile(
    *,
    subject: str = OBJECT_ID,
    auth_status: str = "healthy",
    expires_at: int | None = None,
) -> dict[str, object]:
    external_subject = f"{TENANT_ID}:{subject}"
    return {
        "profile_ref": PROFILE_REF,
        "provider": "azure_devops",
        "identity_ref": external_subject,
        "external_subject": external_subject,
        "auth_status": auth_status,
        "auth_mode": "delegated_oauth",
        "access_mode": "actor_owned",
        "expires_at": expires_at or int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "oauth_scopes": ["https://app.vssps.visualstudio.com/.default"],
        "target_scope": _scope(),
    }


def _principal(subject: str = OBJECT_ID) -> IntegrationPrincipal:
    return IntegrationPrincipal(
        issuer=ISSUER,
        subject=subject,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        allowed_operation_ids=frozenset({OPERATION_ID}),
    )


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
            lease_ref="ado-lease-one-use",
            profile_ref=str(request["profile_ref"]),
            provider="azure_devops",
            operation_id=str(request["operation_id"]),
            target=dict(request["target"]),
            arguments_sha256=str(request["arguments_sha256"]),
            expires_at=datetime.now(UTC) + timedelta(seconds=30),
            profile_scope_sha256="d" * 64,
        )


class _AuthorizationCloud:
    def __init__(self) -> None:
        self.arguments: dict[str, object] | None = None

    def invoke_connector_tool(self, _principal, _connection, **request):
        self.arguments = dict(request["arguments"])
        return {"complete": True, "items": []}


def _dispatcher(profile: dict[str, object]):
    source = _source()
    host_profile = SimpleNamespace(
        provider="azure_devops",
        access_mode="actor_owned",
        azure_devops_tenant_id=TENANT_ID,
        azure_devops_organization="contoso",
        authorized_sources={SOURCE_ID: source},
        endpoint=SimpleNamespace(binding_id=BINDING_ID),
    )
    registry = SimpleNamespace(settings=SimpleNamespace(profiles={"ado-host": host_profile}))
    connection = IntegrationConnection(
        id=CONNECTION_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        actor_issuer=ISSUER,
        actor_subject=OBJECT_ID,
        account_link_ref=PROFILE_REF,
        provider="azure_devops",
        binding_ref="ado-host",
        target_ref=SOURCE_ID,
        display_name="Builds",
        access_mode="actor_owned",
    )
    accounts = _Accounts(profile)
    provider = _AuthorizationCloud()
    dispatcher = ConnectorOperationDispatcher(
        store=SimpleNamespace(current_connection_for_provider_call=lambda _id: connection),
        accounts=accounts,
        github=None,
        authorization_cloud=provider,
        registry=registry,
    )
    return connection, accounts, provider, dispatcher


def _arguments():
    return {
        "target": {"id": SOURCE_ID, "kind": "pipeline_runs", "bindingId": BINDING_ID},
        "pageSize": 20,
        "pageCursor": None,
        "windowStart": None,
        "windowEnd": "2026-10-27T00:00:00Z",
    }


def test_ado_operation_binds_exact_source_tuple_and_preserves_public_target_shape() -> None:
    projection, lease_target = targets_for_operation(
        OPERATION_ID,
        _arguments(),
        _scope(),
        binding_id=BINDING_ID,
        selected_source_id=SOURCE_ID,
    )

    assert projection == {"id": SOURCE_ID, "kind": "pipeline_runs", "bindingId": BINDING_ID}
    assert lease_target == _scope()
    with pytest.raises(ExchangeProductError, match="target"):
        targets_for_operation(
            OPERATION_ID,
            {
                **_arguments(),
                "target": {
                    "id": "other-source",
                    "kind": "pipeline_runs",
                    "bindingId": BINDING_ID,
                },
            },
            _scope(),
            binding_id=BINDING_ID,
            selected_source_id=SOURCE_ID,
        )


@pytest.mark.parametrize(
    ("operation_id", "scope", "arguments", "expected_extra"),
    [
        (
            "azure_devops.observations.poll",
            _scope(),
            {
                "target": {"id": SOURCE_ID, "kind": "pipeline_runs", "bindingId": BINDING_ID},
                "pageSize": 20,
                "pageCursor": None,
                "windowStart": None,
                "windowEnd": "2026-10-27T00:00:00Z",
            },
            {},
        ),
        (
            "azure_devops.pipelines.list",
            {
                "tenant_id": TENANT_ID,
                "organization": "contoso",
                "project_id": "22222222-3333-4444-8555-666666666666",
                "source_id": "project-source-a",
                "source_kind": "project_pipelines",
            },
            {
                "target": {
                    "id": "project-source-a",
                    "kind": "project_pipelines",
                    "bindingId": BINDING_ID,
                },
                "pageSize": 20,
                "pageCursor": None,
            },
            {},
        ),
        (
            "azure_devops.pipeline_runs.list",
            _scope(),
            {
                "target": {"id": SOURCE_ID, "kind": "pipeline_runs", "bindingId": BINDING_ID},
                "pageSize": 20,
                "pageCursor": None,
                "windowStart": None,
                "windowEnd": "2026-10-27T00:00:00Z",
            },
            {},
        ),
        (
            "azure_devops.pipeline_run.get",
            _scope(),
            {
                "target": {"id": SOURCE_ID, "kind": "pipeline_runs", "bindingId": BINDING_ID},
                "runId": 45,
            },
            {"run_id": 45},
        ),
        (
            "azure_devops.deployments.list",
            _release_scope(),
            {
                "target": {
                    "id": "release-source-a",
                    "kind": "release_deployments",
                    "bindingId": BINDING_ID,
                },
                "pageSize": 20,
                "pageCursor": None,
                "windowStart": None,
                "windowEnd": "2026-10-27T00:00:00Z",
            },
            {},
        ),
        (
            "azure_devops.release_environment.get",
            _release_scope(),
            {
                "target": {
                    "id": "release-source-a",
                    "kind": "release_deployments",
                    "bindingId": BINDING_ID,
                },
                "releaseId": 71,
                "environmentId": 6,
            },
            {"release_id": 71, "environment_id": 6},
        ),
        (
            "azure_devops.observations.poll",
            _release_scope(),
            {
                "target": {
                    "id": "release-source-a",
                    "kind": "release_deployments",
                    "bindingId": BINDING_ID,
                },
                "pageSize": 20,
                "pageCursor": None,
                "windowStart": None,
                "windowEnd": "2026-10-27T00:00:00Z",
            },
            {},
        ),
    ],
)
def test_all_ado_reads_project_to_the_exact_source_and_lease_target(
    operation_id: str,
    scope: dict[str, object],
    arguments: dict[str, object],
    expected_extra: dict[str, object],
) -> None:
    target_projection, lease_target = targets_for_operation(
        operation_id,
        arguments,
        scope,
        binding_id=BINDING_ID,
        selected_source_id=str(scope["source_id"]),
    )
    assert target_projection == arguments["target"]
    assert lease_target == {**scope, **expected_extra}


def test_ado_profile_identity_is_bound_to_original_entra_actor() -> None:
    with pytest.raises(ValueError, match="different Entra actor"):
        validate_profile_identity(
            _profile(subject=OTHER_OBJECT_ID),
            profile_ref=PROFILE_REF,
            principal=_principal(),
        )


def test_ado_dispatch_checks_actor_profile_before_lease_and_keeps_token_server_side() -> None:
    operation_id = OPERATION_ID
    principal = _principal()
    connection, accounts, provider, dispatcher = _dispatcher(_profile())
    arguments = _arguments()
    projection, lease_target = targets_for_operation(
        operation_id,
        arguments,
        _scope(),
        binding_id=BINDING_ID,
        selected_source_id=SOURCE_ID,
    )
    resource_ref = _resource_ref(
        provider_id="azure_devops",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        target=projection,
    )
    prepared = dispatcher.prepare_connection_operation(
        principal=principal,
        connection=connection,
        provider_id="azure_devops",
        profile_ref=PROFILE_REF,
        operation_id=operation_id,
        resource_ref=resource_ref,
        arguments=arguments,
        request_id="ado-request-1",
    )
    digest = digest_arguments(arguments)
    claims = SimpleNamespace(
        grant_ref="ado-grant-1",
        request_id="ado-request-1",
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        principal_issuer=ISSUER,
        principal_subject=OBJECT_ID,
        connection_ref=str(CONNECTION_ID),
        provider_id="azure_devops",
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
            "target": lease_target,
            "arguments_sha256": digest,
            "connector_grant": None,
        }
    ]
    assert provider.arguments == {
        "profile_ref": PROFILE_REF,
        "lease_ref": "ado-lease-one-use",
        "target": lease_target,
        "arguments_sha256": digest,
        "profile_scope_sha256": "d" * 64,
        "payload": arguments,
    }
    assert "access_token" not in provider.arguments


def test_ado_profile_for_another_user_in_the_same_tenant_is_denied_before_lease() -> None:
    connection, accounts, _provider, dispatcher = _dispatcher(_profile(subject=OTHER_OBJECT_ID))
    arguments = _arguments()
    projection, _lease_target = targets_for_operation(
        OPERATION_ID,
        arguments,
        _scope(),
        binding_id=BINDING_ID,
        selected_source_id=SOURCE_ID,
    )

    with pytest.raises(PermissionError, match="different Entra actor"):
        dispatcher.prepare_connection_operation(
            principal=_principal(),
            connection=connection,
            provider_id="azure_devops",
            profile_ref=PROFILE_REF,
            operation_id=OPERATION_ID,
            resource_ref=_resource_ref(
                provider_id="azure_devops",
                profile_ref=PROFILE_REF,
                operation_id=OPERATION_ID,
                target=projection,
            ),
            arguments=arguments,
            request_id="ado-other-user-same-tenant",
        )

    assert accounts.profile_reads == 1
    assert accounts.lease_requests == []


def test_ado_requires_reauthorization_before_lease_creation() -> None:
    connection, accounts, _provider, dispatcher = _dispatcher(
        _profile(auth_status="reauthorization_required")
    )
    arguments = _arguments()
    projection, _lease_target = targets_for_operation(
        OPERATION_ID,
        arguments,
        _scope(),
        binding_id=BINDING_ID,
        selected_source_id=SOURCE_ID,
    )
    with pytest.raises(ExchangeProductError) as failure:
        dispatcher.prepare_connection_operation(
            principal=_principal(),
            connection=connection,
            provider_id="azure_devops",
            profile_ref=PROFILE_REF,
            operation_id=OPERATION_ID,
            resource_ref=_resource_ref(
                provider_id="azure_devops",
                profile_ref=PROFILE_REF,
                operation_id=OPERATION_ID,
                target=projection,
            ),
            arguments=arguments,
            request_id="ado-reauthorization-required",
        )
    assert failure.value.status == 409
    assert accounts.lease_requests == []


def test_ado_expired_profile_is_reauthorization_required_before_lease_creation() -> None:
    expired_at = int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())
    connection, accounts, _provider, dispatcher = _dispatcher(_profile(expires_at=expired_at))
    arguments = _arguments()
    projection, _lease_target = targets_for_operation(
        OPERATION_ID,
        arguments,
        _scope(),
        binding_id=BINDING_ID,
        selected_source_id=SOURCE_ID,
    )

    with pytest.raises(ExchangeProductError) as expired:
        dispatcher.prepare_connection_operation(
            principal=_principal(),
            connection=connection,
            provider_id="azure_devops",
            profile_ref=PROFILE_REF,
            operation_id=OPERATION_ID,
            resource_ref=_resource_ref(
                provider_id="azure_devops",
                profile_ref=PROFILE_REF,
                operation_id=OPERATION_ID,
                target=projection,
            ),
            arguments=arguments,
            request_id="ado-expired-profile",
        )

    assert expired.value.code == "EXCHANGE_CONNECTION_REAUTHORIZATION_REQUIRED"
    assert expired.value.context["reasonCode"] == "azure_devops_token_expired"
    assert accounts.lease_requests == []


@pytest.mark.parametrize(
    ("reason", "status", "expected_reason"),
    [
        ("AUTHENTICATION_DENIED", 403, "authentication_denied"),
        ("SOURCE_SCOPE_DENIED", 403, "source_scope_denied"),
        ("PROFILE_SCOPE_MISMATCH", 403, "profile_scope_mismatch"),
        ("AUTHENTICATION_FAILED", 401, "auth_expired"),
        ("AUTHORIZATION_DENIED", 403, "authorization_denied"),
        ("RESOURCE_SCOPE_MISMATCH", 403, "resource_scope_mismatch"),
        ("INVALID_CURSOR", 422, "invalid_cursor"),
        ("AUTHORIZATION_UNAVAILABLE", 503, "authorization_unavailable"),
    ],
)
def test_ado_provider_failures_keep_auth_scope_cursor_and_outage_classes_distinct(
    reason: str,
    status: int,
    expected_reason: str,
) -> None:
    with pytest.raises(ExchangeProductError) as failure:
        _raise_azure_devops_provider_error(reason, retryable=reason == "AUTHORIZATION_UNAVAILABLE")

    assert failure.value.status == status
    assert failure.value.context["reasonCode"] == expected_reason


@pytest.mark.parametrize("scope_digest", ["d" * 64, None])
def test_ado_account_center_lease_requires_a_profile_scope_digest(scope_digest: str | None) -> None:
    class LeaseClient:
        def create_provider_credential_lease(self, _principal, **request):
            lease = {
                **request,
                "lease_ref": "ado-lease-test",
                "provider": "azure_devops",
                "expires_at": int((datetime.now(UTC) + timedelta(seconds=30)).timestamp()),
            }
            if scope_digest is not None:
                lease["profile_scope_sha256"] = scope_digest
            return lease

    port = IntegrationAccountCenterPort(LeaseClient())
    if scope_digest is None:
        with pytest.raises(RuntimeError, match="scope digest"):
            port.create_provider_credential_lease(
                _principal(),
                profile_ref=PROFILE_REF,
                operation_id=OPERATION_ID,
                target=_scope(),
                arguments_sha256="e" * 64,
            )
        return
    lease = port.create_provider_credential_lease(
        _principal(),
        profile_ref=PROFILE_REF,
        operation_id=OPERATION_ID,
        target=_scope(),
        arguments_sha256="e" * 64,
    )
    assert lease.profile_scope_sha256 == scope_digest
