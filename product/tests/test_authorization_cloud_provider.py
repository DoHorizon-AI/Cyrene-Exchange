"""Signed provider adapter and live Platform revalidation checks.

Module: product.tests.test_authorization_cloud_provider
Role: Exercise typed signed calls, resource scoping, and email revocation gates.
模块职责：验证类型化签名调用、资源范围和邮件发送撤权检查。
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cyrene_account_center_contracts import verify_context as verify_account_center_context
from cyrene_plugin_runtime import DirectPayload

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
    tool_provider_pb2 as tool_wire,
)
from cyrene_exchange_product.integrations.authorization_cloud import (
    AuthorizationCloudRunner,
    ProviderObservationUnavailable,
)
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    AuthorizationCloudConfigurationError,
    AuthorizationCloudProfileRegistry,
    parse_authorization_cloud_settings,
)
from cyrene_exchange_product.integrations.authorization_cloud_provider import (
    AuthorizationCloudDirectProvider,
    IntegrationToolCallUnavailable,
    PlatformCurrentAuthorizationContextResolver,
    _invoke_signed_microsoft_graph_tool,
)
from cyrene_exchange_product.integrations.connector_operations import _account_center_grant_proof
from cyrene_exchange_product.integrations.connector_security import digest_arguments
from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    CreateIntegrationConnection,
    EmailNotificationJob,
    IntegrationNotificationDraft,
    IntegrationNotificationKind,
    IntegrationPrincipal,
    LoginState,
    NotificationSeverity,
)
from cyrene_exchange_product.integrations.store import IntegrationStore

sdk = pytest.importorskip("cyrene_integration_contracts")

_ISSUER = "https://identity.example.test"
_SUBJECT = "member-a"
_ORG = "org-a"
_WORKSPACE = "workspace-a"
_WE_COM_AUTH_REF = "wecom-auth-a"
_KEY = b"k" * 32


def _principal(*, operations: set[str] | None = None, subject: str = _SUBJECT):
    return IntegrationPrincipal(
        issuer=_ISSUER,
        subject=subject,
        organization_id=_ORG,
        workspace_id=_WORKSPACE,
        allowed_operation_ids=frozenset(
            operations
            or {
                "integrationCreateConnection",
                "integrationGetAuthorizationHealth",
                "integrationRefreshConnectionResources",
                "integrationListNotifications",
                "integrationDeliverNotification",
                "accountBeginRenewalSession",
                "accountGetRenewalSession",
                "integrationGetOperation",
            }
        ),
    )


def _settings(*, include_wecom: bool = True, include_email: bool = True, include_gcp: bool = False):
    profiles: dict[str, Any] = {
        "azure-prod": {
            "provider": "azure",
            "directPlugin": {
                "bindingId": "cloud.binding.azure",
                "connectionRef": "grpc://127.0.0.1:5501",
                "transport": "local",
            },
            "callerWorkload": "exchange.integrations",
            "audience": "cloud-management",
            "expectedIssuer": _ISSUER,
            "contextKeyRef": "keys/cloud-azure",
            "organizationId": _ORG,
            "workspaceId": _WORKSPACE,
            "allowedContextRefs": ["actor-a"],
            "targets": {
                "vm-prod": {
                    "targetRef": "azure-vm-prod",
                    "displayName": "Production VM",
                    "allowedContextRefs": ["actor-a"],
                }
            },
        }
    }
    if include_gcp:
        profiles["gcp-prod"] = {
            "provider": "gcp",
            "directPlugin": {
                "bindingId": "cloud.binding.gcp",
                "connectionRef": "grpc://127.0.0.1:5504",
                "transport": "local",
            },
            "callerWorkload": "exchange.integrations",
            "audience": "cloud-management",
            "expectedIssuer": _ISSUER,
            "contextKeyRef": "keys/cloud-gcp",
            "organizationId": _ORG,
            "workspaceId": _WORKSPACE,
            "allowedContextRefs": ["actor-a"],
            "targets": {
                "instance-prod": {
                    "targetRef": "gcp-instance-prod",
                    "displayName": "Production instance",
                    "allowedContextRefs": ["actor-a"],
                }
            },
        }
    if include_wecom:
        profiles["wecom-prod"] = {
            "provider": "wecom",
            "directPlugin": {
                "bindingId": "wecom.binding.authorization",
                "connectionRef": "grpc://127.0.0.1:5502",
                "transport": "local",
            },
            "callerWorkload": "exchange.integrations",
            "audience": "wecom-authorization",
            "expectedIssuer": _ISSUER,
            "contextKeyRef": "keys/wecom",
            "organizationId": _ORG,
            "workspaceId": _WORKSPACE,
            "allowedContextRefs": ["actor-a"],
            "displayName": "WeCom",
            "authorizationRef": _WE_COM_AUTH_REF,
        }
    email: dict[str, Any] = {"enabled": False}
    if include_email:
        email = {
            "enabled": True,
            "directPlugin": {
                "bindingId": "email.binding.notifications",
                "connectionRef": "grpc://127.0.0.1:5503",
                "transport": "local",
            },
            "callerWorkload": "cyrene-exchange",
            "audience": "cyrene.connectors.email-notification",
            "expectedIssuer": _ISSUER,
            "contextKeyRef": "keys/email",
            "organizationId": _ORG,
            "workspaceId": _WORKSPACE,
            "recipientRef": "oncall",
            "allowedContextRefs": ["actor-a"],
        }
    return parse_authorization_cloud_settings(
        {
            "currentAuthority": {
                "contexts": [
                    {
                        "contextRef": "actor-a",
                        "issuer": _ISSUER,
                        "subject": _SUBJECT,
                        "organizationId": _ORG,
                        "workspaceId": _WORKSPACE,
                        "bearerTokenEnvRef": "bearers/actor-a",
                    }
                ]
            },
            "profiles": profiles,
            "monitorIntervalSeconds": 900,
        },
        email_value=email,
    )


def _hf_settings():
    return parse_authorization_cloud_settings(
        {
            "currentAuthority": {
                "contexts": [
                    {
                        "contextRef": "actor-a",
                        "issuer": _ISSUER,
                        "subject": _SUBJECT,
                        "organizationId": _ORG,
                        "workspaceId": _WORKSPACE,
                        "bearerTokenEnvRef": "bearers/actor-a",
                    }
                ]
            },
            "profiles": {
                "hf-oauth": {
                    "provider": "hf",
                    "directPlugin": {
                        "bindingId": "huggingface.binding.oauth",
                        "connectionRef": "grpc://127.0.0.1:5510",
                        "transport": "local",
                    },
                    "callerWorkload": "exchange-service",
                    "audience": "huggingface-provider",
                    "expectedIssuer": _ISSUER,
                    "contextKeyRef": "keys/huggingface",
                    "organizationId": _ORG,
                    "workspaceId": _WORKSPACE,
                    "allowedContextRefs": ["actor-a"],
                    "credentialSecretRef": "huggingface/oauth-seed",
                    "authMode": "device_oauth",
                    "accountScopes": {
                        "repositories": [
                            {
                                "repoType": "model",
                                "repoId": "org/private-model",
                                "permissions": ["read"],
                            }
                        ]
                    },
                    "targets": {
                        "selected-model": {
                            "targetRef": "org/private-model",
                            "displayName": "Selected model",
                        }
                    },
                }
            },
            "monitorIntervalSeconds": 900,
        },
        email_value={"enabled": False},
    )


def _connection(store: IntegrationStore, principal: IntegrationPrincipal, provider: str = "wecom"):
    return store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider=provider,
            binding_ref=(
                "wecom-prod"
                if provider == "wecom"
                else "gcp-prod"
                if provider == "gcp"
                else "azure-prod"
            ),
            target_ref=(
                None if provider == "wecom" else "instance-prod" if provider == "gcp" else "vm-prod"
            ),
            display_name="WeCom" if provider == "wecom" else "Production VM",
        ),
        idempotency_key=f"connection-{provider}",
    )


def _hf_connection(
    store: IntegrationStore,
    principal: IntegrationPrincipal,
    account_profile_ref: str = "00000000-0000-4000-8000-000000000401",
):
    return store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider="hf",
            binding_ref="hf-oauth",
            target_ref="selected-model",
            account_link_ref=account_profile_ref,
            display_name="Selected HF model",
        ),
        idempotency_key="connection-hf-oauth",
    )


class _IdentityVerifier:
    def __init__(self, principals: dict[str, IntegrationPrincipal]) -> None:
        self.principals = principals
        self.calls: list[tuple[str, str]] = []

    def principal_for(self, *, bearer_token: str, workspace_id: str):
        self.calls.append((bearer_token, workspace_id))
        principal = self.principals[bearer_token]
        assert principal.workspace_id == workspace_id
        return principal


class _EmailStateIdentityVerifier(_IdentityVerifier):
    """Record the durable outbox state at each real Platform verifier call."""

    def __init__(
        self,
        store: IntegrationStore,
        job_id,
        principals: dict[str, IntegrationPrincipal],
    ) -> None:
        super().__init__(principals)
        self.store = store
        self.job_id = job_id
        self.outbox_states: list[str] = []

    def principal_for(self, *, bearer_token: str, workspace_id: str):
        with self.store._lock:
            row = self.store._connection.execute(
                "SELECT document FROM email_notification_outbox WHERE id=?",
                (str(self.job_id),),
            ).fetchone()
        assert row is not None
        job = EmailNotificationJob.model_validate_json(str(row["document"]))
        self.outbox_states.append(job.state.value)
        return super().principal_for(bearer_token=bearer_token, workspace_id=workspace_id)


class _DirectClient:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result
        self.requests: list[tool_wire.CallToolRequest] = []

    def invoke(self, *, request: Any, **kwargs: Any) -> DirectPayload:
        del kwargs
        raw_request = tool_wire.CallToolRequest.FromString(request.value)
        self.requests.append(raw_request)
        response = tool_wire.CallToolResponse(
            outcome=tool_wire.ToolCallOutcome(
                content=[
                    tool_wire.ToolContentPart(
                        json=tool_wire.ToolJsonContent(
                            json=json.dumps(self.result, separators=(",", ":"))
                        )
                    )
                ],
                is_error=False,
            )
        )
        return DirectPayload(
            "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse",
            response.SerializeToString(deterministic=True),
        )


def test_microsoft_graph_signed_context_uses_exchange_caller_and_keeps_provider_workload() -> None:
    from cyrene_exchange_product.integrations.microsoft_graph import (
        lease_arguments_for_operation,
    )

    tenant_id = "11111111-2222-4333-8444-555555555555"
    object_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    operation_id = "microsoft_graph.todo.lists.list"
    principal = IntegrationPrincipal(
        issuer=issuer,
        subject=object_id,
        organization_id="office-org",
        workspace_id="office-workspace",
        allowed_operation_ids=frozenset({operation_id}),
    )
    profile = SimpleNamespace(
        provider="microsoft_graph",
        caller_workload="microsoft-graph-provider",
        access_mode="actor_owned",
        expected_issuer=issuer,
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        microsoft_graph_plan_ids=(),
        microsoft_graph_sharepoint_site_id=None,
        microsoft_graph_sharepoint_list_ids=(),
        microsoft_graph_office_v2=None,
    )
    payload = {"page_size": 10}
    arguments = {
        "payload": payload,
        "profile_ref": "66666666-7777-4888-8999-aaaaaaaaaaaa",
        "lease_ref": "77777777-8888-4999-8aaa-bbbbbbbbbbbb",
        "target": {"tenant_id": tenant_id},
        "arguments_sha256": digest_arguments(lease_arguments_for_operation(operation_id, payload)),
        "profile_scope_sha256": "a" * 64,
    }
    client = _DirectClient({"items": []})

    result = _invoke_signed_microsoft_graph_tool(
        client,
        endpoint=SimpleNamespace(binding_id="graph-provider-binding"),
        principal=principal,
        profile=profile,
        context_key=_KEY,
        tool_id=operation_id,
        operation_id=operation_id,
        arguments=arguments,
        request_id="office-graph-discovery-1",
    )

    assert result == {"items": []}
    assert profile.caller_workload == "microsoft-graph-provider"
    request = client.requests[0]
    envelope = json.loads(request.arguments_json)
    signed_payload = {
        key: envelope[key]
        for key in (
            "payload",
            "profile_ref",
            "lease_ref",
            "target",
            "arguments_sha256",
            "profile_scope_sha256",
        )
    }
    assert envelope["trusted_context"]["caller_id"] == "exchange-service"
    assert verify_account_center_context(
        method="call_tool",
        payload=signed_payload,
        context=envelope["trusted_context"],
        keys={"exchange-service": _KEY},
        expected_caller_id="exchange-service",
    )


def test_mail_send_unknown_result_is_preserved_for_durable_receipt_mapping() -> None:
    from cyrene_exchange_product.integrations.microsoft_graph import (
        lease_arguments_for_operation,
    )

    tenant_id = "11111111-2222-4333-8444-555555555555"
    object_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    operation_id = "microsoft_graph.mail.message.send"
    principal = IntegrationPrincipal(
        issuer=issuer,
        subject=object_id,
        organization_id="office-org",
        workspace_id="office-workspace",
        allowed_operation_ids=frozenset({operation_id}),
    )
    profile = SimpleNamespace(
        provider="microsoft_graph",
        caller_workload="microsoft-graph-provider",
        expected_issuer=issuer,
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        microsoft_graph_plan_ids=(),
        microsoft_graph_sharepoint_site_id=None,
        microsoft_graph_sharepoint_list_ids=(),
        microsoft_graph_office_v2=None,
    )
    payload = {"message_id": "AAMkDraft-opaque=="}
    target = {
        "tenant_id": tenant_id,
        "folder_id": "drafts",
        "message_id": "AAMkDraft-opaque==",
    }
    arguments = {
        "payload": payload,
        "profile_ref": "66666666-7777-4888-8999-aaaaaaaaaaaa",
        "lease_ref": "77777777-8888-4999-8aaa-bbbbbbbbbbbb",
        "target": target,
        "arguments_sha256": digest_arguments(lease_arguments_for_operation(operation_id, payload)),
        "profile_scope_sha256": "a" * 64,
    }

    def invoke(result: dict[str, Any]) -> dict[str, Any]:
        return _invoke_signed_microsoft_graph_tool(
            _DirectClient(result),
            endpoint=SimpleNamespace(binding_id="graph-provider-binding"),
            principal=principal,
            profile=profile,
            context_key=_KEY,
            tool_id=operation_id,
            operation_id=operation_id,
            arguments=arguments,
            request_id="office-mail-send-unknown",
        )

    result = invoke(
        {
            "status": "UNKNOWN",
            "message_id": "AAMkDraft-opaque==",
            "reconciliation": "Read the selected mailbox metadata before another send attempt.",
        }
    )
    assert result["status"] == "UNKNOWN"
    assert result["message_id"] == "AAMkDraft-opaque=="
    assert "reconciliation" in result
    for malformed in (
        {
            "status": "ACCEPTED",
            "message_id": "AAMkDraft-opaque==",
            "error": {"code": "unexpected"},
        },
        {"status": "ACCEPTED", "message_id": "AAMkOtherDraft=="},
        {
            "status": "ACCEPTED",
            "message_id": "AAMkDraft-opaque==",
            "message": {"bodyPreview": "private text"},
        },
    ):
        with pytest.raises(ExchangeProductError) as unknown:
            invoke(malformed)
        assert unknown.value.code == "EXCHANGE_CONNECTOR_OUTCOME_UNKNOWN"
        assert unknown.value.context["resultState"] == "UNKNOWN_RESULT"


def test_graph_mail_mutation_transport_loss_is_unknown_while_reads_remain_retryable() -> None:
    from cyrene_exchange_product.integrations.microsoft_graph import (
        lease_arguments_for_operation,
    )

    tenant_id = "11111111-2222-4333-8444-555555555555"
    object_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    principal = IntegrationPrincipal(
        issuer=issuer,
        subject=object_id,
        organization_id="office-org",
        workspace_id="office-workspace",
        allowed_operation_ids=frozenset(),
    )
    profile = SimpleNamespace(
        provider="microsoft_graph",
        caller_workload="microsoft-graph-provider",
        access_mode="actor_owned",
        expected_issuer=issuer,
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        microsoft_graph_plan_ids=(),
        microsoft_graph_sharepoint_site_id=None,
        microsoft_graph_sharepoint_list_ids=(),
        microsoft_graph_office_v2=None,
    )

    class LostReplyClient:
        def invoke(self, **_kwargs):
            raise TimeoutError("simulated post-dispatch response loss")

    def invoke(
        operation_id: str,
        payload: dict[str, object],
        target: dict[str, object],
        client: Any | None = None,
    ) -> None:
        _invoke_signed_microsoft_graph_tool(
            client or LostReplyClient(),
            endpoint=SimpleNamespace(binding_id="graph-provider-binding"),
            principal=principal,
            profile=profile,
            context_key=_KEY,
            tool_id=operation_id,
            operation_id=operation_id,
            arguments={
                "payload": payload,
                "profile_ref": "66666666-7777-4888-8999-aaaaaaaaaaaa",
                "lease_ref": "77777777-8888-4999-8aaa-bbbbbbbbbbbb",
                "target": target,
                "arguments_sha256": digest_arguments(
                    lease_arguments_for_operation(operation_id, payload)
                ),
                "profile_scope_sha256": "a" * 64,
            },
            request_id="mail-mutation-transport-loss",
        )

    with pytest.raises(ExchangeProductError) as unknown:
        invoke(
            "microsoft_graph.mail.message.send",
            {"message_id": "AAMkDraft-opaque=="},
            {
                "tenant_id": tenant_id,
                "folder_id": "drafts",
                "message_id": "AAMkDraft-opaque==",
            },
        )
    assert unknown.value.code == "EXCHANGE_CONNECTOR_OUTCOME_UNKNOWN"
    assert unknown.value.context["resultState"] == "UNKNOWN_RESULT"
    assert unknown.value.retryable is False

    class InvalidReplyClient:
        def invoke(self, **_kwargs):
            return DirectPayload("type.invalid/response", b"not-a-provider-response")

    with pytest.raises(ExchangeProductError) as malformed:
        invoke(
            "microsoft_graph.mail.draft.delete",
            {"message_id": "AAMkDraft-opaque==", "if_match": 'W/"etag"'},
            {
                "tenant_id": tenant_id,
                "folder_id": "drafts",
                "message_id": "AAMkDraft-opaque==",
            },
            InvalidReplyClient(),
        )
    assert malformed.value.code == "EXCHANGE_CONNECTOR_OUTCOME_UNKNOWN"
    assert malformed.value.context["resultState"] == "UNKNOWN_RESULT"

    with pytest.raises(IntegrationToolCallUnavailable) as read_failure:
        invoke("microsoft_graph.mail.folders.list", {"page_size": 10}, {"tenant_id": tenant_id})
    assert read_failure.value.retryable is True


class _StaticContexts:
    def __init__(self, principal: IntegrationPrincipal) -> None:
        self.principal = principal

    def for_connection(self, connection, *, operation_id: str):
        self.principal.require(operation_id)
        assert connection.actor_subject == self.principal.subject
        return self.principal

    def for_connection_with_connector_grant(
        self,
        connection,
        *,
        operation_id: str,
        provider_operation_id: str,
        arguments: dict[str, object],
    ):
        self.principal.require(operation_id)
        assert connection.actor_subject == self.principal.subject
        assert provider_operation_id == "huggingface.repo.get"
        assert arguments == {"repo_type": "model", "repo_id": "org/private-model"}
        return self.principal, None

    def for_claimed_notification(self, job, *, claim_fence: int, operation_id: str):
        self.principal.require(operation_id)
        assert job.actor_subject == self.principal.subject
        assert job.claim_fence == claim_fence
        return self.principal

    def for_sending_notification(self, job, *, claim_fence: int, operation_id: str):
        self.principal.require(operation_id)
        assert job.actor_subject == self.principal.subject
        assert job.claim_fence == claim_fence
        return self.principal


def test_contextless_cloud_health_requires_a_fresh_workspace_connector_grant(
    tmp_path: Path,
) -> None:
    settings = _settings(include_wecom=False, include_email=False)
    configured_profile = settings.profiles["azure-prod"]
    profile = replace(
        configured_profile,
        allowed_context_refs=frozenset(),
        allowed_actors=frozenset({(_ISSUER, _SUBJECT)}),
        access_mode="workspace_operator",
        targets={
            alias: replace(target, allowed_context_refs=frozenset())
            for alias, target in configured_profile.targets.items()
        },
    )
    settings = replace(settings, contexts={}, profiles={"azure-prod": profile})
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal(
        operations={
            "integrationCreateConnection",
            "integrationGetAuthorizationHealth",
            "navigator.connector.operator.v1",
        }
    )
    store = IntegrationStore(tmp_path / "cloud-contextless.sqlite3")
    connection = store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider="azure",
            binding_ref="azure-prod",
            target_ref="vm-prod",
            display_name="Production VM",
        ),
        idempotency_key="contextless-cloud-health",
        access_mode="workspace_operator",
    )

    class _Authority:
        def __init__(self) -> None:
            self.requests: list[dict[str, Any]] = []

        def authorize_connector_operation(self, **kwargs: Any) -> bytes:
            self.requests.append(kwargs)
            return b"synthetic-signed-grant"

    class _Verifier:
        configured = True

        def __init__(self) -> None:
            self.expected: dict[str, Any] | None = None
            self.consumed = 0

        def validate_authority_response(self, _grant: bytes, *, expected: dict[str, Any]):
            self.expected = expected

        def consume(self, _grant: bytes, *, expected: dict[str, Any]):
            assert self.expected == expected
            self.consumed += 1
            return SimpleNamespace(
                principal_issuer=expected["principal_issuer"],
                principal_subject=expected["principal_subject"],
                organization_id=expected["organization_id"],
                workspace_id=expected["workspace_id"],
            )

    authority = _Authority()
    verifier = _Verifier()
    resolver = PlatformCurrentAuthorizationContextResolver(
        store=store,
        identity_verifier=None,
        registry=registry,
        bearer_token=lambda _reference: pytest.fail("contextless profile must not read a bearer"),
        connector_grant_authority=authority,
        connector_grant_verifier=verifier,
    )

    fresh = resolver.for_connection(
        connection,
        operation_id="integrationGetAuthorizationHealth",
    )

    assert fresh is not None
    assert fresh.issuer == _ISSUER
    assert fresh.subject == _SUBJECT
    assert fresh.organization_id == _ORG
    assert fresh.workspace_id == _WORKSPACE
    assert authority.requests[0]["provider_id"] == "azure"
    assert authority.requests[0]["profile_ref"] == "azure-prod"
    assert authority.requests[0]["operation_id"] == "cloud.provider.health.read"
    assert authority.requests[0]["arguments_digest_sha256"] == bytes.fromhex(
        digest_arguments({"profile_ref": "azure-prod"})
    )
    assert verifier.consumed == 1
    assert (
        resolver.for_connection(
            connection,
            operation_id="integrationRefreshConnectionResources",
        )
        is None
    )
    assert len(authority.requests) == 1
    direct = _DirectClient({"resources": []})
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"azure-prod": direct},
        email_client=None,
        account_center=None,
        current_context_resolver=resolver,
        context_key=lambda _reference: _KEY,
    )
    refresh_principal = _principal(operations={"integrationRefreshConnectionResources"})
    with pytest.raises(PermissionError, match="current Platform grant"):
        provider.cloud_resources(refresh_principal, connection)
    assert direct.requests == []
    store.close()


def test_contextless_hf_health_projects_exact_grant_into_account_center_lease(
    tmp_path: Path,
) -> None:
    settings = _hf_settings()
    configured = settings.profiles["hf-oauth"]
    profile = replace(
        configured,
        allowed_context_refs=frozenset(),
        allowed_actors=frozenset({(_ISSUER, _SUBJECT)}),
        access_mode="workspace_operator",
        targets={
            alias: replace(target, allowed_context_refs=frozenset())
            for alias, target in configured.targets.items()
        },
    )
    registry = AuthorizationCloudProfileRegistry(
        replace(settings, contexts={}, profiles={"hf-oauth": profile})
    )
    store = IntegrationStore(tmp_path / "hf-contextless.sqlite3")
    connection = store.create_connection(
        _principal(),
        CreateIntegrationConnection(
            provider="hf",
            binding_ref="hf-oauth",
            target_ref="selected-model",
            account_link_ref="00000000-0000-4000-8000-000000000401",
            display_name="Selected HF model",
        ),
        idempotency_key="hf-contextless-connection",
        access_mode="workspace_operator",
    )

    class _Authority:
        def __init__(self) -> None:
            self.requests: list[dict[str, Any]] = []

        def authorize_connector_operation(self, **kwargs: Any) -> bytes:
            self.requests.append(kwargs)
            return b"synthetic-signed-grant"

    class _Verifier:
        configured = True

        def validate_authority_response(self, _grant: bytes, *, expected: dict[str, Any]):
            self.expected = expected

        def consume(self, _grant: bytes, *, expected: dict[str, Any]):
            assert self.expected == expected
            return SimpleNamespace(
                request_id=expected["request_id"],
                audience="exchange",
                organization_id=expected["organization_id"],
                workspace_id=expected["workspace_id"],
                principal_issuer=expected["principal_issuer"],
                principal_subject=expected["principal_subject"],
                connection_ref=expected["connection_ref"],
                provider_id=expected["provider_id"],
                profile_ref=expected["profile_ref"],
                operation_id=expected["operation_id"],
                resource_ref=expected["resource_ref"],
                arguments_digest_sha256=expected["arguments_digest_sha256"],
                issued_at_epoch=100.0,
                expires_at_epoch=115.0,
                grant_ref="sha256:" + "b" * 64,
            )

    authority = _Authority()
    resolver = PlatformCurrentAuthorizationContextResolver(
        store=store,
        identity_verifier=None,
        registry=registry,
        bearer_token=lambda _reference: pytest.fail("contextless profile must not read a bearer"),
        connector_grant_authority=authority,
        connector_grant_verifier=_Verifier(),
    )
    target = {"repo_type": "model", "repo_id": "org/private-model"}
    principal, claims = resolver.for_connection_with_connector_grant(
        connection,
        operation_id="integrationGetAuthorizationHealth",
        provider_operation_id="huggingface.repo.get",
        arguments=target,
    )

    assert principal is not None
    assert claims is not None
    proof = _account_center_grant_proof(
        claims,
        arguments_sha256=digest_arguments(target),
    )
    assert proof["profile_ref"] == connection.account_link_ref
    assert proof["connection_ref"] == str(connection.id)
    assert proof["provider_id"] == "huggingface"
    assert proof["operation_id"] == "huggingface.repo.get"
    assert proof["arguments_sha256"] == digest_arguments(target)
    assert authority.requests[0]["resource_ref"].startswith("sha256:")
    assert principal.allowed_operation_ids == frozenset(
        {"integrationGetAuthorizationHealth", "huggingface.repo.get"}
    )
    denied_principal, denied_claims = resolver.for_connection_with_connector_grant(
        connection,
        operation_id="integrationRefreshConnectionResources",
        provider_operation_id="cloud.provider.health.read",
        arguments={"profile_ref": "hf-oauth"},
    )
    assert denied_principal is None and denied_claims is None
    assert len(authority.requests) == 1
    store.close()


def test_hf_device_renewal_uses_the_fresh_actor_request_without_a_stored_bearer_context(
    tmp_path: Path,
) -> None:
    settings = _hf_settings()
    configured = settings.profiles["hf-oauth"]
    profile = replace(
        configured,
        allowed_context_refs=frozenset(),
        allowed_actors=frozenset({(_ISSUER, _SUBJECT)}),
        access_mode="workspace_operator",
        targets={
            alias: replace(target, allowed_context_refs=frozenset())
            for alias, target in configured.targets.items()
        },
    )
    registry = AuthorizationCloudProfileRegistry(
        replace(settings, contexts={}, profiles={"hf-oauth": profile})
    )
    principal = _principal(
        operations={
            "integrationCreateConnection",
            "accountBeginRenewalSession",
            "navigator.connector.operator.v1",
        }
    )
    profile_ref = "00000000-0000-4000-8000-000000000401"
    store = IntegrationStore(tmp_path / "hf-renewal-without-stored-context.sqlite3")
    connection = store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider="hf",
            binding_ref="hf-oauth",
            target_ref="selected-model",
            account_link_ref=profile_ref,
            display_name="Selected HF model",
        ),
        idempotency_key="hf-static-owner-renewal",
        access_mode="workspace_operator",
    )

    class _Accounts:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def begin_huggingface_renewal(
            self,
            selected: IntegrationPrincipal,
            *,
            profile_ref: str,
            session_ref: str,
        ) -> dict[str, Any]:
            self.calls.append((selected.subject, profile_ref))
            return {
                "profile_ref": profile_ref,
                "session_ref": session_ref,
                "state": "waiting_user",
                "verification_uri": "https://hf.co/oauth/device",
                "user_code": "ABCD-EFGH",
                "generation": 5,
            }

    accounts = _Accounts()
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={},
        email_client=None,
        account_center=accounts,
        current_context_resolver=None,
        context_key=lambda _reference: _KEY,
    )

    session = provider.start_renewal(
        principal,
        connection,
        profile_ref,
        request_id="renewal-session-owner-1",
    )

    assert session.authorization_ref == profile_ref
    assert session.session_ref == "renewal-session-owner-1"
    assert session.state.value == "WAITING_USER"
    assert session.authorization_url == "https://hf.co/oauth/device"
    assert session.user_code == "ABCD-EFGH"
    assert accounts.calls == [(_SUBJECT, profile_ref)]
    store.close()


class _HuggingFaceAccounts:
    def __init__(
        self,
        profile_ref: str,
        *,
        repositories: list[dict[str, Any]] | None = None,
        denied_repo_id: str | None = None,
    ) -> None:
        self.profile_ref = profile_ref
        self.revision = 5
        self.list_calls = 0
        self.lease_calls: list[dict[str, Any]] = []
        self.repositories = repositories or [
            {
                "repo_type": "model",
                "repo_id": "org/private-model",
                "permissions": ["read"],
            }
        ]
        self.denied_repo_id = denied_repo_id

    def list_provider_profiles(self, principal: IntegrationPrincipal) -> dict[str, Any]:
        assert principal.subject == _SUBJECT
        self.list_calls += 1
        return {
            "profiles": [
                {
                    "profile_ref": self.profile_ref,
                    "provider": "huggingface",
                    "auth_mode": "device_oauth",
                    "auth_status": "healthy",
                    "target_scope": {"repositories": self.repositories},
                    "credential_revision": self.revision,
                    "expires_at": 1_800_000_000,
                }
            ]
        }

    def create_provider_credential_lease(self, principal: IntegrationPrincipal, **kwargs):
        assert "huggingface.repo.get" in principal.allowed_operation_ids
        self.lease_calls.append(kwargs)
        if (
            self.denied_repo_id is not None
            and kwargs["target"].get("repo_id") == self.denied_repo_id
        ):
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_AUTHORIZATION_DENIED",
                title="The selected HF repository is not readable",
                detail="Synthetic target-specific authorization denial.",
                status=403,
            )
        return {
            "lease_ref": "00000000-0000-4000-8000-000000000402",
            "profile_ref": kwargs["profile_ref"],
            "provider": "huggingface",
            "operation_id": kwargs["operation_id"],
            "target": kwargs["target"],
            "arguments_sha256": kwargs["arguments_sha256"],
        }


def test_hf_health_uses_account_center_lease_and_suppresses_oauth_access_ttl(
    tmp_path: Path,
) -> None:
    settings = _hf_settings()
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal(
        operations={
            "integrationCreateConnection",
            "integrationGetAuthorizationHealth",
            "huggingface.repo.get",
        }
    )
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    account_profile_ref = "00000000-0000-4000-8000-000000000401"
    connection = _hf_connection(store, principal, account_profile_ref)
    accounts = _HuggingFaceAccounts(account_profile_ref)
    direct = _DirectClient({"repo_id": "org/private-model"})
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"hf-oauth": direct},
        email_client=None,
        account_center=accounts,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda reference: _KEY if reference == "keys/huggingface" else b"e" * 32,
    )

    observed = provider.authorization_health(principal, connection)

    assert observed.login_state == LoginState.PRESENT, (
        observed.reason_code,
        accounts.lease_calls,
        len(direct.requests),
    )
    assert observed.authorization_state == AuthorizationState.VALID
    assert observed.authorization_ref == account_profile_ref
    assert observed.expires_at is None
    assert observed.generation == 5
    assert observed.capabilities[0].state == AuthorizationState.VALID
    assert accounts.list_calls == 2
    assert len(accounts.lease_calls) == 1
    assert accounts.lease_calls[0] | {"arguments_sha256": "removed"} == {
        "profile_ref": account_profile_ref,
        "operation_id": "huggingface.repo.get",
        "target": {"repo_type": "model", "repo_id": "org/private-model"},
        "arguments_sha256": "removed",
    }
    assert isinstance(accounts.lease_calls[0]["arguments_sha256"], str)
    assert len(accounts.lease_calls[0]["arguments_sha256"]) == 64
    assert direct.requests[0].provider_tool_id == "huggingface.repo.get"
    envelope = json.loads(direct.requests[0].arguments_json)
    assert set(envelope) == {"profile_ref", "lease_ref", "payload", "trusted_context"}
    assert envelope["profile_ref"] == account_profile_ref
    assert envelope["lease_ref"] == "00000000-0000-4000-8000-000000000402"
    assert envelope["payload"] == {
        "repo_type": "model",
        "repo_id": "org/private-model",
    }
    signed_payload = {
        "profile_ref": envelope["profile_ref"],
        "lease_ref": envelope["lease_ref"],
        "payload": envelope["payload"],
    }
    assert verify_account_center_context(
        method="call_tool",
        payload=signed_payload,
        context=envelope["trusted_context"],
        keys={"exchange-service": _KEY},
        expected_caller_id="exchange-service",
    )
    store.close()


def test_hf_health_probes_only_the_connection_selected_repository(
    tmp_path: Path,
) -> None:
    settings = _hf_settings()
    profile = settings.profiles["hf-oauth"]
    repositories = [
        {
            "repo_type": "model",
            "repo_id": "org/other-model",
            "permissions": ["read"],
        },
        {
            "repo_type": "model",
            "repo_id": "org/selected-model",
            "permissions": ["read"],
        },
    ]
    profile = replace(
        profile,
        account_scopes={"repositories": repositories},
        targets={
            "selected-model": replace(
                profile.targets["selected-model"],
                target_ref="org/selected-model",
            )
        },
    )
    settings = replace(settings, profiles={"hf-oauth": profile})
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal(
        operations={
            "integrationCreateConnection",
            "integrationGetAuthorizationHealth",
            "huggingface.repo.get",
        }
    )
    store = IntegrationStore(tmp_path / "hf-selected-target.sqlite3")
    account_profile_ref = "00000000-0000-4000-8000-000000000401"
    connection = _hf_connection(store, principal, account_profile_ref)
    accounts = _HuggingFaceAccounts(
        account_profile_ref,
        repositories=repositories,
        denied_repo_id="org/selected-model",
    )
    direct = _DirectClient({"repo_id": "org/other-model"})
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"hf-oauth": direct},
        email_client=None,
        account_center=accounts,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )

    observed = provider.authorization_health(principal, connection)

    assert observed.authorization_state == AuthorizationState.PERMISSION_DENIED
    assert observed.reason_code == "account_center_authorization_denied"
    assert len(accounts.lease_calls) == 1
    assert accounts.lease_calls[0]["target"] == {
        "repo_type": "model",
        "repo_id": "org/selected-model",
    }
    assert direct.requests == []
    store.close()


@pytest.mark.parametrize(
    ("error_code", "expected_state"),
    [
        ("EXCHANGE_CONNECTOR_AUTH_EXPIRED", AuthorizationState.REAUTHORIZATION_REQUIRED),
        ("EXCHANGE_CONNECTOR_PERMISSION_DENIED", AuthorizationState.PERMISSION_DENIED),
        ("EXCHANGE_CONNECTOR_PROVIDER_UNAVAILABLE", AuthorizationState.UNAVAILABLE),
    ],
)
def test_hf_health_separates_reauth_permission_and_provider_unavailable(
    tmp_path: Path,
    error_code: str,
    expected_state: AuthorizationState,
) -> None:
    settings = _hf_settings()
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal(
        operations={
            "integrationCreateConnection",
            "integrationGetAuthorizationHealth",
            "huggingface.repo.get",
        }
    )
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    account_profile_ref = "00000000-0000-4000-8000-000000000401"
    connection = _hf_connection(store, principal, account_profile_ref)
    accounts = _HuggingFaceAccounts(account_profile_ref)
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"hf-oauth": _DirectClient({"repo_id": "unused"})},
        email_client=None,
        account_center=accounts,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )

    def failed_probe(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise ExchangeProductError(
            code=error_code,
            title="fixed test failure",
            detail="synthetic result",
            status=503,
        )

    provider.invoke_connector_tool = failed_probe  # type: ignore[method-assign]
    observed = provider.authorization_health(principal, connection)

    assert observed.authorization_state == expected_state
    assert observed.expires_at is None
    assert observed.capabilities[0].state == expected_state
    store.close()


def test_current_authority_bearer_is_reread_and_operation_grant_is_fresh() -> None:
    settings = _settings(include_email=False)
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    revoked = _principal(operations={"integrationListConnections"})
    source = {"ACTOR_BEARER": "token-v1"}
    refs = {"bearers/actor-a": "ACTOR_BEARER"}
    identity = _IdentityVerifier({"token-v1": principal, "token-v2": principal, "revoked": revoked})
    store = IntegrationStore(":memory:")
    connection = _connection(store, principal)
    resolver = PlatformCurrentAuthorizationContextResolver(
        store=store,
        identity_verifier=identity,
        registry=registry,
        bearer_token=lambda ref: source.get(refs.get(ref, "")),
    )

    assert (
        resolver.for_connection(
            connection,
            operation_id="integrationGetAuthorizationHealth",
        )
        == principal
    )
    source["ACTOR_BEARER"] = "token-v2"
    assert (
        resolver.for_connection(
            connection,
            operation_id="integrationGetAuthorizationHealth",
        )
        == principal
    )
    source["ACTOR_BEARER"] = "revoked"
    assert (
        resolver.for_connection(
            connection,
            operation_id="integrationGetAuthorizationHealth",
        )
        is None
    )
    source["ACTOR_BEARER"] = ""
    assert (
        resolver.for_connection(
            connection,
            operation_id="integrationGetAuthorizationHealth",
        )
        is None
    )

    assert identity.calls == [
        ("token-v1", _WORKSPACE),
        ("token-v2", _WORKSPACE),
        ("revoked", _WORKSPACE),
    ]
    store.close()


def test_registered_target_and_actor_allowlists_are_enforced() -> None:
    settings = _settings(include_wecom=False, include_email=False)
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    request = CreateIntegrationConnection(
        provider="azure",
        binding_ref="azure-prod",
        target_ref="vm-prod",
    )
    assert registry.display_name_for_connection(principal, request) == "Production VM"

    denied = _principal(subject="other-member")
    with pytest.raises(PermissionError):
        registry.display_name_for_connection(denied, request)
    with pytest.raises(AuthorizationCloudConfigurationError):
        registry.display_name_for_connection(
            principal,
            request.model_copy(update={"target_ref": "unconfigured-target"}),
        )


def test_authorization_health_uses_fixed_signed_wecom_tool_and_native_ref(tmp_path: Path) -> None:
    settings = _settings(include_email=False)
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal)
    now = datetime.now(UTC)
    health = sdk.AuthorizationHealth(
        schema_version=1,
        authorization_ref=_WE_COM_AUTH_REF,
        login_state=sdk.LoginState.PRESENT,
        authorization_state=sdk.AuthorizationState.VALID,
        checked_at=now,
        expires_at=now + timedelta(days=2),
        generation=2,
        capabilities=(
            sdk.CapabilityAuthorizationHealth(
                capability_id="wecom.message.aibot.sessions.list",
                state=sdk.AuthorizationState.VALID,
                last_verified_at=now,
                expires_at=now + timedelta(days=2),
                reason_code=None,
            ),
        ),
    )
    direct = _DirectClient(sdk.serialize_authorization_health(health))
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"wecom-prod": direct},
        email_client=None,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda reference: _KEY if reference == "keys/wecom" else b"e" * 32,
    )

    observed = provider.authorization_health(principal, connection)

    assert observed.authorization_state == AuthorizationState.VALID
    assert observed.authorization_ref == _WE_COM_AUTH_REF
    request = direct.requests[0]
    assert request.binding_id == "wecom.binding.authorization"
    assert request.provider_tool_id == "wecom_authorization_health"
    envelope = sdk.parse_tool_envelope(json.loads(request.arguments_json))
    assert dict(envelope.arguments) == {"authorization_ref": _WE_COM_AUTH_REF}
    assert sdk.verify_context(
        method=request.provider_tool_id,
        operation_id="wecom.authorization.health.read",
        payload=dict(envelope.arguments),
        context=envelope.caller_context,
        key=_KEY,
        expected_caller_workload="exchange.integrations",
        expected_audience="wecom-authorization",
        expected_binding_id="wecom.binding.authorization",
        expected_organization_id=_ORG,
        expected_workspace_id=_WORKSPACE,
        expected_issuer=_ISSUER,
        expected_subject=_SUBJECT,
    )
    store.close()


@pytest.mark.parametrize("provider_id", ["azure", "gcp"])
def test_managed_cloud_token_ttl_is_not_projected_as_authorization_expiry(
    tmp_path: Path,
    provider_id: str,
) -> None:
    settings = _settings(
        include_wecom=False,
        include_email=False,
        include_gcp=provider_id == "gcp",
    )
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal, provider=provider_id)
    now = datetime.now(UTC)
    direct = _DirectClient(
        {
            "profile_ref": f"{provider_id}-prod",
            "provider": provider_id,
            "identity_ref": "managed-identity://health-test",
            "authentication_state": "VALID",
            "authorization_state": "VALID",
            "scope_refs": [f"{provider_id}.resource.read"],
            "checked_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=60))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "reason_code": None,
        }
    )
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={f"{provider_id}-prod": direct},
        email_client=None,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )

    observed = provider.authorization_health(principal, connection)

    assert observed.authorization_state == AuthorizationState.VALID
    assert observed.expires_at is None
    assert observed.capabilities[0].expires_at is None
    assert observed.generation == 0
    assert direct.requests[0].provider_tool_id == "cloud_provider_health"
    envelope = sdk.parse_tool_envelope(json.loads(direct.requests[0].arguments_json))
    assert dict(envelope.arguments) == {"profile_ref": f"{provider_id}-prod"}
    store.close()


@pytest.mark.parametrize(
    ("authentication", "authorization", "expected_login", "expected_state"),
    [
        (
            "INVALID",
            "REAUTHORIZATION_REQUIRED",
            LoginState.PRESENT,
            AuthorizationState.REAUTHORIZATION_REQUIRED,
        ),
        (
            "MISSING",
            "REAUTHORIZATION_REQUIRED",
            LoginState.MISSING,
            AuthorizationState.REAUTHORIZATION_REQUIRED,
        ),
        (
            "VALID",
            "PERMISSION_DENIED",
            LoginState.PRESENT,
            AuthorizationState.PERMISSION_DENIED,
        ),
        (
            "VALID",
            "VALID",
            LoginState.PRESENT,
            AuthorizationState.VALID,
        ),
        ("UNKNOWN", "UNKNOWN", LoginState.UNKNOWN, AuthorizationState.UNKNOWN),
    ],
)
def test_cloud_management_health_maps_official_auth_permission_and_unknown_states(
    tmp_path: Path,
    authentication: str,
    authorization: str,
    expected_login: LoginState,
    expected_state: AuthorizationState,
) -> None:
    registry = AuthorizationCloudProfileRegistry(
        _settings(include_wecom=False, include_email=False)
    )
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal, provider="azure")
    direct = _DirectClient(
        {
            "profile_ref": "azure-prod",
            "provider": "azure",
            "identity_ref": "managed-identity://health-test",
            "authentication_state": authentication,
            "authorization_state": authorization,
            "scope_refs": ["azure.subscription.read"],
            "checked_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": None,
            "reason_code": "PROVIDER_TIMEOUT"
            if authentication == "UNKNOWN"
            else "AUTHENTICATION_FAILED"
            if authorization == "REAUTHORIZATION_REQUIRED" and authentication == "INVALID"
            else "CREDENTIAL_MISSING"
            if authentication == "MISSING"
            else "SCOPE_DENIED"
            if authorization == "PERMISSION_DENIED"
            else None,
        }
    )
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"azure-prod": direct},
        email_client=None,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )

    observed = provider.authorization_health(principal, connection)

    assert observed.login_state == expected_login
    assert observed.authorization_state == expected_state
    assert observed.expires_at is None
    store.close()


@pytest.mark.parametrize(
    ("authentication", "authorization"),
    [("VALID", "DENIED"), ("INVALID", "NOT_A_PROVIDER_STATE")],
)
def test_cloud_management_health_rejects_noncanonical_state_values(
    tmp_path: Path,
    authentication: str,
    authorization: str,
) -> None:
    registry = AuthorizationCloudProfileRegistry(
        _settings(include_wecom=False, include_email=False)
    )
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal, provider="azure")
    direct = _DirectClient(
        {
            "profile_ref": "azure-prod",
            "provider": "azure",
            "identity_ref": "managed-identity://health-test",
            "authentication_state": authentication,
            "authorization_state": authorization,
            "scope_refs": ["azure.subscription.read"],
            "checked_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": None,
            "reason_code": "AUTHENTICATION_FAILED",
        }
    )
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"azure-prod": direct},
        email_client=None,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )

    with pytest.raises(ProviderObservationUnavailable, match="health state is invalid"):
        provider.authorization_health(principal, connection)

    store.close()


@pytest.mark.parametrize(
    ("authentication", "authorization", "reason_code", "expected_login", "expected_state"),
    [
        (
            "INVALID",
            "REAUTHORIZATION_REQUIRED",
            "AUTHENTICATION_FAILED",
            LoginState.PRESENT,
            AuthorizationState.REAUTHORIZATION_REQUIRED,
        ),
        (
            "VALID",
            "PERMISSION_DENIED",
            "SCOPE_DENIED",
            LoginState.PRESENT,
            AuthorizationState.PERMISSION_DENIED,
        ),
        (
            "VALID",
            "VALID",
            None,
            LoginState.PRESENT,
            AuthorizationState.VALID,
        ),
        (
            "UNKNOWN",
            "UNKNOWN",
            "PROVIDER_UNAVAILABLE",
            LoginState.UNKNOWN,
            AuthorizationState.UNKNOWN,
        ),
    ],
)
def test_cloud_management_health_contract_reaches_durable_runner_observation(
    tmp_path: Path,
    authentication: str,
    authorization: str,
    reason_code: str | None,
    expected_login: LoginState,
    expected_state: AuthorizationState,
) -> None:
    """Persist the native provider DTO before classifying authorization notifications."""

    settings = _settings(include_wecom=False, include_email=False, include_gcp=True)
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal, provider="gcp")
    checked_at = datetime.now(UTC)
    direct = _DirectClient(
        {
            "profile_ref": "gcp-prod",
            "provider": "gcp",
            "identity_ref": "workload-identity://health-test",
            "authentication_state": authentication,
            "authorization_state": authorization,
            "scope_refs": ["gcp.project.read"],
            "checked_at": checked_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": None,
            "reason_code": reason_code,
        }
    )
    contexts = _StaticContexts(principal)
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"gcp-prod": direct},
        email_client=None,
        current_context_resolver=contexts,
        context_key=lambda _reference: _KEY,
    )
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=contexts,
        provider=provider,
        email=None,
        worker_id="gcp-health-contract-test",
    )

    result = runner.run_once(now=checked_at + timedelta(seconds=1))

    observed = store.latest_authorization_health(principal, connection.id)
    assert result.authorization_checks == 1
    assert observed is not None
    assert observed.login_state == expected_login
    assert observed.authorization_state == expected_state
    assert observed.reason_code == reason_code
    assert observed.expires_at is None
    notifications = store.list_notifications(principal)
    if expected_state == AuthorizationState.REAUTHORIZATION_REQUIRED:
        assert [item.kind for item in notifications] == [
            IntegrationNotificationKind.AUTHORIZATION_REQUIRED
        ]
    else:
        assert notifications == []
    store.close()


def test_legacy_cloud_resources_query_uses_host_target_alias_and_projects_observation(
    tmp_path: Path,
) -> None:
    settings = _settings(include_wecom=False, include_email=False)
    legacy_profile = replace(settings.profiles["azure-prod"], audience="cloud-resources")
    settings = replace(settings, profiles={"azure-prod": legacy_profile})
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal, provider="azure")
    now = datetime.now(UTC)
    query = sdk.CloudQueryResult(
        provider="azure",
        checked_at=now,
        resources=(
            sdk.CloudObservation(
                external_ref="azure-vm-external-1",
                kind=sdk.CloudResourceKind.AZURE_VM,
                display_name="Production VM",
                status=sdk.CloudResourceState.RUNNING,
                provider_status="running",
                collected_at=now,
                observed_at=now,
                attributes={"region": "test-region", "cpuCount": 4},
                platform_resource_ref=None,
                platform_generation=None,
            ),
        ),
    )
    direct = _DirectClient(sdk.serialize_cloud_query_result(query))
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={"azure-prod": direct},
        email_client=None,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )

    observations = provider.cloud_resources(principal, connection)

    assert len(observations) == 1
    assert observations[0].provider == "azure"
    assert observations[0].source == "azure"
    assert observations[0].kind == "azure.vm"
    assert observations[0].status.value == "RUNNING"
    assert observations[0].attributes == {"region": "test-region", "cpuCount": 4}
    request = direct.requests[0]
    assert request.provider_tool_id == "cloud_resources_query"
    envelope = sdk.parse_tool_envelope(json.loads(request.arguments_json))
    assert dict(envelope.arguments) == {"target_ref": "azure-vm-prod"}
    assert sdk.verify_context(
        method=request.provider_tool_id,
        operation_id="cloud.resources.query",
        payload=dict(envelope.arguments),
        context=envelope.caller_context,
        key=_KEY,
        expected_caller_workload="exchange.integrations",
        expected_audience="cloud-resources",
        expected_binding_id="cloud.binding.azure",
        expected_organization_id=_ORG,
        expected_workspace_id=_WORKSPACE,
        expected_issuer=_ISSUER,
        expected_subject=_SUBJECT,
    )
    store.close()


def test_wecom_renewal_accepts_only_approved_official_navigation_urls(tmp_path: Path) -> None:
    settings = _settings(include_email=False)
    registry = AuthorizationCloudProfileRegistry(settings)
    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal)
    now = datetime.now(UTC)
    session = sdk.RenewalSession(
        session_ref="provider-session-1",
        authorization_ref=_WE_COM_AUTH_REF,
        state=sdk.RenewalState.WAITING_USER,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        authorization_url=(
            "https://work.weixin.qq.com/ai/qc/gen?source=wecom_cli_external&scode=abcdefgh12345678"
        ),
        qr_attachment_ref="wecom-qr-attachment-1",
        generation=2,
    )

    def start_with_url(url: str, request_id: str):
        direct_client = _DirectClient(
            sdk.serialize_renewal_session(replace(session, authorization_url=url))
        )
        provider_client = AuthorizationCloudDirectProvider(
            store=store,
            registry=registry,
            provider_clients={"wecom-prod": direct_client},
            email_client=None,
            current_context_resolver=_StaticContexts(principal),
            context_key=lambda _reference: _KEY,
        )
        result = provider_client.start_renewal(
            principal,
            connection,
            _WE_COM_AUTH_REF,
            request_id=request_id,
        )
        return result, direct_client

    started, direct = start_with_url(
        session.authorization_url,
        "product-session-request-id",
    )

    assert started.session_ref == "provider-session-1"
    assert started.authorization_url == session.authorization_url
    request = direct.requests[0]
    assert request.provider_tool_id == "wecom_reauthorization_start"
    envelope = sdk.parse_tool_envelope(json.loads(request.arguments_json))
    assert envelope.caller_context.request_id == "product-session-request-id"
    assert dict(envelope.arguments) == {"authorization_ref": _WE_COM_AUTH_REF}

    management_url = (
        "https://work.weixin.qq.com/ai/aiHelper/authorizationList?"
        "aibotid=12345678901234567&bar_style_type=3&for_native=true&forceInnerBrowser=1"
        "&from=chat&hide_more_btn=true&pc_bar_bg=f6f6f7%2C202021"
        "&str_aibotid=bot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=6&ww_vh=640&ww_vw=640"
    )
    shuffled_management_url = (
        "https://work.weixin.qq.com/ai/aiHelper/authorizationList?"
        "ww_vw=640&ww_vh=640&type=6&str_aibotid=bot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "&pc_bar_bg=f6f6f7%2C202021&hide_more_btn=true&from=chat"
        "&forceInnerBrowser=1&for_native=true&bar_style_type=3&aibotid=12345678901234567"
    )
    managed, management_direct = start_with_url(
        shuffled_management_url,
        "product-session-request-id-management",
    )
    assert managed.authorization_url == management_url
    assert management_direct.requests[0].provider_tool_id == "wecom_reauthorization_start"

    invalid_management_urls = [
        management_url + "&type=6",
        management_url + "&redirect=https%3A%2F%2Fevil.example",
        management_url.replace("type=6", "type=4"),
        management_url.replace("type=6", "type=5"),
        management_url.replace("work.weixin.qq.com", "work.weixin.qq.com.evil.example"),
        management_url.replace("work.weixin.qq.com", "sub.work.weixin.qq.com"),
        management_url.replace("work.weixin.qq.com", "work.weixin.qq.com:443"),
        management_url.replace("https://work.weixin.qq.com", "https://user@work.weixin.qq.com"),
        management_url + "#fragment",
        management_url + "#",
        management_url.replace(
            "/ai/aiHelper/authorizationList", "/prefix/ai/aiHelper/authorizationList"
        ),
        management_url + "/suffix",
        management_url.replace("aibotid=12345678901234567", "aibotid=1234567890123456"),
        management_url.replace(
            "str_aibotid=bot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "str_aibotid=bot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        management_url.replace("pc_bar_bg=f6f6f7%2C202021", "pc_bar_bg=not-colors"),
        management_url.replace("ww_vh=640", "ww_vh=0"),
        management_url.replace("ww_vw=640", "ww_vw=4097"),
        management_url.replace("ww_vh=640", "ww_vh=wide"),
        management_url.replace("forceInnerBrowser=1", "forceInnerBrowser=0"),
        management_url.replace("from=chat", "from=chatforce"),
        management_url.replace("&hide_more_btn=true", ""),
    ]
    invalid_qr_urls = [
        "https://work.weixin.qq.com:443/ai/qc/gen?source=wecom_cli_external&scode=abcdefgh12345678",
        "https://work.weixin.qq.com/ai/qc/gen"
        "?source=wecom_cli_external&scode=abcdefgh12345678"
        "&scode=abcdefgh12345678",
    ]
    for index, invalid_url in enumerate([*invalid_management_urls, *invalid_qr_urls]):
        with pytest.raises(RuntimeError, match="escaped its configured scope"):
            start_with_url(invalid_url, f"invalid-provider-session-{index}")
    store.close()


def _queue_test_notification_email(
    store: IntegrationStore,
    connection,
    *,
    now: datetime,
) -> EmailNotificationJob:
    """Create the same durable notification-derived job used by the worker."""

    claim = store.claim_authorization_checks("monitor", now=now)[0]
    store.complete_authorization_check(
        claim,
        AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=_WE_COM_AUTH_REF,
            login_state=LoginState.PRESENT,
            authorization_state=AuthorizationState.VALID,
            checked_at=now,
            expires_at=None,
            generation=1,
        ),
        [
            IntegrationNotificationDraft(
                connection_id=connection.id,
                kind=IntegrationNotificationKind.AUTHORIZATION_REQUIRED,
                severity=NotificationSeverity.ERROR,
                title="Reauthorization required",
                description="The provider confirmed that authorization is no longer valid.",
                dedupe_key="email-current-authority-test",
            )
        ],
        now=now,
        interval_seconds=900,
        email_recipient_ref="oncall",
    )
    with store._lock:
        row = store._connection.execute(
            "SELECT document FROM email_notification_outbox ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    return EmailNotificationJob.model_validate_json(str(row["document"]))


def _email_worker(
    store: IntegrationStore,
    registry: AuthorizationCloudProfileRegistry,
    resolver: PlatformCurrentAuthorizationContextResolver,
    mail: _DirectClient,
) -> AuthorizationCloudRunner:
    """Build the production resolver/adapter path around a synthetic DirectPlugin client."""

    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={},
        email_client=mail,
        current_context_resolver=resolver,
        context_key=lambda _reference: _KEY,
    )
    return AuthorizationCloudRunner(
        store=store,
        contexts=resolver,
        provider=provider,
        email=provider,
        worker_id="mail-worker",
        email_recipient_resolver=lambda _connection: "oncall",
    )


def _email_identity_resolver(
    store: IntegrationStore,
    registry: AuthorizationCloudProfileRegistry,
    identity: _IdentityVerifier,
    tokens: list[str | None],
) -> PlatformCurrentAuthorizationContextResolver:
    """Resolve each Product worker grant through a fresh synthetic bearer."""

    def next_bearer(_reference: str) -> str | None:
        return tokens.pop(0) if tokens else None

    return PlatformCurrentAuthorizationContextResolver(
        store=store,
        identity_verifier=identity,
        registry=registry,
        bearer_token=next_bearer,
    )


def test_email_worker_reverifies_claimed_then_sending_with_live_identity(tmp_path: Path) -> None:
    principal = _principal()
    settings = _settings(include_wecom=True, include_email=True)
    registry = AuthorizationCloudProfileRegistry(settings)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    job = _queue_test_notification_email(store, connection, now=now)
    identity = _EmailStateIdentityVerifier(
        store,
        job.id,
        {"token-v1": principal, "token-v2": principal},
    )
    resolver = _email_identity_resolver(
        store,
        registry,
        identity,
        ["token-v1", "token-v2"],
    )
    submission = sdk.EmailSubmission(
        request_ref=job.request_ref,
        status=sdk.EmailSubmissionStatus.ACCEPTED,
        vendor_receipt_ref="synthetic-receipt-1",
        delivery_confirmed=False,
    )
    mail = _DirectClient(sdk.serialize_email_submission(submission))
    runner = _email_worker(store, registry, resolver, mail)

    result = runner.run_once(now=now + timedelta(seconds=1))

    assert result.email_submissions == 1
    assert result.deferred == 0
    assert identity.calls == [
        ("token-v1", _WORKSPACE),
        ("token-v2", _WORKSPACE),
    ]
    assert identity.outbox_states == ["CLAIMED", "SENDING"]
    assert len(mail.requests) == 1
    request = mail.requests[0]
    assert request.provider_tool_id == "email_notification_send"
    envelope = sdk.parse_tool_envelope(json.loads(request.arguments_json))
    assert envelope.caller_context.operation_id == "email.notification.send"
    assert dict(envelope.arguments)["request_ref"] == job.request_ref
    persisted = store.get_email_notification_job(
        principal,
        job.id,
        authorization_operation_id="integrationDeliverNotification",
    )
    assert persisted.state.value == "ACCEPTED"
    assert persisted.attempts == 1
    store.close()


def test_email_revocation_between_claimed_precheck_and_sending_releases_without_send(
    tmp_path: Path,
) -> None:
    principal = _principal()
    revoked = _principal(operations={"integrationListConnections"})
    registry = AuthorizationCloudProfileRegistry(_settings(include_wecom=True, include_email=True))
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    job = _queue_test_notification_email(store, connection, now=now)
    identity = _EmailStateIdentityVerifier(
        store,
        job.id,
        {"token-v1": principal, "token-revoked": revoked},
    )
    resolver = _email_identity_resolver(
        store,
        registry,
        identity,
        ["token-v1", "token-revoked"],
    )
    mail = _DirectClient({})
    runner = _email_worker(store, registry, resolver, mail)

    result = runner.run_once(now=now + timedelta(seconds=1))

    assert result.email_submissions == 0
    assert result.deferred == 1
    assert identity.calls == [
        ("token-v1", _WORKSPACE),
        ("token-revoked", _WORKSPACE),
    ]
    assert identity.outbox_states == ["CLAIMED", "SENDING"]
    assert mail.requests == []
    persisted = store.get_email_notification_job(
        principal,
        job.id,
        authorization_operation_id="integrationDeliverNotification",
    )
    assert persisted.state.value == "READY"
    assert persisted.failure_reason_code == "current_authority_unavailable"
    assert persisted.attempts == 1
    store.close()


def test_email_missing_live_bearer_defers_claim_without_sending_or_unknown(
    tmp_path: Path,
) -> None:
    principal = _principal()
    registry = AuthorizationCloudProfileRegistry(_settings(include_wecom=True, include_email=True))
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
    job = _queue_test_notification_email(store, connection, now=now)
    identity = _IdentityVerifier({})
    resolver = _email_identity_resolver(store, registry, identity, [None])
    mail = _DirectClient({})
    runner = _email_worker(store, registry, resolver, mail)

    result = runner.run_once(now=now + timedelta(seconds=1))

    assert result.email_submissions == 0
    assert result.deferred == 1
    assert identity.calls == []
    assert mail.requests == []
    persisted = store.get_email_notification_job(
        principal,
        job.id,
        authorization_operation_id="integrationDeliverNotification",
    )
    assert persisted.state.value == "READY"
    assert persisted.failure_reason_code == "current_authority_unavailable"
    assert persisted.attempts == 0
    store.close()


def test_huggingface_renewal_uses_owner_scoped_account_center_device_session(
    tmp_path: Path,
) -> None:
    """HF renewal returns only official device metadata through its linked profile."""

    class _AccountCenter:
        def __init__(self, selected_profile_ref: str) -> None:
            self.selected_profile_ref = selected_profile_ref
            self.calls: list[tuple[str, str, str]] = []

        def begin_huggingface_renewal(
            self,
            _principal: IntegrationPrincipal,
            *,
            profile_ref: str,
            session_ref: str,
        ) -> dict[str, Any]:
            self.calls.append(("begin", profile_ref, session_ref))
            return {
                "profile_ref": self.selected_profile_ref,
                "session_ref": session_ref,
                "state": "waiting_user",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://hf.co/oauth/device",
                "expires_at": 1_800_000_000,
                "interval_seconds": 5,
                "generation": 7,
                "reason_code": None,
            }

        def poll_huggingface_renewal(
            self,
            _principal: IntegrationPrincipal,
            *,
            profile_ref: str,
            session_ref: str,
        ) -> dict[str, Any]:
            self.calls.append(("poll", profile_ref, session_ref))
            return {
                "profile_ref": self.selected_profile_ref,
                "session_ref": session_ref,
                "state": "succeeded",
                "user_code": None,
                "verification_uri": None,
                "expires_at": None,
                "interval_seconds": None,
                "generation": 8,
                "reason_code": None,
            }

    principal = _principal()
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _hf_connection(store, principal)
    profile_ref = connection.account_link_ref
    assert profile_ref is not None
    account_center = _AccountCenter(profile_ref)
    registry = AuthorizationCloudProfileRegistry(_hf_settings())
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={},
        email_client=None,
        account_center=account_center,
        current_context_resolver=_StaticContexts(principal),
        context_key=lambda _reference: _KEY,
    )
    session_ref = "30000000-0000-4000-8000-000000000001"

    started = provider.start_renewal(
        principal,
        connection,
        profile_ref,
        request_id=session_ref,
    )
    assert started.session_ref == session_ref
    assert started.state.value == "WAITING_USER"
    assert started.authorization_url == "https://hf.co/oauth/device"
    assert started.user_code == "ABCD-EFGH"
    assert started.qr_attachment_ref is None
    assert account_center.calls == [("begin", profile_ref, session_ref)]

    now = datetime(2026, 10, 26, 12, tzinfo=UTC)
    claim = store.claim_authorization_checks("renewal-test", now=now)[0]
    store.complete_authorization_check(
        claim,
        AuthorizationHealthRecord(
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            actor_issuer=connection.actor_issuer,
            actor_subject=connection.actor_subject,
            connection_id=connection.id,
            authorization_ref=profile_ref,
            login_state=LoginState.PRESENT,
            authorization_state=AuthorizationState.REAUTHORIZATION_REQUIRED,
            checked_at=now,
            generation=7,
        ),
        [],
        now=now,
    )
    completed = provider.renewal_status(
        principal,
        profile_ref,
        session_ref,
        request_id="renewal-status-request",
    )
    assert completed.session_ref == session_ref
    assert completed.state.value == "SUCCEEDED"
    assert completed.user_code is None
    assert account_center.calls[-1] == ("poll", profile_ref, session_ref)
    store.close()
