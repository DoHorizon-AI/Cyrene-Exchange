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
from typing import Any

import pytest
from cyrene_plugin_runtime import DirectPayload

from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
    tool_provider_pb2 as tool_wire,
)
from cyrene_exchange_product.integrations.authorization_cloud import (
    AuthorizationCloudRunner,
)
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    AuthorizationCloudConfigurationError,
    AuthorizationCloudProfileRegistry,
    parse_authorization_cloud_settings,
)
from cyrene_exchange_product.integrations.authorization_cloud_provider import (
    AuthorizationCloudDirectProvider,
    PlatformCurrentAuthorizationContextResolver,
)
from cyrene_exchange_product.integrations.models import (
    AuthorizationHealthRecord,
    AuthorizationState,
    CreateIntegrationConnection,
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


def _settings(*, include_wecom: bool = True, include_email: bool = True):
    profiles: dict[str, Any] = {
        "azure-prod": {
            "provider": "azure",
            "directPlugin": {
                "bindingId": "cloud.binding.azure",
                "connectionRef": "grpc://127.0.0.1:5501",
                "transport": "local",
            },
            "callerWorkload": "exchange.integrations",
            "audience": "cloud-resources",
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


def _connection(store: IntegrationStore, principal: IntegrationPrincipal, provider: str = "wecom"):
    return store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider=provider,
            binding_ref="wecom-prod" if provider == "wecom" else "azure-prod",
            target_ref=None if provider == "wecom" else "vm-prod",
            display_name="WeCom" if provider == "wecom" else "Production VM",
        ),
        idempotency_key=f"connection-{provider}",
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


class _StaticContexts:
    def __init__(self, principal: IntegrationPrincipal) -> None:
        self.principal = principal

    def for_connection(self, connection, *, operation_id: str):
        self.principal.require(operation_id)
        assert connection.actor_subject == self.principal.subject
        return self.principal

    def for_notification(self, job, *, operation_id: str):
        self.principal.require(operation_id)
        assert job.actor_subject == self.principal.subject
        return self.principal


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


def test_cloud_query_uses_host_target_alias_and_projects_provider_observation(
    tmp_path: Path,
) -> None:
    settings = _settings(include_wecom=False, include_email=False)
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


class _FlippingContexts:
    def __init__(self, principal: IntegrationPrincipal) -> None:
        self.principal = principal
        self.calls = 0

    def for_notification(self, job, *, operation_id: str):
        assert operation_id == "integrationDeliverNotification"
        self.calls += 1
        return self.principal if self.calls == 1 else None


def test_email_revocation_between_precheck_and_sign_releases_without_send(
    tmp_path: Path,
) -> None:
    principal = _principal()
    settings = _settings(include_wecom=True, include_email=True)
    registry = AuthorizationCloudProfileRegistry(settings)
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = _connection(store, principal)
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)
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
                dedupe_key="mail-revocation-test",
            )
        ],
        now=now,
        interval_seconds=900,
        email_recipient_ref="oncall",
    )
    contexts = _FlippingContexts(principal)
    mail = _DirectClient({})
    provider = AuthorizationCloudDirectProvider(
        store=store,
        registry=registry,
        provider_clients={},
        email_client=mail,
        current_context_resolver=contexts,
        context_key=lambda reference: _KEY,
    )
    runner = AuthorizationCloudRunner(
        store=store,
        contexts=contexts,
        provider=provider,
        email=provider,
        worker_id="mail-worker",
        email_recipient_resolver=lambda _connection: "oncall",
    )

    result = runner.run_once(now=now + timedelta(seconds=1))
    job = store._connection.execute("SELECT document FROM email_notification_outbox").fetchone()

    assert result.email_submissions == 0
    assert result.deferred == 1
    assert contexts.calls == 2
    assert mail.requests == []
    assert job is not None
    persisted = store.get_email_notification_job(
        principal,
        __import__("uuid").UUID(json.loads(job["document"])["id"]),
        authorization_operation_id="integrationDeliverNotification",
    )
    assert persisted.state.value == "READY"
    assert persisted.failure_reason_code == "current_authority_unavailable"
    store.close()
