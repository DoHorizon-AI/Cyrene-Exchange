"""Closed host-profile startup checks without contacting Authority or Plugins.

Module: product.tests.test_authorization_cloud_config
Role: Verify production builder configuration and per-call bearer revalidation.
模块职责：验证生产配置构建以及每次调用重新验证 bearer。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import cyrene_exchange_product.integrations.auth as auth_module
import cyrene_exchange_product.integrations.cli as integration_cli
import cyrene_exchange_product.integrations.clients as clients_module
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    AuthorizationCloudConfigurationError,
    AuthorizationCloudProfileRegistry,
    parse_authorization_cloud_settings,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationPrincipal,
)


def _config(tmp_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    root_cert = tmp_path / "platform-root.pem"
    product_cert = tmp_path / "product-cert.pem"
    product_key = tmp_path / "product-key.pem"
    for path in (root_cert, product_cert, product_key):
        path.write_text("synthetic test material", encoding="ascii")
    product_key.chmod(0o600)
    secret_refs = {
        "platform/root": "PLATFORM_ROOT",
        "platform/product-cert": "PLATFORM_PRODUCT_CERT",
        "platform/product-key": "PLATFORM_PRODUCT_KEY",
        "account/signing": "ACCOUNT_SIGNING",
        "account/callback": "ACCOUNT_CALLBACK",
        "account/wecom-source": "ACCOUNT_WECOM_SOURCE",
        "wecom/inbound": "WECOM_INBOUND",
        "bearers/actor-a": "CURRENT_ACTOR_BEARER",
        "keys/wecom": "WECOM_AUTH_CONTEXT_KEY",
        "keys/azure": "AZURE_AUTH_CONTEXT_KEY",
        "keys/email": "EMAIL_CONTEXT_KEY",
    }
    configuration = {
        "schemaVersion": 1,
        "hostSecretRefs": secret_refs,
        "platformAuthority": {
            "audience": "exchange-product",
            "identity": {
                "connectionRef": "unix:///tmp/platform-authority.sock",
                "transport": "local",
            },
            "productWorkload": {
                "connectionRef": "grpcs://authority.example:7443",
                "workloadId": "exchange-product",
                "audience": "exchange-product",
                "rootCertificateRef": "platform/root",
                "clientCertificateRef": "platform/product-cert",
                "clientKeyRef": "platform/product-key",
            },
        },
        "accountCenter": {
            "bindingId": "account-center-binding",
            "connectionRef": "grpc://127.0.0.1:5500",
            "transport": "local",
            "callerId": "exchange-service",
            "signingKeyRef": "account/signing",
            "callbackCallerId": "exchange-callback",
            "callbackSigningKeyRef": "account/callback",
            "wecomSourceCallerId": "exchange-wecom-source",
            "wecomSourceSigningKeyRef": "account/wecom-source",
        },
        "githubIssues": {
            "bindingId": "github-binding",
            "connectionRef": "grpc://127.0.0.1:5501",
            "transport": "local",
            "callerId": "exchange-service",
            "signingKeyRef": "account/signing",
        },
        "wecom": {
            "bindingId": "wecom-message-binding",
            "connectionRef": "grpc://127.0.0.1:5502",
            "transport": "local",
            "targets": {"oncall": {"botId": "bot-1", "conversationId": "group-1", "kind": "GROUP"}},
            "inboundSources": {
                "0a8f22dd-2a49-4ef2-9b36-a8d37ac10a12": {
                    "organizationId": "org-a",
                    "workspaceId": "workspace-a",
                    "sourceAuthority": "wecom.example",
                    "botNamespace": "bot-namespace",
                    "accountId": "bot:exchange",
                    "groupConversationId": "group-1",
                    "requestHmacSecretRef": "wecom/inbound",
                }
            },
        },
        "authorizationCloud": {
            "monitorIntervalSeconds": 900,
            "currentAuthority": {
                "contexts": [
                    {
                        "contextRef": "actor-a",
                        "issuer": "https://identity.example.test",
                        "subject": "member-a",
                        "organizationId": "org-a",
                        "workspaceId": "workspace-a",
                        "bearerTokenEnvRef": "bearers/actor-a",
                    }
                ]
            },
            "profiles": {
                "wecom-prod": {
                    "provider": "wecom",
                    "directPlugin": {
                        "bindingId": "wecom.authorization.binding",
                        "connectionRef": "grpc://127.0.0.1:5503",
                        "transport": "local",
                    },
                    "callerWorkload": "exchange.integrations",
                    "audience": "wecom-authorization",
                    "expectedIssuer": "https://identity.example.test",
                    "contextKeyRef": "keys/wecom",
                    "organizationId": "org-a",
                    "workspaceId": "workspace-a",
                    "allowedContextRefs": ["actor-a"],
                    "displayName": "WeCom Production",
                    "authorizationRef": "wecom-auth-1",
                },
                "azure-prod": {
                    "provider": "azure",
                    "directPlugin": {
                        "bindingId": "cloud.binding.azure",
                        "connectionRef": "grpc://127.0.0.1:5504",
                        "transport": "local",
                    },
                    "callerWorkload": "exchange.integrations",
                    "audience": "cloud-resources",
                    "expectedIssuer": "https://identity.example.test",
                    "contextKeyRef": "keys/azure",
                    "organizationId": "org-a",
                    "workspaceId": "workspace-a",
                    "allowedContextRefs": ["actor-a"],
                    "targets": {
                        "vm-prod": {
                            "targetRef": "azure-vm-1",
                            "displayName": "Production VM",
                            "allowedContextRefs": ["actor-a"],
                        }
                    },
                },
            },
        },
        "emailNotifications": {
            "enabled": True,
            "directPlugin": {
                "bindingId": "email.binding.notifications",
                "connectionRef": "grpc://127.0.0.1:5505",
                "transport": "local",
            },
            "callerWorkload": "cyrene-exchange",
            "audience": "cyrene.connectors.email-notification",
            "expectedIssuer": "https://identity.example.test",
            "contextKeyRef": "keys/email",
            "organizationId": "org-a",
            "workspaceId": "workspace-a",
            "recipientRef": "oncall",
            "allowedContextRefs": ["actor-a"],
        },
    }
    environ = {
        integration_cli.CONFIGURATION_ENV: json.dumps(configuration),
        "PLATFORM_ROOT": str(root_cert),
        "PLATFORM_PRODUCT_CERT": str(product_cert),
        "PLATFORM_PRODUCT_KEY": str(product_key),
        "ACCOUNT_SIGNING": "a" * 64,
        "ACCOUNT_CALLBACK": "b" * 64,
        "ACCOUNT_WECOM_SOURCE": "c" * 64,
        "WECOM_INBOUND": "request-hmac-key-value-that-is-long-enough",
        "WECOM_AUTH_CONTEXT_KEY": "d" * 64,
        "AZURE_AUTH_CONTEXT_KEY": "e" * 64,
        "EMAIL_CONTEXT_KEY": "f" * 64,
        # Intentionally absent until a host supplies a live actor bearer.
    }
    return configuration, environ


def test_host_preflight_accepts_live_bearer_reference_without_caching_a_value(
    tmp_path: Path,
) -> None:
    _, environ = _config(tmp_path)

    result = integration_cli.validate_host_configuration(environ=environ)

    assert result["authorizationCloudProfileCount"] == 2
    assert result["currentAuthorityContextCount"] == 1
    assert result["emailNotificationsEnabled"] is True
    assert "CURRENT_ACTOR_BEARER" not in str(result)


def test_host_profiles_reject_unbound_or_mismatched_actor_contexts(tmp_path: Path) -> None:
    configuration, _ = _config(tmp_path)
    settings = configuration["authorizationCloud"]
    settings["profiles"]["azure-prod"]["allowedContextRefs"] = ["not-configured"]

    with pytest.raises(AuthorizationCloudConfigurationError, match="unknown actor context"):
        parse_authorization_cloud_settings(
            settings,
            email_value=configuration["emailNotifications"],
        )


def test_target_specific_actor_allowlist_denies_other_configured_member(
    tmp_path: Path,
) -> None:
    configuration, _ = _config(tmp_path)
    settings = configuration["authorizationCloud"]
    settings["currentAuthority"]["contexts"].append(
        {
            "contextRef": "member-b",
            "issuer": "https://identity.example.test",
            "subject": "member-b",
            "organizationId": "org-a",
            "workspaceId": "workspace-a",
            "bearerTokenEnvRef": "bearers/member-b",
        }
    )
    settings["profiles"]["azure-prod"]["allowedContextRefs"].append("member-b")
    registry = AuthorizationCloudProfileRegistry(
        parse_authorization_cloud_settings(
            settings,
            email_value=configuration["emailNotifications"],
        )
    )
    other_actor = IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject="member-b",
        organization_id="org-a",
        workspace_id="workspace-a",
        allowed_operation_ids=frozenset({"integrationCreateConnection"}),
    )

    with pytest.raises(PermissionError, match="target is not allowed"):
        registry.display_name_for_connection(
            other_actor,
            CreateIntegrationConnection(
                provider="azure",
                binding_ref="azure-prod",
                target_ref="vm-prod",
            ),
        )

    configuration, _ = _config(tmp_path)
    settings = configuration["authorizationCloud"]
    settings["profiles"]["azure-prod"]["expectedIssuer"] = "https://wrong.example"
    with pytest.raises(AuthorizationCloudConfigurationError, match="actor pins"):
        parse_authorization_cloud_settings(
            settings,
            email_value=configuration["emailNotifications"],
        )


def test_disabled_mail_profile_cannot_retain_binding_or_recipient(tmp_path: Path) -> None:
    configuration, _ = _config(tmp_path)
    settings = configuration["authorizationCloud"]
    with pytest.raises(AuthorizationCloudConfigurationError, match="disabled emailNotifications"):
        parse_authorization_cloud_settings(
            settings,
            email_value={"enabled": False, "recipientRef": "oncall"},
        )


def test_documented_host_configuration_sample_matches_the_closed_parser() -> None:
    sample_path = (
        Path(__file__).parents[1] / "examples/integration-configuration.authorization-cloud.json"
    )
    configuration = json.loads(sample_path.read_text(encoding="utf-8"))
    settings = parse_authorization_cloud_settings(
        configuration["authorizationCloud"],
        email_value=configuration["emailNotifications"],
    )
    assert set(settings.profiles) == {"wecom-primary", "azure-primary"}
    assert settings.email.enabled is False


def test_documented_configuration_schema_accepts_default_and_enabled_email_examples() -> None:
    """Keep the reusable schema synchronized with both copyable configuration examples."""

    examples = Path(__file__).parents[1] / "examples"
    schema = json.loads(
        (examples / "authorization-cloud-configuration.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)

    full_configuration = json.loads(
        (examples / "integration-configuration.authorization-cloud.json").read_text(
            encoding="utf-8"
        )
    )
    default_fragment = {
        "authorizationCloud": full_configuration["authorizationCloud"],
        "emailNotifications": full_configuration["emailNotifications"],
    }
    Draft202012Validator(schema).validate(default_fragment)

    enabled_email = json.loads(
        (examples / "email-notifications.enabled.fragment.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(enabled_email)


class _FakeAuthority:
    def __init__(self, principals: dict[str, IntegrationPrincipal]) -> None:
        self.principals = principals
        self.calls: list[str] = []

    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal:
        self.calls.append(bearer_token)
        principal = self.principals[bearer_token]
        assert principal.workspace_id == workspace_id
        return principal


class _FakeDirectClient:
    def __init__(self) -> None:
        self.closed = False
        self.invokes = 0

    def invoke(self, **_kwargs: Any) -> None:
        self.invokes += 1
        raise AssertionError("startup must not call a provider")

    def close(self) -> None:
        self.closed = True


class _FakeHealth:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_production_builder_wires_profiles_and_rechecks_rotating_bearer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, environ = _config(tmp_path)
    operations = {
        "integrationCreateConnection",
        "integrationGetAuthorizationHealth",
        "integrationRefreshConnectionResources",
        "integrationListNotifications",
        "integrationDeliverNotification",
        "integrationGetOperation",
    }
    principal = IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject="member-a",
        organization_id="org-a",
        workspace_id="workspace-a",
        allowed_operation_ids=frozenset(operations),
    )
    revoked = IntegrationPrincipal(
        issuer=principal.issuer,
        subject=principal.subject,
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        allowed_operation_ids=frozenset(),
    )
    authority = _FakeAuthority({"token-v1": principal, "token-v2": principal, "revoked": revoked})
    direct_clients: list[_FakeDirectClient] = []

    monkeypatch.setattr(
        auth_module.PlatformAuthorityIdentityVerifier,
        "from_unix_socket",
        classmethod(lambda _cls, _path: authority),
    )

    def direct_client(_reference: str, **_kwargs: Any) -> _FakeDirectClient:
        client = _FakeDirectClient()
        direct_clients.append(client)
        return client

    monkeypatch.setattr(clients_module, "direct_plugin_client_from_connection", direct_client)
    monkeypatch.setattr(clients_module, "DirectPluginHealthClient", _FakeHealth)
    environ["CURRENT_ACTOR_BEARER"] = "token-v1"

    services = integration_cli.build_production_services(
        tmp_path / "integrations.sqlite3",
        environ=environ,
    )
    try:
        assert services.authorization_cloud is not None
        assert services.current_context_resolver is not None
        assert services.email_notifications is not None
        assert services.authorization_cloud_runner is not None
        assert services.email_delivery_recipient_resolver is not None

        request = CreateIntegrationConnection(
            provider="azure",
            binding_ref="azure-prod",
            target_ref="vm-prod",
        )
        assert services.connection_profile_resolver is not None
        request = request.model_copy(
            update={"display_name": services.connection_profile_resolver(principal, request)}
        )
        connection = services.store.create_connection(
            principal,
            request,
            idempotency_key="builder-profile-test",
        )
        resolver = services.current_context_resolver
        assert (
            resolver.for_connection(
                connection,
                operation_id="integrationGetAuthorizationHealth",
            )
            == principal
        )

        environ["CURRENT_ACTOR_BEARER"] = "token-v2"
        assert (
            resolver.for_connection(
                connection,
                operation_id="integrationGetAuthorizationHealth",
            )
            == principal
        )

        environ["CURRENT_ACTOR_BEARER"] = "revoked"
        assert (
            resolver.for_connection(
                connection,
                operation_id="integrationGetAuthorizationHealth",
            )
            is None
        )
        assert authority.calls == ["token-v1", "token-v2", "revoked"]
        assert services.email_delivery_recipient_resolver(principal) == "oncall"
        assert direct_clients and all(client.invokes == 0 for client in direct_clients)
    finally:
        services.close()
