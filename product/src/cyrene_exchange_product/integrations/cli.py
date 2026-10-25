"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 cli.py                                                          │
│  Module: cyrene_exchange_product.integrations.cli                   │
│  Role: Resolve host configuration and build production integrations. │
│                                                                     │
│  模块职责：解析 Host 配置并构建生产集成客户端。                          │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import ssl
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID

from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.clients import (
    DEFAULT_GITHUB_PROVIDER_RPC_DEADLINE_SECONDS,
    MAX_GITHUB_PROVIDER_RPC_DEADLINE_SECONDS,
)

CONFIGURATION_ENV = "CYRENE_EXCHANGE_INTEGRATION_CONFIGURATION_JSON"
MAX_CONFIGURATION_BYTES = 64 * 1024
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class IntegrationConfigurationError(ValueError):
    """Host configuration cannot construct a complete fixed integration path."""


def build_production_services(
    database_path: Path | str,
    *,
    environ: Mapping[str, str] | None = None,
) -> IntegrationServices:
    """Resolve trusted configuration into production clients and a separate store.

    All provider endpoints and secret references come from the host-projected
    Exchange integration configuration. Missing capabilities fail closed.
    中文：端点与密钥引用只来自 Host 配置，缺失 capability 时拒绝启动。
    """

    from cyrene_exchange_product.integrations.auth import (
        AccountCenterRequestSigner,
        PlatformAuthorityIdentityVerifier,
        PlatformExecutionAuthorizationVerifier,
    )
    from cyrene_exchange_product.integrations.authorization_cloud import AuthorizationCloudRunner
    from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
        AuthorizationCloudConfigurationError,
        AuthorizationCloudProfileRegistry,
        parse_authorization_cloud_settings,
    )
    from cyrene_exchange_product.integrations.authorization_cloud_provider import (
        AuthorizationCloudDirectProvider,
        PlatformCurrentAuthorizationContextResolver,
    )
    from cyrene_exchange_product.integrations.clients import (
        DEFAULT_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
        MAX_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
        AccountCenterClient,
        ComputerRunnerClient,
        DirectPluginHealthClient,
        GitHubIssuesClient,
        GitHubWebhookClient,
        IntegrationAccountCenterPort,
        IntegrationGitHubPort,
        PlatformAuthorityDelegationClient,
        PlatformConnectorAuthorizationClient,
        TeamsMessageClient,
        WeComMessageClient,
        direct_plugin_client_from_connection,
    )
    from cyrene_exchange_product.integrations.connector_operations import (
        ConnectorOperationDispatcher,
    )
    from cyrene_exchange_product.integrations.connector_profiles import (
        ConnectorHostConfigurationError,
        parse_connector_host_settings,
    )
    from cyrene_exchange_product.integrations.connector_security import (
        ConnectorOperationGrantVerifier,
        NavigatorHmacAuthenticator,
        NavigatorHmacSettings,
    )
    from cyrene_exchange_product.integrations.dispatcher import (
        DispatcherRunner,
        IntegrationDispatcher,
    )
    from cyrene_exchange_product.integrations.intake import WeComInboundSource
    from cyrene_exchange_product.integrations.models import IntegrationPrincipal
    from cyrene_exchange_product.integrations.store import IntegrationStore

    source = os.environ if environ is None else environ
    validate_host_configuration(environ=source)
    configuration = _read_configuration(source)
    refs = _secret_refs(configuration.get("hostSecretRefs"))
    used_refs: set[str] = set()
    try:
        connector_settings = parse_connector_host_settings(configuration.get("connectorHost", {}))
    except ConnectorHostConfigurationError as exc:
        raise IntegrationConfigurationError(str(exc)) from exc

    try:
        authorization_settings = (
            parse_authorization_cloud_settings(
                configuration["authorizationCloud"],
                email_value=configuration.get("emailNotifications"),
            )
            if "authorizationCloud" in configuration
            else None
        )
    except AuthorizationCloudConfigurationError as exc:
        raise IntegrationConfigurationError(str(exc)) from exc

    def secret(reference: object) -> str:
        if not isinstance(reference, str) or reference not in refs:
            raise IntegrationConfigurationError("configuration refers to an unknown host secret")
        used_refs.add(reference)
        value = source.get(refs[reference], "")
        if not value:
            raise IntegrationConfigurationError("a configured host secret is unavailable")
        return value

    def secret_path(reference: object) -> Path:
        return Path(secret(reference)).expanduser()

    def hmac_key(reference: object) -> bytes:
        encoded = secret(reference)
        try:
            key = (
                bytes.fromhex(encoded)
                if len(encoded) == 64
                else base64.b64decode(encoded, validate=True)
            )
        except (ValueError, TypeError):
            raise IntegrationConfigurationError("a configured HMAC key is malformed") from None
        if len(key) != 32:
            raise IntegrationConfigurationError("configured HMAC keys must decode to 32 bytes")
        return key

    def direct_client(value: object) -> Any:
        if not isinstance(value, Mapping) or not {
            "bindingId",
            "connectionRef",
            "transport",
        } <= set(value):
            raise IntegrationConfigurationError("DirectPluginRuntime endpoint is incomplete")
        endpoint = dict(value)
        transport = endpoint["transport"]
        connection_ref = _text(endpoint["connectionRef"], "connectionRef")
        mtls = endpoint.get("mtls")
        if transport == "local":
            if mtls is not None:
                raise IntegrationConfigurationError("local Plugin connections cannot specify mTLS")
            return direct_plugin_client_from_connection(connection_ref)
        if transport != "mtls" or not isinstance(mtls, Mapping):
            raise IntegrationConfigurationError("remote Plugin connections require an mTLS profile")
        _exact_fields(
            mtls,
            required={"rootCertificateRef", "clientCertificateRef", "clientKeyRef"},
            optional=set(),
            label="DirectPluginRuntime mTLS profile",
        )
        return direct_plugin_client_from_connection(
            connection_ref,
            root_certificates_path=secret_path(mtls["rootCertificateRef"]),
            private_key_path=secret_path(mtls["clientKeyRef"]),
            certificate_chain_path=secret_path(mtls["clientCertificateRef"]),
        )

    def direct_health_client(value: Mapping[str, Any]) -> DirectPluginHealthClient:
        """Resolve the fixed DirectPluginRuntime Health channel from host config."""

        connection_ref = _text(value["connectionRef"], "connectionRef")
        if value["transport"] == "local":
            return DirectPluginHealthClient(connection_ref)
        mtls = _config_object(
            value.get("mtls"),
            required={"rootCertificateRef", "clientCertificateRef", "clientKeyRef"},
            optional=set(),
            label="DirectPluginRuntime health mTLS profile",
        )
        return DirectPluginHealthClient(
            connection_ref,
            root_certificates_path=secret_path(mtls["rootCertificateRef"]),
            certificate_chain_path=secret_path(mtls["clientCertificateRef"]),
            private_key_path=secret_path(mtls["clientKeyRef"]),
        )

    # ── Phase 1: Validate the authority channels and workload profile ─────
    authority = _config_object(
        configuration["platformAuthority"],
        required=set(),
        optional={"audience", "identity", "productWorkload", "connectorWorkload"},
        label="platformAuthority",
    )
    identity_verifier = None
    authority_client = None
    connector_authority = None
    execution_verifier = None
    workload_id = "exchange-connectors"

    if "productWorkload" in authority:
        if "identity" not in authority or "audience" not in authority:
            raise IntegrationConfigurationError(
                "legacy ProductWorkload requires Platform identity and audience profiles"
            )
        identity_profile = _config_object(
            authority["identity"],
            required={"connectionRef", "transport"},
            optional={"mtls"},
            label="Platform identity profile",
        )
        identity_ref = _text(identity_profile["connectionRef"], "identity.connectionRef")
        if identity_profile["transport"] == "local":
            if not identity_ref.startswith("unix://") or "mtls" in identity_profile:
                raise IntegrationConfigurationError(
                    "local Platform identity verification requires a protected Unix socket"
                )
            identity_verifier = PlatformAuthorityIdentityVerifier.from_unix_socket(
                Path(identity_ref.removeprefix("unix://"))
            )
        elif identity_profile["transport"] == "mtls":
            if not identity_ref.startswith("grpcs://"):
                raise IntegrationConfigurationError("remote Platform identity must use grpcs://")
            tls = _config_object(
                identity_profile.get("mtls"),
                required={"rootCertificateRef", "clientCertificateRef", "clientKeyRef"},
                optional=set(),
                label="Platform identity mTLS profile",
            )
            identity_verifier = PlatformAuthorityIdentityVerifier.from_managed_tls_files(
                target=identity_ref.removeprefix("grpcs://"),
                root_certificates_path=secret_path(tls["rootCertificateRef"]),
                private_key_path=secret_path(tls["clientKeyRef"]),
                certificate_chain_path=secret_path(tls["clientCertificateRef"]),
            )
        else:
            raise IntegrationConfigurationError("Platform identity transport is unsupported")

        workload = _config_object(
            authority["productWorkload"],
            required={
                "connectionRef",
                "workloadId",
                "audience",
                "rootCertificateRef",
                "clientCertificateRef",
                "clientKeyRef",
            },
            optional=set(),
            label="Platform ProductWorkload profile",
        )
        workload_ref = _text(workload["connectionRef"], "productWorkload.connectionRef")
        if not workload_ref.startswith("grpcs://"):
            raise IntegrationConfigurationError("Platform ProductWorkload must use grpcs:// mTLS")
        authority_target = workload_ref.removeprefix("grpcs://")
        authority_root = secret_path(workload["rootCertificateRef"])
        authority_key = secret_path(workload["clientKeyRef"])
        authority_chain = secret_path(workload["clientCertificateRef"])
        workload_id = _text(workload["workloadId"], "productWorkload.workloadId")
        audience = _text(authority["audience"], "platformAuthority.audience")
        if _text(workload["audience"], "productWorkload.audience") != audience:
            raise IntegrationConfigurationError(
                "Platform workload audience does not match authority"
            )
        authority_client = PlatformAuthorityDelegationClient(
            identity_verifier=identity_verifier,
            target=workload_ref,
            root_certificates_path=authority_root,
            private_key_path=authority_key,
            certificate_chain_path=authority_chain,
            workload_id=workload_id,
            audience=audience,
        )
        execution_verifier = PlatformExecutionAuthorizationVerifier.from_managed_tls_files(
            target=authority_target,
            root_certificates_path=authority_root,
            private_key_path=authority_key,
            certificate_chain_path=authority_chain,
        )

    if "connectorWorkload" in authority:
        connector_workload = _config_object(
            authority["connectorWorkload"],
            required={
                "connectionRef",
                "rootCertificateRef",
                "clientCertificateRef",
                "clientKeyRef",
            },
            optional={"deadlineSeconds"},
            label="Platform connector workload",
        )
        connector_authority = PlatformConnectorAuthorizationClient(
            target=_text(connector_workload["connectionRef"], "connectorWorkload.connectionRef"),
            root_certificates_path=secret_path(connector_workload["rootCertificateRef"]),
            certificate_chain_path=secret_path(connector_workload["clientCertificateRef"]),
            private_key_path=secret_path(connector_workload["clientKeyRef"]),
            deadline_seconds=float(connector_workload.get("deadlineSeconds", 3.0)),
        )
    if authority_client is None and connector_authority is None:
        raise IntegrationConfigurationError(
            "platformAuthority requires connectorWorkload or legacy productWorkload"
        )

    # ── Phase 2: Resolve the caller, provider, webhook, and notification ports ──
    account_settings = _config_object(
        configuration["accountCenter"],
        required={
            "bindingId",
            "connectionRef",
            "transport",
            "callerId",
            "signingKeyRef",
        },
        optional={
            "mtls",
            "deadlineSeconds",
            "githubAppInstallationDeadlineSeconds",
            "callbackCallerId",
            "callbackSigningKeyRef",
            "wecomSourceCallerId",
            "wecomSourceSigningKeyRef",
        },
        label="accountCenter",
    )
    account_binding = _text(account_settings["bindingId"], "accountCenter.bindingId")
    github_app_installation_deadline_seconds = _bounded_deadline_seconds(
        account_settings.get(
            "githubAppInstallationDeadlineSeconds",
            DEFAULT_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
        ),
        "accountCenter.githubAppInstallationDeadlineSeconds",
        maximum=MAX_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
    )
    account_runtime = direct_client(account_settings)
    account_signer = AccountCenterRequestSigner(
        caller_id=_text(account_settings["callerId"], "accountCenter.callerId"),
        key=hmac_key(account_settings["signingKeyRef"]),
    )
    callback_signer = None
    if "callbackCallerId" in account_settings or "callbackSigningKeyRef" in account_settings:
        if not {"callbackCallerId", "callbackSigningKeyRef"} <= set(account_settings):
            raise IntegrationConfigurationError(
                "GitHub callback caller and signing key must be configured together"
            )
        callback_signer = AccountCenterRequestSigner(
            caller_id=_text(account_settings["callbackCallerId"], "accountCenter.callbackCallerId"),
            key=hmac_key(account_settings["callbackSigningKeyRef"]),
        )
    wecom_source_signer = None
    if "wecomSourceCallerId" in account_settings or "wecomSourceSigningKeyRef" in account_settings:
        if not {"wecomSourceCallerId", "wecomSourceSigningKeyRef"} <= set(account_settings):
            raise IntegrationConfigurationError(
                "WeCom source caller and signing key must be configured together"
            )
        wecom_source_signer = AccountCenterRequestSigner(
            caller_id=_text(
                account_settings["wecomSourceCallerId"], "accountCenter.wecomSourceCallerId"
            ),
            key=hmac_key(account_settings["wecomSourceSigningKeyRef"]),
        )
    accounts = AccountCenterClient(
        account_runtime,
        exchange_signer=account_signer,
        binding_id=account_binding,
        callback_signer=callback_signer,
        wecom_source_signer=wecom_source_signer,
        github_app_installation_deadline_seconds=github_app_installation_deadline_seconds,
    )

    github_settings = _config_object(
        configuration["githubIssues"],
        required={"bindingId", "connectionRef", "transport", "callerId", "signingKeyRef"},
        optional={"mtls", "deadlineSeconds"},
        label="githubIssues",
    )
    github_deadline_seconds = _bounded_deadline_seconds(
        github_settings.get("deadlineSeconds", DEFAULT_GITHUB_PROVIDER_RPC_DEADLINE_SECONDS),
        "githubIssues.deadlineSeconds",
        maximum=MAX_GITHUB_PROVIDER_RPC_DEADLINE_SECONDS,
    )
    if (
        _text(github_settings["callerId"], "githubIssues.callerId") != account_signer.caller_id
        or github_settings["signingKeyRef"] != account_settings["signingKeyRef"]
    ):
        raise IntegrationConfigurationError(
            "GitHub and Account Center must share the Exchange caller trust reference"
        )
    github_runtime = direct_client(github_settings)
    github_health = direct_health_client(github_settings)
    github = GitHubIssuesClient(
        github_runtime,
        signer=account_signer,
        binding_id=_text(github_settings["bindingId"], "githubIssues.bindingId"),
        deadline_seconds=github_deadline_seconds,
    )
    webhook_verifier = GitHubWebhookClient(github_runtime)

    wecom_runtime = None
    targets: dict[str, dict[str, str]] = {}
    if "wecom" in configuration:
        wecom_settings = _config_object(
            configuration["wecom"],
            required={"bindingId", "connectionRef", "transport", "targets", "inboundSources"},
            optional={"mtls", "deadlineSeconds"},
            label="wecom",
        )
        wecom_runtime = direct_client(wecom_settings)
        raw_targets = wecom_settings["targets"]
        if not isinstance(raw_targets, Mapping) or not raw_targets:
            raise IntegrationConfigurationError("wecom.targets must be a non-empty object")
        for reference, target in raw_targets.items():
            fields = _config_object(
                target,
                required={"botId", "conversationId", "kind"},
                optional=set(),
                label="WeCom message target",
            )
            kind = _text(fields["kind"], "wecom target kind").upper()
            if kind not in {"PRIVATE", "GROUP"}:
                raise IntegrationConfigurationError("WeCom target kind must be PRIVATE or GROUP")
            targets[_text(reference, "wecom target reference")] = {
                "bot_id": _text(fields["botId"], "wecom target botId"),
                "conversation_id": _text(fields["conversationId"], "wecom target conversationId"),
                "kind": kind,
            }
        raw_sources = wecom_settings["inboundSources"]
        if not isinstance(raw_sources, Mapping) or not raw_sources:
            raise IntegrationConfigurationError("wecom.inboundSources must be a non-empty object")
        if wecom_source_signer is None:
            raise IntegrationConfigurationError(
                "WeCom requires accountCenter.wecomSourceCallerId and signing key"
            )
    else:
        raw_sources = {}
    wecom_sources: dict[str, WeComInboundSource] = {}
    wecom_source_accounts: dict[str, dict[str, str]] = {}
    source_principals: dict[str, IntegrationPrincipal] = {}
    for binding_id, raw_source in raw_sources.items():
        source_profile_fields = _config_object(
            raw_source,
            required={
                "organizationId",
                "workspaceId",
                "sourceAuthority",
                "botNamespace",
                "accountId",
                "groupConversationId",
                "requestHmacSecretRef",
            },
            optional=set(),
            label="WeCom inbound source",
        )
        binding_key = _text(binding_id, "WeCom inbound binding ID")
        try:
            binding_uuid = UUID(binding_key)
        except ValueError as exc:
            raise IntegrationConfigurationError("WeCom inbound binding ID must be a UUID") from exc
        organization_id = _text(
            source_profile_fields["organizationId"], "WeCom source organizationId"
        )
        workspace_id = _text(source_profile_fields["workspaceId"], "WeCom source workspaceId")
        source_authority = _text(
            source_profile_fields["sourceAuthority"], "WeCom source sourceAuthority"
        )
        bot_namespace = _text(source_profile_fields["botNamespace"], "WeCom source botNamespace")
        account_id = _text(source_profile_fields["accountId"], "WeCom source accountId")
        group_conversation_id = _text(
            source_profile_fields["groupConversationId"], "WeCom source groupConversationId"
        )
        request_hmac_key = secret(source_profile_fields["requestHmacSecretRef"]).encode("utf-8")
        if len(request_hmac_key) < 32 or not account_id.startswith("bot:"):
            raise IntegrationConfigurationError("WeCom source HMAC key or bot account is invalid")
        source_principal = IntegrationPrincipal(
            issuer="urn:cyrene:wecom-source",
            subject=f"exchange-wecom-source:{binding_key}",
            organization_id=organization_id,
            workspace_id=workspace_id,
            allowed_operation_ids=frozenset(),
        )
        source_principals[binding_key] = source_principal
        wecom_sources[binding_key] = WeComInboundSource(
            binding_id=binding_uuid,
            organization_id=organization_id,
            workspace_id=workspace_id,
            source_authority=source_authority,
            bot_namespace=bot_namespace,
            account_id=account_id,
            group_conversation_id=group_conversation_id,
            request_hmac_key=request_hmac_key,
        )
        wecom_source_accounts[binding_key] = {
            "account_id": account_id,
            "group_conversation_id": group_conversation_id,
        }
    message = (
        WeComMessageClient(
            wecom_runtime,
            targets=targets,
            source_accounts=wecom_source_accounts,
        )
        if wecom_runtime is not None
        else None
    )
    integration_store = IntegrationStore(database_path)

    navigator_hmac_settings = None
    if connector_settings.navigator is not None:
        key_file_ref = connector_settings.navigator.key_file_ref
        env_name = refs.get(key_file_ref)
        if env_name is None:
            raise IntegrationConfigurationError(
                "connectorHost.navigatorConnector keyFileRef must resolve through hostSecretRefs"
            )
        used_refs.add(key_file_ref)
        key_file_value = source.get(env_name, "").strip()
        if key_file_value:
            navigator_hmac_settings = NavigatorHmacSettings(
                key_id=connector_settings.navigator.key_id,
                key_file=Path(key_file_value).expanduser(),
            )
    navigator_hmac_authenticator = NavigatorHmacAuthenticator(
        navigator_hmac_settings,
        replay_guard=integration_store,
    )
    signing_keys_file = source.get("CYRENE_EXCHANGE_AUTHORITY_SIGNING_KEYS_FILE", "").strip()
    connector_grant_verifier = ConnectorOperationGrantVerifier(
        keyring_file=Path(signing_keys_file).expanduser() if signing_keys_file else None,
        expected_audience=source.get("CYRENE_AUTHORITY_EXCHANGE_WORKLOAD_AUDIENCE", "exchange"),
        grant_registry=integration_store,
    )
    teams_message_client = None
    teams_runtime = None
    teams_message_profile = connector_settings.teams_messages
    if teams_message_profile is not None:
        teams_endpoint: dict[str, Any] = {
            "bindingId": teams_message_profile.endpoint.binding_id,
            "connectionRef": teams_message_profile.endpoint.connection_ref,
            "transport": teams_message_profile.endpoint.transport,
        }
        if teams_message_profile.endpoint.mtls is not None:
            teams_endpoint["mtls"] = dict(teams_message_profile.endpoint.mtls)
        teams_runtime = direct_client(teams_endpoint)
        teams_message_client = TeamsMessageClient(teams_runtime)

    computer_runner_client = None
    computer_runtime = None
    computer_runner_profile = connector_settings.computer_runner
    if computer_runner_profile is not None:
        computer_endpoint: dict[str, Any] = {
            "bindingId": computer_runner_profile.endpoint.binding_id,
            "connectionRef": computer_runner_profile.endpoint.connection_ref,
            "transport": computer_runner_profile.endpoint.transport,
        }
        if computer_runner_profile.endpoint.mtls is not None:
            computer_endpoint["mtls"] = dict(computer_runner_profile.endpoint.mtls)
        computer_runtime = direct_client(computer_endpoint)
        computer_runner_client = ComputerRunnerClient(
            computer_runtime,
            binding_id=computer_runner_profile.endpoint.binding_id,
            deadline_seconds=computer_runner_profile.max_command_timeout_ms / 1000 + 5,
        )

    authorization_clients: dict[str, Any] = {}
    email_notification_client = None
    authorization_registry = None
    current_context_resolver = None
    authorization_cloud_provider = None
    authorization_cloud_runner = None
    connection_profile_resolver = None
    email_delivery_recipient_resolver = None
    if authorization_settings is not None:
        authorization_registry = AuthorizationCloudProfileRegistry(authorization_settings)
        for profile_ref, profile in authorization_settings.profiles.items():
            profile_endpoint: dict[str, Any] = {
                "bindingId": profile.endpoint.binding_id,
                "connectionRef": profile.endpoint.connection_ref,
                "transport": profile.endpoint.transport,
            }
            if profile.endpoint.mtls is not None:
                profile_endpoint["mtls"] = dict(profile.endpoint.mtls)
            authorization_clients[profile_ref] = direct_client(profile_endpoint)
            hmac_key(profile.context_key_ref)
            used_refs.add(profile.context_key_ref)
        email_profile = authorization_settings.email
        if email_profile.enabled:
            if email_profile.endpoint is None or email_profile.context_key_ref is None:
                raise IntegrationConfigurationError("enabled email profile is incomplete")
            email_endpoint: dict[str, Any] = {
                "bindingId": email_profile.endpoint.binding_id,
                "connectionRef": email_profile.endpoint.connection_ref,
                "transport": email_profile.endpoint.transport,
            }
            if email_profile.endpoint.mtls is not None:
                email_endpoint["mtls"] = dict(email_profile.endpoint.mtls)
            email_notification_client = direct_client(email_endpoint)
            hmac_key(email_profile.context_key_ref)
            used_refs.add(email_profile.context_key_ref)
        for actor_context in authorization_settings.contexts.values():
            reference = actor_context.bearer_token_env_ref
            if reference not in refs:
                raise IntegrationConfigurationError(
                    "currentAuthority refers to an unknown bearer token secret reference"
                )
            # The live value is read on every use and may be absent while a durable
            # connection is reporting its actionable unavailable state.
            used_refs.add(reference)

        def current_bearer(reference: str) -> str | None:
            env_ref = refs.get(reference)
            token = source.get(env_ref, "") if env_ref is not None else ""
            return token if token.strip() else None

        if identity_verifier is not None and authorization_settings.contexts:
            current_context_resolver = PlatformCurrentAuthorizationContextResolver(
                store=integration_store,
                identity_verifier=identity_verifier,
                registry=authorization_registry,
                bearer_token=current_bearer,
            )
        authorization_cloud_provider = AuthorizationCloudDirectProvider(
            store=integration_store,
            registry=authorization_registry,
            provider_clients=authorization_clients,
            email_client=email_notification_client,
            current_context_resolver=current_context_resolver,
            context_key=hmac_key,
        )
        if current_context_resolver is not None:
            authorization_cloud_runner = AuthorizationCloudRunner(
                store=integration_store,
                contexts=current_context_resolver,
                provider=authorization_cloud_provider,
                email=authorization_cloud_provider if email_profile.enabled else None,
                worker_id=workload_id,
                email_recipient_resolver=(
                    current_context_resolver.email_recipient_for_connection
                    if email_profile.enabled
                    else None
                ),
                monitor_interval_seconds=authorization_settings.monitor_interval_seconds,
            )
        elif email_profile.enabled:
            raise IntegrationConfigurationError(
                "email notifications require a configured Platform identity context"
            )
        connection_profile_resolver = authorization_registry.display_name_for_connection
        if email_profile.enabled:
            email_delivery_recipient_resolver = authorization_registry.email_recipient_for_principal

    callback_principal = IntegrationPrincipal(
        issuer="urn:cyrene:exchange-service",
        subject="exchange-github-oauth-callback",
        organization_id="exchange-service",
        workspace_id="exchange-service",
        allowed_operation_ids=frozenset(),
    )
    account_port = IntegrationAccountCenterPort(accounts)
    github_port = IntegrationGitHubPort(github)
    connector_operation_dispatcher = ConnectorOperationDispatcher(
        store=integration_store,
        accounts=account_port,
        github=github,
        authorization_cloud=authorization_cloud_provider,
        registry=authorization_registry,
        computer=computer_runner_client,
        computer_runner_profile=computer_runner_profile,
    )
    dispatcher = None
    runner = None
    if authority_client is not None and message is not None:
        dispatcher = IntegrationDispatcher(
            store=integration_store,
            account_center=account_port,
            github=github_port,
            message=message,
            delegation=authority_client,
        )
        runner = DispatcherRunner(dispatcher, worker_id=workload_id)

    # ── Phase 3: Validate every secret reference was consumed exactly once ──
    if used_refs != set(refs):
        raise IntegrationConfigurationError(
            "hostSecretRefs contains unused or unreferenced entries"
        )
    return IntegrationServices(
        store=integration_store,
        authorizer=identity_verifier,
        accounts=accounts,
        github=github,
        webhook_verifier=webhook_verifier,
        delegation_authorizer=authority_client,
        callback_principal=callback_principal,
        plugin_health=github_health,
        dispatcher=dispatcher,
        dispatcher_runner=runner,
        execution_authorization_verifier=execution_verifier,
        message=message,
        account_center=account_port,
        wecom_sources=wecom_sources,
        wecom_source_principal=source_principals.get,
        connection_profile_resolver=connection_profile_resolver,
        authorization_cloud=authorization_cloud_provider,
        current_context_resolver=current_context_resolver,
        email_notifications=(
            authorization_cloud_provider
            if authorization_settings is not None and authorization_settings.email.enabled
            else None
        ),
        email_delivery_recipient_resolver=email_delivery_recipient_resolver,
        authorization_cloud_runner=authorization_cloud_runner,
        navigator_hmac_authenticator=navigator_hmac_authenticator,
        connector_grant_authority=connector_authority,
        connector_grant_verifier=connector_grant_verifier,
        connector_operation_dispatcher=connector_operation_dispatcher,
        teams_message_client=teams_message_client,
        teams_message_profile=teams_message_profile,
        computer_runner_client=computer_runner_client,
        computer_runner_profile=computer_runner_profile,
        authorization_profile_registry=authorization_registry,
        transport_clients=(
            account_runtime,
            github_runtime,
            *((wecom_runtime,) if wecom_runtime is not None else ()),
            *((teams_runtime,) if teams_runtime is not None else ()),
            *((computer_runtime,) if computer_runtime is not None else ()),
            github_health,
            *authorization_clients.values(),
            *((email_notification_client,) if email_notification_client is not None else ()),
        ),
    )


def resolve_integration_database_path(
    gateway_database_path: Path | str | None,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the Product-owned SQLite path independently from Gateway state."""

    source = os.environ if environ is None else environ
    configured = explicit_path or source.get("CYRENE_EXCHANGE_INTEGRATION_DATABASE")
    if configured:
        selected = Path(configured).expanduser().resolve()
    else:
        if gateway_database_path is None:
            raise IntegrationConfigurationError(
                "integration database path requires --integration-database or "
                "CYRENE_EXCHANGE_INTEGRATION_DATABASE"
            )
        gateway = Path(gateway_database_path).expanduser().resolve()
        selected = gateway.with_name(f"{gateway.stem}.integrations{gateway.suffix or '.sqlite3'}")
    gateway_resolved = (
        Path(gateway_database_path).expanduser().resolve()
        if gateway_database_path is not None
        else None
    )
    if selected == gateway_resolved:
        raise IntegrationConfigurationError(
            "integration state must use its separate SQLite database"
        )
    return selected


def validate_host_configuration(
    *,
    environ: Mapping[str, str] | None = None,
    require_platform_workload_profile: bool = False,
) -> dict[str, Any]:
    """Check the closed runtime projection without opening a DB or any network.

    The result contains only non-secret binding names and the workload ID.
    Workspace preflight sets ``require_platform_workload_profile`` to ensure the
    Exchange client certificate is present in Platform's active mTLS profile.
    """

    source = os.environ if environ is None else environ
    configuration = _read_configuration(source)
    refs = _secret_refs(configuration.get("hostSecretRefs"))
    used: set[str] = set()
    from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
        AuthorizationCloudConfigurationError,
        parse_authorization_cloud_settings,
    )
    from cyrene_exchange_product.integrations.clients import (
        DEFAULT_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
        MAX_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
    )
    from cyrene_exchange_product.integrations.connector_profiles import (
        ConnectorHostConfigurationError,
        parse_connector_host_settings,
    )

    try:
        authorization_settings = (
            parse_authorization_cloud_settings(
                configuration["authorizationCloud"],
                email_value=configuration.get("emailNotifications"),
            )
            if "authorizationCloud" in configuration
            else None
        )
    except AuthorizationCloudConfigurationError as exc:
        raise IntegrationConfigurationError(str(exc)) from exc
    try:
        connector_settings = parse_connector_host_settings(configuration.get("connectorHost", {}))
    except ConnectorHostConfigurationError as exc:
        raise IntegrationConfigurationError(str(exc)) from exc
    if authorization_settings is None and configuration.get("emailNotifications") is not None:
        raise IntegrationConfigurationError(
            "emailNotifications requires authorizationCloud current authority contexts"
        )

    def resolve(reference: object) -> str:
        if not isinstance(reference, str) or reference not in refs:
            raise IntegrationConfigurationError("configuration refers to an unknown host secret")
        used.add(reference)
        value = source.get(refs[reference], "")
        if not value:
            raise IntegrationConfigurationError("a configured host secret is unavailable")
        return value

    def check_hmac(reference: object) -> None:
        encoded = resolve(reference)
        try:
            key = (
                bytes.fromhex(encoded)
                if len(encoded) == 64
                else base64.b64decode(encoded, validate=True)
            )
        except (ValueError, TypeError):
            raise IntegrationConfigurationError("a configured HMAC key is malformed") from None
        if len(key) != 32:
            raise IntegrationConfigurationError("configured HMAC keys must decode to 32 bytes")

    def check_bearer_reference(reference: str) -> None:
        if reference not in refs:
            raise IntegrationConfigurationError(
                "currentAuthority refers to an unknown bearer token secret reference"
            )
        # Live bearer tokens can be rotated while the worker runs. Do not pin
        # their value at startup; a missing/expired value becomes durable UNAVAILABLE.
        used.add(reference)

    def endpoint_mapping(endpoint: Any) -> dict[str, Any]:
        result: dict[str, Any] = {
            "bindingId": endpoint.binding_id,
            "connectionRef": endpoint.connection_ref,
            "transport": endpoint.transport,
        }
        if endpoint.mtls is not None:
            result["mtls"] = dict(endpoint.mtls)
        return result

    def check_path(reference: object, *, private: bool = False) -> Path:
        path = Path(resolve(reference)).expanduser()
        info = path.stat()
        if not path.is_file() or (private and info.st_mode & 0o077):
            raise IntegrationConfigurationError(
                "a managed TLS file is unavailable or has loose permissions"
            )
        if not path.read_bytes():
            raise IntegrationConfigurationError("a managed TLS file is empty")
        return path

    authority = _config_object(
        configuration["platformAuthority"],
        required=set(),
        optional={"audience", "identity", "productWorkload", "connectorWorkload"},
        label="platformAuthority",
    )
    if not ({"productWorkload", "connectorWorkload"} & set(authority)):
        raise IntegrationConfigurationError(
            "platformAuthority requires connectorWorkload or legacy productWorkload"
        )
    workload_id = "exchange-connectors"
    audience: str | None = None
    product_cert_path: Path | None = None
    workload: dict[str, Any] | None = None
    if "connectorWorkload" in authority:
        connector_workload = _config_object(
            authority["connectorWorkload"],
            required={
                "connectionRef",
                "rootCertificateRef",
                "clientCertificateRef",
                "clientKeyRef",
            },
            optional={"deadlineSeconds"},
            label="Platform connector workload",
        )
        if not _text(
            connector_workload["connectionRef"], "connectorWorkload.connectionRef"
        ).startswith("grpcs://"):
            raise IntegrationConfigurationError(
                "Platform connector workload must use grpcs:// mTLS"
            )
        check_path(connector_workload["rootCertificateRef"])
        check_path(connector_workload["clientCertificateRef"])
        check_path(connector_workload["clientKeyRef"], private=True)
        keyring_name = "CYRENE_EXCHANGE_AUTHORITY_SIGNING_KEYS_FILE"
        keyring_value = source.get(keyring_name, "").strip()
        if not keyring_value:
            raise IntegrationConfigurationError(
                "the pinned Platform Authority connector signing keyring is unavailable"
            )
        keyring_path = Path(keyring_value).expanduser()
        try:
            from cyrene_exchange_product.integrations.connector_security import (
                decode_authority_keyring,
            )

            if not decode_authority_keyring(keyring_path):
                raise ValueError("Authority signing keyring has no keys")
        except (OSError, ValueError) as exc:
            raise IntegrationConfigurationError(
                "the pinned Platform Authority connector signing keyring is invalid"
            ) from exc
        if not source.get("CYRENE_AUTHORITY_EXCHANGE_WORKLOAD_AUDIENCE", "exchange").strip():
            raise IntegrationConfigurationError("connector Authority audience is empty")

    if "productWorkload" in authority:
        if "identity" not in authority or "audience" not in authority:
            raise IntegrationConfigurationError(
                "legacy ProductWorkload requires Platform identity and audience profiles"
            )
        audience = _text(authority["audience"], "platformAuthority.audience")
        identity = _config_object(
            authority["identity"],
            required={"connectionRef", "transport"},
            optional={"mtls"},
            label="Platform identity profile",
        )
        identity_ref = _text(identity["connectionRef"], "identity.connectionRef")
        if identity["transport"] == "local":
            if not identity_ref.startswith("unix://") or "mtls" in identity:
                raise IntegrationConfigurationError(
                    "local identity verification requires protected unix://"
                )
        elif identity["transport"] == "mtls":
            if not identity_ref.startswith("grpcs://"):
                raise IntegrationConfigurationError(
                    "remote identity verification requires grpcs://"
                )
            identity_tls = _config_object(
                identity.get("mtls"),
                required={"rootCertificateRef", "clientCertificateRef", "clientKeyRef"},
                optional=set(),
                label="Platform identity mTLS profile",
            )
            check_path(identity_tls["rootCertificateRef"])
            check_path(identity_tls["clientCertificateRef"])
            check_path(identity_tls["clientKeyRef"], private=True)
        else:
            raise IntegrationConfigurationError("Platform identity transport is unsupported")

        workload = _config_object(
            authority["productWorkload"],
            required={
                "connectionRef",
                "workloadId",
                "audience",
                "rootCertificateRef",
                "clientCertificateRef",
                "clientKeyRef",
            },
            optional=set(),
            label="Platform ProductWorkload profile",
        )
        workload_ref = _text(workload["connectionRef"], "productWorkload.connectionRef")
        workload_id = _text(workload["workloadId"], "productWorkload.workloadId")
        if (
            not workload_ref.startswith("grpcs://")
            or _text(workload["audience"], "productWorkload.audience") != audience
        ):
            raise IntegrationConfigurationError(
                "Platform ProductWorkload target or audience is invalid"
            )
        check_path(workload["rootCertificateRef"])
        product_cert_path = check_path(workload["clientCertificateRef"])
        check_path(workload["clientKeyRef"], private=True)

    account = _config_object(
        configuration["accountCenter"],
        required={
            "bindingId",
            "connectionRef",
            "transport",
            "callerId",
            "signingKeyRef",
        },
        optional={
            "mtls",
            "deadlineSeconds",
            "githubAppInstallationDeadlineSeconds",
            "callbackCallerId",
            "callbackSigningKeyRef",
            "wecomSourceCallerId",
            "wecomSourceSigningKeyRef",
        },
        label="accountCenter",
    )
    _bounded_deadline_seconds(
        account.get(
            "githubAppInstallationDeadlineSeconds",
            DEFAULT_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
        ),
        "accountCenter.githubAppInstallationDeadlineSeconds",
        maximum=MAX_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS,
    )
    github = _config_object(
        configuration["githubIssues"],
        required={"bindingId", "connectionRef", "transport", "callerId", "signingKeyRef"},
        optional={"mtls", "deadlineSeconds"},
        label="githubIssues",
    )
    _bounded_deadline_seconds(
        github.get("deadlineSeconds", DEFAULT_GITHUB_PROVIDER_RPC_DEADLINE_SECONDS),
        "githubIssues.deadlineSeconds",
        maximum=MAX_GITHUB_PROVIDER_RPC_DEADLINE_SECONDS,
    )
    if (
        github["callerId"] != account["callerId"]
        or github["signingKeyRef"] != account["signingKeyRef"]
    ):
        raise IntegrationConfigurationError(
            "GitHub provider and Account Center Exchange caller keys differ"
        )
    check_hmac(account["signingKeyRef"])
    for caller_key in (
        ("callbackCallerId", "callbackSigningKeyRef"),
        ("wecomSourceCallerId", "wecomSourceSigningKeyRef"),
    ):
        if any(field in account for field in caller_key):
            if not set(caller_key) <= set(account):
                raise IntegrationConfigurationError(
                    "optional Account Center caller ID and signing key must be configured together"
                )
            check_hmac(account[caller_key[1]])

    wecom: dict[str, Any] | None = None
    sources: Mapping[str, Any] = {}
    if "wecom" in configuration:
        wecom = _config_object(
            configuration["wecom"],
            required={"bindingId", "connectionRef", "transport", "targets", "inboundSources"},
            optional={"mtls", "deadlineSeconds"},
            label="wecom",
        )
        targets = wecom["targets"]
        sources_value = wecom["inboundSources"]
        if (
            not isinstance(targets, Mapping)
            or not targets
            or not isinstance(sources_value, Mapping)
            or not sources_value
        ):
            raise IntegrationConfigurationError(
                "WeCom fixed targets and inboundSources are required"
            )
        sources = sources_value
        if "wecomSourceSigningKeyRef" not in account:
            raise IntegrationConfigurationError(
                "WeCom requires Account Center source caller and signing key references"
            )
        for reference, target in targets.items():
            _text(reference, "WeCom target reference")
            item = _config_object(
                target,
                required={"botId", "conversationId", "kind"},
                optional=set(),
                label="WeCom target",
            )
            if _text(item["kind"], "WeCom target kind").upper() not in {"PRIVATE", "GROUP"}:
                raise IntegrationConfigurationError("WeCom target kind is invalid")
        for binding_id, raw_source in sources.items():
            _text(binding_id, "WeCom source binding ID")
            source_profile = _config_object(
                raw_source,
                required={
                    "organizationId",
                    "workspaceId",
                    "sourceAuthority",
                    "botNamespace",
                    "accountId",
                    "groupConversationId",
                    "requestHmacSecretRef",
                },
                optional=set(),
                label="WeCom inbound source",
            )
            if not _text(source_profile["accountId"], "WeCom source accountId").startswith("bot:"):
                raise IntegrationConfigurationError(
                    "WeCom inbound source must identify a bot account"
                )
            request_key = resolve(source_profile["requestHmacSecretRef"]).encode("utf-8")
            if len(request_key) < 32:
                raise IntegrationConfigurationError("WeCom inbound request HMAC key is too short")

    if authorization_settings is not None:
        for actor_context in authorization_settings.contexts.values():
            check_bearer_reference(actor_context.bearer_token_env_ref)
        for profile in authorization_settings.profiles.values():
            check_hmac(profile.context_key_ref)
            _validate_direct_endpoint(
                endpoint_mapping(profile.endpoint),
                f"authorizationCloud.{profile.profile_ref}",
                check_path,
            )
        if authorization_settings.email.enabled:
            email_profile = authorization_settings.email
            if email_profile.context_key_ref is None or email_profile.endpoint is None:
                raise IntegrationConfigurationError(
                    "enabled email notification profile is incomplete"
                )
            check_hmac(email_profile.context_key_ref)
            _validate_direct_endpoint(
                endpoint_mapping(email_profile.endpoint),
                "emailNotifications",
                check_path,
            )

    if connector_settings.navigator is not None:
        key_file_ref = connector_settings.navigator.key_file_ref
        if key_file_ref not in refs:
            raise IntegrationConfigurationError(
                "Navigator connector keyFileRef must resolve through hostSecretRefs"
            )
        # The value is a mounted-file path; the raw key is never loaded into JSON.
        check_path(key_file_ref, private=True)

    if connector_settings.teams_messages is not None:
        teams_endpoint_config = connector_settings.teams_messages.endpoint
        _validate_direct_endpoint(
            endpoint_mapping(teams_endpoint_config),
            "connectorHost.teamsMessages",
            check_path,
        )
    if connector_settings.computer_runner is not None:
        _validate_direct_endpoint(
            endpoint_mapping(connector_settings.computer_runner.endpoint),
            "connectorHost.computerRunner",
            check_path,
        )

    # Validate direct Plugin endpoint profiles without dialing the runtime.
    endpoints = [("accountCenter", account), ("githubIssues", github)]
    if wecom is not None:
        endpoints.append(("wecom", wecom))
    for label, provider_endpoint in endpoints:
        _validate_direct_endpoint(provider_endpoint, label, check_path)
    if used != set(refs):
        raise IntegrationConfigurationError(
            "hostSecretRefs contains unused or unreferenced entries"
        )

    if require_platform_workload_profile and workload is not None:
        if product_cert_path is None:
            raise IntegrationConfigurationError(
                "Platform ProductWorkload certificate was not validated"
            )
        encoded = source.get("CYRENE_AUTHORITY_PRODUCT_WORKLOAD_PROFILES_JSON", "")
        try:
            profiles = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise IntegrationConfigurationError(
                "Platform ProductWorkload profiles are unavailable"
            ) from exc
        if not isinstance(profiles, list):
            raise IntegrationConfigurationError(
                "Platform ProductWorkload profile registry is invalid"
            )
        certificate_digest = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(product_cert_path.read_text(encoding="ascii"))
        ).hexdigest()
        matches = [
            profile
            for profile in profiles
            if isinstance(profile, Mapping) and profile.get("workload_id") == workload_id
        ]
        if (
            len(matches) != 1
            or matches[0].get("owner_id") != "exchange"
            or matches[0].get("target_component") != "exchange-product"
            or matches[0].get("audience") != audience
            or certificate_digest not in matches[0].get("certificate_fingerprints_sha256", [])
        ):
            raise IntegrationConfigurationError(
                "Exchange ProductWorkload profile does not match Platform"
            )

    return {
        "valid": True,
        "workloadId": workload_id,
        "accountCenterBindingId": str(account["bindingId"]),
        "githubIssuesBindingId": str(github["bindingId"]),
        "wecomBindingId": str(wecom["bindingId"]) if wecom is not None else None,
        "wecomInboundSourceCount": len(sources),
        "authorizationCloudProfileCount": (
            len(authorization_settings.profiles) if authorization_settings is not None else 0
        ),
        "currentAuthorityContextCount": (
            len(authorization_settings.contexts) if authorization_settings is not None else 0
        ),
        "emailNotificationsEnabled": bool(
            authorization_settings is not None and authorization_settings.email.enabled
        ),
        "navigatorConnectorConfigured": connector_settings.navigator is not None,
        "teamsMessagesConfigured": connector_settings.teams_messages is not None,
        "computerRunnerConfigured": connector_settings.computer_runner is not None,
    }


def _read_configuration(environ: Mapping[str, str]) -> dict[str, Any]:
    """Decode one bounded, duplicate-free Exchange integration configuration."""

    raw = environ.get(CONFIGURATION_ENV)
    if raw is None or not raw.strip():
        raise IntegrationConfigurationError(f"{CONFIGURATION_ENV} is required")
    if len(raw.encode("utf-8")) > MAX_CONFIGURATION_BYTES:
        raise IntegrationConfigurationError(
            "Exchange integration configuration exceeds its size limit"
        )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as exc:
        raise IntegrationConfigurationError(
            "Exchange integration configuration is invalid JSON"
        ) from exc
    return _config_object(
        value,
        required={
            "schemaVersion",
            "hostSecretRefs",
            "platformAuthority",
            "accountCenter",
            "githubIssues",
        },
        optional={"authorizationCloud", "emailNotifications", "connectorHost", "wecom"},
        label="Exchange integration configuration",
        expected_version=1,
    )


def _secret_refs(value: object) -> dict[str, str]:
    """Validate stable-reference to uppercase environment-name mappings."""

    if not isinstance(value, Mapping) or not value:
        raise IntegrationConfigurationError("hostSecretRefs must be a non-empty object")
    refs: dict[str, str] = {}
    for stable_ref, environment_name in value.items():
        if (
            not isinstance(stable_ref, str)
            or not stable_ref.strip()
            or len(stable_ref) > 256
            or not isinstance(environment_name, str)
            or not _ENV_NAME.fullmatch(environment_name)
        ):
            raise IntegrationConfigurationError("hostSecretRefs contains an invalid reference")
        refs[stable_ref] = environment_name
    return refs


def _config_object(
    value: object,
    *,
    required: set[str],
    optional: set[str],
    label: str,
    expected_version: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrationConfigurationError(f"{label} must be an object")
    _exact_fields(value, required=required, optional=optional, label=label)
    result = dict(value)
    if expected_version is not None and (
        isinstance(result.get("schemaVersion"), bool)
        or result.get("schemaVersion") != expected_version
    ):
        raise IntegrationConfigurationError("Exchange integration schemaVersion is unsupported")
    return result


def _validate_direct_endpoint(
    endpoint: Mapping[str, Any],
    label: str,
    check_path: Any,
) -> None:
    """Validate a resolved DirectPluginRuntime endpoint without dialing it."""

    connection_ref = _text(endpoint.get("connectionRef"), f"{label}.connectionRef")
    transport = endpoint.get("transport")
    mtls = endpoint.get("mtls")
    if transport == "local":
        if not connection_ref.startswith("grpc://") or mtls is not None:
            raise IntegrationConfigurationError(
                f"{label} local endpoint must use grpc:// without mTLS"
            )
        return
    if transport != "mtls" or not connection_ref.startswith("grpcs://"):
        raise IntegrationConfigurationError(f"{label} remote endpoint must use grpcs:// mTLS")
    profile = _config_object(
        mtls,
        required={"rootCertificateRef", "clientCertificateRef", "clientKeyRef"},
        optional=set(),
        label=f"{label} mTLS profile",
    )
    check_path(profile["rootCertificateRef"])
    check_path(profile["clientCertificateRef"])
    check_path(profile["clientKeyRef"], private=True)


def _exact_fields(
    value: Mapping[str, Any], *, required: set[str], optional: set[str], label: str
) -> None:
    if not required <= set(value) or set(value) - required - optional:
        raise IntegrationConfigurationError(f"{label} has missing or unknown fields")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise IntegrationConfigurationError(f"{label} must be bounded non-empty text")
    return value.strip()


def _bounded_deadline_seconds(value: object, label: str, *, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < value <= maximum
        or not math.isfinite(value)
    ):
        raise IntegrationConfigurationError(
            f"{label} must be greater than zero and at most {maximum:g} seconds"
        )
    return float(value)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration property")
        result[key] = value
    return result
