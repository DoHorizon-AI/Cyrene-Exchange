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
import os
import re
import ssl
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID

from cyrene_exchange_product.integrations.api import IntegrationServices

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
        AccountCenterClient,
        DirectPluginHealthClient,
        GitHubIssuesClient,
        GitHubWebhookClient,
        IntegrationAccountCenterPort,
        IntegrationGitHubPort,
        PlatformAuthorityDelegationClient,
        WeComMessageClient,
        direct_plugin_client_from_connection,
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
        required={"audience", "identity", "productWorkload"},
        optional=set(),
        label="platformAuthority",
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
        raise IntegrationConfigurationError("Platform workload audience does not match authority")
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

    # ── Phase 2: Resolve the caller, provider, webhook, and notification ports ──
    account_settings = _config_object(
        configuration["accountCenter"],
        required={
            "bindingId",
            "connectionRef",
            "transport",
            "callerId",
            "signingKeyRef",
            "callbackCallerId",
            "callbackSigningKeyRef",
            "wecomSourceCallerId",
            "wecomSourceSigningKeyRef",
        },
        optional={"mtls", "deadlineSeconds"},
        label="accountCenter",
    )
    account_binding = _text(account_settings["bindingId"], "accountCenter.bindingId")
    account_runtime = direct_client(account_settings)
    account_signer = AccountCenterRequestSigner(
        caller_id=_text(account_settings["callerId"], "accountCenter.callerId"),
        key=hmac_key(account_settings["signingKeyRef"]),
    )
    callback_signer = AccountCenterRequestSigner(
        caller_id=_text(account_settings["callbackCallerId"], "accountCenter.callbackCallerId"),
        key=hmac_key(account_settings["callbackSigningKeyRef"]),
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
    )

    github_settings = _config_object(
        configuration["githubIssues"],
        required={"bindingId", "connectionRef", "transport", "callerId", "signingKeyRef"},
        optional={"mtls", "deadlineSeconds"},
        label="githubIssues",
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
    )
    webhook_verifier = GitHubWebhookClient(github_runtime)

    wecom_settings = _config_object(
        configuration["wecom"],
        required={"bindingId", "connectionRef", "transport", "targets", "inboundSources"},
        optional={"mtls", "deadlineSeconds"},
        label="wecom",
    )
    wecom_runtime = direct_client(wecom_settings)
    raw_targets = wecom_settings["targets"]
    if not isinstance(raw_targets, Mapping):
        raise IntegrationConfigurationError("wecom.targets must be an object")
    targets: dict[str, dict[str, str]] = {}
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
    if not targets:
        raise IntegrationConfigurationError("wecom.targets must contain at least one fixed target")

    raw_sources = wecom_settings["inboundSources"]
    if not isinstance(raw_sources, Mapping) or not raw_sources:
        raise IntegrationConfigurationError("wecom.inboundSources must be a non-empty object")
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
    message = WeComMessageClient(
        wecom_runtime,
        targets=targets,
        source_accounts=wecom_source_accounts,
    )
    integration_store = IntegrationStore(database_path)

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
            endpoint: dict[str, Any] = {
                "bindingId": profile.endpoint.binding_id,
                "connectionRef": profile.endpoint.connection_ref,
                "transport": profile.endpoint.transport,
            }
            if profile.endpoint.mtls is not None:
                endpoint["mtls"] = dict(profile.endpoint.mtls)
            authorization_clients[profile_ref] = direct_client(endpoint)
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
        transport_clients=(
            account_runtime,
            github_runtime,
            wecom_runtime,
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
        required={"audience", "identity", "productWorkload"},
        optional=set(),
        label="platformAuthority",
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
            raise IntegrationConfigurationError("remote identity verification requires grpcs://")
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
            "callbackCallerId",
            "callbackSigningKeyRef",
            "wecomSourceCallerId",
            "wecomSourceSigningKeyRef",
        },
        optional={"mtls", "deadlineSeconds"},
        label="accountCenter",
    )
    github = _config_object(
        configuration["githubIssues"],
        required={"bindingId", "connectionRef", "transport", "callerId", "signingKeyRef"},
        optional={"mtls", "deadlineSeconds"},
        label="githubIssues",
    )
    if (
        github["callerId"] != account["callerId"]
        or github["signingKeyRef"] != account["signingKeyRef"]
    ):
        raise IntegrationConfigurationError(
            "GitHub provider and Account Center Exchange caller keys differ"
        )
    check_hmac(account["signingKeyRef"])
    check_hmac(account["callbackSigningKeyRef"])
    check_hmac(account["wecomSourceSigningKeyRef"])

    wecom = _config_object(
        configuration["wecom"],
        required={"bindingId", "connectionRef", "transport", "targets", "inboundSources"},
        optional={"mtls", "deadlineSeconds"},
        label="wecom",
    )
    targets = wecom["targets"]
    sources = wecom["inboundSources"]
    if (
        not isinstance(targets, Mapping)
        or not targets
        or not isinstance(sources, Mapping)
        or not sources
    ):
        raise IntegrationConfigurationError("WeCom fixed targets and inboundSources are required")
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
            raise IntegrationConfigurationError("WeCom inbound source must identify a bot account")
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

    # Validate direct Plugin endpoint profiles without dialing the runtime.
    for label, endpoint in (("accountCenter", account), ("githubIssues", github), ("wecom", wecom)):
        _validate_direct_endpoint(endpoint, label, check_path)
    if used != set(refs):
        raise IntegrationConfigurationError(
            "hostSecretRefs contains unused or unreferenced entries"
        )

    if require_platform_workload_profile:
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
        "wecomBindingId": str(wecom["bindingId"]),
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
            "wecom",
        },
        optional={"authorizationCloud", "emailNotifications"},
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


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration property")
        result[key] = value
    return result
