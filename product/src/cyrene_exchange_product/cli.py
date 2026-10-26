"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 cli.py                                                          │
│  Module: cyrene_exchange_product.cli                                │
│  Role: Operator entrypoint for the independent Exchange gateway.    │
│                                                                     │
│  模块职责：Exchange 独立网关与路由/密钥运维命令行入口。                    │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import ssl
import sys
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from threading import Event
from typing import Any
from uuid import UUID

import uvicorn

from cyrene_exchange_product.domain import (
    CreateApiKeyRequest,
    CreateRouteRequest,
    ProductPrincipal,
    WorkspaceEndpointGrant,
    WorkspaceReactorEndpointGrant,
)
from cyrene_exchange_product.route_admission import ReactorWorkspaceSourceResolver
from cyrene_exchange_product.server import (
    OpenAICompatibleProvider,
    OperatorBindingResolver,
    RouteSourceProviderResolver,
    build_product_app,
)
from cyrene_exchange_product.service import ExchangeProductService
from cyrene_exchange_product.store import ExchangeStore

_INTEGRATION_TLS_CERT_ENV = "CYRENE_EXCHANGE_TLS_CERT_FILE"
_INTEGRATION_TLS_KEY_ENV = "CYRENE_EXCHANGE_TLS_KEY_FILE"
_AUTHORIZATION_CLOUD_RUNNER_ENV = "CYRENE_EXCHANGE_AUTHORIZATION_CLOUD_RUNNER_ENABLED"


def _authorization_cloud_runner_enabled() -> bool:
    """Read the explicit host switch for the app-owned authorization worker."""

    value = os.environ.get(_AUTHORIZATION_CLOUD_RUNNER_ENV, "false").strip().lower()
    if value not in {"true", "false"}:
        raise SystemExit(f"{_AUTHORIZATION_CLOUD_RUNNER_ENV} must be true or false")
    return value == "true"


def _bindings(entries: list[str]) -> dict[str, OpenAICompatibleProvider]:
    """Parse ``binding=url`` provider declarations from the operator.

    中文:解析 operator 提供的 binding=url provider 声明。
    """
    # 中文:解析操作员提供的 ``binding=url`` 形式的提供方声明。

    resolved: dict[str, OpenAICompatibleProvider] = {}
    for entry in entries:
        binding, separator, url = entry.partition("=")
        if not separator or not binding.strip() or not url.strip():
            raise SystemExit(f"provider binding must be binding=url, got {entry!r}")
        resolved[binding.strip()] = OpenAICompatibleProvider(url.strip())
    return resolved


def _principal(arguments: argparse.Namespace) -> ProductPrincipal:
    return ProductPrincipal(
        actor_id=arguments.actor_id,
        workspace_id=arguments.workspace_id,
        credential_ref=arguments.credential_ref,
        organization_id=getattr(arguments, "organization_id", None),
    )


def _timestamp(value: str) -> datetime:
    """Parse an ISO-8601 expiry into an aware UTC timestamp.

    中文:将 ISO-8601 过期时间解析为带时区的 UTC 时间戳。
    """
    # 中文:将 ISO-8601 到期时间解析为带时区的 UTC 时间戳。

    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _admitted_bindings(arguments: argparse.Namespace) -> frozenset[str]:
    declared = {entry.strip() for entry in arguments.allowed_bindings.split(",") if entry.strip()}
    return frozenset(declared | set(_bindings(arguments.provider)))


def _workspace_endpoint_grants(entries: list[str]) -> tuple[WorkspaceEndpointGrant, ...]:
    """Parse operator endpoint grants without accepting request-supplied scope."""

    grants: list[WorkspaceEndpointGrant] = []
    for entry in entries:
        parts = entry.split("=", 2)
        if len(parts) != 3 or not all(part.strip() for part in parts):
            raise SystemExit("Workspace endpoint grants must use ENDPOINT_UUID=ORG_ID=WORKSPACE_ID")
        try:
            endpoint_id = UUID(parts[0].strip())
            grants.append(
                WorkspaceEndpointGrant(
                    endpoint_id=endpoint_id,
                    organization_id=parts[1].strip(),
                    workspace_id=parts[2].strip(),
                )
            )
        except ValueError as exc:
            raise SystemExit("Workspace endpoint grant contains an invalid endpoint UUID") from exc
    return tuple(grants)


def _workspace_reactor_endpoint_grants(
    entries: list[str],
) -> tuple[WorkspaceReactorEndpointGrant, ...]:
    """Parse operator grants for Reactor source Endpoints."""

    grants: list[WorkspaceReactorEndpointGrant] = []
    for entry in entries:
        parts = entry.split("=", 2)
        if len(parts) != 3 or not all(part.strip() for part in parts):
            raise SystemExit("Reactor Endpoint grants must use ENDPOINT_UUID=ORG_ID=WORKSPACE_ID")
        try:
            grants.append(
                WorkspaceReactorEndpointGrant(
                    endpoint_id=UUID(parts[0].strip()),
                    organization_id=parts[1].strip(),
                    workspace_id=parts[2].strip(),
                )
            )
        except ValueError as exc:
            raise SystemExit("Reactor Endpoint grant contains an invalid UUID") from exc
    return tuple(grants)


def _serve(arguments: argparse.Namespace) -> int:
    runtime_mode = arguments.mode or os.environ.get("CYRENE_EXCHANGE_RUNTIME_MODE", "gateway-only")
    if runtime_mode not in {"gateway-only", "integration-only", "combined"}:
        raise SystemExit(
            "CYRENE_EXCHANGE_RUNTIME_MODE must be gateway-only, integration-only, or combined"
        )
    if runtime_mode in {"gateway-only", "combined"} and arguments.database is None:
        raise SystemExit("--database is required for gateway-only and combined modes")
    authorization_cloud_runner_enabled = _authorization_cloud_runner_enabled()
    if authorization_cloud_runner_enabled and runtime_mode != "integration-only":
        raise SystemExit(
            f"{_AUTHORIZATION_CLOUD_RUNNER_ENV} is supported only in integration-only mode"
        )
    listener_tls = _integration_listener_tls_options(arguments, runtime_mode=runtime_mode)
    integrations = None
    if runtime_mode != "gateway-only":
        from cyrene_exchange_product.integrations.cli import (
            build_production_services,
            resolve_integration_database_path,
        )
        from cyrene_exchange_product.server import build_integration_app

        integration_database = resolve_integration_database_path(
            arguments.database,
            explicit_path=arguments.integration_database,
        )
        integrations = build_production_services(integration_database)
        if runtime_mode == "integration-only":
            app = build_integration_app(
                database_path=integration_database,
                integrations=integrations,
                enable_authorization_cloud_runner=authorization_cloud_runner_enabled,
            )
            if listener_tls:
                uvicorn.run(
                    app,
                    host=arguments.host,
                    port=arguments.port,
                    access_log=False,
                    ssl_certfile=listener_tls["ssl_certfile"],
                    ssl_keyfile=listener_tls["ssl_keyfile"],
                )
            else:
                uvicorn.run(app, host=arguments.host, port=arguments.port, access_log=False)
            return 0

    if arguments.database is None:
        raise SystemExit("--database is required for the selected runtime mode")

    credentials: dict[str, ProductPrincipal] = {}
    gateway_credentials: dict[str, ProductPrincipal] = {}
    if arguments.control_token and arguments.control_token_env:
        raise SystemExit("Choose either --control-token or --control-token-env")
    control_token = arguments.control_token
    if arguments.control_token_env:
        control_token = os.environ.get(arguments.control_token_env)
        if not control_token:
            raise SystemExit("The configured control credential variable is empty")
    if control_token:
        if arguments.organization_id:
            raise SystemExit(
                "Legacy --control-token credentials cannot carry organization scope; "
                "use --control-credential-env"
            )
        legacy_principal = ProductPrincipal(
            actor_id=arguments.actor_id,
            workspace_id=arguments.workspace_id,
            credential_ref=arguments.credential_ref,
        )
        credentials[control_token] = legacy_principal
        gateway_credentials[control_token] = legacy_principal
    for entry in arguments.control_credential_env:
        parts = entry.split("=", 3)
        if len(parts) != 4 or not all(part.strip() for part in parts):
            raise SystemExit(
                "Control credential entries must use CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME"
            )
        credential_ref, organization_id, workspace_id, variable_name = (
            part.strip() for part in parts
        )
        token = os.environ.get(variable_name)
        if not token:
            raise SystemExit(
                f"The configured control credential variable {variable_name!r} is empty"
            )
        if token in credentials:
            raise SystemExit("The same control credential was configured more than once")
        credentials[token] = ProductPrincipal(
            actor_id=arguments.actor_id,
            workspace_id=workspace_id,
            credential_ref=credential_ref,
            organization_id=organization_id,
        )
    for entry in arguments.gateway_credential_env:
        parts = entry.split("=", 2)
        if len(parts) != 3 or not all(part.strip() for part in parts):
            raise SystemExit(
                "Gateway credential entries must use CREDENTIAL_REF=WORKSPACE_ID=ENV_NAME"
            )
        credential_ref, workspace_id, variable_name = (part.strip() for part in parts)
        token = os.environ.get(variable_name)
        if not token:
            raise SystemExit(
                f"The configured Gateway credential variable {variable_name!r} is empty"
            )
        if token in credentials or token in gateway_credentials:
            raise SystemExit("The same bearer secret cannot be assigned to multiple roles")
        gateway_credentials[token] = ProductPrincipal(
            actor_id=arguments.actor_id,
            workspace_id=workspace_id,
            credential_ref=credential_ref,
        )
    providers = _bindings(arguments.provider)
    if arguments.provider_from_route_source:
        source_token = (
            os.environ.get(arguments.source_token_env) if arguments.source_token_env else None
        )
        if arguments.source_token_env and not source_token:
            raise SystemExit("The configured source credential variable is empty")
        origins = frozenset(arguments.allowed_source_origin)
        resolver = None
        resolver_factory = partial(
            RouteSourceProviderResolver,
            source_bearer_token=source_token,
            allowed_source_origins=origins,
        )
    else:
        resolver = OperatorBindingResolver(providers)
        resolver_factory = None
    workspace_reactor_origin = arguments.workspace_reactor_origin
    workspace_reactor_token_env = arguments.workspace_reactor_token_env
    if bool(workspace_reactor_origin) != bool(workspace_reactor_token_env):
        raise SystemExit(
            "Workspace Reactor source requires both --workspace-reactor-origin and "
            "--workspace-reactor-token-env"
        )
    workspace_source_resolver = None
    if workspace_reactor_origin and workspace_reactor_token_env:
        workspace_reactor_token = os.environ.get(workspace_reactor_token_env)
        if not workspace_reactor_token:
            raise SystemExit("The configured Workspace Reactor source credential is empty")
        if workspace_reactor_token in credentials or workspace_reactor_token in gateway_credentials:
            raise SystemExit(
                "The Reactor source credential must be distinct from Exchange credentials"
            )
        try:
            workspace_source_resolver = ReactorWorkspaceSourceResolver(
                reactor_origin=workspace_reactor_origin,
                reactor_token=workspace_reactor_token,
            )
        except ValueError as exc:
            raise SystemExit("Workspace Reactor source configuration is invalid") from exc
    app = build_product_app(
        database_path=arguments.database.resolve(),
        resolver=resolver,
        resolver_factory=resolver_factory,
        control_credentials=credentials or None,
        gateway_credentials=gateway_credentials or None,
        workspace_endpoint_grants=_workspace_endpoint_grants(arguments.workspace_endpoint_grant),
        workspace_reactor_endpoint_grants=_workspace_reactor_endpoint_grants(
            arguments.workspace_reactor_endpoint_grant
        ),
        resolve_workspace_reactor_endpoint=(
            workspace_source_resolver.resolve if workspace_source_resolver is not None else None
        ),
        allowed_binding_ids=_admitted_bindings(arguments),
        endpoint_id=arguments.endpoint_id,
        integrations=integrations,
    )
    uvicorn.run(app, host=arguments.host, port=arguments.port, access_log=False)
    return 0


def _integration_listener_tls_options(
    arguments: argparse.Namespace,
    *,
    runtime_mode: str,
) -> dict[str, str]:
    """Validate the optional TLS pair used only by the integration-only listener."""

    cert_option = getattr(arguments, "tls_cert_file", None)
    key_option = getattr(arguments, "tls_key_file", None)
    cert_environment = os.environ.get(_INTEGRATION_TLS_CERT_ENV, "").strip()
    key_environment = os.environ.get(_INTEGRATION_TLS_KEY_ENV, "").strip()
    cert_environment_path = Path(cert_environment) if cert_environment else None
    key_environment_path = Path(key_environment) if key_environment else None
    cert_path = _coalesce_tls_path(
        cert_option,
        cert_environment_path,
        option_name="--tls-cert-file",
        environment_name=_INTEGRATION_TLS_CERT_ENV,
    )
    key_path = _coalesce_tls_path(
        key_option,
        key_environment_path,
        option_name="--tls-key-file",
        environment_name=_INTEGRATION_TLS_KEY_ENV,
    )
    if (cert_path is None) != (key_path is None):
        raise SystemExit(
            "Exchange listener TLS requires both CYRENE_EXCHANGE_TLS_CERT_FILE and "
            "CYRENE_EXCHANGE_TLS_KEY_FILE"
        )
    if cert_path is None or key_path is None:
        return {}
    if runtime_mode != "integration-only":
        raise SystemExit("Exchange listener TLS files are supported only in integration-only mode")
    cert_path = cert_path.expanduser()
    key_path = key_path.expanduser()
    if not cert_path.is_file() or not key_path.is_file():
        raise SystemExit("Exchange listener TLS certificate and key must be regular files")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise SystemExit("Exchange listener TLS certificate/key pair is invalid") from exc
    return {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}


def _coalesce_tls_path(
    option: Path | None,
    environment: Path | None,
    *,
    option_name: str,
    environment_name: str,
) -> Path | None:
    """Reject conflicting CLI and host paths instead of silently choosing one."""

    if (
        option is not None
        and environment is not None
        and option.expanduser().resolve() != environment.expanduser().resolve()
    ):
        raise SystemExit(f"{option_name} and {environment_name} refer to different TLS files")
    return option or environment


def _integration_dispatch(arguments: argparse.Namespace, *, once: bool) -> int:
    """Run the durable worker as its own host unit, never in the API process."""

    from cyrene_exchange_product.integrations.cli import (
        build_production_services,
        resolve_integration_database_path,
    )

    database_path = resolve_integration_database_path(
        arguments.database,
        explicit_path=arguments.integration_database,
    )
    services = build_production_services(database_path)
    runner = services.dispatcher_runner
    if runner is None:
        services.close()
        raise SystemExit("production integration DispatcherRunner was not constructed")
    try:
        if once:
            print(json.dumps(asdict(runner.run_once()), sort_keys=True, separators=(",", ":")))
            return 0
        stop_event = Event()
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())
        signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
        runner.run_forever(stop_event)
        return 0
    finally:
        services.close()


def _integration_authorization_cloud(arguments: argparse.Namespace, *, once: bool) -> int:
    """Run authorization/cloud monitoring independently from the issue dispatcher."""

    from cyrene_exchange_product.integrations.cli import (
        build_production_services,
        resolve_integration_database_path,
    )

    database_path = resolve_integration_database_path(
        arguments.database,
        explicit_path=arguments.integration_database,
    )
    services = build_production_services(database_path)
    runner = services.authorization_cloud_runner
    if runner is None:
        services.close()
        raise SystemExit(
            "authorization/cloud provider bindings or current authority resolver are unavailable"
        )
    try:
        if once:
            print(json.dumps(asdict(runner.run_once()), sort_keys=True, separators=(",", ":")))
            return 0
        stop_event = Event()
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())
        signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
        runner.run_forever(stop_event)
        return 0
    finally:
        services.close()


def _hf_scope_signature(
    value: object,
    *,
    camel_case: bool,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Normalize one host or Account Center Hugging Face scope for exact comparison."""

    if not isinstance(value, list) or not value:
        raise SystemExit("Hugging Face repository scope is missing or malformed")
    repo_type_key = "repoType" if camel_case else "repo_type"
    repo_id_key = "repoId" if camel_case else "repo_id"
    signature: list[tuple[str, str, tuple[str, ...]]] = []
    for row in value:
        if not isinstance(row, Mapping):
            raise SystemExit("Hugging Face repository scope row is malformed")
        repo_type = row.get(repo_type_key)
        repo_id = row.get(repo_id_key)
        permissions = row.get("permissions")
        if (
            repo_type not in {"model", "dataset", "space"}
            or not isinstance(repo_id, str)
            or not repo_id
            or not isinstance(permissions, list)
            or not permissions
            or any(
                not isinstance(item, str) or item not in {"read", "write"} for item in permissions
            )
            or "read" not in permissions
            or len(permissions) != len(set(permissions))
        ):
            raise SystemExit("Hugging Face repository scope row is invalid")
        signature.append((str(repo_type), repo_id, tuple(sorted(permissions))))
    if len(signature) != len(set(signature)):
        raise SystemExit("Hugging Face repository scope contains duplicate targets")
    return tuple(sorted(signature))


def _integration_connector_export_data(
    services: Any,
    arguments: argparse.Namespace,
    *,
    include_profile_metadata: bool,
    include_live_catalog: bool,
) -> dict[str, Any]:
    """Build one exact actor-scoped snapshot from Exchange and live plugin catalogs.

    Read-only Hugging Face operations come from the selected Account Center target's
    read grant. Cloud catalogs may be complete or the exact canonical read-only set;
    all other missing operations fail closed. No credential or authorization ref is
    copied into the projection. 中文：只导出固定连接范围与无凭据 profile 元数据。
    """

    from collections.abc import Mapping

    from cyrene_exchange_product.integrations.clients import ProviderToolDefinition
    from cyrene_exchange_product.integrations.connector_operations import (
        connector_binding_tools,
        validate_computer_tool_schema,
    )
    from cyrene_exchange_product.integrations.models import IntegrationPrincipal

    connections = services.store.connector_bindings_for_actor(
        issuer=arguments.issuer,
        subject=arguments.subject,
        organization_id=arguments.organization_id,
        workspace_id=arguments.workspace_id,
    )
    account_connections = [row for row in connections if row.provider in {"github", "hf"}]
    need_account_profiles = include_profile_metadata or any(
        row.provider == "hf" for row in account_connections
    )
    account_profiles: dict[tuple[str, str], dict[str, Any]] = {}
    if need_account_profiles and account_connections:
        if not arguments.organization_id:
            raise SystemExit("provider profile export requires --organization-id")
        principal = IntegrationPrincipal(
            issuer=arguments.issuer,
            subject=arguments.subject,
            organization_id=arguments.organization_id,
            workspace_id=arguments.workspace_id,
            allowed_operation_ids=frozenset({"accountListProviderProfiles"}),
        )
        response = services.accounts.list_provider_profiles(principal)
        rows = response.get("profiles") if isinstance(response, Mapping) else None
        if not isinstance(rows, list):
            raise SystemExit("Account Center provider profile readback is unavailable")
        for row in rows:
            if not isinstance(row, Mapping):
                raise SystemExit("Account Center returned malformed profile metadata")
            profile_ref = row.get("profile_ref")
            provider = row.get("provider")
            auth_status = row.get("auth_status")
            access_mode = row.get("access_mode", "actor_owned")
            if (
                not isinstance(profile_ref, str)
                or not profile_ref
                or provider not in {"github", "huggingface"}
                or not isinstance(auth_status, str)
                or not isinstance(access_mode, str)
                or access_mode not in {"actor_owned", "workspace_operator"}
            ):
                raise SystemExit("Account Center returned unsupported profile metadata")
            raw_scope = row.get("target_scope")
            if not isinstance(raw_scope, Mapping) or set(raw_scope) != {"repositories"}:
                raise SystemExit("Account Center returned an unsupported provider scope")
            repositories = raw_scope.get("repositories")
            if not isinstance(repositories, list) or not repositories:
                raise SystemExit("Account Center returned an empty provider scope")
            safe_repositories: list[dict[str, Any]] = []
            for repository in repositories:
                if not isinstance(repository, Mapping):
                    raise SystemExit("Account Center returned malformed provider scope")
                if provider == "huggingface":
                    repo_type = repository.get("repo_type")
                    repo_id = repository.get("repo_id")
                    permissions = repository.get("permissions")
                    if (
                        repo_type not in {"model", "dataset", "space"}
                        or not isinstance(repo_id, str)
                        or not repo_id
                        or not isinstance(permissions, list)
                        or not permissions
                        or any(value not in {"read", "write"} for value in permissions)
                        or "read" not in permissions
                    ):
                        raise SystemExit("Account Center returned invalid Hugging Face scope")
                    safe_repositories.append(
                        {
                            "repoType": repo_type,
                            "repoId": repo_id,
                            "permissions": sorted(set(permissions)),
                        }
                    )
                else:
                    repository_id = repository.get("repository_id")
                    owner = repository.get("owner")
                    name = repository.get("name")
                    if not all(
                        isinstance(value, str) and value for value in (repository_id, owner, name)
                    ):
                        raise SystemExit("Account Center returned invalid GitHub scope")
                    safe_repositories.append(
                        {"repositoryId": repository_id, "owner": owner, "name": name}
                    )
            auth_mode = row.get("auth_mode")
            if auth_mode is not None and (
                provider != "huggingface" or auth_mode not in {"fine_grained_token", "device_oauth"}
            ):
                raise SystemExit("Account Center returned unsupported authentication mode")
            revision = row.get("credential_revision")
            if revision is not None and (
                not isinstance(revision, int) or isinstance(revision, bool) or revision < 0
            ):
                raise SystemExit("Account Center returned invalid credential revision")
            key = (profile_ref, str(provider))
            if key in account_profiles:
                raise SystemExit("Account Center returned duplicate provider profile metadata")
            account_profiles[key] = {
                "profileRef": profile_ref,
                "providerId": str(provider),
                "authStatus": auth_status,
                "accessMode": access_mode,
                "targetScope": {"repositories": safe_repositories},
                **({"authMode": auth_mode} if isinstance(auth_mode, str) else {}),
                **({"credentialRevision": revision} if revision is not None else {}),
            }

    bindings: list[dict[str, Any]] = []
    catalog_items: list[dict[str, Any]] = []
    profile_metadata: dict[tuple[str, str], dict[str, Any]] = {}
    connection_metadata: list[dict[str, Any]] = []
    catalog_cache: dict[tuple[str, str], dict[str, ProviderToolDefinition]] = {}
    registry = getattr(services, "authorization_profile_registry", None)

    for connection in connections:
        provider_id = "huggingface" if connection.provider == "hf" else connection.provider
        full_map = connector_binding_tools(provider_id)
        if not full_map:
            continue
        profile_ref = (
            connection.account_link_ref
            if connection.provider in {"github", "hf"}
            else connection.binding_ref
        )
        if (
            provider_id == "github"
            and profile_ref is None
            and connection.binding_ref is None
            and connection.target_ref is None
        ):
            continue
        if not profile_ref or (connection.provider != "github" and not connection.target_ref):
            raise SystemExit("an enabled connector connection has no complete host profile scope")

        read_only_hf_target = False
        selected_hf_repo_type: str | None = None
        connection_target_scope: dict[str, Any] | None = None
        account_profile: dict[str, Any] | None = None
        host_profile: Any = None
        target: Any = None
        if connection.provider in {"github", "hf"}:
            provider_name = "huggingface" if connection.provider == "hf" else "github"
            account_profile = account_profiles.get((str(profile_ref), provider_name))
            if need_account_profiles and account_profile is None:
                raise SystemExit("Exchange connection does not match an Account Center profile")
            if connection.provider == "github":
                connection_target_scope = {
                    "repositoryId": connection.repository_id,
                    "repository": connection.repository_name,
                }
            else:
                if registry is None:
                    raise SystemExit("Hugging Face connection profile registry is unavailable")
                host_profile = registry.settings.profiles.get(str(connection.binding_ref))
                target = (
                    host_profile.targets.get(str(connection.target_ref))
                    if host_profile is not None
                    else None
                )
                if host_profile is None or host_profile.provider != "hf" or target is None:
                    raise SystemExit("Hugging Face connection target is not host configured")
                if account_profile is None:
                    raise SystemExit("Hugging Face Account Center profile readback is unavailable")
                repositories = account_profile["targetScope"]["repositories"]
                configured_repositories = (host_profile.account_scopes or {}).get("repositories")
                if not isinstance(configured_repositories, list):
                    raise SystemExit("Hugging Face host profile has no declared repository scope")

                if _hf_scope_signature(repositories, camel_case=True) != _hf_scope_signature(
                    configured_repositories,
                    camel_case=False,
                ):
                    raise SystemExit(
                        "Hugging Face Account Center scope does not match the host profile"
                    )
                target_rows = [row for row in repositories if row["repoId"] == target.target_ref]
                if len(target_rows) != 1:
                    raise SystemExit("Hugging Face target does not match its issued profile scope")
                target_row = target_rows[0]
                selected_hf_repo_type = str(target_row["repoType"])
                read_only_hf_target = "write" not in target_row["permissions"]
                connection_target_scope = {
                    "repoType": target_row["repoType"],
                    "repoId": target_row["repoId"],
                    "permissions": target_row["permissions"],
                }
        elif provider_id in {"azure", "gcp", "runpod"} and include_profile_metadata:
            if registry is None:
                raise SystemExit("cloud connection profile registry is unavailable")
            host_profile = registry.settings.profiles.get(str(connection.binding_ref))
            target = (
                host_profile.targets.get(str(connection.target_ref))
                if host_profile is not None
                else None
            )
            if host_profile is None or host_profile.provider != provider_id or target is None:
                raise SystemExit("cloud connection does not match a configured profile target")
            connection_target_scope = {
                "targetAlias": str(connection.target_ref),
                "targetRef": target.target_ref,
            }
        elif provider_id == "github":
            connection_target_scope = {
                "repositoryId": connection.repository_id,
                "repository": connection.repository_name,
            }

        source_binding = "github" if provider_id == "github" else str(connection.binding_ref)
        cache_key = (provider_id, source_binding)
        expected = {str(entry["toolId"]): entry for entry in full_map}
        if len(expected) != len(full_map):
            raise SystemExit("Exchange connector operation map contains duplicate tool IDs")
        expected_ids = set(expected)
        read_ids = {
            tool_id for tool_id, mapping in expected.items() if mapping.get("mutating") is False
        }
        descriptors: dict[str, ProviderToolDefinition] = {}
        if include_live_catalog:
            descriptors = catalog_cache.get(cache_key, {})
            if not descriptors:
                if provider_id == "github":
                    provider_catalog = services.github.list_tool_catalog()
                else:
                    if services.authorization_cloud is None:
                        raise SystemExit("configured connector provider catalog is unavailable")
                    provider_catalog = services.authorization_cloud.list_tool_catalog(
                        source_binding
                    )
                descriptors = {descriptor.tool_id: descriptor for descriptor in provider_catalog}
                catalog_cache[cache_key] = descriptors
        descriptor_ids = set(descriptors)
        if provider_id == "huggingface":
            list_operations = {
                "huggingface.models.list": "model",
                "huggingface.datasets.list": "dataset",
                "huggingface.spaces.list": "space",
            }
            selected_list_operation = next(
                (
                    operation_id
                    for operation_id, repo_type in list_operations.items()
                    if repo_type == selected_hf_repo_type
                ),
                None,
            )
            selected_ids = {
                tool_id
                for tool_id, mapping in expected.items()
                if mapping["operationId"] not in list_operations
                or mapping["operationId"] == selected_list_operation
            }
            if read_only_hf_target:
                selected_ids &= read_ids
        elif include_live_catalog and provider_id in {"azure", "gcp", "runpod"}:
            available = descriptor_ids & expected_ids
            if available == expected_ids:
                selected_ids = expected_ids
            elif read_ids and available == read_ids:
                selected_ids = read_ids
            else:
                raise SystemExit(
                    "configured provider catalog is missing required Exchange read operations"
                )
        else:
            selected_ids = expected_ids
        if include_live_catalog and selected_ids - descriptor_ids:
            raise SystemExit("configured provider catalog is missing required Exchange operations")

        tools: list[dict[str, Any]] = []
        binding_tools: list[dict[str, object]] = []
        for tool_id in sorted(selected_ids):
            mapping = expected[tool_id]
            mutating = mapping.get("mutating")
            if not isinstance(mutating, bool):
                raise SystemExit("Exchange connector operation map has invalid mutability")
            binding_tools.append(mapping)
            if include_live_catalog:
                definition = descriptors[tool_id]
                tools.append(
                    {
                        "id": definition.tool_id,
                        "name": definition.name,
                        "description": definition.description,
                        "readOnly": not mutating,
                        "inputSchema": definition.input_schema,
                    }
                )
        binding_id = f"exchange-{provider_id}-{connection.id}"
        connection_ref = str(connection.id)
        bindings.append(
            {
                "bindingId": binding_id,
                "connectionRef": connection_ref,
                "providerId": provider_id,
                "profileRef": str(profile_ref),
                "tools": binding_tools,
            }
        )
        if include_live_catalog:
            catalog_items.append(
                {
                    "bindingId": binding_id,
                    "capabilityId": "tool.provider.v1",
                    "providerId": provider_id,
                    "connectionRef": connection_ref,
                    "profileRef": str(profile_ref),
                    "tools": tools,
                }
            )

        if account_profile is not None:
            profile_key = (str(profile_ref), provider_id)
            profile_metadata[profile_key] = {
                **account_profile,
                "profileAlias": str(connection.binding_ref)
                if connection.binding_ref is not None
                else None,
            }
        elif include_profile_metadata and host_profile is not None:
            profile_key = (str(host_profile.profile_ref), provider_id)
            profile_metadata[profile_key] = {
                "profileRef": host_profile.profile_ref,
                "profileAlias": host_profile.profile_ref,
                "providerId": provider_id,
                "accessMode": connection.access_mode,
                "targetScope": {
                    "targets": {
                        alias: {"targetRef": configured_target.target_ref}
                        for alias, configured_target in host_profile.targets.items()
                    }
                },
                **(
                    {"authMode": host_profile.auth_mode}
                    if isinstance(host_profile.auth_mode, str)
                    else {}
                ),
                "readOnly": selected_ids == read_ids,
            }
        connection_metadata.append(
            {
                "connectionRef": connection_ref,
                "providerId": provider_id,
                "profileRef": str(profile_ref),
                "profileAlias": str(connection.binding_ref)
                if connection.binding_ref is not None
                else None,
                "targetAlias": str(connection.target_ref)
                if connection.target_ref is not None
                else None,
                "accessMode": connection.access_mode,
                "readOnly": selected_ids == read_ids,
                **({"targetScope": connection_target_scope} if connection_target_scope else {}),
            }
        )

    computer_profile = getattr(services, "computer_runner_profile", None)
    if (
        computer_profile is not None
        and computer_profile.expected_issuer == arguments.issuer
        and computer_profile.organization_id == arguments.organization_id
        and computer_profile.workspace_id == arguments.workspace_id
    ):
        operation_map = connector_binding_tools("computer")
        expected = {str(item["toolId"]): item for item in operation_map}
        tools = []
        if len(expected) != len(operation_map):
            raise SystemExit("computer runner operation map contains duplicate tool IDs")
        if include_live_catalog:
            computer_client = getattr(services, "computer_runner_client", None)
            if computer_client is None:
                raise SystemExit("configured computer runner tool catalog is unavailable")
            descriptors = {item.tool_id: item for item in computer_client.list_tool_catalog()}
            if set(expected) - set(descriptors):
                raise SystemExit("computer runner catalog is missing a required fixed operation")
            for tool_id in sorted(expected):
                definition = descriptors[tool_id]
                mapping = expected[tool_id]
                validate_computer_tool_schema(
                    computer_profile,
                    tool_id=tool_id,
                    input_schema=definition.input_schema,
                )
                mutating = mapping.get("mutating")
                if not isinstance(mutating, bool):
                    raise SystemExit("computer runner operation map has invalid mutability")
                tools.append(
                    {
                        "id": definition.tool_id,
                        "name": definition.name,
                        "description": definition.description,
                        "readOnly": not mutating,
                        "inputSchema": definition.input_schema,
                    }
                )
        connection_ref = computer_profile.connection_ref
        binding_id = f"exchange-computer-{connection_ref}"
        bindings.append(
            {
                "bindingId": binding_id,
                "connectionRef": connection_ref,
                "providerId": "computer",
                "profileRef": computer_profile.profile_ref,
                "tools": operation_map,
            }
        )
        if include_live_catalog:
            catalog_items.append(
                {
                    "bindingId": binding_id,
                    "capabilityId": "tool.provider.v1",
                    "providerId": "computer",
                    "connectionRef": connection_ref,
                    "profileRef": computer_profile.profile_ref,
                    "tools": tools,
                }
            )
        if include_profile_metadata:
            profile_metadata[(computer_profile.profile_ref, "computer")] = {
                "profileRef": computer_profile.profile_ref,
                "profileAlias": computer_profile.profile_ref,
                "providerId": "computer",
                "accessMode": "workspace_operator",
                "targetScope": {
                    "maxCommandTimeoutMs": computer_profile.max_command_timeout_ms,
                    "maxFileBytes": computer_profile.max_file_bytes,
                    "maxReadBytes": computer_profile.max_read_bytes,
                    "maxDirectoryDepth": computer_profile.max_directory_depth,
                },
            }
            connection_metadata.append(
                {
                    "connectionRef": connection_ref,
                    "providerId": "computer",
                    "profileRef": computer_profile.profile_ref,
                    "profileAlias": computer_profile.profile_ref,
                    "accessMode": "workspace_operator",
                    "readOnly": False,
                }
            )

    return {
        "profiles": [profile_metadata[key] for key in sorted(profile_metadata)],
        "connections": connection_metadata,
        "bindings": bindings,
        "catalog": {"schemaVersion": 1, "items": catalog_items},
    }


def _integration_connector_bindings(arguments: argparse.Namespace) -> int:
    """Export the launcher-owned connection map from live Exchange state."""

    from cyrene_exchange_product.integrations.cli import build_production_services

    database_path = Path(arguments.integration_database).expanduser().resolve()
    if not database_path.is_file():
        raise SystemExit("Exchange integration database does not exist")
    services = build_production_services(database_path)
    try:
        exported = _integration_connector_export_data(
            services,
            arguments,
            include_profile_metadata=False,
            include_live_catalog=False,
        )
        payload = json.dumps(
            {"schemaVersion": 1, "bindings": exported["bindings"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    finally:
        services.close()
    print(payload)
    return 0


def _integration_connector_tool_catalog(arguments: argparse.Namespace) -> int:
    """Export actual Plugin tool schemas for Exchange-owned connections.

    The command is a private host bootstrap operation. It uses the configured
    DirectPluginRuntime channels and SQLite records, and emits JSON only after
    every selected provider catalog passes validation.
    中文：只从真实插件目录与 Exchange 持久连接导出，不查询时不伪造空工具。
    """

    from cyrene_exchange_product.integrations.cli import build_production_services

    database_path = Path(arguments.integration_database).expanduser().resolve()
    if not database_path.is_file():
        raise SystemExit("Exchange integration database does not exist")
    services = build_production_services(database_path)
    try:
        exported = _integration_connector_export_data(
            services,
            arguments,
            include_profile_metadata=False,
            include_live_catalog=True,
        )
        output = json.dumps(
            exported["catalog"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(output.encode("utf-8")) > 16 * 1024 * 1024:
            raise SystemExit("provider tool catalog snapshot exceeds its size limit")
    finally:
        services.close()
    print(output)
    return 0


def _integration_connector_readiness(arguments: argparse.Namespace) -> int:
    """Export a credential-free readiness snapshot from the pinned Exchange runtime."""

    from cyrene_exchange_product.integrations.cli import build_production_services

    database_path = Path(arguments.integration_database).expanduser().resolve()
    if not database_path.is_file():
        raise SystemExit("Exchange integration database does not exist")
    services = build_production_services(database_path)
    try:
        exported = _integration_connector_export_data(
            services,
            arguments,
            include_profile_metadata=True,
            include_live_catalog=True,
        )
        output = {
            "schemaVersion": 1,
            "actor": {
                "issuer": arguments.issuer,
                "subject": arguments.subject,
                "organizationId": arguments.organization_id,
                "workspaceId": arguments.workspace_id,
            },
            **exported,
        }
        serialized = json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(serialized.encode("utf-8")) > 16 * 1024 * 1024:
            raise SystemExit("connector readiness snapshot exceeds its size limit")
    finally:
        services.close()
    print(serialized)
    return 0


def _integration_check_config() -> int:
    """Run offline config and Platform-profile preflight without side effects."""

    from cyrene_exchange_product.integrations.cli import (
        IntegrationConfigurationError,
        validate_host_configuration,
    )

    try:
        report = validate_host_configuration(require_platform_workload_profile=True)
    except IntegrationConfigurationError:
        print(
            json.dumps(
                {
                    "valid": False,
                    "code": "EXCHANGE_INTEGRATION_CONFIGURATION_INVALID",
                    "message": "Integration configuration preflight failed.",
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


def _integration_connector_bootstrap(arguments: argparse.Namespace) -> int:
    """Provision initial provider profiles through the privileged local host path."""

    from cyrene_exchange_product.integrations.bootstrap import provision_connector_profiles
    from cyrene_exchange_product.integrations.cli import build_production_services

    services = build_production_services(arguments.integration_database)
    try:
        result = provision_connector_profiles(
            services,
            arguments.private_config,
            plan_only=arguments.plan_only,
        )
    finally:
        services.close()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _route_list(arguments: argparse.Namespace) -> int:
    store = ExchangeStore(arguments.database.resolve())
    try:
        payload = [
            {
                "id": str(route.id),
                "endpointId": str(route.endpoint_id),
                "modelPattern": route.model_pattern,
                "targetBindingId": route.target_binding_id,
                "targetModel": route.target_model,
                "priority": route.priority,
                "state": route.state.value,
                "resourceVersion": route.resource_version,
            }
            for route in store.list_active_routes()
        ]
    finally:
        store.close()
    print(json.dumps({"object": "list", "data": payload}, indent=2))
    return 0


def _route_create(arguments: argparse.Namespace) -> int:
    store = ExchangeStore(arguments.database.resolve())
    try:
        route = ExchangeProductService(store).create_route(
            CreateRouteRequest(
                endpoint_id=arguments.endpoint_id,
                model_pattern=arguments.model_pattern,
                target_binding_id=arguments.target_binding,
                target_model=arguments.target_model,
                priority=arguments.priority,
            ),
            arguments.idempotency_key,
        )
    finally:
        store.close()
    print(json.dumps({"id": str(route.id), "state": route.state.value}))
    return 0


def _route_enable(arguments: argparse.Namespace) -> int:
    store = ExchangeStore(arguments.database.resolve())
    try:
        route = ExchangeProductService(store).confirm_route_draft(
            UUID(arguments.route_id),
            arguments.resource_version,
            _principal(arguments),
            lambda _route: None,
        )
    finally:
        store.close()
    print(
        json.dumps(
            {
                "id": str(route.id),
                "state": route.state.value,
                "resourceVersion": route.resource_version,
            }
        )
    )
    return 0


def _key_create(arguments: argparse.Namespace) -> int:
    store = ExchangeStore(arguments.database.resolve())
    try:
        store.configure_credentials({arguments.token: _principal(arguments)})
    finally:
        store.close()
    print(json.dumps({"credentialRef": arguments.credential_ref, "enabled": True}))
    return 0


def _key_issue(arguments: argparse.Namespace) -> int:
    """Generate one gateway key; the secret is printed exactly once.

    中文:生成一个 gateway key;secret 仅打印一次。
    """
    # 中文:生成一个网关密钥;秘密值只打印一次。

    store = ExchangeStore(arguments.database.resolve())
    try:
        service = ExchangeProductService(store)
        principal = ProductPrincipal(
            actor_id=arguments.actor_id,
            workspace_id=arguments.workspace_id,
            credential_ref="cred://exchange/cli",
        )
        created, _ = service.create_api_key(
            CreateApiKeyRequest(
                name=arguments.name,
                expires_at=arguments.expires_at,
                model_scope=arguments.model_scope or [],
            ),
            principal,
            arguments.idempotency_key,
        )
    finally:
        store.close()
    payload = created.model_dump(mode="json", exclude_none=True)
    print(json.dumps(payload, indent=2))
    return 0


def _key_list(arguments: argparse.Namespace) -> int:
    """List one workspace's key metadata without any secret material.

    中文:列出一个 workspace 的 key 元数据,不包含 secret 材料。
    """
    # 中文:列出一个工作区的密钥元数据,不包含任何秘密材料。

    store = ExchangeStore(arguments.database.resolve())
    try:
        service = ExchangeProductService(store)
        principal = ProductPrincipal(
            actor_id=arguments.actor_id,
            workspace_id=arguments.workspace_id,
            credential_ref="cred://exchange/cli",
        )
        keys = service.list_api_keys(principal)
    finally:
        store.close()
    print(
        json.dumps(
            {
                "object": "list",
                "data": [key.model_dump(mode="json", exclude_none=True) for key in keys],
            },
            indent=2,
        )
    )
    return 0


def _key_revoke(arguments: argparse.Namespace) -> int:
    if arguments.api_key_id is not None:
        return _key_revoke_api_key(arguments)
    store = ExchangeStore(arguments.database.resolve())
    try:
        revoked = store.disable_credential(arguments.credential_ref)
    finally:
        store.close()
    if not revoked:
        print(f"credential not found: {arguments.credential_ref}", file=sys.stderr)
        return 1
    print(json.dumps({"credentialRef": arguments.credential_ref, "enabled": False}))
    return 0


def _key_revoke_api_key(arguments: argparse.Namespace) -> int:
    store = ExchangeStore(arguments.database.resolve())
    try:
        service = ExchangeProductService(store)
        principal = ProductPrincipal(
            actor_id=arguments.actor_id,
            workspace_id=arguments.workspace_id,
            credential_ref="cred://exchange/cli",
        )
        revoked = service.revoke_api_key(arguments.api_key_id, principal)
    finally:
        store.close()
    print(json.dumps({"id": str(revoked.id), "state": revoked.state.value}))
    return 0


def _add_principal_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--actor-id", default="cyrene-operator")
    command.add_argument("--workspace-id", default="default")
    command.add_argument("--organization-id")
    command.add_argument("--credential-ref", default="cred://exchange/operator")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Cyrene Exchange Product operator CLI")
    value.add_argument("--database", type=Path)
    commands = value.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="Run the independent Exchange gateway")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--mode",
        choices=("gateway-only", "integration-only", "combined"),
        default=os.environ.get("CYRENE_EXCHANGE_RUNTIME_MODE", "gateway-only"),
        help="Serve the gateway, integration API, or both; gateway-only remains the default",
    )
    serve.add_argument(
        "--integration-database",
        type=Path,
        help="Separate SQLite path for integration inbox, outbox, and operation state",
    )
    serve.add_argument(
        "--tls-cert-file",
        type=Path,
        help=(
            "Optional integration-only HTTPS certificate file; can also use "
            "CYRENE_EXCHANGE_TLS_CERT_FILE"
        ),
    )
    serve.add_argument(
        "--tls-key-file",
        type=Path,
        help=(
            "Optional integration-only HTTPS private key file; can also use "
            "CYRENE_EXCHANGE_TLS_KEY_FILE"
        ),
    )
    serve.add_argument(
        "--control-token",
        help=(
            "Legacy compatibility only; this value is also a Gateway credential. "
            "Prefer --control-token-env to keep secrets out of process arguments."
        ),
    )
    serve.add_argument(
        "--control-token-env",
        help="Name of the environment variable holding the control credential",
    )
    serve.add_argument(
        "--control-credential-env",
        action="append",
        default=[],
        metavar="CREDENTIAL_REF=ORG_ID=WORKSPACE_ID=ENV_NAME",
        help=(
            "Add a scoped server-side control bearer mapping; repeat entries for "
            "multiple workspaces or token rotation; "
            "the environment variable contains the secret"
        ),
    )
    serve.add_argument(
        "--gateway-credential-env",
        action="append",
        default=[],
        metavar="CREDENTIAL_REF=WORKSPACE_ID=ENV_NAME",
        help=(
            "Add a Gateway data-plane bearer from an environment variable; repeat "
            "for multiple credentials or rotation"
        ),
    )
    serve.add_argument(
        "--workspace-endpoint-grant",
        action="append",
        default=[],
        metavar="ENDPOINT_UUID=ORG_ID=WORKSPACE_ID",
        help=(
            "Operator grant allowing one organization/workspace to target an Exchange "
            "GatewayEndpoint"
        ),
    )
    serve.add_argument(
        "--workspace-reactor-endpoint-grant",
        action="append",
        default=[],
        metavar="ENDPOINT_UUID=ORG_ID=WORKSPACE_ID",
        help="Operator grant allowing one organization/workspace to select a Reactor Endpoint",
    )
    serve.add_argument(
        "--workspace-reactor-origin",
        help="Fixed private Reactor service origin used only for granted source resolution",
    )
    serve.add_argument(
        "--workspace-reactor-token-env",
        help="Environment variable holding the private Reactor service Bearer",
    )
    serve.add_argument("--endpoint-id", type=UUID)
    serve.add_argument(
        "--provider",
        action="append",
        default=[],
        metavar="BINDING=URL",
        help="Operator provider endpoint for one opaque binding id",
    )
    serve.add_argument(
        "--provider-from-route-source",
        action="store_true",
        help="Resolve each provider URL from the persisted route source endpoint",
    )
    serve.add_argument(
        "--allowed-bindings",
        default="",
        help="Comma-separated binding ids admitted for route drafts",
    )
    serve.add_argument(
        "--allowed-source-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="Origin a route source URI may use, for example http://127.0.0.1:19300",
    )
    serve.add_argument(
        "--source-token-env",
        help="Name of the environment variable holding the source Product credential",
    )
    _add_principal_arguments(serve)

    route = commands.add_parser("route", help="Inspect, create, or enable gateway routes")
    route_commands = route.add_subparsers(dest="route_command", required=True)
    route_commands.add_parser("list")
    create = route_commands.add_parser("create")
    create.add_argument("--endpoint-id", type=UUID, required=True)
    create.add_argument("--model-pattern", required=True)
    create.add_argument("--target-binding", required=True)
    create.add_argument("--target-model")
    create.add_argument("--priority", type=int, default=100)
    create.add_argument("--idempotency-key")
    enable = route_commands.add_parser("enable")
    enable.add_argument("--route-id", required=True)
    enable.add_argument("--resource-version", type=int, required=True)
    _add_principal_arguments(enable)

    key = commands.add_parser("key", help="Manage Exchange gateway credentials")
    key_commands = key.add_subparsers(dest="key_command", required=True)
    create_key = key_commands.add_parser("create", help="Install an operator credential")
    create_key.add_argument("--token", required=True)
    _add_principal_arguments(create_key)
    issue_key = key_commands.add_parser("issue", help="Generate a one-time gateway API key")
    issue_key.add_argument("--name", required=True)
    issue_key.add_argument("--expires-at", type=_timestamp)
    issue_key.add_argument("--model-scope", action="append", default=[])
    issue_key.add_argument("--idempotency-key")
    _add_principal_arguments(issue_key)
    list_keys = key_commands.add_parser("list", help="List gateway API key metadata")
    _add_principal_arguments(list_keys)
    revoke_key = key_commands.add_parser("revoke", help="Revoke a credential or API key")
    revoke_target = revoke_key.add_mutually_exclusive_group(required=True)
    revoke_target.add_argument("--credential-ref")
    revoke_target.add_argument("--api-key-id", type=UUID)
    revoke_key.add_argument("--actor-id", default="cyrene-operator")
    revoke_key.add_argument("--workspace-id", default="default")

    integrations = commands.add_parser(
        "integrations",
        help="Run an Exchange integration worker as a separate host-managed process",
    )
    integration_commands = integrations.add_subparsers(dest="integration_command", required=True)
    integration_commands.add_parser(
        "check-config",
        help=(
            "Validate Exchange integration config and Platform profile without DB or network calls"
        ),
    )
    for command_name, help_text in (
        ("dispatch", "Run the durable integration dispatcher until shutdown"),
        ("dispatch-once", "Claim and process at most one durable integration job"),
        ("authorization-cloud", "Run authorization, cloud, and email monitoring until shutdown"),
        ("authorization-cloud-once", "Run one authorization/cloud/email worker cycle"),
    ):
        worker = integration_commands.add_parser(command_name, help=help_text)
        worker.add_argument(
            "--integration-database",
            type=Path,
            help="Separate SQLite path for integration inbox, outbox, and operation state",
        )
    binding_export = integration_commands.add_parser(
        "connector-bindings",
        help=(
            "Export a Navigator launcher binding map for one actor and optional "
            "organization/workspace"
        ),
    )
    binding_export.add_argument("--integration-database", type=Path, required=True)
    binding_export.add_argument("--issuer", required=True)
    binding_export.add_argument("--subject", required=True)
    binding_export.add_argument("--organization-id")
    binding_export.add_argument("--workspace-id", required=True)
    catalog_export = integration_commands.add_parser(
        "connector-tool-catalog",
        help="Export actual provider tool schemas for one exact actor, organization, and workspace",
    )
    catalog_export.add_argument("--integration-database", type=Path, required=True)
    catalog_export.add_argument("--issuer", required=True)
    catalog_export.add_argument("--subject", required=True)
    catalog_export.add_argument("--organization-id", required=True)
    catalog_export.add_argument("--workspace-id", required=True)
    readiness_export = integration_commands.add_parser(
        "connector-readiness",
        help=(
            "Export Exchange-issued profiles, connections, and live tool catalogs "
            "without credentials"
        ),
    )
    readiness_export.add_argument("--integration-database", type=Path, required=True)
    readiness_export.add_argument("--issuer", required=True)
    readiness_export.add_argument("--subject", required=True)
    readiness_export.add_argument("--organization-id", required=True)
    readiness_export.add_argument("--workspace-id", required=True)
    bootstrap_connectors = integration_commands.add_parser(
        "bootstrap-connectors",
        help="Provision initial GitHub and Hugging Face profiles from a private operator file",
    )
    bootstrap_connectors.add_argument("--integration-database", type=Path, required=True)
    bootstrap_connectors.add_argument("--private-config", type=Path, required=True)
    bootstrap_connectors.add_argument(
        "--plan-only",
        action="store_true",
        help=(
            "Verify the current Directory role and print refs without linking profiles "
            "or saving connections"
        ),
    )
    return value


def run(argv: list[str] | None = None) -> int:
    """Execute one operator command and return its process exit code.

    中文:执行一条 operator 命令并返回进程退出码。
    """
    # 中文:执行一条操作员命令并返回其进程退出码。

    if os.environ.get("CYRENE_EXCHANGE_PROCESS_ROLE") == "check-config":
        return _integration_check_config()
    arguments = parser().parse_args(argv)
    if arguments.command == "serve":
        return _serve(arguments)
    if arguments.command == "integrations":
        if arguments.integration_command == "check-config":
            return _integration_check_config()
        if arguments.integration_command == "connector-bindings":
            return _integration_connector_bindings(arguments)
        if arguments.integration_command == "connector-tool-catalog":
            return _integration_connector_tool_catalog(arguments)
        if arguments.integration_command == "connector-readiness":
            return _integration_connector_readiness(arguments)
        if arguments.integration_command == "bootstrap-connectors":
            return _integration_connector_bootstrap(arguments)
        if arguments.integration_command.startswith("authorization-cloud"):
            return _integration_authorization_cloud(
                arguments,
                once=arguments.integration_command.endswith("-once"),
            )
        return _integration_dispatch(
            arguments,
            once=arguments.integration_command == "dispatch-once",
        )
    if arguments.database is None:
        raise SystemExit("--database is required for route and key commands")
    if arguments.command == "route":
        if arguments.route_command == "list":
            return _route_list(arguments)
        if arguments.route_command == "create":
            return _route_create(arguments)
        return _route_enable(arguments)
    if arguments.key_command == "create":
        return _key_create(arguments)
    if arguments.key_command == "issue":
        return _key_issue(arguments)
    if arguments.key_command == "list":
        return _key_list(arguments)
    return _key_revoke(arguments)


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
