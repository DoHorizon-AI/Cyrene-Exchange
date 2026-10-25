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
from dataclasses import asdict
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from threading import Event
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


def _integration_connector_bindings(arguments: argparse.Namespace) -> int:
    """Export the launcher-owned connection map from trusted Exchange SQLite rows."""

    from cyrene_exchange_product.integrations.cli import build_production_services
    from cyrene_exchange_product.integrations.connector_operations import (
        connector_binding_tools,
    )

    database_path = Path(arguments.integration_database).expanduser().resolve()
    if not database_path.is_file():
        raise SystemExit("Exchange integration database does not exist")
    services = build_production_services(database_path)
    try:
        connections = services.store.connector_bindings_for_actor(
            issuer=arguments.issuer,
            subject=arguments.subject,
            workspace_id=arguments.workspace_id,
        )
        bindings: list[dict[str, object]] = []
        skipped = 0
        for connection in connections:
            provider_id = "huggingface" if connection.provider == "hf" else connection.provider
            tools = connector_binding_tools(provider_id)
            if not tools:
                continue
            profile_ref = (
                connection.account_link_ref
                if connection.provider in {"github", "hf"}
                else connection.binding_ref
            )
            if not profile_ref or (connection.provider != "github" and not connection.target_ref):
                skipped += 1
                continue
            bindings.append(
                {
                    "bindingId": f"exchange-{provider_id}-{connection.id}",
                    "connectionRef": str(connection.id),
                    "providerId": provider_id,
                    "profileRef": profile_ref,
                    "tools": tools,
                }
            )
        computer_profile = getattr(services, "computer_runner_profile", None)
        if (
            computer_profile is not None
            and computer_profile.expected_issuer == arguments.issuer
            and computer_profile.workspace_id == arguments.workspace_id
        ):
            if not arguments.organization_id:
                raise SystemExit("computer connector binding export requires --organization-id")
            if computer_profile.organization_id == arguments.organization_id:
                bindings.append(
                    {
                        "bindingId": f"exchange-computer-{computer_profile.connection_ref}",
                        "connectionRef": computer_profile.connection_ref,
                        "providerId": "computer",
                        "profileRef": computer_profile.profile_ref,
                        "tools": connector_binding_tools("computer"),
                    }
                )
        if skipped:
            print(
                f"Skipped {skipped} provider connection(s) without a configured profile or target.",
                file=sys.stderr,
            )
        payload = json.dumps(
            {"schemaVersion": 1, "bindings": bindings},
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
    from cyrene_exchange_product.integrations.clients import ProviderToolDefinition
    from cyrene_exchange_product.integrations.connector_operations import (
        connector_binding_tools,
        validate_computer_tool_schema,
    )

    database_path = Path(arguments.integration_database).expanduser().resolve()
    if not database_path.is_file():
        raise SystemExit("Exchange integration database does not exist")
    services = build_production_services(database_path)
    try:
        connections = services.store.connector_bindings_for_actor(
            issuer=arguments.issuer,
            subject=arguments.subject,
            organization_id=arguments.organization_id,
            workspace_id=arguments.workspace_id,
        )
        items: list[dict[str, object]] = []
        catalog_cache: dict[tuple[str, str], dict[str, ProviderToolDefinition]] = {}
        for connection in connections:
            if connection.organization_id != arguments.organization_id:
                continue
            provider_id = "huggingface" if connection.provider == "hf" else connection.provider
            operation_map = connector_binding_tools(provider_id)
            if not operation_map:
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
                raise SystemExit(
                    "an enabled connector connection has no complete host profile scope"
                )

            source_binding = "github" if provider_id == "github" else str(connection.binding_ref)
            cache_key = (provider_id, source_binding)
            descriptors = catalog_cache.get(cache_key)
            if descriptors is None:
                if provider_id == "github":
                    provider_catalog = services.github.list_tool_catalog()
                else:
                    if services.authorization_cloud is None:
                        raise SystemExit("configured connector provider catalog is unavailable")
                    provider_catalog = services.authorization_cloud.list_tool_catalog(
                        str(connection.binding_ref)
                    )
                descriptors = {descriptor.tool_id: descriptor for descriptor in provider_catalog}
                catalog_cache[cache_key] = descriptors

            expected = {str(entry["toolId"]): entry for entry in operation_map}
            if len(expected) != len(operation_map):
                raise SystemExit("Exchange connector operation map contains duplicate tool IDs")
            missing = set(expected) - set(descriptors)
            if missing:
                raise SystemExit(
                    "configured provider catalog is missing required Exchange operations"
                )
            tools: list[dict[str, object]] = []
            for tool_id in sorted(expected):
                definition = descriptors[tool_id]
                mapping = expected[tool_id]
                mutating = mapping.get("mutating")
                if not isinstance(mutating, bool):
                    raise SystemExit("Exchange connector operation map has invalid mutability")
                tools.append(
                    {
                        "id": definition.tool_id,
                        "name": definition.name,
                        "description": definition.description,
                        "readOnly": not mutating,
                        "inputSchema": definition.input_schema,
                    }
                )
            items.append(
                {
                    "bindingId": f"exchange-{provider_id}-{connection.id}",
                    "capabilityId": "tool.provider.v1",
                    "providerId": provider_id,
                    "connectionRef": str(connection.id),
                    "profileRef": profile_ref,
                    "tools": tools,
                }
            )

        computer_profile = getattr(services, "computer_runner_profile", None)
        if (
            computer_profile is not None
            and computer_profile.expected_issuer == arguments.issuer
            and computer_profile.organization_id == arguments.organization_id
            and computer_profile.workspace_id == arguments.workspace_id
        ):
            computer_client = getattr(services, "computer_runner_client", None)
            if computer_client is None:
                raise SystemExit("configured computer runner tool catalog is unavailable")
            descriptors = computer_client.list_tool_catalog()
            by_id = {descriptor.tool_id: descriptor for descriptor in descriptors}
            operation_map = connector_binding_tools("computer")
            expected = {str(item["toolId"]): item for item in operation_map}
            if len(expected) != len(operation_map) or set(expected) - set(by_id):
                raise SystemExit("computer runner catalog is missing a required fixed operation")
            computer_tools: list[dict[str, object]] = []
            for tool_id in sorted(expected):
                definition = by_id[tool_id]
                mapping = expected[tool_id]
                validate_computer_tool_schema(
                    computer_profile,
                    tool_id=tool_id,
                    input_schema=definition.input_schema,
                )
                mutating = mapping.get("mutating")
                if not isinstance(mutating, bool):
                    raise SystemExit("computer runner operation map has invalid mutability")
                computer_tools.append(
                    {
                        "id": definition.tool_id,
                        "name": definition.name,
                        "description": definition.description,
                        "readOnly": not mutating,
                        "inputSchema": definition.input_schema,
                    }
                )
            items.append(
                {
                    "bindingId": f"exchange-computer-{computer_profile.connection_ref}",
                    "capabilityId": "tool.provider.v1",
                    "providerId": "computer",
                    "connectionRef": computer_profile.connection_ref,
                    "profileRef": computer_profile.profile_ref,
                    "tools": computer_tools,
                }
            )

        output = json.dumps(
            {"schemaVersion": 1, "items": items},
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
