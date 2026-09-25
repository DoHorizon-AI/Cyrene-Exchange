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
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from uuid import UUID

import uvicorn

from cyrene_exchange_product.domain import (
    CreateApiKeyRequest,
    CreateRouteRequest,
    ProductPrincipal,
)
from cyrene_exchange_product.server import (
    OpenAICompatibleProvider,
    OperatorBindingResolver,
    RouteSourceProviderResolver,
    build_product_app,
)
from cyrene_exchange_product.service import ExchangeProductService
from cyrene_exchange_product.store import ExchangeStore


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


def _serve(arguments: argparse.Namespace) -> int:
    control_token = arguments.control_token
    if arguments.control_token_env:
        control_token = os.environ.get(arguments.control_token_env)
        if not control_token:
            raise SystemExit("The configured control credential variable is empty")
    credentials = {control_token: _principal(arguments)} if control_token else {}
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
    app = build_product_app(
        database_path=arguments.database.resolve(),
        resolver=resolver,
        resolver_factory=resolver_factory,
        control_credentials=credentials or None,
        allowed_binding_ids=_admitted_bindings(arguments),
        endpoint_id=arguments.endpoint_id,
    )
    uvicorn.run(app, host=arguments.host, port=arguments.port, access_log=False)
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
    command.add_argument("--credential-ref", default="cred://exchange/operator")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Cyrene Exchange Product operator CLI")
    value.add_argument("--database", type=Path, required=True)
    commands = value.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="Run the independent Exchange gateway")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--control-token")
    serve.add_argument(
        "--control-token-env",
        help="Name of the environment variable holding the control credential",
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
    return value


def run(argv: list[str] | None = None) -> int:
    """Execute one operator command and return its process exit code.

    中文:执行一条 operator 命令并返回进程退出码。
    """
    # 中文:执行一条操作员命令并返回其进程退出码。

    arguments = parser().parse_args(argv)
    if arguments.command == "serve":
        return _serve(arguments)
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
