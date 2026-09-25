#!/usr/bin/env python3
"""Run a real persisted Product route through a direct Plugin and vLLM.

The proof provisions ``GatewayEndpoint`` and ``GatewayRoute`` in the Product
SQLite authority, asks Platform's generic resolver to select an implementation,
and calls the Plugins-owned endpoint directly. It prints only credential-free
outcome metadata.

中文:通过直连 Plugin 和 vLLM 运行一条真实持久化 Product 路由。

中文:此证明流程会在 Product SQLite 权威存储中创建 ``GatewayEndpoint`` 和 ``GatewayRoute``,请求 Platform 通用 resolver 选择实现,并直接调用 Plugins 所有的端点。输出仅包含不带凭据的结果元数据。
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from http.client import HTTPConnection
from pathlib import Path
from threading import Event, Thread
from typing import Any
from uuid import UUID

from cyrene_exchange.direct_plugin import (  # type: ignore[import-untyped]
    local_plugin_client,
)
from cyrene_exchange.http import create_reference_server  # type: ignore[import-untyped]
from cyrene_exchange.platform_resolver import (  # type: ignore[import-untyped]
    PlatformResolverAdapter,
)

from cyrene_exchange_product import ProductPrincipal, build_gateway_from_store
from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.domain import CreateEndpointRequest, CreateRouteRequest
from cyrene_exchange_product.route_admission import ReactorRouteAdmission
from cyrene_exchange_product.service import ExchangeProductService
from cyrene_exchange_product.store import ExchangeStore

_PRODUCT_ENDPOINT_IDEMPOTENCY_KEY = "cyrene-product-vllm-proof-endpoint-v1"
_PRODUCT_ROUTE_IDEMPOTENCY_KEY = "cyrene-product-vllm-proof-route-v1"
_PRODUCT_BINDING_ID = "vllm-product"


def _default_root(name: str) -> Path:
    """Resolve sibling repositories from the Cyrene umbrella directory.

    中文:从 Cyrene 总仓目录解析同级仓库。"""

    return Path(__file__).resolve().parents[4] / name


def _wait_for_ready(process: subprocess.Popen[str], timeout: float) -> str:
    """Read one credential-free direct Plugin readiness document.

    中文:读取一份不含凭据的直连 Plugin 就绪文档。"""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"direct Plugin exited before readiness with code {process.returncode}"
            )
        if process.stdout is not None:
            readable, _, _ = select.select([process.stdout], [], [], 0.05)
            if readable:
                document = json.loads(process.stdout.readline())
                return str(document["connection_ref"])
    _stop_process(process, timeout=5)
    raise RuntimeError(f"direct Plugin did not publish readiness within {timeout:.1f}s")


def _post(port: int, payload: dict[str, Any], token: str) -> tuple[int, str]:
    """Call the Product-composed data plane without printing message content.

    中文:调用 Product 组合的数据平面,不打印消息内容。"""

    connection = HTTPConnection("127.0.0.1", port, timeout=180)
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=json.dumps(payload),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def _request_id(body: str, *, stream: bool = False) -> str | None:
    """Extract only the Exchange request id from a response.

    中文:从响应中只提取 Exchange 请求 ID。"""

    try:
        if stream:
            for line in body.splitlines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    document = json.loads(line[6:])
                    if isinstance(document, dict) and isinstance(document.get("id"), str):
                        return document["id"]
            return None
        document = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(document, dict) and isinstance(document.get("id"), str):
        return document["id"]
    return None


def _tool_from_response(body: str) -> list[dict[str, Any]]:
    """Validate a non-stream tool response without retaining its text.

    中文:验证非流式工具响应,不保留其文本内容。"""

    document = json.loads(body)
    calls = document["choices"][0]["message"]["tool_calls"]
    if not isinstance(calls, list) or not calls:
        raise RuntimeError("tool proof response contains no tool_calls")
    return calls


def _provision_product_route(store: ExchangeStore, binding_id: str) -> tuple[UUID, UUID]:
    """Create or replay one stable Product endpoint and route.

    中文:创建或重放一组稳定的 Product 端点和路由。"""

    service = ExchangeProductService(store)
    endpoint = service.create_endpoint(
        CreateEndpointRequest(
            name="product-vllm-proof",
            public_base_url="http://127.0.0.1/v1",
            auth_policy_ref="policy://exchange/product-proof",
        ),
        idempotency_key=_PRODUCT_ENDPOINT_IDEMPOTENCY_KEY,
    )
    route = service.create_route(
        CreateRouteRequest(
            endpoint_id=endpoint.id,
            model_pattern="*",
            target_binding_id=binding_id,
            target_model=None,
            priority=10,
        ),
        idempotency_key=_PRODUCT_ROUTE_IDEMPOTENCY_KEY,
    )
    return endpoint.id, route.id


def _publish_readiness(readiness_file: Path | None, document: dict[str, Any]) -> None:
    """Publish credential-free readiness metadata to stdout and an optional file.

    中文:将不含凭据的就绪元数据写入 stdout 和可选文件。"""

    encoded = json.dumps(document, separators=(",", ":"))
    if readiness_file is not None:
        readiness_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_file = readiness_file.with_name(f".{readiness_file.name}.{os.getpid()}.tmp")
        temporary_file.write_text(encoded + "\n", encoding="utf-8")
        temporary_file.chmod(0o600)
        temporary_file.replace(readiness_file)
    print(encoded, flush=True)


def _wait_for_stop() -> None:
    """Wait for SIGINT/SIGTERM while the reference server runs in its thread.

    中文:参考服务器在线程中运行时等待 SIGINT/SIGTERM。"""

    stop_event = Event()
    previous_handlers: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    try:
        stop_event.wait()
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        for previous_signum, handler in previous_handlers.items():
            signal.signal(previous_signum, handler)


def _stop_process(process: subprocess.Popen[str], *, timeout: float = 8.0) -> None:
    """Terminate a child process and escalate if it does not exit.

    中文:终止子进程;若进程未退出则升级为强制终止。"""

    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    """Compose Product persistence, Platform selection, and direct Plugin execution.

    中文:组合 Product 持久化、Platform 选择和直连 Plugin 执行。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-root", type=Path, default=_default_root("Cyrene-Platform"))
    parser.add_argument(
        "--plugins-root", type=Path, default=_default_root("Cyrene-Plugins-Official")
    )
    parser.add_argument(
        "--vllm-base-url",
        default=os.environ.get("CYRENE_VLLM_BASE_URL", "http://127.0.0.1:19180/v1"),
    )
    parser.add_argument("--model", default=os.environ.get("CYRENE_VLLM_MODEL", "cyrene-proof-text"))
    parser.add_argument("--api-key", default=os.environ.get("CYRENE_VLLM_API_KEY", ""))
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="private SQLite path; required for --serve so the route survives restart",
    )
    parser.add_argument(
        "--message", default="Reply with one short sentence proving the Product route works."
    )
    parser.add_argument("--tool-smoke", action="store_true")
    parser.add_argument(
        "--serve",
        action="store_true",
        help="keep the Product-composed Exchange gateway running after readiness",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=os.environ.get("CYRENE_EXCHANGE_PRODUCT_PORT", "0"),
        help="loopback port used by --serve (default: 0, choose an ephemeral port)",
    )
    parser.add_argument(
        "--ready-file",
        type=Path,
        default=os.environ.get("CYRENE_EXCHANGE_PRODUCT_READY_FILE"),
        help="optional path receiving the credential-free readiness JSON",
    )
    parser.add_argument(
        "--actor-id",
        default=os.environ.get("CYRENE_EXCHANGE_ACTOR_ID", "product-proof-actor"),
        help="controlled Product principal actor reference (or CYRENE_EXCHANGE_ACTOR_ID)",
    )
    parser.add_argument(
        "--workspace-id",
        default=os.environ.get("CYRENE_EXCHANGE_WORKSPACE_ID", "product-proof-workspace"),
        help="controlled Product principal Workspace reference (or CYRENE_EXCHANGE_WORKSPACE_ID)",
    )
    parser.add_argument(
        "--credential-ref",
        default=os.environ.get("CYRENE_EXCHANGE_CREDENTIAL_REF", "product-proof-credential"),
        help="controlled persisted credential reference (or CYRENE_EXCHANGE_CREDENTIAL_REF)",
    )
    parser.add_argument("--ready-timeout", type=float, default=15.0)
    parser.add_argument(
        "--draft-control-port",
        type=int,
        default=None,
        help="serve authenticated route drafts without provisioning an active route",
    )
    parser.add_argument("--reactor-base-url", default=None)
    parser.add_argument("--reactor-credential-file", type=Path, default=None)
    args = parser.parse_args()
    if args.draft_control_port is not None and (
        not args.serve
        or not 1 <= args.draft_control_port <= 65535
        or not 1 <= args.listen_port <= 65535
        or not args.reactor_base_url
        or not args.reactor_credential_file
    ):
        parser.error(
            "draft control requires --serve, fixed valid ports and Reactor source configuration"
        )
    if args.serve and args.tool_smoke:
        parser.error("--serve and --tool-smoke cannot be combined")
    if args.listen_port < 0 or args.listen_port > 65535:
        parser.error("--listen-port must be between 0 and 65535")
    if args.serve and args.database is None:
        parser.error("--database is required with --serve for durable route reuse")

    exchange_token = os.environ.get("CYRENE_EXCHANGE_BEARER_TOKEN", "")
    if not exchange_token.strip():
        raise RuntimeError("CYRENE_EXCHANGE_BEARER_TOKEN must be set")
    principal = ProductPrincipal(
        actor_id=args.actor_id,
        workspace_id=args.workspace_id,
        credential_ref=args.credential_ref,
    )

    platform_root = args.platform_root.resolve()
    plugins_root = args.plugins_root.resolve()
    connector_root = plugins_root / "plugins/providers/model-api-connector"
    provider_manifest = connector_root / "plugin.manifest.json"
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", platform_root / "target"))
    if not target_root.is_absolute():
        target_root = platform_root / target_root
    resolver_binary = target_root / "debug/cyrene-capability-resolver"
    missing = [str(path) for path in (resolver_binary, provider_manifest) if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "missing proof prerequisites; build Platform binaries first: " + ", ".join(missing)
        )

    temporary_context = tempfile.TemporaryDirectory(prefix="cyrene-product-vllm-proof-")
    database = (
        args.database.resolve()
        if args.database is not None
        else Path(temporary_context.name) / "exchange.sqlite3"
    )
    runtime_environment = os.environ.copy()
    runtime_environment.update(
        {
            "PYTHONPATH": os.pathsep.join(
                (
                    str(plugins_root / "sdk/python/cyrene_model_provider_contracts/src"),
                    str(plugins_root / "sdk/python/cyrene_plugin_runtime/src"),
                    str(connector_root / "src"),
                )
            ),
            "CYRENE_CHAT_BASE_URL": args.vllm_base_url,
            "CYRENE_CHAT_MODEL": args.model,
            "CYRENE_CHAT_API_KEY": args.api_key,
            "CYRENE_CHAT_TIMEOUT": "180",
            "CYRENE_EMBEDDINGS_SUPPORTED": "false",
        }
    )
    plugin_command = [
        sys.executable,
        "-m",
        "cyrene_plugin_runtime.server",
        "--entrypoint",
        "model_api_connector:ModelApiConnector",
        "--capability",
        "model.provider.v1",
        "--interface-version",
        "1",
        "--interface-version",
        "2",
        "--listen",
        "127.0.0.1:0",
    ]
    store = ExchangeStore(database)
    plugin_process: subprocess.Popen[str] | None = None
    plugin_client = None
    gateway_server = None
    server_thread: Thread | None = None
    endpoint_id: UUID | None = None
    route_id: UUID | None = None
    published_ready_file: Path | None = None
    control_server = None
    control_thread: Thread | None = None
    try:
        plugin_process = subprocess.Popen(
            plugin_command,
            cwd=connector_root,
            env=runtime_environment,
            text=True,
            stdout=subprocess.PIPE,
        )
        if args.draft_control_port is None:
            endpoint_id, route_id = _provision_product_route(store, _PRODUCT_BINDING_ID)
        else:
            endpoint_id = (
                ExchangeProductService(store)
                .create_endpoint(
                    CreateEndpointRequest(
                        name="reactor-explicit-route-gateway",
                        public_base_url=f"http://127.0.0.1:{args.listen_port}/v1",
                        auth_policy_ref="policy://exchange/product-proof",
                    ),
                    idempotency_key=_PRODUCT_ENDPOINT_IDEMPOTENCY_KEY + "-draft-control-v1",
                )
                .id
            )
        assert endpoint_id is not None
        # Reopen the same Product database before composing the data plane.
        # This keeps the proof tied to persisted endpoint/route state.
        # 中文:在组合数据平面前重新打开同一个 Product 数据库,使该证明仍绑定到已持久化的端点/路由状态。
        store.close()
        store = ExchangeStore(database)
        connection_ref = _wait_for_ready(plugin_process, args.ready_timeout)
        plugin_client = local_plugin_client(connection_ref)
        resolver = PlatformResolverAdapter(
            [str(resolver_binary)],
            [provider_manifest],
            resolver_cwd=platform_root,
            plugin_clients={_PRODUCT_BINDING_ID: plugin_client},
            provider_deadline_seconds=180.0,
        )
        gateway = build_gateway_from_store(
            store,
            endpoint_id,
            resolver,
            credentials={exchange_token: principal},
            max_route_attempts=1,
        )
        gateway_server = create_reference_server(gateway, port=args.listen_port)
        server_thread = Thread(target=gateway_server.serve_forever, daemon=True)
        server_thread.start()

        if args.draft_control_port is not None:
            import uvicorn

            control_token = os.environ.get("CYRENE_EXCHANGE_CONTROL_BEARER_TOKEN", "")
            if len(control_token) < 32:
                raise RuntimeError("an explicit private Exchange control credential is required")
            reactor_token = args.reactor_credential_file.read_text().strip()
            admission = ReactorRouteAdmission(
                reactor_base_url=args.reactor_base_url,
                reactor_token=reactor_token,
                resolver=resolver,
            )
            control_app = create_app(
                database_path=database,
                control_credentials={
                    control_token: ProductPrincipal(
                        actor_id=args.actor_id,
                        workspace_id=args.workspace_id,
                        credential_ref=args.credential_ref + "-route-control",
                    )
                },
                allowed_binding_ids=frozenset({_PRODUCT_BINDING_ID}),
                validate_route_target=admission,
            )
            control_server = uvicorn.Server(
                uvicorn.Config(
                    control_app, host="127.0.0.1", port=args.draft_control_port, log_level="warning"
                )
            )
            control_thread = Thread(target=control_server.run, daemon=True)
            control_thread.start()
            deadline = time.monotonic() + args.ready_timeout
            while not control_server.started and time.monotonic() < deadline:
                time.sleep(0.05)
            if not control_server.started:
                raise RuntimeError("Exchange draft control API did not start")

        if args.serve:
            address = gateway_server.server_address
            readiness = {
                "event": "ready",
                "service": "cyrene-exchange-product",
                "mode": "serve",
                "url": f"http://127.0.0.1:{address[1]}/v1",
                "auth": "bearer",
                "model": args.model,
                "endpointId": str(endpoint_id),
                "routeId": str(route_id) if route_id else None,
                "routePublication": "explicit-draft-confirmation"
                if args.draft_control_port
                else "preprovisioned-active-route",
                "controlUrl": f"http://127.0.0.1:{args.draft_control_port}"
                if args.draft_control_port
                else None,
                "binding": _PRODUCT_BINDING_ID,
                "actorId": principal.actor_id,
                "workspaceId": principal.workspace_id,
                "credentialRef": principal.credential_ref,
                "resolver": "cyrene-capability-resolver",
                "pluginEndpoint": connection_ref,
                "providerConnector": "cyrene.providers.model-api-connector",
                "pid": os.getpid(),
            }
            _publish_readiness(args.ready_file, readiness)
            published_ready_file = args.ready_file
            _wait_for_stop()
            return 0

        statuses: dict[str, int] = {}
        request_ids: dict[str, str | None] = {}
        statuses["unary"], unary_body = _post(
            gateway_server.server_port,
            {"model": args.model, "messages": [{"role": "user", "content": args.message}]},
            exchange_token,
        )
        request_ids["unary"] = _request_id(unary_body)
        if statuses["unary"] != 200:
            raise RuntimeError(f"Product unary proof failed with HTTP {statuses['unary']}")

        if args.tool_smoke:
            tool = {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Look up weather for one city.",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"],
                        "additionalProperties": False,
                    },
                },
            }
            tool_request = {
                "model": args.model,
                "messages": [{"role": "user", "content": "Call get_weather for Paris."}],
                "tools": [tool],
                "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
            }
            statuses["tool_call"], tool_body = _post(
                gateway_server.server_port, tool_request, exchange_token
            )
            request_ids["tool_call"] = _request_id(tool_body)
            if statuses["tool_call"] != 200:
                raise RuntimeError(f"Product tool proof failed with HTTP {statuses['tool_call']}")
            tool_calls = _tool_from_response(tool_body)
            call_id = tool_calls[0].get("id")
            if not isinstance(call_id, str) or not call_id:
                raise RuntimeError("Product tool proof returned a tool call without an id")
            statuses["tool_result"], result_body = _post(
                gateway_server.server_port,
                {
                    **tool_request,
                    "messages": [
                        tool_request["messages"][0],
                        {"role": "assistant", "content": None, "tool_calls": tool_calls},
                        {"role": "tool", "tool_call_id": call_id, "content": "Paris: clear."},
                    ],
                    "tool_choice": "none",
                },
                exchange_token,
            )
            request_ids["tool_result"] = _request_id(result_body)
            if statuses["tool_result"] != 200:
                raise RuntimeError(
                    f"Product tool-result proof failed with HTTP {statuses['tool_result']}"
                )

        statuses["stream"], stream_body = _post(
            gateway_server.server_port,
            {
                "model": args.model,
                "messages": [{"role": "user", "content": args.message}],
                "stream": True,
                "stream_options": {"include_usage": True},
            },
            exchange_token,
        )
        request_ids["stream"] = _request_id(stream_body, stream=True)
        if statuses["stream"] != 200 or not stream_body.rstrip().endswith("data: [DONE]"):
            raise RuntimeError(f"Product stream proof failed with HTTP {statuses['stream']}")

        audits = store.list_request_audits(workspace_id=principal.workspace_id)
        expected_ids = {request_id for request_id in request_ids.values() if request_id is not None}
        audited_ids = {record.request_id for record in audits}
        if not expected_ids.issubset(audited_ids):
            raise RuntimeError("Product proof responses were not durably audited")
        expected_audits = [record for record in audits if record.request_id in expected_ids]
        if any(record.status.value != "completed" for record in expected_audits):
            raise RuntimeError("Product proof did not reach completed audit state")
        print(
            json.dumps(
                {
                    "outcome": "pass",
                    "mode": "product-vllm-smoke",
                    "model": args.model,
                    "tool_smoke": args.tool_smoke,
                    "request_ids": request_ids,
                    "audit_statuses": {record.request_id: record.status.value for record in audits},
                    "audit_usage_states": {
                        record.request_id: record.usage_state.value for record in audits
                    },
                    "route": str(route_id),
                    "endpoint": str(endpoint_id),
                    "port": gateway_server.server_port,
                    "resolver": resolver.resolutions,
                },
                separators=(",", ":"),
            )
        )
        return 0
    finally:
        if control_server is not None:
            control_server.should_exit = True
        if control_thread is not None:
            control_thread.join(timeout=10)
        if gateway_server is not None:
            gateway_server.shutdown()
            gateway_server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=3)
        if published_ready_file is not None and published_ready_file.exists():
            published_ready_file.unlink()
        if plugin_client is not None:
            plugin_client.close()
        store.close()
        if plugin_process is not None:
            _stop_process(plugin_process)
        temporary_context.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as error:
        print(f"Product proof setup failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
