#!/usr/bin/env python3
"""Run the local Exchange -> direct Official Plugin smoke path.

The script owns only process composition for a developer check. Platform's
generic resolver selects the implementation; Exchange calls the Plugins-owned
endpoint directly, and the provider connector owns upstream HTTP.

中文:运行 Exchange 到官方 Direct Plugin 的本地 smoke 检查。脚本只负责为开发者组合进程;Platform 通用 resolver 选择实现,Exchange 直接调用 Plugins 所有的 endpoint,而 provider connector 负责上游 HTTP。
"""
# 中文:运行本地 Exchange → 直接 Official Plugin 冒烟流程。此脚本只负责开发者检查所需的进程组合。Platform 的通用解析器负责选择实现;Exchange 直接调用 Plugins 所有的端点,而提供方连接器负责上游 HTTP。

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import subprocess
import sys
import time
from http.client import HTTPConnection
from pathlib import Path
from threading import Event, Thread
from typing import Any

from cyrene_exchange.direct_plugin import local_plugin_client
from cyrene_exchange.gateway import ExchangeGateway, NoOpLifecycleObserver, RequestPrincipal
from cyrene_exchange.http import create_reference_server
from cyrene_exchange.platform_resolver import PlatformResolverAdapter


def _default_root(name: str) -> Path:
    # ``scripts`` is under ``Cyrene-Exchange``; sibling repositories live in
    # the workspace's ``Cyrene`` directory.
    # 中文:``scripts`` 位于 ``Cyrene-Exchange`` 下;同级仓库位于工作区的 ``Cyrene`` 目录中。
    return Path(__file__).resolve().parents[3] / name


def _wait_for_ready(process: subprocess.Popen[str], timeout: float) -> str:
    """Read one credential-free direct Plugin readiness document.

    中文:读取一份无凭据的 Direct Plugin readiness 文档。
    """
# 中文:读取一份不含凭据的直接 Plugin 就绪状态文档。

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"direct Plugin exited before readiness with code {process.returncode}")
        if process.stdout is not None:
            readable, _, _ = select.select([process.stdout], [], [], 0.05)
            if readable:
                document = json.loads(process.stdout.readline())
                return str(document["connection_ref"])
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError(f"direct Plugin did not publish readiness within {timeout:.1f}s")


def _post(port: int, payload: dict[str, Any], exchange_token: str) -> tuple[int, str, str]:
    connection = HTTPConnection("127.0.0.1", port, timeout=180)
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=json.dumps(payload),
            headers={
                "Authorization": f"Bearer {exchange_token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "")
        body = response.read().decode("utf-8")
        return response.status, content_type, body
    except OSError as error:
        raise RuntimeError(f"Exchange HTTP request failed: {error}") from error
    finally:
        connection.close()


def _request_id(body: str, *, stream: bool = False) -> str | None:
    """Extract a response request id without retaining the response body.

    中文:从响应中提取 request ID,不保留响应正文。
    """
# 中文:提取响应请求 ID,但不保留响应正文。

    try:
        if stream:
            for line in body.splitlines():
                if not line.startswith("data: ") or line == "data: [DONE]":
                    continue
                document = json.loads(line[6:])
                if isinstance(document, dict) and isinstance(document.get("id"), str):
                    return document["id"]
            return None
        document = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    return document.get("id") if isinstance(document, dict) and isinstance(document.get("id"), str) else None


def _publish_readiness(readiness_file: Path | None, document: dict[str, Any]) -> None:
    """Publish one credential-free JSON readiness document to stdout and disk.

    中文:向 stdout 和磁盘发布一份不含凭据的 JSON readiness 文档。
    """
# 中文:向标准输出和磁盘发布一份不含凭据的 JSON 就绪状态文档。

    encoded = json.dumps(document, separators=(",", ":"))
    if readiness_file is not None:
        readiness_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_file = readiness_file.with_name(f".{readiness_file.name}.{os.getpid()}.tmp")
        temporary_file.write_text(encoded + "\n", encoding="utf-8")
        temporary_file.replace(readiness_file)
    print(encoded, flush=True)


def _wait_for_stop() -> None:
    """Wait for SIGINT/SIGTERM while leaving the HTTP server on its worker thread.

    中文:等待 SIGINT/SIGTERM,同时保持 HTTP server 在线程中继续运行。
    """
# 中文:等待 SIGINT/SIGTERM,同时让 HTTP 服务器继续运行在线程中。

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-root", type=Path, default=_default_root("Cyrene-Platform"))
    parser.add_argument("--plugins-root", type=Path, default=_default_root("Cyrene-Plugins-Official"))
    parser.add_argument("--vllm-base-url", default=os.environ.get("CYRENE_VLLM_BASE_URL", "http://127.0.0.1:19180/v1"))
    parser.add_argument("--model", default=os.environ.get("CYRENE_VLLM_MODEL", "cyrene-proof-text"))
    parser.add_argument("--api-key", default=os.environ.get("CYRENE_VLLM_API_KEY", ""))
    parser.add_argument("--message", default="Reply with one short sentence proving the local model path works.")
    parser.add_argument(
        "--tool-smoke",
        action="store_true",
        help="also require a function tool call and a follow-up tool-result turn",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="keep the canonical Exchange gateway running on 127.0.0.1:19181",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=os.environ.get("CYRENE_EXCHANGE_PORT", "19181"),
        help="loopback port used by --serve (default: 19181)",
    )
    parser.add_argument(
        "--ready-file",
        type=Path,
        default=os.environ.get("CYRENE_EXCHANGE_READY_FILE"),
        help="optional path receiving the same credential-free readiness JSON",
    )
    parser.add_argument("--ready-timeout", type=float, default=15.0)
    args = parser.parse_args()
    if args.serve and args.tool_smoke:
        parser.error("--serve and --tool-smoke cannot be combined")
    if args.listen_port < 0 or args.listen_port > 65535:
        parser.error("--listen-port must be between 0 and 65535")

    exchange_token = os.environ.get("CYRENE_EXCHANGE_BEARER_TOKEN", "")
    if not exchange_token.strip():
        raise RuntimeError("CYRENE_EXCHANGE_BEARER_TOKEN must be set")

    platform_root = args.platform_root.resolve()
    plugins_root = args.plugins_root.resolve()
    connector_root = plugins_root / "plugins/providers/model-api-connector"
    provider_manifest = connector_root / "plugin.manifest.json"
    routing_manifest = Path(__file__).resolve().parents[1] / "tests/reference-routing.manifest.json"
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", platform_root / "target"))
    if not target_root.is_absolute():
        target_root = platform_root / target_root
    resolver_binary = target_root / "debug/cyrene-capability-resolver"
    missing = [str(path) for path in (resolver_binary, provider_manifest) if not path.exists()]
    if missing:
        raise FileNotFoundError("missing smoke prerequisites; build Platform binaries first: " + ", ".join(missing))

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
    plugin_process = subprocess.Popen(
        plugin_command,
        cwd=connector_root,
        env=runtime_environment,
        text=True,
        stdout=subprocess.PIPE,
    )
    client = None
    server = None
    thread: Thread | None = None
    published_ready_file: Path | None = None
    try:
        connection_ref = _wait_for_ready(plugin_process, args.ready_timeout)
        client = local_plugin_client(connection_ref)
        resolver = PlatformResolverAdapter(
            [str(resolver_binary)],
            [routing_manifest, provider_manifest],
            resolver_cwd=platform_root,
            plugin_configs={
                "cyrene.exchange.reference-routing": {
                    "targets": [{"provider_ref": "vllm-local", "route_id": "vllm-local"}]
                }
            },
            plugin_clients={"vllm-local": client},
            provider_deadline_seconds=180.0,
        )
        gateway = ExchangeGateway(
            resolver,
            principal_resolver=lambda token: (
                RequestPrincipal("local-smoke", "local-smoke", "environment-token") if token == exchange_token else None
            ),
            lifecycle_observer=NoOpLifecycleObserver(),
        )
        server = create_reference_server(gateway, port=args.listen_port if args.serve else 0)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()

        if args.serve:
            address = server.server_address
            readiness = {
                "event": "ready",
                "service": "cyrene-exchange-canonical",
                "mode": "serve",
                "url": f"http://127.0.0.1:{address[1]}/v1",
                "auth": "bearer",
                "model": args.model,
                "route": "vllm-local",
                "resolver": "cyrene-capability-resolver",
                "plugin_endpoint": "cyrene.providers.model-api-connector",
                "provider_connector": "cyrene.providers.model-api-connector",
                "pid": os.getpid(),
            }
            _publish_readiness(args.ready_file, readiness)
            published_ready_file = args.ready_file
            _wait_for_stop()
            return 0

        unary_status, unary_type, unary_body = _post(
            server.server_port,
            {"model": args.model, "messages": [{"role": "user", "content": args.message}]},
            exchange_token,
        )
        print(f"unary status={unary_status} content_type={unary_type}")
        print(unary_body)
        if unary_status != 200:
            return 1

        if args.tool_smoke:
            tool = {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Look up the weather for one city.",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"],
                        "additionalProperties": False,
                    },
                },
            }
            tool_status, tool_type, tool_body = _post(
                server.server_port,
                {
                    "model": args.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Call get_weather for Paris and do not answer directly.",
                        }
                    ],
                    "tools": [tool],
                    "tool_choice": {
                        "type": "function",
                        "function": {"name": "get_weather"},
                    },
                    "parallel_tool_calls": False,
                },
                exchange_token,
            )
            print(f"tool status={tool_status} content_type={tool_type}")
            print(tool_body)
            if tool_status != 200:
                return 1
            try:
                tool_document = json.loads(tool_body)
                tool_calls = tool_document["choices"][0]["message"]["tool_calls"]
                if not isinstance(tool_calls, list) or not tool_calls:
                    raise ValueError("response contains no tool_calls")
                first_tool_call = tool_calls[0]
                call_id = first_tool_call["id"]
                if not isinstance(call_id, str) or not call_id:
                    raise ValueError("tool call has no id")
            except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
                print(f"tool response validation failed: {error}", file=sys.stderr)
                return 1

            result_status, result_type, result_body = _post(
                server.server_port,
                {
                    "model": args.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Call get_weather for Paris and do not answer directly.",
                        },
                        {"role": "assistant", "content": None, "tool_calls": tool_calls},
                        {
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": "Paris: 20 C and clear.",
                        },
                    ],
                    "tools": [tool],
                    "tool_choice": "none",
                },
                exchange_token,
            )
            print(f"tool-result status={result_status} content_type={result_type}")
            print(result_body)
            if result_status != 200:
                return 1

        stream_status, stream_type, stream_body = _post(
            server.server_port,
            {
                "model": args.model,
                "messages": [{"role": "user", "content": args.message}],
                "stream": True,
                "stream_options": {"include_usage": True},
            },
            exchange_token,
        )
        print(f"stream status={stream_status} content_type={stream_type}")
        print(stream_body)
        if stream_status != 200:
            return 1
        request_ids = {
            "unary": _request_id(unary_body),
            "stream": _request_id(stream_body, stream=True),
        }
        if args.tool_smoke:
            request_ids["tool_call"] = _request_id(tool_body)
            request_ids["tool_result"] = _request_id(result_body)
        print("outcome:")
        print(
            json.dumps(
                {
                    "outcome": "pass",
                    "mode": "smoke",
                    "model": args.model,
                    "tool_smoke": args.tool_smoke,
                    "request_ids": request_ids,
                    "resolver_resolutions": resolver.resolutions,
                },
                indent=2,
            )
        )
        print("resolver resolutions:")
        print(json.dumps(resolver.resolutions, indent=2))
        return 0
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        if published_ready_file is not None and published_ready_file.exists():
            published_ready_file.unlink()
        if client is not None:
            client.close()
        if plugin_process.poll() is None:
            plugin_process.terminate()
            try:
                plugin_process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                plugin_process.kill()
                plugin_process.wait(timeout=5)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as error:
        print(f"smoke setup failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
