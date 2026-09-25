###############################################################################
# 📄 File: tests/test_platform_integration.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; runtime behavior is unchanged.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；运行时行为保持不变。
###############################################################################
from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread

import pytest

from cyrene_exchange import (
    ExchangeGateway,
    PlatformResolverAdapter,
    RequestCancelled,
    local_plugin_client,
)
from cyrene_exchange.gateway import RequestPrincipal
from cyrene_exchange.http import create_reference_server


EXCHANGE_ROOT = Path(__file__).parents[1]
PLATFORM_ROOT = Path(
    os.environ.get(
        "CYRENE_PLATFORM_WORKTREE",
        EXCHANGE_ROOT.parents[1] / "Cyrene-Platform",
    )
)
PLUGIN_ROOT = Path(
    os.environ.get(
        "CYRENE_PLUGINS_WORKTREE",
        EXCHANGE_ROOT.parents[1] / "Cyrene-Plugins-Official",
    )
)
CONNECTOR_ROOT = PLUGIN_ROOT / "plugins" / "providers" / "model-api-connector"
PROVIDER_MANIFEST = PLUGIN_ROOT / "plugins" / "providers" / "model-api-connector" / "plugin.manifest.json"
ROUTING_MANIFEST = EXCHANGE_ROOT / "tests" / "reference-routing.manifest.json"
PROVIDER_SOURCE = CONNECTOR_ROOT / "src"
MODEL_CONTRACT_ROOT = PLUGIN_ROOT / "sdk" / "python" / "cyrene_model_provider_contracts" / "src"
DIRECT_RUNTIME_ROOT = PLUGIN_ROOT / "sdk" / "python" / "cyrene_plugin_runtime" / "src"

pytestmark = pytest.mark.skipif(
    not CONNECTOR_ROOT.exists(),
    reason="Cyrene-Plugins-Official checkout not available; set CYRENE_PLUGINS_WORKTREE for cross-repo acceptance lane",
)


class UpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        with self.server.requests_lock:  # type: ignore[attr-defined]
            self.server.requests.append({"path": self.path, "payload": payload})  # type: ignore[attr-defined]
        behavior = self.path.strip("/").split("/", 1)[0]
        if behavior == "error":
            self.send_response(503)
            self.end_headers()
            return
        if behavior == "malformed":
            body = b"not-json"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if behavior == "slow":
            self.server.slow_started.set()  # type: ignore[attr-defined]
            self.server.slow_release.wait(timeout=10)  # type: ignore[attr-defined]
        if behavior == "slow-tool-stream":
            self._serve_slow_tool_stream()
            return
        if behavior == "role-only-stream":
            self._serve_role_only_stream()
            return
        if payload.get("tools"):
            if payload.get("stream"):
                events = [
                    {
                        "choices": [
                            {
                                "delta": {
                                    "role": "assistant",
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call-weather",
                                            "type": "function",
                                            "function": {
                                                "name": "weather",
                                                "arguments": '{"city":',
                                            },
                                        }
                                    ],
                                },
                                "finish_reason": None,
                            }
                        ]
                    },
                    {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "function": {"arguments": '"Paris"}'},
                                        }
                                    ]
                                },
                                "finish_reason": "tool_calls",
                            }
                        ]
                    },
                    {
                        "choices": [],
                        "usage": {
                            "prompt_tokens": 8,
                            "completion_tokens": 4,
                            "total_tokens": 12,
                        },
                    },
                ]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for event in events:
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
                return
            body = json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call-weather",
                                        "type": "function",
                                        "function": {
                                            "name": "weather",
                                            "arguments": '{"city":"Paris"}',
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 8,
                        "completion_tokens": 4,
                        "total_tokens": 12,
                    },
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if payload.get("stream"):
            events = [
                {"choices": [{"delta": {"content": "real "}, "finish_reason": None}]},
                {"choices": [{"delta": {"content": "path"}, "finish_reason": "stop"}]},
            ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for event in events:
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "real path"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_slow_tool_stream(self) -> None:
        """Emit one tool fragment, then wait for cancellation or release.

        中文：发出一个工具调用片段，然后等待取消或释放。"""

        first = {
            "choices": [
                {
                    "delta": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call-cancel-weather",
                                "type": "function",
                                "function": {"name": "weather", "arguments": '{"city":'},
                            }
                        ],
                    },
                    "finish_reason": None,
                }
            ]
        }
        second = {
            "choices": [
                {
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"Paris"}'}}]},
                    "finish_reason": "tool_calls",
                }
            ]
        }
        usage = {
            "choices": [],
            "usage": {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16},
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        try:
            self._write_sse(first)
            self.server.slow_tool_first_chunk.set()  # type: ignore[attr-defined]
            while not self.server.slow_tool_release.wait(0.05):  # type: ignore[attr-defined]
                if self._peer_disconnected():
                    self.server.slow_tool_disconnected.set()  # type: ignore[attr-defined]
                    return
            self._write_sse(second)
            self._write_sse(usage)
            self.server.slow_tool_usage_sent.set()  # type: ignore[attr-defined]
            self._write_sse("[DONE]")
            self.server.slow_tool_terminal_sent.set()  # type: ignore[attr-defined]
        except (BrokenPipeError, ConnectionResetError):
            self.server.slow_tool_disconnected.set()  # type: ignore[attr-defined]

    def _serve_role_only_stream(self) -> None:
        """Emit an empty-content assistant preamble before real text.

        中文：在实际文本之前发出一个空内容的助手前导消息。"""

        events = [
            {
                "choices": [
                    {
                        "delta": {"role": "assistant", "content": ""},
                        "finish_reason": None,
                    }
                ]
            },
            {"choices": [{"delta": {"content": "real "}, "finish_reason": None}]},
            {"choices": [{"delta": {"content": "path"}, "finish_reason": "stop"}]},
            {
                "choices": [],
                "usage": {
                    "prompt_tokens": 3,
                    "completion_tokens": 2,
                    "total_tokens": 5,
                },
            },
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in events:
            self._write_sse(event)
        self._write_sse("[DONE]")

    def _write_sse(self, value: object) -> None:
        encoded = value if isinstance(value, str) else json.dumps(value)
        self.wfile.write(f"data: {encoded}\n\n".encode())
        self.wfile.flush()

    def _peer_disconnected(self) -> bool:
        """Probe the upstream connector socket without consuming request data.

        中文：探测上游连接器套接字，不消费请求数据。"""

        try:
            readable, _, _ = select.select([self.connection], [], [], 0.05)
            if not readable:
                return False
            flags = socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0)
            return not self.connection.recv(1, flags)
        except (BlockingIOError, InterruptedError):
            return False
        except OSError:
            return True

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture(scope="session")
def platform_binaries():
    """Build only the generic Platform capability resolver.

    中文：只构建通用 Platform 能力解析器。"""

    package = "cy-platform-api"
    binary = "cyrene-capability-resolver"
    result = subprocess.run(
        ["cargo", "build", "--locked", "-p", package, "--bin", binary],
        cwd=PLATFORM_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"failed to build actual Platform binary {binary}:\n{result.stdout}\n{result.stderr}")

    target_root = Path(os.environ.get("CARGO_TARGET_DIR", PLATFORM_ROOT / "target"))
    if not target_root.is_absolute():
        target_root = PLATFORM_ROOT / target_root
    suffix = ".exe" if os.name == "nt" else ""
    executable = target_root / "debug" / f"{binary}{suffix}"
    if not executable.exists():
        pytest.fail(f"Platform binary was not produced ({binary}): {executable}")
    return {binary: executable}


@pytest.fixture(scope="session")
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    server.requests = []
    server.requests_lock = Lock()
    server.slow_started = Event()
    server.slow_release = Event()
    server.slow_tool_first_chunk = Event()
    server.slow_tool_release = Event()
    server.slow_tool_disconnected = Event()
    server.slow_tool_usage_sent = Event()
    server.slow_tool_terminal_sent = Event()
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.slow_release.set()
    server.slow_tool_release.set()
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture(scope="session")
def plugin_runtime(upstream, tmp_path_factory):
    """Start one independent Plugins-owned endpoint per Product provider ref.

    中文：为每个 Product provider ref 启动一个独立的 Plugins 所有端点。"""

    runtime_dir = tmp_path_factory.mktemp("exchange-direct-plugins")
    upstream_root = f"http://127.0.0.1:{upstream.server_port}"
    behavior_by_provider = {
        "model-provider-local": "success",
        "model-provider-stream": "success",
        "model-provider-failure-error": "error",
        "model-provider-failure-malformed": "malformed",
        "model-provider-primary": "error",
        "model-provider-secondary": "success",
        "model-provider-cancelled": "slow",
        "model-provider-cancelled-tool-stream": "slow-tool-stream",
        "model-provider-role-only-stream": "role-only-stream",
    }
    clients = {}
    processes = []
    logs = []
    python_path = os.pathsep.join((str(MODEL_CONTRACT_ROOT), str(DIRECT_RUNTIME_ROOT), str(PROVIDER_SOURCE)))
    try:
        for provider_ref, behavior in behavior_by_provider.items():
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPATH": python_path,
                    "CYRENE_CHAT_BASE_URL": f"{upstream_root}/{behavior}",
                    "CYRENE_CHAT_API_KEY": "conformance-only",
                    "CYRENE_CHAT_TIMEOUT": "8",
                    "CYRENE_EMBEDDINGS_SUPPORTED": "false",
                }
            )
            log_path = runtime_dir / f"{provider_ref}.log"
            log_file = log_path.open("w+", encoding="utf-8")
            process = subprocess.Popen(
                [
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
                ],
                cwd=CONNECTOR_ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=log_file,
            )
            processes.append(process)
            logs.append(log_file)
            deadline = time.monotonic() + 10
            ready_line = ""
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log_file.flush()
                    log_file.seek(0)
                    pytest.fail(
                        f"direct Plugin {provider_ref} exited before readiness "
                        f"({process.returncode}):\n{log_file.read()}"
                    )
                readable, _, _ = select.select([process.stdout], [], [], 0.05)
                if readable:
                    ready_line = process.stdout.readline()
                    break
            if not ready_line:
                process.terminate()
                process.wait(timeout=5)
                log_file.flush()
                log_file.seek(0)
                pytest.fail(f"direct Plugin {provider_ref} did not publish readiness:\n{log_file.read()}")
            ready = json.loads(ready_line)
            clients[provider_ref] = local_plugin_client(ready["connection_ref"])
        yield {"clients": clients, "processes": processes}
    finally:
        for client in clients.values():
            client.close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log_file in logs:
            log_file.close()


def upstream_requests(server) -> list[dict]:
    with server.requests_lock:
        return list(server.requests)


def make_gateway(platform_binaries, plugin_runtime, targets):
    resolver = PlatformResolverAdapter(
        [str(platform_binaries["cyrene-capability-resolver"])],
        [ROUTING_MANIFEST, PROVIDER_MANIFEST],
        resolver_cwd=PLATFORM_ROOT,
        plugin_configs={
            "cyrene.exchange.reference-routing": {"targets": targets},
        },
        plugin_clients=plugin_runtime["clients"],
        provider_deadline_seconds=5,
    )
    gateway = ExchangeGateway(
        resolver,
        principal_resolver=lambda token: (
            RequestPrincipal("actor-test", "workspace-test", "credential-test") if token == "exchange-test" else None
        ),
    )
    return gateway, resolver


def test_routing_fixture_is_explicitly_reference_only():
    manifest = json.loads(ROUTING_MANIFEST.read_text(encoding="utf-8"))

    assert manifest["status"] == "reference-only"


def post(server: ThreadingHTTPServer, payload: dict) -> tuple[int, str, str]:
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    client.request(
        "POST",
        "/v1/chat/completions",
        body=json.dumps(payload),
        headers={
            "Authorization": "Bearer exchange-test",
            "Content-Type": "application/json",
        },
    )
    response = client.getresponse()
    content_type = response.getheader("Content-Type", "")
    body = response.read().decode()
    client.close()
    return response.status, content_type, body


def test_real_platform_resolver_and_direct_plugin_non_stream(platform_binaries, plugin_runtime, upstream):
    provider_ref = "model-provider-local"
    request_count = len(upstream_requests(upstream))
    gateway, resolver = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref, "route_id": "local"}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = post(
            server,
            {"model": "local-model", "messages": [{"role": "user", "content": "hello"}]},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200, body
    assert json.loads(body)["choices"][0]["message"]["content"] == "real path"
    assert resolver.resolutions == [
        {
            "capability": "model.routing.v1",
            "plugin": "cyrene.exchange.reference-routing",
            "reference": None,
            "execution_mode": "INLINE",
        },
        {
            "capability": "model.provider.v1",
            "plugin": "cyrene.providers.model-api-connector",
            "reference": provider_ref,
            "execution_mode": "SERVICE",
        },
    ]
    requests = upstream_requests(upstream)
    assert requests[request_count]["path"] == "/success/v1/chat/completions"
    assert requests[request_count]["payload"]["messages"][0]["content"] == "hello"


def test_real_canonical_provider_forwards_tool_call_and_usage(platform_binaries, plugin_runtime, upstream):
    """Exercise v2 tools through resolver, direct Plugin endpoint, and HTTP.

    中文：通过 resolver、直连 Plugin 端点和 HTTP 测试 v2 工具调用。"""

    request_count = len(upstream_requests(upstream))
    gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": "model-provider-local", "route_id": "local"}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = post(
            server,
            {
                "model": "local-model",
                "messages": [{"role": "user", "content": "use weather"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "weather",
                            "parameters": {"type": "object"},
                        },
                    }
                ],
                "tool_choice": "auto",
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200, body
    response = json.loads(body)
    assert response["choices"][0]["finish_reason"] == "tool_calls"
    assert response["choices"][0]["message"] == {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call-weather",
                "type": "function",
                "function": {"name": "weather", "arguments": '{"city":"Paris"}'},
            }
        ],
    }
    assert response["usage"] == {
        "prompt_tokens": 8,
        "completion_tokens": 4,
        "total_tokens": 12,
    }
    requests = upstream_requests(upstream)
    assert len(requests) == request_count + 1
    assert requests[-1]["payload"]["tools"][0]["function"]["name"] == "weather"


def test_real_canonical_provider_forwards_streamed_tool_fragments_and_usage(
    platform_binaries, plugin_runtime, upstream
):
    gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": "model-provider-stream", "route_id": "stream"}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, content_type, body = post(
            server,
            {
                "model": "local-model",
                "messages": [{"role": "user", "content": "use weather"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "weather",
                            "parameters": {"type": "object"},
                        },
                    }
                ],
                "tool_choice": "auto",
                "stream": True,
                "stream_options": {"include_usage": True},
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200, body
    assert content_type.startswith("text/event-stream")
    assert '"id":"call-weather"' in body
    assert '"arguments":"{\\"city\\":"' in body
    assert '"arguments":"\\"Paris\\"}"' in body
    assert '"finish_reason":"tool_calls"' in body
    assert '"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}' in body
    assert body.rstrip().endswith("data: [DONE]")


def test_real_plugin_sse_stream(platform_binaries, plugin_runtime):
    provider_ref = "model-provider-stream"
    gateway, resolver = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, content_type, body = post(
            server,
            {
                "model": "local-model",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200, body
    assert content_type.startswith("text/event-stream")
    assert '"content":"real "' in body
    assert '"content":"path"' in body
    assert '"finish_reason":"stop"' in body
    assert "data: [DONE]" in body
    assert resolver.resolutions[-1]["plugin"] == "cyrene.providers.model-api-connector"


def test_real_canonical_provider_preserves_role_only_first_stream_chunk(platform_binaries, plugin_runtime, upstream):
    """Keep a role-only empty-content preamble and all following stream facts.

    中文：保留仅包含角色的空内容前导消息及其后的所有流式事实。"""

    provider_ref = "model-provider-role-only-stream"
    request_count = len(upstream_requests(upstream))
    gateway, resolver = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref, "route_id": "role-only-stream"}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, content_type, body = post(
            server,
            {
                "model": "local-model",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
                "stream_options": {"include_usage": True},
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200, body
    assert content_type.startswith("text/event-stream")
    frames = [line.removeprefix("data: ") for line in body.splitlines() if line.startswith("data: ")]
    assert frames[-1] == "[DONE]"
    events = [json.loads(frame) for frame in frames[:-1]]
    assert len(events) == 4
    assert events[0]["choices"] == [
        {
            "index": 0,
            "delta": {"role": "assistant"},
            "finish_reason": None,
        }
    ]
    assert events[1]["choices"][0]["delta"] == {"content": "real "}
    assert events[2]["choices"] == [
        {
            "index": 0,
            "delta": {"content": "path"},
            "finish_reason": "stop",
        }
    ]
    assert events[3]["choices"] == []
    assert events[3]["usage"] == {
        "prompt_tokens": 3,
        "completion_tokens": 2,
        "total_tokens": 5,
    }
    requests = upstream_requests(upstream)
    assert len(requests) == request_count + 1
    assert requests[-1]["path"] == "/role-only-stream/v1/chat/completions"
    assert resolver.resolutions[-1] == {
        "capability": "model.provider.v1",
        "plugin": "cyrene.providers.model-api-connector",
        "reference": provider_ref,
        "execution_mode": "SERVICE",
    }


@pytest.mark.parametrize("behavior", ["error", "malformed"])
def test_real_plugin_upstream_failures_map_to_provider_error(platform_binaries, plugin_runtime, behavior):
    provider_ref = f"model-provider-failure-{behavior}"
    gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = post(
            server,
            {"model": "local-model", "messages": [{"role": "user", "content": "hello"}]},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 502
    assert json.loads(body)["error"]["type"] == "provider_error"


def test_real_plugin_pre_first_token_failure_uses_product_fallback(platform_binaries, plugin_runtime, upstream):
    primary_ref = "model-provider-primary"
    secondary_ref = "model-provider-secondary"
    request_count = len(upstream_requests(upstream))
    gateway, resolver = make_gateway(
        platform_binaries,
        plugin_runtime,
        [
            {"provider_ref": primary_ref, "route_id": "primary"},
            {"provider_ref": secondary_ref, "route_id": "secondary"},
        ],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = post(
            server,
            {
                "model": "local-model",
                "messages": [{"role": "user", "content": "fallback"}],
                "stream": True,
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200, body
    assert '"content":"real "' in body
    paths = [request["path"] for request in upstream_requests(upstream)[request_count:]]
    assert paths == ["/error/v1/chat/completions", "/success/v1/chat/completions"]
    assert [entry["reference"] for entry in resolver.resolutions] == [
        None,
        primary_ref,
        secondary_ref,
    ]


def test_real_provider_cancellation_is_cooperative(platform_binaries, plugin_runtime, upstream):
    provider_ref = "model-provider-cancelled"
    gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref}],
    )
    cancelled = Event()
    upstream.slow_started.clear()
    upstream.slow_release.clear()
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            gateway.handle_openai_chat,
            {"Authorization": "Bearer exchange-test"},
            {"model": "local-model", "messages": [{"role": "user", "content": "cancel"}]},
            cancel_event=cancelled,
        )
        try:
            assert upstream.slow_started.wait(timeout=3), "real provider request did not reach the slow upstream"
            cancelled.set()
            with pytest.raises(RequestCancelled):
                future.result(timeout=3)
        finally:
            upstream.slow_release.set()
    assert time.monotonic() - started < 4

    next_gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": "model-provider-local"}],
    )
    response = next_gateway.handle_openai_chat(
        {"Authorization": "Bearer exchange-test"},
        {"model": "local-model", "messages": [{"role": "user", "content": "after cancel"}]},
    )
    assert response.status_code == 200


def test_real_canonical_sse_tool_disconnect_cancels_upstream_without_retry(platform_binaries, plugin_runtime, upstream):
    """Verify an HTTP disconnect cancels a real tool SSE before terminal usage.

    中文：验证 HTTP 断开会在最终用量事件之前取消真实工具 SSE。"""

    provider_ref = "model-provider-cancelled-tool-stream"
    request_count = len(upstream_requests(upstream))
    gateway, resolver = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref, "route_id": "cancelled-tool-stream"}],
    )
    upstream.slow_tool_first_chunk.clear()
    upstream.slow_tool_release.clear()
    upstream.slow_tool_disconnected.clear()
    upstream.slow_tool_usage_sent.clear()
    upstream.slow_tool_terminal_sent.clear()
    client: HTTPConnection | None = None
    server = create_reference_server(gateway)
    server_errors: list[str] = []

    def record_server_error(_request: object, _client_address: object) -> None:
        error = sys.exc_info()[1]
        server_errors.append(type(error).__name__ if error is not None else "unknown")

    server.handle_error = record_server_error  # type: ignore[method-assign]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        payload = {
            "model": "local-model",
            "messages": [{"role": "user", "content": "use weather, then wait"}],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "weather", "parameters": {"type": "object"}},
                }
            ],
            "tool_choice": "auto",
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        client.connect()
        client.putrequest("POST", "/v1/chat/completions")
        client.putheader("Authorization", "Bearer exchange-test")
        client.putheader("Content-Type", "application/json")
        body = json.dumps(payload).encode()
        client.putheader("Content-Length", str(len(body)))
        client.endheaders()
        client.send(body)
        transport_socket = client.sock

        assert upstream.slow_tool_first_chunk.wait(timeout=3), "real provider did not emit the first tool fragment"
        # The direct Plugin invocation is still active while the provider is
        # consuming this SSE. Closing the client must reach the HTTP watcher,
        # direct gRPC cancellation and finally the upstream socket.
        # 中文：提供方正在消费此 SSE 时，直连 Plugin 调用仍处于活动状态。关闭客户端必须依次触发 HTTP watcher、直连 gRPC 取消，最终关闭上游套接字。
        response = client.getresponse()
        assert response.status == 200
        first_line = response.fp.readline() if response.fp is not None else b""
        assert b'"id":"call-cancel-weather"' in first_line
        assert b"data: [DONE]" not in first_line
        assert transport_socket is not None
        transport_socket.shutdown(socket.SHUT_RDWR)
        response.close()
        client.close()
        assert upstream.slow_tool_disconnected.wait(timeout=3), "client disconnect did not cancel upstream SSE"
        assert not upstream.slow_tool_usage_sent.is_set(), "cancelled stream must not emit provider usage"
        assert not upstream.slow_tool_terminal_sent.is_set(), "cancelled stream must not emit [DONE]"
    finally:
        if client is not None:
            client.close()
        upstream.slow_tool_release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    cancelled_requests = upstream_requests(upstream)[request_count:]
    assert len(cancelled_requests) == 1, "a cancelled stream must not be retried"
    assert cancelled_requests[0]["path"] == "/slow-tool-stream/v1/chat/completions"
    assert [entry["reference"] for entry in resolver.resolutions] == [None, provider_ref]
    assert server_errors == [], f"request handler leaked an exception: {server_errors}"

    # A subsequent direct Plugin invocation proves the cancelled worker was cleaned
    # up enough for the service to activate and complete another provider.
    # 中文：后续的直连 Plugin 调用可证明取消后的工作进程已清理到足以重新激活服务，并完成另一项提供方请求。
    next_gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": "model-provider-local"}],
    )
    response = next_gateway.handle_openai_chat(
        {"Authorization": "Bearer exchange-test"},
        {"model": "local-model", "messages": [{"role": "user", "content": "after tool cancel"}]},
    )
    assert response.status_code == 200


def test_real_canonical_sse_exposes_first_tool_fragment_before_upstream_terminal(
    platform_binaries, plugin_runtime, upstream
):
    """Prove the first typed chunk reaches HTTP while the provider is blocked.

    中文：证明提供方被阻塞期间，第一个有类型数据块仍能到达 HTTP。"""

    provider_ref = "model-provider-cancelled-tool-stream"
    gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": provider_ref, "route_id": "live-tool-stream"}],
    )
    upstream.slow_tool_first_chunk.clear()
    upstream.slow_tool_release.clear()
    upstream.slow_tool_usage_sent.clear()
    upstream.slow_tool_terminal_sent.clear()
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client: HTTPConnection | None = None
    try:
        client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        payload = {
            "model": "local-model",
            "messages": [{"role": "user", "content": "use weather, then wait"}],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "weather", "parameters": {"type": "object"}},
                }
            ],
            "tool_choice": "auto",
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        client.connect()
        client.putrequest("POST", "/v1/chat/completions")
        client.putheader("Authorization", "Bearer exchange-test")
        client.putheader("Content-Type", "application/json")
        body = json.dumps(payload).encode()
        client.putheader("Content-Length", str(len(body)))
        client.endheaders()
        client.send(body)

        assert upstream.slow_tool_first_chunk.wait(timeout=3), "real provider did not emit the first tool fragment"
        response = client.getresponse()
        assert response.status == 200
        first_line = response.fp.readline() if response.fp is not None else b""
        assert b'"id":"call-cancel-weather"' in first_line
        assert not upstream.slow_tool_usage_sent.is_set()
        assert not upstream.slow_tool_terminal_sent.is_set()

        upstream.slow_tool_release.set()
        remaining = response.read().decode("utf-8")
        assert '"arguments":"\\"Paris\\"}"' in remaining
        assert '"usage":{"prompt_tokens":11,"completion_tokens":5,"total_tokens":16}' in remaining
        assert remaining.rstrip().endswith("data: [DONE]")
        assert upstream.slow_tool_usage_sent.wait(timeout=3)
        assert upstream.slow_tool_terminal_sent.wait(timeout=3)
    finally:
        if client is not None:
            client.close()
        upstream.slow_tool_release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unknown_configured_binding_fails_closed(platform_binaries, plugin_runtime):
    gateway, _ = make_gateway(
        platform_binaries,
        plugin_runtime,
        [{"provider_ref": "model-provider-missing"}],
    )
    server = create_reference_server(gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = post(
            server,
            {"model": "local-model", "messages": [{"role": "user", "content": "missing"}]},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 502
    assert "no direct Plugin client is configured" in json.loads(body)["error"]["message"]


def test_exchange_sources_have_no_concrete_plugin_or_legacy_control_plane_imports():
    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in (EXCHANGE_ROOT / "src" / "cyrene_exchange").rglob("*.py")
    )

    assert "import model_api_connector" not in sources
    assert "from model_api_connector" not in sources
    assert "cyrene_core_compat" not in sources
    assert "legacy.cyrene" not in sources
    assert "cyrene_capability_client" not in sources
    assert "capability_execution" not in sources
    assert "cyrene-capability-client" not in (EXCHANGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert str(PROVIDER_SOURCE) not in sys.path
