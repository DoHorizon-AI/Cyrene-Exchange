###############################################################################
# 📄 File: src/cyrene_exchange/http.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; the reference transport emits structured SSE.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；参考传输会输出结构化 SSE。
###############################################################################
"""Reference stdlib HTTP transport for the Exchange Product Core.

Exchange Product Core 使用的标准库 HTTP 参考传输层。
"""

from __future__ import annotations

import json
import select
import socket
from collections.abc import Iterable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from typing import Any
from uuid import uuid4

from .gateway import ExchangeGateway, GatewayError


def _watch_client_disconnect(connection: socket.socket, cancel_event: Event, stop_event: Event) -> None:
    """Set ``cancel_event`` when the peer closes while Product work is running.

    Product 工作进行期间,如果对端关闭连接则设置 ``cancel_event``。
    """

    peek_flags = socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0)
    while not stop_event.wait(0.05):
        try:
            readable, _, _ = select.select([connection], [], [], 0.1)
        except (OSError, ValueError):
            cancel_event.set()
            return
        if not readable:
            continue
        try:
            probe = connection.recv(1, peek_flags)
        except (BlockingIOError, InterruptedError):
            continue
        except OSError:
            cancel_event.set()
            return
        if not probe:
            cancel_event.set()
            return


# ════════════════════════════════════════════════════════════════════════
# 🔧 FUNCTION: create_reference_server
#
#   Creates the replaceable HTTP transport and leaves server-thread ownership
#   to the caller.
#
#   创建可替换的 HTTP 传输适配器，并将 server 线程的归属留给调用方。
# ════════════════════════════════════════════════════════════════════════
def create_reference_server(
    gateway: ExchangeGateway,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Create an HTTP adapter without starting or owning the server thread.

    创建 HTTP adapter,但不启动或拥有服务线程。
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            # Mint the correlation ID before parsing or authenticating. Never
            # accept a caller-selected ID as a durable ledger primary key.
            # 在解析和认证之前创建关联 ID，不接受调用方指定的账本主键。
            request_id = f"chatcmpl-{uuid4().hex}"
            if self.path != "/v1/chat/completions":
                self._write_error(HTTPStatus.NOT_FOUND, "not_found", "endpoint not found", request_id)
                return

            length_header = self.headers.get("Content-Length")
            try:
                length = int(length_header or "0")
                if length <= 0 or length > 2 * 1024 * 1024:
                    raise ValueError("invalid content length")
                payload = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError) as exc:
                self._write_error(HTTPStatus.BAD_REQUEST, "invalid_request_error", str(exc), request_id)
                return

            cancel_event = Event()
            disconnect_stop = Event()
            disconnect_watcher = Thread(
                target=_watch_client_disconnect,
                args=(self.connection, cancel_event, disconnect_stop),
                name="cyrene-exchange-client-disconnect",
                daemon=True,
            )
            disconnect_watcher.start()
            try:
                response = gateway.handle_openai_chat(
                    dict(self.headers.items()),
                    payload,
                    cancel_event=cancel_event,
                    request_id=request_id,
                )
                if response.stream:
                    self._write_stream(response.body, cancel_event, request_id)
                else:
                    self._write_json(response.status_code, response.body, request_id)
            except GatewayError as exc:
                try:
                    self._write_json(exc.status_code, exc.to_openai_error(), request_id)
                except (BrokenPipeError, ConnectionResetError):
                    cancel_event.set()
            except (BrokenPipeError, ConnectionResetError):
                cancel_event.set()
            finally:
                disconnect_stop.set()
                disconnect_watcher.join(timeout=0.5)

        def _write_json(self, status: int, body: object, request_id: str) -> None:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Request-Id", request_id)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def _write_error(self, status: HTTPStatus, error_type: str, message: str, request_id: str) -> None:
            self._write_json(int(status), {"error": {"type": error_type, "message": message}}, request_id)

        def _write_stream(self, body: object, cancel_event: Event, request_id: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("X-Request-Id", request_id)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                if not isinstance(body, Iterable):
                    raise TypeError("stream response body must be iterable")
                for item in body:
                    encoded = item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))
                    self.wfile.write(f"data: {encoded}\n\n".encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                cancel_event.set()
            except GatewayError:
                # Headers are already committed, so a second JSON response
                # would corrupt the SSE stream. The client observes a
                # truncated stream and the request is not retried.
                # 响应标头已经提交,再发送 JSON 响应会破坏 SSE 流。客户端会观察到流被截断,且请求不会重试。
                cancel_event.set()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)
