"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_billing_client.py                                           │
│  Module: tests.test_billing_client                                  │
│  Role: Real HTTP-wire checks for the billing plugin adapter.         │
│                                                                     │
│  模块职责：验证计费插件适配器的真实 HTTP 载荷与响应。                  │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from cyrene_exchange.billing import HttpBillingUsageClient, TokenUsageEvent


class BillingHandler(BaseHTTPRequestHandler):
    """Minimal contract peer that captures the adapter's wire payload.

    中文：能够捕获 adapter wire payload 的最小契约 peer。
    """
# 中文：捕获适配器线协议负载的最小契约对端。

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        self.server.received.append(payload)  # type: ignore[attr-defined]
        body = {
            **payload,
            "id": "67c46cba-cdd2-49af-a12a-ea1ee58781d5",
            "usageState": "PARTIAL",
            "costCents": None,
            "recordedAt": "2026-09-09T00:00:00Z",
        }
        self._write(201, body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.server.requested_paths.append(self.path)  # type: ignore[attr-defined]
        self._write(
            200,
            {
                "tenantId": "tenant/corp-a",
                "promptTokens": 8,
                "completionTokens": 5,
                "totalTokens": 13,
                "recordCount": 1,
                "finalRecordCount": 1,
                "partialRecordCount": 0,
                "costCents": 0,
                "hasIncompleteUsage": False,
            },
        )

    def _write(self, status: int, body: object) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


def test_http_billing_client_preserves_partial_usage_and_encodes_tenant_path() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), BillingHandler)
    server.received = []  # type: ignore[attr-defined]
    server.requested_paths = []  # type: ignore[attr-defined]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpBillingUsageClient(f"http://127.0.0.1:{server.server_port}")
        client.record_token_usage(
            TokenUsageEvent(
                request_id="chatcmpl-partial",
                tenant_id="tenant/corp-a",
                workspace_id="workspace-main",
                model="model-a",
                request_status="cancelled",
                prompt_tokens=8,
                completion_tokens=None,
                total_tokens=None,
                usage_source="stream-provider",
            )
        )

        assert server.received == [  # type: ignore[attr-defined]
            {
                "requestId": "chatcmpl-partial",
                "tenantId": "tenant/corp-a",
                "workspaceId": "workspace-main",
                "model": "model-a",
                "requestStatus": "cancelled",
                "usageSource": "stream-provider",
                "promptTokens": 8,
            }
        ]
        assert client.total_tokens("tenant/corp-a") == 13
        assert server.requested_paths == [  # type: ignore[attr-defined]
            "/api/v1/billing/tenants/tenant%2Fcorp-a/token-summary"
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
