"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 billing.py                                                       │
│  Module: cyrene_exchange.billing                                    │
│  Role: Direct HTTP adapter for the Plugins-owned usage ledger.       │
│                                                                     │
│  模块职责：直接调用 Plugins 所有的 Token 用量账本。                    │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .capabilities import ProviderUsage
from .gateway import RequestAuditTerminalStatus, RequestMetadata


class BillingUsageError(RuntimeError):
    """The billing plugin rejected a request or returned an invalid response.

    账单插件拒绝了请求,或返回了无效响应。
    """


@dataclass(frozen=True)
class TokenUsageEvent:
    """One content-free terminal usage event sent to `billing.usage.v1`.

    发送到 `billing.usage.v1` 的一条不含内容的终态用量事件。
    """

    request_id: str
    tenant_id: str
    workspace_id: str
    model: str
    request_status: RequestAuditTerminalStatus
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    usage_source: str

    def to_wire(self) -> dict[str, str | int]:
        """Serialize contract field names while preserving missing token facts.

        序列化契约字段名,同时保留缺失的 token 事实。
        """

        wire: dict[str, str | int] = {
            "requestId": self.request_id,
            "tenantId": self.tenant_id,
            "workspaceId": self.workspace_id,
            "model": self.model,
            "requestStatus": self.request_status,
            "usageSource": self.usage_source,
        }
        for key, value in (
            ("promptTokens", self.prompt_tokens),
            ("completionTokens", self.completion_tokens),
            ("totalTokens", self.total_tokens),
        ):
            if value is not None:
                wire[key] = value
        return wire


class BillingUsageClient(Protocol):
    """Consumer port for the Plugins-owned `billing.usage.v1` capability.

    供消费者使用的 `billing.usage.v1` 能力接口,该能力由 Plugins 所有。
    """

    def record_token_usage(self, event: TokenUsageEvent) -> None:
        """Idempotently record one terminal provider usage event.

        幂等地记录一条终态提供方用量事件。
        """

    def total_tokens(self, tenant_id: str) -> int:
        """Return the ledger's complete provider-backed token total.

        返回账本中完整的、由提供方报告的 token 总量。
        """


def observed_token_usage_event(
    metadata: RequestMetadata,
    status: RequestAuditTerminalStatus,
    usage: ProviderUsage | None,
) -> TokenUsageEvent | None:
    """Build an event only when at least one provider token fact exists.

    仅当至少存在一项提供方 token 事实时才构建事件。
    """

    if usage is None or not usage.to_openai_dict():
        return None
    return TokenUsageEvent(
        request_id=metadata.request_id,
        tenant_id=metadata.principal.actor_id,
        workspace_id=metadata.principal.workspace_id,
        model=metadata.model,
        request_status=status,
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
        total_tokens=usage.total_tokens,
        usage_source=usage.source,
    )


class HttpBillingUsageClient:
    """Synchronous stdlib HTTP client for a Plugins-owned billing endpoint.

    用于访问 Plugins 所有账单端点的同步标准库 HTTP 客户端。
    """

    def __init__(self, base_url: str, *, timeout_seconds: float = 2.0) -> None:
        normalized = base_url.rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username:
            raise ValueError("billing base URL must be an HTTP(S) origin without user info")
        if timeout_seconds <= 0:
            raise ValueError("billing timeout must be positive")
        self._base_url = normalized
        self._timeout_seconds = timeout_seconds

    def record_token_usage(self, event: TokenUsageEvent) -> None:
        """POST the exact event and verify the idempotent response identity."""

        response = self._request(
            "/api/v1/billing/token-usage",
            method="POST",
            body=event.to_wire(),
            accepted_statuses={200, 201},
        )
        if response.get("requestId") != event.request_id or response.get("tenantId") != event.tenant_id:
            raise BillingUsageError("billing plugin returned a mismatched usage record")

    def total_tokens(self, tenant_id: str) -> int:
        """Read a tenant summary and reject malformed or mismatched totals."""

        response = self._request(
            f"/api/v1/billing/tenants/{quote(tenant_id, safe='')}/token-summary",
            method="GET",
            body=None,
            accepted_statuses={200},
        )
        total = response.get("totalTokens")
        if response.get("tenantId") != tenant_id or isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise BillingUsageError("billing plugin returned an invalid token summary")
        return total

    def _request(
        self,
        path: str,
        *,
        method: str,
        body: dict[str, str | int] | None,
        accepted_statuses: set[int],
    ) -> dict[str, object]:
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = Request(
            f"{self._base_url}{path}",
            data=encoded,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:  # noqa: S310 - validated HTTP(S) origin | 已验证的 HTTP(S) 来源
                status = response.status
                payload = json.load(response)
        except HTTPError as exc:
            raise BillingUsageError(f"billing plugin rejected the request with HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise BillingUsageError("billing plugin is unavailable or returned invalid JSON") from exc
        if status not in accepted_statuses or not isinstance(payload, dict):
            raise BillingUsageError("billing plugin returned an unexpected response")
        return payload
