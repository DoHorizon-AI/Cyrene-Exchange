"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 audit.py                                                        │
│  Module: cyrene_exchange_product.audit                              │
│  Role: Product-owned request usage and audit observer.               │
│                                                                     │
│  模块职责：记录请求生命周期与 provider usage 事实，不保存内容。           │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from cyrene_exchange.billing import BillingUsageClient, observed_token_usage_event
from cyrene_exchange.capabilities import ProviderUsage
from cyrene_exchange.gateway import (
    RequestAuditTerminalStatus,
    RequestMetadata,
    RequestPrincipal,
    RequestRejectionStatus,
)

from cyrene_exchange_product.store import ExchangeStore


class RequestAuditRecorder:
    """Persist Product audit facts and optionally publish derived billing usage.

    中文:持久化 Product 审计事实,并可选择发布派生的计费用量。
    """

    # 中文:持久化 Product 审计事实,并可选择发布派生的计费用量。

    def __init__(
        self,
        store: ExchangeStore,
        billing: BillingUsageClient | None = None,
    ) -> None:
        self._store = store
        self._billing = billing

    def on_request_started(self, metadata: RequestMetadata) -> None:
        """Persist route and trusted principal before provider invocation.

        中文:在调用 Provider 前持久化 route 和可信主体。
        """
        # 中文:在调用提供方之前持久化路由和可信主体。

        self._store.begin_request(metadata)

    def on_request_finished(
        self,
        metadata: RequestMetadata,
        *,
        status: RequestAuditTerminalStatus,
        usage: ProviderUsage | None,
        error_type: str | None,
    ) -> None:
        """Persist one terminal result and exact observed usage.

        中文:持久化一条终态结果及精确观测到的用量。
        """
        # 中文:持久化一条终态结果和实际观测到的准确用量。

        self._store.finish_request(
            metadata,
            status=status,
            usage=usage,
            error_type=error_type,
        )
        event = observed_token_usage_event(metadata, status, usage)
        if self._billing is not None and event is not None:
            self._billing.record_token_usage(event)

    def on_request_rejected(
        self,
        *,
        request_id: str,
        principal: RequestPrincipal | None,
        status: RequestRejectionStatus,
        error_type: str,
        model: str | None,
        stream: bool | None,
    ) -> None:
        """Persist a rejected or pre-provider cancellation outcome.

        中文:持久化拒绝请求或 Provider 调用前取消的结果。
        """
        # 中文:持久化被拒绝的取消结果或提供方调用前的取消结果。

        self._store.record_rejection(
            request_id=request_id,
            principal=principal,
            status=status,
            error_type=error_type,
            model=model,
            stream=stream,
        )
