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
    """Persist Product audit facts and optionally publish derived billing usage."""

    def __init__(
        self,
        store: ExchangeStore,
        billing: BillingUsageClient | None = None,
    ) -> None:
        self._store = store
        self._billing = billing

    def on_request_started(self, metadata: RequestMetadata) -> None:
        """Persist route and trusted principal before provider invocation."""

        self._store.begin_request(metadata)

    def on_request_finished(
        self,
        metadata: RequestMetadata,
        *,
        status: RequestAuditTerminalStatus,
        usage: ProviderUsage | None,
        error_type: str | None,
    ) -> None:
        """Persist one terminal result and exact observed usage."""

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
        """Persist a rejected or pre-provider cancellation outcome."""

        self._store.record_rejection(
            request_id=request_id,
            principal=principal,
            status=status,
            error_type=error_type,
            model=model,
            stream=stream,
        )
