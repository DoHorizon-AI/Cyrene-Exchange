"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 quota.py                                                        │
│  Module: cyrene_exchange_product.quota                              │
│  Role: Enforce Product quota policy against Plugins-owned usage.    │
│                                                                     │
│  模块职责：依据 Plugins 用量事实执行 Product 租户配额策略。                │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from cyrene_exchange.billing import BillingUsageClient, BillingUsageError
from cyrene_exchange.gateway import (
    QuotaExceededError,
    QuotaUnavailableError,
    RequestPrincipal,
)

from cyrene_exchange_product.store import ExchangeStore


class ProductQuotaGuard:
    """Evaluate persisted Product policy without owning usage aggregation.

    中文：评估已持久化的 Product 策略，不负责用量聚合。
    """
# 中文：评估已持久化的 Product 策略，但不拥有用量汇总职责。

    def __init__(
        self,
        store: ExchangeStore,
        billing: BillingUsageClient | None,
    ) -> None:
        self._store = store
        self._billing = billing

    def __call__(self, principal: RequestPrincipal) -> None:
        """Reject exhausted or workspace-mismatched quota assignments.

        中文：拒绝已耗尽或 workspace 不匹配的 quota 分配。
        """
    # 中文：拒绝已耗尽或工作区不匹配的配额分配。

        quota = self._store.get_tenant_quota(principal.actor_id)
        if quota is None:
            return
        if quota.workspace_id != principal.workspace_id:
            raise QuotaExceededError(
                f"Tenant '{principal.actor_id}' is not admitted in this workspace."
            )
        if self._billing is None:
            raise QuotaUnavailableError("quota usage source is not configured")
        try:
            used_tokens = self._billing.total_tokens(principal.actor_id)
        except BillingUsageError as exc:
            raise QuotaUnavailableError("quota usage source is unavailable") from exc
        if used_tokens >= quota.monthly_token_quota:
            raise QuotaExceededError(
                f"Tenant '{principal.actor_id}' has exceeded its monthly token quota."
            )
