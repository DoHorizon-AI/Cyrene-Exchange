###############################################################################
# 📄 File: src/cyrene_exchange/reference_routing.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; runtime behavior is unchanged.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；运行时行为保持不变。
###############################################################################
"""Reference-only implementation of the experimental routing capability.

This module is used by integration tests as a replaceable route planner. It
is not instantiated by ``ExchangeGateway`` and is not the production routing
implementation; the future ``cyrene.policy.model-routing`` plugin owns that
capability implementation.

实验性路由能力的参考实现，仅供参考。集成测试会将此模块用作可替换的路由规划器。它不会由 ``ExchangeGateway`` 实例化，也不是生产路由实现；未来该能力实现将由 ``cyrene.policy.model-routing`` 插件所有。
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .capabilities import RouteTarget


class StaticRoutePlanner:
    """Return configured candidates; fallback lifecycle remains Product-owned.

    返回已配置的候选项；fallback 生命周期仍归 Product 所有。
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        config = config or {}
        raw_targets = config.get("targets", ())
        if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes)):
            raise ValueError("routing targets must be a sequence")
        self._targets = tuple(
            RouteTarget(
                provider_ref=target["provider_ref"],
                route_id=target.get("route_id", ""),
                model=target.get("model"),
            )
            for target in raw_targets
            if isinstance(target, Mapping) and isinstance(target.get("provider_ref"), str)
        )

    def plan(self, request: object) -> tuple[RouteTarget, ...]:
        del request
        return self._targets
