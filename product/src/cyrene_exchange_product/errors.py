"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 errors.py                                                       │
│  Module: cyrene_exchange_product.errors                             │
│  Role: Stable Product control-plane errors.                          │
│                                                                     │
│  模块职责：稳定 Exchange 产品控制面错误。                               │
└─────────────────────────────────────────────────────────────────────┘
"""


class ExchangeProductError(RuntimeError):
    """Typed error exposed through the Product control API. | 类型化控制面错误。"""

    def __init__(
        self,
        *,
        code: str,
        title: str,
        detail: str,
        status: int,
        retryable: bool = False,
        resource_ref: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.title = title
        self.detail = detail
        self.status = status
        self.retryable = retryable
        self.resource_ref = resource_ref
