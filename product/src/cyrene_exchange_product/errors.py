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


class ErrorMapping:
    """Canonical error metadata mapping conforming to Cyrene specification."""

    def __init__(
        self,
        canonical_code: str,
        cause_kind: str,
        recovery_action: str,
        status: int,
    ) -> None:
        self.canonical_code = canonical_code
        self.cause_kind = cause_kind
        self.recovery_action = recovery_action
        self.status = status

    def __repr__(self) -> str:
        return f"ErrorMapping({self.canonical_code!r}, {self.cause_kind!r}, {self.recovery_action!r}, {self.status})"


EXCHANGE_ERROR_MAPPINGS: dict[str, ErrorMapping] = {
    "EXCHANGE_CONTROL_PERMISSION_DENIED": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.PERMISSION_DENIED",
        cause_kind="authorization",
        recovery_action="fix_configuration",
        status=403,
    ),
    "EXCHANGE_BINDING_PERMISSION_DENIED": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.BINDING_DENIED",
        cause_kind="authorization",
        recovery_action="fix_configuration",
        status=403,
    ),
    "EXCHANGE_TARGET_UNREACHABLE": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.TARGET_UNREACHABLE",
        cause_kind="upstream_unreachable",
        recovery_action="query_state_first",
        status=502,
    ),
    "EXCHANGE_REQUEST_INVALID": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.REQUEST_INVALID",
        cause_kind="validation",
        recovery_action="fix_configuration",
        status=422,
    ),
    "EXCHANGE_API_KEY_INVALID": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.API_KEY_INVALID",
        cause_kind="authentication",
        recovery_action="user_action_required",
        status=401,
    ),
    "EXCHANGE_QUOTA_EXCEEDED": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.QUOTA_EXCEEDED",
        cause_kind="quota",
        recovery_action="user_action_required",
        status=429,
    ),
    "EXCHANGE_INTERNAL_ERROR": ErrorMapping(
        canonical_code="PRODUCT.EXCHANGE.INTERNAL_ERROR",
        cause_kind="internal",
        recovery_action="safely_retry",
        status=500,
    ),
}


def map_exchange_error(code: str) -> ErrorMapping:
    """Map an Exchange Product error code onto canonical Platform/Product error fields."""
    return EXCHANGE_ERROR_MAPPINGS.get(
        code,
        ErrorMapping(
            canonical_code=f"PRODUCT.EXCHANGE.{code.upper()}",
            cause_kind="unknown",
            recovery_action="none",
            status=500,
        ),
    )

