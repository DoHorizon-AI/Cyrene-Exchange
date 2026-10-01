"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 runtime_activity.py                                             │
│  Module: cyrene_exchange_product.runtime_activity                             │
│  Role: Bind Product activity to the local maintenance broker.       │
│                                                                     │
│  模块职责：将 Product 活动接入本地维护 broker。                          │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import atexit
import os
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyrene_runtime_maintenance import ActivitySourceLifecycle

_TOKEN_FILE = "/run/secrets/cyrene-runtime-activity-token"
_SOCKET_PATH = "/run/cyrene/runtime-maintenance.sock"
_SOCKET_ENV = "CYRENE_RUNTIME_MAINTENANCE_SOCKET"


class RuntimeActivityConfigurationError(RuntimeError):
    """Raised when managed activity is configured without a usable SDK.

    中文:托管活动已启用但 SDK 或配置不可用时明确失败。
    """


def start_activity_source(
    expected_source_id: str,
    load_active_tasks: Callable[[], Iterable[Mapping[str, str]]],
) -> ActivitySourceLifecycle | None:
    """Start managed tracking when an installer supplied broker settings.

    A standalone Product without broker configuration stays independent.
    Managed configuration is fail-closed and never falls back to untracked work.

    中文:仅在安装器提供 broker 配置时启用；启用后启动恢复或准入失败会拒绝启动。
    """

    token_path = os.environ.get("CYRENE_RUNTIME_ACTIVITY_SOURCE_TOKEN_FILE", _TOKEN_FILE)
    socket_path = os.environ.get(_SOCKET_ENV, _SOCKET_PATH)
    managed = (
        any(
            name in os.environ
            for name in (
                "CYRENE_RUNTIME_ACTIVITY_SOURCE_ID",
                "CYRENE_RUNTIME_ACTIVITY_SOURCE_TOKEN_FILE",
                "CYRENE_RUNTIME_ACTIVITY_CATALOG_GENERATION",
                _SOCKET_ENV,
            )
        )
        or Path(token_path).is_file()
        or Path(socket_path).exists()
    )
    if not managed:
        return None

    configured_source_id = os.environ.get("CYRENE_RUNTIME_ACTIVITY_SOURCE_ID", expected_source_id)
    if configured_source_id != expected_source_id:
        raise RuntimeActivityConfigurationError(
            f"activity source ID must be {expected_source_id!r}"
        )
    generation_text = os.environ.get("CYRENE_RUNTIME_ACTIVITY_CATALOG_GENERATION", "").strip()
    if not generation_text.isdecimal():
        raise RuntimeActivityConfigurationError(
            "CYRENE_RUNTIME_ACTIVITY_CATALOG_GENERATION must be a non-negative integer"
        )

    try:
        from cyrene_runtime_maintenance import ActivitySourceLifecycle, RuntimeMaintenanceClient
    except ImportError as error:
        raise RuntimeActivityConfigurationError(
            "managed activity requires the installed cyrene_runtime_maintenance SDK"
        ) from error

    client = RuntimeMaintenanceClient.from_source_secret(
        expected_source_id,
        token_path,
        catalog_generation=int(generation_text),
        socket_path=socket_path,
    )
    lifecycle = ActivitySourceLifecycle(client)
    lifecycle.start(load_active_tasks)
    atexit.register(lifecycle.close)
    return lifecycle
