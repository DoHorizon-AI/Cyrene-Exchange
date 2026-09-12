"""Reuse the canonical Platform resolver/direct Plugin process fixtures. | 复用真实进程夹具。"""

from tests.test_platform_integration import (
    plugin_runtime as plugin_runtime,
    platform_binaries as platform_binaries,
    upstream as upstream,
)

__all__ = ["plugin_runtime", "platform_binaries", "upstream"]
