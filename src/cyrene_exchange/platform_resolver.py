###############################################################################
# 📄 File: src/cyrene_exchange/platform_resolver.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; runtime behavior is unchanged.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；运行时行为保持不变。
###############################################################################
"""Adapter from Exchange's Product seam to Platform's generic resolver.

The Platform resolver owns manifest normalization and capability selection. It
intentionally does not import, instantiate, or proxy plugin business APIs.
This Product adapter binds INLINE reference implementations locally and pairs
WORKER or SERVICE results with Product-composed direct Plugin clients.

从 Exchange 的 Product 接口接入 Platform 通用 resolver 的 adapter。Platform resolver 负责 manifest 规范化和能力选择；它不会导入、实例化或代理插件业务 API。此 Product adapter 会在本地绑定 INLINE 参考实现，并将 WORKER 或 SERVICE 结果与 Product 组合的 Direct Plugin 客户端配对。
"""

from __future__ import annotations

import importlib
import inspect
import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .capabilities import MODEL_PROVIDER_CAPABILITY
from .direct_plugin import (
    DirectPluginInvoker,
    DirectPluginModelProvider,
)


class PlatformResolverError(RuntimeError):
    """The Platform resolver or generic implementation binding failed.

    Platform resolver 或通用实现绑定失败。
    """


EntryPointLoader = Callable[[str, Mapping[str, Any]], object]

_REFERENCE_EXECUTION_MODES = ("INLINE", "WORKER", "SERVICE")
_DIRECT_EXECUTION_MODES = frozenset({"WORKER", "SERVICE"})


def load_entrypoint(entrypoint: str, config: Mapping[str, Any]) -> object:
    """Load a manifest entrypoint without naming a concrete plugin in Exchange.

    加载 manifest entrypoint，同时不在 Exchange 中指定具体插件。
    """

    module_name, separator, attribute = entrypoint.partition(":")
    if not separator or not module_name or not attribute:
        raise PlatformResolverError(f"invalid plugin entrypoint '{entrypoint}'; expected module:attribute")
    try:
        target: Any = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise PlatformResolverError(f"cannot load plugin entrypoint '{entrypoint}'") from exc
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return target(config)
    try:
        signature.bind(config)
    except TypeError:
        try:
            signature.bind()
        except TypeError as exc:
            raise PlatformResolverError(f"entrypoint '{entrypoint}' cannot accept its configuration") from exc
        return target()
    return target(config)


class PlatformResolverAdapter:
    """Use the actual Platform registry/resolver and bind its result generically.

    使用真实的 Platform registry/resolver，并以通用方式绑定其结果。
    """

    def __init__(
        self,
        resolver_command: Sequence[str],
        manifest_paths: Sequence[str | Path],
        *,
        resolver_cwd: str | Path | None = None,
        plugin_configs: Mapping[str, Mapping[str, Any]] | None = None,
        entrypoint_loader: EntryPointLoader = load_entrypoint,
        plugin_clients: Mapping[str, DirectPluginInvoker] | None = None,
        provider_deadline_seconds: float = 30.0,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not resolver_command:
            raise ValueError("resolver_command must not be empty")
        if not manifest_paths:
            raise ValueError("manifest_paths must not be empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if provider_deadline_seconds <= 0:
            raise ValueError("provider_deadline_seconds must be positive")
        self._resolver_command = tuple(resolver_command)
        self._manifest_paths = tuple(Path(path) for path in manifest_paths)
        self._resolver_cwd = Path(resolver_cwd) if resolver_cwd else None
        self._plugin_configs = dict(plugin_configs or {})
        self._entrypoint_loader = entrypoint_loader
        self._plugin_clients = dict(plugin_clients or {})
        self._provider_deadline_seconds = provider_deadline_seconds
        self._timeout_seconds = timeout_seconds
        self.resolutions: list[dict[str, str | None]] = []

    # ════════════════════════════════════════════════════════════════════════
    # 🔧 FUNCTION: PlatformResolverAdapter.resolve
    #
    #   Delegates capability selection to the Platform resolver and binds the
    #   manifest-declared entry point without importing a concrete plugin here.
    #
    #   将能力选择委托给 Platform resolver，并绑定 manifest 声明的入口，不在此处导入具体插件。
    # ════════════════════════════════════════════════════════════════════════
    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        manifests = [self._read_manifest(path) for path in self._manifest_paths]

        request = {
            "manifests": manifests,
            "requirements": [
                {
                    "capability": capability_id,
                    "interface_version": "1",
                    # The reference adapter can bind any canonical manifest
                    # entrypoint; Platform remains authoritative for selecting
                    # the execution mode declared by that manifest.
                    # 参考 adapter 可以绑定任意规范 manifest entrypoint；manifest 声明的执行模式仍由 Platform 负责选择。
                    "execution_modes": list(_REFERENCE_EXECUTION_MODES),
                }
            ],
        }
        try:
            completed = subprocess.run(
                self._resolver_command,
                cwd=self._resolver_cwd,
                input=json.dumps(request),
                text=True,
                capture_output=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PlatformResolverError("Platform resolver timed out") from exc
        except OSError as exc:
            raise PlatformResolverError("Platform resolver could not be started") from exc
        if completed.returncode != 0:
            detail = completed.stdout.strip() or completed.stderr.strip()
            raise PlatformResolverError(f"Platform resolver exited with {completed.returncode}: {detail}")
        try:
            output = json.loads(completed.stdout)
            resolved = output["resolutions"][0]
            plugin = resolved["plugin"]
            plugin_version = resolved["plugin_version"]
            plugin_id = plugin["id"]
            selected_version = plugin_version["version"]
            execution_mode = resolved["execution_mode"]
            if not all(isinstance(value, str) and value for value in (plugin_id, selected_version, execution_mode)):
                raise TypeError("resolution identity fields must be non-empty strings")
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise PlatformResolverError("Platform resolver returned invalid JSON") from exc

        manifest = next(
            (
                candidate
                for candidate in manifests
                if self._plugin_id(candidate) == plugin_id and self._plugin_version(candidate) == selected_version
            ),
            None,
        )
        if manifest is None:
            raise PlatformResolverError(f"resolver selected unknown plugin release '{plugin_id}@{selected_version}'")
        self.resolutions.append(
            {
                "capability": capability_id,
                "plugin": plugin_id,
                "reference": implementation_ref,
                "execution_mode": execution_mode,
            }
        )

        if execution_mode in _DIRECT_EXECUTION_MODES:
            if capability_id != MODEL_PROVIDER_CAPABILITY:
                raise PlatformResolverError(f"no Product direct adapter is registered for capability '{capability_id}'")
            if implementation_ref is None:
                raise PlatformResolverError("direct Plugin resolution requires a stable Product provider reference")
            client = self._plugin_clients.get(implementation_ref)
            if client is None:
                raise PlatformResolverError(
                    f"no direct Plugin client is configured for Product provider '{implementation_ref}'"
                )
            return DirectPluginModelProvider(
                client,
                deadline_seconds=self._provider_deadline_seconds,
            )

        if execution_mode != "INLINE":
            raise PlatformResolverError(f"execution mode '{execution_mode}' has no configured Product transport")

        entrypoint = self._entrypoint(manifest)
        if not isinstance(entrypoint, str):
            raise PlatformResolverError(f"plugin '{plugin_id}' has no entrypoint")
        config_key = implementation_ref or plugin_id
        config = self._plugin_configs.get(config_key, self._plugin_configs.get(plugin_id, {}))
        return self._entrypoint_loader(entrypoint, config)

    @staticmethod
    def _read_manifest(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlatformResolverError(f"cannot read Platform manifest '{path}'") from exc
        if not isinstance(value, dict):
            raise PlatformResolverError(f"invalid Platform manifest '{path}'")
        return value

    @staticmethod
    def _plugin_id(manifest: Mapping[str, Any]) -> object:
        """Read identity only; Platform remains the manifest-shape authority.

        仅读取身份信息；manifest 结构仍由 Platform 负责判定。
        """

        platform_plugin = manifest.get("plugin")
        if isinstance(platform_plugin, Mapping):
            return platform_plugin.get("id")
        return manifest.get("id")

    @staticmethod
    def _plugin_version(manifest: Mapping[str, Any]) -> object:
        """Read release identity without normalizing the manifest in Product.

        读取发布身份，不在 Product 中规范化 manifest。
        """

        platform_plugin = manifest.get("plugin")
        if isinstance(platform_plugin, Mapping):
            return platform_plugin.get("version")
        return manifest.get("version")

    @staticmethod
    def _entrypoint(manifest: Mapping[str, Any]) -> object:
        """Read the selected INLINE entrypoint from either accepted wire shape.

        从任一受支持的线格式中读取已选定的 INLINE entrypoint。
        """

        platform_plugin = manifest.get("plugin")
        if isinstance(platform_plugin, Mapping):
            return platform_plugin.get("entrypoint")
        runtime = manifest.get("runtime")
        if isinstance(runtime, Mapping):
            return runtime.get("entrypoint")
        return None
