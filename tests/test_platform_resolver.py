"""
Authority and failure tests for the Exchange-to-Platform resolver adapter.

Exchange 到 Platform resolver 适配器的权威与故障测试。
"""

from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace

import pytest

from cyrene_exchange import PlatformResolverAdapter, PlatformResolverError
from cyrene_exchange.platform_resolver import load_entrypoint


def resolver_command(output: object, *, assertion: str = "") -> list[str]:
    encoded = repr(json.dumps(output))
    check = f"{assertion}; " if assertion else ""
    script = f"import json, sys; request = json.loads(sys.stdin.read()); {check}print({encoded})"
    return [sys.executable, "-c", script]


def write_platform_manifest(tmp_path, version: str, entrypoint: str):
    path = tmp_path / f"manifest-{version}.json"
    path.write_text(
        json.dumps(
            {
                "plugin": {
                    "id": "example.provider",
                    "version": version,
                    "entrypoint": entrypoint,
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_selected_plugin_release_controls_inline_entrypoint(tmp_path):
    first = write_platform_manifest(tmp_path, "1.0.0", "example:First")
    second = write_platform_manifest(tmp_path, "2.0.0", "example:Second")
    output = {
        "resolutions": [
            {
                "plugin": {"id": "example.provider"},
                "plugin_version": {"version": "2.0.0"},
                "execution_mode": "INLINE",
            }
        ]
    }
    loaded = []
    adapter = PlatformResolverAdapter(
        resolver_command(output),
        [first, second],
        entrypoint_loader=lambda entrypoint, config: loaded.append((entrypoint, config)),
    )

    result = adapter.resolve("example.capability.v1")

    assert result is None
    assert loaded == [("example:Second", {})]


def test_official_manifest_is_forwarded_raw_to_platform_authority(tmp_path):
    manifest = tmp_path / "official.json"
    manifest.write_text(
        json.dumps(
            {
                "id": "example.provider",
                "version": "1.0.0",
                "runtime": {"entrypoint": "example:Provider"},
            }
        ),
        encoding="utf-8",
    )
    output = {
        "resolutions": [
            {
                "plugin": {"id": "example.provider"},
                "plugin_version": {"version": "1.0.0"},
                "execution_mode": "WORKER",
            }
        ]
    }
    adapter = PlatformResolverAdapter(
        resolver_command(
            output,
            assertion="assert request['manifests'][0]['id'] == 'example.provider'",
        ),
        [manifest],
        plugin_clients={
            "opaque-binding-id": SimpleNamespace(
                invoke=lambda **_: None,
                invoke_stream=lambda **_: iter(()),
            )
        },
    )

    provider = adapter.resolve("model.provider.v1", "opaque-binding-id")

    assert provider is not None
    assert adapter.resolutions[0]["reference"] == "opaque-binding-id"


@pytest.mark.parametrize(
    "output",
    [
        {},
        {"resolutions": []},
        {"resolutions": [{"plugin": None}]},
        {
            "resolutions": [
                {
                    "plugin": {"id": "example.provider"},
                    "plugin_version": {"version": ""},
                    "execution_mode": "INLINE",
                }
            ]
        },
    ],
)
def test_malformed_resolver_output_fails_closed(tmp_path, output):
    manifest = write_platform_manifest(tmp_path, "1.0.0", "example:Provider")
    adapter = PlatformResolverAdapter(resolver_command(output), [manifest])

    with pytest.raises(PlatformResolverError, match="invalid JSON"):
        adapter.resolve("example.capability.v1")


def test_resolver_start_failure_is_classified(tmp_path):
    manifest = write_platform_manifest(tmp_path, "1.0.0", "example:Provider")
    adapter = PlatformResolverAdapter([str(tmp_path / "missing-resolver")], [manifest])

    with pytest.raises(PlatformResolverError, match="could not be started"):
        adapter.resolve("example.capability.v1")


def test_entrypoint_internal_type_error_is_not_retried(monkeypatch):
    calls = 0

    class Target:
        def __init__(self, config):
            nonlocal calls
            calls += 1
            raise TypeError("constructor failed internally")

    monkeypatch.setattr(
        importlib,
        "import_module",
        lambda _: SimpleNamespace(Target=Target),
    )

    with pytest.raises(TypeError, match="failed internally"):
        load_entrypoint("fixture:Target", {})

    assert calls == 1
