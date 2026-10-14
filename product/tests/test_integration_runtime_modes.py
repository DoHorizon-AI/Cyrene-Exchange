"""CLI runtime mode boundaries. | CLI 运行模式边界测试。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import cyrene_exchange_product.cli as exchange_cli
import cyrene_exchange_product.integrations.cli as integration_cli
import cyrene_exchange_product.server as product_server


def test_gateway_only_is_default_and_does_not_construct_integrations(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.delenv("CYRENE_EXCHANGE_RUNTIME_MODE", raising=False)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        exchange_cli.uvicorn,
        "run",
        lambda app, **kwargs: captured.update(app=app, kwargs=kwargs),
    )
    store = SimpleNamespace(close=lambda: None)
    app = SimpleNamespace(state=SimpleNamespace(integration_services=None, exchange_store=store))
    monkeypatch.setattr(exchange_cli, "build_product_app", lambda **_kwargs: app)

    assert exchange_cli.run(["--database", str(tmp_path / "gateway.sqlite3"), "serve"]) == 0
    assert captured["app"].state.integration_services is None
    assert captured["kwargs"]["port"] == 8000
    captured["app"].state.exchange_store.close()


def test_integration_only_uses_only_its_separate_database(tmp_path: Path, monkeypatch: Any) -> None:
    database_path = tmp_path / "integration.sqlite3"
    services = object()
    app = object()
    constructed: dict[str, Any] = {}
    monkeypatch.setattr(
        integration_cli,
        "build_production_services",
        lambda path: constructed.update(database=path) or services,
    )
    monkeypatch.setattr(
        product_server,
        "build_integration_app",
        lambda *, database_path, integrations: (
            constructed.update(app_database=database_path, integrations=integrations) or app
        ),
    )
    monkeypatch.setattr(
        exchange_cli.uvicorn,
        "run",
        lambda selected_app, **kwargs: constructed.update(served_app=selected_app, **kwargs),
    )

    result = exchange_cli.run(
        [
            "serve",
            "--mode",
            "integration-only",
            "--integration-database",
            str(database_path),
        ]
    )

    assert result == 0
    assert constructed["database"] == database_path
    assert constructed["app_database"] == database_path
    assert constructed["integrations"] is services
    assert constructed["served_app"] is app


def test_combined_mode_constructs_integrations_without_changing_gateway_app(
    tmp_path: Path, monkeypatch: Any
) -> None:
    database_path = tmp_path / "gateway.sqlite3"
    services = object()
    app = object()
    constructed: dict[str, Any] = {}
    monkeypatch.setattr(
        integration_cli,
        "build_production_services",
        lambda path: constructed.update(integration_database=path) or services,
    )
    monkeypatch.setattr(
        exchange_cli,
        "build_product_app",
        lambda **kwargs: constructed.update(product_app=kwargs) or app,
    )
    monkeypatch.setattr(
        exchange_cli.uvicorn,
        "run",
        lambda selected_app, **kwargs: constructed.update(served_app=selected_app, **kwargs),
    )

    result = exchange_cli.run(["--database", str(database_path), "serve", "--mode", "combined"])

    assert result == 0
    assert constructed["integration_database"] != database_path
    assert constructed["product_app"]["integrations"] is services
    assert constructed["product_app"]["database_path"] == database_path.resolve()
    assert constructed["served_app"] is app
