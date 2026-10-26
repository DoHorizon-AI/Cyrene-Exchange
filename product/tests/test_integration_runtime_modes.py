"""CLI runtime mode boundaries. | CLI 运行模式边界测试。"""

from __future__ import annotations

from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import cyrene_exchange_product.cli as exchange_cli
import cyrene_exchange_product.integrations.cli as integration_cli
import cyrene_exchange_product.server as product_server


def test_gateway_only_is_default_and_does_not_construct_integrations(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.delenv("CYRENE_EXCHANGE_RUNTIME_MODE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_AUTHORIZATION_CLOUD_RUNNER_ENABLED", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)
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
    assert "ssl_certfile" not in captured["kwargs"]
    assert "ssl_keyfile" not in captured["kwargs"]
    captured["app"].state.exchange_store.close()


def test_integration_only_uses_only_its_separate_database(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.delenv("CYRENE_EXCHANGE_AUTHORIZATION_CLOUD_RUNNER_ENABLED", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)
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
        lambda *, database_path, integrations, enable_authorization_cloud_runner: (
            constructed.update(
                app_database=database_path,
                integrations=integrations,
                runner_enabled=enable_authorization_cloud_runner,
            )
            or app
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
    assert constructed["runner_enabled"] is False


def test_integration_only_env_starts_the_app_owned_authorization_runner(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("CYRENE_EXCHANGE_AUTHORIZATION_CLOUD_RUNNER_ENABLED", "true")
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)
    captured: dict[str, Any] = {}
    services = object()
    monkeypatch.setattr(
        integration_cli,
        "build_production_services",
        lambda _path: services,
    )
    monkeypatch.setattr(
        product_server,
        "build_integration_app",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    monkeypatch.setattr(exchange_cli.uvicorn, "run", lambda *_args, **_kwargs: None)

    assert (
        exchange_cli.run(
            [
                "serve",
                "--mode",
                "integration-only",
                "--integration-database",
                str(tmp_path / "integrations.sqlite3"),
            ]
        )
        == 0
    )
    assert captured["integrations"] is services
    assert captured["enable_authorization_cloud_runner"] is True


def test_authorization_cloud_runner_switch_rejects_ambiguous_values(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("CYRENE_EXCHANGE_AUTHORIZATION_CLOUD_RUNNER_ENABLED", "sometimes")

    with pytest.raises(SystemExit, match="must be true or false"):
        exchange_cli._authorization_cloud_runner_enabled()


def test_integration_app_starts_and_drains_the_existing_authorization_runner(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    started = Event()
    stopped = Event()
    close_state: dict[str, bool] = {}

    class _Runner:
        monitor_interval_seconds = 900

        def run_forever(self, stop_event: Event) -> None:
            started.set()
            stop_event.wait(timeout=5)
            stopped.set()

    runner = _Runner()

    def close_services() -> None:
        close_state["worker_stopped_before_close"] = stopped.is_set()

    services = SimpleNamespace(
        store=object(),
        authorization_cloud_runner=runner,
        close=close_services,
    )

    def create_app(**_kwargs: Any) -> FastAPI:
        app = FastAPI()
        app.router.on_shutdown.append(services.close)
        return app

    monkeypatch.setattr(product_server, "create_app", create_app)
    app = product_server.build_integration_app(
        database_path=tmp_path / "unused.sqlite3",
        integrations=services,
        enable_authorization_cloud_runner=True,
    )

    with TestClient(app) as client:
        assert started.wait(timeout=2)
        assert client.get("/healthz").json() == {
            "status": "ok",
            "authorizationCloudRunner": "running",
        }
        assert client.get("/readyz").json() == {
            "status": "ready",
            "authorizationCloudRunner": "running",
        }

    assert stopped.is_set()
    assert close_state["worker_stopped_before_close"] is True


@pytest.mark.parametrize(
    ("runner", "message"),
    [
        (None, "enabled but not configured"),
        (SimpleNamespace(monitor_interval_seconds=901), "requires a 900-second"),
    ],
)
def test_integration_app_runner_enable_fails_closed_on_missing_or_wrong_cadence(
    tmp_path: Path,
    monkeypatch: Any,
    runner: object | None,
    message: str,
) -> None:
    monkeypatch.setattr(product_server, "create_app", lambda **_kwargs: FastAPI())
    services = SimpleNamespace(store=object(), authorization_cloud_runner=runner)

    with pytest.raises(ValueError, match=message):
        product_server.build_integration_app(
            database_path=tmp_path / "unused.sqlite3",
            integrations=services,
            enable_authorization_cloud_runner=True,
        )


def test_integration_listener_tls_requires_both_host_files(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    cert_path = tmp_path / "exchange-tls-cert.pem"
    cert_path.write_text("synthetic certificate", encoding="ascii")
    monkeypatch.setenv("CYRENE_EXCHANGE_TLS_CERT_FILE", str(cert_path))
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)

    arguments = exchange_cli.parser().parse_args(
        ["serve", "--mode", "integration-only", "--integration-database", str(tmp_path / "db")]
    )
    with pytest.raises(SystemExit, match="requires both"):
        exchange_cli._integration_listener_tls_options(
            arguments,
            runtime_mode="integration-only",
        )


def test_integration_listener_tls_rejects_invalid_certificate_key_pair(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    cert_path = tmp_path / "exchange-tls-cert.pem"
    key_path = tmp_path / "exchange-tls-key.pem"
    cert_path.write_text("invalid certificate", encoding="ascii")
    key_path.write_text("invalid private key", encoding="ascii")
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("CYRENE_EXCHANGE_TLS_KEY_FILE", raising=False)

    with pytest.raises(SystemExit, match="certificate/key pair is invalid"):
        exchange_cli._integration_listener_tls_options(
            SimpleNamespace(tls_cert_file=cert_path, tls_key_file=key_path),
            runtime_mode="integration-only",
        )


def test_integration_listener_tls_does_not_change_gateway_or_combined_modes(
    tmp_path: Path,
) -> None:
    cert_path = tmp_path / "exchange-tls-cert.pem"
    key_path = tmp_path / "exchange-tls-key.pem"
    cert_path.write_text("certificate", encoding="ascii")
    key_path.write_text("private key", encoding="ascii")

    with pytest.raises(SystemExit, match="only in integration-only mode"):
        exchange_cli._integration_listener_tls_options(
            SimpleNamespace(tls_cert_file=cert_path, tls_key_file=key_path),
            runtime_mode="combined",
        )


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
