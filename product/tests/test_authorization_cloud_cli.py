"""Independent authorization/cloud worker CLI lifecycle checks."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import cyrene_exchange_product.cli as exchange_cli
import cyrene_exchange_product.integrations.cli as integration_cli
from cyrene_exchange_product.integrations.authorization_cloud import AuthorizationCloudRunResult


@dataclass
class _Runner:
    calls: int = 0

    def run_once(self):
        self.calls += 1
        return AuthorizationCloudRunResult(
            authorization_checks=1,
            cloud_refreshes=2,
            email_submissions=3,
            deferred=4,
            unknown=5,
        )


class _Services:
    def __init__(self, runner: _Runner | None) -> None:
        self.authorization_cloud_runner = runner
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_authorization_cloud_once_is_independent_of_gateway_server(
    tmp_path: Path, monkeypatch: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = _Runner()
    services = _Services(runner)
    path = tmp_path / "integrations.sqlite3"
    monkeypatch.setattr(
        integration_cli, "resolve_integration_database_path", lambda *_a, **_k: path
    )
    monkeypatch.setattr(integration_cli, "build_production_services", lambda _path: services)

    result = exchange_cli.run(
        ["integrations", "authorization-cloud-once", "--integration-database", str(path)]
    )

    assert result == 0
    assert runner.calls == 1
    assert services.closed is True
    assert capsys.readouterr().out.strip() == (
        '{"authorization_checks":1,"cloud_refreshes":2,"deferred":4,'
        '"email_submissions":3,"unknown":5}'
    )


def test_authorization_cloud_cli_fails_closed_without_current_context_resolver(
    tmp_path: Path, monkeypatch: Any
) -> None:
    services = _Services(None)
    path = tmp_path / "integrations.sqlite3"
    monkeypatch.setattr(
        integration_cli, "resolve_integration_database_path", lambda *_a, **_k: path
    )
    monkeypatch.setattr(integration_cli, "build_production_services", lambda _path: services)

    with pytest.raises(SystemExit, match="current authority resolver are unavailable"):
        exchange_cli.run(
            ["integrations", "authorization-cloud-once", "--integration-database", str(path)]
        )
    assert services.closed is True
