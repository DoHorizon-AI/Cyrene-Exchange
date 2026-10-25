"""Provider catalog export tests using synthetic DirectPlugin responses."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from cyrene_plugin_runtime import DirectPayload

import cyrene_exchange_product.cli as exchange_cli
import cyrene_exchange_product.integrations.cli as integrations_cli
from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
    tool_provider_pb2 as tool_wire,
)
from cyrene_exchange_product.integrations.auth import AccountCenterRequestSigner
from cyrene_exchange_product.integrations.clients import (
    COMPUTER_TOOL_IDS,
    GitHubIssuesClient,
    ProviderToolDefinition,
    list_provider_tool_catalog,
)
from cyrene_exchange_product.integrations.connector_operations import connector_binding_tools
from cyrene_exchange_product.integrations.connector_profiles import parse_connector_host_settings


class _DirectClient:
    """Capture one fixed DirectPlugin call and return its synthetic typed response."""

    def __init__(self, response: DirectPayload) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> DirectPayload:
        self.calls.append(kwargs)
        return self.response


def _catalog_payload(
    binding_id: str,
    definitions: list[tuple[str, str]],
) -> DirectPayload:
    response = tool_wire.ListToolsResponse()
    response.catalog.catalog_version = "v-test"
    for tool_id, schema_json in definitions:
        descriptor = response.catalog.tools.add()
        descriptor.binding_id = binding_id
        descriptor.provider_tool_id = tool_id
        descriptor.display_name = f"Display {tool_id}"
        descriptor.description = f"Description for {tool_id}."
        descriptor.input_schema_json = schema_json
    return DirectPayload(
        "type.cyrene.io/cyrene.tool.provider.v1.ListToolsResponse",
        response.SerializeToString(deterministic=True),
    )


def test_list_provider_tool_catalog_uses_fixed_direct_plugin_catalog_method() -> None:
    binding_id = "github-plugin-binding"
    schema = '{"type":"object","properties":{"repository":{"type":"string"}}}'
    transport = _DirectClient(_catalog_payload(binding_id, [("github.repository.get", schema)]))

    catalog = list_provider_tool_catalog(transport, binding_id=binding_id)

    assert catalog == (
        ProviderToolDefinition(
            tool_id="github.repository.get",
            name="Display github.repository.get",
            description="Description for github.repository.get.",
            input_schema={
                "type": "object",
                "properties": {"repository": {"type": "string"}},
            },
        ),
    )
    call = transport.calls[0]
    request = tool_wire.ListToolsRequest.FromString(call["request"].value)
    assert call["capability"] == "tool.provider.v1"
    assert call["interface_version"] == "1"
    assert call["method"] == "list_tools"
    assert request.binding_id == binding_id


@pytest.mark.parametrize(
    ("descriptor_binding", "schema_json"),
    [
        (
            "other-binding",
            '{"type":"object","properties":{}}',
        ),
        (
            "github-plugin-binding",
            '{"type":"object","properties":{"api_token":{"type":"string"}}}',
        ),
        (
            "github-plugin-binding",
            '{"type":"object","properties":{"safe":1,"safe":2}}',
        ),
    ],
)
def test_list_provider_tool_catalog_rejects_untrusted_descriptor_data(
    descriptor_binding: str,
    schema_json: str,
) -> None:
    response = tool_wire.ListToolsResponse()
    response.catalog.catalog_version = "v-test"
    descriptor = response.catalog.tools.add()
    descriptor.binding_id = descriptor_binding
    descriptor.provider_tool_id = "github.repository.get"
    descriptor.display_name = "Get Repository"
    descriptor.description = "Read repository metadata."
    descriptor.input_schema_json = schema_json
    transport = _DirectClient(
        DirectPayload(
            "type.cyrene.io/cyrene.tool.provider.v1.ListToolsResponse",
            response.SerializeToString(deterministic=True),
        )
    )

    with pytest.raises(RuntimeError, match=r"catalog|schema|descriptor"):
        list_provider_tool_catalog(transport, binding_id="github-plugin-binding")


def test_github_client_catalog_reads_its_host_bound_plugin() -> None:
    schema = '{"type":"object","properties":{},"additionalProperties":false}'
    transport = _DirectClient(
        _catalog_payload("github-plugin-binding", [("github.repository.list", schema)])
    )
    client = GitHubIssuesClient(
        transport,
        signer=AccountCenterRequestSigner(caller_id="exchange", key=b"g" * 32),
        binding_id="github-plugin-binding",
    )

    catalog = client.list_tool_catalog()

    assert [tool.tool_id for tool in catalog] == ["github.repository.list"]
    assert transport.calls[0]["method"] == "list_tools"


def test_connector_tool_catalog_cli_exports_real_schema_and_fixed_mutability(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    connection = SimpleNamespace(
        id=uuid4(),
        provider="github",
        organization_id="org-1",
        workspace_id="workspace-1",
        actor_issuer="https://issuer.example",
        actor_subject="actor-1",
        account_link_ref="github-profile-1",
        binding_ref="github-profile-alias",
        target_ref=None,
    )
    operation_map = connector_binding_tools("github")
    provider_catalog = (
        *(
            ProviderToolDefinition(
                tool_id=str(item["toolId"]),
                name=f"Provider {item['toolId']}",
                description="Read from provider ListTools.",
                input_schema={"type": "object", "properties": {"source": {"const": "plugin"}}},
            )
            for item in operation_map
        ),
        ProviderToolDefinition(
            tool_id="provider.unmapped.debug",
            name="Unmapped debug tool",
            description="Must not be exposed.",
            input_schema={"type": "object", "properties": {}},
        ),
    )
    calls: dict[str, Any] = {}

    class _Store:
        def connector_bindings_for_actor(self, **kwargs: Any) -> list[Any]:
            calls["scope"] = kwargs
            return [connection]

    class _Services:
        store = _Store()
        github = SimpleNamespace(
            list_tool_catalog=lambda: calls.update(github_catalog_calls=1) or provider_catalog
        )
        authorization_cloud = None

        def close(self) -> None:
            calls["closed"] = True

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    result = exchange_cli.run(
        [
            "integrations",
            "connector-tool-catalog",
            "--integration-database",
            str(database_path),
            "--issuer",
            "https://issuer.example",
            "--subject",
            "actor-1",
            "--organization-id",
            "org-1",
            "--workspace-id",
            "workspace-1",
        ]
    )

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert result == 0
    assert captured.err == ""
    assert calls["closed"] is True
    assert calls["github_catalog_calls"] == 1
    assert calls["scope"] == {
        "issuer": "https://issuer.example",
        "subject": "actor-1",
        "organization_id": "org-1",
        "workspace_id": "workspace-1",
    }
    assert set(document) == {"schemaVersion", "items"}
    assert document["schemaVersion"] == 1
    item = document["items"][0]
    assert set(item) == {
        "bindingId",
        "capabilityId",
        "providerId",
        "connectionRef",
        "profileRef",
        "tools",
    }
    assert item["bindingId"] == f"exchange-github-{connection.id}"
    assert item["capabilityId"] == "tool.provider.v1"
    assert item["providerId"] == "github"
    assert item["profileRef"] == "github-profile-1"
    assert "provider.unmapped.debug" not in captured.out
    tool_by_id = {tool["id"]: tool for tool in item["tools"]}
    assert set(tool_by_id) == {str(entry["toolId"]) for entry in operation_map}
    assert tool_by_id["github.repository.get"]["readOnly"] is True
    assert tool_by_id["github.issue.comment.create"]["readOnly"] is False
    assert tool_by_id["github.repository.get"]["inputSchema"] == {
        "type": "object",
        "properties": {"source": {"const": "plugin"}},
    }


def test_connector_tool_catalog_cli_fails_without_a_required_provider_tool(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    connection = SimpleNamespace(
        id=uuid4(),
        provider="github",
        organization_id="org-1",
        workspace_id="workspace-1",
        actor_issuer="https://issuer.example",
        actor_subject="actor-1",
        account_link_ref="github-profile-1",
        binding_ref="github-profile-alias",
        target_ref=None,
    )

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return [connection]

    class _Services:
        store = _Store()
        github = SimpleNamespace(list_tool_catalog=lambda: ())
        authorization_cloud = None

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    with pytest.raises(SystemExit, match="missing required Exchange operations"):
        exchange_cli.run(
            [
                "integrations",
                "connector-tool-catalog",
                "--integration-database",
                str(database_path),
                "--issuer",
                "https://issuer.example",
                "--subject",
                "actor-1",
                "--organization-id",
                "org-1",
                "--workspace-id",
                "workspace-1",
            ]
        )

    assert capsys.readouterr().out == ""


def test_connector_tool_catalog_cli_allows_a_teams_only_empty_snapshot(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return []

    class _Services:
        store = _Store()
        github = SimpleNamespace()
        authorization_cloud = None

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    assert (
        exchange_cli.run(
            [
                "integrations",
                "connector-tool-catalog",
                "--integration-database",
                str(database_path),
                "--issuer",
                "https://issuer.example",
                "--subject",
                "actor-1",
                "--organization-id",
                "org-1",
                "--workspace-id",
                "workspace-1",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"items": [], "schemaVersion": 1}


def test_connector_tool_catalog_exports_host_computer_profile_without_account_connection(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The private tool catalog binds a host runner without fabricating OAuth state."""

    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    issuer = "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0"
    profile_value = {
        "profileRef": "computer-workspace-profile",
        "connectionRef": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "organizationId": "org-1",
        "workspaceId": "workspace-1",
        "expectedIssuer": issuer,
        "directPlugin": {
            "bindingId": "computer-runtime",
            "connectionRef": "grpcs://computer-runner.test:443",
            "transport": "mtls",
            "mtls": {
                "rootCertificateRef": "test/root-ca",
                "clientCertificateRef": "test/client-cert",
                "clientKeyRef": "test/client-key",
            },
        },
    }
    profile = parse_connector_host_settings({"computerRunner": profile_value}).computer_runner
    assert profile is not None
    schemas: dict[str, dict[str, Any]] = {
        "computer.command.execute": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "maxLength": 8192, "x-maxUtf8Bytes": 32768},
                "cwd": {"type": "string", "maxLength": 1024, "x-maxUtf8Bytes": 4096},
                "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 600000},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "computer.file.read": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "maxLength": 1024, "x-maxUtf8Bytes": 4096},
                "length": {"type": "integer", "minimum": 0, "maximum": 65536},
                "offset": {"type": "integer", "minimum": 0, "maximum": (1 << 63) - 1},
            },
            "required": ["path", "length"],
            "additionalProperties": False,
        },
        "computer.file.write": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "maxLength": 1024, "x-maxUtf8Bytes": 4096},
                "content_base64": {"type": "string", "maxLength": 1_398_104},
                "overwrite": {"type": "boolean"},
            },
            "required": ["path", "content_base64", "overwrite"],
            "additionalProperties": False,
        },
        "computer.directory.list": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "maxLength": 1024, "x-maxUtf8Bytes": 4096},
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 32},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    }
    tool_definitions = tuple(
        ProviderToolDefinition(
            tool_id=tool_id,
            name=f"Computer {tool_id}",
            description="Host-bound isolated operation.",
            input_schema=schemas[tool_id],
        )
        for tool_id in COMPUTER_TOOL_IDS
    )

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return []

    class _Services:
        store = _Store()
        computer_runner_profile = profile
        computer_runner_client = SimpleNamespace(list_tool_catalog=lambda: tool_definitions)
        github = SimpleNamespace()
        authorization_cloud = None

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    result = exchange_cli.run(
        [
            "integrations",
            "connector-tool-catalog",
            "--integration-database",
            str(database_path),
            "--issuer",
            issuer,
            "--subject",
            "actor-1",
            "--organization-id",
            "org-1",
            "--workspace-id",
            "workspace-1",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["schemaVersion"] == 1
    assert len(output["items"]) == 1
    item = output["items"][0]
    assert item["bindingId"] == f"exchange-computer-{profile.connection_ref}"
    assert item["capabilityId"] == "tool.provider.v1"
    assert item["providerId"] == "computer"
    assert item["connectionRef"] == profile.connection_ref
    tools = {tool["id"]: tool for tool in item["tools"]}
    assert set(tools) == COMPUTER_TOOL_IDS
    assert tools["computer.command.execute"]["readOnly"] is False
    assert tools["computer.file.write"]["readOnly"] is False
    assert tools["computer.file.read"]["readOnly"] is True
    assert tools["computer.directory.list"]["readOnly"] is True


def test_connector_binding_map_exports_host_computer_profile_without_database_row(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Navigator receives the host runner's fixed map without an OAuth connection row."""

    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    issuer = "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0"
    profile = parse_connector_host_settings(
        {
            "computerRunner": {
                "profileRef": "computer-workspace-profile",
                "connectionRef": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "organizationId": "org-1",
                "workspaceId": "workspace-1",
                "expectedIssuer": issuer,
                "directPlugin": {
                    "bindingId": "computer-runtime",
                    "connectionRef": "grpcs://computer-runner.test:443",
                    "transport": "mtls",
                    "mtls": {
                        "rootCertificateRef": "test/root-ca",
                        "clientCertificateRef": "test/client-cert",
                        "clientKeyRef": "test/client-key",
                    },
                },
            }
        }
    ).computer_runner
    assert profile is not None

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return []

    class _Services:
        store = _Store()
        computer_runner_profile = profile

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    result = exchange_cli.run(
        [
            "integrations",
            "connector-bindings",
            "--integration-database",
            str(database_path),
            "--issuer",
            issuer,
            "--subject",
            "actor-1",
            "--organization-id",
            "org-1",
            "--workspace-id",
            "workspace-1",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert len(output["bindings"]) == 1
    binding = output["bindings"][0]
    assert binding == {
        "bindingId": f"exchange-computer-{profile.connection_ref}",
        "connectionRef": profile.connection_ref,
        "providerId": "computer",
        "profileRef": profile.profile_ref,
        "tools": connector_binding_tools("computer"),
    }


def test_connector_tool_catalog_cli_omits_legacy_oauth_issue_connections(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    legacy_connection = SimpleNamespace(
        id=uuid4(),
        provider="github",
        organization_id="org-1",
        workspace_id="workspace-1",
        actor_issuer="https://issuer.example",
        actor_subject="actor-1",
        account_link_ref=None,
        binding_ref=None,
        target_ref=None,
    )

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return [legacy_connection]

    class _Services:
        store = _Store()
        github = SimpleNamespace(
            list_tool_catalog=lambda: pytest.fail(
                "legacy issue-sync connection must not query or export the App catalog"
            )
        )
        authorization_cloud = None

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    assert (
        exchange_cli.run(
            [
                "integrations",
                "connector-tool-catalog",
                "--integration-database",
                str(database_path),
                "--issuer",
                "https://issuer.example",
                "--subject",
                "actor-1",
                "--organization-id",
                "org-1",
                "--workspace-id",
                "workspace-1",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"items": [], "schemaVersion": 1}
