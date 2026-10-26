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


def _definitions_for_operation_map(
    operation_map: list[dict[str, object]],
) -> tuple[ProviderToolDefinition, ...]:
    """Build only the fixed descriptors requested by a CLI export test."""

    return tuple(
        ProviderToolDefinition(
            tool_id=str(item["toolId"]),
            name=f"Provider {item['toolId']}",
            description="Fixed provider operation.",
            input_schema={"type": "object", "properties": {}},
        )
        for item in operation_map
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
        repository_id="123",
        repository_name="acme/project",
        access_mode="actor_owned",
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
        repository_id="123",
        repository_name="acme/project",
        access_mode="actor_owned",
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


def test_connector_readiness_exports_real_read_only_hf_profile_and_catalog(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    profile_ref = "00000000-0000-4000-8000-000000000401"
    connection = SimpleNamespace(
        id=uuid4(),
        provider="hf",
        organization_id="org-1",
        workspace_id="workspace-1",
        actor_issuer="https://issuer.example",
        actor_subject="actor-1",
        account_link_ref=profile_ref,
        binding_ref="hf-primary",
        target_ref="hf-qwen",
        access_mode="workspace_operator",
    )
    target_ref = "Qwen/Qwen2.5-0.5B-Instruct"
    read_only_map = [
        item for item in connector_binding_tools("huggingface") if item["mutating"] is False
    ]
    provider_catalog = _definitions_for_operation_map(read_only_map)
    account_profile = {
        "profile_ref": profile_ref,
        "provider": "huggingface",
        "auth_status": "healthy",
        "auth_mode": "device_oauth",
        "access_mode": "workspace_operator",
        "credential_revision": 3,
        "target_scope": {
            "repositories": [
                {
                    "repo_type": "model",
                    "repo_id": target_ref,
                    "permissions": ["read"],
                }
            ]
        },
    }
    calls: dict[str, Any] = {}

    class _Store:
        def connector_bindings_for_actor(self, **kwargs: Any) -> list[Any]:
            calls["scope"] = kwargs
            return [connection]

    class _Services:
        store = _Store()
        accounts = SimpleNamespace(
            list_provider_profiles=lambda principal: (
                calls.update(actor=(principal.issuer, principal.subject, principal.organization_id))
                or {"profiles": [account_profile]}
            )
        )
        authorization_cloud = SimpleNamespace(
            list_tool_catalog=lambda binding_ref: (
                calls.update(binding_ref=binding_ref) or provider_catalog
            )
        )
        authorization_profile_registry = SimpleNamespace(
            settings=SimpleNamespace(
                profiles={
                    "hf-primary": SimpleNamespace(
                        profile_ref="hf-primary",
                        provider="hf",
                        targets={
                            "hf-qwen": SimpleNamespace(
                                target_ref=target_ref,
                                display_name="Qwen target",
                            )
                        },
                    )
                }
            )
        )

        def close(self) -> None:
            calls["closed"] = True

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    result = exchange_cli.run(
        [
            "integrations",
            "connector-readiness",
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

    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert calls["closed"] is True
    assert calls["binding_ref"] == "hf-primary"
    assert calls["actor"] == ("https://issuer.example", "actor-1", "org-1")
    assert output["schemaVersion"] == 1
    assert output["actor"] == {
        "issuer": "https://issuer.example",
        "subject": "actor-1",
        "organizationId": "org-1",
        "workspaceId": "workspace-1",
    }
    profile = output["profiles"][0]
    assert profile["profileRef"] == profile_ref
    assert profile["profileAlias"] == "hf-primary"
    assert profile["providerId"] == "huggingface"
    assert profile["authMode"] == "device_oauth"
    assert profile["credentialRevision"] == 3
    binding = output["bindings"][0]
    catalog_item = output["catalog"]["items"][0]
    assert binding["profileRef"] == profile_ref
    assert binding["connectionRef"] == str(connection.id)
    assert {tool["toolId"] for tool in binding["tools"]} == {
        tool["id"] for tool in catalog_item["tools"]
    }
    assert {tool["id"] for tool in catalog_item["tools"]} == {
        str(item["toolId"]) for item in read_only_map
    }
    assert output["connections"][0]["targetScope"] == {
        "repoType": "model",
        "repoId": target_ref,
        "permissions": ["read"],
    }
    serialized = json.dumps(output)
    assert "authorizationRef" not in serialized
    assert "credentialSecretRef" not in serialized


def test_connector_readiness_fails_when_read_only_catalog_lacks_a_read_operation(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    target_ref = "Qwen/Qwen2.5-0.5B-Instruct"
    connection = SimpleNamespace(
        id=uuid4(),
        provider="azure",
        organization_id="org-1",
        workspace_id="workspace-1",
        actor_issuer="https://issuer.example",
        actor_subject="actor-1",
        account_link_ref=None,
        binding_ref="azure-primary",
        target_ref="subscription-prod",
        access_mode="workspace_operator",
    )
    operation_map = connector_binding_tools("azure")
    read_only_map = [item for item in operation_map if item["mutating"] is False]
    missing_read = next(
        item for item in read_only_map if item["operationId"] == "cloud.resources.list"
    )
    provider_catalog = _definitions_for_operation_map(
        [item for item in read_only_map if item is not missing_read]
    )

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return [connection]

    class _Services:
        store = _Store()
        authorization_cloud = SimpleNamespace(
            list_tool_catalog=lambda _binding_ref: provider_catalog
        )
        authorization_profile_registry = SimpleNamespace(
            settings=SimpleNamespace(
                profiles={
                    "azure-primary": SimpleNamespace(
                        profile_ref="azure-primary",
                        provider="azure",
                        auth_mode="managed_identity",
                        targets={"subscription-prod": SimpleNamespace(target_ref=target_ref)},
                    )
                }
            )
        )

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    with pytest.raises(SystemExit, match="missing required Exchange read operations"):
        exchange_cli.run(
            [
                "integrations",
                "connector-readiness",
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


def test_connector_readiness_filters_exact_live_cloud_read_only_catalog(
    tmp_path: Path,
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "integrations.sqlite3"
    database_path.touch()
    connection = SimpleNamespace(
        id=uuid4(),
        provider="azure",
        organization_id="org-1",
        workspace_id="workspace-1",
        actor_issuer="https://issuer.example",
        actor_subject="actor-1",
        account_link_ref=None,
        binding_ref="azure-primary",
        target_ref="subscription-prod",
        access_mode="workspace_operator",
    )
    operation_map = connector_binding_tools("azure")
    read_only_map = [item for item in operation_map if item["mutating"] is False]
    provider_catalog = _definitions_for_operation_map(read_only_map)

    class _Store:
        def connector_bindings_for_actor(self, **_kwargs: Any) -> list[Any]:
            return [connection]

    class _Services:
        store = _Store()
        authorization_cloud = SimpleNamespace(
            list_tool_catalog=lambda _binding_ref: provider_catalog
        )
        authorization_profile_registry = SimpleNamespace(
            settings=SimpleNamespace(
                profiles={
                    "azure-primary": SimpleNamespace(
                        profile_ref="azure-primary",
                        provider="azure",
                        auth_mode="managed_identity",
                        targets={
                            "subscription-prod": SimpleNamespace(target_ref="subscription-id-123")
                        },
                    )
                }
            )
        )

        def close(self) -> None:
            return None

    monkeypatch.delenv("CYRENE_EXCHANGE_PROCESS_ROLE", raising=False)
    monkeypatch.setattr(integrations_cli, "build_production_services", lambda _path: _Services())

    result = exchange_cli.run(
        [
            "integrations",
            "connector-readiness",
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

    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["profiles"][0]["profileRef"] == "azure-primary"
    assert output["profiles"][0]["authMode"] == "managed_identity"
    assert output["profiles"][0]["readOnly"] is True
    binding = output["bindings"][0]
    catalog_item = output["catalog"]["items"][0]
    assert {tool["toolId"] for tool in binding["tools"]} == {
        str(item["toolId"]) for item in read_only_map
    }
    assert {tool["id"] for tool in catalog_item["tools"]} == {
        str(item["toolId"]) for item in read_only_map
    }
    assert all(tool["readOnly"] for tool in catalog_item["tools"])
