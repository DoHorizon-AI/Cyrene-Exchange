"""Focused authorization, scope, and replay tests for connector invocation receipts."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations import store as store_module
from cyrene_exchange_product.integrations.api import (
    ConnectorOperationBody,
    TeamsMessageBody,
    _connector_operation_response,
    _connector_replay_response,
    _teams_resource_ref,
)
from cyrene_exchange_product.integrations.connector_operations import (
    ConnectorOperationDispatcher,
    _account_lease_target,
    _resource_projection,
    _resource_ref,
    _safe_provider_result,
    _validate_github_target,
    _without_cli_output,
    connector_binding_tools,
    validate_computer_tool_schema,
)
from cyrene_exchange_product.integrations.connector_profiles import (
    ComputerRunnerProfile,
    parse_connector_host_settings,
    validate_teams_service_url,
)
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    connector_canonical_json,
    digest_arguments,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationConflict,
    IntegrationConnection,
    IntegrationPrincipal,
)
from cyrene_exchange_product.integrations.store import (
    ConnectorInvocationLedgerFull,
    ConnectorInvocationReservation,
    IntegrationStore,
)


def actor() -> IntegrationPrincipal:
    """Return a fixed trusted principal for local persistence tests."""

    return IntegrationPrincipal(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        subject="11111111-1111-4111-8111-111111111111",
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"navigator.connector.operator.v1"}),
    )


def computer_profile() -> ComputerRunnerProfile:
    """Return one host-owned runner profile without any provider account identity."""

    parsed = parse_connector_host_settings(
        {
            "computerRunner": {
                "profileRef": "local-runner-profile",
                "connectionRef": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "organizationId": "org-test",
                "workspaceId": "workspace-test",
                "expectedIssuer": "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/v2.0",
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
    )
    assert parsed.computer_runner is not None
    return parsed.computer_runner


def reserve(
    store: IntegrationStore,
    *,
    request_id: str,
    now_epoch: int,
    envelope_sha256: str | None = None,
    is_mutating: bool = False,
) -> ConnectorInvocationReservation:
    """Reserve one deterministic GitHub-like call for receipt invariant tests."""

    return store.reserve_connector_invocation(
        actor(),
        request_id=request_id,
        connection_ref="9dca6ec0-4874-4d09-8e37-c3f4718e619c",
        provider_id="github",
        profile_ref="gh-profile-1",
        operation_id="github.repository.list",
        resource_ref="sha256:resource",
        arguments_sha256="a" * 64,
        envelope_sha256=envelope_sha256 or "b" * 64,
        grant_ref="sha256:" + "0" * 64,
        is_mutating=is_mutating,
        now_epoch=now_epoch,
    )


def test_git_hub_and_hugging_face_lease_targets_are_provider_specific() -> None:
    """Account Center lease targets follow provider contract, not Directory hashes."""

    assert (
        _account_lease_target(
            "github",
            "github.repository.list",
            {"profile_ref": "gh-profile-1"},
            {"profile_ref": "gh-profile-1"},
        )
        == {}
    )
    for operation_id, repo_type in (
        ("huggingface.models.list", "model"),
        ("huggingface.datasets.list", "dataset"),
        ("huggingface.spaces.list", "space"),
    ):
        assert _account_lease_target(
            "huggingface",
            operation_id,
            {"profile_ref": "hf-profile-1"},
            {"profile_ref": "hf-profile-1"},
        ) == {"repo_type": repo_type}


def test_legacy_github_issue_connection_cannot_enter_app_connector_dispatch(tmp_path) -> None:
    """The actor-owned OAuth issue path cannot be promoted to a GitHub App profile."""

    principal = IntegrationPrincipal(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        subject="11111111-1111-4111-8111-111111111111",
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"integrationCreateConnection", "github.repository.list"}),
    )
    store = IntegrationStore(tmp_path / "legacy-github-connection.sqlite3")
    connection = store.create_connection(
        principal,
        CreateIntegrationConnection(
            provider="github",
            repository_id="4242",
            repository_name="example-org/legacy-repository",
        ),
        idempotency_key="legacy-oauth-connection",
    )
    dispatcher = ConnectorOperationDispatcher(
        store=store,
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
    )

    try:
        with pytest.raises(PermissionError, match="profile ref does not match"):
            dispatcher.prepare_connection_operation(
                principal=principal,
                connection=connection,
                provider_id="github",
                profile_ref="untrusted-legacy-account-ref",
                operation_id="github.repository.list",
                resource_ref="sha256:" + "0" * 64,
                arguments={},
                request_id="legacy-oauth-connector-call",
            )
    finally:
        store.close()


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({}, {"repository_id": "42", "repository": "acme/demo"}),
        (
            {"branch": "release/1"},
            {"repository_id": "42", "repository": "acme/demo", "branch": "release/1"},
        ),
        (
            {"commit_sha": "a" * 40},
            {"repository_id": "42", "repository": "acme/demo", "commit_sha": "a" * 40},
        ),
        (
            {"branch": "release/1", "commit_sha": "a" * 40},
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "release/1",
                "commit_sha": "a" * 40,
            },
        ),
    ],
)
def test_github_actions_lease_binds_optional_branch_and_commit_filters(
    filters: dict[str, str], expected: dict[str, str]
) -> None:
    """Actions filters are added to the lease while Directory scope stays repository-wide."""

    directory_projection = {"repository_id": "42", "repository": "acme/demo"}
    assert (
        _account_lease_target(
            "github",
            "github.actions.runs.list",
            directory_projection,
            {**directory_projection, **filters},
        )
        == expected
    )


def test_proactive_github_tools_use_exact_resource_targets_and_mutability() -> None:
    """New GitHub tools share provider schemas, stable targets, and fixed write policy."""

    principal = actor()
    connection = IntegrationConnection(
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        actor_issuer=principal.issuer,
        actor_subject=principal.subject,
        provider="github",
        repository_id="42",
        repository_name="acme/demo",
        account_link_ref="gh-profile-1",
    )
    cases: list[tuple[str, dict[str, object], str, dict[str, object], bool]] = [
        (
            "github.issues.search",
            {
                "state": "OPEN",
                "query": "bug report",
                "limit": 25,
                "labels": ["bug"],
                "updated_since": "2026-10-24T09:15:30.125+00:00",
                "page_cursor": "2",
            },
            "github_repository",
            {"repository_id": "42", "repository": "acme/demo"},
            False,
        ),
        (
            "github.actions.jobs.list",
            {"run_id": "9001", "limit": 50},
            "github_actions_run",
            {"repository_id": "42", "repository": "acme/demo", "run_id": "9001"},
            False,
        ),
        (
            "github.actions.job.logs.read",
            {"run_id": "9001", "job_id": "9002", "max_lines": 100},
            "github_actions_job",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "run_id": "9001",
                "job_id": "9002",
            },
            False,
        ),
        (
            "github.branch.create",
            {"branch": "task/assistant-v1", "from_sha": "a" * 40},
            "github_branch",
            {"repository_id": "42", "repository": "acme/demo", "branch": "task/assistant-v1"},
            True,
        ),
        (
            "github.branch.delete",
            {"branch": "task/assistant-v1", "expected_sha": "b" * 40},
            "github_branch",
            {"repository_id": "42", "repository": "acme/demo", "branch": "task/assistant-v1"},
            True,
        ),
        (
            "github.branch.get",
            {"branch": "task/assistant-v1"},
            "github_branch",
            {"repository_id": "42", "repository": "acme/demo", "branch": "task/assistant-v1"},
            False,
        ),
        (
            "github.file.commit",
            {
                "branch": "task/assistant-v1",
                "path": "docs/assistant.md",
                "message": "Add assistant notes",
                "content_base64": "c21hbGw=",
                "expected_sha": "c" * 40,
            },
            "github_file",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "task/assistant-v1",
                "path": "docs/assistant.md",
            },
            True,
        ),
        (
            "github.file.get",
            {"branch": "task/assistant-v1", "path": "docs/assistant.md"},
            "github_file",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "task/assistant-v1",
                "path": "docs/assistant.md",
            },
            False,
        ),
        (
            "github.pull_request.draft.create",
            {
                "head_branch": "task/assistant-v1",
                "base_branch": "develop",
                "title": "Assistant work",
                "body": "Review this change",
            },
            "github_pull_request_draft",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "head_branch": "task/assistant-v1",
                "base_branch": "develop",
            },
            True,
        ),
        (
            "github.pull_request.draft.find",
            {"head_branch": "task/assistant-v1", "base_branch": "develop"},
            "github_pull_request_draft",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "head_branch": "task/assistant-v1",
                "base_branch": "develop",
            },
            False,
        ),
        (
            "github.actions.rerun_failed",
            {
                "run_id": "9001",
                "expected_workflow_id": "9002",
                "expected_head_branch": "cyrene/assistant/task-1",
                "expected_head_sha": "d" * 40,
                "expected_attempt": 2,
            },
            "github_actions_run",
            {"repository_id": "42", "repository": "acme/demo", "run_id": "9001"},
            True,
        ),
    ]
    operation_policy = {
        str(item["operationId"]): item for item in connector_binding_tools("github")
    }

    for operation_id, operation_arguments, projection_name, target, mutating in cases:
        arguments = {
            "repository_id": connection.repository_id,
            "repository": connection.repository_name,
            **operation_arguments,
        }
        _validate_github_target(connection, operation_id, arguments)
        actual_projection = _resource_projection(
            provider_id="github",
            profile_ref="gh-profile-1",
            operation_id=operation_id,
            arguments=arguments,
        )
        assert actual_projection == target
        assert _account_lease_target("github", operation_id, actual_projection, arguments) == target
        assert operation_policy[operation_id] == {
            "toolId": operation_id,
            "operationId": operation_id,
            "resourceProjection": projection_name,
            "mutating": mutating,
        }

    _validate_github_target(
        connection,
        "github.issues.search",
        {
            "repository_id": "42",
            "repository": "acme/demo",
            "state": "ALL",
            "limit": 25,
            "updated_since": "2026-10-24T09:15:30Z",
        },
    )

    rerun_arguments = {
        "repository_id": "42",
        "repository": "acme/demo",
        "run_id": "9001",
        "expected_workflow_id": "9002",
        "expected_head_branch": "cyrene/assistant/task-1",
        "expected_head_sha": "d" * 40,
        "expected_attempt": 2,
    }
    jobs_arguments = {
        "repository_id": "42",
        "repository": "acme/demo",
        "run_id": "9001",
        "limit": 50,
    }
    assert _resource_projection(
        provider_id="github",
        profile_ref="gh-profile-1",
        operation_id="github.actions.rerun_failed",
        arguments=rerun_arguments,
    ) == _resource_projection(
        provider_id="github",
        profile_ref="gh-profile-1",
        operation_id="github.actions.jobs.list",
        arguments=jobs_arguments,
    )
    changed_attempt = {**rerun_arguments, "expected_attempt": 3}
    assert digest_arguments(changed_attempt) != digest_arguments(rerun_arguments)


@pytest.mark.parametrize(
    ("operation_id", "arguments"),
    [
        (
            "github.branch.delete",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "main",
                "expected_sha": "a" * 40,
            },
        ),
        (
            "github.file.commit",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "task/assistant-v1",
                "path": ".github/workflows/build.yml",
                "message": "Change workflow",
                "content_base64": "YQ==",
            },
        ),
        (
            "github.file.commit",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "task/assistant-v1",
                "path": "config/production.yaml",
                "message": "Change config",
                "content_base64": "YQ==",
            },
        ),
        (
            "github.file.commit",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "branch": "task/assistant-v1",
                "path": "docs/assistant.md",
                "message": "Commit content",
                "content_base64": "YR==",
            },
        ),
        (
            "github.actions.jobs.list",
            {"repository_id": "42", "repository": "acme/demo", "run_id": "01", "limit": 10},
        ),
        (
            "github.issues.search",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "state": "OPEN",
                "limit": 50,
                "page_cursor": "21",
            },
        ),
        (
            "github.issues.search",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "state": "OPEN",
                "limit": 25,
                "labels": ["bug", "bug"],
            },
        ),
        (
            "github.issues.search",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "state": "OPEN",
                "limit": 25,
                "query": "is:open",
            },
        ),
        (
            "github.actions.rerun_failed",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "run_id": "9001",
                "expected_head_sha": "d" * 40,
                "expected_attempt": 2,
            },
        ),
        (
            "github.actions.rerun_failed",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "run_id": "9001",
                "expected_workflow_id": "9002",
                "expected_head_branch": "bot/assistant-task",
                "expected_head_sha": "d" * 40,
                "expected_attempt": 2,
            },
        ),
        (
            "github.actions.rerun_failed",
            {
                "repository_id": "42",
                "repository": "acme/demo",
                "run_id": "9001",
                "expected_workflow_id": "0",
                "expected_head_branch": "cyrene/assistant/task-1",
                "expected_head_sha": "d" * 40,
                "expected_attempt": 2,
            },
        ),
    ],
)
def test_proactive_github_tools_reject_protected_or_malformed_targets(
    operation_id: str, arguments: dict[str, object]
) -> None:
    """Provider write preconditions and stable target fields fail closed in Exchange."""

    principal = actor()
    connection = IntegrationConnection(
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        actor_issuer=principal.issuer,
        actor_subject=principal.subject,
        provider="github",
        repository_id="42",
        repository_name="acme/demo",
        account_link_ref="gh-profile-1",
    )
    with pytest.raises((PermissionError, ValueError)):
        _validate_github_target(connection, operation_id, arguments)


def test_computer_host_profile_is_closed_scoped_and_has_transport_safe_limits() -> None:
    """The local runner profile is host-owned and does not create an OAuth connection."""

    assert parse_connector_host_settings({}).computer_runner is None
    profile = computer_profile()
    assert profile.connection_ref == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert profile.profile_ref == "local-runner-profile"
    assert profile.endpoint.binding_id == "computer-runtime"
    assert profile.max_file_bytes == 1_048_576
    assert profile.max_read_bytes == 65_536
    assert profile.max_directory_depth == 32
    operation_policy = {
        str(item["operationId"]): item for item in connector_binding_tools("computer")
    }
    assert {operation_id: item["mutating"] for operation_id, item in operation_policy.items()} == {
        "computer.command.execute": True,
        "computer.file.read": False,
        "computer.file.write": True,
        "computer.directory.list": False,
    }

    with pytest.raises(ValueError):
        parse_connector_host_settings(
            {
                "computerRunner": {
                    "profileRef": "local-runner-profile",
                    "connectionRef": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "organizationId": "org-test",
                    "workspaceId": "workspace-test",
                    "expectedIssuer": actor().issuer,
                    "directPlugin": {
                        "bindingId": "untrusted-provider",
                        "connectionRef": "grpc://127.0.0.1:50051",
                        "transport": "local",
                    },
                }
            }
        )

    with pytest.raises(ValueError, match="private mTLS"):
        parse_connector_host_settings(
            {
                "computerRunner": {
                    "profileRef": "local-runner-profile",
                    "connectionRef": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "organizationId": "org-test",
                    "workspaceId": "workspace-test",
                    "expectedIssuer": actor().issuer,
                    "directPlugin": {
                        "bindingId": "computer-runtime",
                        "connectionRef": "grpc://127.0.0.1:50051",
                        "transport": "local",
                    },
                }
            }
        )


def test_computer_tool_catalog_schemas_cannot_exceed_the_host_profile_limits() -> None:
    """Host export rejects catalog bounds that the internal routes cannot carry."""

    profile = computer_profile()
    schemas: dict[str, dict[str, object]] = {
        "computer.command.execute": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "maxLength": 8192,
                    "x-maxUtf8Bytes": 32768,
                },
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
    for tool_id, schema in schemas.items():
        validate_computer_tool_schema(profile, tool_id=tool_id, input_schema=schema)

    over_limit = dict(schemas["computer.file.write"])
    over_limit["properties"] = {
        **schemas["computer.file.write"]["properties"],  # type: ignore[dict-item]
        "content_base64": {"type": "string", "maxLength": 1_398_108},
    }
    with pytest.raises(ValueError, match=r"file\.write schema"):
        validate_computer_tool_schema(
            profile,
            tool_id="computer.file.write",
            input_schema=over_limit,
        )


def test_computer_dispatch_uses_exact_workspace_grants_and_no_account_lease() -> None:
    """Typed local runner calls reuse the same exact Directory grant envelope."""

    profile = computer_profile()
    principal = IntegrationPrincipal(
        issuer=profile.expected_issuer,
        subject=actor().subject,
        organization_id=profile.organization_id,
        workspace_id=profile.workspace_id,
        allowed_operation_ids=frozenset({"computer.command.execute"}),
    )
    arguments: dict[str, object] = {
        "command": "printf done",
        "cwd": ".",
        "timeout_ms": 1_000,
    }
    workspace_target = {"workspace_ref": profile.connection_ref}
    resource_ref = _resource_ref(
        provider_id="computer",
        profile_ref=profile.profile_ref,
        operation_id="computer.command.execute",
        target=workspace_target,
    )
    calls: list[dict[str, object]] = []

    class _Computer:
        def call_provider_tool(
            self,
            *,
            tool_id: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            calls.append({"tool_id": tool_id, "payload": payload})
            return {
                "status": "COMMAND_COMPLETED",
                "exit_code": 0,
                "duration_ms": 3,
                "stdout": "done",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "sha256_hash": "a" * 64,
                "resource_usage": None,
                "isError": False,
            }

    dispatcher = ConnectorOperationDispatcher(
        store=SimpleNamespace(),
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
        computer=_Computer(),
        computer_runner_profile=profile,
    )
    prepared = dispatcher.prepare_computer_operation(
        principal=principal,
        profile=profile,
        connection_ref=profile.connection_ref,
        provider_id="computer",
        profile_ref=profile.profile_ref,
        operation_id="computer.command.execute",
        resource_ref=resource_ref,
        arguments=arguments,
        request_id="computer-command-1",
    )
    claims = ConnectorGrantClaims(
        request_id=prepared.request_id,
        audience="exchange",
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        principal_issuer=principal.issuer,
        principal_subject=principal.subject,
        connection_ref=profile.connection_ref,
        provider_id="computer",
        profile_ref=profile.profile_ref,
        operation_id=prepared.operation_id,
        resource_ref=prepared.resource_ref,
        arguments_digest_sha256=bytes.fromhex(digest_arguments(arguments)),
        issued_at_epoch=1_000.0,
        expires_at_epoch=1_015.0,
        grant_ref="sha256:" + "a" * 64,
    )

    result = dispatcher.invoke(prepared, principal=principal, claims=claims)

    assert prepared.connection is None
    assert prepared.account_lease_target is None
    assert prepared.is_mutating is True
    assert calls == [{"tool_id": "computer.command.execute", "payload": arguments}]
    assert result["status"] == "COMMAND_COMPLETED"


@pytest.mark.parametrize(
    ("operation_id", "arguments"),
    [
        ("computer.command.execute", {"command": "echo hi", "cwd": "../outside"}),
        ("computer.command.execute", {"command": "\x00bad"}),
        (
            "computer.file.read",
            {"path": "src/main.py", "length": 65_537},
        ),
        (
            "computer.file.write",
            {"path": "../outside.txt", "content_base64": "YQ==", "overwrite": True},
        ),
        (
            "computer.directory.list",
            {"path": "src", "max_depth": 33},
        ),
    ],
)
def test_computer_dispatch_rejects_paths_and_limits_outside_the_host_profile(
    operation_id: str,
    arguments: dict[str, object],
) -> None:
    """Path traversal and profile limit violations fail before provider authorization."""

    profile = computer_profile()
    principal = IntegrationPrincipal(
        issuer=profile.expected_issuer,
        subject=actor().subject,
        organization_id=profile.organization_id,
        workspace_id=profile.workspace_id,
        allowed_operation_ids=frozenset({operation_id}),
    )
    dispatcher = ConnectorOperationDispatcher(
        store=SimpleNamespace(),
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
        computer=SimpleNamespace(),
        computer_runner_profile=profile,
    )
    target = {
        "workspace_ref": profile.connection_ref,
        **({"path": str(arguments.get("path"))} if "path" in arguments else {}),
    }
    resource_ref = _resource_ref(
        provider_id="computer",
        profile_ref=profile.profile_ref,
        operation_id=operation_id,
        target=target,
    )
    with pytest.raises(ValueError):
        dispatcher.prepare_computer_operation(
            principal=principal,
            profile=profile,
            connection_ref=profile.connection_ref,
            provider_id="computer",
            profile_ref=profile.profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=arguments,
            request_id="computer-invalid-1",
        )


def test_runpod_resource_bindings_use_the_navigator_cloud_target_projection() -> None:
    """The generated RunPod map uses the same typed target shape as Navigator."""

    tools = connector_binding_tools("runpod")
    resource_tools = [
        tool for tool in tools if str(tool["operationId"]).startswith("cloud.resource.")
    ]
    assert resource_tools
    assert {tool["resourceProjection"] for tool in resource_tools} == {"cloud_target"}


def test_github_and_huggingface_cli_bind_profile_scope_and_argv_only() -> None:
    """Vendor CLI calls bind a host profile separately from exact argv payloads."""

    expected = {
        "github": ("github.vendor.cli.execute", "github_vendor_cli"),
        "huggingface": ("huggingface.vendor.cli.execute", "hf_vendor_cli"),
    }
    for provider_id, (operation_id, tool_id) in expected.items():
        tool = next(
            item
            for item in connector_binding_tools(provider_id)
            if item["operationId"] == operation_id
        )
        assert tool == {
            "toolId": tool_id,
            "operationId": operation_id,
            "resourceProjection": "profile",
            "mutating": True,
        }
        profile_ref = f"{provider_id}-profile"
        arguments = {"argv": ["provider", "list", "--limit", "10"]}
        projection = _resource_projection(
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            arguments=arguments,
        )
        assert projection == {"profile_ref": profile_ref}
        assert (
            _account_lease_target(
                provider_id,
                operation_id,
                projection,
                arguments,
            )
            == {}
        )
        assert digest_arguments(arguments) == (
            "5a2ca3b9a451f50ce859e18c8ff9f4aea84e3ff6852a58c8de3062ddc050b0d1"
        )
        assert digest_arguments({**arguments, "profile_ref": profile_ref}) != digest_arguments(
            arguments
        )
        resource_ref = _resource_ref(
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            target=projection,
        )
        assert resource_ref.startswith("sha256:")
        if provider_id == "github":
            assert resource_ref == (
                "sha256:9031004a086a6305d650baa3abc61754871d04768605235c5d6262fefe9fa433"
            )


def test_vendor_cli_argument_schemas_exclude_model_profile_refs_and_block_exports() -> None:
    """Only argv is model-controlled; Exchange injects profile refs from host rows."""

    principal = actor()
    argv = {"argv": ["gh", "repo", "view"]}
    github_connection = IntegrationConnection(
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        actor_issuer=principal.issuer,
        actor_subject=principal.subject,
        provider="github",
        repository_id="42",
        repository_name="example-org/private-repo",
    )
    _validate_github_target(github_connection, "github.vendor.cli.execute", argv)
    with pytest.raises(ValueError, match="argument fields"):
        _validate_github_target(
            github_connection,
            "github.vendor.cli.execute",
            {**argv, "profile_ref": "model-selected-profile"},
        )
    with pytest.raises(PermissionError, match="credential export"):
        _validate_github_target(
            github_connection,
            "github.vendor.cli.execute",
            {"argv": ["gh", "auth", "token"]},
        )
    with pytest.raises(PermissionError, match="credential export"):
        _validate_github_target(
            github_connection,
            "github.vendor.cli.execute",
            {"argv": ["gh", "auth", "login"]},
        )

    hf_profile = SimpleNamespace(provider="hf", targets={"hf-target": object()})
    registry = SimpleNamespace(settings=SimpleNamespace(profiles={"hf-primary": hf_profile}))
    dispatcher = ConnectorOperationDispatcher(
        store=None,
        accounts=None,
        github=None,
        authorization_cloud=None,
        registry=registry,
    )
    hf_connection = IntegrationConnection(
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        actor_issuer=principal.issuer,
        actor_subject=principal.subject,
        provider="hf",
        account_link_ref="hf-profile-ref",
        binding_ref="hf-primary",
        target_ref="hf-target",
    )
    dispatcher._validate_huggingface_target(
        hf_connection,
        "huggingface.vendor.cli.execute",
        argv,
    )
    with pytest.raises(ValueError, match="argument fields"):
        dispatcher._validate_huggingface_target(
            hf_connection,
            "huggingface.vendor.cli.execute",
            {**argv, "profile_ref": "model-selected-profile"},
        )


def test_shared_github_connection_uses_each_verified_actor_for_account_center_lease(
    tmp_path,
) -> None:
    """Shared connections preserve the caller identity in each signed lease proof."""

    store = IntegrationStore(tmp_path / "shared-connector.sqlite3")
    owner = IntegrationPrincipal(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        subject="owner-subject",
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"integrationCreateConnection", "github.repository.list"}),
    )
    second_operator = IntegrationPrincipal(
        issuer=owner.issuer,
        subject="second-operator-subject",
        organization_id=owner.organization_id,
        workspace_id=owner.workspace_id,
        allowed_operation_ids=frozenset({"github.repository.list"}),
    )

    class AccountCenter:
        def __init__(self) -> None:
            self.leases: list[dict[str, object]] = []

        def create_provider_credential_lease(
            self,
            principal: IntegrationPrincipal,
            *,
            profile_ref: str,
            operation_id: str,
            target: dict[str, object],
            arguments_sha256: str,
            connector_grant: dict[str, object] | None = None,
        ) -> object:
            self.leases.append(
                {
                    "subject": principal.subject,
                    "profile_ref": profile_ref,
                    "operation_id": operation_id,
                    "target": target,
                    "arguments_sha256": arguments_sha256,
                    "connector_grant": connector_grant,
                }
            )
            return SimpleNamespace(
                profile_ref=profile_ref,
                operation_id=operation_id,
                lease_ref=f"lease-{principal.subject}",
            )

    class GitHub:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def call_provider_tool(
            self,
            principal: IntegrationPrincipal,
            *,
            tool_id: str,
            profile_ref: str,
            lease_ref: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            self.calls.append(
                {
                    "subject": principal.subject,
                    "tool_id": tool_id,
                    "profile_ref": profile_ref,
                    "lease_ref": lease_ref,
                    "payload": payload,
                }
            )
            return {"repositories": [{"id": "42", "name": "acme/demo"}]}

    accounts = AccountCenter()
    github = GitHub()
    connection = store.create_connection(
        owner,
        CreateIntegrationConnection(
            provider="github",
            account_link_ref="gh-shared-profile",
            repository_id="42",
            repository_name="acme/demo",
        ),
        idempotency_key="shared-github-connection",
        access_mode="workspace_operator",
    )
    arguments: dict[str, object] = {}
    target = _resource_projection(
        provider_id="github",
        profile_ref="gh-shared-profile",
        operation_id="github.repository.list",
        arguments=arguments,
    )
    resource_ref = _resource_ref(
        provider_id="github",
        profile_ref="gh-shared-profile",
        operation_id="github.repository.list",
        target=target,
    )
    dispatcher = ConnectorOperationDispatcher(
        store=store,
        accounts=accounts,
        github=github,
        authorization_cloud=None,
        registry=None,
    )
    try:
        for index, principal in enumerate((owner, second_operator), start=1):
            selected_connection = store.connector_connection_for_actor(
                connection.id,
                issuer=principal.issuer,
                subject=principal.subject,
                workspace_id=principal.workspace_id,
                organization_id=principal.organization_id,
            )
            prepared = dispatcher.prepare_connection_operation(
                principal=principal,
                connection=selected_connection,
                provider_id="github",
                profile_ref="gh-shared-profile",
                operation_id="github.repository.list",
                resource_ref=resource_ref,
                arguments=arguments,
                request_id=f"shared-attempt-{index}",
            )
            claims = ConnectorGrantClaims(
                request_id=f"shared-attempt-{index}",
                audience="exchange",
                organization_id=principal.organization_id,
                workspace_id=principal.workspace_id,
                principal_issuer=principal.issuer,
                principal_subject=principal.subject,
                connection_ref=str(connection.id),
                provider_id="github",
                profile_ref="gh-shared-profile",
                operation_id="github.repository.list",
                resource_ref=resource_ref,
                arguments_digest_sha256=bytes.fromhex(digest_arguments(arguments)),
                issued_at_epoch=100,
                expires_at_epoch=115,
                grant_ref=f"sha256:{index:064x}",
            )
            dispatcher.invoke(prepared, principal=principal, claims=claims)

        assert [lease["subject"] for lease in accounts.leases] == [
            "owner-subject",
            "second-operator-subject",
        ]
        assert [call["subject"] for call in github.calls] == [
            "owner-subject",
            "second-operator-subject",
        ]
        for index, lease in enumerate(accounts.leases, start=1):
            proof = lease["connector_grant"]
            assert isinstance(proof, dict)
            assert set(proof) == {
                "grant_ref",
                "issued_at",
                "expires_at",
                "issuer",
                "subject",
                "organization_id",
                "workspace_id",
                "connection_ref",
                "provider_id",
                "profile_ref",
                "operation_id",
                "resource_ref",
                "arguments_sha256",
            }
            assert proof["subject"] == lease["subject"]
            assert proof["connection_ref"] == str(connection.id)
            assert proof["profile_ref"] == "gh-shared-profile"
            assert proof["provider_id"] == "github"
            assert proof["arguments_sha256"] == digest_arguments(arguments)
            assert proof["grant_ref"] == f"sha256:{index:064x}"
    finally:
        store.close()


def test_provider_business_states_do_not_masquerade_as_tool_lifecycle() -> None:
    """Read results preserve provider state; only writes map remote lifecycle to outcome."""

    read_cases = [
        ("github.ci.status", {"state": "PENDING"}),
        ("github.ci.status", {"state": "ERROR"}),
        ("cloud.resource.get", {"state": "RUNNING"}),
        ("cloud.operation.status.read", {"state": "FAILED"}),
    ]
    for _operation_id, result in read_cases:
        response = _connector_operation_response("read-request", result)
        assert response["outcome"] == "verified"
        business_result = json.loads(response["result"]["content"][0]["text"])
        assert business_result["state"] == result["state"]

    pending = _connector_operation_response(
        "write-pending",
        {"state": "RUNNING", "operation_ref": "op-1"},
        is_mutating=True,
    )
    assert pending["outcome"] == "pending"
    assert pending["operationRef"] == "op-1"
    assert (
        _connector_operation_response(
            "write-unknown", {"state": "UNKNOWN_RESULT"}, is_mutating=True
        )["outcome"]
        == "uncertain"
    )
    assert (
        _connector_operation_response(
            "write-no-state", {"resource_ref": "pod-1"}, is_mutating=True
        )["outcome"]
        == "uncertain"
    )
    assert (
        _connector_operation_response(
            "cli-unknown",
            {"state": "REMOTE_STATE_UNVERIFIED", "operation_ref": "cli-op-1"},
            is_mutating=True,
        )["outcome"]
        == "uncertain"
    )
    assert (
        _connector_operation_response("cli-read", {"state": "COMMAND_COMPLETED"}, is_mutating=True)[
            "outcome"
        ]
        == "verified"
    )
    assert (
        _connector_operation_response(
            "cli-remote-unknown",
            {"state": "COMMAND_COMPLETED", "remote_state": "UNKNOWN"},
            is_mutating=True,
        )["outcome"]
        == "uncertain"
    )
    assert (
        _connector_operation_response(
            "cli-command-failed",
            {"state": "COMMAND_FAILED", "remote_state": "NOT_APPLICABLE"},
            is_mutating=True,
        )["outcome"]
        == "failed"
    )
    assert (
        _connector_operation_response(
            "cli-command-cancelled",
            {"state": "COMMAND_CANCELLED", "remote_state": "NOT_APPLICABLE"},
            is_mutating=True,
        )["outcome"]
        == "uncertain"
    )


def test_provider_response_rejects_camelcase_secrets_and_suppresses_nested_cli_output() -> None:
    """Secret fields and command output cannot escape through provider result shapes."""

    with pytest.raises(ExchangeProductError):
        _safe_provider_result({"accessToken": "not-to-be-returned"})
    projected = _without_cli_output(
        {
            "state": "COMMAND_COMPLETED",
            "metadata": {"stdout": "secret-bearing output", "stderr": "diagnostic"},
            "entries": [{"raw_output": "private"}],
        }
    )
    assert projected == {"state": "COMMAND_COMPLETED", "metadata": {}, "entries": [{}]}


def test_connector_hashes_match_shared_rfc8785_cross_language_vector() -> None:
    """Argument digests and Directory resource refs use ECMAScript-compatible JCS bytes."""

    value = {
        "\ue000": "bmp",
        "𐀀": "supplementary",
        "small": 1e-7,
        "decimal": 1e-6,
    }
    canonical = ('{"decimal":0.000001,"small":1e-7,"𐀀":"supplementary","":"bmp"}').encode()
    assert connector_canonical_json(value) == canonical
    assert digest_arguments(value) == (
        "201897b3c1db3ba8f346a7cd54066c3879fb96d13c7bd04b59e1c4e0a1992bd5"
    )
    assert (
        _resource_ref(
            provider_id="github",
            profile_ref="profile-jcs",
            operation_id="github.repository.get",
            target=value,
        )
        == "sha256:04bc33d8da254c0f5ef974bbab9b7df00379d1dbfefadbd8972fb92b30facbe9"
    )
    with pytest.raises(ExchangeProductError):
        digest_arguments({"unsafe_integer": 2**53})
    with pytest.raises(ExchangeProductError):
        connector_canonical_json({"not_json": float("nan")})


def test_teams_resource_ref_hashes_only_the_canonical_conversation() -> None:
    """Teams and Navigator share the conversation-only SHA-256 projection."""

    route = {
        "tenantId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "teamId": "team-1",
        "channelId": "channel-1",
        "conversationId": "19:channel-conversation",
        "rootThreadId": "1698765432101",
        "serviceUrl": "https://smba.trafficmanager.net/emea/",
    }
    assert _teams_resource_ref(route) == _teams_resource_ref(dict(reversed(list(route.items()))))
    assert _teams_resource_ref(route) != _teams_resource_ref(
        {**route, "rootThreadId": "1698765432102"}
    )
    assert _teams_resource_ref(route) == (
        "sha256:78c889cfc0c6f06fa00005ce2bb2e017a1008a4f38694bfc7e1c3bfb2155e375"
    )
    assert digest_arguments({"conversation": route, "text": "The task completed."}) == (
        "813a88c0637c1de73e4a74757216a62e3fd84e7e98d1f6f97de923f1d42e251f"
    )


def test_minimal_http_dtos_accept_navigator_camelcase_without_mutating_claims() -> None:
    """DTOs accept Navigator JSON names and derive mutability inside Exchange."""

    invoke = ConnectorOperationBody.model_validate(
        {
            "requestId": "attempt-1",
            "providerId": "github",
            "profileRef": "gh-profile-1",
            "operationId": "github.repository.list",
            "resourceRef": "sha256:resource",
            "arguments": {},
        }
    )
    assert invoke.request_id == "attempt-1"
    assert invoke.provider_id == "github"
    assert not hasattr(invoke, "mutating")
    teams = TeamsMessageBody.model_validate(
        {
            "requestId": "teams-attempt-1",
            "conversation": {
                "tenantId": "tenant-1",
                "teamId": "team-1",
                "channelId": "channel-1",
                "conversationId": "conversation-1",
                "rootThreadId": "1740000000000",
                "serviceUrl": "https://smba.trafficmanager.net/amer/",
            },
            "text": "reply",
        }
    )
    assert teams.conversation.root_thread_id == "1740000000000"
    assert teams.conversation.service_url == "https://smba.trafficmanager.net/amer/"
    assert teams.provider_id is None


def test_teams_service_url_allows_only_verified_official_routes() -> None:
    """Regional Bot Framework URLs retain paths while disallowed origins are rejected."""

    tenant_id = "00000000-0000-4000-8000-000000000001"
    for url in (
        "https://smba.trafficmanager.net/teams/",
        "https://smba.trafficmanager.net/amer/",
        f"https://smba.trafficmanager.net/amer/{tenant_id}/",
        "https://smba.infra.teams.microsoft.com/teams/",
    ):
        assert validate_teams_service_url(url, tenant_id=tenant_id) == url
    for url in (
        "http://smba.trafficmanager.net/amer/",
        "https://evil.example/teams/",
        "https://smba.trafficmanager.net/amer/other-tenant/",
        "https://smba.trafficmanager.net/teams?next=evil",
        "https://smba.trafficmanager.net/amer/%2e%2e/",
        "https://smba.infra.teams.microsoft.com/amer/",
    ):
        with pytest.raises(ValueError):
            validate_teams_service_url(url, tenant_id=tenant_id)


def test_connector_receipt_replay_conflict_and_restart_persistence(tmp_path) -> None:
    """An exact request returns its receipt, while altered args conflict after restart."""

    path = tmp_path / "connector-ledger.sqlite3"
    store = IntegrationStore(path)
    assert (
        reserve(store, request_id="attempt-1", now_epoch=10, is_mutating=True).disposition == "NEW"
    )
    response = {
        "requestId": "attempt-1",
        "outcome": "pending",
        "operationRef": "cloud-op-1",
        "result": {
            "content": [{"type": "text", "text": '{"state":"PENDING"}'}],
            "isError": False,
        },
    }
    store.complete_connector_invocation(
        actor(),
        request_id="attempt-1",
        envelope_sha256="b" * 64,
        state="PENDING",
        response=response,
        operation_ref="cloud-op-1",
        response_status=200,
        now_epoch=11,
    )
    store.close()

    restarted = IntegrationStore(path)
    replay = reserve(
        restarted,
        request_id="attempt-1",
        now_epoch=10 + 25 * 60 * 60,
        is_mutating=True,
    )
    assert replay.disposition == "REPLAY"
    assert replay.response is not None
    replay_result = json.loads(replay.response["result"]["content"][0]["text"])
    assert replay_result["receiptOnly"] is True
    assert replay_result["freshRequestRequired"] is False
    encoded_response = json.dumps(
        response,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    assert replay_result["resultDigestSha256"] == hashlib.sha256(encoded_response).hexdigest()
    with pytest.raises(IntegrationConflict):
        reserve(
            restarted,
            request_id="attempt-1",
            now_epoch=10 + 25 * 60 * 60,
            envelope_sha256="c" * 64,
            is_mutating=True,
        )
    assert (
        restarted.reconcile_connector_invocations(
            actor(),
            profile_ref="gh-profile-1",
            operation_ref="cloud-op-1",
            terminal_state="FAILED",
            now_epoch=10 + 25 * 60 * 60,
        )
        == 1
    )
    settled = reserve(
        restarted,
        request_id="attempt-1",
        now_epoch=10 + 25 * 60 * 60,
        is_mutating=True,
    )
    assert settled.state == "FAILED"
    settled_response = _connector_replay_response(request_id="attempt-1", reservation=settled)
    assert settled_response["outcome"] == "verified"
    result = json.loads(settled_response["result"]["content"][0]["text"])
    assert result["state"] == "FAILED"
    restarted.close()


def test_connector_receipt_cache_is_bounded_by_entries_and_bytes(tmp_path) -> None:
    """Large and numerous terminal results cannot exceed the configured receipt cache."""

    store = IntegrationStore(tmp_path / "connector-cache.sqlite3")
    for index in range(270):
        request_id = f"read-{index}"
        reserve(store, request_id=request_id, now_epoch=100 + index)
        store.complete_connector_invocation(
            actor(),
            request_id=request_id,
            envelope_sha256="b" * 64,
            state="SUCCEEDED",
            response={
                "requestId": request_id,
                "outcome": "verified",
                "result": {
                    "content": [{"type": "text", "text": "x" * 15_000}],
                    "isError": False,
                },
            },
            operation_ref=None,
            response_status=200,
            now_epoch=100 + index,
        )
    rows = store._connection.execute(
        "SELECT response_json FROM connector_invocations WHERE response_json IS NOT NULL"
    ).fetchall()
    assert len(rows) <= 256
    assert sum(len(str(row["response_json"]).encode("utf-8")) for row in rows) <= 4 * 1024 * 1024
    assert max(len(str(row["response_json"]).encode("utf-8")) for row in rows) <= 16 * 1024
    assert all("receiptOnly" in str(row["response_json"]) for row in rows)
    assert all("x" * 100 not in str(row["response_json"]) for row in rows)
    store.close()


def test_oversized_connector_receipt_is_replaced_by_a_digest_summary(tmp_path) -> None:
    """A cached provider result is summarized before it exceeds the per-entry budget."""

    store = IntegrationStore(tmp_path / "connector-large-receipt.sqlite3")
    reserve(store, request_id="large-read", now_epoch=10)
    store.complete_connector_invocation(
        actor(),
        request_id="large-read",
        envelope_sha256="b" * 64,
        state="SUCCEEDED",
        response={
            "requestId": "large-read",
            "outcome": "verified",
            "result": {
                "content": [{"type": "text", "text": "x" * 100_000}],
                "isError": False,
            },
        },
        operation_ref=None,
        response_status=200,
        now_epoch=11,
    )
    replay = reserve(store, request_id="large-read", now_epoch=12)
    assert replay.response is not None
    assert len(json.dumps(replay.response).encode("utf-8")) <= 16 * 1024
    summary = json.loads(replay.response["result"]["content"][0]["text"])
    assert summary["receiptOnly"] is True
    assert summary["freshRequestRequired"] is True
    assert len(summary["resultDigestSha256"]) == 64
    store.close()


def test_authority_grant_use_is_durable_and_one_shot_across_restart(tmp_path) -> None:
    """A minted grant remains consumable once after restart and rejects later replay."""

    path = tmp_path / "connector-grants.sqlite3"
    store = IntegrationStore(path)
    assert store.register_connector_grant(
        grant_ref="sha256:" + "a" * 64,
        encoded_sha256="b" * 64,
        expires_at=1_015,
        now_epoch=1_000,
    )
    store.close()

    restarted = IntegrationStore(path)
    assert restarted.consume_connector_grant(
        grant_ref="sha256:" + "a" * 64,
        encoded_sha256="b" * 64,
        now_epoch=1_005,
    )
    assert not restarted.consume_connector_grant(
        grant_ref="sha256:" + "a" * 64,
        encoded_sha256="b" * 64,
        now_epoch=1_005,
    )
    assert not restarted.consume_connector_grant(
        grant_ref="sha256:" + "a" * 64,
        encoded_sha256="c" * 64,
        now_epoch=1_005,
    )
    restarted.close()


def test_connector_unresolved_tombstones_survive_receipt_pressure(tmp_path) -> None:
    """Receipt eviction never deletes an unresolved operation idempotency tombstone."""

    store = IntegrationStore(tmp_path / "connector-tombstones.sqlite3")
    for index in range(260):
        request_id = f"pending-{index}"
        reserve(store, request_id=request_id, now_epoch=1_000 + index, is_mutating=True)
        store.complete_connector_invocation(
            actor(),
            request_id=request_id,
            envelope_sha256="b" * 64,
            state="UNKNOWN_RESULT" if index == 0 else "PENDING",
            response={
                "requestId": request_id,
                "outcome": "uncertain" if index == 0 else "pending",
                "operationRef": f"operation-{index}",
                "result": {"content": [{"type": "text", "text": "x" * 1000}], "isError": False},
            },
            operation_ref=f"operation-{index}",
            response_status=200,
            now_epoch=1_000 + index,
        )
    replay = reserve(store, request_id="pending-0", now_epoch=90_000, is_mutating=True)
    assert replay.disposition in {"REPLAY", "UNKNOWN"}
    assert replay.state == "UNKNOWN_RESULT"
    assert replay.operation_ref == "operation-0"
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM connector_invocations WHERE state IN ('PENDING','UNKNOWN_RESULT')"
        ).fetchone()[0]
        == 260
    )
    store.close()


def test_tombstone_capacity_fails_closed_without_replaying_unresolved_calls(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A saturated pending ledger rejects work rather than evicting an unsafe tombstone."""

    monkeypatch.setattr(store_module, "_CONNECTOR_TOMBSTONE_MAX_ENTRIES", 2)
    store = IntegrationStore(tmp_path / "connector-full.sqlite3")
    for index in range(2):
        reserve(store, request_id=f"tombstone-{index}", now_epoch=50, is_mutating=True)
    with pytest.raises(ConnectorInvocationLedgerFull):
        reserve(store, request_id="one-too-many", now_epoch=50, is_mutating=True)
    store.close()
