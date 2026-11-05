"""Approved connector manifests, and the provider routes the dispatcher reads."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cyrene_exchange_product.integrations.connector_manifest import (
    MANIFEST_FILE_ENV,
    MANIFEST_MAX_BYTES,
    MANIFEST_SHA256_ENV,
    ConnectorManifestError,
    DeclaredOperations,
    declared_operations_from_bytes,
    load_declared_operations,
    verify_declared_operations,
)
from cyrene_exchange_product.integrations.connector_operations import (
    _PROVIDER_ROUTES,
    _TOOL_IDS_BY_PROVIDER,
    ConnectorOperationDispatcher,
    _provider_route,
    _resource_ref,
    connector_binding_tools,
    exchange_operation_facts,
)
from cyrene_exchange_product.integrations.models import (
    IntegrationConnection,
    IntegrationPrincipal,
)


def manifest(
    *,
    leave_out: frozenset[str] = frozenset(),
    exchange_only: frozenset[str] = frozenset({"github.commits.compare"}),
) -> dict[str, Any]:
    """A manifest stating exactly what this Exchange's tables say."""

    rows = []
    for operation_id, facts in sorted(exchange_operation_facts().items()):
        if operation_id in leave_out or operation_id in exchange_only:
            continue
        rows.append(
            {
                "operationId": operation_id,
                "providerIds": sorted(facts.tool_ids),
                "roles": ["operator"],
                "automationTransport": False,
                "mutating": facts.mutating,
                "exchangeToolIds": dict(facts.tool_ids),
                "exchangeResourceProjections": dict(facts.resource_projections),
                "navigatorToolId": None,
            }
        )
    rows.append(
        {
            "operationId": "msteams.message.reply",
            "providerIds": ["msteams"],
            "roles": ["operator"],
            "automationTransport": True,
            "mutating": None,
            "exchangeToolIds": {},
            "exchangeResourceProjections": {},
        }
    )
    return {
        "schemaVersion": "cyrene.connector-operations.v1",
        "sources": {},
        "operations": rows,
        "exchangeOnlyOperations": [{"operationId": item} for item in sorted(exchange_only)],
    }


def approved(document: dict[str, Any]) -> tuple[bytes, str]:
    data = json.dumps(document).encode()
    return data, "sha256:" + hashlib.sha256(data).hexdigest()


def load(document: dict[str, Any]) -> DeclaredOperations:
    data, digest = approved(document)
    return declared_operations_from_bytes(data, digest)


def row(document: dict[str, Any], operation_id: str) -> dict[str, Any]:
    return next(item for item in document["operations"] if item["operationId"] == operation_id)


def test_without_the_settings_every_exchange_operation_is_allowed() -> None:
    declared = load_declared_operations({})
    assert declared.digest is None
    for provider, tools in _TOOL_IDS_BY_PROVIDER.items():
        for operation_id in tools:
            assert declared.allows(provider, operation_id)


@pytest.mark.parametrize("present", [MANIFEST_FILE_ENV, MANIFEST_SHA256_ENV])
def test_half_of_the_settings_is_refused(present: str) -> None:
    with pytest.raises(ConnectorManifestError, match="set both"):
        load_declared_operations({present: "value"})


def test_only_the_approved_bytes_are_accepted() -> None:
    data, digest = approved(manifest())
    assert declared_operations_from_bytes(data, digest).digest == digest
    with pytest.raises(ConnectorManifestError, match="differs from the approved"):
        declared_operations_from_bytes(data + b"\n", digest)
    with pytest.raises(ConnectorManifestError, match="differs from the approved"):
        declared_operations_from_bytes(data, "sha256:" + "0" * 64)
    for invalid in ("", digest[7:], digest.upper(), digest + " ", "sha256:" + "g" * 64):
        with pytest.raises(ConnectorManifestError, match="approved digest is not"):
            declared_operations_from_bytes(data, invalid)
    oversized = b" " * (MANIFEST_MAX_BYTES + 1)
    with pytest.raises(ConnectorManifestError, match="too large"):
        declared_operations_from_bytes(oversized, "sha256:" + hashlib.sha256(oversized).hexdigest())


def _refused(document_or_bytes: dict[str, Any] | bytes, message: str) -> None:
    data = (
        document_or_bytes
        if isinstance(document_or_bytes, bytes)
        else json.dumps(document_or_bytes).encode()
    )
    with pytest.raises(ConnectorManifestError, match=message):
        declared_operations_from_bytes(data, "sha256:" + hashlib.sha256(data).hexdigest())


def test_malformed_manifests_are_refused() -> None:
    _refused(b"not json", "not valid JSON")
    _refused(b"\xff\xfe", "not valid JSON")
    _refused(
        b'{"schemaVersion": "cyrene.connector-operations.v1", '
        b'"schemaVersion": "cyrene.connector-operations.v1", "operations": []}',
        "repeats the key",
    )
    _refused([], "schema version")  # type: ignore[arg-type]
    _refused(manifest() | {"schemaVersion": "cyrene.connector-operations.v2"}, "schema version")
    _refused(manifest() | {"operations": []}, "lists no operations")

    repeated = manifest()
    repeated["operations"].append(dict(row(repeated, "github.repository.list")))
    _refused(repeated, "twice")

    for field, value, message in [
        ("operationId", "", "no operation ID"),
        ("providerIds", [], "providers"),
        ("providerIds", ["github", "github"], "providers"),
        ("providerIds", [7], "providers"),
        ("mutating", "yes", "mutating flag"),
        ("exchangeToolIds", ["github.repository.list"], "exchangeToolIds"),
        ("exchangeToolIds", {"github": 7}, "exchangeToolIds"),
        ("exchangeResourceProjections", None, "exchangeResourceProjections"),
    ]:
        document = manifest()
        row(document, "github.repository.list")[field] = value
        _refused(document, message)
    document = manifest()
    del row(document, "github.repository.list")["mutating"]
    _refused(document, "mutating flag")


def test_the_manifest_file_must_be_a_readable_regular_file(tmp_path: Path) -> None:
    data, digest = approved(manifest())
    good = tmp_path / "connector-operations.json"
    good.write_bytes(data)
    environ = {MANIFEST_FILE_ENV: str(good), MANIFEST_SHA256_ENV: digest}
    assert load_declared_operations(environ).digest == digest

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (tmp_path / "absent.json", tmp_path, fifo, Path("")):
        with pytest.raises(ConnectorManifestError, match="could not be read"):
            load_declared_operations({MANIFEST_FILE_ENV: str(path), MANIFEST_SHA256_ENV: digest})


def test_a_manifest_generated_from_this_exchange_is_accepted() -> None:
    declared = load(manifest())
    verify_declared_operations(declared, exchange_operation_facts())
    verify_declared_operations(DeclaredOperations.builtin(), exchange_operation_facts())


def test_a_manifest_generated_from_another_exchange_is_refused() -> None:
    facts = exchange_operation_facts()

    changed_tool = manifest()
    row(changed_tool, "github.branch.get")["exchangeToolIds"] = {"github": "github.branch.read"}
    with pytest.raises(ConnectorManifestError, match="tool IDs"):
        verify_declared_operations(load(changed_tool), facts)

    changed_projection = manifest()
    row(changed_projection, "github.branch.get")["exchangeResourceProjections"] = {
        "github": "profile"
    }
    with pytest.raises(ConnectorManifestError, match="resource projections"):
        verify_declared_operations(load(changed_projection), facts)

    flipped = manifest()
    row(flipped, "github.file.commit")["mutating"] = False
    with pytest.raises(ConnectorManifestError, match="mutates"):
        verify_declared_operations(load(flipped), facts)

    # A tool this Exchange doesn't have.
    unknown = manifest()
    unknown["operations"].append(
        {
            "operationId": "github.wiki.read",
            "providerIds": ["github"],
            "mutating": False,
            "exchangeToolIds": {"github": "github.wiki.read"},
            "exchangeResourceProjections": {"github": "profile"},
        }
    )
    with pytest.raises(ConnectorManifestError, match="tool IDs"):
        verify_declared_operations(load(unknown), facts)

    # No source decided whether this mutates, so there is nothing to compare.
    unresolved = manifest()
    row(unresolved, "github.file.commit")["mutating"] = None
    verify_declared_operations(load(unresolved), facts)


def test_binding_export_leaves_out_operations_the_manifest_does_not_declare() -> None:
    declared = load(manifest(leave_out=frozenset({"github.branch.delete"})))
    exported = {item["operationId"] for item in connector_binding_tools("github", declared)}
    everything = {item["operationId"] for item in connector_binding_tools("github")}
    assert everything - exported == {"github.branch.delete", "github.commits.compare"}
    assert connector_binding_tools("github", DeclaredOperations.builtin()) == (
        connector_binding_tools("github")
    )


def test_provider_routes_keep_the_provider_rules() -> None:
    """The registry holds the provider sets the dispatcher used to spell out inline."""

    def providers(flag: str) -> set[str]:
        return {name for name, route in _PROVIDER_ROUTES.items() if getattr(route, flag)}

    assert providers("actor_owned_only") == {"microsoft_graph", "azure_devops", "bilibili"}
    assert providers("account_profile") == {
        "github",
        "huggingface",
        "microsoft_graph",
        "azure_devops",
        "bilibili",
    }
    assert providers("account_lease") == {
        "github",
        "huggingface",
        "microsoft_graph",
        "azure_devops",
        "bilibili",
    }
    assert {name for name, route in _PROVIDER_ROUTES.items() if route.check is None} == {"bilibili"}
    # Providers with no entry of their own get the cloud checks, as before.
    assert _provider_route("oracle") is _provider_route("azure")
    assert _provider_route("gcp") is _provider_route("runpod")


def _github_dispatcher(
    declared: DeclaredOperations | None = None,
) -> tuple[ConnectorOperationDispatcher, IntegrationPrincipal, IntegrationConnection]:
    principal = IntegrationPrincipal(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        subject="11111111-1111-4111-8111-111111111111",
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset({"github.repository.list", "github.branch.delete"}),
    )
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
    dispatcher = ConnectorOperationDispatcher(
        store=SimpleNamespace(current_connection_for_provider_call=lambda _id: connection),
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
        declared=declared,
    )
    return dispatcher, principal, connection


def _prepare(
    dispatcher: ConnectorOperationDispatcher,
    principal: IntegrationPrincipal,
    connection: IntegrationConnection,
    operation_id: str,
    arguments: dict[str, object],
    target: dict[str, object],
) -> Any:
    return dispatcher.prepare_connection_operation(
        principal=principal,
        connection=connection,
        provider_id="github",
        profile_ref="gh-profile-1",
        operation_id=operation_id,
        resource_ref=_resource_ref(
            provider_id="github",
            profile_ref="gh-profile-1",
            operation_id=operation_id,
            target=target,
        ),
        arguments=arguments,
        request_id="request-1",
    )


def test_the_dispatcher_refuses_operations_outside_an_approved_manifest() -> None:
    declared = load(manifest(leave_out=frozenset({"github.repository.list"})))
    dispatcher, principal, connection = _github_dispatcher(declared)
    with pytest.raises(PermissionError, match="not in the approved manifest"):
        _prepare(
            dispatcher,
            principal,
            connection,
            "github.repository.list",
            {},
            {"profile_ref": "gh-profile-1"},
        )
    assert dispatcher.declared_operations is declared

    allowed, principal, connection = _github_dispatcher(load(manifest()))
    prepared = _prepare(
        allowed,
        principal,
        connection,
        "github.repository.list",
        {},
        {"profile_ref": "gh-profile-1"},
    )
    assert prepared.tool_id == "github.repository.list"
    assert prepared.account_lease_target == {}
    assert prepared.is_mutating is False


@pytest.mark.parametrize("branch", ["main", "develop", "release/1.0", "production"])
def test_the_dispatcher_still_refuses_protected_branch_writes(branch: str) -> None:
    """The GitHub route's checks run on the real entry point, not only when called directly."""

    dispatcher, principal, connection = _github_dispatcher()
    arguments: dict[str, object] = {
        "repository_id": "42",
        "repository": "acme/demo",
        "branch": branch,
        "expected_sha": "a" * 40,
    }
    with pytest.raises(PermissionError, match="protected"):
        _prepare(
            dispatcher,
            principal,
            connection,
            "github.branch.delete",
            arguments,
            arguments,
        )


def _principal(*operation_ids: str) -> IntegrationPrincipal:
    return IntegrationPrincipal(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        subject="11111111-1111-4111-8111-111111111111",
        organization_id="org-test",
        workspace_id="workspace-test",
        allowed_operation_ids=frozenset(operation_ids),
    )


def _dispatcher_for(
    connection: IntegrationConnection | None = None,
    *,
    declared: DeclaredOperations | None = None,
    computer_runner_profile: Any = None,
) -> ConnectorOperationDispatcher:
    return ConnectorOperationDispatcher(
        store=SimpleNamespace(current_connection_for_provider_call=lambda _id: connection),
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
        computer_runner_profile=computer_runner_profile,
        declared=declared,
    )


def test_the_huggingface_route_checks_run_on_the_real_entry_point() -> None:
    principal = _principal("huggingface.repo.get")
    connection = IntegrationConnection(
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        actor_issuer=principal.issuer,
        actor_subject=principal.subject,
        provider="hf",
        binding_ref="hf-host-profile",
        target_ref="acme/model",
        account_link_ref="hf-account-profile",
    )
    with pytest.raises(PermissionError, match="HF host profile is unavailable"):
        _dispatcher_for(connection).prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="huggingface",
            profile_ref="hf-account-profile",
            operation_id="huggingface.repo.get",
            resource_ref="sha256:" + "0" * 64,
            arguments={"repo_type": "model", "repo_id": "acme/model"},
            request_id="request-1",
        )


def test_the_cloud_route_checks_run_on_the_real_entry_point() -> None:
    principal = _principal("cloud.resource.get")
    connection = IntegrationConnection(
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        actor_issuer=principal.issuer,
        actor_subject=principal.subject,
        provider="azure",
        binding_ref="azure-prod",
        target_ref="vm-prod",
    )
    with pytest.raises(PermissionError, match="cloud host profile is unavailable"):
        _dispatcher_for(connection).prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="azure",
            profile_ref="azure-prod",
            operation_id="cloud.resource.get",
            resource_ref="sha256:" + "0" * 64,
            arguments={"profile_ref": "azure-prod", "target": {"resource_id": "vm-prod"}},
            request_id="request-1",
        )


def test_computer_operations_outside_an_approved_manifest_are_refused() -> None:
    profile = SimpleNamespace(
        connection_ref="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        profile_ref="local-runner-profile",
        authorize_principal=lambda _principal: None,
    )
    declared = load(manifest(leave_out=frozenset({"computer.file.read"})))
    dispatcher = ConnectorOperationDispatcher(
        store=SimpleNamespace(),
        accounts=SimpleNamespace(),
        github=SimpleNamespace(),
        authorization_cloud=None,
        registry=None,
        computer_runner_profile=profile,
        declared=declared,
    )
    with pytest.raises(PermissionError, match="computer operation is not in the approved"):
        dispatcher.prepare_computer_operation(
            principal=_principal("computer.file.read"),
            profile=profile,
            connection_ref=profile.connection_ref,
            provider_id="computer",
            profile_ref=profile.profile_ref,
            operation_id="computer.file.read",
            resource_ref="sha256:" + "0" * 64,
            arguments={},
            request_id="request-1",
        )


def test_teams_replies_outside_an_approved_manifest_are_refused() -> None:
    principal = _principal("msteams.message.reply")
    profile = SimpleNamespace(
        profile_ref="teams-profile",
        expected_issuer=principal.issuer,
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        authorize_principal=lambda _principal: None,
    )
    without_reply = manifest()
    without_reply["operations"] = [
        item
        for item in without_reply["operations"]
        if item["operationId"] != "msteams.message.reply"
    ]
    request: dict[str, Any] = {
        "principal": principal,
        "profile": profile,
        "provider_id": "msteams",
        "profile_ref": "teams-profile",
        "operation_id": "msteams.message.reply",
        "resource_ref": "sha256:" + "0" * 64,
        "arguments": {},
        "request_id": "request-1",
    }
    with pytest.raises(PermissionError, match="Teams operation is not in the approved"):
        _dispatcher_for(declared=load(without_reply)).prepare_teams_reply(**request)
    # With the reply declared, it gets past the manifest to the argument checks.
    with pytest.raises(ValueError, match="fixed operation schema"):
        _dispatcher_for(declared=load(manifest())).prepare_teams_reply(**request)
