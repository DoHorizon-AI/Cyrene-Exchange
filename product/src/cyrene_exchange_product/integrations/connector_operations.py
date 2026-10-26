"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 connector_operations.py                                         │
│  Module: cyrene_exchange_product.integrations.connector_operations  │
│  Role: Resolve fixed provider actions and invoke them once.          │
│                                                                      │
│  模块职责：校验连接/Profile/资源范围并执行固定 Provider 工具一次。       │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.connector_profiles import (
    ComputerRunnerProfile,
    validate_teams_root_thread_id,
    validate_teams_service_url,
)
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    connector_canonical_json,
    digest_arguments,
)
from cyrene_exchange_product.integrations.models import (
    IntegrationConnection,
    IntegrationPrincipal,
)

_TOOL_IDS_BY_PROVIDER: Mapping[str, Mapping[str, str]] = {
    "github": {
        "github.repository.list": "github.repository.list",
        "github.repository.get": "github.repository.get",
        "github.branches.list": "github.branches.list",
        "github.pull_requests.list": "github.pull_requests.list",
        "github.pull_request.get": "github.pull_request.get",
        "github.actions.runs.list": "github.actions.runs.list",
        "github.issues.search": "github.issues.search",
        "github.actions.jobs.list": "github.actions.jobs.list",
        "github.actions.job.logs.read": "github.actions.job.logs.read",
        "github.branch.create": "github.branch.create",
        "github.branch.delete": "github.branch.delete",
        "github.branch.get": "github.branch.get",
        "github.file.commit": "github.file.commit",
        "github.file.get": "github.file.get",
        "github.pull_request.draft.create": "github.pull_request.draft.create",
        "github.pull_request.draft.find": "github.pull_request.draft.find",
        "github.actions.rerun_failed": "github.actions.rerun_failed",
        "github.ci.status": "github.ci.status",
        "github.vendor.cli.execute": "github_vendor_cli",
        "github.issue.get": "github.issue.get",
        "github.issue.comment.create": "github.issue.comment.create",
        "github.issue.state.update": "github.issue.state.update",
    },
    "huggingface": {
        "huggingface.models.list": "huggingface.models.list",
        "huggingface.datasets.list": "huggingface.datasets.list",
        "huggingface.spaces.list": "huggingface.spaces.list",
        "huggingface.repo.get": "huggingface.repo.get",
        "huggingface.file.download": "huggingface.file.download",
        "huggingface.file.upload": "huggingface.file.upload",
        "huggingface.vendor.cli.execute": "hf_vendor_cli",
    },
    "azure": {
        "cloud.provider.health.read": "cloud_provider_health",
        "cloud.resources.list": "cloud_resources_list",
        "cloud.resource.get": "cloud_resource_get",
        "cloud.resource.create": "cloud_resource_create",
        "cloud.resource.deploy": "cloud_resource_deploy",
        "cloud.resource.start": "cloud_resource_start",
        "cloud.resource.stop": "cloud_resource_stop",
        "cloud.resource.update": "cloud_resource_update",
        "cloud.resource.delete": "cloud_resource_delete",
        "cloud.operation.status.read": "cloud_operation_status",
        "cloud.operation.logs.read": "cloud_operation_logs",
        "cloud.operation.cancel": "cloud_operation_cancel",
        "cloud.vendor.cli.execute": "cloud_vendor_cli",
    },
    "gcp": {
        "cloud.provider.health.read": "cloud_provider_health",
        "cloud.resources.list": "cloud_resources_list",
        "cloud.resource.get": "cloud_resource_get",
        "cloud.resource.create": "cloud_resource_create",
        "cloud.resource.deploy": "cloud_resource_deploy",
        "cloud.resource.start": "cloud_resource_start",
        "cloud.resource.stop": "cloud_resource_stop",
        "cloud.resource.update": "cloud_resource_update",
        "cloud.resource.delete": "cloud_resource_delete",
        "cloud.operation.status.read": "cloud_operation_status",
        "cloud.operation.logs.read": "cloud_operation_logs",
        "cloud.operation.cancel": "cloud_operation_cancel",
        "cloud.vendor.cli.execute": "cloud_vendor_cli",
    },
    "runpod": {
        "cloud.provider.health.read": "cloud_provider_health",
        "cloud.resources.list": "cloud_resources_list",
        "cloud.resource.get": "cloud_resource_get",
        "cloud.resource.create": "cloud_resource_create",
        "cloud.resource.deploy": "cloud_resource_deploy",
        "cloud.resource.start": "cloud_resource_start",
        "cloud.resource.stop": "cloud_resource_stop",
        "cloud.resource.restart": "cloud_resource_restart",
        "cloud.resource.update": "cloud_resource_update",
        "cloud.resource.delete": "cloud_resource_delete",
        "cloud.operation.status.read": "cloud_operation_status",
        "cloud.operation.logs.read": "cloud_operation_logs",
        "cloud.operation.cancel": "cloud_operation_cancel",
        "cloud.vendor.cli.execute": "cloud_vendor_cli",
    },
    "computer": {
        "computer.command.execute": "computer.command.execute",
        "computer.file.read": "computer.file.read",
        "computer.file.write": "computer.file.write",
        "computer.directory.list": "computer.directory.list",
    },
}
_MUTATING_OPERATIONS = frozenset(
    {
        "github.issue.comment.create",
        "github.issue.state.update",
        "github.branch.create",
        "github.branch.delete",
        "github.file.commit",
        "github.pull_request.draft.create",
        "github.actions.rerun_failed",
        "computer.command.execute",
        "computer.file.write",
        "github.vendor.cli.execute",
        "huggingface.file.upload",
        "huggingface.vendor.cli.execute",
        "cloud.resource.create",
        "cloud.resource.deploy",
        "cloud.resource.start",
        "cloud.resource.stop",
        "cloud.resource.restart",
        "cloud.resource.update",
        "cloud.resource.delete",
        "cloud.operation.cancel",
        "cloud.vendor.cli.execute",
    }
)
_CLI_SECRET_WORDS = frozenset(
    {"access-token", "api-key", "auth-token", "password", "secret", "token"}
)
_CLI_EXPORT_PATTERNS = (
    ("account", "get-access-token"),
    ("auth", "print-access-token"),
    ("auth", "token"),
    ("auth", "print-access-token"),
    ("auth", "login"),
    ("auth", "logout"),
    ("login",),
    ("logout",),
    ("configure",),
    ("config", "show"),
    ("credentials", "list"),
)
_GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_GITHUB_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")
_GITHUB_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
_GITHUB_PROTECTED_BRANCHES = frozenset(
    {"main", "master", "develop", "release", "production", "staging"}
)
_GITHUB_PROTECTED_BRANCH_PREFIXES = (
    "main/",
    "master/",
    "develop/",
    "release/",
    "production/",
    "prod/",
    "staging/",
)
_GITHUB_PROTECTED_PATH_DIRECTORIES = frozenset(
    {
        ".github",
        ".git",
        ".gitlab",
        ".circleci",
        ".azure",
        "deploy",
        "deployment",
        "infra",
        "infrastructure",
        "terraform",
        "helm",
        "k8s",
        "kubernetes",
        "production",
        "prod",
        "permissions",
    }
)
_GITHUB_PROTECTED_PATH_FILES = frozenset(
    {
        "codeowners",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        ".gitmodules",
    }
)
_GITHUB_SENSITIVE_PATH_SEGMENT = re.compile(
    r"^(?:prod|production|permissions|authorization|access-control)(?:[._-]|$)"
)
_COMPUTER_MAX_COMMAND_CHARS = 8_192
_COMPUTER_MAX_COMMAND_BYTES = 32_768
_COMPUTER_MAX_PATH_CHARS = 1_024
_COMPUTER_MAX_PATH_BYTES = 4_096
_COMPUTER_MAX_READ_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class PreparedConnectorOperation:
    """One validated, grant-bound provider operation ready for a one-time call."""

    connection: IntegrationConnection | None
    connection_ref: str
    principal: IntegrationPrincipal
    provider_id: str
    profile_ref: str
    operation_id: str
    resource_ref: str
    arguments: dict[str, object]
    tool_id: str
    request_id: str
    target_projection: dict[str, object]
    account_lease_target: dict[str, object] | None
    expected_organization_id: str
    expected_workspace_id: str
    is_mutating: bool


class ConnectorOperationDispatcher:
    """Validate current connection scope and route fixed tools to provider clients."""

    def __init__(
        self,
        *,
        store: Any,
        accounts: Any,
        github: Any,
        authorization_cloud: Any,
        registry: Any,
        computer: Any = None,
        computer_runner_profile: ComputerRunnerProfile | None = None,
    ) -> None:
        self._store = store
        self._accounts = accounts
        self._github = github
        self._authorization_cloud = authorization_cloud
        self._registry = registry
        self._computer = computer
        self._computer_runner_profile = computer_runner_profile

    def prepare_connection_operation(
        self,
        *,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        provider_id: str,
        profile_ref: str,
        operation_id: str,
        resource_ref: str,
        arguments: Mapping[str, object],
        request_id: str,
    ) -> PreparedConnectorOperation:
        """Validate exact actor, provider, profile, operation, and resource projection."""

        principal.require(operation_id)
        current = self._store.current_connection_for_provider_call(connection.id)
        if current is None or current != connection or not current.enabled:
            raise PermissionError("connector connection changed or is disabled")
        same_scope = (
            current.actor_issuer == principal.issuer
            and current.organization_id == principal.organization_id
            and current.workspace_id == principal.workspace_id
        )
        owner_match = current.actor_subject == principal.subject
        shared_match = current.access_mode == "workspace_operator"
        if not same_scope or not (owner_match or shared_match):
            raise PermissionError("connector connection owner does not match the signed actor")
        canonical_provider = _canonical_provider(current.provider)
        if provider_id != canonical_provider:
            raise PermissionError("provider id does not match the persisted connection")
        expected_profile = (
            current.account_link_ref
            if current.provider in {"github", "hf"}
            else current.binding_ref
        )
        if not expected_profile or profile_ref != expected_profile:
            raise PermissionError("profile ref does not match the persisted connection")
        tool_id = _TOOL_IDS_BY_PROVIDER.get(canonical_provider, {}).get(operation_id)
        if tool_id is None:
            raise PermissionError("provider operation is not in the fixed Exchange tool map")
        if current.provider == "runpod" and operation_id == "cloud.resource.restart":
            pass
        elif current.provider != "runpod" and operation_id == "cloud.resource.restart":
            raise PermissionError("restart is supported only by RunPod profiles")
        selected = dict(arguments)
        if current.provider not in {"github", "hf"} and selected.get("profile_ref") != profile_ref:
            raise PermissionError("provider arguments do not bind the selected profile ref")
        if current.provider == "github":
            _validate_github_target(current, operation_id, selected)
        elif current.provider == "hf":
            self._validate_huggingface_target(current, operation_id, selected)
        else:
            self._validate_cloud_target(principal, current, operation_id, selected)
        if operation_id in {
            "cloud.vendor.cli.execute",
            "github.vendor.cli.execute",
            "huggingface.vendor.cli.execute",
        }:
            if "target" in selected:
                raise PermissionError("vendor CLI cannot select a model-supplied target")
            _reject_credential_export(selected)
        target_projection = _resource_projection(
            provider_id=canonical_provider,
            profile_ref=profile_ref,
            operation_id=operation_id,
            arguments=selected,
        )
        expected_resource_ref = _resource_ref(
            provider_id=canonical_provider,
            profile_ref=profile_ref,
            operation_id=operation_id,
            target=target_projection,
        )
        if resource_ref != expected_resource_ref:
            raise PermissionError("resource ref does not match canonical provider arguments")
        lease_target = (
            _account_lease_target(
                canonical_provider,
                operation_id,
                target_projection,
                selected,
            )
            if current.provider in {"github", "hf"}
            else None
        )
        return PreparedConnectorOperation(
            connection=current,
            connection_ref=str(current.id),
            principal=principal,
            provider_id=canonical_provider,
            profile_ref=profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=selected,
            tool_id=tool_id,
            request_id=request_id,
            target_projection=target_projection,
            account_lease_target=lease_target,
            expected_organization_id=current.organization_id,
            expected_workspace_id=current.workspace_id,
            is_mutating=operation_id in _MUTATING_OPERATIONS,
        )

    def prepare_teams_reply(
        self,
        *,
        principal: IntegrationPrincipal,
        profile: Any,
        provider_id: str,
        profile_ref: str,
        operation_id: str,
        resource_ref: str,
        arguments: Mapping[str, object],
        request_id: str,
    ) -> PreparedConnectorOperation:
        """Validate one fixed Teams outbound message under the configured tenant/team."""

        if (
            provider_id != "msteams"
            or profile_ref != profile.profile_ref
            or operation_id != "msteams.message.reply"
            or principal.issuer != profile.expected_issuer
            or principal.organization_id != profile.organization_id
            or principal.workspace_id != profile.workspace_id
        ):
            raise PermissionError("Teams actor or profile does not match the fixed host binding")
        profile.authorize_principal(principal)
        principal.require(operation_id)
        selected = dict(arguments)
        _exact_fields(selected, required={"conversation", "text"})
        conversation = selected["conversation"]
        if not isinstance(conversation, Mapping):
            raise PermissionError("Teams conversation scope is invalid")
        _exact_fields(
            conversation,
            required={
                "tenantId",
                "teamId",
                "channelId",
                "conversationId",
                "rootThreadId",
                "serviceUrl",
            },
        )
        try:
            profile.authorize_conversation(
                tenant_id=_text(conversation["tenantId"], "tenantId"),
                team_id=_text(conversation["teamId"], "teamId"),
                channel_id=_text(conversation["channelId"], "channelId"),
                conversation_id=_text(conversation["conversationId"], "conversationId"),
                root_thread_id=_text(conversation["rootThreadId"], "rootThreadId"),
                service_url=_text(conversation["serviceUrl"], "serviceUrl"),
            )
        except (ValueError, PermissionError) as exc:
            raise PermissionError("Teams conversation is outside the configured allowlist") from exc
        _text(conversation["conversationId"], "conversationId")
        try:
            validate_teams_root_thread_id(_text(conversation["rootThreadId"], "rootThreadId"))
        except ValueError as exc:
            raise PermissionError("Teams root activity id is not a channel message id") from exc
        try:
            validate_teams_service_url(
                _text(conversation["serviceUrl"], "serviceUrl"),
                tenant_id=_text(conversation["tenantId"], "tenantId"),
            )
        except ValueError as exc:
            raise PermissionError(
                "Teams service URL is outside the official route allowlist"
            ) from exc
        text = _text(selected["text"], "text")
        if len(text) > 24_000:
            raise ValueError("Teams reply exceeds the configured size limit")
        selected["conversation"] = dict(conversation)
        projection: dict[str, object] = {"conversation": dict(conversation)}
        expected_resource = teams_resource_ref(dict(conversation))
        if resource_ref != expected_resource:
            raise PermissionError("Teams resource ref does not match the canonical thread")
        return PreparedConnectorOperation(
            connection=None,
            connection_ref=profile.connection_ref,
            principal=principal,
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=selected,
            tool_id="msteams.message.reply",
            request_id=request_id,
            target_projection=projection,
            account_lease_target=None,
            expected_organization_id=profile.organization_id,
            expected_workspace_id=profile.workspace_id,
            is_mutating=False,
        )

    def prepare_computer_operation(
        self,
        *,
        principal: IntegrationPrincipal,
        profile: ComputerRunnerProfile,
        connection_ref: str,
        provider_id: str,
        profile_ref: str,
        operation_id: str,
        resource_ref: str,
        arguments: Mapping[str, object],
        request_id: str,
    ) -> PreparedConnectorOperation:
        """Validate one exact Directory-authorized operation for the host runner."""

        if (
            provider_id != "computer"
            or profile != self._computer_runner_profile
            or connection_ref != profile.connection_ref
            or profile_ref != profile.profile_ref
        ):
            raise PermissionError("computer runner does not match its host-owned profile")
        connection_lookup = getattr(self._store, "current_connection_for_provider_call", None)
        if (
            callable(connection_lookup)
            and connection_lookup(UUID(profile.connection_ref)) is not None
        ):
            raise PermissionError("computer runner reference collides with an external connection")
        profile.authorize_principal(principal)
        principal.require(operation_id)
        tool_id = _TOOL_IDS_BY_PROVIDER["computer"].get(operation_id)
        if tool_id is None:
            raise PermissionError("computer operation is not in the fixed Exchange tool map")
        selected = dict(arguments)
        _validate_computer_target(profile, operation_id, selected)
        target_projection = _resource_projection(
            provider_id="computer",
            profile_ref=profile_ref,
            operation_id=operation_id,
            arguments=selected,
            workspace_ref=profile.connection_ref,
        )
        expected_resource_ref = _resource_ref(
            provider_id="computer",
            profile_ref=profile_ref,
            operation_id=operation_id,
            target=target_projection,
        )
        if resource_ref != expected_resource_ref:
            raise PermissionError("computer resource ref does not match its host workspace target")
        return PreparedConnectorOperation(
            connection=None,
            connection_ref=profile.connection_ref,
            principal=principal,
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=selected,
            tool_id=tool_id,
            request_id=request_id,
            target_projection=target_projection,
            account_lease_target=None,
            expected_organization_id=profile.organization_id,
            expected_workspace_id=profile.workspace_id,
            is_mutating=operation_id in _MUTATING_OPERATIONS,
        )

    def invoke(
        self,
        prepared: PreparedConnectorOperation,
        *,
        principal: IntegrationPrincipal,
        claims: ConnectorGrantClaims,
    ) -> dict[str, Any]:
        """Invoke a one-use grant-bound provider call and return only safe structured JSON."""

        connection = prepared.connection
        if prepared.provider_id == "computer":
            if connection is not None or self._computer is None:
                raise ValueError("computer provider is not configured for the host runner")
            if prepared.account_lease_target is not None:
                raise ValueError("computer operations do not use Account Center leases")
        elif connection is None or prepared.provider_id == "msteams":
            raise ValueError("Teams replies use the dedicated message connector route")
        if (
            not claims.grant_ref
            or claims.request_id != prepared.request_id
            or claims.organization_id != principal.organization_id
            or claims.workspace_id != principal.workspace_id
            or claims.principal_issuer != principal.issuer
            or claims.principal_subject != principal.subject
            or claims.connection_ref != prepared.connection_ref
            or claims.provider_id != prepared.provider_id
            or claims.profile_ref != prepared.profile_ref
            or claims.operation_id != prepared.operation_id
            or claims.resource_ref != prepared.resource_ref
            or claims.arguments_digest_sha256 != bytes.fromhex(digest_arguments(prepared.arguments))
        ):
            raise PermissionError("grant does not match the prepared operation")
        if prepared.provider_id == "computer":
            result = self._computer.call_provider_tool(
                tool_id=prepared.tool_id,
                payload=prepared.arguments,
            )
        elif prepared.provider_id in {"github", "huggingface"}:
            if connection is None:
                raise ValueError("provider connection is missing")
            if prepared.account_lease_target is None:
                raise ValueError("Account Center lease target is missing")
            payload = dict(prepared.arguments)
            payload_digest = digest_arguments(payload)
            if bytes.fromhex(payload_digest) != claims.arguments_digest_sha256:
                raise PermissionError("provider payload digest differs from the Directory grant")
            connector_grant = (
                _account_center_grant_proof(claims, arguments_sha256=payload_digest)
                if connection.access_mode == "workspace_operator"
                else None
            )
            lease = self._accounts.create_provider_credential_lease(
                principal,
                profile_ref=prepared.profile_ref,
                operation_id=prepared.operation_id,
                target=prepared.account_lease_target,
                arguments_sha256=payload_digest,
                connector_grant=connector_grant,
            )
            if (
                lease.profile_ref != prepared.profile_ref
                or lease.operation_id != prepared.operation_id
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_RESPONSE_INVALID",
                    title="Account Center response invalid",
                    detail="Account Center returned a credential lease with a mismatched scope.",
                    status=502,
                )
            if prepared.provider_id == "github":
                result = self._github.call_provider_tool(
                    principal,
                    tool_id=prepared.tool_id,
                    profile_ref=prepared.profile_ref,
                    lease_ref=lease.lease_ref,
                    payload=payload,
                )
            else:
                if self._authorization_cloud is None:
                    raise _connector_not_configured("huggingface_provider_not_configured")
                invocation_arguments = {
                    "profile_ref": prepared.profile_ref,
                    "lease_ref": lease.lease_ref,
                    "payload": payload,
                }
                result = self._authorization_cloud.invoke_connector_tool(
                    principal,
                    connection,
                    operation_id=prepared.operation_id,
                    tool_id=prepared.tool_id,
                    arguments=invocation_arguments,
                    request_id=prepared.request_id,
                )
        else:
            if self._authorization_cloud is None:
                raise _connector_not_configured("cloud_provider_not_configured")
            result = self._authorization_cloud.invoke_connector_tool(
                principal,
                connection,
                operation_id=prepared.operation_id,
                tool_id=prepared.tool_id,
                arguments=prepared.arguments,
                request_id=prepared.request_id,
            )
        safe_result = _safe_provider_result(result)
        if prepared.operation_id in {
            "cloud.vendor.cli.execute",
            "github.vendor.cli.execute",
            "huggingface.vendor.cli.execute",
        }:
            safe_result = _without_cli_output(safe_result)
            safe_result["stdout_suppressed"] = True
            safe_result["stderr_suppressed"] = True
        return safe_result

    def _validate_huggingface_target(
        self,
        connection: IntegrationConnection,
        operation_id: str,
        arguments: Mapping[str, object],
    ) -> None:
        if self._registry is None:
            raise PermissionError("HF host profile is unavailable")
        profile = self._registry.settings.profiles.get(connection.binding_ref or "")
        alias = profile.targets.get(connection.target_ref or "") if profile is not None else None
        if profile is None or profile.provider != "hf" or alias is None:
            raise PermissionError("HF connection target is not configured")
        if operation_id == "huggingface.vendor.cli.execute":
            _exact_fields(arguments, required={"argv"})
            _reject_credential_export(arguments)
            return
        if operation_id in {
            "huggingface.models.list",
            "huggingface.datasets.list",
            "huggingface.spaces.list",
        }:
            _exact_optional_fields(arguments, required=set(), optional={"search", "limit"})
            if "search" in arguments:
                _text(arguments["search"], "search", maximum=200)
            if "limit" in arguments:
                limit = arguments["limit"]
                if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
                    raise ValueError("limit must be between 1 and 100")
            return
        base_fields = {"repo_type", "repo_id"}
        if operation_id == "huggingface.repo.get":
            _exact_optional_fields(arguments, required=base_fields, optional=set())
        elif operation_id == "huggingface.file.download":
            _exact_optional_fields(
                arguments,
                required=base_fields | {"path"},
                optional={"revision"},
            )
            _validate_huggingface_path(arguments["path"])
            if "revision" in arguments:
                _text(arguments["revision"], "revision", maximum=300)
        elif operation_id == "huggingface.file.upload":
            _exact_optional_fields(
                arguments,
                required=base_fields | {"path", "content_base64"},
                optional={"revision"},
            )
            _validate_huggingface_path(arguments["path"])
            if "revision" in arguments:
                _text(arguments["revision"], "revision", maximum=300)
            encoded_content = arguments["content_base64"]
            if not isinstance(encoded_content, str) or len(encoded_content) > 1_398_104:
                raise ValueError("HF upload content exceeds the 1 MiB file limit")
            try:
                decoded_content = base64.b64decode(encoded_content, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("HF upload content must be valid base64") from exc
            if len(decoded_content) > 1_048_576:
                raise ValueError("HF upload content exceeds the 1 MiB file limit")
        else:
            raise PermissionError("HF operation is not supported by the Exchange argument map")
        repo_type = arguments.get("repo_type")
        repo_id = arguments.get("repo_id")
        scope = profile.account_scopes or {}
        repositories = scope.get("repositories")
        if (
            not isinstance(repo_type, str)
            or not isinstance(repo_id, str)
            or not isinstance(repositories, list)
            or not any(
                isinstance(item, Mapping)
                and item.get("repo_type") == repo_type
                and item.get("repo_id") == repo_id
                for item in repositories
            )
        ):
            raise PermissionError("HF repository is outside the host-configured profile scope")
        # The Account Center profile scope is authoritative for multi-repository HF
        # profiles. The connection target is a host alias, not a repository name.

    def _validate_cloud_target(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        operation_id: str,
        arguments: Mapping[str, object],
    ) -> None:
        if self._registry is None:
            raise PermissionError("cloud host profile is unavailable")
        try:
            _profile, _target_ref = self._registry.profile_for_connection(
                principal,
                connection,
                operation_id=operation_id,
            )
        except Exception as exc:
            raise PermissionError("cloud host profile or target is unavailable") from exc
        target = arguments.get("target")
        if operation_id in {"cloud.provider.health.read"}:
            if target is not None:
                raise PermissionError("cloud profile health does not accept a resource target")
            return
        if operation_id in {
            "cloud.operation.status.read",
            "cloud.operation.logs.read",
            "cloud.operation.cancel",
        }:
            _text(arguments.get("operation_ref"), "operation_ref")
            return
        if operation_id == "cloud.vendor.cli.execute":
            if "target" in arguments:
                raise PermissionError("cloud CLI cannot select a model-supplied target")
            argv = arguments.get("argv")
            if not isinstance(argv, list) or not argv:
                raise PermissionError("cloud CLI requires an argv array")
            return
        if not isinstance(target, Mapping) or not target:
            raise PermissionError("cloud operation requires a typed target object")


def connector_binding_tools(provider_id: str) -> list[dict[str, object]]:
    """Return the closed launcher map for one Exchange provider binding."""

    provider = _canonical_provider(provider_id)
    tools = _TOOL_IDS_BY_PROVIDER.get(provider)
    if tools is None:
        return []
    result: list[dict[str, object]] = []
    for operation_id, tool_id in sorted(tools.items()):
        if provider == "github":
            projection = (
                "profile"
                if operation_id in {"github.repository.list", "github.vendor.cli.execute"}
                else "github_pull_request"
                if operation_id == "github.pull_request.get"
                else "github_commit"
                if operation_id == "github.ci.status"
                else "github_actions_run"
                if operation_id in {"github.actions.jobs.list", "github.actions.rerun_failed"}
                else "github_actions_job"
                if operation_id == "github.actions.job.logs.read"
                else "github_branch"
                if operation_id
                in {
                    "github.branch.create",
                    "github.branch.delete",
                    "github.branch.get",
                }
                else "github_file"
                if operation_id in {"github.file.commit", "github.file.get"}
                else "github_pull_request_draft"
                if operation_id
                in {"github.pull_request.draft.create", "github.pull_request.draft.find"}
                else "github_issue"
                if operation_id.startswith("github.issue.")
                else "github_repository"
            )
        elif provider == "computer":
            projection = (
                "computer_workspace"
                if operation_id == "computer.command.execute"
                else "computer_file"
                if operation_id in {"computer.file.read", "computer.file.write"}
                else "computer_directory"
            )
        elif provider == "huggingface":
            projection = (
                "profile"
                if operation_id.endswith(".list")
                or operation_id == "huggingface.vendor.cli.execute"
                else "huggingface_repository"
            )
        elif operation_id == "cloud.vendor.cli.execute":
            projection = "profile"
        elif operation_id in {
            "cloud.operation.status.read",
            "cloud.operation.logs.read",
            "cloud.operation.cancel",
        }:
            projection = "cloud_operation"
        elif operation_id == "cloud.provider.health.read":
            projection = "profile"
        else:
            projection = "cloud_target"
        result.append(
            {
                "toolId": tool_id,
                "operationId": operation_id,
                "resourceProjection": projection,
                "mutating": operation_id in _MUTATING_OPERATIONS,
            }
        )
    return result


def _canonical_provider(provider_id: str) -> str:
    """Map persisted discriminators onto stable provider IDs used by Platform and Navigator."""

    return {"hf": "huggingface"}.get(provider_id, provider_id)


def _resource_projection(
    *,
    provider_id: str,
    profile_ref: str,
    operation_id: str,
    arguments: Mapping[str, object],
    workspace_ref: str | None = None,
) -> dict[str, object]:
    """Project only the provider resource selector used by the Directory grant."""

    if provider_id == "msteams":
        conversation = arguments.get("conversation")
        if not isinstance(conversation, Mapping):
            raise ValueError("Teams conversation projection is invalid")
        return {"conversation": dict(conversation)}
    if operation_id == "cloud.vendor.cli.execute":
        argv = arguments.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(item, str) for item in argv)
        ):
            raise ValueError("cloud CLI argv projection is invalid")
        return {"profile_ref": profile_ref}
    if operation_id in {
        "github.vendor.cli.execute",
        "huggingface.vendor.cli.execute",
    }:
        return {"profile_ref": profile_ref}
    if provider_id == "computer":
        if not isinstance(workspace_ref, str) or not workspace_ref:
            raise ValueError("computer workspace target is not host-bound")
        if operation_id == "computer.command.execute":
            return {"workspace_ref": workspace_ref}
        if operation_id in {
            "computer.file.read",
            "computer.file.write",
            "computer.directory.list",
        }:
            return {
                "workspace_ref": workspace_ref,
                "path": _text(arguments.get("path"), "path", maximum=4096),
            }
        raise PermissionError("computer operation is not in the fixed Exchange target map")
    if "target" in arguments:
        target = arguments["target"]
        if not isinstance(target, Mapping) or not target:
            raise ValueError("provider target projection must be a non-empty object")
        return dict(target)
    if provider_id == "github":
        if operation_id == "github.repository.list":
            return {"profile_ref": profile_ref}
        target = _fields(arguments, {"repository_id", "repository"})
        if operation_id == "github.pull_request.get":
            target.update(_fields(arguments, {"pull_number"}))
        elif operation_id == "github.ci.status":
            target.update(_fields(arguments, {"commit_sha"}))
        elif operation_id.startswith("github.issue."):
            target.update(_fields(arguments, {"issue_number"}))
        elif operation_id == "github.actions.jobs.list":
            target.update(_fields(arguments, {"run_id"}))
        elif operation_id == "github.actions.job.logs.read":
            target.update(_fields(arguments, {"run_id", "job_id"}))
        elif operation_id == "github.actions.rerun_failed":
            target.update(_fields(arguments, {"run_id"}))
        elif operation_id in {
            "github.branch.create",
            "github.branch.delete",
            "github.branch.get",
        }:
            target.update(_fields(arguments, {"branch"}))
        elif operation_id in {"github.file.commit", "github.file.get"}:
            target.update(_fields(arguments, {"branch", "path"}))
        elif operation_id in {
            "github.pull_request.draft.create",
            "github.pull_request.draft.find",
        }:
            target.update(_fields(arguments, {"head_branch", "base_branch"}))
        return target
    if provider_id == "huggingface":
        if operation_id in {
            "huggingface.models.list",
            "huggingface.datasets.list",
            "huggingface.spaces.list",
        }:
            return {"profile_ref": profile_ref}
        keys = {"repo_type", "repo_id"}
        if operation_id in {"huggingface.file.download", "huggingface.file.upload"}:
            keys.add("path")
        if "revision" in arguments:
            keys.add("revision")
        return _fields(arguments, keys)
    if operation_id in {
        "cloud.operation.status.read",
        "cloud.operation.logs.read",
        "cloud.operation.cancel",
    }:
        return _fields(arguments, {"operation_ref"})
    return {"profile_ref": profile_ref}


def _resource_ref(
    *,
    provider_id: str,
    profile_ref: str,
    operation_id: str,
    target: Mapping[str, object],
) -> str:
    """Hash exact public provider/profile/action/resource scope for Platform signing."""

    payload = {
        "providerId": provider_id,
        "profileRef": profile_ref,
        "operationId": operation_id,
        "target": dict(target),
    }
    return "sha256:" + hashlib.sha256(connector_canonical_json(payload)).hexdigest()


def _account_lease_target(
    provider_id: str,
    operation_id: str,
    resource_projection: Mapping[str, object],
    arguments: Mapping[str, object],
) -> dict[str, object]:
    """Return the Account Center-specific profile target for one one-use lease."""

    if provider_id == "github" and operation_id == "github.repository.list":
        return {}
    hf_list_targets = {
        "huggingface.models.list": "model",
        "huggingface.datasets.list": "dataset",
        "huggingface.spaces.list": "space",
    }
    if provider_id == "huggingface" and operation_id in hf_list_targets:
        return {"repo_type": hf_list_targets[operation_id]}
    if operation_id in {
        "github.vendor.cli.execute",
        "huggingface.vendor.cli.execute",
    }:
        return {}
    if provider_id == "github" and operation_id == "github.actions.runs.list":
        result = dict(resource_projection)
        for field in ("branch", "commit_sha"):
            value = arguments.get(field)
            if value is not None:
                result[field] = value
        return result
    return dict(resource_projection)


def teams_resource_ref(conversation: Mapping[str, object]) -> str:
    """Bind Teams output to the exact canonical tenant/team/channel/root thread."""

    return "sha256:" + hashlib.sha256(connector_canonical_json(dict(conversation))).hexdigest()


def _fields(arguments: Mapping[str, object], names: set[str]) -> dict[str, object]:
    selected = {name: arguments[name] for name in sorted(names) if name in arguments}
    if not selected or any(value is None for value in selected.values()):
        raise ValueError("provider resource projection is incomplete")
    return selected


def _validate_github_target(
    connection: IntegrationConnection,
    operation_id: str,
    arguments: Mapping[str, object],
) -> None:
    if operation_id == "github.vendor.cli.execute":
        _exact_fields(arguments, required={"argv"})
        _reject_credential_export(arguments)
        return
    if operation_id == "github.repository.list":
        _exact_fields(arguments, required=set())
        return
    repository_fields = {"repository_id", "repository"}
    optional_fields: set[str] = set()
    if operation_id == "github.pull_requests.list":
        optional_fields = {"state"}
    elif operation_id == "github.pull_request.get":
        optional_fields = {"pull_number"}
    elif operation_id == "github.actions.runs.list":
        optional_fields = {"branch", "commit_sha"}
    elif operation_id == "github.issues.search":
        optional_fields = {
            "state",
            "limit",
            "query",
            "labels",
            "updated_since",
            "page_cursor",
        }
    elif operation_id == "github.actions.jobs.list":
        optional_fields = {"run_id", "limit"}
    elif operation_id == "github.actions.job.logs.read":
        optional_fields = {"run_id", "job_id", "max_lines"}
    elif operation_id == "github.branch.create":
        optional_fields = {"branch", "from_sha"}
    elif operation_id == "github.branch.delete":
        optional_fields = {"branch", "expected_sha"}
    elif operation_id == "github.branch.get":
        optional_fields = {"branch"}
    elif operation_id == "github.file.commit":
        optional_fields = {"branch", "path", "message", "content_base64", "expected_sha"}
    elif operation_id == "github.file.get":
        optional_fields = {"branch", "path"}
    elif operation_id == "github.pull_request.draft.create":
        optional_fields = {"head_branch", "base_branch", "title", "body"}
    elif operation_id == "github.pull_request.draft.find":
        optional_fields = {"head_branch", "base_branch"}
    elif operation_id == "github.actions.rerun_failed":
        optional_fields = {
            "run_id",
            "expected_workflow_id",
            "expected_head_branch",
            "expected_head_sha",
            "expected_attempt",
        }
    elif operation_id == "github.ci.status":
        optional_fields = {"commit_sha"}
    elif operation_id in {
        "github.issue.get",
        "github.issue.comment.create",
        "github.issue.state.update",
    }:
        optional_fields = {"issue_number"}
        if operation_id == "github.issue.comment.create":
            optional_fields.add("body")
        elif operation_id == "github.issue.state.update":
            optional_fields.add("state")
    elif operation_id not in {"github.repository.get", "github.branches.list"}:
        raise PermissionError("GitHub operation is not supported by the Exchange argument map")
    required_fields = set() if operation_id.startswith("github.issue.") else repository_fields
    if operation_id.startswith("github.issue."):
        required_fields = repository_fields | {"issue_number"}
        if operation_id == "github.issue.comment.create":
            required_fields.add("body")
        elif operation_id == "github.issue.state.update":
            required_fields.add("state")
        optional_fields = set()
    elif operation_id == "github.pull_request.get":
        required_fields |= {"pull_number"}
        optional_fields = set()
    elif operation_id == "github.ci.status":
        required_fields |= {"commit_sha"}
        optional_fields = set()
    elif operation_id == "github.issues.search":
        required_fields |= {"state", "limit"}
        optional_fields = {"query", "labels", "updated_since", "page_cursor"}
    elif operation_id == "github.actions.jobs.list":
        required_fields |= {"run_id", "limit"}
        optional_fields = set()
    elif operation_id == "github.actions.job.logs.read":
        required_fields |= {"run_id", "job_id", "max_lines"}
        optional_fields = set()
    elif operation_id == "github.branch.create":
        required_fields |= {"branch", "from_sha"}
        optional_fields = set()
    elif operation_id == "github.branch.delete":
        required_fields |= {"branch", "expected_sha"}
        optional_fields = set()
    elif operation_id == "github.branch.get":
        required_fields |= {"branch"}
        optional_fields = set()
    elif operation_id == "github.file.commit":
        required_fields |= {"branch", "path", "message", "content_base64"}
        optional_fields = {"expected_sha"}
    elif operation_id == "github.file.get":
        required_fields |= {"branch", "path"}
        optional_fields = set()
    elif operation_id == "github.pull_request.draft.create":
        required_fields |= {"head_branch", "base_branch", "title", "body"}
        optional_fields = set()
    elif operation_id == "github.pull_request.draft.find":
        required_fields |= {"head_branch", "base_branch"}
        optional_fields = set()
    elif operation_id == "github.actions.rerun_failed":
        required_fields |= {
            "run_id",
            "expected_workflow_id",
            "expected_head_branch",
            "expected_head_sha",
            "expected_attempt",
        }
        optional_fields = set()
    _exact_optional_fields(arguments, required=required_fields, optional=optional_fields)
    repository_id = arguments.get("repository_id")
    repository = arguments.get("repository")
    if (
        not isinstance(repository_id, str)
        or not re.fullmatch(r"[0-9]+", repository_id)
        or not isinstance(repository, str)
        or not _GITHUB_REPOSITORY.fullmatch(repository)
    ):
        raise ValueError("GitHub repository identity is malformed")
    if repository_id != connection.repository_id or repository != connection.repository_name:
        raise PermissionError("GitHub repository does not match the selected connection")
    if operation_id == "github.pull_request.get":
        _positive_int(arguments.get("pull_number"), "pull_number")
    elif operation_id == "github.ci.status":
        _text(arguments.get("commit_sha"), "commit_sha")
    elif operation_id.startswith("github.issue."):
        _positive_int(arguments.get("issue_number"), "issue_number")
        if operation_id == "github.issue.comment.create":
            _text(arguments.get("body"), "body")
        elif operation_id == "github.issue.state.update" and arguments.get("state") not in {
            "OPEN",
            "CLOSED",
        }:
            raise ValueError("GitHub issue state must be OPEN or CLOSED")
    elif operation_id == "github.pull_requests.list" and "state" in arguments:
        if arguments["state"] not in {"OPEN", "CLOSED", "ALL"}:
            raise ValueError("GitHub pull request state is invalid")
    elif operation_id == "github.actions.runs.list":
        for field in ("branch", "commit_sha"):
            if field in arguments:
                _text(arguments[field], field)
    elif operation_id == "github.issues.search":
        if arguments.get("state") not in {"OPEN", "CLOSED", "ALL"}:
            raise ValueError("GitHub issue search state is invalid")
        limit = _bounded_int(arguments.get("limit"), "limit", minimum=1, maximum=50)
        if "query" in arguments:
            query = _text(arguments["query"], "query", maximum=128)
            if not query.isascii() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}", query):
                raise ValueError("GitHub issue search query has an invalid format")
        if "labels" in arguments:
            labels = arguments["labels"]
            if (
                not isinstance(labels, list)
                or len(labels) > 10
                or any(
                    not isinstance(label, str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,49}", label)
                    for label in labels
                )
                or len(set(labels)) != len(labels)
            ):
                raise ValueError("GitHub issue search labels are invalid")
        if "updated_since" in arguments:
            updated_since = arguments["updated_since"]
            if not isinstance(updated_since, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)",
                updated_since,
            ):
                raise ValueError("GitHub updated_since must be a UTC RFC 3339 timestamp")
            try:
                parsed_timestamp = (
                    updated_since[:-1] + "+00:00" if updated_since.endswith("Z") else updated_since
                )
                datetime.fromisoformat(parsed_timestamp)
            except ValueError as exc:
                raise ValueError("GitHub updated_since is not a valid timestamp") from exc
        if "page_cursor" in arguments:
            page_cursor = arguments["page_cursor"]
            if not isinstance(page_cursor, str) or not re.fullmatch(
                r"[1-9][0-9]{0,3}", page_cursor
            ):
                raise ValueError("GitHub issue search page_cursor must be a positive page number")
            maximum_page = (1000 + limit - 1) // limit
            if int(page_cursor) > maximum_page:
                raise ValueError(
                    "GitHub issue search page_cursor exceeds the bounded result window"
                )
    elif operation_id == "github.actions.jobs.list":
        _numeric_resource_id(arguments.get("run_id"), "run_id")
        _bounded_int(arguments.get("limit"), "limit", minimum=1, maximum=100)
    elif operation_id == "github.actions.job.logs.read":
        _numeric_resource_id(arguments.get("run_id"), "run_id")
        _numeric_resource_id(arguments.get("job_id"), "job_id")
        _bounded_int(arguments.get("max_lines"), "max_lines", minimum=1, maximum=200)
    elif operation_id == "github.branch.create":
        _validate_github_branch(arguments.get("branch"), allow_protected=False)
        _validate_github_sha(arguments.get("from_sha"), "from_sha")
    elif operation_id == "github.branch.delete":
        _validate_github_branch(arguments.get("branch"), allow_protected=False)
        _validate_github_sha(arguments.get("expected_sha"), "expected_sha")
    elif operation_id == "github.branch.get":
        _validate_github_branch(arguments.get("branch"), allow_protected=True)
    elif operation_id == "github.file.commit":
        _validate_github_branch(arguments.get("branch"), allow_protected=False)
        _validate_github_path(arguments.get("path"))
        _text(arguments.get("message"), "message", maximum=200)
        if "expected_sha" in arguments:
            _validate_github_sha(arguments["expected_sha"], "expected_sha")
        _validate_github_content(arguments.get("content_base64"))
    elif operation_id == "github.file.get":
        _validate_github_branch(arguments.get("branch"), allow_protected=True)
        _validate_github_path(arguments.get("path"))
    elif operation_id == "github.pull_request.draft.create":
        _validate_github_branch(arguments.get("head_branch"), allow_protected=False)
        _validate_github_branch(arguments.get("base_branch"), allow_protected=True)
        if arguments["head_branch"] == arguments["base_branch"]:
            raise ValueError("GitHub pull request branches must differ")
        _text(arguments.get("title"), "title", maximum=256)
        body = arguments.get("body")
        if not isinstance(body, str) or len(body) > 65_536:
            raise ValueError("GitHub pull request body exceeds the configured limit")
    elif operation_id == "github.pull_request.draft.find":
        _validate_github_branch(arguments.get("head_branch"), allow_protected=False)
        _validate_github_branch(arguments.get("base_branch"), allow_protected=True)
        if arguments["head_branch"] == arguments["base_branch"]:
            raise ValueError("GitHub pull request branches must differ")
    elif operation_id == "github.actions.rerun_failed":
        _numeric_resource_id(arguments.get("run_id"), "run_id")
        _numeric_resource_id(arguments.get("expected_workflow_id"), "expected_workflow_id")
        expected_head_branch = _validate_github_branch(
            arguments.get("expected_head_branch"), allow_protected=False
        )
        if not expected_head_branch.casefold().startswith("cyrene/assistant/"):
            raise PermissionError("GitHub workflow reruns require an assistant task branch")
        _validate_github_sha(arguments.get("expected_head_sha"), "expected_head_sha")
        _bounded_int(
            arguments.get("expected_attempt"),
            "expected_attempt",
            minimum=1,
            maximum=2_147_483_647,
        )
    elif operation_id == "github.pull_request.get" or operation_id == "github.repository.get":
        return


def _bounded_int(value: object, label: str, *, minimum: int, maximum: int) -> int:
    """Require one bounded JSON integer without accepting bool as an integer."""

    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _numeric_resource_id(value: object, label: str) -> str:
    """Require a decimal resource id as text to preserve 64-bit precision."""

    if (
        not isinstance(value, str)
        or len(value) > 20
        or not re.fullmatch(r"[1-9][0-9]{0,19}", value)
    ):
        raise ValueError(f"{label} must be a positive decimal resource id string")
    return value


def _validate_github_sha(value: object, label: str) -> str:
    """Require the full GitHub SHA form used for optimistic write checks."""

    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", value):
        raise ValueError(f"{label} must be a full 40-character hexadecimal SHA")
    return value


def _validate_github_branch(value: object, *, allow_protected: bool) -> str:
    """Reject malformed refs and prevent protected names from branch writes."""

    if not isinstance(value, str) or len(value) > 255 or not value:
        raise ValueError("GitHub branch must be bounded non-empty text")
    parts = value.split("/")
    if (
        not _GITHUB_BRANCH.fullmatch(value)
        or value.startswith("/")
        or value.endswith(("/", "."))
        or "//" in value
        or "@{" in value
        or any(
            part in {"", ".", ".."} or part.startswith(".") or part.endswith(".lock")
            for part in parts
        )
    ):
        raise ValueError("GitHub branch is not a safe Git reference")
    if not allow_protected and _is_protected_branch(value):
        raise PermissionError("protected branch names are outside the task-branch write allowlist")
    return value


def _is_protected_branch(value: str) -> bool:
    """Identify branch names reserved for primary, release, or deployment targets."""

    lowered = value.casefold()
    return lowered in _GITHUB_PROTECTED_BRANCHES or lowered.startswith(
        _GITHUB_PROTECTED_BRANCH_PREFIXES
    )


def _validate_github_path(value: object) -> str:
    """Reject hidden and deployment/configuration paths from assistant file operations."""

    if not isinstance(value, str) or len(value) > 512 or not _GITHUB_PATH.fullmatch(value):
        raise ValueError("GitHub file path is invalid")
    parts = value.split("/")
    lowered_parts = [part.casefold() for part in parts]
    if (
        any(part in {"", ".", ".."} or part.startswith(".") for part in parts)
        or any(part in _GITHUB_PROTECTED_PATH_DIRECTORIES for part in lowered_parts)
        or lowered_parts[-1] in _GITHUB_PROTECTED_PATH_FILES
        or lowered_parts[-1].startswith("dockerfile")
        or any(_GITHUB_SENSITIVE_PATH_SEGMENT.search(part) for part in lowered_parts)
    ):
        raise PermissionError("hidden or deployment configuration paths are blocked")
    return value


def _validate_github_content(value: object) -> bytes:
    """Decode a bounded base64 file body without retaining it in the lease target."""

    if not isinstance(value, str) or len(value) > 666_668:
        raise ValueError("GitHub file content exceeds the configured limit")
    try:
        content = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("GitHub file content must be valid base64") from exc
    if len(content) > 500_000:
        raise ValueError("GitHub file content exceeds the configured limit")
    if base64.b64encode(content).decode("ascii") != value:
        raise ValueError("GitHub file content must use canonical base64 encoding")
    return content


def _validate_computer_target(
    profile: ComputerRunnerProfile,
    operation_id: str,
    arguments: Mapping[str, object],
) -> None:
    """Validate fixed computer operations before they receive a Directory grant."""

    path_max_bytes = _COMPUTER_MAX_PATH_BYTES
    if operation_id == "computer.command.execute":
        _exact_optional_fields(arguments, required={"command"}, optional={"cwd", "timeout_ms"})
        command = arguments["command"]
        if (
            not isinstance(command, str)
            or not command.strip()
            or "\x00" in command
            or len(command) > _COMPUTER_MAX_COMMAND_CHARS
            or len(command.encode("utf-8")) > _COMPUTER_MAX_COMMAND_BYTES
        ):
            raise ValueError("computer command must be bounded non-empty text without NUL")
        if "cwd" in arguments:
            _validate_computer_path(
                arguments["cwd"], "cwd", max_bytes=path_max_bytes, allow_root=True
            )
        if "timeout_ms" in arguments:
            _bounded_int(
                arguments["timeout_ms"],
                "timeout_ms",
                minimum=1,
                maximum=profile.max_command_timeout_ms,
            )
        return
    if operation_id == "computer.file.read":
        _exact_optional_fields(
            arguments,
            required={"path", "length"},
            optional={"offset"},
        )
        _validate_computer_path(arguments["path"], "path", max_bytes=path_max_bytes)
        _bounded_int(
            arguments["length"],
            "length",
            minimum=0,
            maximum=min(profile.max_read_bytes, _COMPUTER_MAX_READ_BYTES),
        )
        if "offset" in arguments:
            _bounded_int(arguments["offset"], "offset", minimum=0, maximum=(1 << 63) - 1)
        return
    if operation_id == "computer.file.write":
        _exact_fields(arguments, required={"path", "content_base64", "overwrite"})
        _validate_computer_path(arguments["path"], "path", max_bytes=path_max_bytes)
        if not isinstance(arguments["overwrite"], bool):
            raise ValueError("computer overwrite must be boolean")
        _validate_bounded_base64(
            arguments["content_base64"],
            label="content_base64",
            maximum_bytes=profile.max_file_bytes,
        )
        return
    if operation_id == "computer.directory.list":
        _exact_optional_fields(arguments, required={"path"}, optional={"max_depth"})
        _validate_computer_path(
            arguments["path"], "path", max_bytes=path_max_bytes, allow_root=True
        )
        if "max_depth" in arguments:
            _bounded_int(
                arguments["max_depth"],
                "max_depth",
                minimum=1,
                maximum=profile.max_directory_depth,
            )
        return
    raise PermissionError("computer operation is not in the fixed Exchange argument map")


def _validate_computer_path(
    value: object,
    label: str,
    *,
    max_bytes: int,
    allow_root: bool = False,
) -> str:
    """Require a workspace-relative path that cannot traverse above the fixed root."""

    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or value.startswith("/")
        or len(value) > _COMPUTER_MAX_PATH_CHARS
        or len(value.encode("utf-8")) > max_bytes
        or (value == "." and not allow_root)
        or (value != "." and any(segment in {"", ".", ".."} for segment in value.split("/")))
    ):
        raise ValueError(f"{label} must be a bounded workspace-relative path")
    return value


def _validate_bounded_base64(value: object, *, label: str, maximum_bytes: int) -> bytes:
    """Decode canonical base64 only after applying the host profile's byte limit."""

    encoded_limit = ((maximum_bytes + 2) // 3) * 4
    if not isinstance(value, str) or len(value) > encoded_limit:
        raise ValueError(f"{label} exceeds the configured content limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} must be valid base64") from exc
    if len(decoded) > maximum_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} must use canonical base64 within the configured limit")
    return decoded


def validate_computer_tool_schema(
    profile: ComputerRunnerProfile,
    *,
    tool_id: str,
    input_schema: Mapping[str, Any],
) -> None:
    """Require provider-advertised tool schemas to stay within host limits."""

    schema_properties = input_schema.get("properties")
    schema_required = input_schema.get("required")
    if (
        input_schema.get("type") != "object"
        or input_schema.get("additionalProperties") is not False
        or not isinstance(schema_properties, Mapping)
        or not isinstance(schema_required, list)
    ):
        raise ValueError("computer tool schema must be a closed object")

    operation_fields: dict[str, tuple[set[str], set[str]]] = {
        "computer.command.execute": ({"command"}, {"cwd", "timeout_ms"}),
        "computer.file.read": ({"path", "length"}, {"offset"}),
        "computer.file.write": ({"path", "content_base64", "overwrite"}, set()),
        "computer.directory.list": ({"path"}, {"max_depth"}),
    }
    fields = operation_fields.get(tool_id)
    if fields is None:
        raise ValueError("computer tool schema is outside the fixed operation map")
    required, optional = fields
    properties = set(schema_properties)
    if properties != required | optional or set(schema_required) != required:
        raise ValueError("computer tool schema fields do not match the fixed operation contract")

    def integer_bound(field_name: str, *, minimum: int, maximum: int) -> None:
        field = schema_properties.get(field_name)
        if (
            not isinstance(field, Mapping)
            or field.get("type") != "integer"
            or isinstance(field.get("minimum"), bool)
            or not isinstance(field.get("minimum"), int)
            or field["minimum"] < minimum
            or isinstance(field.get("maximum"), bool)
            or not isinstance(field.get("maximum"), int)
            or field["maximum"] > maximum
        ):
            raise ValueError(f"computer tool {field_name} schema exceeds the host limit")

    if "command" in required:
        command = schema_properties.get("command")
        if (
            not isinstance(command, Mapping)
            or command.get("type") != "string"
            or isinstance(command.get("maxLength"), bool)
            or not isinstance(command.get("maxLength"), int)
            or command["maxLength"] > _COMPUTER_MAX_COMMAND_CHARS
            or isinstance(command.get("x-maxUtf8Bytes"), bool)
            or not isinstance(command.get("x-maxUtf8Bytes"), int)
            or command["x-maxUtf8Bytes"] > _COMPUTER_MAX_COMMAND_BYTES
        ):
            raise ValueError("computer command schema exceeds the host text limits")
        if "cwd" in optional:
            path_schema = schema_properties.get("cwd")
            if (
                not isinstance(path_schema, Mapping)
                or path_schema.get("type") != "string"
                or isinstance(path_schema.get("maxLength"), bool)
                or not isinstance(path_schema.get("maxLength"), int)
                or path_schema["maxLength"] > _COMPUTER_MAX_PATH_CHARS
                or isinstance(path_schema.get("x-maxUtf8Bytes"), bool)
                or not isinstance(path_schema.get("x-maxUtf8Bytes"), int)
                or path_schema["x-maxUtf8Bytes"] > _COMPUTER_MAX_PATH_BYTES
            ):
                raise ValueError("computer cwd schema exceeds the host path limits")
        if "timeout_ms" in optional:
            integer_bound(
                "timeout_ms",
                minimum=1,
                maximum=profile.max_command_timeout_ms,
            )
    if "path" in required:
        path = schema_properties.get("path")
        if (
            not isinstance(path, Mapping)
            or path.get("type") != "string"
            or isinstance(path.get("maxLength"), bool)
            or not isinstance(path.get("maxLength"), int)
            or path["maxLength"] > _COMPUTER_MAX_PATH_CHARS
            or isinstance(path.get("x-maxUtf8Bytes"), bool)
            or not isinstance(path.get("x-maxUtf8Bytes"), int)
            or path["x-maxUtf8Bytes"] > _COMPUTER_MAX_PATH_BYTES
        ):
            raise ValueError("computer path schema exceeds the host path limits")
    if tool_id == "computer.file.read":
        integer_bound("length", minimum=0, maximum=profile.max_read_bytes)
        if "offset" in optional:
            integer_bound("offset", minimum=0, maximum=(1 << 63) - 1)
    elif tool_id == "computer.file.write":
        content = schema_properties.get("content_base64")
        encoded_limit = ((profile.max_file_bytes + 2) // 3) * 4
        overwrite = schema_properties.get("overwrite")
        if (
            not isinstance(content, Mapping)
            or content.get("type") != "string"
            or isinstance(content.get("maxLength"), bool)
            or not isinstance(content.get("maxLength"), int)
            or content["maxLength"] > encoded_limit
            or not isinstance(overwrite, Mapping)
            or overwrite.get("type") != "boolean"
        ):
            raise ValueError("computer file.write schema exceeds the host file limits")
    elif tool_id == "computer.directory.list" and "max_depth" in optional:
        integer_bound("max_depth", minimum=1, maximum=profile.max_directory_depth)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _text(value: object, label: str, *, maximum: int = 24_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be bounded non-empty text")
    return value


def _exact_fields(value: Mapping[str, object], *, required: set[str]) -> None:
    if set(value) != required:
        raise ValueError("connector argument fields do not match the fixed operation schema")


def _exact_optional_fields(
    value: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str],
) -> None:
    keys = set(value)
    if not required <= keys or keys - required - optional:
        raise ValueError("connector argument fields do not match the fixed operation schema")


def _validate_huggingface_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("HF repository path is invalid")
    if (
        value.startswith("/")
        or "\\" in value
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise ValueError("HF repository path is invalid")
    return value


def _reject_credential_export(arguments: Mapping[str, object]) -> None:
    argv = arguments.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 128
        or any(not isinstance(item, str) or len(item) > 4096 for item in argv)
    ):
        raise ValueError("vendor CLI requires a bounded typed argv array")
    lowered = [item.strip().lower() for item in argv]
    if any(any(word in item for word in _CLI_SECRET_WORDS) for item in lowered):
        raise PermissionError("cloud vendor CLI credential export is blocked")
    for pattern in _CLI_EXPORT_PATTERNS:
        if any(
            tuple(lowered[index : index + len(pattern)]) == pattern for index in range(len(lowered))
        ):
            raise PermissionError("cloud vendor CLI credential export is blocked")


def _safe_provider_result(result: object) -> dict[str, Any]:
    """Reject credential-bearing or oversized provider result projections."""

    if not isinstance(result, Mapping):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
            title="Provider response invalid",
            detail="The provider must return one structured JSON object.",
            status=502,
        )
    forbidden = {
        "accesstoken",
        "apikey",
        "authorization",
        "bearertoken",
        "clientsecret",
        "credential",
        "credentialvalue",
        "idtoken",
        "password",
        "privatekey",
        "refreshtoken",
        "secret",
        "token",
    }

    def inspect(value: object) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized = (
                    key.lower().replace("_", "").replace("-", "") if isinstance(key, str) else ""
                )
                if normalized in forbidden:
                    raise ExchangeProductError(
                        code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
                        title="Provider response invalid",
                        detail="The provider attempted to return credential material.",
                        status=502,
                    )
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect(result)
    try:
        encoded = connector_canonical_json(dict(result))
    except ExchangeProductError as exc:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
            title="Provider response invalid",
            detail="The provider result is outside the RFC 8785 JSON domain.",
            status=502,
        ) from exc
    if len(encoded) > 1_100_000:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_TOO_LARGE",
            title="Provider response is too large",
            detail="The provider result exceeds Exchange's bounded response size.",
            status=502,
        )
    return dict(result)


def _without_cli_output(value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove captured command output recursively before any provider response escapes."""

    forbidden = {"stdout", "stderr", "rawoutput", "commandoutput"}

    def project(item: object) -> object:
        if isinstance(item, Mapping):
            return {
                key: project(child)
                for key, child in item.items()
                if not isinstance(key, str)
                or key.lower().replace("_", "").replace("-", "") not in forbidden
            }
        if isinstance(item, list):
            return [project(child) for child in item]
        return item

    projected = project(value)
    if not isinstance(projected, dict):
        raise ValueError("CLI result projection must remain a JSON object")
    return projected


def _account_center_grant_proof(
    claims: ConnectorGrantClaims,
    *,
    arguments_sha256: str,
) -> dict[str, object]:
    """Project only the exact consumed Authority grant claims for a shared lease."""

    if (
        len(arguments_sha256) != 64
        or claims.arguments_digest_sha256.hex() != arguments_sha256
        or claims.expires_at_epoch <= claims.issued_at_epoch
        or claims.expires_at_epoch - claims.issued_at_epoch > 15
    ):
        raise PermissionError("shared provider lease grant proof is invalid")
    return {
        "grant_ref": claims.grant_ref,
        "issued_at": int(claims.issued_at_epoch),
        "expires_at": int(claims.expires_at_epoch),
        "issuer": claims.principal_issuer,
        "subject": claims.principal_subject,
        "organization_id": claims.organization_id,
        "workspace_id": claims.workspace_id,
        "connection_ref": claims.connection_ref,
        "provider_id": claims.provider_id,
        "profile_ref": claims.profile_ref,
        "operation_id": claims.operation_id,
        "resource_ref": claims.resource_ref,
        "arguments_sha256": arguments_sha256,
    }


def _connector_not_configured(reason_code: str) -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
        title="Connector provider is not configured",
        detail="Exchange cannot dispatch this provider operation.",
        status=503,
        retryable=True,
        context={"reasonCode": reason_code},
    )
