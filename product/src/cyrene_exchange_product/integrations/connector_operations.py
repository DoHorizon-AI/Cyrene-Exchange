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
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.connector_profiles import (
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
}
_MUTATING_OPERATIONS = frozenset(
    {
        "github.issue.comment.create",
        "github.issue.state.update",
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


@dataclass(frozen=True, slots=True)
class PreparedConnectorOperation:
    """One validated, grant-bound provider operation ready for a one-time call."""

    connection: IntegrationConnection | None
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
    ) -> None:
        self._store = store
        self._accounts = accounts
        self._github = github
        self._authorization_cloud = authorization_cloud
        self._registry = registry

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

    def invoke(
        self,
        prepared: PreparedConnectorOperation,
        *,
        principal: IntegrationPrincipal,
        claims: ConnectorGrantClaims,
    ) -> dict[str, Any]:
        """Invoke a one-use grant-bound provider call and return only safe structured JSON."""

        connection = prepared.connection
        if connection is None or prepared.provider_id == "msteams":
            raise ValueError("Teams replies use the dedicated message connector route")
        if (
            not claims.grant_ref
            or claims.request_id != prepared.request_id
            or claims.organization_id != principal.organization_id
            or claims.workspace_id != principal.workspace_id
            or claims.principal_issuer != principal.issuer
            or claims.principal_subject != principal.subject
            or claims.connection_ref != str(connection.id)
            or claims.provider_id != prepared.provider_id
            or claims.profile_ref != prepared.profile_ref
            or claims.operation_id != prepared.operation_id
            or claims.resource_ref != prepared.resource_ref
            or claims.arguments_digest_sha256 != bytes.fromhex(digest_arguments(prepared.arguments))
        ):
            raise PermissionError("grant does not match the prepared operation")
        if prepared.provider_id in {"github", "huggingface"}:
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
                else "github_issue"
                if operation_id.startswith("github.issue.")
                else "github_repository"
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
    _exact_optional_fields(arguments, required=required_fields, optional=optional_fields)
    repository_id = arguments.get("repository_id")
    repository = arguments.get("repository")
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
    elif operation_id == "github.pull_request.get" or operation_id == "github.repository.get":
        return


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
