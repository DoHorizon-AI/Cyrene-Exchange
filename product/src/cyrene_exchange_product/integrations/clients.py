"""Production clients for fixed Account Center, GitHub, and computer capabilities.

Every call targets a host-resolved DirectPluginRuntime endpoint and a fixed
capability method. Payloads contain only the capability contract, never a
caller-selected endpoint or credential.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.auth import (
    AccountCenterRequestSigner,
    PlatformAuthorityIdentityVerifier,
    _load_authority_wire,
    _read_tls_file,
    canonical_json,
)
from cyrene_exchange_product.integrations.connector_profiles import (
    validate_teams_service_url,
)
from cyrene_exchange_product.integrations.models import IntegrationPrincipal
from cyrene_exchange_product.integrations.ports import (
    AccountAuthorization,
    AuthorityEnqueueEvidence,
    AuthorityInvocationEvidence,
    AuthorityInvocationState,
    DelegationPort,
    IssueSnapshot,
    LinkedSender,
    MessageEvidence,
    PluginHealthObservation,
    PluginHealthPort,
    ProviderCredentialLeaseEvidence,
    ProviderRejectedError,
    RetryableReadError,
    WriteEvidence,
)

if TYPE_CHECKING:
    from cyrene_plugin_runtime import DirectPayload

ACCOUNT_CAPABILITY = "account.center.v1"
PROVIDER_CAPABILITY = "tool.provider.v1"
DEFAULT_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS = 50.0
MAX_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS = 120.0
ACCOUNT_METHODS = {
    "begin_link": "BeginLink",
    "complete_github_link": "CompleteGitHubLink",
    "observe_wecom_challenge": "ObserveWeComChallenge",
    "confirm_wecom_link": "ConfirmWeComLink",
    "list_links": "ListLinks",
    "get_authorization": "GetAuthorization",
    "unlink": "Unlink",
    "create_credential_lease": "CreateCredentialLease",
    "link_github_app_installation": "LinkGitHubAppInstallation",
    "link_huggingface_profile": "LinkHuggingFaceProfile",
    "rotate_huggingface_profile": "RotateHuggingFaceProfile",
    "register_host_identity_profile": "RegisterHostIdentityProfile",
    "list_provider_profiles": "ListProviderProfiles",
    "create_provider_credential_lease": "CreateProviderCredentialLease",
    "redeem_credential_lease": "RedeemCredentialLease",
    "unlink_provider_profile": "UnlinkProviderProfile",
    "resolve_linked_sender": "ResolveLinkedSender",
}
GITHUB_TOOL_IDS = frozenset(
    {
        "github.repository.list",
        "github.repository.get",
        "github.branches.list",
        "github.pull_requests.list",
        "github.pull_request.get",
        "github.actions.runs.list",
        "github.issues.search",
        "github.actions.jobs.list",
        "github.actions.job.logs.read",
        "github.branch.create",
        "github.branch.delete",
        "github.branch.get",
        "github.file.commit",
        "github.file.get",
        "github.pull_request.draft.create",
        "github.pull_request.draft.find",
        "github.actions.rerun_failed",
        "github.ci.status",
        "github_vendor_cli",
        "github.issue.get",
        "github.issue.comment.create",
        "github.issue.state.update",
    }
)
COMPUTER_TOOL_IDS = frozenset(
    {
        "computer.command.execute",
        "computer.file.read",
        "computer.file.write",
        "computer.directory.list",
    }
)


def direct_plugin_client_from_managed_tls(
    *,
    resolved_target: str,
    root_certificates_path: Path,
    private_key_path: Path,
    certificate_chain_path: Path,
) -> DirectInvoker:
    """Create one TLS-only client for a host-resolved DirectPluginRuntime target."""

    if not resolved_target or "://" in resolved_target:
        raise ValueError("resolved Plugin target must be a gRPC host:port")
    import grpc
    from cyrene_plugin_runtime import DirectPluginClient

    credentials = grpc.ssl_channel_credentials(
        root_certificates=_read_tls_file(root_certificates_path, private=False),
        private_key=_read_tls_file(private_key_path, private=True),
        certificate_chain=_read_tls_file(certificate_chain_path, private=False),
    )
    channel = grpc.secure_channel(resolved_target, credentials)
    return DirectPluginClient(channel, owns_channel=True)


def direct_plugin_client_from_connection(
    connection_ref: str,
    *,
    root_certificates_path: Path | None = None,
    private_key_path: Path | None = None,
    certificate_chain_path: Path | None = None,
) -> DirectInvoker:
    """Build one resolved local or mTLS DirectPluginRuntime client."""

    try:
        from cyrene_plugin_runtime import DirectPluginClient
    except ImportError as exc:
        raise RuntimeError(
            "the cyrene-plugin-runtime integration dependency is unavailable"
        ) from exc
    if connection_ref.startswith("grpc://"):
        if any((root_certificates_path, private_key_path, certificate_chain_path)):
            raise ValueError("local DirectPluginRuntime connections do not use TCP TLS files")
        return DirectPluginClient.for_local_connection_ref(connection_ref)
    if not connection_ref.startswith("grpcs://"):
        raise ValueError("resolved DirectPluginRuntime ref must use grpc:// or grpcs://")
    paths = (root_certificates_path, private_key_path, certificate_chain_path)
    if not all(paths):
        raise ValueError("remote DirectPluginRuntime requires the full managed mTLS profile")
    return direct_plugin_client_from_managed_tls(
        resolved_target=connection_ref.removeprefix("grpcs://"),
        root_certificates_path=root_certificates_path,  # type: ignore[arg-type]
        private_key_path=private_key_path,  # type: ignore[arg-type]
        certificate_chain_path=certificate_chain_path,  # type: ignore[arg-type]
    )


def _direct_payload(type_url: str, value: bytes) -> Any:
    """Load the Plugin transport DTO only when an integration call is made."""

    try:
        from cyrene_plugin_runtime import DirectPayload
    except ImportError as exc:
        raise RuntimeError(
            "the cyrene-plugin-runtime integration dependency is unavailable"
        ) from exc
    return DirectPayload(type_url, value)


@dataclass(frozen=True, slots=True)
class ProviderToolDefinition:
    """One validated tool descriptor read from a configured provider catalog."""

    tool_id: str
    name: str
    description: str
    input_schema: dict[str, Any]


_LIST_TOOLS_RESPONSE_TYPE_URL = "type.cyrene.io/cyrene.tool.provider.v1.ListToolsResponse"
_MAX_PROVIDER_CATALOG_BYTES = 1_048_576
_MAX_PROVIDER_CATALOG_TOOLS = 256
_MAX_PROVIDER_TOOL_SCHEMA_BYTES = 131_072
_PROVIDER_TOOL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREDENTIAL_SCHEMA_PROPERTY = re.compile(
    r"(?:token|secret|password|credential|api[-_]?key|private[-_]?key|bearer)",
    re.IGNORECASE,
)


def list_provider_tool_catalog(
    client: DirectInvoker,
    *,
    binding_id: str,
    deadline_seconds: float = 5.0,
) -> tuple[ProviderToolDefinition, ...]:
    """Read and validate one catalog over the provider's configured DirectPlugin channel.

    The result contains only provider-authored display/schema metadata. Invalid,
    oversized, mismatched, or credential-bearing descriptors fail closed.
    中文：目录来自已配置的 DirectPlugin 通道；不可信或含凭据字段时拒绝导出。
    """

    if not binding_id.strip() or deadline_seconds <= 0:
        raise ValueError("a bound provider ID and positive catalog deadline are required")
    from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
        tool_provider_pb2 as tool_wire,
    )

    request = tool_wire.ListToolsRequest(binding_id=binding_id)
    try:
        response = client.invoke(
            capability=PROVIDER_CAPABILITY,
            interface_version="1",
            method="list_tools",
            request=_direct_payload(
                "type.cyrene.io/cyrene.tool.provider.v1.ListToolsRequest",
                request.SerializeToString(deterministic=True),
            ),
            deadline_seconds=deadline_seconds,
            request_id=str(uuid4()),
        )
    except Exception as exc:
        raise RuntimeError("configured provider tool catalog is unavailable") from exc
    if (
        response.type_url != _LIST_TOOLS_RESPONSE_TYPE_URL
        or not response.value
        or len(response.value) > _MAX_PROVIDER_CATALOG_BYTES
    ):
        raise RuntimeError("configured provider tool catalog response is invalid")
    try:
        typed_response = tool_wire.ListToolsResponse.FromString(response.value)
    except Exception as exc:
        raise RuntimeError("configured provider tool catalog response is malformed") from exc
    result_kind = typed_response.WhichOneof("result")
    if result_kind != "catalog":
        raise RuntimeError("configured provider did not return a tool catalog")
    catalog = typed_response.catalog
    if (
        not catalog.catalog_version
        or len(catalog.catalog_version) > 128
        or not catalog.tools
        or len(catalog.tools) > _MAX_PROVIDER_CATALOG_TOOLS
    ):
        raise RuntimeError("configured provider tool catalog has invalid bounds")

    descriptors: list[ProviderToolDefinition] = []
    seen_ids: set[str] = set()
    schema_bytes = 0
    for descriptor in catalog.tools:
        tool_id = descriptor.provider_tool_id
        name = descriptor.display_name
        description = descriptor.description
        raw_schema = descriptor.input_schema_json
        schema_bytes += len(raw_schema.encode("utf-8"))
        if (
            descriptor.binding_id != binding_id
            or not _PROVIDER_TOOL_ID.fullmatch(tool_id)
            or tool_id in seen_ids
            or not name.strip()
            or len(name) > 256
            or not description.strip()
            or len(description) > 4096
            or not raw_schema
            or len(raw_schema.encode("utf-8")) > _MAX_PROVIDER_TOOL_SCHEMA_BYTES
            or schema_bytes > _MAX_PROVIDER_CATALOG_BYTES
        ):
            raise RuntimeError("configured provider returned an invalid tool descriptor")
        try:
            schema_value = json.loads(
                raw_schema,
                object_pairs_hook=_reject_duplicate_json_pairs,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise RuntimeError("configured provider returned an invalid tool schema") from exc
        if (
            not isinstance(schema_value, dict)
            or schema_value.get("type") != "object"
            or _schema_has_credential_property(schema_value)
        ):
            raise RuntimeError("configured provider returned a disallowed tool schema")
        seen_ids.add(tool_id)
        descriptors.append(
            ProviderToolDefinition(
                tool_id=tool_id,
                name=name,
                description=description,
                input_schema=schema_value,
            )
        )
    return tuple(descriptors)


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("provider schema contains a duplicate JSON member")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("provider schema contains a non-standard JSON constant")


def _schema_has_credential_property(value: object) -> bool:
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping) and any(
            not isinstance(name, str) or _CREDENTIAL_SCHEMA_PROPERTY.search(name)
            for name in properties
        ):
            return True
        return any(_schema_has_credential_property(child) for child in value.values())
    if isinstance(value, list):
        return any(_schema_has_credential_property(child) for child in value)
    return False


class DirectPluginHealthClient(PluginHealthPort):
    """Read one fixed Plugin health RPC over the resolved endpoint transport."""

    def __init__(
        self,
        connection_ref: str,
        *,
        root_certificates_path: Path | None = None,
        private_key_path: Path | None = None,
        certificate_chain_path: Path | None = None,
        deadline_seconds: float = 2.0,
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError("health RPC deadline must be positive")
        try:
            import grpc
            from cyrene_plugin_runtime._generated import (
                direct_plugin_runtime_pb2_grpc as runtime_grpc_module,
            )
        except ImportError as exc:
            raise RuntimeError("the cyrene-plugin-runtime health contract is unavailable") from exc

        self._deadline_seconds = deadline_seconds
        if connection_ref.startswith("grpc://"):
            if any((root_certificates_path, private_key_path, certificate_chain_path)):
                raise ValueError("local health probes cannot use TLS files")
            target = connection_ref.removeprefix("grpc://")
            if not _is_local_direct_target(target):
                raise ValueError("insecure health probes must target loopback or Unix sockets")
            self._channel = grpc.insecure_channel(target)
        elif connection_ref.startswith("grpcs://"):
            if (
                root_certificates_path is None
                or private_key_path is None
                or certificate_chain_path is None
            ):
                raise ValueError("remote health probes require the managed mTLS profile")
            credentials = grpc.ssl_channel_credentials(
                root_certificates=_read_tls_file(root_certificates_path, private=False),
                private_key=_read_tls_file(private_key_path, private=True),
                certificate_chain=_read_tls_file(certificate_chain_path, private=False),
            )
            self._channel = grpc.secure_channel(
                connection_ref.removeprefix("grpcs://"), credentials
            )
        else:
            raise ValueError("resolved health endpoint must use grpc:// or grpcs://")
        runtime_grpc: Any = runtime_grpc_module
        self._stub = runtime_grpc.DirectPluginRuntimeStub(self._channel)

    def close(self) -> None:
        """Close the read-only health channel."""

        self._channel.close()

    def observe(self) -> PluginHealthObservation:
        """Return the actual Plugin runtime Health response or explicit UNKNOWN."""

        from cyrene_plugin_runtime._generated import (
            direct_plugin_runtime_pb2 as runtime_wire_module,
        )

        runtime_wire: Any = runtime_wire_module
        observed_at = datetime.now(UTC)
        try:
            response = self._stub.Health(
                runtime_wire.HealthRequest(), timeout=self._deadline_seconds
            )
        except Exception:
            return PluginHealthObservation(
                status="UNKNOWN",
                observed_at=observed_at,
                error_code="plugin_health_unavailable",
            )
        status_by_wire = {
            runtime_wire.HealthResponse.STATUS_SERVING: "SERVING",
            runtime_wire.HealthResponse.STATUS_NOT_SERVING: "NOT_SERVING",
        }
        status = status_by_wire.get(response.status, "UNKNOWN")
        plugin_id = response.plugin_id if response.plugin_id else None
        plugin_version = response.plugin_version if response.plugin_version else None
        capabilities = tuple(sorted(set(response.capabilities)))
        if status == "UNKNOWN" or not plugin_id or not plugin_version:
            return PluginHealthObservation(
                status="UNKNOWN",
                observed_at=observed_at,
                plugin_id=plugin_id,
                plugin_version=plugin_version,
                capabilities=capabilities,
                error_code="plugin_health_response_invalid",
            )
        return PluginHealthObservation(
            status=status,
            observed_at=observed_at,
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            capabilities=capabilities,
        )


def _is_local_direct_target(target: str) -> bool:
    """Keep the health transport local unless host config selects managed mTLS."""

    if target.startswith("unix:"):
        return True
    host, separator, port = target.rpartition(":")
    return (
        bool(separator)
        and port.isdigit()
        and host.strip("[]").lower() in {"127.0.0.1", "localhost", "::1"}
    )


class DirectInvoker(Protocol):
    """Product-facing subset of the resolved Plugins runtime client."""

    def invoke(
        self,
        *,
        capability: str,
        interface_version: str,
        method: str,
        request: DirectPayload,
        deadline_seconds: float | None = None,
        cancel_event: Any = None,
        request_id: str | None = None,
    ) -> DirectPayload: ...


class AccountCenterClient:
    """Invoke the fixed Account Center methods with per-call signed context."""

    def __init__(
        self,
        client: DirectInvoker,
        *,
        exchange_signer: AccountCenterRequestSigner,
        binding_id: str,
        callback_signer: AccountCenterRequestSigner | None = None,
        wecom_source_signer: AccountCenterRequestSigner | None = None,
        deadline_seconds: float = 3.0,
        github_app_installation_deadline_seconds: float = (
            DEFAULT_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS
        ),
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        if (
            isinstance(github_app_installation_deadline_seconds, bool)
            or not isinstance(github_app_installation_deadline_seconds, (int, float))
            or not math.isfinite(github_app_installation_deadline_seconds)
            or not (
                0
                < github_app_installation_deadline_seconds
                <= MAX_GITHUB_APP_INSTALLATION_DEADLINE_SECONDS
            )
        ):
            raise ValueError(
                "github_app_installation_deadline_seconds must be greater than zero "
                "and at most 120 seconds"
            )
        self._client = client
        self._exchange_signer = exchange_signer
        if not binding_id.strip():
            raise ValueError("Account Center binding_id is required")
        self._binding_id = binding_id
        self._callback_signer = callback_signer
        self._wecom_source_signer = wecom_source_signer
        self._deadline_seconds = deadline_seconds
        self._github_app_installation_deadline_seconds = float(
            github_app_installation_deadline_seconds
        )

    def begin_link(
        self,
        principal: IntegrationPrincipal,
        *,
        provider: str,
        workspace_id: str | None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._invoke_user(
            "begin_link",
            principal,
            {
                "provider": provider,
                "workspace_id": workspace_id,
                "idempotency_key": idempotency_key,
            },
        )

    def complete_github_link(
        self,
        callback_principal: IntegrationPrincipal,
        *,
        state: str,
        code: str,
    ) -> dict[str, Any]:
        return self._invoke_service(
            "complete_github_link",
            self._callback_signer,
            callback_principal,
            {
                "state": state,
                "code": code,
            },
        )

    def observe_wecom_challenge(
        self,
        source_principal: IntegrationPrincipal,
        *,
        bot_namespace: str,
        source_authority: str,
        stable_subject: str,
        challenge_id: str,
        challenge_value: str,
        expires_at: int,
    ) -> dict[str, Any]:
        return self._invoke_service(
            "observe_wecom_challenge",
            self._wecom_source_signer,
            source_principal,
            {
                "bot_namespace": bot_namespace,
                "source_authority": source_authority,
                "stable_subject": stable_subject,
                "challenge_id": challenge_id,
                "challenge_value": challenge_value,
                "expires_at": expires_at,
            },
        )

    def resolve_linked_sender(
        self,
        source_principal: IntegrationPrincipal,
        *,
        source_authority: str,
        bot_namespace: str,
        stable_subject: str,
    ) -> dict[str, Any]:
        """Resolve one source-authenticated sender through Account Center."""

        exchange_principal = IntegrationPrincipal(
            issuer="urn:cyrene:exchange-service",
            subject="exchange-wecom-link-resolver",
            organization_id=source_principal.organization_id,
            workspace_id=source_principal.workspace_id,
            allowed_operation_ids=frozenset(),
        )
        return self._invoke_service(
            "resolve_linked_sender",
            self._exchange_signer,
            exchange_principal,
            {
                "source_authority": source_authority,
                "bot_namespace": bot_namespace,
                "stable_subject": stable_subject,
            },
        )

    def confirm_wecom_link(
        self,
        principal: IntegrationPrincipal,
        *,
        link_session_ref: str,
        challenge_id: str,
        challenge_value: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._invoke_user(
            "confirm_wecom_link",
            principal,
            {
                "link_session_ref": link_session_ref,
                "challenge_id": challenge_id,
                "challenge_value": challenge_value,
                "idempotency_key": idempotency_key,
            },
        )

    def list_links(
        self, principal: IntegrationPrincipal, *, workspace_id: str | None
    ) -> dict[str, Any]:
        return self._invoke_user("list_links", principal, {"workspace_id": workspace_id})

    def get_authorization(
        self,
        principal: IntegrationPrincipal,
        *,
        account_ref: str,
        operation_id: str,
        resource: Mapping[str, object],
        arguments_sha256: str,
    ) -> dict[str, Any]:
        return self._invoke_user(
            "get_authorization",
            principal,
            {
                "account_ref": account_ref,
                "operation_id": operation_id,
                "resource": dict(resource),
                "arguments_sha256": arguments_sha256,
            },
        )

    def unlink(
        self,
        principal: IntegrationPrincipal,
        *,
        account_ref: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._invoke_user(
            "unlink",
            principal,
            {"account_ref": account_ref, "idempotency_key": idempotency_key},
        )

    def create_credential_lease(
        self,
        principal: IntegrationPrincipal,
        *,
        account_ref: str,
        operation_id: str,
        resource: Mapping[str, object],
        arguments_sha256: str,
    ) -> dict[str, Any]:
        return self._invoke_user(
            "create_credential_lease",
            principal,
            {
                "account_ref": account_ref,
                "operation_id": operation_id,
                "resource": dict(resource),
                "arguments_sha256": arguments_sha256,
            },
        )

    def link_github_app_installation(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        installation_id: str,
        repositories: list[Mapping[str, str]],
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Link one verified GitHub App installation and its selected repository scope."""

        return self._invoke_user(
            "link_github_app_installation",
            principal,
            {
                "profile_ref": profile_ref,
                "installation_id": installation_id,
                "repositories": [dict(item) for item in repositories],
                "idempotency_key": idempotency_key,
            },
        )

    def link_huggingface_profile(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        credential_secret_ref: str,
        scopes: Mapping[str, object],
        idempotency_key: str,
        auth_mode: str | None = None,
    ) -> dict[str, Any]:
        """Link one HF credential resolved only inside Account Center's host secret store."""

        if auth_mode is not None and auth_mode not in {"fine_grained_token", "device_oauth"}:
            raise ValueError("Hugging Face auth mode is unsupported")
        payload: dict[str, object] = {
            "profile_ref": profile_ref,
            "credential_secret_ref": credential_secret_ref,
            "scopes": dict(scopes),
            "idempotency_key": idempotency_key,
        }
        if auth_mode is not None:
            payload["auth_mode"] = auth_mode
        return self._invoke_user(
            "link_huggingface_profile",
            principal,
            payload,
        )

    def rotate_huggingface_profile(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        credential_secret_ref: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Replace one HF host secret reference while checking the same external owner."""

        return self._invoke_user(
            "rotate_huggingface_profile",
            principal,
            {
                "profile_ref": profile_ref,
                "credential_secret_ref": credential_secret_ref,
                "idempotency_key": idempotency_key,
            },
        )

    def register_host_identity_profile(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        provider: str,
        identity_ref: str,
        target_scope: Mapping[str, object],
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register non-secret host identity and scope metadata for a fixed cloud profile."""

        return self._invoke_user(
            "register_host_identity_profile",
            principal,
            {
                "profile_ref": profile_ref,
                "provider": provider,
                "identity_ref": identity_ref,
                "target_scope": dict(target_scope),
                "idempotency_key": idempotency_key,
            },
        )

    def list_provider_profiles(self, principal: IntegrationPrincipal) -> dict[str, Any]:
        """List only non-secret provider identity metadata visible to this actor."""

        return self._invoke_user("list_provider_profiles", principal, {})

    def create_provider_credential_lease(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        operation_id: str,
        target: Mapping[str, object],
        arguments_sha256: str,
        connector_grant: Mapping[str, object] | None = None,
    ) -> dict[str, Any]:
        """Create one exact target/argument-bound provider credential lease."""

        payload: dict[str, object] = {
            "profile_ref": profile_ref,
            "operation_id": operation_id,
            "target": dict(target),
            "arguments_sha256": arguments_sha256,
        }
        if connector_grant is not None:
            payload["connector_grant"] = dict(connector_grant)
        return self._invoke_user(
            "create_provider_credential_lease",
            principal,
            payload,
        )

    def unlink_provider_profile(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Remove a provider profile and invalidate its outstanding leases."""

        return self._invoke_user(
            "unlink_provider_profile",
            principal,
            {"profile_ref": profile_ref, "idempotency_key": idempotency_key},
        )

    def _invoke_user(
        self,
        method: str,
        principal: IntegrationPrincipal,
        payload: Mapping[str, object],
    ) -> dict[str, Any]:
        return self._invoke_service(method, self._exchange_signer, principal, payload)

    def _invoke_service(
        self,
        method: str,
        signer: AccountCenterRequestSigner | None,
        principal: IntegrationPrincipal,
        payload: Mapping[str, object],
    ) -> dict[str, Any]:
        if signer is None:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_NOT_CONFIGURED",
                title="Account Center operation is not configured",
                detail="This optional Account Center operation has no host-authorized signer.",
                status=503,
                retryable=False,
            )
        payload = _typed_account_payload(method, payload)
        request_id = str(uuid4())
        trusted_context = signer.sign(
            principal=principal,
            binding_id=self._binding_id,
            operation_id=method,
            payload=payload,
            request_id=request_id,
        ).as_payload()
        method_name = ACCOUNT_METHODS[method]
        request = {"payload": dict(payload), "trusted_context": trusted_context}
        request_type = f"type.googleapis.com/cyrene.account.center.v1.{method_name}Request"
        response_type = f"type.googleapis.com/cyrene.account.center.v1.{method_name}Response"
        deadline_seconds = (
            self._github_app_installation_deadline_seconds
            if method == "link_github_app_installation"
            else self._deadline_seconds
        )
        try:
            response = self._client.invoke(
                capability=ACCOUNT_CAPABILITY,
                interface_version="1",
                method=method,
                request=_direct_payload(request_type, canonical_json(request)),
                deadline_seconds=deadline_seconds,
                request_id=request_id,
            )
        except Exception as exc:
            domain_code = getattr(exc, "domain_code", "")
            provider_reason = getattr(exc, "message", "")
            if domain_code in {
                "idempotency_conflict",
                "idempotency_in_progress",
            } or provider_reason in {"idempotency_conflict", "idempotency_in_progress"}:
                raise ExchangeProductError(
                    code="EXCHANGE_IDEMPOTENCY_CONFLICT",
                    title="Idempotency key conflict",
                    detail=(
                        "The Account Center idempotency key is already bound to another request."
                    ),
                    status=409,
                ) from exc
            if domain_code == "PERMISSION_DENIED" and provider_reason == "connector_grant_replayed":
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_REPLAYED",
                    title="Connector grant was already used",
                    detail="Account Center rejected a previously consumed one-use connector grant.",
                    status=409,
                    context={"reasonCode": "account_center_connector_grant_replayed"},
                ) from exc
            if domain_code == "PERMISSION_DENIED":
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_AUTHORIZATION_DENIED",
                    title="Account Center authorization denied",
                    detail="Account Center rejected the verified actor or provider scope.",
                    status=403,
                    context={"reasonCode": "account_center_permission_denied"},
                ) from exc
            if domain_code == "INVALID_REQUEST":
                raise ExchangeProductError(
                    code="EXCHANGE_ACCOUNT_CENTER_REQUEST_INVALID",
                    title="Account Center request invalid",
                    detail="Account Center rejected the typed request fields.",
                    status=422,
                    context={"reasonCode": "account_center_request_invalid"},
                ) from exc
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_UNAVAILABLE",
                title="Account Center unavailable",
                detail="The configured Account Center capability did not complete the request.",
                status=503,
                retryable=True,
            ) from exc
        if response.type_url != response_type:
            raise RuntimeError("Account Center returned an unexpected response type")
        try:
            value = json.loads(response.value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Account Center returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeError("Account Center returned a non-object result")
        if method == "redeem_credential_lease":
            return value
        if any(key in value for key in ("access_token", "refresh_token", "client_secret")):
            raise RuntimeError(
                "Account Center exposed provider credential material on a user route"
            )
        return value


def _typed_account_payload(method: str, payload: Mapping[str, object]) -> dict[str, object]:
    """Serialize the Plugins-owned Account Center request DTO for one method."""

    try:
        from dataclasses import asdict

        import cyrene_account_center_contracts as account_contracts
        from cyrene_account_center_contracts import (
            BeginLinkRequest,
            CompleteGitHubLinkRequest,
            ConfirmWeComLinkRequest,
            CreateCredentialLeaseRequest,
            GetAuthorizationRequest,
            ListLinksRequest,
            ObserveWeComChallengeRequest,
            ResolveLinkedSenderRequest,
            Resource,
            UnlinkRequest,
        )
    except ImportError as exc:
        raise RuntimeError(
            "the cyrene-account-center-contracts integration dependency is unavailable"
        ) from exc
    dto_types = {
        "begin_link": BeginLinkRequest,
        "complete_github_link": CompleteGitHubLinkRequest,
        "observe_wecom_challenge": ObserveWeComChallengeRequest,
        "confirm_wecom_link": ConfirmWeComLinkRequest,
        "list_links": ListLinksRequest,
        "get_authorization": GetAuthorizationRequest,
        "unlink": UnlinkRequest,
        "create_credential_lease": CreateCredentialLeaseRequest,
        "resolve_linked_sender": ResolveLinkedSenderRequest,
    }
    dynamic_types = {
        "link_github_app_installation": "LinkGitHubAppInstallationRequest",
        "link_huggingface_profile": "LinkHuggingFaceProfileRequest",
        "rotate_huggingface_profile": "RotateHuggingFaceProfileRequest",
        "register_host_identity_profile": "RegisterHostIdentityProfileRequest",
        "list_provider_profiles": "ListProviderProfilesRequest",
        "create_provider_credential_lease": "CreateProviderCredentialLeaseRequest",
        "unlink_provider_profile": "UnlinkProviderProfileRequest",
    }
    if method in dynamic_types:
        dto_type = getattr(account_contracts, dynamic_types[method], None)
        if dto_type is None:
            raise RuntimeError(
                "the configured Account Center SDK lacks the requested provider profile contract"
            )
    else:
        dto_type = dto_types.get(method)
    if dto_type is None:
        raise ValueError("unsupported Account Center method")
    values = dict(payload)
    if method == "create_provider_credential_lease" and "connector_grant" in values:
        dto_fields = getattr(dto_type, "__dataclass_fields__", {})
        if "connector_grant" not in dto_fields:
            raise ExchangeProductError(
                code="EXCHANGE_ACCOUNT_CENTER_SHARED_PROFILE_NOT_CONFIGURED",
                title="Shared Account Center lease authorization is unavailable",
                detail=(
                    "The pinned Account Center contract cannot verify workspace-operator grants."
                ),
                status=503,
                retryable=True,
                context={"reasonCode": "account_center_connector_grant_contract_missing"},
            )
    if method == "link_huggingface_profile" and "auth_mode" in values:
        dto_fields = getattr(dto_type, "__dataclass_fields__", {})
        if "auth_mode" not in dto_fields:
            if values["auth_mode"] == "fine_grained_token":
                values.pop("auth_mode")
            else:
                raise RuntimeError(
                    "the configured Account Center SDK lacks Hugging Face OAuth profile support"
                )
    if method in {"get_authorization", "create_credential_lease"}:
        resource = values.get("resource")
        if not isinstance(resource, Mapping):
            raise ValueError("Account Center resource must be a typed resource object")
        values["resource"] = Resource(**dict(resource))
    return asdict(dto_type(**values))


class IntegrationAccountCenterPort:
    """Validate Account Center decisions and project opaque leases to dispatcher types."""

    def __init__(
        self,
        client: AccountCenterClient,
    ) -> None:
        self._client = client

    def get_authorization(
        self,
        principal: IntegrationPrincipal,
        *,
        account_link_ref: str,
        operation_id: str,
        repository_id: str,
        repository_name: str,
        issue_number: int,
        arguments: Mapping[str, object],
        arguments_sha256: str,
    ) -> AccountAuthorization:
        resource = {
            "repository_id": repository_id,
            "repository": repository_name,
            "issue_number": issue_number,
        }
        decision = self._client.get_authorization(
            principal,
            account_ref=account_link_ref,
            operation_id=operation_id,
            resource=resource,
            arguments_sha256=arguments_sha256,
        )
        if (
            decision.get("authorized") is not True
            or decision.get("account_ref") != account_link_ref
            or decision.get("provider") != "github"
        ):
            raise PermissionError("Account Center did not authorize this provider operation")
        lease = self._client.create_credential_lease(
            principal,
            account_ref=account_link_ref,
            operation_id=operation_id,
            resource=resource,
            arguments_sha256=arguments_sha256,
        )
        if (
            lease.get("provider") != "github"
            or lease.get("operation_id") != operation_id
            or lease.get("arguments_sha256") != arguments_sha256
            or lease.get("resource") != resource
        ):
            raise RuntimeError("Account Center returned a lease with mismatched authority")
        lease_ref = lease.get("lease_ref")
        expires_at = lease.get("expires_at")
        if not isinstance(lease_ref, str) or not isinstance(expires_at, int):
            raise RuntimeError("Account Center returned an invalid credential lease")
        return AccountAuthorization(
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            account_link_ref=account_link_ref,
            provider="github",
            repository_id=repository_id,
            repository_name=repository_name,
            operation_id=operation_id,
            arguments_sha256=arguments_sha256,
            expires_at=datetime.fromtimestamp(expires_at, UTC),
            lease_ref=lease_ref,
        )

    def resolve_linked_sender(
        self,
        service_principal: IntegrationPrincipal,
        *,
        source_authority: str,
        bot_namespace: str,
        stable_subject: str,
    ) -> LinkedSender | None:
        """Resolve only a source-authenticated sender through Account Center."""

        if not source_authority or not bot_namespace or not stable_subject:
            raise ValueError("source authority, bot namespace, and sender ID are required")
        result = self._client.resolve_linked_sender(
            service_principal,
            source_authority=source_authority,
            bot_namespace=bot_namespace,
            stable_subject=stable_subject,
        )
        if result.get("linked") is not True:
            return None
        fields = {
            "account_ref": result.get("account_ref"),
            "issuer": result.get("issuer"),
            "subject": result.get("subject"),
            "organization_id": result.get("organization_id"),
        }
        if any(not isinstance(value, str) or not value for value in fields.values()):
            raise RuntimeError("Account Center returned an invalid linked sender projection")
        workspace_id = result.get("workspace_id")
        if workspace_id is not None and not isinstance(workspace_id, str):
            raise RuntimeError("Account Center returned an invalid linked workspace")
        return LinkedSender(
            issuer=str(fields["issuer"]),
            subject=str(fields["subject"]),
            organization_id=str(fields["organization_id"]),
            workspace_id=workspace_id,
            account_link_ref=str(fields["account_ref"]),
            external_sender_id=stable_subject,
        )

    def create_provider_credential_lease(
        self,
        principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        operation_id: str,
        target: Mapping[str, object],
        arguments_sha256: str,
        connector_grant: Mapping[str, object] | None = None,
    ) -> ProviderCredentialLeaseEvidence:
        """Request one-use lease metadata without redeeming any provider credential."""

        if len(arguments_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in arguments_sha256
        ):
            raise ValueError("provider lease arguments digest is invalid")
        lease = self._client.create_provider_credential_lease(
            principal,
            profile_ref=profile_ref,
            operation_id=operation_id,
            target=target,
            arguments_sha256=arguments_sha256,
            connector_grant=connector_grant,
        )
        if (
            lease.get("profile_ref") != profile_ref
            or lease.get("operation_id") != operation_id
            or lease.get("target") != dict(target)
            or lease.get("arguments_sha256") != arguments_sha256
        ):
            raise PermissionError("Account Center returned a lease with mismatched scope")
        lease_ref = lease.get("lease_ref")
        provider = lease.get("provider")
        expires_at = lease.get("expires_at")
        if (
            not isinstance(lease_ref, str)
            or not lease_ref
            or not isinstance(provider, str)
            or provider not in {"github", "huggingface"}
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
        ):
            raise RuntimeError("Account Center returned malformed provider lease metadata")
        return ProviderCredentialLeaseEvidence(
            lease_ref=lease_ref,
            profile_ref=profile_ref,
            provider=provider,
            operation_id=operation_id,
            target=dict(target),
            arguments_sha256=arguments_sha256,
            expires_at=datetime.fromtimestamp(expires_at, UTC),
        )


class IntegrationGitHubPort:
    """Validate fixed provider results against the authorization lease before projecting."""

    def __init__(self, client: GitHubIssuesClient) -> None:
        self._client = client

    def get_issue(
        self, authorization: AccountAuthorization, *, repository_id: str, issue_number: int
    ) -> IssueSnapshot:
        tool_arguments = {
            "repository_id": repository_id,
            "repository": authorization.repository_name,
            "issue_number": issue_number,
        }
        self._require_authorization(
            authorization, "github.issue.get", repository_id, issue_number, tool_arguments
        )
        result = self._client.get_issue(
            _principal_for_authorization(authorization),
            lease_ref=authorization.lease_ref,
            repository_id=repository_id,
            repository=authorization.repository_name,
            issue_number=issue_number,
        )
        if (
            result.get("number") != issue_number
            or result.get("repository_id", repository_id) != repository_id
            or result.get("state") not in {"OPEN", "CLOSED"}
            or not isinstance(result.get("title"), str)
        ):
            raise RuntimeError("GitHub provider returned an invalid issue projection")
        snapshot_bytes = canonical_json(dict(result))
        return IssueSnapshot(
            repository_id=repository_id,
            issue_number=issue_number,
            state=str(result["state"]),
            title=str(result["title"]),
            body=str(result.get("body", "")),
            version=hashlib.sha256(snapshot_bytes).hexdigest(),
            observed_at=datetime.now(UTC),
        )

    def create_comment(
        self,
        authorization: AccountAuthorization,
        *,
        repository_id: str,
        issue_number: int,
        body: str,
    ) -> WriteEvidence:
        self._require_authorization(
            authorization,
            "github.issue.comment.create",
            repository_id,
            issue_number,
            {
                "repository_id": repository_id,
                "repository": authorization.repository_name,
                "issue_number": issue_number,
                "body": body,
            },
        )
        result = self._client.create_comment(
            _principal_for_authorization(authorization),
            lease_ref=authorization.lease_ref,
            repository_id=repository_id,
            repository=authorization.repository_name,
            issue_number=issue_number,
            body=body,
        )
        if result.get("status") == "REJECTED":
            raise ProviderRejectedError(str(result.get("reason_code", "provider_rejected")))
        if (
            result.get("status") != "CONFIRMED"
            or result.get("issue_number") != issue_number
            or result.get("repository_id") != repository_id
            or not isinstance(result.get("comment_id"), str)
        ):
            raise RuntimeError("GitHub provider did not confirm the comment result")
        return WriteEvidence(
            accepted=True,
            succeeded=True,
            vendor_resource_id=str(result["comment_id"]),
            observed_at=datetime.now(UTC),
            evidence={"status": "CONFIRMED", "commentId": str(result["comment_id"])},
        )

    def update_state(
        self,
        authorization: AccountAuthorization,
        *,
        repository_id: str,
        issue_number: int,
        state: str,
    ) -> WriteEvidence:
        self._require_authorization(
            authorization,
            "github.issue.state.update",
            repository_id,
            issue_number,
            {
                "repository_id": repository_id,
                "repository": authorization.repository_name,
                "issue_number": issue_number,
                "state": state,
            },
        )
        if state not in {"OPEN", "CLOSED"}:
            raise ValueError("GitHub issue state must be OPEN or CLOSED")
        result = self._client.update_state(
            _principal_for_authorization(authorization),
            lease_ref=authorization.lease_ref,
            repository_id=repository_id,
            repository=authorization.repository_name,
            issue_number=issue_number,
            state=state,
        )
        if result.get("status") == "REJECTED":
            raise ProviderRejectedError(str(result.get("reason_code", "provider_rejected")))
        issue = result.get("issue")
        if (
            result.get("status") != "CONFIRMED"
            or not isinstance(issue, Mapping)
            or issue.get("number") != issue_number
            or issue.get("state") != state
        ):
            raise RuntimeError("GitHub provider did not confirm the requested issue state")
        return WriteEvidence(
            accepted=True,
            succeeded=True,
            vendor_resource_id=str(issue.get("issue_id", "")) or None,
            observed_at=datetime.now(UTC),
            evidence={"status": "CONFIRMED", "state": state},
        )

    @staticmethod
    def _require_authorization(
        authorization: AccountAuthorization,
        operation_id: str,
        repository_id: str,
        issue_number: int,
        arguments: Mapping[str, object],
    ) -> None:
        if (
            authorization.provider != "github"
            or authorization.operation_id != operation_id
            or authorization.repository_id != repository_id
            or authorization.expires_at <= datetime.now(UTC)
            or not authorization.lease_ref
            or issue_number < 1
            or hashlib.sha256(canonical_json(arguments)).hexdigest()
            != authorization.arguments_sha256
        ):
            raise PermissionError("GitHub operation does not match its Account Center lease")


def _principal_for_authorization(authorization: AccountAuthorization) -> IntegrationPrincipal:
    """Reconstruct only the already verified actor anchor used for signed provider calls."""

    return IntegrationPrincipal(
        issuer=authorization.actor_issuer,
        subject=authorization.actor_subject,
        organization_id=authorization.organization_id,
        workspace_id=authorization.workspace_id,
        allowed_operation_ids=frozenset({authorization.operation_id}),
    )


class GitHubIssuesClient:
    """Read and invoke fixed GitHub provider tools through Plugins."""

    def __init__(
        self,
        client: DirectInvoker,
        *,
        signer: AccountCenterRequestSigner,
        binding_id: str,
        deadline_seconds: float = 10.0,
    ) -> None:
        if deadline_seconds <= 0 or not binding_id.strip():
            raise ValueError("binding_id and a positive deadline are required")
        self._client = client
        self._signer = signer
        self._binding_id = binding_id
        self._deadline_seconds = deadline_seconds

    def list_tool_catalog(self) -> tuple[ProviderToolDefinition, ...]:
        """Return the live catalog exposed by this configured GitHub Plugin binding."""

        return list_provider_tool_catalog(
            self._client,
            binding_id=self._binding_id,
            deadline_seconds=self._deadline_seconds,
        )

    def get_issue(
        self,
        principal: IntegrationPrincipal,
        *,
        lease_ref: str,
        repository_id: str,
        repository: str,
        issue_number: int,
    ) -> dict[str, Any]:
        return self._call_tool(
            "github.issue.get",
            principal,
            lease_ref,
            {
                "repository_id": repository_id,
                "repository": repository,
                "issue_number": issue_number,
            },
        )

    def create_comment(
        self,
        principal: IntegrationPrincipal,
        *,
        lease_ref: str,
        repository_id: str,
        repository: str,
        issue_number: int,
        body: str,
    ) -> dict[str, Any]:
        return self._call_tool(
            "github.issue.comment.create",
            principal,
            lease_ref,
            {
                "repository_id": repository_id,
                "repository": repository,
                "issue_number": issue_number,
                "body": body,
            },
        )

    def update_state(
        self,
        principal: IntegrationPrincipal,
        *,
        lease_ref: str,
        repository_id: str,
        repository: str,
        issue_number: int,
        state: str,
    ) -> dict[str, Any]:
        if state not in {"OPEN", "CLOSED"}:
            raise ValueError("GitHub issue state must be OPEN or CLOSED")
        return self._call_tool(
            "github.issue.state.update",
            principal,
            lease_ref,
            {
                "repository_id": repository_id,
                "repository": repository,
                "issue_number": issue_number,
                "state": state,
            },
        )

    def call_provider_tool(
        self,
        principal: IntegrationPrincipal,
        *,
        tool_id: str,
        profile_ref: str,
        lease_ref: str,
        payload: Mapping[str, object],
    ) -> dict[str, Any]:
        """Invoke one fixed GitHub operation with Account Center one-use lease metadata."""

        if tool_id not in GITHUB_TOOL_IDS or not profile_ref or not lease_ref:
            raise ValueError("GitHub provider tool, profile, and lease must be allowlisted")
        envelope_payload = {
            "payload": dict(payload),
            "profile_ref": profile_ref,
            "lease_ref": lease_ref,
        }
        trusted_context = self._signer.sign_provider_call(
            principal=principal,
            binding_id=self._binding_id,
            method="call_tool",
            operation_id=tool_id,
            payload=envelope_payload,
        ).as_payload()
        from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
            tool_provider_pb2 as tool_wire,
        )

        call = tool_wire.CallToolRequest(
            binding_id=self._binding_id,
            provider_tool_id=tool_id,
            arguments_json=canonical_json(
                {**envelope_payload, "trusted_context": trusted_context}
            ).decode("utf-8"),
        )
        try:
            response = self._client.invoke(
                capability=PROVIDER_CAPABILITY,
                interface_version="1",
                method="call_tool",
                request=_direct_payload(
                    "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                    call.SerializeToString(deterministic=True),
                ),
                deadline_seconds=self._deadline_seconds,
                request_id=str(uuid4()),
            )
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_PROVIDER_UNAVAILABLE",
                title="GitHub provider unavailable",
                detail="The configured GitHub provider capability did not complete the request.",
                status=503,
                retryable=True,
                context={"reasonCode": "provider_unavailable"},
            ) from exc
        if response.type_url != "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse":
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_PROVIDER_RESPONSE_INVALID",
                title="GitHub provider response invalid",
                detail="The configured GitHub provider returned an unexpected response type.",
                status=502,
            )
        result = _decode_generic_provider_result(response.value, provider="GitHub")
        return result

    def _call_tool(
        self,
        tool_id: str,
        principal: IntegrationPrincipal,
        lease_ref: str,
        tool_arguments: Mapping[str, object],
    ) -> dict[str, Any]:
        if tool_id not in GITHUB_TOOL_IDS or not lease_ref:
            raise ValueError("GitHub tool and account lease must be allowlisted")
        payload = {"payload": dict(tool_arguments), "lease_ref": lease_ref}
        trusted_context = self._signer.sign_provider_call(
            principal=principal,
            binding_id=self._binding_id,
            method="call_tool",
            operation_id=tool_id,
            payload=payload,
        ).as_payload()
        from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
            tool_provider_pb2 as tool_wire,
        )

        call = tool_wire.CallToolRequest(
            binding_id=self._binding_id,
            provider_tool_id=tool_id,
            arguments_json=canonical_json({**payload, "trusted_context": trusted_context}).decode(
                "utf-8"
            ),
        )
        request_id = str(uuid4())
        try:
            response = self._client.invoke(
                capability=PROVIDER_CAPABILITY,
                interface_version="1",
                method="call_tool",
                request=_direct_payload(
                    "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                    call.SerializeToString(deterministic=True),
                ),
                deadline_seconds=self._deadline_seconds,
                request_id=request_id,
            )
        except Exception as exc:
            if tool_id == "github.issue.get" and getattr(exc, "retryable", False):
                raise RetryableReadError("github_provider_unavailable") from exc
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_PROVIDER_UNAVAILABLE",
                title="GitHub provider unavailable",
                detail="The configured GitHub provider capability did not complete the request.",
                status=503,
                retryable=True,
            ) from exc
        if response.type_url != "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse":
            raise RuntimeError("GitHub provider returned an unexpected response type")
        return _decode_tool_result(response.value, tool_id=tool_id)


class ComputerRunnerClient:
    """Invoke only the fixed, mTLS-bound computer tools without passing caller or profile data."""

    def __init__(
        self,
        client: DirectInvoker,
        *,
        binding_id: str,
        deadline_seconds: float = 605.0,
    ) -> None:
        if binding_id != "computer-runtime" or deadline_seconds <= 0:
            raise ValueError("computer runtime requires its fixed binding and positive deadline")
        self._client = client
        self._binding_id = binding_id
        self._deadline_seconds = deadline_seconds

    def list_tool_catalog(self) -> tuple[ProviderToolDefinition, ...]:
        """Read the actual computer tool schemas from the configured private plugin peer."""

        return list_provider_tool_catalog(
            self._client,
            binding_id=self._binding_id,
            deadline_seconds=min(self._deadline_seconds, 10.0),
        )

    def call_provider_tool(
        self,
        *,
        tool_id: str,
        payload: Mapping[str, object],
    ) -> dict[str, Any]:
        """Send schema arguments only over the host-configured mTLS plugin channel."""

        if tool_id not in COMPUTER_TOOL_IDS:
            raise ValueError("computer provider tool is not in the fixed Exchange allowlist")
        from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
            tool_provider_pb2 as tool_wire,
        )

        call = tool_wire.CallToolRequest(
            binding_id=self._binding_id,
            provider_tool_id=tool_id,
            arguments_json=canonical_json(dict(payload)).decode("utf-8"),
        )
        try:
            response = self._client.invoke(
                capability=PROVIDER_CAPABILITY,
                interface_version="1",
                method="call_tool",
                request=_direct_payload(
                    "type.cyrene.io/cyrene.tool.provider.v1.CallToolRequest",
                    call.SerializeToString(deterministic=True),
                ),
                deadline_seconds=self._deadline_seconds,
                request_id=str(uuid4()),
            )
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_UNAVAILABLE",
                title="Computer runner unavailable",
                detail="The configured isolated computer runtime did not complete the request.",
                status=503,
                retryable=True,
            ) from exc
        if response.type_url != "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse":
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The configured computer runtime returned an unexpected response type.",
                status=502,
            )
        result = _decode_computer_provider_result(response.value, tool_id=tool_id)
        if tool_id == "computer.file.write":
            encoded = payload.get("content_base64")
            if not isinstance(encoded, str):
                raise ValueError("computer file.write payload is malformed")
            try:
                content = base64.b64decode(encoded, validate=True)
            except (TypeError, ValueError, binascii.Error) as exc:
                raise ValueError("computer file.write payload is malformed") from exc
            if base64.b64encode(content).decode("ascii") != encoded or result.get(
                "bytes_written"
            ) != len(content):
                raise ExchangeProductError(
                    code="EXCHANGE_COMPUTER_WRITE_UNCONFIRMED",
                    title="Computer file write could not be confirmed",
                    detail="The runtime did not report the expected number of written bytes.",
                    status=502,
                )
        elif tool_id == "computer.file.read":
            requested_length = payload.get("length")
            if (
                isinstance(requested_length, bool)
                or not isinstance(requested_length, int)
                or result.get("size_bytes", requested_length + 1) > requested_length
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                    title="Computer runner response invalid",
                    detail="The file read result exceeds its requested chunk size.",
                    status=502,
                )
        return result


class GitHubWebhookClient:
    """Submit original GitHub webhook bytes to the Plugin's native HMAC verifier."""

    def __init__(self, client: DirectInvoker, *, deadline_seconds: float = 3.0) -> None:
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        self._client = client
        self._deadline_seconds = deadline_seconds

    def verify_and_normalize(
        self,
        *,
        delivery_id: str,
        event_name: str,
        signature: str,
        body: bytes,
    ) -> Mapping[str, Any]:
        request = {
            "delivery_id": delivery_id,
            "event": event_name,
            "signature": signature,
            "raw_body_base64": base64.b64encode(body).decode("ascii"),
        }
        response = self._client.invoke(
            capability=PROVIDER_CAPABILITY,
            interface_version="1",
            method="normalize_webhook",
            request=_direct_payload(
                "type.cyrene.io/cyrene.github.webhook.v1.WebhookRequest",
                canonical_json(request),
            ),
            deadline_seconds=self._deadline_seconds,
            request_id=str(uuid4()),
        )
        if response.type_url != "type.cyrene.io/cyrene.github.webhook.v1.WebhookResponse":
            raise RuntimeError("GitHub webhook verifier returned an unexpected response type")
        try:
            normalized = json.loads(response.value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("GitHub webhook verifier returned malformed JSON") from exc
        if not isinstance(normalized, Mapping):
            raise RuntimeError("GitHub webhook verifier returned an invalid normalized event")
        error = normalized.get("error")
        if isinstance(error, Mapping):
            code = error.get("code")
            status = (
                401
                if code == "INVALID_SIGNATURE"
                else 403
                if code == "REPOSITORY_NOT_ALLOWED"
                else 400
            )
            raise ExchangeProductError(
                code="EXCHANGE_GITHUB_WEBHOOK_INVALID",
                title="GitHub webhook rejected",
                detail="GitHub webhook signature, event, or repository validation failed.",
                status=status,
            )
        return normalized


class WeComMessageClient:
    """Send fixed text notifications through the official WeCom bot adapter."""

    def __init__(
        self,
        client: DirectInvoker,
        *,
        targets: Mapping[str, Mapping[str, str]],
        source_accounts: Mapping[str, Mapping[str, str]] | None = None,
        deadline_seconds: float = 10.0,
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        self._client = client
        self._targets = {key: dict(value) for key, value in targets.items()}
        self._source_accounts = {key: dict(value) for key, value in (source_accounts or {}).items()}
        self._deadline_seconds = deadline_seconds

    def send_notification(
        self,
        *,
        target_ref: str,
        text: str,
        idempotency_key: str,
    ) -> MessageEvidence:
        """Send one text notification and preserve explicit connector ACK facts."""

        target = self._targets.get(target_ref)
        if target is None:
            raise ValueError("notification target reference is not configured")
        bot_id = target.get("bot_id", "")
        conversation_id = target.get("conversation_id", "")
        kind = target.get("kind", "")
        if not bot_id or not conversation_id or kind not in {"PRIVATE", "GROUP"}:
            raise ValueError("configured WeCom target is invalid")
        if not text.strip() or len(text) > 4000 or not idempotency_key:
            raise ValueError("WeCom notification text and idempotency key are required")
        return self._send_message(
            account_id=f"bot:{bot_id}",
            conversation_id=conversation_id,
            kind=kind,
            text=text,
            reply_message_id=None,
            idempotency_key=idempotency_key,
        )

    def send_wecom_challenge_reply(
        self,
        *,
        source_binding_id: str,
        sender_id: str,
        conversation_ref: str,
        reply_message_id: str,
        reply_context_ref: str,
        text: str,
        idempotency_key: str,
    ) -> MessageEvidence:
        """Reply privately to one source-authenticated WeCom message."""

        source = self._source_accounts.get(source_binding_id)
        if source is None:
            raise ValueError("WeCom challenge source is not configured")
        account_id = source.get("account_id", "")
        prefix, separator, conversation_id = conversation_ref.partition(":")
        if (
            not account_id.startswith("bot:")
            or not sender_id.strip()
            or not separator
            or prefix.lower() != "private"
        ):
            raise ValueError("WeCom challenge reply requires a fixed bot and private source")
        if (
            not conversation_id
            or conversation_id != sender_id
            or not reply_message_id.strip()
            or not reply_context_ref.strip()
        ):
            raise ValueError("WeCom challenge reply requires the authenticated source message")
        if not text.strip() or len(text) > 4000 or not idempotency_key:
            raise ValueError("WeCom challenge reply text and idempotency key are required")
        return self._send_message(
            account_id=account_id,
            conversation_id=conversation_id,
            kind="PRIVATE",
            text=text,
            reply_message_id=reply_message_id,
            idempotency_key=idempotency_key,
        )

    def send_command_reply(
        self,
        *,
        source_binding_id: str,
        sender_id: str,
        conversation_ref: str,
        reply_message_id: str,
        reply_context_ref: str,
        text: str,
        idempotency_key: str,
    ) -> MessageEvidence:
        """Reply through a fixed bot target using persisted inbound context."""

        source = self._source_accounts.get(source_binding_id)
        if source is None:
            raise ValueError("WeCom command source is not configured")
        account_id = source.get("account_id", "")
        group_conversation_id = source.get("group_conversation_id", "")
        if not account_id.startswith("bot:") or not group_conversation_id:
            raise ValueError("configured WeCom command source is invalid")
        if (
            not conversation_ref.strip()
            or not reply_message_id.strip()
            or not reply_context_ref.strip()
        ):
            raise ValueError("WeCom command reply requires durable source conversation context")
        if not text.strip() or len(text) > 4000 or not idempotency_key:
            raise ValueError("WeCom command reply text and idempotency key are required")
        conversation_kind, _, conversation_id = conversation_ref.partition(":")
        kind = conversation_kind.upper()
        if kind not in {"PRIVATE", "GROUP"} or not conversation_id:
            raise ValueError("WeCom command reply conversation scope is invalid")
        if kind == "GROUP" and conversation_id != group_conversation_id:
            raise ValueError("WeCom command reply conversation does not match its fixed source")
        if kind == "PRIVATE" and conversation_id != sender_id:
            raise ValueError("WeCom command reply conversation does not match its sender")
        return self._send_message(
            account_id=account_id,
            conversation_id=conversation_id,
            kind=kind,
            text=text,
            reply_message_id=reply_message_id,
            idempotency_key=idempotency_key,
        )

    def _send_message(
        self,
        *,
        account_id: str,
        conversation_id: str,
        kind: str,
        text: str,
        reply_message_id: str | None,
        idempotency_key: str,
    ) -> MessageEvidence:
        """Send typed canonical connector protobuf and preserve explicit ACK facts."""

        from cyrene_exchange_product.integrations._generated.cyrene.message.connector.v1 import (
            message_connector_pb2 as message_wire,
        )

        kind_id = {
            "PRIVATE": message_wire.CONVERSATION_KIND_PRIVATE,
            "GROUP": message_wire.CONVERSATION_KIND_GROUP,
        }.get(kind.upper())
        if kind_id is None:
            raise ValueError("WeCom conversation kind is unsupported")
        request = message_wire.SendMessageRequest(
            conversation=message_wire.ConversationScope(
                vendor="wecom.bot",
                account_id=account_id,
                conversation_id=conversation_id,
                kind=kind_id,
            ),
            content=[message_wire.MessageContentPart(text=message_wire.TextContent(text=text))],
        )
        if reply_message_id is not None:
            request.reply.message_id = reply_message_id

        response = self._client.invoke(
            capability="message.connector.v1",
            interface_version="1",
            method="send_message",
            request=_direct_payload(
                "type.cyrene.io/cyrene.message.connector.v1.SendMessageRequest",
                request.SerializeToString(deterministic=True),
            ),
            deadline_seconds=self._deadline_seconds,
            request_id=_runtime_request_id(idempotency_key),
        )
        if response.type_url != "type.cyrene.io/cyrene.message.connector.v1.DeliveryResult":
            raise RuntimeError("WeCom connector returned an unexpected delivery result type")
        result = message_wire.DeliveryResult()
        try:
            result.ParseFromString(response.value)
        except Exception as exc:
            raise RuntimeError(
                "WeCom connector returned malformed DeliveryResult protobuf"
            ) from exc
        if result.status not in {
            message_wire.DELIVERY_STATUS_ACCEPTED,
            message_wire.DELIVERY_STATUS_REJECTED,
            message_wire.DELIVERY_STATUS_RATE_LIMITED,
        }:
            raise RuntimeError("WeCom connector returned an indeterminate delivery status")
        facts: dict[str, str] = {}
        for fact in result.vendor_extension.facts:
            if fact.name:
                facts[fact.name] = fact.value
        request_id = facts.get("transport_request_id")
        vendor_id = result.vendor_message_id
        return MessageEvidence(
            accepted=result.status == message_wire.DELIVERY_STATUS_ACCEPTED,
            vendor_message_id=(
                vendor_id
                if result.status == message_wire.DELIVERY_STATUS_ACCEPTED
                and isinstance(vendor_id, str)
                and vendor_id
                else None
            ),
            transport_request_id=request_id
            if result.status == message_wire.DELIVERY_STATUS_ACCEPTED
            else None,
            observed_at=datetime.now(UTC),
            evidence={
                "status": message_wire.DeliveryStatus.Name(result.status),
                "reasonCode": facts.get("reason_code"),
            },
        )


class TeamsMessageClient:
    """Send one grant-bound reply through the configured Teams message Plugin."""

    def __init__(self, client: DirectInvoker, *, deadline_seconds: float = 10.0) -> None:
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        self._client = client
        self._deadline_seconds = deadline_seconds

    def send_reply(
        self,
        *,
        bot_app_id: str,
        tenant_id: str,
        team_id: str,
        channel_id: str,
        conversation_id: str,
        root_thread_id: str,
        service_url: str,
        text: str,
        request_id: str,
    ) -> MessageEvidence:
        """Reply to one exact Teams thread using the fixed bot account binding."""

        values = (
            bot_app_id,
            tenant_id,
            team_id,
            channel_id,
            conversation_id,
            root_thread_id,
            service_url,
            request_id,
        )
        if (
            any(not isinstance(value, str) or not value.strip() for value in values)
            or not text.strip()
            or len(text) > 24_000
        ):
            raise ValueError("Teams reply scope, text, and request id are required")
        validate_teams_service_url(service_url, tenant_id=tenant_id)
        from cyrene_exchange_product.integrations._generated.cyrene.message.connector.v1 import (
            message_connector_pb2 as message_wire,
        )

        request = message_wire.SendMessageRequest(
            conversation=message_wire.ConversationScope(
                vendor="msteams",
                account_id=bot_app_id,
                conversation_id=conversation_id,
                kind=message_wire.CONVERSATION_KIND_CHANNEL,
            ),
            content=[message_wire.MessageContentPart(text=message_wire.TextContent(text=text))],
            vendor_extension=message_wire.VendorExtension(
                vendor="msteams",
                facts=[
                    message_wire.VendorFact(name="tenant_id", value=tenant_id),
                    message_wire.VendorFact(name="team_id", value=team_id),
                    message_wire.VendorFact(name="channel_id", value=channel_id),
                    message_wire.VendorFact(name="service_url", value=service_url),
                ],
            ),
        )
        request.reply.message_id = root_thread_id
        try:
            response = self._client.invoke(
                capability="message.connector.v1",
                interface_version="1",
                method="send_message",
                request=_direct_payload(
                    "type.cyrene.io/cyrene.message.connector.v1.SendMessageRequest",
                    request.SerializeToString(deterministic=True),
                ),
                deadline_seconds=self._deadline_seconds,
                request_id=_runtime_request_id(request_id),
            )
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_TEAMS_PROVIDER_UNAVAILABLE",
                title="Teams connector unavailable",
                detail="The configured Teams message connector did not complete the reply.",
                status=503,
                retryable=True,
                context={"reasonCode": "provider_unavailable"},
            ) from exc
        expected_type = "type.cyrene.io/cyrene.message.connector.v1.DeliveryResult"
        if response.type_url != expected_type:
            raise ExchangeProductError(
                code="EXCHANGE_TEAMS_PROVIDER_RESPONSE_INVALID",
                title="Teams connector response invalid",
                detail="The configured Teams connector returned an unexpected response type.",
                status=502,
            )
        result = message_wire.DeliveryResult()
        try:
            result.ParseFromString(response.value)
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_TEAMS_PROVIDER_RESPONSE_INVALID",
                title="Teams connector response invalid",
                detail="The configured Teams connector returned a malformed delivery result.",
                status=502,
            ) from exc
        if result.status not in {
            message_wire.DELIVERY_STATUS_ACCEPTED,
            message_wire.DELIVERY_STATUS_REJECTED,
            message_wire.DELIVERY_STATUS_RATE_LIMITED,
        }:
            raise ExchangeProductError(
                code="EXCHANGE_TEAMS_PROVIDER_RESPONSE_INVALID",
                title="Teams connector response invalid",
                detail="The configured Teams connector returned an indeterminate delivery state.",
                status=502,
            )
        facts = {fact.name: fact.value for fact in result.vendor_extension.facts if fact.name}
        reason_code = facts.get("reason_code")
        if reason_code in {"AUTH_EXPIRED", "AUTHENTICATION_FAILED", "CREDENTIAL_MISSING"}:
            raise ExchangeProductError(
                code="EXCHANGE_TEAMS_AUTH_EXPIRED",
                title="Teams authorization expired",
                detail=(
                    "The Teams provider reported that its configured bot authorization "
                    "is unavailable."
                ),
                status=401,
                context={"reasonCode": "auth_expired"},
            )
        if reason_code in {"PERMISSION_DENIED", "SCOPE_DENIED"}:
            raise ExchangeProductError(
                code="EXCHANGE_TEAMS_PERMISSION_DENIED",
                title="Teams permission denied",
                detail="The Teams provider denied this configured channel operation.",
                status=403,
                context={"reasonCode": "permission_denied"},
            )
        evidence: dict[str, object] = {
            "status": message_wire.DeliveryStatus.Name(result.status),
            "reasonCode": reason_code,
        }
        if result.status == message_wire.DELIVERY_STATUS_RATE_LIMITED and result.HasField(
            "retry_after"
        ):
            retry_after = max(
                1,
                int(result.retry_after.seconds) + int(result.retry_after.nanos > 0),
            )
            evidence["retryAfterSeconds"] = retry_after
        return MessageEvidence(
            accepted=result.status == message_wire.DELIVERY_STATUS_ACCEPTED,
            vendor_message_id=(result.vendor_message_id or None),
            transport_request_id=request_id
            if result.status == message_wire.DELIVERY_STATUS_ACCEPTED
            else None,
            observed_at=datetime.now(UTC),
            evidence=evidence,
        )


class PlatformConnectorAuthorizationClient:
    """Call only the dedicated connector grant RPC over Exchange workload mTLS."""

    def __init__(
        self,
        *,
        target: str,
        root_certificates_path: Path,
        private_key_path: Path,
        certificate_chain_path: Path,
        deadline_seconds: float = 3.0,
    ) -> None:
        if not target.startswith("grpcs://"):
            raise ValueError("connector Authority target must use grpcs:// mTLS")
        if deadline_seconds <= 0:
            raise ValueError("Authority RPC deadline must be positive")
        self._target = target.removeprefix("grpcs://")
        self._root_certificates = _read_tls_file(root_certificates_path, private=False)
        self._private_key = _read_tls_file(private_key_path, private=True)
        self._certificate_chain = _read_tls_file(certificate_chain_path, private=False)
        self._deadline_seconds = deadline_seconds

    def authorize_connector_operation(
        self,
        *,
        workspace_id: str,
        principal_issuer: str,
        principal_subject: str,
        connection_ref: str,
        provider_id: str,
        profile_ref: str,
        operation_id: str,
        resource_ref: str,
        arguments_digest_sha256: bytes,
        request_id: str,
    ) -> bytes:
        """Request one fresh Directory grant; this client has no legacy RPC stub."""

        authority_wire, authority_grpc = _load_authority_wire()
        request_type = getattr(authority_wire, "AuthorizeConnectorOperationRequest", None)
        if request_type is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Connector authorization is not configured",
                detail="The pinned Platform Authority contract has no connector grant method.",
                status=503,
                retryable=True,
                context={"reasonCode": "authority_connector_grant_contract_missing"},
            )
        if (
            len(arguments_digest_sha256) != 32
            or not request_id
            or not all(
                (
                    workspace_id,
                    principal_issuer,
                    principal_subject,
                    connection_ref,
                    provider_id,
                    profile_ref,
                    operation_id,
                    resource_ref,
                )
            )
        ):
            raise ValueError("connector grant request scope is incomplete")
        rpc_request = request_type(
            workspace_id=workspace_id,
            principal_issuer=principal_issuer,
            principal_subject=principal_subject,
            connection_ref=connection_ref,
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments_digest_sha256=arguments_digest_sha256,
            request_id=request_id,
        )
        import grpc

        credentials = grpc.ssl_channel_credentials(
            root_certificates=self._root_certificates,
            private_key=self._private_key,
            certificate_chain=self._certificate_chain,
        )
        channel = grpc.secure_channel(self._target, credentials)
        try:
            stub_type = getattr(
                authority_grpc,
                "WorkspaceConnectorAuthorizationServiceStub",
                None,
            )
            if stub_type is None:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                    title="Connector authorization is not configured",
                    detail="The pinned Platform contract has no connector-only Authority service.",
                    status=503,
                    retryable=True,
                    context={"reasonCode": "authority_connector_service_missing"},
                )
            response = stub_type(channel).AuthorizeConnectorOperation(
                rpc_request,
                timeout=self._deadline_seconds,
            )
        except ExchangeProductError:
            raise
        except Exception as exc:
            status_code = exc.code() if hasattr(exc, "code") else None
            if status_code == grpc.StatusCode.PERMISSION_DENIED:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Connector authorization denied",
                    detail="Platform Directory did not grant this exact connector operation.",
                    status=403,
                    context={"reasonCode": "directory_grant_denied"},
                ) from exc
            if status_code == grpc.StatusCode.INVALID_ARGUMENT:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Connector request is invalid",
                    detail="Platform rejected the connector operation scope or request fields.",
                    status=422,
                    context={"reasonCode": "authority_request_invalid"},
                ) from exc
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORITY_UNAVAILABLE",
                title="Connector authorization unavailable",
                detail="Platform Authority could not authorize this connector operation.",
                status=503,
                retryable=True,
                context={"reasonCode": "authority_unavailable"},
            ) from exc
        finally:
            channel.close()
        grant = getattr(response, "grant", None)
        if grant is None or not grant.grant_ref:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORITY_RESPONSE_INVALID",
                title="Connector authorization response invalid",
                detail="Platform Authority returned no signed connector operation grant.",
                status=502,
            )
        return bytes(grant.SerializeToString(deterministic=True))


class PlatformAuthorityDelegationClient(DelegationPort):
    """Use the registered Exchange workload profile for delegated enqueue/status."""

    def __init__(
        self,
        *,
        identity_verifier: PlatformAuthorityIdentityVerifier,
        target: str,
        root_certificates_path: Path,
        private_key_path: Path,
        certificate_chain_path: Path,
        workload_id: str,
        audience: str,
        deadline_seconds: float = 5.0,
    ) -> None:
        if not target.startswith("grpcs://") or not workload_id or not audience:
            raise ValueError(
                "a resolved mTLS Authority target, workload ID, and audience are required"
            )
        if deadline_seconds <= 0:
            raise ValueError("Authority RPC deadline must be positive")
        self._identity_verifier = identity_verifier
        self._target = target.removeprefix("grpcs://")
        self._root_certificates = _read_tls_file(root_certificates_path, private=False)
        self._private_key = _read_tls_file(private_key_path, private=True)
        self._certificate_chain = _read_tls_file(certificate_chain_path, private=False)
        self._workload_id = workload_id
        self._audience = audience
        self._deadline_seconds = deadline_seconds

    def authorize_connector_operation(
        self,
        *,
        workspace_id: str,
        principal_issuer: str,
        principal_subject: str,
        connection_ref: str,
        provider_id: str,
        profile_ref: str,
        operation_id: str,
        resource_ref: str,
        arguments_digest_sha256: bytes,
        request_id: str,
    ) -> bytes:
        """Ask Authority for one fresh signed connector grant over Exchange mTLS."""

        authority_wire, _ = _load_authority_wire()
        request_type = getattr(authority_wire, "AuthorizeConnectorOperationRequest", None)
        if request_type is None:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                title="Connector authorization is not configured",
                detail="The pinned Platform Authority contract has no connector grant method.",
                status=503,
                retryable=True,
                context={"reasonCode": "authority_connector_grant_contract_missing"},
            )
        if (
            len(arguments_digest_sha256) != 32
            or not request_id
            or not all(
                (
                    workspace_id,
                    principal_issuer,
                    principal_subject,
                    connection_ref,
                    provider_id,
                    profile_ref,
                    operation_id,
                    resource_ref,
                )
            )
        ):
            raise ValueError("connector grant request scope is incomplete")
        request = request_type(
            workspace_id=workspace_id,
            principal_issuer=principal_issuer,
            principal_subject=principal_subject,
            connection_ref=connection_ref,
            provider_id=provider_id,
            profile_ref=profile_ref,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments_digest_sha256=arguments_digest_sha256,
            request_id=request_id,
        )
        try:
            import grpc

            with self._workload_stub(connector_only=True) as stub:
                response = stub.AuthorizeConnectorOperation(
                    request,
                    timeout=self._deadline_seconds,
                )
        except Exception as exc:
            status_code = exc.code() if hasattr(exc, "code") else None
            code = getattr(grpc.StatusCode, "PERMISSION_DENIED", None)
            if status_code == code:
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
                    title="Connector authorization denied",
                    detail="Platform Directory did not grant this exact connector operation.",
                    status=403,
                    context={"reasonCode": "directory_grant_denied"},
                ) from exc
            if status_code == getattr(grpc.StatusCode, "INVALID_ARGUMENT", None):
                raise ExchangeProductError(
                    code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
                    title="Connector request is invalid",
                    detail="Platform rejected the connector operation scope or request fields.",
                    status=422,
                    context={"reasonCode": "authority_request_invalid"},
                ) from exc
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORITY_UNAVAILABLE",
                title="Connector authorization unavailable",
                detail="Platform Authority could not authorize this connector operation.",
                status=503,
                retryable=True,
                context={"reasonCode": "authority_unavailable"},
            ) from exc
        grant = getattr(response, "grant", None)
        if grant is None or not grant.grant_ref:
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_AUTHORITY_RESPONSE_INVALID",
                title="Connector authorization response invalid",
                detail="Platform Authority returned no signed connector operation grant.",
                status=502,
            )
        return bytes(grant.SerializeToString(deterministic=True))

    def validate_binding(
        self,
        principal: IntegrationPrincipal,
        *,
        bearer_token: str | None,
        execution_credential: bytes | None = None,
        delegation_ref: str,
        binding_id: UUID,
        account_link_ref: str,
    ) -> None:
        """Require the exact member grant, workload audience, and binding scope."""

        del account_link_ref  # Account Center ownership is verified separately by the REST facade.
        if bool(bearer_token) == bool(execution_credential):
            raise PermissionError("exactly one verified grant-read credential is required")
        if bearer_token:
            delegation = self._identity_verifier.get_delegation(
                bearer_token=bearer_token,
                workspace_id=principal.workspace_id,
                delegation_id=delegation_ref,
            )
        else:
            authority_wire, _ = _load_authority_wire()

            if execution_credential is None:
                raise PermissionError("approved Product credential is required")
            request = authority_wire.GetDelegationRequest(
                workspace_id=principal.workspace_id,
                delegation_id=delegation_ref,
            )
            if "execution_credential" not in request.DESCRIPTOR.fields_by_name:
                raise ExchangeProductError(
                    code="EXCHANGE_PLATFORM_DELEGATION_UNAVAILABLE",
                    title="Delegation verification unavailable",
                    detail=(
                        "Platform does not support Product-authenticated self-grant verification."
                    ),
                    status=503,
                    retryable=True,
                )
            credential_field_name = "execution_credential"
            credential_field = getattr(request, credential_field_name)
            credential_field.CopyFrom(
                authority_wire.ExecutionCredential.FromString(execution_credential)
            )
            try:
                with self._workload_stub() as stub:
                    negotiated = stub.NegotiateVersion(
                        authority_wire.NegotiateVersionRequest(
                            minimum_version=2,
                            maximum_version=2,
                        ),
                        timeout=self._deadline_seconds,
                    )
                    if negotiated.selected_version != 2:
                        raise RuntimeError("Platform Authority v2 was not negotiated")
                    delegation = stub.GetDelegation(
                        request,
                        timeout=self._deadline_seconds,
                    )
            except Exception as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_PLATFORM_DELEGATION_UNAVAILABLE",
                    title="Delegation verification unavailable",
                    detail="Platform could not verify the approved member's current delegation.",
                    status=503,
                    retryable=True,
                ) from exc
        try:
            expires_at = delegation.expires_at.ToDatetime(tzinfo=UTC)
        except Exception as exc:
            raise PermissionError("Platform returned a delegation without expiry") from exc
        if (
            delegation.organization_id != principal.organization_id
            or delegation.workspace_id != principal.workspace_id
            or delegation.principal_issuer != principal.issuer
            or delegation.principal_subject != principal.subject
            or delegation.audience != self._audience
            or delegation.managed_workload_id != self._workload_id
            or delegation.revoked
            or expires_at <= datetime.now(UTC)
        ):
            raise PermissionError("Platform delegation is not active for this member and workload")
        expected = {
            "integrationExecuteIssueComment",
            "integrationExecuteIssueState",
            "integrationExecuteIssueQuery",
        }
        received: set[str] = set()
        for scope in delegation.operations:
            if (
                scope.owner_id != "exchange"
                or scope.operation_id not in expected
                or list(scope.resource_ids) != [str(binding_id)]
                or scope.operation_id in received
            ):
                raise PermissionError("Platform delegation scope does not match this binding")
            received.add(scope.operation_id)
        if not received:
            raise PermissionError("Platform delegation has no fixed Exchange issue operation")

    def enqueue_authorized_action(
        self,
        *,
        delegation_ref: str,
        workspace_id: str,
        binding_id: str,
        execution_operation_id: str,
        operation_id: str,
        argument_digest: str,
        idempotency_key: str,
    ) -> AuthorityEnqueueEvidence:
        """Submit the immutable issue intent using the host-authenticated workload."""

        from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
            workspace_authority_pb2 as authority_wire,
        )
        from cyrene_exchange_product.integrations._generated.cyrene.workspace.product.v2 import (
            product_api_pb2 as product_wire,
        )

        invocation = product_wire.ProductApiInvocationV2(
            owner_id="exchange",
            operation_id=execution_operation_id,
            json_body=canonical_json(
                {"operationId": operation_id, "argumentDigest": argument_digest}
            ),
            resource_id=binding_id,
            idempotency_key=idempotency_key,
        )
        try:
            with self._workload_stub() as stub:
                negotiated = stub.NegotiateVersion(
                    authority_wire.NegotiateVersionRequest(
                        minimum_version=2,
                        maximum_version=2,
                        requested_features=["delegated_invocations_v1"],
                    ),
                    timeout=self._deadline_seconds,
                )
                if (
                    negotiated.selected_version != 2
                    or not negotiated.managed_workload_feature_token
                ):
                    raise RuntimeError("Platform did not negotiate the registered workload feature")
                token = authority_wire.ManagedWorkloadFeatureToken.FromString(
                    negotiated.managed_workload_feature_token
                )
                if token.audience != self._audience or token.expires_at.ToDatetime(
                    tzinfo=UTC
                ) <= datetime.now(UTC):
                    raise RuntimeError("Platform workload feature token is invalid or expired")
                response = stub.ApproveAndEnqueueDelegatedInvocation(
                    authority_wire.ApproveAndEnqueueDelegatedInvocationRequest(
                        workspace_id=workspace_id,
                        delegation_id=delegation_ref,
                        invocation=invocation,
                        managed_workload_feature_token=negotiated.managed_workload_feature_token,
                    ),
                    timeout=self._deadline_seconds,
                )
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_DELEGATED_ENQUEUE_UNAVAILABLE",
                title="Delegated execution unavailable",
                detail="Platform could not enqueue the stored issue intent.",
                status=503,
                retryable=True,
            ) from exc
        if not response.invocation_id:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_DELEGATED_ENQUEUE_INVALID",
                title="Delegated execution response invalid",
                detail="Platform did not return a durable invocation reference.",
                status=502,
            )
        state = _authority_invocation_state(authority_wire, response.state)
        return AuthorityEnqueueEvidence(response.invocation_id, state)

    def poll_invocation(self, invocation_id: str) -> AuthorityInvocationEvidence:
        """Read status under Exchange mTLS; status never supplies execution proof."""

        from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
            workspace_authority_pb2 as authority_wire,
        )

        try:
            with self._workload_stub() as stub:
                response = stub.GetProductInvocationStatus(
                    authority_wire.GetProductInvocationStatusRequest(invocation_id=invocation_id),
                    timeout=self._deadline_seconds,
                )
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_INVOCATION_STATUS_UNAVAILABLE",
                title="Invocation status unavailable",
                detail="Platform could not return current delegated invocation status.",
                status=503,
                retryable=True,
            ) from exc
        if response.invocation_id != invocation_id:
            raise PermissionError("Platform returned status for a different invocation")
        return AuthorityInvocationEvidence(
            invocation_id=invocation_id,
            state=_authority_invocation_state(authority_wire, response.state),
            observed_at=datetime.now(UTC),
            result_ref=None,
        )

    def _workload_stub(self, *, connector_only: bool = False) -> Any:
        """Return a scoped context manager for one short-lived gRPC channel."""

        from contextlib import contextmanager

        import grpc

        from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
            workspace_authority_pb2_grpc as authority_grpc,
        )

        @contextmanager
        def channel_scope() -> Any:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=self._root_certificates,
                private_key=self._private_key,
                certificate_chain=self._certificate_chain,
            )
            channel = grpc.secure_channel(self._target, credentials)
            try:
                stub_type_name = (
                    "WorkspaceConnectorAuthorizationServiceStub"
                    if connector_only
                    else "WorkspaceAuthorityServiceStub"
                )
                stub_type = getattr(authority_grpc, stub_type_name, None)
                if stub_type is None:
                    raise ExchangeProductError(
                        code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
                        title="Connector authorization is not configured",
                        detail=(
                            "The pinned Platform contract has no connector-only Authority service."
                        ),
                        status=503,
                        retryable=True,
                        context={"reasonCode": "authority_connector_service_missing"},
                    )
                yield stub_type(channel)
            finally:
                channel.close()

        return channel_scope()


def _authority_invocation_state(wire: Any, value: int) -> AuthorityInvocationState:
    """Map only known Platform lifecycle observations without inventing outcomes."""

    mapping = {
        wire.INVOCATION_STATE_PENDING: AuthorityInvocationState.PENDING,
        wire.INVOCATION_STATE_CLAIMED: AuthorityInvocationState.AUTHORIZED,
        wire.INVOCATION_STATE_ACKNOWLEDGED: AuthorityInvocationState.DISPATCHED,
        wire.INVOCATION_STATE_SUCCEEDED: AuthorityInvocationState.COMPLETED,
        wire.INVOCATION_STATE_FAILED: AuthorityInvocationState.FAILED,
        wire.INVOCATION_STATE_UNKNOWN_RESULT: AuthorityInvocationState.UNKNOWN_RESULT,
    }
    state = mapping.get(value)
    if state is None:
        raise ValueError("Platform returned an unknown invocation state")
    return state


def _runtime_request_id(idempotency_key: str) -> str:
    """Derive a stable UUID request ID from an internal durable idempotency key."""

    try:
        return str(UUID(idempotency_key))
    except ValueError:
        return str(uuid5(NAMESPACE_URL, f"cyrene-exchange:{idempotency_key}"))


def _decode_tool_result(value: bytes, *, tool_id: str) -> dict[str, Any]:
    """Decode the canonical ToolProvider response and one JSON result part."""

    from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
        tool_provider_pb2 as tool_wire,
    )

    response = tool_wire.CallToolResponse()
    try:
        response.ParseFromString(value)
    except Exception as exc:
        raise RuntimeError("GitHub provider returned malformed CallToolResponse protobuf") from exc
    result_kind = response.WhichOneof("result")
    if result_kind == "error":
        if tool_id == "github.issue.get" and response.error.retryable:
            raise RetryableReadError("github_provider_unavailable")
        raise RuntimeError("GitHub provider returned a typed provider error")
    if result_kind != "outcome":
        raise RuntimeError("GitHub provider response has no result")
    outcome = response.outcome
    if outcome.is_error:
        error_payload = _structured_tool_json(outcome.content)
        error = error_payload.get("error")
        if not isinstance(error, Mapping):
            raise RuntimeError("GitHub provider returned a malformed domain error")
        code = error.get("code")
        retryable = error.get("retryable") is True
        retry_after = error.get("retry_after_seconds")
        uncertain = error.get("outcome") == "UNKNOWN"
        if tool_id == "github.issue.get" and retryable:
            raise RetryableReadError(
                str(code or "github_provider_unavailable"),
                retry_after_seconds=(retry_after if isinstance(retry_after, int) else None),
            )
        if uncertain:
            raise RuntimeError("GitHub provider could not confirm the write outcome")
        if code in {
            "AUTHENTICATION_DENIED",
            "AUTHORIZATION_DENIED",
            "INVALID_ARGUMENTS",
            "ISSUE_IDENTITY_MISMATCH",
            "REPOSITORY_IDENTITY_MISMATCH",
            "RESOURCE_NOT_FOUND",
            "UPSTREAM_REJECTED",
        }:
            return {"status": "REJECTED", "reason_code": str(code)}
        raise ExchangeProductError(
            code="EXCHANGE_GITHUB_OPERATION_FAILED",
            title="GitHub operation failed",
            detail="The configured GitHub provider rejected the fixed operation.",
            status=502,
            retryable=retryable,
        )
    content = outcome.content
    results: list[dict[str, Any]] = []
    for item in content:
        if item.WhichOneof("content") == "json":
            try:
                decoded = json.loads(item.json.json)
            except json.JSONDecodeError as exc:
                raise RuntimeError("GitHub provider returned malformed result JSON") from exc
            if isinstance(decoded, Mapping):
                results.append(dict(decoded))
    if len(results) != 1:
        raise RuntimeError("GitHub provider must return exactly one structured result")
    return results[0]


def _decode_generic_provider_result(value: bytes, *, provider: str) -> dict[str, Any]:
    """Map one typed connector failure to a structured Exchange HTTP problem."""

    from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
        tool_provider_pb2 as tool_wire,
    )

    try:
        response = tool_wire.CallToolResponse.FromString(value)
    except Exception as exc:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
            title="Provider response invalid",
            detail=f"The configured {provider} provider returned malformed response data.",
            status=502,
        ) from exc
    result_kind = response.WhichOneof("result")
    if result_kind == "error":
        code_name = tool_wire.ToolProviderErrorCode.Name(response.error.code)
        _raise_provider_error(code_name, retryable=response.error.retryable)
    if result_kind != "outcome":
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
            title="Provider response invalid",
            detail=f"The configured {provider} provider returned no structured result.",
            status=502,
        )
    if response.outcome.is_error:
        error = _structured_tool_json(response.outcome.content).get("error")
        if not isinstance(error, Mapping) or not isinstance(error.get("code"), str):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
                title="Provider response invalid",
                detail=f"The configured {provider} provider returned an invalid structured error.",
                status=502,
            )
        _raise_provider_error(
            str(error["code"]),
            retryable=error.get("retryable") is True,
            unknown=error.get("outcome") == "UNKNOWN" or error.get("state") == "UNKNOWN_RESULT",
        )
    result = _structured_tool_json(response.outcome.content)
    if result:
        return result
    raise ExchangeProductError(
        code="EXCHANGE_CONNECTOR_PROVIDER_RESPONSE_INVALID",
        title="Provider response invalid",
        detail=f"The configured {provider} provider must return one structured JSON object.",
        status=502,
    )


def _decode_computer_provider_result(value: bytes, *, tool_id: str) -> dict[str, Any]:
    """Validate one computer tool result and keep the serialized reply bounded."""

    from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
        tool_provider_pb2 as tool_wire,
    )

    if len(value) > 1_000_000:
        raise ExchangeProductError(
            code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_TOO_LARGE",
            title="Computer result is too large",
            detail="The computer runtime response exceeds Exchange's bounded transport size.",
            status=502,
        )
    try:
        response = tool_wire.CallToolResponse.FromString(value)
    except Exception as exc:
        raise ExchangeProductError(
            code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
            title="Computer runner response invalid",
            detail="The computer runtime returned malformed response data.",
            status=502,
        ) from exc
    result_kind = response.WhichOneof("result")
    if result_kind == "error":
        try:
            code_name = tool_wire.ToolProviderErrorCode.Name(response.error.code)
        except ValueError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The computer runtime returned an unknown protocol error.",
                status=502,
            ) from exc
        _raise_provider_error(code_name, retryable=response.error.retryable)
    if result_kind != "outcome":
        raise ExchangeProductError(
            code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
            title="Computer runner response invalid",
            detail="The computer runtime returned no structured result.",
            status=502,
        )
    try:
        result = _computer_structured_tool_json(response.outcome.content)
    except Exception as exc:
        raise ExchangeProductError(
            code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
            title="Computer runner response invalid",
            detail="The computer runtime must return one structured JSON object.",
            status=502,
        ) from exc
    if response.outcome.is_error and not (
        tool_id == "computer.command.execute" and "exit_code" in result
    ):
        error = result.get("error")
        retryable = error.get("retryable") is True if isinstance(error, Mapping) else False
        code_value = error.get("code") if isinstance(error, Mapping) else None
        code_detail = str(code_value) if isinstance(code_value, (str, int)) else "runtime_failure"
        raise ExchangeProductError(
            code=(
                "EXCHANGE_COMPUTER_PROVIDER_UNAVAILABLE"
                if retryable
                else "EXCHANGE_COMPUTER_OPERATION_FAILED"
            ),
            title="Computer operation failed",
            detail="The isolated computer runtime could not complete the fixed operation.",
            status=503 if retryable else 502,
            retryable=retryable,
            context={"reasonCode": code_detail[:64]},
        )

    safe = dict(result)
    if tool_id == "computer.command.execute":
        expected_fields = {
            "exit_code",
            "duration_ms",
            "stdout",
            "stderr",
            "stdout_truncated",
            "stderr_truncated",
            "sha256_hash",
            "resource_usage",
        }
        exit_code = safe.get("exit_code")
        duration_ms = safe.get("duration_ms")
        stdout = safe.get("stdout")
        stderr = safe.get("stderr")
        if (
            set(safe) != expected_fields
            or isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or isinstance(duration_ms, bool)
            or not isinstance(duration_ms, int)
            or duration_ms < 0
            or not isinstance(stdout, str)
            or not isinstance(stderr, str)
            or len(stdout.encode("utf-8")) > 65_536
            or len(stderr.encode("utf-8")) > 65_536
            or not isinstance(safe.get("stdout_truncated"), bool)
            or not isinstance(safe.get("stderr_truncated"), bool)
            or not isinstance(safe.get("sha256_hash"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(safe.get("sha256_hash")))
            or safe.get("resource_usage") is not None
        ):
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The command result exceeds its fixed output contract.",
                status=502,
            )
        safe["status"] = "COMMAND_COMPLETED" if exit_code == 0 else "COMMAND_FAILED"
        safe["isError"] = exit_code != 0
    elif tool_id == "computer.file.write":
        bytes_written = safe.get("bytes_written")
        if (
            set(safe) != {"bytes_written"}
            or isinstance(bytes_written, bool)
            or not isinstance(bytes_written, int)
            or bytes_written < 0
        ):
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The file write result is invalid.",
                status=502,
            )
        safe["status"] = "WRITE_COMPLETED"
    elif tool_id == "computer.file.read":
        if set(safe) not in ({"size_bytes", "content_text"}, {"size_bytes", "content_base64"}):
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The bounded file read result contains unexpected fields.",
                status=502,
            )
        size_bytes = safe.get("size_bytes")
        text_content = safe.get("content_text")
        base64_content = safe.get("content_base64")
        has_text = isinstance(text_content, str)
        has_base64 = isinstance(base64_content, str)
        if (
            isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes < 0
            or has_text == has_base64
            or (isinstance(text_content, str) and len(text_content.encode("utf-8")) > 65_536)
        ):
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The bounded file read result is invalid.",
                status=502,
            )
        if has_text:
            assert isinstance(text_content, str)
            if len(text_content.encode("utf-8")) != size_bytes:
                raise ExchangeProductError(
                    code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                    title="Computer runner response invalid",
                    detail="The file read size does not match its returned UTF-8 content.",
                    status=502,
                )
        else:
            assert isinstance(base64_content, str)
            try:
                decoded = base64.b64decode(base64_content, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ExchangeProductError(
                    code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                    title="Computer runner response invalid",
                    detail="The file read content is not valid base64.",
                    status=502,
                ) from exc
            if (
                len(decoded) > 65_536
                or len(decoded) != size_bytes
                or base64.b64encode(decoded).decode("ascii") != base64_content
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                    title="Computer runner response invalid",
                    detail="The file read exceeds its chunk limit or uses non-canonical base64.",
                    status=502,
                )
    elif tool_id == "computer.directory.list":
        entries = safe.get("entries")
        if set(safe) != {"entries"} or not isinstance(entries, list):
            raise ExchangeProductError(
                code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                title="Computer runner response invalid",
                detail="The directory list result is invalid.",
                status=502,
            )
        for entry in entries:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"name", "is_directory", "size_bytes", "modified_at_ms"}
                or not isinstance(entry.get("name"), str)
                or not entry["name"]
                or "\x00" in entry["name"]
                or len(entry["name"].encode("utf-8")) > 1024
                or not isinstance(entry.get("is_directory"), bool)
                or isinstance(entry.get("size_bytes"), bool)
                or not isinstance(entry.get("size_bytes"), int)
                or entry["size_bytes"] < 0
                or isinstance(entry.get("modified_at_ms"), bool)
                or not isinstance(entry.get("modified_at_ms"), int)
            ):
                raise ExchangeProductError(
                    code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
                    title="Computer runner response invalid",
                    detail="A directory entry does not match the fixed result contract.",
                    status=502,
                )

    try:
        response_bytes = len(canonical_json(safe))
    except (TypeError, ValueError) as exc:
        raise ExchangeProductError(
            code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_INVALID",
            title="Computer runner response invalid",
            detail="The computer result is outside the JSON response contract.",
            status=502,
        ) from exc
    if response_bytes > 800_000:
        raise ExchangeProductError(
            code="EXCHANGE_COMPUTER_PROVIDER_RESPONSE_TOO_LARGE",
            title="Computer result is too large",
            detail="The computer result exceeds Exchange's bounded response size.",
            status=502,
        )
    return safe


def _computer_structured_tool_json(content: Any) -> dict[str, Any]:
    """Read exactly one duplicate-free JSON result from the fixed host runner."""

    if len(content) != 1 or content[0].WhichOneof("content") != "json":
        raise ValueError("computer provider must return one structured JSON result")
    try:
        decoded = json.loads(
            content[0].json.json,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("computer provider returned malformed structured JSON") from exc
    if not isinstance(decoded, Mapping):
        raise ValueError("computer provider result must be a JSON object")
    return dict(decoded)


def _raise_provider_error(
    code: str,
    *,
    retryable: bool,
    unknown: bool = False,
) -> None:
    """Translate vendor-neutral Plugin error codes without exposing raw output."""

    normalized = code.upper()
    if unknown:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_OUTCOME_UNKNOWN",
            title="Provider operation outcome is unknown",
            detail=(
                "The provider could not confirm whether this operation completed; "
                "query its status before retrying."
            ),
            status=502,
            context={"reasonCode": normalized, "resultState": "UNKNOWN_RESULT"},
        )
    if normalized in {
        "AUTHENTICATION_DENIED",
        "AUTHENTICATION_FAILED",
        "AUTH_EXPIRED",
        "CREDENTIAL_MISSING",
    }:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_AUTH_EXPIRED",
            title="Provider authorization expired",
            detail="The provider could not authenticate with its configured server-side identity.",
            status=401,
            context={"reasonCode": "auth_expired"},
        )
    if normalized in {"AUTHORIZATION_DENIED", "PERMISSION_DENIED", "SCOPE_DENIED"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PERMISSION_DENIED",
            title="Provider permission denied",
            detail="The configured provider identity lacks permission for this operation.",
            status=403,
            context={"reasonCode": "permission_denied"},
        )
    if normalized in {"INVALID_ARGUMENTS", "OPERATION_NOT_FOUND", "UNSUPPORTED_OPERATION"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_OPERATION_INVALID",
            title="Provider operation is invalid",
            detail="The provider rejected the fixed operation or its typed arguments.",
            status=422,
            context={"reasonCode": normalized.lower()},
        )
    if normalized in {"RESOURCE_NOT_FOUND", "PROFILE_NOT_FOUND"}:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_RESOURCE_NOT_FOUND",
            title="Provider resource not found",
            detail="The configured provider did not find the selected resource or profile.",
            status=404,
            context={"reasonCode": normalized.lower()},
        )
    raise ExchangeProductError(
        code="EXCHANGE_CONNECTOR_PROVIDER_UNAVAILABLE",
        title="Provider operation failed",
        detail="The configured provider could not complete the operation.",
        status=503 if retryable else 502,
        retryable=retryable,
        context={"reasonCode": normalized.lower()},
    )


def _structured_tool_json(content: Any) -> dict[str, Any]:
    """Extract exactly one JSON part from a typed provider failure outcome."""

    values: list[dict[str, Any]] = []
    for item in content:
        if item.WhichOneof("content") == "json":
            try:
                decoded = json.loads(item.json.json)
            except json.JSONDecodeError as exc:
                raise RuntimeError("GitHub provider returned malformed error JSON") from exc
            if isinstance(decoded, Mapping):
                values.append(dict(decoded))
    if len(values) != 1:
        raise RuntimeError("GitHub provider must return one structured error")
    return values[0]
