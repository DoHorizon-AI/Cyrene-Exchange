"""Production clients for fixed Account Center and GitHub capabilities.

Every call targets a host-resolved DirectPluginRuntime endpoint and a fixed
capability method. Payloads contain only the capability contract, never a
caller-selected endpoint or credential.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
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
    ProviderRejectedError,
    RetryableReadError,
    WriteEvidence,
)

if TYPE_CHECKING:
    from cyrene_plugin_runtime import DirectPayload

ACCOUNT_CAPABILITY = "account.center.v1"
PROVIDER_CAPABILITY = "tool.provider.v1"
ACCOUNT_METHODS = {
    "begin_link": "BeginLink",
    "complete_github_link": "CompleteGitHubLink",
    "observe_wecom_challenge": "ObserveWeComChallenge",
    "confirm_wecom_link": "ConfirmWeComLink",
    "list_links": "ListLinks",
    "get_authorization": "GetAuthorization",
    "unlink": "Unlink",
    "create_credential_lease": "CreateCredentialLease",
    "redeem_credential_lease": "RedeemCredentialLease",
    "resolve_linked_sender": "ResolveLinkedSender",
}
GITHUB_TOOL_IDS = frozenset(
    {"github.issue.get", "github.issue.comment.create", "github.issue.state.update"}
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
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        self._client = client
        self._exchange_signer = exchange_signer
        if not binding_id.strip():
            raise ValueError("Account Center binding_id is required")
        self._binding_id = binding_id
        self._callback_signer = callback_signer
        self._wecom_source_signer = wecom_source_signer
        self._deadline_seconds = deadline_seconds

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
            raise RuntimeError(f"the configured {method} Account Center signer is unavailable")
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
        try:
            response = self._client.invoke(
                capability=ACCOUNT_CAPABILITY,
                interface_version="1",
                method=method,
                request=_direct_payload(request_type, canonical_json(request)),
                deadline_seconds=self._deadline_seconds,
                request_id=request_id,
            )
        except Exception as exc:
            if getattr(exc, "domain_code", "") in {
                "idempotency_conflict",
                "idempotency_in_progress",
            }:
                raise ExchangeProductError(
                    code="EXCHANGE_IDEMPOTENCY_CONFLICT",
                    title="Idempotency key conflict",
                    detail=(
                        "The Account Center idempotency key is already bound to another request."
                    ),
                    status=409,
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
    dto_type = dto_types.get(method)
    if dto_type is None:
        raise ValueError("unsupported Account Center method")
    values = dict(payload)
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
    """Invoke only the three allowlisted GitHub issue tools through Plugins."""

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

    def _workload_stub(self) -> Any:
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
                yield authority_grpc.WorkspaceAuthorityServiceStub(channel)
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
