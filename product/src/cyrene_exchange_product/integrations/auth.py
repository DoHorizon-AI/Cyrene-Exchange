"""Exchange integration authentication and capability caller signing.

This module accepts identity only after Platform has verified the caller's
current first-party bearer. It also signs fixed Product-to-Plugin requests.
It never reads roles or identity from a request body.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.models import IntegrationPrincipal

_CONNECTOR_OPERATOR_ROLE = "navigator.connector.operator.v1"


@dataclass(frozen=True, slots=True)
class VerifiedPlatformIdentity:
    """Identity fields decoded from the Platform Authority VerifyIdentity RPC."""

    issuer: str
    subject: str
    organization_id: str
    workspace_id: str
    granted_operation_ids: frozenset[str]
    directory_roles: frozenset[str] = frozenset()


class IdentityVerifier(Protocol):
    """Verify a current first-party credential for one requested workspace."""

    def verify(self, *, bearer_token: str, workspace_id: str) -> VerifiedPlatformIdentity:
        """Return Platform-verified identity or raise a fail-closed error."""


class PlatformAuthorityIdentityVerifier:
    """Verify current identity and Exchange operation grants through Authority v2.

    The bearer is forwarded to Platform for signature, issuer, expiry, and
    directory verification. Exact operation grants come from the current
    Authority catalog snapshot, never from local role-to-operation mappings.
    """

    def __init__(
        self,
        *,
        target: str,
        root_certificates: bytes | None = None,
        private_key: bytes | None = None,
        certificate_chain: bytes | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        if not target or target.startswith(("http://", "https://")):
            raise ValueError("Platform Authority target must be a gRPC target")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        is_unix = target.startswith("unix:")
        tls_values = (root_certificates, private_key, certificate_chain)
        if is_unix and any(tls_values):
            raise ValueError("protected Unix Authority channels do not accept TCP TLS files")
        if not is_unix and not all(tls_values):
            raise ValueError("remote Authority TCP requires a complete managed mTLS profile")
        self._target = target
        self._root_certificates = root_certificates
        self._private_key = private_key
        self._certificate_chain = certificate_chain
        self._timeout_seconds = timeout_seconds

    @classmethod
    def from_unix_socket(
        cls, socket_path: Path, *, timeout_seconds: float = 3.0
    ) -> PlatformAuthorityIdentityVerifier:
        """Configure the local protected user-verification Unix channel."""

        info = socket_path.stat()
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_mode & 0o002
            or info.st_uid not in {0, os.geteuid()}
        ):
            raise ValueError("Authority Unix socket must be owned by a trusted local principal")
        return cls(target=f"unix://{socket_path}", timeout_seconds=timeout_seconds)

    @classmethod
    def from_managed_tls_files(
        cls,
        *,
        target: str,
        root_certificates_path: Path,
        private_key_path: Path,
        certificate_chain_path: Path,
    ) -> PlatformAuthorityIdentityVerifier:
        """Load private TLS material from host-managed files with safe modes."""

        root = _read_tls_file(root_certificates_path, private=False)
        key = _read_tls_file(private_key_path, private=True)
        chain = _read_tls_file(certificate_chain_path, private=False)
        return cls(
            target=target,
            root_certificates=root,
            private_key=key,
            certificate_chain=chain,
        )

    def verify(self, *, bearer_token: str, workspace_id: str) -> VerifiedPlatformIdentity:
        """Verify identity and fetch current grants over the same Authority channel."""

        if not bearer_token or not workspace_id:
            raise _unauthenticated()
        try:
            import grpc
        except Exception as exc:
            raise _platform_auth_unavailable() from exc
        try:
            authority_wire, authority_grpc = _load_authority_wire()

            if self._target.startswith("unix:"):
                channel = grpc.insecure_channel(self._target)
            else:
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=self._root_certificates,
                    private_key=self._private_key,
                    certificate_chain=self._certificate_chain,
                )
                channel = grpc.secure_channel(self._target, credentials)
            try:
                stub = authority_grpc.WorkspaceAuthorityServiceStub(channel)
                try:
                    negotiation = stub.NegotiateVersion(
                        authority_wire.NegotiateVersionRequest(
                            minimum_version=2,
                            maximum_version=2,
                        ),
                        timeout=self._timeout_seconds,
                    )
                except grpc.RpcError as exc:
                    raise _platform_auth_unavailable() from exc
                if negotiation.selected_version != 2:
                    raise RuntimeError("Platform Authority v2 was not negotiated")
                metadata = (("authorization", f"Bearer {bearer_token}"),)
                try:
                    response = stub.VerifyIdentity(
                        authority_wire.VerifyIdentityRequest(workspace_id=workspace_id),
                        timeout=self._timeout_seconds,
                        metadata=metadata,
                    )
                except grpc.RpcError as exc:
                    raise _identity_rpc_error(exc, grpc) from exc
                try:
                    catalog = stub.GetCatalogSnapshot(
                        authority_wire.CatalogSnapshotRequest(workspace_id=workspace_id),
                        timeout=self._timeout_seconds,
                        metadata=metadata,
                    )
                except grpc.RpcError as exc:
                    raise _identity_rpc_error(exc, grpc) from exc
            finally:
                channel.close()
        except ExchangeProductError:
            raise
        except Exception as exc:  # Transport/protocol errors are intentionally sanitized.
            raise _platform_auth_unavailable() from exc
        exchange_owner = next(
            (item for item in catalog.owners if item.owner_id == "exchange"), None
        )
        identity = VerifiedPlatformIdentity(
            issuer=response.issuer,
            subject=response.subject,
            organization_id=response.organization_id,
            workspace_id=response.workspace_id,
            granted_operation_ids=(
                frozenset(exchange_owner.granted_operation_ids)
                if exchange_owner is not None
                else frozenset()
            ),
            directory_roles=frozenset(response.directory_roles),
        )
        if (
            not identity.issuer
            or not identity.subject
            or not identity.organization_id
            or identity.workspace_id != workspace_id
            or catalog.organization_id != identity.organization_id
            or catalog.workspace_id != workspace_id
            or exchange_owner is None
        ):
            raise _unauthenticated()
        return identity

    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal:
        """Build a principal from fresh Platform identity, catalog, and exact setup role."""

        identity = self.verify(bearer_token=bearer_token, workspace_id=workspace_id)
        granted_operations = set(identity.granted_operation_ids)
        # Connector profile linking is setup/maintenance; Platform returns this
        # dedicated Directory role in the freshly verified identity response.
        # Provider execution still requires a separate exact signed grant.
        if _CONNECTOR_OPERATOR_ROLE in identity.directory_roles:
            granted_operations.add(_CONNECTOR_OPERATOR_ROLE)
        return IntegrationPrincipal(
            issuer=identity.issuer,
            subject=identity.subject,
            organization_id=identity.organization_id,
            workspace_id=identity.workspace_id,
            allowed_operation_ids=frozenset(granted_operations),
        )

    def get_delegation(
        self,
        *,
        bearer_token: str,
        workspace_id: str,
        delegation_id: str,
    ) -> Any:
        """Read self-owned grant metadata through the current first-party session."""

        if not bearer_token or not workspace_id or not delegation_id:
            raise _unauthenticated()
        try:
            import grpc

            authority_wire, authority_grpc = _load_authority_wire()

            if self._target.startswith("unix:"):
                channel = grpc.insecure_channel(self._target)
            else:
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=self._root_certificates,
                    private_key=self._private_key,
                    certificate_chain=self._certificate_chain,
                )
                channel = grpc.secure_channel(self._target, credentials)
            try:
                stub = authority_grpc.WorkspaceAuthorityServiceStub(channel)
                negotiation = stub.NegotiateVersion(
                    authority_wire.NegotiateVersionRequest(
                        minimum_version=2,
                        maximum_version=2,
                    ),
                    timeout=self._timeout_seconds,
                )
                if negotiation.selected_version != 2:
                    raise RuntimeError("Platform Authority v2 was not negotiated")
                response = stub.GetDelegation(
                    authority_wire.GetDelegationRequest(
                        workspace_id=workspace_id,
                        delegation_id=delegation_id,
                    ),
                    timeout=self._timeout_seconds,
                    metadata=(("authorization", f"Bearer {bearer_token}"),),
                )
            finally:
                channel.close()
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_DELEGATION_UNAVAILABLE",
                title="Delegation verification unavailable",
                detail="Platform could not verify the requested current delegation.",
                status=503,
                retryable=True,
            ) from exc
        if response.delegation_id != delegation_id or response.workspace_id != workspace_id:
            raise _unauthenticated()
        return response


class PlatformExecutionAuthorizationVerifier:
    """Validate one signed Product execution credential through Platform Authority."""

    def __init__(
        self,
        *,
        target: str,
        root_certificates: bytes,
        private_key: bytes,
        certificate_chain: bytes,
        timeout_seconds: float = 3.0,
    ) -> None:
        if not target or target.startswith(("http://", "https://")):
            raise ValueError("Platform execution target must be a gRPC host:port")
        if not root_certificates or not private_key or not certificate_chain:
            raise ValueError("registered Product workload mTLS material is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._target = target
        self._root_certificates = root_certificates
        self._private_key = private_key
        self._certificate_chain = certificate_chain
        self._timeout_seconds = timeout_seconds

    @classmethod
    def from_managed_tls_files(
        cls,
        *,
        target: str,
        root_certificates_path: Path,
        private_key_path: Path,
        certificate_chain_path: Path,
    ) -> PlatformExecutionAuthorizationVerifier:
        """Load the Exchange ProductWorkload certificate profile from managed files."""

        return cls(
            target=target,
            root_certificates=_read_tls_file(root_certificates_path, private=False),
            private_key=_read_tls_file(private_key_path, private=True),
            certificate_chain=_read_tls_file(certificate_chain_path, private=False),
        )

    def verify(self, encoded_credential: bytes) -> Any:
        """Return the full Authority ApprovedInvocation or fail closed."""

        if not encoded_credential or len(encoded_credential) > 64 * 1024:
            raise _unauthenticated()
        try:
            import grpc

            authority_wire, authority_grpc = _load_authority_wire()

            credential = authority_wire.ExecutionCredential.FromString(encoded_credential)
            channel_credentials = grpc.ssl_channel_credentials(
                root_certificates=self._root_certificates,
                private_key=self._private_key,
                certificate_chain=self._certificate_chain,
            )
            channel = grpc.secure_channel(self._target, channel_credentials)
            try:
                stub = authority_grpc.WorkspaceAuthorityServiceStub(channel)
                response = stub.ValidateProductExecutionAuthorization(
                    authority_wire.ValidateProductExecutionAuthorizationRequest(
                        credential=credential
                    ),
                    timeout=self._timeout_seconds,
                )
            finally:
                channel.close()
            approved = response.approved_invocation
            if not approved.invocation_id or not approved.HasField("canonical_envelope"):
                raise ValueError("Authority returned no approved invocation envelope")
            if approved.credential.SerializeToString(
                deterministic=True
            ) != credential.SerializeToString(deterministic=True):
                raise ValueError("Authority returned a different execution credential")
            return approved
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PLATFORM_EXECUTION_AUTH_INVALID",
                title="Approved execution required",
                detail="Platform did not validate this Product execution credential.",
                status=403,
            ) from exc


@dataclass(frozen=True, slots=True)
class TrustedCallerContext:
    """Capability request provenance signed by one configured Exchange caller."""

    caller_id: str
    binding_id: str
    issuer: str
    subject: str
    organization_id: str
    workspace_id: str | None
    request_id: str
    issued_at: int
    expires_at: int
    method: str
    operation_id: str
    payload_sha256: str
    signature: str

    def as_payload(self) -> dict[str, object]:
        """Return the exact snake-case context expected by Account Center."""

        return {
            "caller_id": self.caller_id,
            "binding_id": self.binding_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "organization_id": self.organization_id,
            "workspace_id": self.workspace_id,
            "request_id": self.request_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "method": self.method,
            "operation_id": self.operation_id,
            "payload_sha256": self.payload_sha256,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class ProviderCallContext:
    """Exchange provenance envelope accepted by the GitHub provider Plugin."""

    method: str
    payload_sha256: str
    binding_id: str
    caller_id: str
    issuer: str
    subject: str
    organization_id: str
    workspace_id: str
    request_id: str
    issued_at: int
    expires_at: int
    operation_id: str
    signature: str

    def as_payload(self) -> dict[str, object]:
        """Return the provider contract's exact signed context fields."""

        return {
            "method": self.method,
            "payload_sha256": self.payload_sha256,
            "binding_id": self.binding_id,
            "caller_id": self.caller_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "organization_id": self.organization_id,
            "workspace_id": self.workspace_id,
            "request_id": self.request_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "operation_id": self.operation_id,
            "signature": self.signature,
        }


class AccountCenterRequestSigner:
    """Create the canonical per-method HMAC context required by Account Center."""

    def __init__(
        self,
        *,
        caller_id: str,
        key: bytes,
        lifetime_seconds: int = 30,
    ) -> None:
        if not caller_id.strip() or len(key) != 32:
            raise ValueError("caller_id and a 256-bit Account Center HMAC key are required")
        if not 1 <= lifetime_seconds <= 60:
            raise ValueError("trusted caller context lifetime must be between 1 and 60 seconds")
        self._caller_id = caller_id
        self._key = key
        self._lifetime_seconds = lifetime_seconds

    @property
    def caller_id(self) -> str:
        """Return this signer’s configured caller name, never its secret."""

        return self._caller_id

    @classmethod
    def from_secret_reference(cls, caller_id: str, secret_ref: str) -> AccountCenterRequestSigner:
        """Resolve the supported ``env://NAME`` secret reference at startup."""

        if not secret_ref.startswith("env://"):
            raise ValueError("Account Center signer currently requires an env:// secret reference")
        name = secret_ref.removeprefix("env://")
        value = os.environ.get(name)
        if not value:
            raise ValueError("configured Account Center HMAC secret reference is empty")
        try:
            key = (
                bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value, validate=True)
            )
        except (ValueError, TypeError):
            raise ValueError("configured Account Center HMAC secret reference is invalid") from None
        if len(key) != 32:
            raise ValueError("configured Account Center HMAC key must decode to 32 bytes")
        return cls(caller_id=caller_id, key=key)

    def sign(
        self,
        *,
        principal: IntegrationPrincipal,
        binding_id: str,
        operation_id: str,
        payload: Mapping[str, object],
        request_id: str | None = None,
        now: datetime | None = None,
    ) -> TrustedCallerContext:
        """Bind a one-method context to exact canonical payload bytes and actor."""

        current = now or datetime.now(UTC)
        issued_at = int(current.timestamp())
        selected_request_id = request_id or str(uuid4())
        return self._signed_context(
            operation_id=operation_id,
            principal=principal,
            binding_id=binding_id,
            payload=payload,
            request_id=selected_request_id,
            issued_at=issued_at,
        )

    def sign_provider_call(
        self,
        *,
        principal: IntegrationPrincipal,
        binding_id: str,
        operation_id: str,
        method: str,
        payload: Mapping[str, object],
        request_id: str | None = None,
        now: datetime | None = None,
    ) -> ProviderCallContext:
        """Sign the provider's separate call_tool envelope including binding."""

        current = now or datetime.now(UTC)
        issued_at = int(current.timestamp())
        sdk_context = _sdk_sign_context(
            method=method,
            payload=payload,
            caller_id=self._caller_id,
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            binding_id=binding_id,
            request_id=request_id or str(uuid4()),
            operation_id=operation_id,
            key=self._key,
            issued_at=issued_at,
            expires_at=issued_at + self._lifetime_seconds,
        )
        return ProviderCallContext(**sdk_context)

    def _signed_context(
        self,
        *,
        operation_id: str,
        principal: IntegrationPrincipal,
        binding_id: str,
        payload: Mapping[str, object],
        request_id: str,
        issued_at: int,
    ) -> TrustedCallerContext:
        sdk_context = _sdk_sign_context(
            method=operation_id,
            payload=payload,
            caller_id=self._caller_id,
            issuer=principal.issuer,
            subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            binding_id=binding_id,
            request_id=request_id,
            operation_id=operation_id,
            key=self._key,
            issued_at=issued_at,
            expires_at=issued_at + self._lifetime_seconds,
        )
        return TrustedCallerContext(**sdk_context)


def _sdk_sign_context(**values: Any) -> dict[str, Any]:
    """Use the Plugins-owned SDK signer without making it a gateway import dependency."""

    try:
        from cyrene_account_center_contracts import sign_context
    except ImportError as exc:
        raise RuntimeError(
            "the cyrene-account-center-contracts integration dependency is unavailable"
        ) from exc
    context = sign_context(**values)
    return context.as_dict()


def _load_authority_wire() -> tuple[Any, Any]:
    """Load generated Authority messages and stubs only for an integration call."""

    package = "cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2"
    return (
        importlib.import_module(f"{package}.workspace_authority_pb2"),
        importlib.import_module(f"{package}.workspace_authority_pb2_grpc"),
    )


def canonical_json(value: object) -> bytes:
    """Serialize canonical UTF-8 JSON used by the Account Center HMAC contract."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_tls_file(path: Path, *, private: bool) -> bytes:
    """Read a configured managed TLS file and reject loose private-key modes."""

    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("managed TLS reference must name a regular file")
    if private and info.st_mode & 0o077:
        raise ValueError("managed private key file permissions must be owner-only")
    data = path.read_bytes()
    if not data:
        raise ValueError("managed TLS file is empty")
    return data


def _unauthenticated() -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_INTEGRATION_AUTH_REQUIRED",
        title="Verified identity required",
        detail="Authenticate through the configured Platform Authority identity verifier.",
        status=401,
    )


def _identity_permission_denied() -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_INTEGRATION_PERMISSION_DENIED",
        title="Platform denied current identity verification",
        detail="Platform denied this caller or workspace scope.",
        status=403,
    )


def _platform_auth_unavailable() -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_PLATFORM_AUTH_UNAVAILABLE",
        title="Identity verification unavailable",
        detail="Platform could not verify the current identity.",
        status=503,
        retryable=True,
    )


def _identity_rpc_error(error: Any, grpc_module: Any) -> ExchangeProductError:
    """Map authenticated identity/catalog RPC failures without retrying bad credentials."""

    try:
        status_code = error.code()
    except Exception:
        return _platform_auth_unavailable()
    if status_code == grpc_module.StatusCode.UNAUTHENTICATED:
        return _unauthenticated()
    if status_code == grpc_module.StatusCode.PERMISSION_DENIED:
        return _identity_permission_denied()
    return _platform_auth_unavailable()
