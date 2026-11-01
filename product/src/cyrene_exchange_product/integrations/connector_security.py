"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 connector_security.py                                           │
│  Module: cyrene_exchange_product.integrations.connector_security    │
│  Role: Verify Navigator requests and short-lived Authority grants.  │
│                                                                      │
│  模块职责：验证 Navigator 内部签名请求与短时 Platform Connector grant。 │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import stat
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cyrene_exchange_product.errors import ExchangeProductError

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GRANT_DOMAIN = b"cyrene.workspace.authority.v2/connector-operation-grant\x00"
_MAX_GRANT_TTL_SECONDS = 15
_MAX_CONTEXT_SKEW_SECONDS = 30
_MAX_KEYRING_BYTES = 64 * 1024
_MAX_GRANT_BYTES = 64 * 1024
_MAX_NAVIGATOR_BODY_BYTES = 128 * 1024
_MAX_CONNECTOR_GRANT_BODY_BYTES = 1_500_000
_CONNECTOR_OPERATION_GRANTS_PATH = "/internal/v1/connector-operation-grants"


def navigator_hmac_body_limit(method: str, path: str) -> int:
    """Return the fixed raw-body cap for one internal Navigator route."""

    if method.upper() == "POST" and path == _CONNECTOR_OPERATION_GRANTS_PATH:
        return _MAX_CONNECTOR_GRANT_BODY_BYTES
    return _MAX_NAVIGATOR_BODY_BYTES


class ConnectorReplayGuard(Protocol):
    """Persist only short-lived ids to reject a signed internal request replay."""

    def consume_connector_request_id(
        self,
        *,
        key_id: str,
        request_id: str,
        expires_at: int,
        now_epoch: int,
    ) -> bool: ...


class ConnectorGrantRegistry(Protocol):
    """Durable one-use registry for Authority grants minted by this Exchange."""

    def register_connector_grant(
        self,
        *,
        grant_ref: str,
        encoded_sha256: str,
        expires_at: int,
        now_epoch: int,
    ) -> bool: ...

    def consume_connector_grant(
        self,
        *,
        grant_ref: str,
        encoded_sha256: str,
        now_epoch: int,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class NavigatorHmacSettings:
    """One host-owned Navigator service key reference and its public key id."""

    key_id: str
    key_file: Path


@dataclass(frozen=True, slots=True)
class ConnectorGrantClaims:
    """One exact action and verified caller scope carried by an Authority grant."""

    request_id: str
    audience: str
    organization_id: str
    workspace_id: str
    principal_issuer: str
    principal_subject: str
    connection_ref: str
    provider_id: str
    profile_ref: str
    operation_id: str
    resource_ref: str
    arguments_digest_sha256: bytes
    issued_at_epoch: float
    expires_at_epoch: float
    grant_ref: str


class NavigatorHmacAuthenticator:
    """Authenticate only internal Navigator raw-body requests with a mounted key."""

    def __init__(
        self,
        settings: NavigatorHmacSettings | None,
        *,
        replay_guard: ConnectorReplayGuard,
        clock: Any = time.time,
    ) -> None:
        if settings is not None and not _KEY_ID.fullmatch(settings.key_id):
            raise ValueError("Navigator HMAC key id is invalid")
        self._settings = settings
        self._replay_guard = replay_guard
        self._clock = clock

    @property
    def configured(self) -> bool:
        """Report whether the host supplied a key file and key id."""

        return self._settings is not None

    def verify(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        raw_body: bytes,
        request_id: str | None = None,
    ) -> int:
        """Verify method, path, timestamp, body, and one-time request id.

        The signature format is `HMAC-SHA256(key, METHOD + LF + PATH + LF +
        TIMESTAMP + LF + RAW_BODY)`, encoded as lowercase hexadecimal. The key
        file is read for every request so operators can rotate it without a
        key value entering configuration JSON or logs.
        中文：签名覆盖 HTTP 方法、路径、时间戳和原始请求体，并原子消费 requestId。
        """

        settings = self._settings
        if settings is None:
            raise _not_configured("navigator_hmac_not_configured")
        key_id = headers.get("x-cyrene-navigator-key-id", "")
        timestamp_text = headers.get("x-cyrene-navigator-timestamp", "")
        signature_text = headers.get("x-cyrene-navigator-signature", "")
        if key_id != settings.key_id or not _KEY_ID.fullmatch(key_id):
            raise _forbidden("navigator_key_id_invalid")
        if not timestamp_text.isascii() or not timestamp_text.isdecimal():
            raise _forbidden("navigator_timestamp_invalid")
        try:
            timestamp = int(timestamp_text)
        except ValueError:
            raise _forbidden("navigator_timestamp_invalid") from None
        now_epoch = float(self._clock())
        if timestamp > now_epoch + 5 or now_epoch - timestamp > _MAX_CONTEXT_SKEW_SECONDS:
            raise _forbidden("navigator_request_expired")
        if len(raw_body) > navigator_hmac_body_limit(method, path):
            raise ExchangeProductError(
                code="EXCHANGE_CONNECTOR_REQUEST_TOO_LARGE",
                title="Connector request is too large",
                detail="The signed connector request exceeds the configured size limit.",
                status=413,
            )
        if not re.fullmatch(r"[0-9a-f]{64}", signature_text):
            raise _forbidden("navigator_signature_invalid")
        key = _read_private_hmac_key(settings.key_file)
        message = (
            method.upper().encode("ascii")
            + b"\n"
            + path.encode("utf-8")
            + b"\n"
            + timestamp_text.encode("ascii")
            + b"\n"
            + raw_body
        )
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature_text, expected):
            raise _forbidden("navigator_signature_invalid")
        if request_id is not None:
            self.consume_request_id(
                key_id=key_id,
                request_id=request_id,
                timestamp=timestamp,
            )
        return timestamp

    def consume_request_id(self, *, key_id: str, request_id: str, timestamp: int) -> None:
        """Consume the signed request id after the raw body has been authenticated."""

        settings = self._settings
        if settings is None:
            raise _not_configured("navigator_hmac_not_configured")
        if key_id != settings.key_id or not request_id or len(request_id) > 200:
            raise _forbidden("navigator_request_id_invalid")
        now_epoch = int(self._clock())
        if not self._replay_guard.consume_connector_request_id(
            key_id=key_id,
            request_id=request_id,
            expires_at=timestamp + _MAX_CONTEXT_SKEW_SECONDS,
            now_epoch=now_epoch,
        ):
            raise _conflict("navigator_request_replayed")


class ConnectorOperationGrantVerifier:
    """Validate Authority signatures and bind each proof to one request."""

    def __init__(
        self,
        *,
        keyring_file: Path | None,
        expected_audience: str,
        grant_registry: ConnectorGrantRegistry | None = None,
        clock: Any = time.time,
    ) -> None:
        if expected_audience and len(expected_audience) > 300:
            raise ValueError("connector grant audience is invalid")
        self._keyring_file = keyring_file
        self._expected_audience = expected_audience
        self._grant_registry = grant_registry
        self._clock = clock
        self._lock = threading.RLock()
        self._issued: dict[str, tuple[bytes, ConnectorGrantClaims]] = {}
        self._consumed: dict[str, float] = {}

    @property
    def configured(self) -> bool:
        """Report whether both the expected audience and pinned keyring exist."""

        return self._keyring_file is not None and bool(self._expected_audience)

    def validate_authority_response(
        self,
        encoded_grant: bytes,
        *,
        expected: Mapping[str, object],
    ) -> ConnectorGrantClaims:
        """Verify a signed Authority response before it is returned to Navigator."""

        grant, claims = self._parse_and_verify(encoded_grant)
        self._match_expected(claims, expected)
        now_epoch = int(self._clock())
        if claims.expires_at_epoch <= now_epoch:
            raise _forbidden("connector_grant_expired")
        if claims.issued_at_epoch > now_epoch + 5:
            raise _forbidden("connector_grant_issue_time_invalid")
        del grant
        with self._lock:
            self._prune(now_epoch)
            if self._grant_registry is not None:
                registered = self._grant_registry.register_connector_grant(
                    grant_ref=claims.grant_ref,
                    encoded_sha256=hashlib.sha256(encoded_grant).hexdigest(),
                    expires_at=int(claims.expires_at_epoch),
                    now_epoch=now_epoch,
                )
                if not registered:
                    raise _conflict("connector_grant_ref_replayed_or_registry_full")
            else:
                if claims.grant_ref in self._issued or claims.grant_ref in self._consumed:
                    raise _conflict("connector_grant_ref_replayed")
                if len(self._issued) + len(self._consumed) >= 8192:
                    raise _not_configured("connector_grant_registry_full")
                self._issued[claims.grant_ref] = (encoded_grant, claims)
        return claims

    def inspect(
        self,
        encoded_grant: bytes,
        *,
        expected: Mapping[str, object] | None = None,
        allow_expired: bool = False,
    ) -> ConnectorGrantClaims:
        """Verify a grant without consumption, optionally for receipt-only replay.

        Expired proofs are accepted only when the caller separately finds an
        exact durable operation receipt; new provider work must use `consume`.
        """

        _grant, claims = self._parse_and_verify(encoded_grant)
        if not allow_expired and claims.expires_at_epoch <= float(self._clock()):
            raise _forbidden("connector_grant_expired")
        if expected is not None:
            self._match_expected(claims, expected)
        return claims

    def consume(
        self,
        encoded_grant: bytes,
        *,
        expected: Mapping[str, object],
    ) -> ConnectorGrantClaims:
        """Verify and consume one exact grant before a provider side effect."""

        _grant, claims = self._parse_and_verify(encoded_grant)
        self._match_expected(claims, expected)
        now_epoch = float(self._clock())
        if claims.expires_at_epoch <= now_epoch:
            raise _forbidden("connector_grant_expired")
        with self._lock:
            self._prune(now_epoch)
            if self._grant_registry is not None:
                consumed = self._grant_registry.consume_connector_grant(
                    grant_ref=claims.grant_ref,
                    encoded_sha256=hashlib.sha256(encoded_grant).hexdigest(),
                    now_epoch=int(now_epoch),
                )
                if not consumed:
                    raise _conflict("connector_grant_not_minted_here_or_replayed")
                return claims
            issued = self._issued.pop(claims.grant_ref, None)
            if issued is None or not hmac.compare_digest(issued[0], encoded_grant):
                raise _forbidden("connector_grant_not_minted_here")
            if claims.grant_ref in self._consumed:
                raise _conflict("connector_grant_replayed")
            if len(self._issued) + len(self._consumed) >= 8192:
                raise _not_configured("connector_grant_registry_full")
            self._consumed[claims.grant_ref] = claims.expires_at_epoch
        return claims

    def _parse_and_verify(self, encoded_grant: bytes) -> tuple[Any, ConnectorGrantClaims]:
        if self._keyring_file is None or not self._expected_audience:
            raise _not_configured("connector_authority_verifier_not_configured")
        if not encoded_grant or len(encoded_grant) > _MAX_GRANT_BYTES:
            raise _forbidden("connector_grant_invalid")
        authority_wire, _authority_grpc = _load_authority_wire()
        grant = authority_wire.ConnectorOperationGrantV1()
        try:
            grant.ParseFromString(encoded_grant)
        except Exception as exc:
            raise _forbidden("connector_grant_invalid") from exc
        if (
            not grant.grant_ref
            or not grant.signing_key_id
            or len(grant.authority_signature) != 64
            or len(grant.arguments_digest_sha256) != 32
            or not grant.HasField("issued_at")
            or not grant.HasField("expires_at")
        ):
            raise _forbidden("connector_grant_invalid")
        public_key = _load_authority_verification_key(self._keyring_file, grant.signing_key_id)
        signature = bytes(grant.authority_signature)
        original = bytes(encoded_grant)
        digest_source = authority_wire.ConnectorOperationGrantV1.FromString(original)
        digest_source.grant_ref = ""
        digest_source.authority_signature = b""
        digest = hashlib.sha256(digest_source.SerializeToString(deterministic=True)).digest()
        expected_ref = "sha256:" + digest.hex()
        if grant.grant_ref != expected_ref:
            raise _forbidden("connector_grant_digest_invalid")
        key_id = grant.signing_key_id.encode("utf-8")
        signature_message = _GRANT_DOMAIN + len(key_id).to_bytes(4, "big") + key_id + digest
        try:
            public_key.verify(signature, signature_message)
        except InvalidSignature as exc:
            raise _forbidden("connector_grant_signature_invalid") from exc
        if grant.audience != self._expected_audience:
            raise _forbidden("connector_grant_audience_invalid")
        issued = grant.issued_at.ToDatetime(tzinfo=__import__("datetime").UTC)
        expires = grant.expires_at.ToDatetime(tzinfo=__import__("datetime").UTC)
        ttl_seconds = (expires - issued).total_seconds()
        if not 0 < ttl_seconds <= _MAX_GRANT_TTL_SECONDS:
            raise _forbidden("connector_grant_ttl_invalid")
        claims = ConnectorGrantClaims(
            request_id=grant.request_id,
            audience=grant.audience,
            organization_id=grant.organization_id,
            workspace_id=grant.workspace_id,
            principal_issuer=grant.principal_issuer,
            principal_subject=grant.principal_subject,
            connection_ref=grant.connection_ref,
            provider_id=grant.provider_id,
            profile_ref=grant.profile_ref,
            operation_id=grant.operation_id,
            resource_ref=grant.resource_ref,
            arguments_digest_sha256=bytes(grant.arguments_digest_sha256),
            issued_at_epoch=issued.timestamp(),
            expires_at_epoch=expires.timestamp(),
            grant_ref=grant.grant_ref,
        )
        return grant, claims

    @staticmethod
    def _match_expected(
        claims: ConnectorGrantClaims,
        expected: Mapping[str, object],
    ) -> None:
        for key in (
            "request_id",
            "organization_id",
            "workspace_id",
            "principal_issuer",
            "principal_subject",
            "connection_ref",
            "provider_id",
            "profile_ref",
            "operation_id",
            "resource_ref",
        ):
            if key in expected and getattr(claims, key) != expected[key]:
                raise _forbidden("connector_grant_scope_mismatch")
        digest = expected.get("arguments_digest_sha256")
        if digest is not None:
            if not isinstance(digest, bytes):
                raise _forbidden("connector_grant_arguments_mismatch")
            if not hmac.compare_digest(claims.arguments_digest_sha256, digest):
                raise _forbidden("connector_grant_arguments_mismatch")

    def _prune(self, now_epoch: float) -> None:
        stale = [
            grant_ref
            for grant_ref, (_encoded, claims) in self._issued.items()
            if claims.expires_at_epoch <= now_epoch
        ]
        for grant_ref in stale:
            self._issued.pop(grant_ref, None)
        stale_consumed = [
            grant_ref for grant_ref, expires_at in self._consumed.items() if expires_at <= now_epoch
        ]
        for grant_ref in stale_consumed:
            self._consumed.pop(grant_ref, None)


def decode_authority_keyring(path: Path) -> dict[str, Ed25519PublicKey]:
    """Load an externally provisioned key-id-to-raw-public-key JSON file."""

    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("Authority signing keyring must be a protected regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > _MAX_KEYRING_BYTES:
        raise ValueError("Authority signing keyring has an invalid size")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Authority signing keyring is invalid JSON") from exc
    if not isinstance(value, Mapping) or set(value) != {"keys"}:
        raise ValueError("Authority signing keyring has an invalid shape")
    keys = value["keys"]
    if not isinstance(keys, Mapping) or not keys:
        raise ValueError("Authority signing keyring must contain at least one key")
    result: dict[str, Ed25519PublicKey] = {}
    for key_id, encoded in keys.items():
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("Authority signing keyring contains an invalid key id")
        if not isinstance(encoded, str):
            raise ValueError("Authority signing keyring contains a malformed public key")
        try:
            key_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise ValueError("Authority signing keyring contains a malformed public key") from None
        if len(key_bytes) != 32:
            raise ValueError("Authority verification keys must be 32 raw bytes")
        result[key_id] = Ed25519PublicKey.from_public_bytes(key_bytes)
    return result


def _load_authority_verification_key(path: Path, key_id: str) -> Ed25519PublicKey:
    try:
        key = decode_authority_keyring(path).get(key_id)
    except FileNotFoundError as exc:
        raise _not_configured("connector_authority_keyring_missing") from exc
    except OSError as exc:
        raise _not_configured("connector_authority_keyring_unavailable") from exc
    except ValueError as exc:
        raise _not_configured("connector_authority_keyring_invalid") from exc
    if key is None:
        raise _forbidden("connector_grant_signing_key_untrusted")
    return key


def digest_arguments(value: Mapping[str, object]) -> str:
    """Return the lowercase SHA-256 digest of RFC 8785 JCS arguments."""

    return hashlib.sha256(connector_canonical_json(dict(value))).hexdigest()


def connector_canonical_json(value: object) -> bytes:
    """Serialize finite JSON values as RFC 8785 for cross-language connector hashes."""

    try:
        return rfc8785.dumps(cast(Any, value))
    except (TypeError, ValueError) as exc:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_CANONICALIZATION_INVALID",
            title="Connector JSON value is invalid",
            detail="The connector JSON value is outside the RFC 8785 canonicalization domain.",
            status=422,
        ) from exc


def parse_signed_json_object(raw_body: bytes) -> dict[str, Any]:
    """Decode a duplicate-free JSON object used in a signed internal request."""

    try:
        value = json.loads(raw_body, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
            title="Connector request is invalid",
            detail="The signed internal request must be a duplicate-free JSON object.",
            status=400,
        ) from exc
    if not isinstance(value, dict):
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_REQUEST_INVALID",
            title="Connector request is invalid",
            detail="The signed internal request must be a JSON object.",
            status=400,
        )
    return value


def _read_private_hmac_key(path: Path) -> bytes:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise _not_configured("navigator_hmac_key_file_permissions_invalid")
        key = path.read_bytes()
    except FileNotFoundError as exc:
        raise _not_configured("navigator_hmac_key_file_missing") from exc
    except OSError as exc:
        raise _not_configured("navigator_hmac_key_file_unavailable") from exc
    if len(key) != 32:
        raise _not_configured("navigator_hmac_key_invalid")
    return key


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _forbidden(reason_code: str) -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_AUTHORIZATION_DENIED",
        title="Connector authorization denied",
        detail="The connector authorization proof is invalid or out of scope.",
        status=403,
        context={"reasonCode": reason_code},
    )


def _conflict(reason_code: str) -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_REQUEST_REPLAYED",
        title="Connector request was already used",
        detail="The connector request id or one-use grant has already been consumed.",
        status=409,
        context={"reasonCode": reason_code},
    )


def _not_configured(reason_code: str) -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_NOT_CONFIGURED",
        title="Connector authorization is not configured",
        detail="Exchange cannot validate or dispatch this connector operation.",
        status=503,
        retryable=True,
        context={"reasonCode": reason_code},
    )


def _load_authority_wire() -> tuple[Any, Any]:
    """Load exact generated Authority messages and RPC stubs on demand."""

    from cyrene_exchange_product.integrations.auth import _load_authority_wire as load_wire

    return load_wire()
