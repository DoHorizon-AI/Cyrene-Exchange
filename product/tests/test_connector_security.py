"""Authority grant signature, TTL, and durable one-use verification cases."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2 as authority_wire,
)
from cyrene_exchange_product.integrations.auth import (
    PlatformAuthorityIdentityVerifier,
    VerifiedPlatformIdentity,
)
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorOperationGrantVerifier,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


def _signed_grant(private_key: Ed25519PrivateKey, *, request_id: str) -> bytes:
    """Create one Platform-wire grant with the production canonical signing rules."""

    grant = authority_wire.ConnectorOperationGrantV1(
        schema_version="cyrene.workspace.connector-operation-grant.v1",
        audience="exchange",
        organization_id="org-test",
        workspace_id="workspace-test",
        principal_issuer="https://login.microsoftonline.com/tenant/v2.0",
        principal_subject="11111111-1111-4111-8111-111111111111",
        connection_ref="9dca6ec0-4874-4d09-8e37-c3f4718e619c",
        provider_id="github",
        profile_ref="gh-profile-1",
        operation_id="github.repository.list",
        resource_ref="sha256:" + "1" * 64,
        arguments_digest_sha256=b"\x02" * 32,
        request_id=request_id,
        signing_key_id="test-authority-key",
    )
    grant.issued_at.seconds = 1_000
    grant.expires_at.seconds = 1_015
    digest_source = authority_wire.ConnectorOperationGrantV1.FromString(
        grant.SerializeToString(deterministic=True)
    )
    digest_source.grant_ref = ""
    digest_source.authority_signature = b""
    digest = hashlib.sha256(digest_source.SerializeToString(deterministic=True)).digest()
    grant.grant_ref = "sha256:" + digest.hex()
    key_id = grant.signing_key_id.encode("utf-8")
    signature_input = (
        b"cyrene.workspace.authority.v2/connector-operation-grant\x00"
        + len(key_id).to_bytes(4, "big")
        + key_id
        + digest
    )
    grant.authority_signature = private_key.sign(signature_input)
    return grant.SerializeToString(deterministic=True)


def _expected(request_id: str) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "organization_id": "org-test",
        "workspace_id": "workspace-test",
        "principal_issuer": "https://login.microsoftonline.com/tenant/v2.0",
        "principal_subject": "11111111-1111-4111-8111-111111111111",
        "connection_ref": "9dca6ec0-4874-4d09-8e37-c3f4718e619c",
        "provider_id": "github",
        "profile_ref": "gh-profile-1",
        "operation_id": "github.repository.list",
        "resource_ref": "sha256:" + "1" * 64,
        "arguments_digest_sha256": b"\x02" * 32,
    }


def _verifier(
    keyring_file: Path,
    store: IntegrationStore,
    clock: Any,
) -> ConnectorOperationGrantVerifier:
    return ConnectorOperationGrantVerifier(
        keyring_file=keyring_file,
        expected_audience="exchange",
        grant_registry=store,
        clock=clock,
    )


def test_authority_signature_is_pinned_and_one_use_registry_survives_restart(
    tmp_path: Path,
) -> None:
    """A fresh signed grant survives restart but cannot authorize a second operation."""

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = tmp_path / "authority-keyring.json"
    keyring.write_text(
        json.dumps(
            {"keys": {"test-authority-key": base64.b64encode(public_key).decode("ascii")}},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    keyring.chmod(0o600)
    database = tmp_path / "connector-grant-registry.sqlite3"
    store = IntegrationStore(database)
    grant_bytes = _signed_grant(private_key, request_id="attempt-1")
    verifier = _verifier(keyring, store, clock=lambda: 1_001)

    claims = verifier.validate_authority_response(
        grant_bytes,
        expected=_expected("attempt-1"),
    )
    assert claims.grant_ref.startswith("sha256:")
    assert verifier.inspect(grant_bytes, expected=_expected("attempt-1")) == claims
    assert verifier.consume(grant_bytes, expected=_expected("attempt-1")) == claims
    store.close()

    restarted_store = IntegrationStore(database)
    restarted = _verifier(keyring, restarted_store, clock=lambda: 1_002)
    with pytest.raises(ExchangeProductError):
        restarted.consume(grant_bytes, expected=_expected("attempt-1"))
    with pytest.raises(ExchangeProductError):
        _verifier(keyring, restarted_store, clock=lambda: 1_016).inspect(
            grant_bytes,
            expected=_expected("attempt-1"),
        )
    restarted_store.close()


def test_authority_grant_rejects_untrusted_signing_key(tmp_path: Path) -> None:
    """A valid Authority signature cannot introduce its own verification key."""

    private_key = Ed25519PrivateKey.generate()
    trusted_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    keyring = tmp_path / "authority-keyring.json"
    keyring.write_text(
        json.dumps(
            {"keys": {"trusted-key": base64.b64encode(trusted_key).decode("ascii")}},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    keyring.chmod(0o600)
    store = IntegrationStore(tmp_path / "untrusted-grant.sqlite3")
    verifier = _verifier(keyring, store, clock=lambda: 1_001)
    with pytest.raises(ExchangeProductError):
        verifier.inspect(_signed_grant(private_key, request_id="attempt-untrusted"))
    store.close()


def test_verified_directory_role_allows_only_connector_profile_maintenance() -> None:
    """Only Platform-verified Directory role data can expose connector setup calls."""

    identity = VerifiedPlatformIdentity(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        subject="11111111-1111-4111-8111-111111111111",
        organization_id="org-test",
        workspace_id="workspace-test",
        granted_operation_ids=frozenset({"integrationListConnections"}),
        directory_roles=frozenset({"navigator.connector.operator.v1"}),
    )
    verifier = PlatformAuthorityIdentityVerifier.__new__(PlatformAuthorityIdentityVerifier)
    verifier.verify = lambda **_kwargs: identity  # type: ignore[method-assign]
    principal = verifier.principal_for(
        bearer_token="real-token-value-is-not-stored",
        workspace_id="workspace-test",
    )
    assert principal.allowed_operation_ids == frozenset(
        {"integrationListConnections", "navigator.connector.operator.v1"}
    )

    no_operator = identity.__class__(
        issuer=identity.issuer,
        subject=identity.subject,
        organization_id=identity.organization_id,
        workspace_id=identity.workspace_id,
        granted_operation_ids=identity.granted_operation_ids,
        directory_roles=frozenset(),
    )
    verifier.verify = lambda **_kwargs: no_operator  # type: ignore[method-assign]
    restricted = verifier.principal_for(
        bearer_token="real-token-value-is-not-stored",
        workspace_id="workspace-test",
    )
    assert "navigator.connector.operator.v1" not in restricted.allowed_operation_ids
