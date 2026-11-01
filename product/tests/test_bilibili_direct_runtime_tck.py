"""Cross-repository SIMULATED Bilibili DirectPlugin and receipt-ledger TCK."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    AuthorizationCloudProfileRegistry,
    parse_authorization_cloud_settings,
)
from cyrene_exchange_product.integrations.authorization_cloud_provider import (
    AuthorizationCloudDirectProvider,
)
from cyrene_exchange_product.integrations.clients import (
    DirectPluginHealthClient,
    direct_plugin_client_from_connection,
)
from cyrene_exchange_product.integrations.connector_operations import (
    ConnectorOperationDispatcher,
    _resource_projection,
    _resource_ref,
    digest_arguments,
)
from cyrene_exchange_product.integrations.connector_security import (
    ConnectorGrantClaims,
    NavigatorHmacAuthenticator,
    NavigatorHmacSettings,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationPrincipal,
)
from cyrene_exchange_product.integrations.ports import ProviderCredentialLeaseEvidence
from cyrene_exchange_product.integrations.store import IntegrationStore

_ISSUER = "https://id.example.test"
_SUBJECT = "actor-123"
_ORGANIZATION = "org-one"
_WORKSPACE = "workspace-one"
_PROFILE_REF = "00000000-0000-4000-8000-000000000010"
_BINDING_ALIAS = "bilibili-host"
_PLUGIN_BINDING_ID = "bilibili-binding"
_CALLER_KEY = b"c" * 32
_ACCOUNT_CENTER_KEY = b"a" * 32
_COOKIE_JAR = json.dumps(
    {
        "schemaVersion": 1,
        "cookies": [
            {
                "name": "SESSDATA",
                "value": "simulated-cookie",
                "domain": ".bilibili.com",
                "path": "/",
            },
            {
                "name": "bili_jct",
                "value": "simulated-csrf",
                "domain": ".bilibili.com",
                "path": "/",
            },
            {
                "name": "DedeUserID",
                "value": "12345",
                "domain": ".bilibili.com",
                "path": "/",
            },
        ],
    },
    separators=(",", ":"),
)


class _FakeDirectoryAuthority:
    """Return distinct synthetic grants while preserving the exact requested scope."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def authorize_connector_operation(self, **kwargs: Any) -> bytes:
        self.calls.append(kwargs)
        return f"directory-grant-{len(self.calls)}".encode("ascii")


class _FakeGrantVerifier:
    """Verify exact fixture claims and allow each synthetic grant once."""

    configured = True

    def __init__(self) -> None:
        self.claims: dict[bytes, ConnectorGrantClaims] = {}
        self.consumed: set[bytes] = set()

    @staticmethod
    def _make_claims(expected: dict[str, Any], index: int) -> ConnectorGrantClaims:
        now = time.time()
        return ConnectorGrantClaims(
            request_id=str(expected["request_id"]),
            audience="exchange",
            organization_id=str(expected["organization_id"]),
            workspace_id=str(expected["workspace_id"]),
            principal_issuer=str(expected["principal_issuer"]),
            principal_subject=str(expected["principal_subject"]),
            connection_ref=str(expected["connection_ref"]),
            provider_id=str(expected["provider_id"]),
            profile_ref=str(expected["profile_ref"]),
            operation_id=str(expected["operation_id"]),
            resource_ref=str(expected["resource_ref"]),
            arguments_digest_sha256=expected["arguments_digest_sha256"],
            issued_at_epoch=now,
            expires_at_epoch=now + 15,
            grant_ref=f"sha256:{index:064x}",
        )

    def validate_authority_response(
        self,
        grant: bytes,
        *,
        expected: dict[str, Any],
    ) -> ConnectorGrantClaims:
        claims = self._make_claims(expected, len(self.claims) + 1)
        self.claims[grant] = claims
        return claims

    def inspect(
        self,
        grant: bytes,
        *,
        expected: dict[str, Any] | None = None,
    ) -> ConnectorGrantClaims:
        claims = self.claims[grant]
        if expected is not None:
            observed = {
                "request_id": claims.request_id,
                "organization_id": claims.organization_id,
                "workspace_id": claims.workspace_id,
                "principal_issuer": claims.principal_issuer,
                "principal_subject": claims.principal_subject,
                "connection_ref": claims.connection_ref,
                "provider_id": claims.provider_id,
                "profile_ref": claims.profile_ref,
                "operation_id": claims.operation_id,
                "resource_ref": claims.resource_ref,
                "arguments_digest_sha256": claims.arguments_digest_sha256,
            }
            assert all(observed[key] == value for key, value in expected.items())
        return claims

    def consume(
        self,
        grant: bytes,
        *,
        expected: dict[str, Any],
    ) -> ConnectorGrantClaims:
        assert grant not in self.consumed
        self.consumed.add(grant)
        return self.inspect(grant, expected=expected)


class _FakeLeaseAccountCenter:
    """Return only opaque one-use lease metadata to Exchange."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create_provider_credential_lease(
        self,
        _principal: IntegrationPrincipal,
        *,
        profile_ref: str,
        operation_id: str,
        target: dict[str, object],
        arguments_sha256: str,
        connector_grant: dict[str, object] | None = None,
    ) -> ProviderCredentialLeaseEvidence:
        self.calls.append(
            {
                "profile_ref": profile_ref,
                "operation_id": operation_id,
                "target": dict(target),
                "arguments_sha256": arguments_sha256,
                "connector_grant": connector_grant,
            }
        )
        return ProviderCredentialLeaseEvidence(
            lease_ref=str(uuid4()),
            profile_ref=profile_ref,
            provider="bilibili",
            operation_id=operation_id,
            target=dict(target),
            arguments_sha256=arguments_sha256,
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )


class _FakeProviderAccountCenter:
    """Redeem leases inside the plugin process without returning credentials to Exchange."""

    def __init__(self) -> None:
        self.redemptions: list[tuple[dict[str, Any], dict[str, str | None]]] = []

    def redeem_provider_credential_lease(
        self,
        payload: dict[str, Any],
        actor: dict[str, str | None],
    ) -> Any:
        from cyrene_account_center_contracts import AuthMaterial

        self.redemptions.append((dict(payload), dict(actor)))
        return AuthMaterial(
            access_token=_COOKIE_JAR,
            token_type="BilibiliCookieJar",
            external_subject="12345",
            expires_at=int(time.time()) + 3600,
        )


class _ReadbackApi:
    """Block the first mutation so a cross-request receipt replay overlaps it."""

    def __init__(self) -> None:
        self.send_count = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def send_dm(
        self,
        _peer_user_id: str,
        _content: str,
        cookies_json: str,
        subject: str,
    ) -> dict[str, Any]:
        self.send_count += 1
        assert cookies_json == _COOKIE_JAR
        assert subject == "12345"
        self.started.set()
        if not self.release.wait(timeout=10):
            raise TimeoutError("fixture did not release the provider mutation")
        return {
            "external_id": "887766",
            "readback_verified": True,
            "readback_sha256": "d" * 64,
        }

    def close(self) -> None:
        pass


def _navigator_headers(path: str, body: bytes, key: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    message = b"POST\n" + path.encode("ascii") + b"\n" + timestamp.encode("ascii") + b"\n" + body
    return {
        "content-type": "application/json",
        "x-cyrene-navigator-key-id": "navigator-bilibili-tck-v1",
        "x-cyrene-navigator-timestamp": timestamp,
        "x-cyrene-navigator-signature": hmac.new(key, message, hashlib.sha256).hexdigest(),
    }


def test_bilibili_exchange_to_direct_runtime_reconciles_same_work_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run real Exchange and provider code over DirectPluginRuntime with fixture wire HTTP."""

    source_value = os.environ.get("CYRENE_BILIBILI_PLUGIN_SOURCE")
    if not source_value:
        pytest.skip(
            "set CYRENE_BILIBILI_PLUGIN_SOURCE to run the cross-repository DirectPlugin TCK"
        )
    plugin_source = Path(source_value).resolve()
    if not plugin_source.is_dir():
        pytest.fail("CYRENE_BILIBILI_PLUGIN_SOURCE must name the Bilibili plugin repository")
    import_roots = [plugin_source / "src"]
    contracts_source_value = os.environ.get("CYRENE_BILIBILI_CONTRACTS_SOURCE")
    if contracts_source_value:
        contracts_source = Path(contracts_source_value).resolve()
        import_roots.extend(
            [
                contracts_source / "sdk/python/cyrene_integration_contracts/src",
                contracts_source / "sdk/python/cyrene_tool_provider_contracts/src",
            ]
        )
    for import_root in import_roots:
        if import_root.is_dir():
            monkeypatch.syspath_prepend(str(import_root))
    integration_contracts = import_module("cyrene_integration_contracts")
    expected_bilibili_operations = {
        "bilibili.auth.qr.begin",
        "bilibili.auth.qr.status",
        "bilibili.search",
        "bilibili.user.find",
        "bilibili.video.read",
        "bilibili.comments.list",
        "bilibili.dynamics.list",
        "bilibili.dynamic.read",
        "bilibili.dm.list",
        "bilibili.dm.read",
        "bilibili.comment.create",
        "bilibili.dynamic.publish",
        "bilibili.dm.send",
    }
    tool_operations = integration_contracts.TOOL_OPERATIONS
    if not expected_bilibili_operations <= set(tool_operations.values()):
        pytest.fail(
            "install/import the merged cyrene-integration-contracts source containing Bilibili ops"
        )
    provider_module = import_module("cyrene_bilibili.plugin")
    settings_module = import_module("cyrene_bilibili.settings")

    from cyrene_plugin_runtime.server import DirectPluginService

    actor = IntegrationPrincipal(
        issuer=_ISSUER,
        subject=_SUBJECT,
        organization_id=_ORGANIZATION,
        workspace_id=_WORKSPACE,
        allowed_operation_ids=frozenset(
            {"integrationCreateConnection", "navigator.connector.operator.v1", "bilibili.dm.send"}
        ),
    )
    trusted_caller = settings_module.TrustedCaller(
        caller_workload="cyrene.exchange.integrations",
        audience="cyrene.connectors.bilibili",
        organization_id=_ORGANIZATION,
        workspace_id=_WORKSPACE,
        issuer=_ISSUER,
        verification_key=_CALLER_KEY,
    )
    plugin_state_dir = tmp_path / "plugin-state"
    plugin_state_dir.mkdir(mode=0o700)
    provider_settings = settings_module.ProviderSettings(
        binding_id=_PLUGIN_BINDING_ID,
        trusted_callers=(trusted_caller,),
        account_center_binding_id="account-center-binding",
        account_center_connection_ref="grpc://127.0.0.1:50051",
        account_center_transport="local",
        provider_caller_id="cyrene.connectors.bilibili",
        provider_signing_key=_ACCOUNT_CENTER_KEY,
        account_center_root_cert_ref=None,
        account_center_client_cert_ref=None,
        account_center_client_key_ref=None,
        state_dir=plugin_state_dir,
        host_secret_names={},
    )
    plugin_account_center = _FakeProviderAccountCenter()
    provider_api = _ReadbackApi()
    provider = provider_module.BilibiliProvider(
        settings=provider_settings,
        account_center=plugin_account_center,
        api=provider_api,
    )

    from concurrent.futures import ThreadPoolExecutor as _RuntimeWorkers

    import grpc
    from cyrene_plugin_runtime._generated import direct_plugin_runtime_pb2_grpc as runtime_wire

    runtime_server = grpc.server(_RuntimeWorkers(max_workers=4))
    runtime_wire.add_DirectPluginRuntimeServicer_to_server(
        DirectPluginService(provider, provider.capabilities, "1"),
        runtime_server,
    )
    bound_port = runtime_server.add_insecure_port("127.0.0.1:0")
    assert bound_port > 0
    runtime_server.start()
    direct_client = direct_plugin_client_from_connection(f"grpc://127.0.0.1:{bound_port}")
    health_client = DirectPluginHealthClient(f"grpc://127.0.0.1:{bound_port}")
    health = health_client.observe()
    assert health.status == "SERVING"
    assert health.plugin_id == "cyrene.connectors.bilibili"

    settings = parse_authorization_cloud_settings(
        {
            "currentAuthority": {"contexts": []},
            "profiles": {
                _BINDING_ALIAS: {
                    "provider": "bilibili",
                    "directPlugin": {
                        "bindingId": _PLUGIN_BINDING_ID,
                        "connectionRef": f"grpc://127.0.0.1:{bound_port}",
                        "transport": "local",
                    },
                    "callerWorkload": "cyrene.exchange.integrations",
                    "audience": "cyrene.connectors.bilibili",
                    "expectedIssuer": _ISSUER,
                    "contextKeyRef": "keys/bilibili",
                    "organizationId": _ORGANIZATION,
                    "workspaceId": _WORKSPACE,
                    "allowedActors": [{"issuer": _ISSUER, "subject": _SUBJECT}],
                    "accessMode": "actor_owned",
                }
            },
        },
        email_value={"enabled": False},
    )
    registry = AuthorizationCloudProfileRegistry(settings)
    integration_store = IntegrationStore(tmp_path / "exchange-integrations.sqlite3")
    connection = integration_store.create_connection(
        actor,
        CreateIntegrationConnection(
            provider="bilibili",
            binding_ref=_BINDING_ALIAS,
            account_link_ref=_PROFILE_REF,
        ),
        idempotency_key="bilibili-direct-runtime-connection",
    )
    provider_caller = AuthorizationCloudDirectProvider(
        store=integration_store,
        registry=registry,
        provider_clients={_BINDING_ALIAS: direct_client},
        provider_health_clients={_BINDING_ALIAS: health_client},
        email_client=None,
        account_center=None,
        current_context_resolver=SimpleNamespace(),
        context_key=lambda _reference: _CALLER_KEY,
    )
    lease_account_center = _FakeLeaseAccountCenter()
    dispatcher = ConnectorOperationDispatcher(
        store=integration_store,
        accounts=lease_account_center,
        github=SimpleNamespace(),
        authorization_cloud=provider_caller,
        registry=registry,
    )
    key = b"n" * 32
    key_file = tmp_path / "navigator-hmac.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    authority = _FakeDirectoryAuthority()
    verifier = _FakeGrantVerifier()
    services = IntegrationServices(
        store=integration_store,
        authorizer=None,
        accounts=SimpleNamespace(),  # type: ignore[arg-type]
        github=SimpleNamespace(),  # type: ignore[arg-type]
        webhook_verifier=SimpleNamespace(),  # type: ignore[arg-type]
        delegation_authorizer=None,
        callback_principal=actor,
        navigator_hmac_authenticator=NavigatorHmacAuthenticator(
            NavigatorHmacSettings("navigator-bilibili-tck-v1", key_file),
            replay_guard=integration_store,
        ),
        connector_grant_authority=authority,
        connector_grant_verifier=verifier,
        connector_operation_dispatcher=dispatcher,
    )
    app = create_app(database_path=tmp_path / "exchange-tck.sqlite3", integrations=services)
    arguments = {"peer_user_id": "9988", "content": "simulated duplicate-safe DM"}
    target = _resource_projection(
        provider_id="bilibili",
        profile_ref=_PROFILE_REF,
        operation_id="bilibili.dm.send",
        arguments=arguments,
    )
    resource_ref = _resource_ref(
        provider_id="bilibili",
        profile_ref=_PROFILE_REF,
        operation_id="bilibili.dm.send",
        target=target,
    )
    work_operation_ref = "work-operation:00000000-0000-4000-8000-000000000222"
    mint_path = "/internal/v1/connector-operation-grants"
    connection_ref = str(connection.id)
    invoke_path = f"/internal/v1/connector-operations/{connection_ref}"

    def invoke_request(client: TestClient, request_id: str) -> dict[str, Any]:
        grant_payload = {
            "request_id": request_id,
            "organization_id": _ORGANIZATION,
            "workspace_id": _WORKSPACE,
            "principal_issuer": _ISSUER,
            "principal_subject": _SUBJECT,
            "connection_ref": connection_ref,
            "provider_id": "bilibili",
            "profile_ref": _PROFILE_REF,
            "operation_id": "bilibili.dm.send",
            "resource_ref": resource_ref,
            "arguments": arguments,
            "arguments_digest_sha256": digest_arguments(arguments),
            "idempotency_key": work_operation_ref,
        }
        raw_grant_request = json.dumps(grant_payload, separators=(",", ":")).encode("utf-8")
        invoke_payload = {
            "request_id": request_id,
            "provider_id": "bilibili",
            "profile_ref": _PROFILE_REF,
            "operation_id": "bilibili.dm.send",
            "resource_ref": resource_ref,
            "arguments": arguments,
            "idempotency_key": work_operation_ref,
        }
        minted = client.post(
            mint_path,
            content=raw_grant_request,
            headers=_navigator_headers(mint_path, raw_grant_request, key),
        )
        assert minted.status_code == 200, minted.text
        invoked = client.post(
            invoke_path,
            json=invoke_payload,
            headers={
                "x-cyrene-connector-grant-bin": minted.json()["connectorGrantBin"],
            },
        )
        assert invoked.status_code == 200, invoked.text
        return invoked.json()

    try:
        with TestClient(app) as client:
            with ThreadPoolExecutor(max_workers=2) as executor:
                first_future = executor.submit(invoke_request, client, "bilibili-work-call-1")
                if not provider_api.started.wait(timeout=5):
                    first_future.result(timeout=1)
                    pytest.fail("the first Exchange operation did not reach Bilibili send_dm")
                overlapping = invoke_request(client, "bilibili-work-call-2")
                provider_api.release.set()
                first = first_future.result(timeout=10)
            replay = invoke_request(client, "bilibili-work-call-3")
            rows = integration_store._connection.execute(
                "SELECT request_id,state,operation_ref,response_json FROM connector_invocations "
                "WHERE operation_id='bilibili.dm.send' ORDER BY request_id"
            ).fetchall()

        assert first["outcome"] == "verified"
        assert first["operationRef"] == work_operation_ref
        assert overlapping["outcome"] == "uncertain"
        assert replay["outcome"] == "verified"
        assert replay["operationRef"] == work_operation_ref
        assert provider_api.send_count == 1
        assert len(lease_account_center.calls) == 3
        assert len(plugin_account_center.redemptions) == 1
        assert "simulated DM" not in json.dumps(first)
        assert "simulated-cookie" not in json.dumps(first)
        ledger = {str(row["request_id"]): row for row in rows}
        assert set(ledger) == {
            "bilibili-work-call-1",
            "bilibili-work-call-2",
            "bilibili-work-call-3",
        }
        assert ledger["bilibili-work-call-1"]["state"] == "SUCCEEDED"
        assert ledger["bilibili-work-call-2"]["state"] == "UNKNOWN_RESULT"
        assert ledger["bilibili-work-call-3"]["state"] == "SUCCEEDED"
        assert ledger["bilibili-work-call-1"]["operation_ref"] == work_operation_ref
        assert ledger["bilibili-work-call-3"]["operation_ref"] == work_operation_ref
        assert json.loads(ledger["bilibili-work-call-1"]["response_json"])["outcome"] == "verified"
        assert json.loads(ledger["bilibili-work-call-2"]["response_json"])["outcome"] == "uncertain"
        assert json.loads(ledger["bilibili-work-call-3"]["response_json"])["outcome"] == "verified"
    finally:
        provider_api.release.set()
        health_client.close()
        direct_client.close()
        runtime_server.stop(grace=0).wait(timeout=5)
        provider.close()
        integration_store.close()
