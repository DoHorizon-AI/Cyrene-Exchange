"""Workspace-local integration proof across Exchange, Plugins, and Authority.

This acceptance test starts the real Plugins DirectPluginRuntime SDK and real
Account Center, GitHub Issues, and WeCom connector entrypoints. Vendor HTTP
surfaces and the Platform Authority boundary use synthetic local responders.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from concurrent import futures
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import grpc
import httpx
import pytest
from fastapi.testclient import TestClient
from google.protobuf.timestamp_pb2 import Timestamp

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2 as authority_wire,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2_grpc as authority_grpc,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.product.v2 import (
    product_api_pb2 as product_wire,
)
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.auth import (
    AccountCenterRequestSigner,
    PlatformAuthorityIdentityVerifier,
    PlatformExecutionAuthorizationVerifier,
    canonical_json,
)
from cyrene_exchange_product.integrations.clients import (
    AccountCenterClient,
    GitHubIssuesClient,
    GitHubWebhookClient,
    IntegrationAccountCenterPort,
    IntegrationGitHubPort,
    PlatformAuthorityDelegationClient,
    WeComMessageClient,
)
from cyrene_exchange_product.integrations.dispatcher import (
    DispatcherRunner,
    IntegrationDispatcher,
)
from cyrene_exchange_product.integrations.models import (
    IntegrationPrincipal as Principal,
)
from cyrene_exchange_product.integrations.models import (
    JobState,
)
from cyrene_exchange_product.integrations.store import IntegrationStore

_USER_A = "first-party-user-a"
_USER_B = "first-party-user-b"
_USER_OTHER_ORG = "first-party-other-org"
_ISSUER = "https://identity.example.test"
_WORKSPACE = "workspace-e2e"
_ORG = "org-e2e"
_AC_BINDING = "account-center-e2e"
_GH_BINDING = "github-provider-e2e"
_WECOM_BINDING = "wecom-binding-e2e"
_REPOSITORY_ID = "4242"
_REPOSITORY = "cyrene/e2e"
_WEBHOOK_SECRET = b"synthetic-github-webhook-secret"
_WECOM_SOURCE_KEY = b"synthetic-wecom-source-hmac-key-32-bytes"
_WECOM_GROUP = "group-e2e"
_AC_KEYS = {
    "exchange-e2e": b"e" * 32,
    "callback-e2e": b"c" * 32,
    "github-e2e": b"g" * 32,
    "wecom-source-e2e": b"w" * 32,
}
_EXECUTION_KEY = b"synthetic-authority-signing-key"


def _plugins_root() -> Path | None:
    configured = os.environ.get("CYRENE_PLUGINS_WORKTREE")
    if configured:
        root = Path(configured)
        if (root / "sdk/python/cyrene_plugin_runtime").exists():
            return root
        if os.environ.get("CYRENE_REQUIRE_PLUGINS_WORKTREE") == "1":
            pytest.fail("required pinned Cyrene-Plugins-Official checkout is unavailable")
        return None
    candidate = Path(__file__).resolve().parents[3] / "plugins"
    if (candidate / "sdk/python/cyrene_plugin_runtime").exists():
        return candidate
    if os.environ.get("CYRENE_REQUIRE_PLUGINS_WORKTREE") == "1":
        pytest.fail("required pinned Cyrene-Plugins-Official checkout is unavailable")
    return None


def _load_plugins(root: Path) -> None:
    """Load sibling Plugin source and its isolated test dependencies."""

    for relative in (
        "plugins/accounts/account-center/.venv/lib/python3.*/site-packages",
        "plugins/connectors/wecom/.venv/lib/python3.*/site-packages",
    ):
        sys.path.extend(str(path) for path in root.glob(relative))
    for relative in (
        "sdk/python/cyrene_account_center_contracts/src",
        "plugins/accounts/account-center/src",
        "plugins/providers/github-issues/src",
        "plugins/connectors/wecom/src",
    ):
        path = str(root / relative)
        if path not in sys.path:
            sys.path.insert(0, path)


class _HttpReply:
    """Small urllib-compatible response for the OAuth HTTP fixture."""

    status = 200

    def __init__(self, value: Mapping[str, Any]) -> None:
        self._value = json.dumps(value, separators=(",", ":")).encode()

    def __enter__(self) -> _HttpReply:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._value


class _GitHubOAuthHttp:
    """Mock only the official OAuth token and identity HTTP endpoints."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, Mapping[str, str]]] = []
        self.forms: list[Mapping[str, list[str]]] = []

    def open(self, request: Any, timeout: float) -> _HttpReply:
        del timeout
        self.requests.append((request.method, request.full_url, dict(request.header_items())))
        if request.full_url == "https://github.com/login/oauth/access_token":
            form = parse_qs(request.data.decode())
            self.forms.append(form)
            code = form.get("code", [""])[0]
            return _HttpReply(
                {
                    "access_token": f"synthetic-{code}-token",
                    "refresh_token": f"synthetic-{code}-refresh",
                    "expires_in": 3600,
                    "refresh_token_expires_in": 7200,
                    "token_type": "bearer",
                }
            )
        if request.full_url == "https://api.github.com/user":
            token = request.get_header("Authorization")
            subject = 102 if token == "Bearer synthetic-member-code-token" else 101
            return _HttpReply({"id": subject, "login": f"user-{subject}"})
        raise AssertionError(f"unexpected OAuth HTTP target: {request.full_url}")


class _GitHubHttp:
    """HTTP response fixture with user-token ACL and explicit write readback."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, bytes | None]] = []
        self.tokens: list[str] = []
        self.issue_state = "open"
        self.comments: list[str] = []

    def __call__(
        self,
        method: str,
        host: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
    ) -> Any:
        from github_issues_provider.github_api import HttpResponse

        token = headers.get("Authorization", "")
        self.calls.append((method, host, path, body))
        self.tokens.append(token)
        if host != "api.github.com":
            raise AssertionError("GitHub provider changed its fixed host")
        # The issue ACL is owned by the linked member account. The creator token
        # cannot create this comment, so a missing actor binding fails here.
        if token != "Bearer synthetic-member-code-token":
            return HttpResponse(403, {}, b'{"message":"resource not accessible"}')
        if path == "/repos/cyrene/e2e":
            payload = {"id": 4242, "full_name": _REPOSITORY}
            return HttpResponse(200, {}, json.dumps(payload).encode())
        if path == "/repos/cyrene/e2e/issues/12/comments" and method == "POST":
            comment = json.loads(body or b"{}")
            self.comments.append(str(comment.get("body", "")))
            return HttpResponse(
                201,
                {},
                json.dumps(
                    {"id": 9001, "body": comment.get("body", ""), "issue_url": "safe"}
                ).encode(),
            )
        if path == "/repos/cyrene/e2e/issues/12" and method == "PATCH":
            self.issue_state = str(json.loads(body or b"{}").get("state", "open"))
            return HttpResponse(200, {}, self._issue().encode())
        if path == "/repos/cyrene/e2e/issues/12" and method == "GET":
            return HttpResponse(200, {}, self._issue().encode())
        raise AssertionError(f"unexpected GitHub request: {method} {path}")

    def _issue(self) -> str:
        return json.dumps(
            {
                "id": 1200,
                "number": 12,
                "title": "Synthetic integration issue",
                "body": "",
                "state": self.issue_state,
                "repository": {"id": 4242, "full_name": _REPOSITORY},
            }
        )


class _LocalExchangeHttpTransport:
    """Route the actual Plugin forwarder into the local FastAPI test app."""

    def __init__(self) -> None:
        self.client: TestClient | None = None
        self.paths: list[str] = []
        self.errors: list[str] = []

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes]:
        if self.client is None:
            raise RuntimeError("local Exchange HTTP client is not attached")
        path = urlsplit(url).path
        self.paths.append(path)
        try:
            response = self.client.post(
                path,
                content=body,
                headers=dict(headers),
                timeout=timeout,
            )
        except Exception as exc:
            self.errors.append(repr(exc))
            raise
        return response.status_code, response.content


class _PluginEventSink:
    """Accept the local Plugin event stream while the source forwarder runs."""

    def emit(self, *_: Any, **__: Any) -> bool:
        return True


class _WeComFakeWebSocket:
    """Drive the real WeCom bot protocol with deterministic acknowledgement."""

    def __init__(self, *, acknowledge: bool) -> None:
        from wecom_connector import ScriptedWsTransport

        self.transport = ScriptedWsTransport()
        self.acknowledge = acknowledge
        self.commands: list[dict[str, Any]] = []
        self.transport.send_hook = self._on_send

    def _on_send(self, message: dict[str, Any]) -> None:
        self.commands.append(message)
        if message.get("cmd") == "aibot_subscribe" or (
            self.acknowledge and message.get("cmd") in {"aibot_send_msg", "aibot_respond_msg"}
        ):
            self.transport.push_inbound(
                {
                    "cmd": f"{message.get('cmd', '')}_resp",
                    "headers": {"req_id": message.get("headers", {}).get("req_id", "")},
                    "errcode": 0,
                    "errmsg": "ok",
                }
            )


@dataclass
class _TlsFiles:
    ca: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    other_client_cert: Path
    other_client_key: Path


def _tls_files(directory: Path) -> _TlsFiles:
    """Create ephemeral local mTLS identities with OpenSSL for the fake Authority."""

    if shutil.which("openssl") is None:
        pytest.skip("OpenSSL is required to create ephemeral integration-test mTLS files")

    def run(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_cert),
        "-subj",
        "/CN=cyrene-e2e-ca",
        "-days",
        "1",
    )

    def signed_client(name: str, common_name: str, *, server: bool) -> tuple[Path, Path]:
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        cert = directory / f"{name}.crt"
        run(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={common_name}",
        )
        extension = directory / f"{name}.ext"
        if server:
            extension.write_text(
                "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
                encoding="ascii",
            )
        else:
            extension.write_text("extendedKeyUsage=clientAuth\n", encoding="ascii")
        run(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(extension),
        )
        return cert, key

    server_cert, server_key = signed_client("authority-server", "localhost", server=True)
    client_cert, client_key = signed_client("exchange-product", "exchange-product", server=False)
    other_cert, other_key = signed_client("other-product", "other-product", server=False)
    return _TlsFiles(
        ca_cert, server_cert, server_key, client_cert, client_key, other_cert, other_key
    )


class _Authority(authority_grpc.WorkspaceAuthorityServiceServicer):
    """Small local Authority RPC projection with signed credentials and live grants."""

    def __init__(self) -> None:
        self.users = {
            _USER_A: ("actor-a", _ORG, _WORKSPACE),
            _USER_B: ("actor-b", _ORG, _WORKSPACE),
            _USER_OTHER_ORG: ("other-org-actor", "org-other", "workspace-other"),
        }
        self.operations = {
            "accountBeginLink",
            "accountListLinks",
            "accountConfirmWeComLink",
            "accountUnlink",
            "integrationCreateConnection",
            "integrationListConnections",
            "integrationCreateBinding",
            "integrationAttachActorBinding",
            "integrationListActorBindings",
            "integrationListBindings",
            "integrationListJobs",
            "integrationGetOperation",
            "integrationCreateIssueComment",
            "integrationUpdateIssueState",
        }
        self.grants: dict[str, dict[str, Any]] = {}
        self.invocations: dict[str, Any] = {}
        self.directory_active = {"actor-a": True, "actor-b": True}
        self.product_workload_common_name = "exchange-product"
        self._feature_token = authority_wire.ManagedWorkloadFeatureToken(
            audience="exchange-product",
            client_certificate_sha256=b"c" * 32,
            signing_key_id="test-authority-key",
            issued_at=Timestamp(seconds=int(datetime.now(UTC).timestamp())),
            expires_at=Timestamp(
                seconds=int((datetime.now(UTC) + timedelta(minutes=10)).timestamp())
            ),
            authority_signature=b"f" * 64,
        ).SerializeToString(deterministic=True)

    @staticmethod
    def _bearer(context: grpc.ServicerContext) -> str:
        value = next(
            (value for key, value in context.invocation_metadata() if key == "authorization"),
            "",
        )
        return value.removeprefix("Bearer ")

    def _require_workload(self, context: grpc.ServicerContext) -> None:
        names = context.auth_context().get("x509_common_name", ())
        if self.product_workload_common_name.encode() not in names:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "registered workload required")

    def NegotiateVersion(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        return authority_wire.NegotiateVersionResponse(
            selected_version=2,
            supported_versions=[2],
            selected_features=["delegated_invocations_v1"],
            supported_features=["delegated_invocations_v1"],
            managed_workload_feature_token=self._feature_token,
        )

    def VerifyIdentity(self, request: Any, context: grpc.ServicerContext) -> Any:
        identity = self.users.get(self._bearer(context))
        if (
            identity is None
            or identity[2] != request.workspace_id
            or not self.directory_active.get(identity[0], True)
        ):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "identity rejected")
        subject, organization, workspace = identity
        return authority_wire.VerifyIdentityResponse(
            principal_id=subject,
            issuer=_ISSUER,
            subject=subject,
            organization_id=organization,
            workspace_id=workspace,
            session_id="session-" + subject,
            session_generation=1,
            permitted_workspaces=[workspace],
        )

    def GetCatalogSnapshot(self, request: Any, context: grpc.ServicerContext) -> Any:
        identity = self.users.get(self._bearer(context))
        if identity is None or identity[2] != request.workspace_id:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "catalog rejected")
        organization = identity[1]
        owner = authority_wire.OwnerSnapshot(
            owner_id="exchange",
            component_id="exchange-product",
            granted_operation_ids=sorted(self.operations),
        )
        return authority_wire.CatalogSnapshotResponse(
            organization_id=organization,
            workspace_id=request.workspace_id,
            owners=[owner],
        )

    def CreateDelegation(self, request: Any, context: grpc.ServicerContext) -> Any:
        identity = self.users.get(self._bearer(context))
        if identity is None or identity[2] != request.workspace_id:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "delegation owner rejected")
        if request.audience != "exchange-product" or not request.operations:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "delegation scope rejected")
        delegation_id = str(UUID(int=len(self.grants) + 1))
        expires = request.expires_at or Timestamp(
            seconds=int((datetime.now(UTC) + timedelta(days=1)).timestamp())
        )
        self.grants[delegation_id] = {
            "delegation_id": delegation_id,
            "organization_id": identity[1],
            "workspace_id": identity[2],
            "principal_issuer": _ISSUER,
            "principal_subject": identity[0],
            "audience": request.audience,
            "managed_workload_id": "exchange-product",
            "operations": [
                authority_wire.DelegatedOperationScope(
                    owner_id=item.owner_id,
                    operation_id=item.operation_id,
                    resource_ids=list(item.resource_ids),
                )
                for item in request.operations
            ],
            "expires_at": expires,
            "generation": 1,
            "revoked": False,
            "revoked_at": None,
        }
        return authority_wire.CreateDelegationResponse(
            delegation_id=delegation_id, generation=1, expires_at=expires
        )

    def GetDelegation(self, request: Any, context: grpc.ServicerContext) -> Any:
        grant = self.grants.get(request.delegation_id)
        if request.HasField("execution_credential"):
            record = self._validate_product_credential(
                request.execution_credential,
                context,
            )
            envelope = record["approved"].canonical_envelope
            invocation = envelope.invocation
            try:
                body = json.loads(invocation.json_body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "attach proof body is invalid")
            target = envelope.target
            expected_path = (
                f"/api/v1/integrations/sync-bindings/{invocation.resource_id}/actor-bindings"
            )
            if (
                envelope.authorization_source
                != authority_wire.INVOCATION_AUTHORIZATION_SOURCE_INTERACTIVE_SESSION
                or envelope.delegation_id
                or envelope.delegation_generation
                or request.execution_credential.delegation_id
                or request.execution_credential.delegation_generation
                or invocation.owner_id != "exchange"
                or invocation.operation_id != "integrationAttachActorBinding"
                or target.http_method != "POST"
                or target.endpoint != expected_path
                or target.resource_id != invocation.resource_id
                or not target.idempotency_key
                or target.idempotency_key != invocation.idempotency_key
                or request.workspace_id != envelope.workspace_id
                or not isinstance(body, dict)
                or body.get("delegationRef") != request.delegation_id
                or not isinstance(body.get("accountLinkRef"), str)
                or not body.get("accountLinkRef")
            ):
                context.abort(
                    grpc.StatusCode.PERMISSION_DENIED, "interactive attach proof mismatch"
                )
            if (
                grant is None
                or grant["revoked"]
                or not self.directory_active.get(envelope.principal_subject, True)
                or grant["principal_issuer"] != envelope.principal_issuer
                or grant["principal_subject"] != envelope.principal_subject
                or grant["organization_id"] != envelope.organization_id
                or grant["workspace_id"] != envelope.workspace_id
                or request.workspace_id != envelope.workspace_id
            ):
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "delegation is not self-owned")
        else:
            identity = self.users.get(self._bearer(context))
            if (
                grant is None
                or identity is None
                or grant["principal_subject"] != identity[0]
                or grant["organization_id"] != identity[1]
                or grant["workspace_id"] != request.workspace_id
            ):
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "delegation is not self-owned")
        return authority_wire.GetDelegationResponse(
            delegation_id=grant["delegation_id"],
            organization_id=grant["organization_id"],
            workspace_id=grant["workspace_id"],
            principal_issuer=grant["principal_issuer"],
            principal_subject=grant["principal_subject"],
            audience=grant["audience"],
            managed_workload_id=grant["managed_workload_id"],
            operations=grant["operations"],
            expires_at=grant["expires_at"],
            generation=grant["generation"],
            revoked=grant["revoked"],
            revoked_at=grant["revoked_at"],
        )

    def RevokeDelegation(self, request: Any, context: grpc.ServicerContext) -> Any:
        grant = self.grants.get(request.delegation_id)
        identity = self.users.get(self._bearer(context))
        if (
            grant is None
            or identity is None
            or grant["principal_subject"] != identity[0]
            or grant["workspace_id"] != request.workspace_id
        ):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "delegation is not self-owned")
        grant["revoked"] = True
        grant["generation"] += 1
        grant["revoked_at"] = Timestamp(seconds=int(datetime.now(UTC).timestamp()))
        return authority_wire.RevokeDelegationResponse(revoked=True, generation=grant["generation"])

    def ApproveAndEnqueueDelegatedInvocation(
        self, request: Any, context: grpc.ServicerContext
    ) -> Any:
        self._require_workload(context)
        grant = self.grants.get(request.delegation_id)
        if (
            grant is None
            or grant["revoked"]
            or not self.directory_active.get(grant["principal_subject"], True)
            or request.managed_workload_feature_token != self._feature_token
            or request.workspace_id != grant["workspace_id"]
        ):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "delegation is inactive")
        invocation = request.invocation
        if not any(
            scope.owner_id == invocation.owner_id
            and scope.operation_id == invocation.operation_id
            and (not scope.resource_ids or invocation.resource_id in scope.resource_ids)
            for scope in grant["operations"]
        ):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "delegation scope mismatch")
        approved = self._approved(grant, invocation)
        self.invocations[approved.invocation_id] = {
            "approved": approved,
            "grant_id": request.delegation_id,
            "state": authority_wire.INVOCATION_STATE_PENDING,
        }
        return authority_wire.ApproveAndEnqueueDelegatedInvocationResponse(
            invocation_id=approved.invocation_id,
            state=authority_wire.INVOCATION_STATE_PENDING,
        )

    def ValidateProductExecutionAuthorization(
        self, request: Any, context: grpc.ServicerContext
    ) -> Any:
        record = self._validate_product_credential(request.credential, context)
        return authority_wire.ValidateProductExecutionAuthorizationResponse(
            approved_invocation=record["approved"]
        )

    def _validate_product_credential(
        self, credential: Any, context: grpc.ServicerContext
    ) -> dict[str, Any]:
        """Verify the locally issued credential against its complete stored envelope."""

        self._require_workload(context)
        record = self.invocations.get(credential.invocation_id)
        if record is None:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "invocation is unknown")
        expected = record["approved"].credential
        expected_sig = (
            hmac.new(_EXECUTION_KEY, expected.request_digest_sha256, hashlib.sha256).digest() * 2
        )
        envelope = record["approved"].canonical_envelope
        grant_ref = record.get("grant_id")
        if grant_ref:
            grant = self.grants.get(grant_ref)
            if (
                grant is None
                or grant["revoked"]
                or not self.directory_active.get(grant["principal_subject"], True)
            ):
                context.abort(
                    grpc.StatusCode.PERMISSION_DENIED,
                    "execution authorization is revoked or invalid",
                )
        else:
            identity = next(
                (
                    value
                    for value in self.users.values()
                    if value[0] == envelope.principal_subject
                    and value[1] == envelope.organization_id
                    and value[2] == envelope.workspace_id
                ),
                None,
            )
            if (
                envelope.authorization_source
                != authority_wire.INVOCATION_AUTHORIZATION_SOURCE_INTERACTIVE_SESSION
                or envelope.delegation_id
                or envelope.delegation_generation
                or expected.delegation_id
                or expected.delegation_generation
                or identity is None
                or not self.directory_active.get(envelope.principal_subject, True)
                or envelope.session_id != f"session-{envelope.principal_subject}"
                or envelope.session_generation != 1
            ):
                context.abort(
                    grpc.StatusCode.PERMISSION_DENIED,
                    "interactive execution authorization is inactive or invalid",
                )
        if credential.SerializeToString(deterministic=True) != expected.SerializeToString(
            deterministic=True
        ) or not hmac.compare_digest(credential.authority_signature, expected_sig):
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "execution authorization is revoked or invalid"
            )
        return record

    def GetProductInvocationStatus(self, request: Any, context: grpc.ServicerContext) -> Any:
        self._require_workload(context)
        record = self.invocations.get(request.invocation_id)
        if record is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "invocation not found")
        grant = self.grants[record["grant_id"]]
        if grant["revoked"]:
            return authority_wire.GetProductInvocationStatusResponse(
                invocation_id=request.invocation_id,
                state=authority_wire.INVOCATION_STATE_FAILED,
                error_code="DELEGATION_REVOKED",
            )
        return authority_wire.GetProductInvocationStatusResponse(
            invocation_id=request.invocation_id,
            state=record["state"],
        )

    def _approved(self, grant: Mapping[str, Any], invocation: Any) -> Any:
        invocation_id = str(UUID(int=len(self.invocations) + 100))
        now = int(datetime.now(UTC).timestamp())
        target = authority_wire.ExecutionTarget(
            target_component="exchange-product",
            http_method="POST",
            endpoint="/api/v1/integrations/sync-bindings/",
            resource_id=invocation.resource_id,
            scope=f"organization={grant['organization_id']};workspace={grant['workspace_id']};resource={invocation.resource_id}",
            idempotency_key=invocation.idempotency_key,
            idempotency_semantics=authority_wire.IDEMPOTENCY_SEMANTICS_REQUIRED,
            execution_device_id="exchange-product",
            execution_device_generation=1,
            execution_authorization_id=b"a" * 16,
            execution_device_certificate_sha256=b"c" * 32,
        )
        path_action = {
            "integrationExecuteIssueComment": "execute-issue-comment",
            "integrationExecuteIssueState": "execute-issue-state",
            "integrationExecuteIssueQuery": "execute-issue-query",
        }[invocation.operation_id]
        endpoint = f"/api/v1/integrations/sync-bindings/{invocation.resource_id}/{path_action}"
        target.endpoint = endpoint
        envelope = authority_wire.CanonicalInvocationEnvelope(
            invocation_id=invocation_id,
            invocation=invocation,
            target=target,
            organization_id=grant["organization_id"],
            workspace_id=grant["workspace_id"],
            principal_issuer=grant["principal_issuer"],
            principal_subject=grant["principal_subject"],
            execution_device_id="exchange-product",
            execution_device_generation=1,
            execution_authorization_id=b"a" * 16,
            execution_device_certificate_sha256=b"c" * 32,
            contract_activation_generation=1,
            issued_at=Timestamp(seconds=now),
            expires_at=Timestamp(seconds=now + 120),
            authorization_source=authority_wire.INVOCATION_AUTHORIZATION_SOURCE_DELEGATION,
            delegation_id=grant["delegation_id"],
            delegation_generation=grant["generation"],
            delegation_audience=grant["audience"],
        )
        digest = hashlib.sha256(envelope.SerializeToString(deterministic=True)).digest()
        invocation_digest = hashlib.sha256(
            invocation.SerializeToString(deterministic=True)
        ).digest()
        credential = authority_wire.ExecutionCredential(
            invocation_id=invocation_id,
            invocation_digest_sha256=invocation_digest,
            request_digest_sha256=digest,
            organization_id=grant["organization_id"],
            workspace_id=grant["workspace_id"],
            principal_issuer=grant["principal_issuer"],
            principal_subject=grant["principal_subject"],
            operation_owner_id=invocation.owner_id,
            operation_id=invocation.operation_id,
            scope=target.scope,
            resource_id=target.resource_id,
            target_component=target.target_component,
            http_method=target.http_method,
            endpoint=target.endpoint,
            execution_device_id=target.execution_device_id,
            execution_device_generation=target.execution_device_generation,
            execution_authorization_id=target.execution_authorization_id,
            execution_device_certificate_sha256=target.execution_device_certificate_sha256,
            contract_activation_generation=1,
            idempotency_key=target.idempotency_key,
            idempotency_semantics=target.idempotency_semantics,
            signing_key_id="test-authority-key",
            issued_at=envelope.issued_at,
            expires_at=envelope.expires_at,
            authority_signature=hmac.new(_EXECUTION_KEY, digest, hashlib.sha256).digest() * 2,
            authorization_source=envelope.authorization_source,
            delegation_id=envelope.delegation_id,
            delegation_generation=envelope.delegation_generation,
            delegation_audience=envelope.delegation_audience,
        )
        return authority_wire.ApprovedInvocation(
            invocation_id=invocation_id,
            canonical_envelope=envelope,
            credential=credential,
        )

    def _approved_interactive(self, subject: str, invocation: Any) -> Any:
        """Issue an interactive-session proof for a fixed current catalog call."""

        identity = next(
            (value for value in self.users.values() if value[0] == subject),
            None,
        )
        if identity is None:
            raise AssertionError("interactive fixture subject is not registered")
        _, organization, workspace = identity
        invocation_id = str(UUID(int=len(self.invocations) + 100))
        now = int(datetime.now(UTC).timestamp())
        binding_id = invocation.resource_id
        path = f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings"
        scope = f"organization={organization};workspace={workspace};resource={binding_id}"
        target = authority_wire.ExecutionTarget(
            target_component="exchange-product",
            http_method="POST",
            endpoint=path,
            resource_id=binding_id,
            scope=scope,
            idempotency_key=invocation.idempotency_key,
            idempotency_semantics=authority_wire.IDEMPOTENCY_SEMANTICS_REQUIRED,
            execution_device_id="exchange-product",
            execution_device_generation=1,
            execution_authorization_id=b"i" * 16,
            execution_device_certificate_sha256=b"c" * 32,
        )
        envelope = authority_wire.CanonicalInvocationEnvelope(
            invocation_id=invocation_id,
            invocation=invocation,
            target=target,
            organization_id=organization,
            workspace_id=workspace,
            principal_issuer=_ISSUER,
            principal_subject=subject,
            execution_device_id="exchange-product",
            execution_device_generation=1,
            execution_authorization_id=b"i" * 16,
            execution_device_certificate_sha256=b"c" * 32,
            session_id=f"session-{subject}",
            session_generation=1,
            contract_activation_generation=1,
            issued_at=Timestamp(seconds=now),
            expires_at=Timestamp(seconds=now + 120),
            authorization_source=(
                authority_wire.INVOCATION_AUTHORIZATION_SOURCE_INTERACTIVE_SESSION
            ),
        )
        digest = hashlib.sha256(envelope.SerializeToString(deterministic=True)).digest()
        invocation_digest = hashlib.sha256(
            invocation.SerializeToString(deterministic=True)
        ).digest()
        credential = authority_wire.ExecutionCredential(
            invocation_id=invocation_id,
            invocation_digest_sha256=invocation_digest,
            request_digest_sha256=digest,
            organization_id=organization,
            workspace_id=workspace,
            principal_issuer=_ISSUER,
            principal_subject=subject,
            operation_owner_id=invocation.owner_id,
            operation_id=invocation.operation_id,
            scope=scope,
            resource_id=binding_id,
            target_component="exchange-product",
            http_method="POST",
            endpoint=path,
            execution_device_id="exchange-product",
            execution_device_generation=1,
            execution_authorization_id=b"i" * 16,
            execution_device_certificate_sha256=b"c" * 32,
            session_id=f"session-{subject}",
            session_generation=1,
            contract_activation_generation=1,
            idempotency_key=invocation.idempotency_key,
            idempotency_semantics=authority_wire.IDEMPOTENCY_SEMANTICS_REQUIRED,
            signing_key_id="test-authority-key",
            issued_at=envelope.issued_at,
            expires_at=envelope.expires_at,
            authority_signature=hmac.new(_EXECUTION_KEY, digest, hashlib.sha256).digest() * 2,
            authorization_source=(
                authority_wire.INVOCATION_AUTHORIZATION_SOURCE_INTERACTIVE_SESSION
            ),
        )
        approved = authority_wire.ApprovedInvocation(
            invocation_id=invocation_id,
            canonical_envelope=envelope,
            credential=credential,
        )
        self.invocations[invocation_id] = {
            "approved": approved,
            "grant_id": None,
            "state": authority_wire.INVOCATION_STATE_PENDING,
        }
        return approved

    def ApproveAndEnqueueInvocation(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "interactive enqueue is outside this E2E")

    def ClaimInvocations(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        context.abort(
            grpc.StatusCode.UNIMPLEMENTED, "Connector polling is outside this Product E2E"
        )

    def ValidateExecutionAuthorization(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "device execution is outside this Product E2E")

    def AcknowledgeDelivery(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "device delivery is outside this Product E2E")

    def SubmitInvocationResult(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "device result is outside this Product E2E")

    def WaitInvocationResult(self, request: Any, context: grpc.ServicerContext) -> Any:
        del request
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "interactive wait is outside this Product E2E")


@dataclass
class _AuthorityNetwork:
    authority: _Authority
    socket_path: Path
    tls_files: _TlsFiles
    workload_target: str
    unix_server: grpc.Server
    workload_server: grpc.Server

    def stop(self) -> None:
        self.unix_server.stop(0).wait()
        self.workload_server.stop(0).wait()


def _start_authority(directory: Path, tls_files: _TlsFiles) -> _AuthorityNetwork:
    authority = _Authority()
    socket_path = directory / "authority.sock"
    unix_server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    authority_grpc.add_WorkspaceAuthorityServiceServicer_to_server(authority, unix_server)
    assert unix_server.add_insecure_port(f"unix://{socket_path}") > 0
    unix_server.start()

    workload_server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    authority_grpc.add_WorkspaceAuthorityServiceServicer_to_server(authority, workload_server)
    server_credentials = grpc.ssl_server_credentials(
        ((tls_files.server_key.read_bytes(), tls_files.server_cert.read_bytes()),),
        root_certificates=tls_files.ca.read_bytes(),
        require_client_auth=True,
    )
    port = workload_server.add_secure_port("127.0.0.1:0", server_credentials)
    assert port > 0
    workload_server.start()
    return _AuthorityNetwork(
        authority,
        socket_path,
        tls_files,
        f"127.0.0.1:{port}",
        unix_server,
        workload_server,
    )


def _direct_plugin(plugin: Any, capability: str) -> tuple[Any, grpc.Server]:
    from cyrene_plugin_runtime import DirectPluginClient
    from cyrene_plugin_runtime._generated import direct_plugin_runtime_pb2_grpc
    from cyrene_plugin_runtime.server import DirectPluginService

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    direct_plugin_runtime_pb2_grpc.add_DirectPluginRuntimeServicer_to_server(
        DirectPluginService(plugin, capability, "1"), server
    )
    port = server.add_insecure_port("127.0.0.1:0")
    assert port > 0
    server.start()
    return DirectPluginClient.for_local_connection_ref(f"grpc://127.0.0.1:{port}"), server


@dataclass
class _Hub:
    plugins_root: Path
    authority_network: _AuthorityNetwork
    tls_files: _TlsFiles
    account_direct: Any
    github_direct: Any
    wecom_direct: Any
    account_client: AccountCenterClient
    github_client: GitHubIssuesClient
    webhook_client: GitHubWebhookClient
    message_client: WeComMessageClient
    account_plugin_server: grpc.Server
    github_plugin_server: grpc.Server
    wecom_plugin_server: grpc.Server
    wecom_plugin: Any
    wecom_http_transport: _LocalExchangeHttpTransport
    oauth_http: _GitHubOAuthHttp
    github_http: _GitHubHttp
    wecom_ws: _WeComFakeWebSocket
    identity_verifier: PlatformAuthorityIdentityVerifier
    delegation_client: PlatformAuthorityDelegationClient
    execution_verifier: PlatformExecutionAuthorizationVerifier
    owner_principal: Principal
    member_principal: Principal
    callback_principal: Principal

    def services(self, store: IntegrationStore) -> IntegrationServices:
        account_center = IntegrationAccountCenterPort(self.account_client)
        dispatcher = IntegrationDispatcher(
            store=store,
            account_center=account_center,
            github=IntegrationGitHubPort(self.github_client),
            message=self.message_client,
            delegation=self.delegation_client,
        )
        runner = DispatcherRunner(dispatcher, worker_id="exchange-integration-e2e")
        return IntegrationServices(
            store=store,
            authorizer=self.identity_verifier,
            accounts=self.account_client,
            github=self.github_client,
            webhook_verifier=self.webhook_client,
            delegation_authorizer=self.delegation_client,
            callback_principal=self.callback_principal,
            account_center=account_center,
            dispatcher=dispatcher,
            dispatcher_runner=runner,
            execution_authorization_verifier=self.execution_verifier,
        )

    def stop_plugins(self) -> None:
        self.wecom_plugin.on_shutdown(1000)
        for client in (self.account_direct, self.github_direct, self.wecom_direct):
            client.close()
        for server in (
            self.account_plugin_server,
            self.github_plugin_server,
            self.wecom_plugin_server,
        ):
            server.stop(0).wait()


@pytest.fixture
def plugins_root() -> Path:
    root = _plugins_root()
    if root is None:
        pytest.skip(
            "requires the sibling Cyrene-Plugins-Official checkout for local DirectPluginRuntime"
        )
    return root


def _make_hub(directory: Path, plugins_root: Path) -> _Hub:
    _load_plugins(plugins_root)
    from account_center.github import GitHubOAuthClient
    from account_center.plugin import AccountCenterPlugin
    from github_issues_provider.account_center import AccountCenterDirectLeaseClient
    from github_issues_provider.github_api import GitHubApi
    from github_issues_provider.plugin import GitHubIssuesProvider
    from github_issues_provider.settings import ProviderSettings, Repository
    from wecom_connector import WeComConnector, WeComInstanceConfig

    tls_files = _tls_files(directory)
    authority_network = _start_authority(directory, tls_files)
    identity_verifier = PlatformAuthorityIdentityVerifier(
        target=f"unix://{authority_network.socket_path}"
    )
    workload_target = f"grpcs://{authority_network.workload_target}"
    delegation_client = PlatformAuthorityDelegationClient(
        identity_verifier=identity_verifier,
        target=workload_target,
        root_certificates_path=tls_files.ca,
        private_key_path=tls_files.client_key,
        certificate_chain_path=tls_files.client_cert,
        workload_id="exchange-product",
        audience="exchange-product",
    )
    execution_verifier = PlatformExecutionAuthorizationVerifier(
        target=authority_network.workload_target,
        root_certificates=tls_files.ca.read_bytes(),
        private_key=tls_files.client_key.read_bytes(),
        certificate_chain=tls_files.client_cert.read_bytes(),
    )

    oauth_http = _GitHubOAuthHttp()
    oauth = GitHubOAuthClient(client_id="synthetic-client", client_secret="synthetic-secret")
    oauth._opener = oauth_http
    account_plugin = AccountCenterPlugin(
        {
            "encryption_key": b"a" * 32,
            "binding_id": _AC_BINDING,
            "storage_path": str(directory / "private-account-center.sqlite3"),
            "github_callback_uri": "https://exchange.example.test/callback",
            "caller_keys": _AC_KEYS,
            "method_callers": {
                "begin_link": ["exchange-e2e"],
                "complete_github_link": ["callback-e2e"],
                "observe_wecom_challenge": ["wecom-source-e2e"],
                "confirm_wecom_link": ["exchange-e2e"],
                "list_links": ["exchange-e2e"],
                "get_authorization": ["exchange-e2e"],
                "unlink": ["exchange-e2e"],
                "create_credential_lease": ["exchange-e2e"],
                "redeem_credential_lease": ["github-e2e"],
                "resolve_linked_sender": ["exchange-e2e"],
            },
            "exchange_caller_id": "exchange-e2e",
            "github_callback_caller_id": "callback-e2e",
            "github_provider_caller_id": "github-e2e",
            "wecom_sources": {
                "wecom-source-e2e": {
                    "source_authority": "wecom.example.test",
                    "bot_namespaces": ["bot-e2e"],
                }
            },
        },
        github_client=oauth,
    )
    account_direct, account_plugin_server = _direct_plugin(account_plugin, "account.center.v1")
    account_signer = AccountCenterRequestSigner(
        caller_id="exchange-e2e", key=_AC_KEYS["exchange-e2e"]
    )
    accounts = AccountCenterClient(
        account_direct,
        exchange_signer=account_signer,
        binding_id=_AC_BINDING,
        callback_signer=AccountCenterRequestSigner(
            caller_id="callback-e2e", key=_AC_KEYS["callback-e2e"]
        ),
        wecom_source_signer=AccountCenterRequestSigner(
            caller_id="wecom-source-e2e", key=_AC_KEYS["wecom-source-e2e"]
        ),
    )

    github_http = _GitHubHttp()
    provider_settings = ProviderSettings(
        binding_id=_GH_BINDING,
        account_center_binding_id=_AC_BINDING,
        account_center_connection_ref="grpc://local-account-center",
        account_center_transport="local",
        account_center_root_cert_ref=None,
        account_center_client_cert_ref=None,
        account_center_client_key_ref=None,
        host_secret_names={},
        repositories=(Repository(_REPOSITORY_ID, "cyrene", "e2e"),),
        provider_caller_id="github-e2e",
        exchange_caller_id="exchange-e2e",
        exchange_verification_key=_AC_KEYS["exchange-e2e"],
        provider_signing_key=_AC_KEYS["github-e2e"],
        github_webhook_secret=_WEBHOOK_SECRET,
        allowed_installation_ids=frozenset({"99"}),
        allowed_events=frozenset({"issues"}),
        allowed_actions=frozenset({"opened", "edited"}),
        timeout_seconds=1.0,
    )
    lease_client = AccountCenterDirectLeaseClient(provider_settings, client=account_direct)
    github_api = GitHubApi(provider_settings, transport=github_http)
    github_plugin = GitHubIssuesProvider(
        settings=provider_settings,
        account_center=lease_client,
        github_api=github_api,
    )
    github_direct, github_plugin_server = _direct_plugin(github_plugin, "tool.provider.v1")
    github = GitHubIssuesClient(
        github_direct,
        signer=account_signer,
        binding_id=_GH_BINDING,
    )
    webhook = GitHubWebhookClient(github_direct)

    wecom_ws = _WeComFakeWebSocket(acknowledge=True)
    wecom_http_transport = _LocalExchangeHttpTransport()
    wecom_plugin = WeComConnector(
        WeComInstanceConfig(
            binding_id=_WECOM_BINDING,
            mode="bot",
            bot_id="bot-e2e",
            bot_secret="synthetic-bot-secret",
        ),
        ws_transport=wecom_ws.transport,
    )
    wecom_direct, wecom_plugin_server = _direct_plugin(wecom_plugin, "message.connector.v1")
    message = WeComMessageClient(
        wecom_direct,
        targets={
            "wecom-target-e2e": {
                "bot_id": "bot-e2e",
                "conversation_id": "chat-e2e",
                "kind": "PRIVATE",
            }
        },
    )
    callback_principal = Principal(
        issuer="urn:cyrene:service",
        subject="exchange-oauth-callback",
        organization_id=_ORG,
        workspace_id=_WORKSPACE,
        allowed_operation_ids=frozenset(),
    )
    return _Hub(
        plugins_root=plugins_root,
        authority_network=authority_network,
        tls_files=tls_files,
        account_direct=account_direct,
        github_direct=github_direct,
        wecom_direct=wecom_direct,
        account_client=accounts,
        github_client=github,
        webhook_client=webhook,
        message_client=message,
        account_plugin_server=account_plugin_server,
        github_plugin_server=github_plugin_server,
        wecom_plugin_server=wecom_plugin_server,
        wecom_plugin=wecom_plugin,
        wecom_http_transport=wecom_http_transport,
        oauth_http=oauth_http,
        github_http=github_http,
        wecom_ws=wecom_ws,
        identity_verifier=identity_verifier,
        delegation_client=delegation_client,
        execution_verifier=execution_verifier,
        owner_principal=identity_verifier.principal_for(
            bearer_token=_USER_A, workspace_id=_WORKSPACE
        ),
        member_principal=identity_verifier.principal_for(
            bearer_token=_USER_B, workspace_id=_WORKSPACE
        ),
        callback_principal=callback_principal,
    )


def _wecom_source(binding_id: UUID) -> Any:
    """Return the host-resolved, synthetic source facts used by the local sink."""

    from cyrene_exchange_product.integrations.intake import WeComInboundSource

    return WeComInboundSource(
        binding_id=binding_id,
        organization_id=_ORG,
        workspace_id=_WORKSPACE,
        source_authority="wecom.example.test",
        bot_namespace="bot-e2e",
        account_id="bot:bot-e2e",
        group_conversation_id=_WECOM_GROUP,
        request_hmac_key=_WECOM_SOURCE_KEY,
    )


def _enable_wecom_ingress(
    hub: _Hub,
    services: IntegrationServices,
    *,
    binding_id: UUID,
    directory: Path,
    client: TestClient,
    configure_plugin: bool,
) -> None:
    """Wire the actual Plugin forwarder to the signed local Exchange route."""

    from wecom_connector import WeComInstanceConfig
    from wecom_connector.integration_forwarder import WeComIntegrationConfig

    services.wecom_sources.clear()
    services.wecom_sources[str(binding_id)] = _wecom_source(binding_id)
    services.wecom_source_principal = lambda _binding: Principal(
        issuer="urn:cyrene:service",
        subject="exchange-wecom-source",
        organization_id=_ORG,
        workspace_id=_WORKSPACE,
        allowed_operation_ids=frozenset(),
    )
    hub.wecom_http_transport.client = client
    hub.message_client._source_accounts[str(binding_id)] = {
        "account_id": "bot:bot-e2e",
        "group_conversation_id": _WECOM_GROUP,
    }
    if configure_plugin:
        integration = WeComIntegrationConfig(
            binding_id=str(binding_id),
            exchange_base_url="http://127.0.0.1:8765",
            organization_id=_ORG,
            workspace_id=_WORKSPACE,
            source_authority="wecom.example.test",
            bot_namespace="bot-e2e",
            account_id="bot:bot-e2e",
            group_conversation_id=_WECOM_GROUP,
            source_hmac_key=_WECOM_SOURCE_KEY,
            outbox_path=directory / "wecom-plugin-forwarder.sqlite3",
            timeout_seconds=1.0,
        )
        hub.wecom_plugin.configure(
            WeComInstanceConfig(
                binding_id=str(binding_id),
                mode="bot",
                bot_id="bot-e2e",
                bot_secret="synthetic-bot-secret",
                integration=integration,
            ),
            ws_transport=hub.wecom_ws.transport,
            integration_http_transport=hub.wecom_http_transport,
        )
        assert (
            hub.wecom_plugin.on_subscribe(
                "exchange-integration-e2e",
                "message.connector.v1",
                b"{}",
                _PluginEventSink(),
            )
            is None
        )


def _wait_for_wecom_forwarder(hub: _Hub, *, acked_count: int) -> None:
    """Wait for the real connector outbox to receive Exchange's durable ACK."""

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        forwarder = hub.wecom_plugin._integration_forwarder
        if forwarder is not None and forwarder.queue_status().get("ACKED") == acked_count:
            return
        time.sleep(0.01)
    forwarder = hub.wecom_plugin._integration_forwarder
    status = forwarder.queue_status() if forwarder is not None else None
    rows = (
        forwarder._db.execute(
            "SELECT source_event_id,status,attempts,last_status_code "
            "FROM wecom_exchange_outbox ORDER BY source_event_id"
        ).fetchall()
        if forwarder is not None
        else []
    )
    raise AssertionError(
        f"WeCom forwarder did not receive its durable ACK: {status}; "
        f"{[tuple(row) for row in rows]}; {hub.wecom_http_transport.errors}"
    )


def _push_wecom_message(
    hub: _Hub,
    *,
    message_id: str,
    sender_id: str,
    conversation_id: str,
    kind: str,
    text: str,
) -> None:
    """Inject one callback into the actual local bot SDK and wait for signed intake."""

    hub.wecom_ws.transport.push_inbound(
        {
            "cmd": "aibot_msg_callback",
            "headers": {"req_id": f"callback-{message_id}"},
            "body": {
                "msgid": message_id,
                "chatid": conversation_id,
                "chattype": "group" if kind == "group" else "single",
                "from": {"userid": sender_id},
                "msgtype": "text",
                "text": {"content": text},
            },
        }
    )


def _create_grant(
    network: _AuthorityNetwork,
    *,
    bearer: str,
    binding_id: UUID,
) -> str:
    """Create an exact member grant through the generated Authority v2 gRPC SDK."""

    channel = grpc.insecure_channel(f"unix://{network.socket_path}")
    try:
        stub = authority_grpc.WorkspaceAuthorityServiceStub(channel)
        response = stub.CreateDelegation(
            authority_wire.CreateDelegationRequest(
                workspace_id=_WORKSPACE,
                audience="exchange-product",
                operations=[
                    authority_wire.DelegatedOperationScope(
                        owner_id="exchange",
                        operation_id=operation,
                        resource_ids=[str(binding_id)],
                    )
                    for operation in (
                        "integrationExecuteIssueComment",
                        "integrationExecuteIssueState",
                        "integrationExecuteIssueQuery",
                    )
                ],
                expires_at=Timestamp(
                    seconds=int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
                ),
            ),
            timeout=2,
            metadata=(("authorization", f"Bearer {bearer}"),),
        )
        return response.delegation_id
    finally:
        channel.close()


def _github_link(client: TestClient, bearer: str, *, code: str) -> str:
    """Exercise Account Center link sessions and its fixed OAuth callback."""

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Idempotency-Key": f"account-link-{code}",
    }
    begin = client.post(
        "/api/v1/accounts/link-sessions",
        params={"workspaceId": _WORKSPACE},
        headers=headers,
        json={"provider": "github"},
    )
    assert begin.status_code == 201, begin.text
    session = begin.json()
    authorization_url = session.get("authorization_url") or session.get("authorizationUrl")
    assert isinstance(authorization_url, str)
    state = parse_qs(urlsplit(authorization_url).query)["state"][0]
    callback = client.get(
        "/api/v1/accounts/github/callback",
        params={
            "state": state,
            "code": code,
        },
    )
    assert callback.status_code == 200, callback.text
    return str(callback.json().get("account_ref") or callback.json()["accountRef"])


def _create_connection_and_binding(
    client: TestClient,
    bearer: str,
) -> tuple[UUID, UUID]:
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Idempotency-Key": "e2e-group-connection-1",
    }
    connection_response = client.post(
        "/api/v1/integrations/connections",
        params={"workspaceId": _WORKSPACE},
        headers=headers,
        json={"repository_id": _REPOSITORY_ID, "repository_name": _REPOSITORY},
    )
    assert connection_response.status_code == 201, connection_response.text
    connection_id = UUID(connection_response.json()["id"])
    binding_response = client.post(
        "/api/v1/integrations/sync-bindings",
        params={"workspaceId": _WORKSPACE},
        headers=headers,
        json={
            "connection_id": str(connection_id),
            "notification_target_ref": "wecom-target-e2e",
        },
    )
    assert binding_response.status_code == 201, binding_response.text
    return connection_id, UUID(binding_response.json()["id"])


def _attach_member(
    client: TestClient,
    *,
    bearer: str,
    binding_id: UUID,
    account_ref: str,
    delegation_ref: str,
) -> None:
    response = client.post(
        f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings",
        params={"workspaceId": _WORKSPACE},
        headers={
            "Authorization": f"Bearer {bearer}",
            "Idempotency-Key": f"actor-binding-{account_ref}",
        },
        json={
            "account_link_ref": account_ref,
            "delegation_ref": delegation_ref,
        },
    )
    assert response.status_code == 201, response.text


def _attach_member_with_interactive_product_proof(
    client: TestClient,
    *,
    hub: _Hub,
    binding_id: UUID,
    account_ref: str,
    delegation_ref: str,
) -> None:
    """Attach a member using a signed interactive invocation over Product mTLS."""

    path = f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings"
    idempotency_key = f"interactive-actor-binding-{account_ref}"
    body = json.dumps(
        {"accountLinkRef": account_ref, "delegationRef": delegation_ref},
        separators=(",", ":"),
    ).encode()
    invocation = product_wire.ProductApiInvocationV2(
        owner_id="exchange",
        operation_id="integrationAttachActorBinding",
        json_body=body,
        resource_id=str(binding_id),
        idempotency_key=idempotency_key,
    )
    approved = hub.authority_network.authority._approved_interactive("actor-a", invocation)
    assert (
        approved.canonical_envelope.authorization_source
        == authority_wire.INVOCATION_AUTHORIZATION_SOURCE_INTERACTIVE_SESSION
    )
    assert approved.canonical_envelope.principal_subject == "actor-a"
    assert not approved.canonical_envelope.delegation_id
    assert not approved.credential.delegation_id
    response = client.post(
        path,
        headers={
            "x-cyrene-execution-credential-bin": base64.b64encode(
                approved.credential.SerializeToString(deterministic=True)
            ).decode("ascii"),
            "X-Cyrene-Workspace-Id": _WORKSPACE,
            "Idempotency-Key": idempotency_key,
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert response.status_code == 201, response.text


def _webhook_body(action: str = "opened") -> bytes:
    return json.dumps(
        {
            "action": action,
            "installation": {"id": 99},
            "repository": {"id": 4242, "full_name": _REPOSITORY},
            "issue": {
                "id": 1200,
                "number": 12,
                "title": "Synthetic issue",
                "body": "Synthetic description",
                "state": "open",
                "user": {"id": 700, "login": "reporter"},
            },
            "sender": {"id": 700, "login": "reporter"},
        },
        separators=(",", ":"),
    ).encode()


def _run_job_at_persisted_due_time(runner: Any, job: Any) -> Any:
    """Advance only the test clock to the durable job's declared eligibility time."""

    moment = max(datetime.now(UTC), job.available_at) + timedelta(microseconds=1)
    return runner.run_once(now=moment)


def _post_webhook(
    client: TestClient,
    *,
    connection_id: UUID,
    delivery_id: str,
    body: bytes,
    valid: bool = True,
) -> Any:
    signature = hmac.new(_WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    if not valid:
        signature = "0" * 64
    return client.post(
        f"/api/v1/integrations/hooks/github/{connection_id}",
        headers={
            "X-GitHub-Delivery": delivery_id,
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": f"sha256={signature}",
        },
        content=body,
    )


def _create_issue_operation(
    client: TestClient,
    *,
    bearer: str,
    binding_id: UUID,
    action: str = "comment",
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {bearer}", "Idempotency-Key": f"e2e-{action}-1"}
    if action == "comment":
        response = client.post(
            f"/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/comment",
            params={"workspaceId": _WORKSPACE},
            headers=headers,
            json={"issueNumber": 12, "body": "Member-authored synthetic comment"},
        )
    else:
        response = client.post(
            f"/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/state",
            params={"workspaceId": _WORKSPACE},
            headers=headers,
            json={"issueNumber": 12, "state": "CLOSED"},
        )
    assert response.status_code == 202, response.text
    return response.json()


def test_integration_hub_webhook_restart_member_execution_and_wecom_receipts(
    tmp_path: Path,
    plugins_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise real local Plugin RPCs, durable Exchange state, and Authority proof."""

    model_requests: list[str] = []
    original_http_request = httpx.Client.request

    def count_model_requests(self: Any, method: str, url: Any, **kwargs: Any) -> Any:
        parsed = httpx.URL(url)
        if parsed.path.endswith("/chat/completions"):
            model_requests.append(f"{method} {parsed.path}")
        return original_http_request(self, method, url, **kwargs)

    monkeypatch.setattr(httpx.Client, "request", count_model_requests)
    hub = _make_hub(tmp_path, plugins_root)
    integration_path = tmp_path / "integration-state.sqlite3"
    exchange_path = tmp_path / "exchange-state.sqlite3"
    store = IntegrationStore(integration_path)
    services = hub.services(store)
    services.wecom_sources["route-registration-placeholder"] = _wecom_source(
        UUID("00000000-0000-0000-0000-000000000001")
    )
    app = create_app(database_path=exchange_path, integrations=services)
    connection_id: UUID
    binding_id: UUID
    owner_account_ref: str
    member_account_ref: str
    owner_grant: str
    member_grant: str
    initial_event_id: str
    restarted_store: IntegrationStore | None = None
    restarted_app: Any = None
    initial_exchange_store_closed = False

    try:
        with TestClient(app) as client:
            # Both users link through the actual Account Center entrypoint. The
            # callback exchanges only synthetic OAuth responses and persists an
            # encrypted account under the verified actor anchor.
            owner_account_ref = _github_link(client, _USER_A, code="owner-code")
            member_account_ref = _github_link(client, _USER_B, code="member-code")
            owner_links = client.get(
                "/api/v1/accounts/links",
                params={"workspaceId": _WORKSPACE},
                headers={"Authorization": f"Bearer {_USER_A}"},
            )
            member_links = client.get(
                "/api/v1/accounts/links",
                params={"workspaceId": _WORKSPACE},
                headers={"Authorization": f"Bearer {_USER_B}"},
            )
            assert owner_links.status_code == member_links.status_code == 200
            assert [row["account_ref"] for row in owner_links.json()["links"]] == [
                owner_account_ref
            ]
            assert [row["account_ref"] for row in member_links.json()["links"]] == [
                member_account_ref
            ]

            connection_id, binding_id = _create_connection_and_binding(client, _USER_A)
            _enable_wecom_ingress(
                hub,
                services,
                binding_id=binding_id,
                directory=tmp_path,
                client=client,
                configure_plugin=True,
            )
            owner_grant = _create_grant(
                hub.authority_network,
                bearer=_USER_A,
                binding_id=binding_id,
            )
            member_grant = _create_grant(
                hub.authority_network,
                bearer=_USER_B,
                binding_id=binding_id,
            )
            _attach_member_with_interactive_product_proof(
                client,
                hub=hub,
                binding_id=binding_id,
                account_ref=owner_account_ref,
                delegation_ref=owner_grant,
            )
            _attach_member(
                client,
                bearer=_USER_B,
                binding_id=binding_id,
                account_ref=member_account_ref,
                delegation_ref=member_grant,
            )

            # A sibling organization cannot inspect the group binding. The
            # member projection contains only that member's own credential refs.
            outsider_bindings = client.get(
                f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings",
                params={"workspaceId": "workspace-other"},
                headers={"Authorization": f"Bearer {_USER_OTHER_ORG}"},
            )
            assert outsider_bindings.status_code == 200
            assert outsider_bindings.json() == []
            member_bindings = client.get(
                f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings",
                params={"workspaceId": _WORKSPACE},
                headers={"Authorization": f"Bearer {_USER_B}"},
            )
            owner_bindings = client.get(
                f"/api/v1/integrations/sync-bindings/{binding_id}/actor-bindings",
                params={"workspaceId": _WORKSPACE},
                headers={"Authorization": f"Bearer {_USER_A}"},
            )
            assert [row["accountLinkRef"] for row in owner_bindings.json()] == [owner_account_ref]
            assert [row["accountLinkRef"] for row in member_bindings.json()] == [member_account_ref]

            raw_event = _webhook_body()
            forged = _post_webhook(
                client,
                connection_id=connection_id,
                delivery_id="delivery-forged",
                body=raw_event,
                valid=False,
            )
            assert forged.status_code == 401
            first = _post_webhook(
                client,
                connection_id=connection_id,
                delivery_id="delivery-e2e-1",
                body=raw_event,
            )
            duplicate = _post_webhook(
                client,
                connection_id=connection_id,
                delivery_id="delivery-e2e-1",
                body=raw_event,
            )
            assert first.status_code == duplicate.status_code == 202, first.text
            assert first.json()["eventId"] == duplicate.json()["eventId"]
            initial_event_id = first.json()["eventId"]

        app.state.exchange_store.close()
        initial_exchange_store_closed = True
        store.close()
        store = None

        # Reopen the integration database to prove the inbox and outbox survive
        # process replacement before a dispatcher claims the notification.
        restarted_store = IntegrationStore(integration_path)
        restarted_services = hub.services(restarted_store)
        restarted_services.wecom_sources["route-registration-placeholder"] = _wecom_source(
            UUID("00000000-0000-0000-0000-000000000001")
        )
        restarted_app = create_app(
            database_path=exchange_path,
            integrations=restarted_services,
        )
        with TestClient(restarted_app) as client:
            _enable_wecom_ingress(
                hub,
                restarted_services,
                binding_id=binding_id,
                directory=tmp_path,
                client=client,
                configure_plugin=False,
            )
            duplicate_after_restart = _post_webhook(
                client,
                connection_id=connection_id,
                delivery_id="delivery-e2e-1",
                body=raw_event,
            )
            assert duplicate_after_restart.status_code == 202
            assert duplicate_after_restart.json()["eventId"] == initial_event_id
            assert len(restarted_store.list_jobs(hub.owner_principal, state=JobState.READY)) == 1

            notification_job = next(
                job
                for job in restarted_store.list_jobs(
                    hub.owner_principal,
                    state=JobState.READY,
                )
                if job.kind == "NOTIFY"
            )
            notification_result = _run_job_at_persisted_due_time(
                restarted_services.dispatcher_runner,
                notification_job,
            )
            assert notification_result.state == "ACCEPTED", (
                notification_result,
                hub.wecom_ws.commands,
            )
            receipts = restarted_store.list_delivery_receipts(hub.owner_principal)
            assert len(receipts) == 1
            assert receipts[0].accepted is True
            assert receipts[0].vendor_message_id is None
            assert receipts[0].transport_request_id
            outbound = [
                item for item in hub.wecom_ws.commands if item.get("cmd") == "aibot_send_msg"
            ]
            assert len(outbound) == 1
            assert outbound[0]["body"]["chatid"] == "chat-e2e"
            assert set(outbound[0]["body"]) == {"chatid", "msgtype", "text"}
            assert outbound[0]["body"]["msgtype"] == "text"
            assert outbound[0]["body"]["text"]["content"]

            # No receipt is success: one lost ACK becomes UNKNOWN and is not
            # automatically resent after the outbox is reopened.
            hub.wecom_ws.acknowledge = False
            from wecom_connector import bot_client as wecom_bot_client

            monkeypatch.setattr(wecom_bot_client, "CONNECT_TIMEOUT_SECONDS", 0.02)
            second_event = _webhook_body(action="edited")
            second_response = _post_webhook(
                client,
                connection_id=connection_id,
                delivery_id="delivery-e2e-2",
                body=second_event,
            )
            assert second_response.status_code == 202, second_response.text
            unknown_job = next(
                job
                for job in restarted_store.list_jobs(
                    hub.owner_principal,
                    state=JobState.READY,
                )
                if job.kind == "NOTIFY"
            )
            unknown_result = _run_job_at_persisted_due_time(
                restarted_services.dispatcher_runner,
                unknown_job,
            )
            assert unknown_result.state == "UNKNOWN"
            unknown_sends = [
                item for item in hub.wecom_ws.commands if item.get("cmd") == "aibot_send_msg"
            ]
            assert len(unknown_sends) == 2
            idle = restarted_services.dispatcher_runner.run_once(
                now=datetime.now(UTC) + timedelta(minutes=5)
            )
            assert idle.state == "IDLE"
            assert (
                len([item for item in hub.wecom_ws.commands if item.get("cmd") == "aibot_send_msg"])
                == 2
            )
            after_crash_store = IntegrationStore(integration_path)
            try:
                after_crash_runner = hub.services(after_crash_store).dispatcher_runner
                restarted_idle = after_crash_runner.run_once(
                    now=datetime.now(UTC) + timedelta(minutes=5)
                )
                assert restarted_idle.state == "IDLE"
                assert (
                    len(
                        [
                            item
                            for item in hub.wecom_ws.commands
                            if item.get("cmd") == "aibot_send_msg"
                        ]
                    )
                    == 2
                )
            finally:
                after_crash_store.close()

            hub.wecom_ws.acknowledge = True
            # Link the member's WeCom sender through an actual normalized Plugin
            # callback, Exchange's source-HMAC HTTP route, and Account Center's
            # durable challenge APIs. The reply uses the exact correlated bot
            # callback context captured by the Plugin forwarder.
            link_begin = client.post(
                "/api/v1/accounts/link-sessions",
                params={"workspaceId": _WORKSPACE},
                headers={
                    "Authorization": f"Bearer {_USER_B}",
                    "Idempotency-Key": "wecom-account-link-member",
                },
                json={"provider": "wecom"},
            )
            assert link_begin.status_code == 201, link_begin.text
            link_session = link_begin.json()
            challenge_value = link_session["callback_nonce"]
            _push_wecom_message(
                hub,
                message_id="wecom-private-link-member-1",
                sender_id="wecom-user-b",
                conversation_id="wecom-user-b",
                kind="private",
                text=f"/link {challenge_value}",
            )
            _wait_for_wecom_forwarder(hub, acked_count=1)
            challenge_reply = restarted_services.dispatcher_runner.run_once(
                now=datetime.now(UTC) + timedelta(seconds=1)
            )
            assert challenge_reply.state == "ACCEPTED"
            challenge_responses = [
                item for item in hub.wecom_ws.commands if item.get("cmd") == "aibot_respond_msg"
            ]
            assert len(challenge_responses) == 1
            challenge_reply_text = challenge_responses[0]["body"]["text"]["content"]
            marker = "Link challenge ID: "
            assert marker in challenge_reply_text
            challenge_id = challenge_reply_text.split(marker, 1)[1].split(".", 1)[0]
            assert UUID(challenge_id)
            confirmed_link = client.post(
                "/api/v1/accounts/link-sessions/wecom/confirm",
                params={"workspaceId": _WORKSPACE},
                headers={
                    "Authorization": f"Bearer {_USER_B}",
                    "Idempotency-Key": "wecom-account-link-confirm-member",
                },
                json={
                    "link_session_ref": link_session["link_session_ref"],
                    "challenge_id": challenge_id,
                    "challenge_value": challenge_value,
                },
            )
            assert confirmed_link.status_code == 200, confirmed_link.text
            linked_accounts = client.get(
                "/api/v1/accounts/links",
                params={"workspaceId": _WORKSPACE},
                headers={"Authorization": f"Bearer {_USER_B}"},
            )
            assert any(
                row.get("provider") == "wecom"
                and row.get("account_ref") == confirmed_link.json()["account_ref"]
                for row in linked_accounts.json()["links"]
            )

            # A real local Plugin callback becomes a fixed `/issue` command.
            # Exchange resolves this sender to user B, then uses only that
            # user's ActorBinding, Account Center credential and delegation.
            _push_wecom_message(
                hub,
                message_id="wecom-group-issue-command-1",
                sender_id="wecom-user-b",
                conversation_id=_WECOM_GROUP,
                kind="group",
                text="/issue comment 12 Member-authored synthetic comment",
            )
            _wait_for_wecom_forwarder(hub, acked_count=2)
            ready_commands = restarted_store.list_jobs(
                hub.member_principal,
                state=JobState.READY,
            )
            command_job = next(job for job in ready_commands if job.kind == "ISSUE_ACTION")
            operation_id = command_job.operation_id
            assert operation_id is not None
            queue_result = _run_job_at_persisted_due_time(
                restarted_services.dispatcher_runner,
                command_job,
            )
            assert queue_result.state == "AWAITING_AUTHORITY"
            member_jobs = restarted_store.list_jobs(
                hub.member_principal,
                state=JobState.AWAITING_AUTHORITY,
            )
            issue_job = next(job for job in member_jobs if job.operation_id == operation_id)
            approved = hub.authority_network.authority.invocations[
                issue_job.authority_invocation_id
            ]["approved"]
            approved_body = bytes(approved.canonical_envelope.invocation.json_body)
            assert b"Member-authored synthetic comment" not in approved_body
            stored_operation = restarted_store.get_operation(hub.member_principal, operation_id)
            assert json.loads(approved_body)["operationId"] == str(stored_operation.id), (
                stored_operation,
                approved_body,
            )
            proof_headers = {
                "x-cyrene-execution-credential-bin": base64.b64encode(
                    approved.credential.SerializeToString(deterministic=True)
                ).decode("ascii"),
                "Idempotency-Key": approved.canonical_envelope.target.idempotency_key,
                "Content-Type": "application/json",
            }
            execution_path = approved.canonical_envelope.target.endpoint

            tampered = client.post(
                execution_path,
                headers=proof_headers,
                content=canonical_json(
                    {"operationId": str(operation_id), "argumentDigest": "0" * 64}
                ),
            )
            assert tampered.status_code == 403
            assert hub.github_http.comments == []

            expected_body = approved_body
            completed = client.post(
                execution_path,
                headers=proof_headers,
                content=expected_body,
            )
            assert completed.status_code == 200, completed.text
            operation = restarted_store.get_operation(hub.member_principal, operation_id)
            assert operation.state.value == "SUCCEEDED"
            assert operation.result["status"] == "CONFIRMED"
            assert hub.github_http.comments == ["Member-authored synthetic comment"]
            assert operation.source_kind == "WECOM_COMMAND", operation
            assert all(
                (
                    operation.source_event_ref,
                    operation.reply_binding_ref,
                    operation.reply_sender_id,
                    operation.reply_conversation_ref,
                    operation.reply_message_id,
                    operation.reply_context_ref,
                )
            ), operation
            ready_replies = restarted_store.list_jobs(
                hub.member_principal,
                state=JobState.READY,
            )
            assert any(job.kind == "COMMAND_REPLY" for job in ready_replies), ready_replies
            reply_job = next(job for job in ready_replies if job.kind == "COMMAND_REPLY")
            result_reply = _run_job_at_persisted_due_time(
                restarted_services.dispatcher_runner,
                reply_job,
            )
            assert result_reply.state == "ACCEPTED"
            command_replies = [
                item for item in hub.wecom_ws.commands if item.get("cmd") == "aibot_respond_msg"
            ]
            assert len(command_replies) == 2
            assert (
                "Comment on cyrene/e2e#12 was confirmed."
                in command_replies[-1]["body"]["text"]["content"]
            )
            assert {call[2] for call in hub.github_http.calls} >= {
                "/repos/cyrene/e2e",
                "/repos/cyrene/e2e/issues/12/comments",
            }
            assert all(
                call[0] == "POST" or call[1] == "api.github.com" for call in hub.github_http.calls
            )
            # The configured GitHub API transport enforced the member account's
            # user-token ACL; the connection creator's credential would fail.
            assert set(hub.github_http.tokens) == {"Bearer synthetic-member-code-token"}

            # The execution credential is accepted only over the registered mTLS
            # workload identity. A different profile and a revoked grant both
            # fail before GitHub sees another request.
            wrong_profile = PlatformExecutionAuthorizationVerifier(
                target=hub.authority_network.workload_target,
                root_certificates=hub.tls_files.ca.read_bytes(),
                private_key=hub.tls_files.other_client_key.read_bytes(),
                certificate_chain=hub.tls_files.other_client_cert.read_bytes(),
            )
            original_verifier = restarted_services.execution_authorization_verifier
            restarted_services.execution_authorization_verifier = wrong_profile
            denied_profile = client.post(
                execution_path,
                headers=proof_headers,
                content=expected_body,
            )
            assert denied_profile.status_code == 403
            restarted_services.execution_authorization_verifier = original_verifier

            issue_call_count = len(hub.github_http.calls)
            revoke_channel = grpc.insecure_channel(f"unix://{hub.authority_network.socket_path}")
            try:
                authority_grpc.WorkspaceAuthorityServiceStub(revoke_channel).RevokeDelegation(
                    authority_wire.RevokeDelegationRequest(
                        workspace_id=_WORKSPACE,
                        delegation_id=member_grant,
                    ),
                    timeout=2,
                    metadata=(("authorization", f"Bearer {_USER_B}"),),
                )
            finally:
                revoke_channel.close()
            revoked = client.post(execution_path, headers=proof_headers, content=expected_body)
            assert revoked.status_code == 403
            assert len(hub.github_http.calls) == issue_call_count

            # The ActorBinding projection is actor-scoped; the connection creator
            # has no fallback access to the member's grant or external account.
            owner_action = client.post(
                f"/api/v1/integrations/sync-bindings/{binding_id}/issues/actions/comment",
                params={"workspaceId": _WORKSPACE},
                headers={
                    "Authorization": f"Bearer {_USER_A}",
                    "Idempotency-Key": "creator-fallback-attempt",
                },
                json={"issueNumber": 12, "body": "must not fallback"},
            )
            assert owner_action.status_code == 202
            assert (
                restarted_services.dispatcher_runner.run_once().state
                == JobState.AWAITING_AUTHORITY.value
            )
            # The owner delegation is separately scoped and has its own link;
            # the revoked member link is never substituted for the creator.
            owner_job = next(
                job
                for job in restarted_store.list_jobs(hub.owner_principal)
                if job.operation_id == UUID(owner_action.json()["operationId"])
            )
            assert owner_job.authority_invocation_id is not None

        assert hub.oauth_http.requests
        assert all(
            request[1].startswith(("https://github.com/", "https://api.github.com/"))
            for request in hub.oauth_http.requests
        )
        assert len(hub.oauth_http.forms) == 2
        verifiers = []
        for form in hub.oauth_http.forms:
            verifier = form["code_verifier"][0]
            assert 43 <= len(verifier) <= 128
            assert form["redirect_uri"] == ["https://exchange.example.test/callback"]
            verifiers.append(verifier.encode("ascii"))
        private_db = tmp_path / "private-account-center.sqlite3"
        db_bytes = private_db.read_bytes()
        assert b"synthetic-member-code-token" not in db_bytes
        assert b"synthetic-owner-code-token" not in db_bytes
        assert all(verifier not in db_bytes for verifier in verifiers)
        assert model_requests == []
    finally:
        if restarted_app is not None:
            restarted_app.state.exchange_store.close()
        if restarted_store is not None:
            restarted_store.close()
        if not initial_exchange_store_closed:
            app.state.exchange_store.close()
        if store is not None:
            store.close()
        hub.stop_plugins()
        hub.authority_network.stop()
