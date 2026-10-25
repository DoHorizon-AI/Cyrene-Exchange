"""HMAC and fixed-capability adapter tests with synthetic identities and payloads."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from concurrent import futures
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from cyrene_plugin_runtime import DirectPayload
from google.protobuf.timestamp_pb2 import Timestamp

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations._generated.cyrene.message.connector.v1 import (
    message_connector_pb2 as message_wire,
)
from cyrene_exchange_product.integrations._generated.cyrene.tool.provider.v1 import (
    tool_provider_pb2 as tool_wire,
)
from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
    workspace_authority_pb2 as authority_wire,
)
from cyrene_exchange_product.integrations.auth import (
    AccountCenterRequestSigner,
    IntegrationPrincipal,
    canonical_json,
)
from cyrene_exchange_product.integrations.clients import (
    COMPUTER_TOOL_IDS,
    GITHUB_TOOL_IDS,
    AccountCenterClient,
    ComputerRunnerClient,
    GitHubIssuesClient,
    GitHubWebhookClient,
    PlatformAuthorityDelegationClient,
    TeamsMessageClient,
    WeComMessageClient,
    _computer_structured_tool_json,
    _decode_computer_provider_result,
    _decode_tool_result,
)


class _DirectClient:
    def __init__(self, responses: list[DirectPayload]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> DirectPayload:
        self.calls.append(kwargs)
        return self.responses.pop(0)


def _principal() -> IntegrationPrincipal:
    return IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="user-7",
        organization_id="org-2",
        workspace_id="workspace-9",
        allowed_operation_ids=frozenset({"accountBeginLink", "github.issue.get"}),
    )


def test_account_center_hmac_binds_method_payload_anchor_and_binding() -> None:
    signer = AccountCenterRequestSigner(caller_id="exchange-service", key=b"s" * 32)
    payload = {"provider": "github", "workspace_id": "workspace-9"}
    context = signer.sign(
        principal=_principal(),
        binding_id="account-center-binding",
        operation_id="begin_link",
        payload=payload,
        request_id="7cc940c4-516b-431b-a03b-4e78426e42ab",
        now=datetime(2026, 10, 12, tzinfo=UTC),
    )
    signed = context.as_payload()
    signature = signed.pop("signature")

    assert signed["payload_sha256"] == hashlib.sha256(canonical_json(payload)).hexdigest()
    expected = hmac.new(b"s" * 32, canonical_json(signed), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, expected)
    assert "roles" not in signed
    assert signed["binding_id"] == "account-center-binding"

    changed_payload = {**payload, "provider": "wecom"}
    assert hashlib.sha256(canonical_json(changed_payload)).hexdigest() != signed["payload_sha256"]


def test_account_center_direct_call_uses_fixed_method_and_signed_context() -> None:
    response_type = "type.googleapis.com/cyrene.account.center.v1.BeginLinkResponse"
    transport = _DirectClient([DirectPayload(response_type, b'{"link_session_ref":"opaque"}')])
    signer = AccountCenterRequestSigner(caller_id="exchange-service", key=b"a" * 32)
    account_client = AccountCenterClient(
        transport,
        exchange_signer=signer,
        binding_id="account-center-binding",
    )

    result = account_client.begin_link(
        _principal(),
        provider="github",
        workspace_id="workspace-9",
        idempotency_key="link-123",
    )
    call = transport.calls[0]
    envelope = json.loads(call["request"].value)
    context = envelope["trusted_context"]
    unsigned = {key: value for key, value in context.items() if key != "signature"}

    assert result == {"link_session_ref": "opaque"}
    assert call["capability"] == "account.center.v1"
    assert call["interface_version"] == "1"
    assert call["method"] == "begin_link"
    assert envelope["payload"] == {
        "provider": "github",
        "workspace_id": "workspace-9",
        "idempotency_key": "link-123",
    }
    assert context["operation_id"] == "begin_link"
    assert context["binding_id"] == "account-center-binding"
    assert hmac.compare_digest(
        context["signature"],
        hmac.new(b"a" * 32, canonical_json(unsigned), hashlib.sha256).hexdigest(),
    )


@pytest.mark.parametrize(
    ("domain_code", "message", "expected_code", "expected_status"),
    [
        (
            "PERMISSION_DENIED",
            "connector_grant_replayed",
            "EXCHANGE_CONNECTOR_REQUEST_REPLAYED",
            409,
        ),
        (
            "PERMISSION_DENIED",
            "authorization_denied",
            "EXCHANGE_ACCOUNT_CENTER_AUTHORIZATION_DENIED",
            403,
        ),
        (
            "INVALID_REQUEST",
            "invalid_request",
            "EXCHANGE_ACCOUNT_CENTER_REQUEST_INVALID",
            422,
        ),
    ],
)
def test_account_center_denials_are_not_reported_as_retryable_outages(
    domain_code: str,
    message: str,
    expected_code: str,
    expected_status: int,
) -> None:
    class DirectFailure(RuntimeError):
        def __init__(self) -> None:
            super().__init__(message)
            self.domain_code = domain_code
            self.message = message

    class FailingDirectClient:
        def invoke(self, **_kwargs: Any) -> Any:
            raise DirectFailure()

    client = AccountCenterClient(
        FailingDirectClient(),  # type: ignore[arg-type]
        exchange_signer=AccountCenterRequestSigner(caller_id="exchange-service", key=b"a" * 32),
        binding_id="account-center-binding",
    )

    with pytest.raises(ExchangeProductError) as captured:
        client.begin_link(
            _principal(),
            provider="github",
            workspace_id="workspace-9",
            idempotency_key="connector-denial-test",
        )

    assert captured.value.code == expected_code
    assert captured.value.status == expected_status
    assert captured.value.retryable is False
    assert message not in captured.value.detail


def test_linked_sender_lookup_uses_exchange_role_with_configured_tenant_scope() -> None:
    response_type = "type.googleapis.com/cyrene.account.center.v1.ResolveLinkedSenderResponse"
    transport = _DirectClient([DirectPayload(response_type, b'{"linked":false}')])
    account_client = AccountCenterClient(
        transport,
        exchange_signer=AccountCenterRequestSigner(caller_id="exchange-caller", key=b"e" * 32),
        wecom_source_signer=AccountCenterRequestSigner(
            caller_id="wecom-source-caller", key=b"w" * 32
        ),
        binding_id="account-center-binding",
    )
    source_principal = IntegrationPrincipal(
        issuer="urn:cyrene:wecom-source",
        subject="exchange-wecom-source:binding-1",
        organization_id="org-source",
        workspace_id="workspace-source",
        allowed_operation_ids=frozenset(),
    )

    assert account_client.resolve_linked_sender(
        source_principal,
        source_authority="wecom.example",
        bot_namespace="bot-1",
        stable_subject="sender-1",
    ) == {"linked": False}
    call = transport.calls[0]
    context = json.loads(call["request"].value)["trusted_context"]
    unsigned = {key: value for key, value in context.items() if key != "signature"}
    assert call["method"] == "resolve_linked_sender"
    assert context["caller_id"] == "exchange-caller"
    assert context["issuer"] == "urn:cyrene:exchange-service"
    assert context["subject"] == "exchange-wecom-link-resolver"
    assert context["organization_id"] == "org-source"
    assert context["workspace_id"] == "workspace-source"
    assert hmac.compare_digest(
        context["signature"],
        hmac.new(b"e" * 32, canonical_json(unsigned), hashlib.sha256).hexdigest(),
    )


def test_github_tool_call_signs_fixed_tool_and_exact_public_args() -> None:
    response = tool_wire.CallToolResponse(
        outcome=tool_wire.ToolCallOutcome(
            content=[
                tool_wire.ToolContentPart(
                    json=tool_wire.ToolJsonContent(
                        json='{"issue_id":"42","number":42,"state":"OPEN","title":"Example"}'
                    )
                )
            ],
            is_error=False,
        )
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse",
                response.SerializeToString(deterministic=True),
            )
        ]
    )
    client = GitHubIssuesClient(
        transport,
        signer=AccountCenterRequestSigner(caller_id="exchange-service", key=b"g" * 32),
        binding_id="github-provider-binding",
    )

    result = client.get_issue(
        _principal(),
        lease_ref="5e58f013-b7a5-4817-90d8-50c8a7aa9aa5",
        repository_id="repo-17",
        repository="owner/repository",
        issue_number=42,
    )
    call = transport.calls[0]
    call_request = tool_wire.CallToolRequest.FromString(call["request"].value)
    tool_envelope = json.loads(call_request.arguments_json)
    context = tool_envelope["trusted_context"]
    unsigned = {key: value for key, value in context.items() if key != "signature"}
    signed_payload = {"payload": tool_envelope["payload"], "lease_ref": tool_envelope["lease_ref"]}

    assert result["issue_id"] == "42"
    assert call["capability"] == "tool.provider.v1"
    assert call["method"] == "call_tool"
    assert call_request.binding_id == "github-provider-binding"
    assert call_request.provider_tool_id == "github.issue.get"
    assert tool_envelope["payload"] == {
        "repository_id": "repo-17",
        "repository": "owner/repository",
        "issue_number": 42,
    }
    assert context["payload_sha256"] == hashlib.sha256(canonical_json(signed_payload)).hexdigest()
    assert hmac.compare_digest(
        context["signature"],
        hmac.new(b"g" * 32, canonical_json(unsigned), hashlib.sha256).hexdigest(),
    )


def test_github_proactive_tool_call_uses_the_existing_provider_capability() -> None:
    """New GitHub operations use the same signed tool.provider.v1 call envelope."""

    response = tool_wire.CallToolResponse(
        outcome=tool_wire.ToolCallOutcome(
            content=[
                tool_wire.ToolContentPart(
                    json=tool_wire.ToolJsonContent(json='{"status":"CREATED","verified":true}')
                )
            ],
            is_error=False,
        )
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse",
                response.SerializeToString(deterministic=True),
            )
        ]
    )
    client = GitHubIssuesClient(
        transport,
        signer=AccountCenterRequestSigner(caller_id="exchange-service", key=b"g" * 32),
        binding_id="github-provider-binding",
    )
    arguments = {
        "repository_id": "42",
        "repository": "acme/demo",
        "branch": "task/assistant-v1",
        "from_sha": "a" * 40,
    }
    assert {
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
    } <= GITHUB_TOOL_IDS

    result = client.call_provider_tool(
        _principal(),
        tool_id="github.branch.create",
        profile_ref="github-app-profile",
        lease_ref="provider-lease-ref",
        payload=arguments,
    )

    call = transport.calls[0]
    request = tool_wire.CallToolRequest.FromString(call["request"].value)
    envelope = json.loads(request.arguments_json)
    assert result == {"status": "CREATED", "verified": True}
    assert call["capability"] == "tool.provider.v1"
    assert call["method"] == "call_tool"
    assert request.provider_tool_id == "github.branch.create"
    assert envelope["profile_ref"] == "github-app-profile"
    assert envelope["lease_ref"] == "provider-lease-ref"
    assert envelope["payload"] == arguments


@pytest.mark.parametrize(("exit_code", "tool_error"), [(0, False), (2, True)])
def test_computer_runner_call_passes_only_typed_args_over_the_fixed_plugin_binding(
    exit_code: int, tool_error: bool
) -> None:
    """No model profile, account lease, or other identity field reaches the runner."""

    result_value = {
        "exit_code": exit_code,
        "duration_ms": 9,
        "stdout": "done",
        "stderr": "" if exit_code == 0 else "failed",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "sha256_hash": "a" * 64,
        "resource_usage": None,
    }
    response = tool_wire.CallToolResponse(
        outcome=tool_wire.ToolCallOutcome(
            content=[
                tool_wire.ToolContentPart(
                    json=tool_wire.ToolJsonContent(
                        json=json.dumps(result_value, separators=(",", ":"))
                    )
                )
            ],
            is_error=tool_error,
        )
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse",
                response.SerializeToString(deterministic=True),
            )
        ]
    )
    client = ComputerRunnerClient(transport, binding_id="computer-runtime")
    arguments = {"command": "printf done", "cwd": ".", "timeout_ms": 1_000}

    result = client.call_provider_tool(
        tool_id="computer.command.execute",
        payload=arguments,
    )

    call = transport.calls[0]
    request = tool_wire.CallToolRequest.FromString(call["request"].value)
    assert call["capability"] == "tool.provider.v1"
    assert call["method"] == "call_tool"
    assert request.binding_id == "computer-runtime"
    assert request.provider_tool_id == "computer.command.execute"
    assert request.arguments_json == canonical_json(arguments).decode("utf-8")
    assert set(json.loads(request.arguments_json)) == {"command", "cwd", "timeout_ms"}
    assert set(COMPUTER_TOOL_IDS) == {
        "computer.command.execute",
        "computer.file.read",
        "computer.file.write",
        "computer.directory.list",
    }
    assert result["status"] == ("COMMAND_COMPLETED" if exit_code == 0 else "COMMAND_FAILED")
    assert result["isError"] is (exit_code != 0)


def test_computer_file_write_rejects_unconfirmed_byte_count() -> None:
    """A provider response cannot claim a complete file write with a partial count."""

    response = tool_wire.CallToolResponse(
        outcome=tool_wire.ToolCallOutcome(
            content=[
                tool_wire.ToolContentPart(
                    json=tool_wire.ToolJsonContent(json='{"bytes_written":0}')
                )
            ]
        )
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse",
                response.SerializeToString(deterministic=True),
            )
        ]
    )
    client = ComputerRunnerClient(transport, binding_id="computer-runtime")

    with pytest.raises(ExchangeProductError, match="expected number of written bytes"):
        client.call_provider_tool(
            tool_id="computer.file.write",
            payload={"path": "src/file.txt", "content_base64": "YQ==", "overwrite": True},
        )


def test_computer_file_read_size_matches_returned_chunk() -> None:
    """The read receipt reports the bytes in this bounded chunk, not file size."""

    def client_for(result: dict[str, Any]) -> ComputerRunnerClient:
        response = tool_wire.CallToolResponse(
            outcome=tool_wire.ToolCallOutcome(
                content=[
                    tool_wire.ToolContentPart(
                        json=tool_wire.ToolJsonContent(json=json.dumps(result))
                    )
                ]
            )
        )
        return ComputerRunnerClient(
            _DirectClient(
                [
                    DirectPayload(
                        "type.cyrene.io/cyrene.tool.provider.v1.CallToolResponse",
                        response.SerializeToString(deterministic=True),
                    )
                ]
            ),
            binding_id="computer-runtime",
        )

    result = client_for({"size_bytes": 3, "content_text": "abc"}).call_provider_tool(
        tool_id="computer.file.read",
        payload={"path": "src/file.txt", "length": 3},
    )
    assert result["size_bytes"] == 3
    assert result["content_text"] == "abc"

    with pytest.raises(ExchangeProductError, match="does not match"):
        client_for({"size_bytes": 4, "content_text": "abc"}).call_provider_tool(
            tool_id="computer.file.read",
            payload={"path": "src/file.txt", "length": 3},
        )


def test_computer_response_is_bounded_before_protobuf_decode() -> None:
    """Reject an oversized private runner response before parsing its protobuf body."""

    with pytest.raises(ExchangeProductError, match="bounded transport size"):
        _decode_computer_provider_result(
            b"x" * 1_000_001,
            tool_id="computer.command.execute",
        )


def test_computer_provider_result_rejects_duplicate_json_members() -> None:
    """Duplicate provider fields cannot bypass closed result checks."""

    content = [
        tool_wire.ToolContentPart(
            json=tool_wire.ToolJsonContent(json='{"bytes_written":1,"bytes_written":2}')
        )
    ]
    with pytest.raises(ValueError, match="malformed structured JSON"):
        _computer_structured_tool_json(content)


def test_provider_context_expires_within_short_operation_window() -> None:
    signer = AccountCenterRequestSigner(caller_id="exchange-service", key=b"e" * 32)
    context = signer.sign_provider_call(
        principal=_principal(),
        binding_id="github-provider-binding",
        operation_id="github.issue.get",
        method="call_tool",
        payload={"payload": {"issue_number": 42}, "lease_ref": "opaque"},
        now=datetime(2026, 10, 12, tzinfo=UTC),
    )
    assert timedelta(seconds=context.expires_at - context.issued_at) == timedelta(seconds=30)


def test_wecom_challenge_reply_uses_canonical_typed_reply_reference() -> None:
    delivery = message_wire.DeliveryResult(
        status=message_wire.DELIVERY_STATUS_ACCEPTED,
        vendor_message_id="vendor-accepted-id",
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.message.connector.v1.DeliveryResult",
                delivery.SerializeToString(deterministic=True),
            )
        ]
    )
    client = WeComMessageClient(
        transport,
        targets={
            "challenge-target": {
                "bot_id": "wecom-bot-7",
                "conversation_id": "group-1",
                "kind": "GROUP",
            }
        },
        source_accounts={
            "binding-7": {
                "account_id": "bot:wecom-bot-7",
                "group_conversation_id": "group-1",
            }
        },
    )

    evidence = client.send_wecom_challenge_reply(
        source_binding_id="binding-7",
        sender_id="member-5",
        conversation_ref="private:member-5",
        reply_message_id="vendor-message-5",
        reply_context_ref="openws-req-5",
        text="challenge-5",
        idempotency_key="challenge-reply-5",
    )

    call = transport.calls[0]
    request = message_wire.SendMessageRequest.FromString(call["request"].value)
    assert call["capability"] == "message.connector.v1"
    assert call["method"] == "send_message"
    assert request.conversation.vendor == "wecom.bot"
    assert request.conversation.account_id == "bot:wecom-bot-7"
    assert request.conversation.conversation_id == "member-5"
    assert request.conversation.kind == message_wire.CONVERSATION_KIND_PRIVATE
    assert request.content[0].text.text == "challenge-5"
    assert request.reply.message_id == "vendor-message-5"
    assert not request.vendor_extension.facts
    assert evidence.accepted is True
    assert evidence.vendor_message_id == "vendor-accepted-id"
    assert evidence.transport_request_id is None


def test_query_only_delegation_is_accepted_but_unexpected_scope_is_rejected() -> None:
    from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
        workspace_authority_pb2 as authority_wire,
    )

    class _Identity:
        def __init__(self, delegation: Any) -> None:
            self.delegation = delegation

        def get_delegation(self, **_: Any) -> Any:
            return self.delegation

    expires = Timestamp()
    expires.FromDatetime(datetime.now(UTC) + timedelta(hours=1))
    delegation = authority_wire.GetDelegationResponse(
        organization_id="org-2",
        workspace_id="workspace-9",
        principal_issuer="https://issuer.example",
        principal_subject="user-7",
        audience="exchange-issues",
        managed_workload_id="exchange-product",
        expires_at=expires,
        revoked=False,
        operations=[
            authority_wire.DelegatedOperationScope(
                owner_id="exchange",
                operation_id="integrationExecuteIssueQuery",
                resource_ids=[str(UUID("59342603-8cd9-41d4-b271-5d4171f0e5f9"))],
            )
        ],
    )
    client = PlatformAuthorityDelegationClient.__new__(PlatformAuthorityDelegationClient)
    client._identity_verifier = _Identity(delegation)
    client._audience = "exchange-issues"
    client._workload_id = "exchange-product"
    client.validate_binding(
        _principal(),
        bearer_token="verified-bearer",
        delegation_ref="delegation-1",
        binding_id=UUID("59342603-8cd9-41d4-b271-5d4171f0e5f9"),
        account_link_ref="opaque-account-ref",
    )

    delegation.operations.append(
        authority_wire.DelegatedOperationScope(
            owner_id="exchange",
            operation_id="integrationExecuteIssueQuery",
            resource_ids=[str(UUID("59342603-8cd9-41d4-b271-5d4171f0e5f9"))],
        )
    )
    with pytest.raises(PermissionError):
        client.validate_binding(
            _principal(),
            bearer_token="verified-bearer",
            delegation_ref="delegation-1",
            binding_id=UUID("59342603-8cd9-41d4-b271-5d4171f0e5f9"),
            account_link_ref="opaque-account-ref",
        )


def test_product_execution_credential_reads_self_grant_over_workload_mtls() -> None:
    from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
        workspace_authority_pb2 as authority_wire,
    )

    binding_id = UUID("59342603-8cd9-41d4-b271-5d4171f0e5f9")
    expires = Timestamp()
    expires.FromDatetime(datetime.now(UTC) + timedelta(hours=1))
    delegation = authority_wire.GetDelegationResponse(
        delegation_id="delegation-1",
        organization_id="org-2",
        workspace_id="workspace-9",
        principal_issuer="https://issuer.example",
        principal_subject="user-7",
        audience="exchange-issues",
        managed_workload_id="exchange-product",
        expires_at=expires,
        revoked=False,
        operations=[
            authority_wire.DelegatedOperationScope(
                owner_id="exchange",
                operation_id="integrationExecuteIssueQuery",
                resource_ids=[str(binding_id)],
            )
        ],
    )
    credential = authority_wire.ExecutionCredential(invocation_id="approved-attach")

    class _Stub:
        def __init__(self) -> None:
            self.request: Any = None

        def NegotiateVersion(self, request: Any, *, timeout: float) -> Any:
            del request, timeout
            return authority_wire.NegotiateVersionResponse(selected_version=2)

        def GetDelegation(self, request: Any, *, timeout: float) -> Any:
            del timeout
            self.request = request
            return delegation

    class _Channel:
        def __init__(self, stub: _Stub) -> None:
            self.stub = stub

        def __enter__(self) -> _Stub:
            return self.stub

        def __exit__(self, *_args: Any) -> None:
            return None

    stub = _Stub()
    client = PlatformAuthorityDelegationClient.__new__(PlatformAuthorityDelegationClient)
    client._identity_verifier = object()
    client._audience = "exchange-issues"
    client._workload_id = "exchange-product"
    client._deadline_seconds = 3.0
    client._workload_stub = lambda: _Channel(stub)  # type: ignore[method-assign]

    client.validate_binding(
        _principal(),
        bearer_token=None,
        execution_credential=credential.SerializeToString(deterministic=True),
        delegation_ref="delegation-1",
        binding_id=binding_id,
        account_link_ref="opaque-account-ref",
    )

    assert stub.request.workspace_id == "workspace-9"
    assert stub.request.delegation_id == "delegation-1"
    assert stub.request.execution_credential.SerializeToString(deterministic=True) == (
        credential.SerializeToString(deterministic=True)
    )


def _make_backdated_mtls_files(tmp_path: Path) -> dict[str, Path]:
    """Create short-lived local TLS identities whose validity starts before test time."""

    ca_key = tmp_path / "ca.key"
    ca_request = tmp_path / "ca.csr"
    ca_certificate = tmp_path / "ca.crt"
    database = tmp_path / "ca-index.txt"
    serial = tmp_path / "ca-serial"
    new_certs = tmp_path / "new-certs"
    new_certs.mkdir()
    database.write_text("", encoding="ascii")
    serial.write_text("1000\n", encoding="ascii")
    config = tmp_path / "ca.cnf"
    config.write_text(
        "\n".join(
            (
                "[ ca ]",
                "default_ca = CA_default",
                "[ CA_default ]",
                f"database = {database}",
                f"serial = {serial}",
                f"new_certs_dir = {new_certs}",
                f"certificate = {ca_certificate}",
                f"private_key = {ca_key}",
                "default_md = sha256",
                "policy = policy_any",
                "[ policy_any ]",
                "commonName = supplied",
                "[ v3_ca ]",
                "subjectKeyIdentifier = hash",
                "authorityKeyIdentifier = keyid:always",
                "basicConstraints = critical,CA:true",
                "keyUsage = critical,keyCertSign,cRLSign",
                "[ server_ext ]",
                "subjectAltName = IP:127.0.0.1",
                "extendedKeyUsage = serverAuth",
                "basicConstraints = critical,CA:false",
                "keyUsage = critical,digitalSignature,keyEncipherment",
                "[ client_ext ]",
                "extendedKeyUsage = clientAuth",
                "basicConstraints = critical,CA:false",
                "keyUsage = critical,digitalSignature,keyEncipherment",
            )
        )
        + "\n",
        encoding="ascii",
    )

    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    openssl("genrsa", "-out", str(ca_key), "2048")
    openssl("req", "-new", "-key", str(ca_key), "-out", str(ca_request), "-subj", "/CN=test-ca")
    now = datetime.now(UTC)
    start = (now - timedelta(minutes=5)).strftime("%y%m%d%H%M%SZ")
    end = (now + timedelta(days=1)).strftime("%y%m%d%H%M%SZ")
    openssl(
        "ca",
        "-batch",
        "-selfsign",
        "-config",
        str(config),
        "-in",
        str(ca_request),
        "-keyfile",
        str(ca_key),
        "-out",
        str(ca_certificate),
        "-startdate",
        start,
        "-enddate",
        end,
        "-extensions",
        "v3_ca",
    )

    def signed_leaf(name: str, common_name: str, extension: str) -> tuple[Path, Path]:
        key = tmp_path / f"{name}.key"
        request = tmp_path / f"{name}.csr"
        certificate = tmp_path / f"{name}.crt"
        openssl(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(request),
            "-subj",
            f"/CN={common_name}",
        )
        openssl(
            "ca",
            "-batch",
            "-config",
            str(config),
            "-in",
            str(request),
            "-cert",
            str(ca_certificate),
            "-keyfile",
            str(ca_key),
            "-out",
            str(certificate),
            "-startdate",
            start,
            "-enddate",
            end,
            "-extensions",
            extension,
        )
        return certificate, key

    server_cert, server_key = signed_leaf("authority-server", "localhost", "server_ext")
    client_cert, client_key = signed_leaf("exchange-product", "exchange-product", "client_ext")
    return {
        "ca": ca_certificate,
        "server_cert": server_cert,
        "server_key": server_key,
        "client_cert": client_cert,
        "client_key": client_key,
    }


def test_signed_self_grant_lookup_uses_real_product_mtls_channel(tmp_path: Path) -> None:
    import grpc

    from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
        workspace_authority_pb2 as authority_wire,
    )
    from cyrene_exchange_product.integrations._generated.cyrene.workspace.authority.v2 import (
        workspace_authority_pb2_grpc as authority_grpc,
    )

    tls_files = _make_backdated_mtls_files(tmp_path)
    binding_id = UUID("59342603-8cd9-41d4-b271-5d4171f0e5f9")
    credential = authority_wire.ExecutionCredential(invocation_id="approved-attach")
    expires = Timestamp()
    expires.FromDatetime(datetime.now(UTC) + timedelta(hours=1))
    delegation = authority_wire.GetDelegationResponse(
        delegation_id="delegation-1",
        organization_id="org-2",
        workspace_id="workspace-9",
        principal_issuer="https://issuer.example",
        principal_subject="user-7",
        audience="exchange-issues",
        managed_workload_id="exchange-product",
        expires_at=expires,
        operations=[
            authority_wire.DelegatedOperationScope(
                owner_id="exchange",
                operation_id="integrationExecuteIssueQuery",
                resource_ids=[str(binding_id)],
            )
        ],
    )
    observed_auth_contexts: list[Any] = []

    class _Authority(authority_grpc.WorkspaceAuthorityServiceServicer):
        def NegotiateVersion(self, request: Any, context: Any) -> Any:
            del request, context
            return authority_wire.NegotiateVersionResponse(selected_version=2)

        def GetDelegation(self, request: Any, context: Any) -> Any:
            metadata = {item.key: item.value for item in context.invocation_metadata()}
            assert "authorization" not in metadata
            assert request.workspace_id == "workspace-9"
            assert request.delegation_id == "delegation-1"
            assert request.execution_credential.SerializeToString(deterministic=True) == (
                credential.SerializeToString(deterministic=True)
            )
            observed_auth_contexts.append(context.auth_context())
            return delegation

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    authority_grpc.add_WorkspaceAuthorityServiceServicer_to_server(_Authority(), server)
    server_credentials = grpc.ssl_server_credentials(
        ((tls_files["server_key"].read_bytes(), tls_files["server_cert"].read_bytes()),),
        root_certificates=tls_files["ca"].read_bytes(),
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", server_credentials)
    assert port > 0
    server.start()

    client = PlatformAuthorityDelegationClient(
        identity_verifier=object(),  # type: ignore[arg-type]
        target=f"grpcs://127.0.0.1:{port}",
        root_certificates_path=tls_files["ca"],
        private_key_path=tls_files["client_key"],
        certificate_chain_path=tls_files["client_cert"],
        workload_id="exchange-product",
        audience="exchange-issues",
    )
    try:
        client.validate_binding(
            _principal(),
            bearer_token=None,
            execution_credential=credential.SerializeToString(deterministic=True),
            delegation_ref="delegation-1",
            binding_id=binding_id,
            account_link_ref="opaque-account-ref",
        )
        assert observed_auth_contexts and observed_auth_contexts[0]
    finally:
        server.stop(0).wait()


def test_connector_authority_client_calls_only_dedicated_rpc() -> None:
    """Connector-only Authority stub has one RPC and receives no version probe."""

    service = authority_wire.DESCRIPTOR.services_by_name["WorkspaceConnectorAuthorizationService"]
    assert [method.name for method in service.methods] == ["AuthorizeConnectorOperation"]

    class _Stub:
        def __init__(self) -> None:
            self.request: Any = None
            self.calls = 0

        def AuthorizeConnectorOperation(self, request: Any, *, timeout: float) -> Any:
            assert timeout == 3.0
            self.request = request
            self.calls += 1
            return authority_wire.AuthorizeConnectorOperationResponse(
                grant=authority_wire.ConnectorOperationGrantV1(grant_ref="sha256:" + "1" * 64)
            )

    class _Channel:
        def __init__(self, stub: _Stub) -> None:
            self.stub = stub

        def __enter__(self) -> _Stub:
            return self.stub

        def __exit__(self, *_args: Any) -> None:
            return None

    stub = _Stub()
    client = PlatformAuthorityDelegationClient.__new__(PlatformAuthorityDelegationClient)
    client._deadline_seconds = 3.0

    def _connector_stub(*, connector_only: bool) -> _Channel:
        assert connector_only is True
        return _Channel(stub)

    client._workload_stub = _connector_stub  # type: ignore[method-assign]
    encoded = client.authorize_connector_operation(
        workspace_id="workspace-9",
        principal_issuer="https://login.microsoftonline.com/tenant/v2.0",
        principal_subject="11111111-1111-4111-8111-111111111111",
        connection_ref="9dca6ec0-4874-4d09-8e37-c3f4718e619c",
        provider_id="github",
        profile_ref="gh-profile-1",
        operation_id="github.repository.list",
        resource_ref="sha256:" + "2" * 64,
        arguments_digest_sha256=b"\x03" * 32,
        request_id="request-1",
    )
    assert stub.calls == 1
    assert stub.request.operation_id == "github.repository.list"
    assert b"sha256:" in encoded


def test_github_explicit_acl_denial_is_a_known_rejection() -> None:
    response = tool_wire.CallToolResponse(
        outcome=tool_wire.ToolCallOutcome(
            is_error=True,
            content=[
                tool_wire.ToolContentPart(
                    json=tool_wire.ToolJsonContent(
                        json='{"error":{"code":"AUTHORIZATION_DENIED","retryable":false}}'
                    )
                )
            ],
        )
    )
    assert _decode_tool_result(
        response.SerializeToString(deterministic=True),
        tool_id="github.issue.comment.create",
    ) == {"status": "REJECTED", "reason_code": "AUTHORIZATION_DENIED"}


def test_wecom_explicit_rejected_ack_has_no_fabricated_receipt_ids() -> None:
    delivery = message_wire.DeliveryResult(
        status=message_wire.DELIVERY_STATUS_REJECTED,
        vendor_message_id="must-not-be-trusted",
        vendor_extension=message_wire.VendorExtension(
            facts=[message_wire.VendorFact(name="transport_request_id", value="not-accepted")]
        ),
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.message.connector.v1.DeliveryResult",
                delivery.SerializeToString(deterministic=True),
            )
        ]
    )
    client = WeComMessageClient(
        transport,
        targets={"notify": {"bot_id": "bot-1", "conversation_id": "group-1", "kind": "GROUP"}},
    )
    evidence = client.send_notification(
        target_ref="notify",
        text="status",
        idempotency_key="send-1",
    )
    assert evidence.accepted is False
    assert evidence.vendor_message_id is None
    assert evidence.transport_request_id is None


def test_teams_reply_forwards_validated_regional_service_url() -> None:
    delivery = message_wire.DeliveryResult(
        status=message_wire.DELIVERY_STATUS_ACCEPTED,
        vendor_message_id="message-1",
    )
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.message.connector.v1.DeliveryResult",
                delivery.SerializeToString(deterministic=True),
            )
        ]
    )
    client = TeamsMessageClient(transport)
    service_url = "https://smba.trafficmanager.net/emea/"
    evidence = client.send_reply(
        bot_app_id="00000000-0000-4000-8000-000000000003",
        tenant_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        team_id="team-1",
        channel_id="channel-1",
        conversation_id="19:channel-conversation",
        root_thread_id="1698765432101",
        service_url=service_url,
        text="The task completed.",
        request_id="notification-1:attempt:1",
    )
    request = message_wire.SendMessageRequest.FromString(transport.calls[0]["request"].value)
    service_facts = {
        fact.value for fact in request.vendor_extension.facts if fact.name == "service_url"
    }
    assert service_facts == {service_url}
    assert request.reply.message_id == "1698765432101"
    assert evidence.accepted is True


def test_github_webhook_verifier_sends_original_bytes_without_connection_claim() -> None:
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.github.webhook.v1.WebhookResponse",
                b'{"event_type":"issues","action":"opened"}',
            )
        ]
    )
    verifier = GitHubWebhookClient(transport)
    result = verifier.verify_and_normalize(
        delivery_id="delivery-1",
        event_name="issues",
        signature="sha256=signature",
        body=b'{"action":"opened"}',
    )
    request = json.loads(transport.calls[0]["request"].value)
    assert set(request) == {"delivery_id", "event", "signature", "raw_body_base64"}
    assert request["raw_body_base64"] == "eyJhY3Rpb24iOiJvcGVuZWQifQ=="
    assert result["event_type"] == "issues"


def test_github_webhook_invalid_signature_is_mapped_to_401() -> None:
    transport = _DirectClient(
        [
            DirectPayload(
                "type.cyrene.io/cyrene.github.webhook.v1.WebhookResponse",
                b'{"error":{"code":"INVALID_SIGNATURE"}}',
            )
        ]
    )
    verifier = GitHubWebhookClient(transport)
    with pytest.raises(ExchangeProductError) as error:
        verifier.verify_and_normalize(
            delivery_id="delivery-1",
            event_name="issues",
            signature="sha256=bad",
            body=b"{}",
        )
    assert getattr(error.value, "status", None) == 401
