"""Authenticated Exchange admission tests for the actual WeCom source contract.

The tests use canonical message.connector.v1 wire fields, signed synthetic
source requests, the real SQLite IntegrationStore, and fake capability ports.
模块职责：验证 HMAC 入站、持久化去重、固定命令路由和私聊挑战 outbox。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.intake import (
    WeComInboundSource,
    _inbound_message_class,
    admit_wecom_event,
    register_wecom_routes,
    verify_and_decode_wecom_request,
)
from cyrene_exchange_product.integrations.models import (
    CreateActorBinding,
    CreateIntegrationConnection,
    CreateSyncBinding,
    IntegrationPrincipal,
    Operation,
    WeComEventState,
    WeComInboundEvent,
)
from cyrene_exchange_product.integrations.ports import LinkedSender
from cyrene_exchange_product.integrations.store import IntegrationStore

EXCHANGE_BINDING_ID = UUID("a8788408-19ba-43ea-96d2-92336dd499d6")
SOURCE_KEY = b"synthetic-wecom-source-key-32-bytes-long"
ORG_ID = "org-test"
WORKSPACE_ID = "workspace-test"
SOURCE_AUTHORITY = "wecom.bot"
BOT_NAMESPACE = "corp:test-bot"
ACCOUNT_ID = "bot:test-bot"
GROUP_ID = "group-42"


class FakeAccountCenter:
    """Source-bound Account Center test port with no caller-selected identity."""

    def __init__(self, linked: LinkedSender | None) -> None:
        self.linked = linked
        self.resolutions: list[tuple[str, str, str]] = []

    def resolve_linked_sender(
        self,
        service_principal: IntegrationPrincipal,
        *,
        source_authority: str,
        bot_namespace: str,
        stable_subject: str,
    ) -> LinkedSender | None:
        assert service_principal.subject == "configured-wecom-source"
        self.resolutions.append((source_authority, bot_namespace, stable_subject))
        return self.linked


class FakeAccounts:
    """Record source-signed challenge observations using synthetic inputs."""

    def __init__(self, failure: Exception | None = None) -> None:
        self.observations: list[dict[str, object]] = []
        self.failure = failure

    def observe_wecom_challenge(
        self,
        source_principal: IntegrationPrincipal,
        **payload: object,
    ) -> dict[str, object]:
        assert source_principal.subject == "configured-wecom-source"
        self.observations.append(dict(payload))
        if self.failure is not None:
            raise self.failure
        return {
            "accepted": True,
            "challenge_id": payload["challenge_id"],
            "expires_at": payload["expires_at"],
        }


def principal(subject: str = "binding-owner") -> IntegrationPrincipal:
    """Return synthetic verified test identity with only setup permissions."""

    return IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject=subject,
        organization_id=ORG_ID,
        workspace_id=WORKSPACE_ID,
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationCreateBinding",
                "integrationAttachActorBinding",
            }
        ),
    )


def source(binding_id: UUID = EXCHANGE_BINDING_ID) -> WeComInboundSource:
    """Build fixed source scope and synthetic request key for one binding."""

    return WeComInboundSource(
        binding_id=binding_id,
        organization_id=ORG_ID,
        workspace_id=WORKSPACE_ID,
        source_authority=SOURCE_AUTHORITY,
        bot_namespace=BOT_NAMESPACE,
        account_id=ACCOUNT_ID,
        group_conversation_id=GROUP_ID,
        request_hmac_key=SOURCE_KEY,
    )


def create_store(tmp_path, *, linked_subject: str | None = None):
    """Create a real binding and optional actor attachment in SQLite."""

    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    owner = principal()
    connection = store.create_connection(
        owner,
        CreateIntegrationConnection(
            repository_id="repo-42",
            repository_name="acme/example",
        ),
        idempotency_key="setup-connection",
    )
    binding = store.create_binding(
        owner,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="wecom:fixed-bot-target",
        ),
        idempotency_key="setup-binding",
    )
    if linked_subject is not None:
        store.create_actor_binding(
            principal(linked_subject),
            CreateActorBinding(
                binding_id=binding.id,
                account_link_ref=f"account-link:{linked_subject}",
                delegation_ref=f"delegation:{linked_subject}",
            ),
            idempotency_key=f"setup-actor:{linked_subject}",
        )
    return store, owner, binding


def services_for(
    store: IntegrationStore,
    *,
    account_center: FakeAccountCenter,
    accounts: FakeAccounts | None = None,
):
    """Assemble only the existing fixed ports used by WeCom intake."""

    source_principal = IntegrationPrincipal(
        issuer="urn:cyrene:wecom-source",
        subject="configured-wecom-source",
        organization_id=ORG_ID,
        workspace_id=WORKSPACE_ID,
        allowed_operation_ids=frozenset(),
    )
    return SimpleNamespace(
        store=store,
        account_center=account_center,
        accounts=accounts or FakeAccounts(),
        wecom_source_principal=lambda _binding_id: source_principal,
    )


def signed_request(
    source_binding: WeComInboundSource,
    *,
    text: str = "/issue query 12",
    sender_id: str = "member-1",
    conversation_id: str = GROUP_ID,
    conversation_kind: str = "group",
    source_event_id: str = "vendor-message-1",
    from_self: bool = False,
    request_id: str = "http-request-1",
    timestamp: int = 1_800_000_000,
) -> tuple[bytes, dict[str, str]]:
    """Serialize the normalized canonical inbound contract and sign exact bytes."""

    message_type = _inbound_message_class()
    message = message_type()
    message.message_id = source_event_id
    message.sender_id = sender_id
    message.sender_display_name = "untrusted display name"
    message.conversation.vendor = "wecom.bot"
    message.conversation.account_id = source_binding.account_id
    message.conversation.conversation_id = conversation_id
    message.conversation.kind = 1 if conversation_kind == "private" else 2
    part = message.content.add()
    part.text.text = text
    message.vendor_extension.vendor = "wecom.bot"
    fact = message.vendor_extension.facts.add()
    fact.name = "transport_request_id"
    fact.value = "vendor-callback-req-1"
    envelope = {
        "schemaVersion": 1,
        "bindingId": str(source_binding.binding_id),
        "organizationId": source_binding.organization_id,
        "workspaceId": source_binding.workspace_id,
        "sourceAuthority": source_binding.source_authority,
        "botNamespace": source_binding.bot_namespace,
        "accountId": source_binding.account_id,
        "conversationId": conversation_id,
        "conversationKind": conversation_kind,
        "sourceEventId": source_event_id,
        "senderId": sender_id,
        "fromSelf": from_self,
        "sourceTransportRequestId": "vendor-callback-req-1",
        "messageProtoB64": base64.b64encode(message.SerializeToString()).decode("ascii"),
    }
    raw_body = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    path = f"/api/v1/integrations/hooks/wecom/{source_binding.binding_id}"
    body_hash = hashlib.sha256(raw_body).hexdigest()
    signing_input = (
        f"v1\nPOST\n{path}\n{timestamp}\n{request_id}\n{source_binding.binding_id}\n{body_hash}"
    ).encode()
    signature = hmac.new(source_binding.request_hmac_key, signing_input, hashlib.sha256).hexdigest()
    headers = {
        "content-type": "application/json",
        "x-cyrene-wecom-timestamp": str(timestamp),
        "x-cyrene-wecom-request-id": request_id,
        "x-cyrene-wecom-body-sha256": body_hash,
        "x-cyrene-wecom-source-binding-id": str(source_binding.binding_id),
        "x-cyrene-wecom-signature": f"sha256={signature}",
    }
    return raw_body, headers


def decode_request(
    source_binding: WeComInboundSource,
    raw_body: bytes,
    headers: dict[str, str],
    *,
    binding_path: str | None = None,
    now_epoch_seconds: int = 1_800_000_000,
):
    """Run the same raw-body verifier used by the registered FastAPI hook."""

    selected = binding_path or str(source_binding.binding_id)
    return verify_and_decode_wecom_request(
        source=source_binding,
        binding_id=selected,
        request_path=f"/api/v1/integrations/hooks/wecom/{selected}",
        headers=headers,
        raw_body=raw_body,
        now_epoch_seconds=now_epoch_seconds,
    )


def resign_request(
    raw_body: bytes,
    source_binding: WeComInboundSource,
    *,
    request_id: str,
    timestamp: int = 1_800_000_000,
) -> dict[str, str]:
    """Sign the same body again with a fresh transport request ID."""

    body_hash = hashlib.sha256(raw_body).hexdigest()
    path = f"/api/v1/integrations/hooks/wecom/{source_binding.binding_id}"
    signing_input = (
        f"v1\nPOST\n{path}\n{timestamp}\n{request_id}\n{source_binding.binding_id}\n{body_hash}"
    ).encode()
    signature = hmac.new(source_binding.request_hmac_key, signing_input, hashlib.sha256).hexdigest()
    return {
        "content-type": "application/json",
        "x-cyrene-wecom-timestamp": str(timestamp),
        "x-cyrene-wecom-request-id": request_id,
        "x-cyrene-wecom-body-sha256": body_hash,
        "x-cyrene-wecom-source-binding-id": str(source_binding.binding_id),
        "x-cyrene-wecom-signature": f"sha256={signature}",
    }


def test_hmac_admission_persists_before_actor_command_and_deduplicates_restart(
    tmp_path,
) -> None:
    store, _owner, binding = create_store(tmp_path, linked_subject="actor-linked")
    configured_source = source(binding.id)
    linked_sender = LinkedSender(
        issuer="https://identity.example.test",
        subject="actor-linked",
        organization_id=ORG_ID,
        workspace_id=None,
        account_link_ref="account-link:actor-linked",
        external_sender_id="member-1",
    )
    account_center = FakeAccountCenter(linked_sender)
    services = services_for(store, account_center=account_center)
    raw_body, headers = signed_request(configured_source, text="/issue close 12")
    first = decode_request(configured_source, raw_body, headers)

    ack = admit_wecom_event(services=services, source=configured_source, envelope=first)
    assert ack["accepted"] is True and ack["persisted"] is True
    assert account_center.resolutions == [(SOURCE_AUTHORITY, BOT_NAMESPACE, "member-1")]
    stored = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE source_event_id=?",
        ("vendor-message-1",),
    ).fetchone()
    event = WeComInboundEvent.model_validate_json(stored[0])
    assert event.state == WeComEventState.COMMAND_QUEUED
    assert event.reply_message_id == "vendor-message-1"
    assert event.reply_context_ref == "vendor-callback-req-1"

    operations = store._connection.execute("SELECT document FROM operations").fetchall()
    assert len(operations) == 1
    operation = Operation.model_validate_json(operations[0][0])
    assert operation.actor_subject == "actor-linked"
    assert operation.account_link_ref == "account-link:actor-linked"
    assert operation.delegation_ref == "delegation:actor-linked"
    assert operation.source_kind == "WECOM_COMMAND"
    assert operation.reply_message_id == "vendor-message-1"
    assert operation.reply_context_ref == "vendor-callback-req-1"
    assert operation.reply_binding_ref == str(binding.id)
    assert operation.reply_conversation_ref == "group:group-42"

    store.close()
    restarted = IntegrationStore(tmp_path / "integrations.sqlite3")
    duplicate_services = services_for(restarted, account_center=FakeAccountCenter(linked_sender))
    duplicate = decode_request(
        configured_source,
        raw_body,
        resign_request(raw_body, configured_source, request_id="http-retry-2"),
    )
    duplicate_ack = admit_wecom_event(
        services=duplicate_services,
        source=configured_source,
        envelope=duplicate,
    )
    assert duplicate_ack["eventId"] == ack["eventId"]
    assert restarted._connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 1
    restarted.close()


def test_registered_hook_returns_durable_ack_only_after_real_store_admission(
    tmp_path,
) -> None:
    store, _owner, binding = create_store(tmp_path, linked_subject="actor-linked")
    configured_source = source(binding.id)
    linked_sender = LinkedSender(
        issuer="https://identity.example.test",
        subject="actor-linked",
        organization_id=ORG_ID,
        workspace_id=WORKSPACE_ID,
        account_link_ref="account-link:actor-linked",
        external_sender_id="member-1",
    )
    services = services_for(store, account_center=FakeAccountCenter(linked_sender))
    services.wecom_sources = {str(binding.id): configured_source}
    router = APIRouter()
    register_wecom_routes(router, services)
    app = FastAPI()
    app.include_router(router)
    operation = app.openapi()["paths"]["/api/v1/integrations/hooks/wecom/{bindingId}"]["post"]
    assert (
        "messageProtoB64"
        in operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
    )
    assert (
        operation["responses"]["202"]["content"]["application/json"]["schema"]["properties"][
            "persisted"
        ]["const"]
        is True
    )
    raw_body, headers = signed_request(
        configured_source,
        text="hello",
        timestamp=int(datetime.now(UTC).timestamp()),
    )

    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/integrations/hooks/wecom/{binding.id}",
            content=raw_body,
            headers=headers,
        )

    assert response.status_code == 202
    assert response.json()["accepted"] is True
    assert response.json()["persisted"] is True
    assert store._connection.execute("SELECT COUNT(*) FROM wecom_inbound_events").fetchone()[0] == 1
    store.close()


def test_hmac_rejects_tampered_sender_stale_timestamp_and_wrong_binding(tmp_path) -> None:
    configured_source = source()
    raw_body, headers = signed_request(configured_source)
    with pytest.raises(ExchangeProductError) as tampered:
        decode_request(
            configured_source,
            raw_body.replace(b"member-1", b"forged-1"),
            headers,
        )
    assert tampered.value.status == 401

    with pytest.raises(ExchangeProductError) as stale:
        decode_request(
            configured_source,
            raw_body,
            headers,
            now_epoch_seconds=1_800_000_301,
        )
    assert stale.value.status == 401

    with pytest.raises(ExchangeProductError) as wrong_route:
        decode_request(
            configured_source,
            raw_body,
            headers,
            binding_path="a8788408-19ba-43ea-96d2-92336dd499d7",
        )
    assert wrong_route.value.status == 404


def test_signed_body_cannot_forge_canonical_sender_or_binding_scope(tmp_path) -> None:
    configured_source = source()
    raw_body, headers = signed_request(configured_source)
    envelope = json.loads(raw_body)
    envelope["senderId"] = "forged-member"
    forged_sender = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    body_hash = hashlib.sha256(forged_sender).hexdigest()
    path = f"/api/v1/integrations/hooks/wecom/{configured_source.binding_id}"
    request_id = "http-forged-signed"
    signing_input = (
        f"v1\nPOST\n{path}\n1800000000\n{request_id}\n{configured_source.binding_id}\n{body_hash}"
    ).encode()
    signature = hmac.new(SOURCE_KEY, signing_input, hashlib.sha256).hexdigest()
    forged_headers = {
        **headers,
        "x-cyrene-wecom-timestamp": "1800000000",
        "x-cyrene-wecom-request-id": request_id,
        "x-cyrene-wecom-body-sha256": body_hash,
        "x-cyrene-wecom-signature": f"sha256={signature}",
    }
    # A valid source signature still cannot make duplicated JSON facts disagree
    # with the canonical protobuf sender_id.
    with pytest.raises(ExchangeProductError) as mismatch:
        decode_request(configured_source, forged_sender, forged_headers)
    assert mismatch.value.status == 400

    envelope = json.loads(raw_body)
    envelope["organizationId"] = "other-org"
    other_scope = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    other_hash = hashlib.sha256(other_scope).hexdigest()
    request_id = "http-other-scope"
    signing_input = (
        f"v1\nPOST\n{path}\n1800000000\n{request_id}\n{configured_source.binding_id}\n{other_hash}"
    ).encode()
    other_signature = hmac.new(SOURCE_KEY, signing_input, hashlib.sha256).hexdigest()
    other_headers = {
        **headers,
        "x-cyrene-wecom-request-id": request_id,
        "x-cyrene-wecom-body-sha256": other_hash,
        "x-cyrene-wecom-signature": f"sha256={other_signature}",
    }
    with pytest.raises(ExchangeProductError) as scope_mismatch:
        decode_request(configured_source, other_scope, other_headers)
    assert scope_mismatch.value.status == 403

    envelope = json.loads(raw_body)
    envelope["bindingId"] = "a8788408-19ba-43ea-96d2-92336dd499d7"
    wrong_binding_body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    wrong_binding_headers = resign_request(
        wrong_binding_body,
        configured_source,
        request_id="http-wrong-binding-body",
    )
    with pytest.raises(ExchangeProductError) as binding_mismatch:
        decode_request(configured_source, wrong_binding_body, wrong_binding_headers)
    assert binding_mismatch.value.status == 403


def test_private_link_is_observed_once_and_reply_is_durably_queued(tmp_path) -> None:
    store, _owner, binding = create_store(tmp_path)
    configured_source = source(binding.id)
    accounts = FakeAccounts()
    services = services_for(
        store,
        account_center=FakeAccountCenter(None),
        accounts=accounts,
    )
    raw_body, headers = signed_request(
        configured_source,
        text="/link 0123456789abcdef0123456789abcdef",
        conversation_id="member-1",
        conversation_kind="private",
    )
    envelope = decode_request(configured_source, raw_body, headers)
    ack = admit_wecom_event(services=services, source=configured_source, envelope=envelope)
    challenge_id = ack["eventId"]
    assert accounts.observations[0]["stable_subject"] == "member-1"
    assert accounts.observations[0]["challenge_id"] == challenge_id
    assert accounts.observations[0]["expires_at"] <= int(datetime.now(UTC).timestamp()) + 301

    event_row = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE id=?", (challenge_id,)
    ).fetchone()
    event = WeComInboundEvent.model_validate_json(event_row[0])
    assert event.message_text == "/link [redacted]"
    assert "0123456789abcdef" not in event.model_dump_json()
    assert event.state == WeComEventState.CHALLENGE_REPLY_PENDING
    job_row = store._connection.execute(
        "SELECT document FROM outbox_jobs WHERE kind='CHALLENGE_REPLY'"
    ).fetchone()
    job = json.loads(job_row[0])
    assert job["payload"]["sourceBindingId"] == str(binding.id)
    assert job["payload"]["replyMessageId"] == "vendor-message-1"
    assert job["payload"]["replyContextRef"] == "vendor-callback-req-1"
    assert challenge_id in job["payload"]["text"]
    assert "0123456789abcdef" not in job["payload"]["text"]

    replay = decode_request(
        configured_source,
        raw_body,
        resign_request(raw_body, configured_source, request_id="http-replay-2"),
    )
    replay_ack = admit_wecom_event(services=services, source=configured_source, envelope=replay)
    assert replay_ack == ack
    assert len(accounts.observations) == 1
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM outbox_jobs WHERE kind='CHALLENGE_REPLY'"
        ).fetchone()[0]
        == 1
    )

    group_body, group_headers = signed_request(
        configured_source,
        text="/link 1123456789abcdef0123456789abcdef",
        conversation_id=GROUP_ID,
        conversation_kind="group",
        source_event_id="group-link-message",
    )
    group_envelope = decode_request(configured_source, group_body, group_headers)
    admit_wecom_event(
        services=services,
        source=configured_source,
        envelope=group_envelope,
    )
    assert len(accounts.observations) == 1
    group_row = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE source_event_id=?",
        ("group-link-message",),
    ).fetchone()
    assert (
        WeComInboundEvent.model_validate_json(group_row[0]).state
        == WeComEventState.IGNORED_NON_COMMAND
    )
    store.close()


def test_ambiguous_challenge_observation_is_durable_unknown_and_never_replayed(
    tmp_path,
) -> None:
    store, _owner, binding = create_store(tmp_path)
    configured_source = source(binding.id)
    accounts = FakeAccounts(failure=TimeoutError("synthetic timeout"))
    services = services_for(
        store,
        account_center=FakeAccountCenter(None),
        accounts=accounts,
    )
    raw_body, headers = signed_request(
        configured_source,
        text="/link 0123456789abcdef0123456789abcdef",
        conversation_id="member-1",
        conversation_kind="private",
    )
    first = decode_request(configured_source, raw_body, headers)
    first_ack = admit_wecom_event(services=services, source=configured_source, envelope=first)
    assert first_ack["persisted"] is True

    event_row = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE source_event_id=?",
        ("vendor-message-1",),
    ).fetchone()
    event = WeComInboundEvent.model_validate_json(event_row[0])
    assert event.state == WeComEventState.CHALLENGE_UNKNOWN

    replay = decode_request(
        configured_source,
        raw_body,
        resign_request(raw_body, configured_source, request_id="http-retry-after-timeout"),
    )
    replay_ack = admit_wecom_event(
        services=services,
        source=configured_source,
        envelope=replay,
    )
    assert replay_ack == first_ack
    assert len(accounts.observations) == 1
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM outbox_jobs WHERE kind='CHALLENGE_REPLY'"
        ).fetchone()[0]
        == 0
    )
    store.close()


def test_redelivery_of_observing_challenge_marks_unknown_without_second_call(
    tmp_path,
) -> None:
    store, _owner, binding = create_store(tmp_path)
    configured_source = source(binding.id)
    raw_body, headers = signed_request(
        configured_source,
        text="/link 0123456789abcdef0123456789abcdef",
        conversation_id="member-1",
        conversation_kind="private",
    )
    envelope = decode_request(configured_source, raw_body, headers)
    message = _inbound_message_class()()
    message.ParseFromString(base64.b64decode(envelope.message_proto_b64))
    event, created = store.persist_wecom_inbound(
        binding.id,
        envelope.source_event_id,
        expected_organization_id=ORG_ID,
        expected_workspace_id=WORKSPACE_ID,
        sender_id=envelope.sender_id,
        conversation_ref=f"private:{envelope.conversation_id}",
        reply_message_id=message.message_id,
        reply_context_ref=envelope.source_transport_request_id,
        message_text="/link 0123456789abcdef0123456789abcdef",
        payload_fingerprint=envelope._raw_body_sha256,
        verified=True,
    )
    assert created is True
    _observing, claimed = store.begin_wecom_challenge_observation(binding.id, str(event.id))
    assert claimed is True
    accounts = FakeAccounts()
    services = services_for(
        store,
        account_center=FakeAccountCenter(None),
        accounts=accounts,
    )

    ack = admit_wecom_event(
        services=services,
        source=configured_source,
        envelope=envelope,
    )

    stored = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE id=?", (str(event.id),)
    ).fetchone()
    assert (
        WeComInboundEvent.model_validate_json(stored[0]).state == WeComEventState.CHALLENGE_UNKNOWN
    )
    assert accounts.observations == []
    assert ack["persisted"] is True
    store.close()


def test_self_and_nonmatching_group_events_are_persisted_without_identity_lookup(
    tmp_path,
) -> None:
    store, _owner, binding = create_store(tmp_path, linked_subject="binding-owner")
    configured_source = source(binding.id)
    account_center = FakeAccountCenter(
        LinkedSender(
            issuer="https://identity.example.test",
            subject="binding-owner",
            organization_id=ORG_ID,
            workspace_id=WORKSPACE_ID,
            account_link_ref="account-link:binding-owner",
            external_sender_id="member-1",
        )
    )
    services = services_for(store, account_center=account_center)

    self_body, self_headers = signed_request(
        configured_source,
        sender_id="test-bot",
        from_self=True,
        source_event_id="self-message",
    )
    self_envelope = decode_request(configured_source, self_body, self_headers)
    self_ack = admit_wecom_event(
        services=services, source=configured_source, envelope=self_envelope
    )
    self_row = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE source_event_id='self-message'"
    ).fetchone()
    assert WeComInboundEvent.model_validate_json(self_row[0]).state == WeComEventState.IGNORED_SELF
    assert self_ack["persisted"] is True

    other_body, other_headers = signed_request(
        configured_source,
        text="/issue close 12",
        conversation_id="different-group",
        source_event_id="other-group-message",
    )
    other_envelope = decode_request(configured_source, other_body, other_headers)
    other_ack = admit_wecom_event(
        services=services, source=configured_source, envelope=other_envelope
    )
    other_row = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE source_event_id='other-group-message'"
    ).fetchone()
    assert (
        WeComInboundEvent.model_validate_json(other_row[0]).state == WeComEventState.IGNORED_SCOPE
    )
    assert other_ack["persisted"] is True
    assert account_center.resolutions == []
    assert store._connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0
    store.close()


def test_host_source_scope_must_match_the_database_sync_binding(tmp_path) -> None:
    store, _owner, binding = create_store(tmp_path)
    misconfigured_source = WeComInboundSource(
        binding_id=binding.id,
        organization_id="other-org",
        workspace_id=WORKSPACE_ID,
        source_authority=SOURCE_AUTHORITY,
        bot_namespace=BOT_NAMESPACE,
        account_id=ACCOUNT_ID,
        group_conversation_id=GROUP_ID,
        request_hmac_key=SOURCE_KEY,
    )
    services = services_for(
        store,
        account_center=FakeAccountCenter(None),
    )
    raw_body, headers = signed_request(
        misconfigured_source,
        text="hello",
        source_event_id="scope-mismatch-message",
    )
    envelope = decode_request(misconfigured_source, raw_body, headers)

    with pytest.raises(ExchangeProductError) as mismatch:
        admit_wecom_event(
            services=services,
            source=misconfigured_source,
            envelope=envelope,
        )

    assert mismatch.value.status == 403
    assert store._connection.execute("SELECT COUNT(*) FROM wecom_inbound_events").fetchone()[0] == 0
    store.close()


def test_missing_sender_actor_binding_never_falls_back_to_binding_creator(tmp_path) -> None:
    store, _owner, binding = create_store(tmp_path, linked_subject="binding-owner")
    configured_source = source(binding.id)
    linked_sender = LinkedSender(
        issuer="https://identity.example.test",
        subject="other-member",
        organization_id=ORG_ID,
        workspace_id=WORKSPACE_ID,
        account_link_ref="account-link:other-member",
        external_sender_id="member-1",
    )
    services = services_for(
        store,
        account_center=FakeAccountCenter(linked_sender),
    )
    raw_body, headers = signed_request(configured_source, text="/issue reopen 12")
    envelope = decode_request(configured_source, raw_body, headers)

    ack = admit_wecom_event(services=services, source=configured_source, envelope=envelope)

    event_row = store._connection.execute(
        "SELECT document FROM wecom_inbound_events WHERE source_event_id=?",
        ("vendor-message-1",),
    ).fetchone()
    assert (
        WeComInboundEvent.model_validate_json(event_row[0]).state == WeComEventState.IGNORED_UNBOUND
    )
    assert ack["persisted"] is True
    assert store._connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0
    store.close()
