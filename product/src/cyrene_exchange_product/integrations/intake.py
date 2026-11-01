"""
Authenticated WeCom ingress for fixed, zero-model Exchange workflows.

This module validates the connector's signed canonical message envelope,
persists it before admission, and routes only the fixed `/issue` and private
`/link` commands through existing Product and Account Center ports.
模块职责：验证企业微信 connector 签名、先持久化入站事件，再调用固定业务端口。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.commands import parse_issue_command
from cyrene_exchange_product.integrations.models import (
    IntegrationAuthorizationError,
    IntegrationNotFound,
    IntegrationValidationError,
    WeComEventState,
    utc_now,
)

_HOOK_PREFIX = "/api/v1/integrations/hooks/wecom/"
_MAX_RAW_BODY_BYTES = 2 * 1024 * 1024
_MAX_PROTO_BYTES = 1024 * 1024
_MAX_SOURCE_TEXT = 4096
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_TIMESTAMP = re.compile(r"^(0|[1-9][0-9]{0,12})$")
_LINK_COMMAND = re.compile(r"^/link[ \t]+([A-Za-z0-9._~-]{16,128})$")
_SIGNATURE = re.compile(r"^sha256=([0-9a-f]{64})$")
_WE_COM_INBOUND_OPENAPI_EXTRA = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "schemaVersion",
                        "bindingId",
                        "organizationId",
                        "workspaceId",
                        "sourceAuthority",
                        "botNamespace",
                        "accountId",
                        "conversationId",
                        "conversationKind",
                        "sourceEventId",
                        "senderId",
                        "fromSelf",
                        "sourceTransportRequestId",
                        "messageProtoB64",
                    ],
                    "properties": {
                        "schemaVersion": {"type": "integer", "const": 1},
                        "bindingId": {"type": "string", "format": "uuid"},
                        "organizationId": {"type": "string", "minLength": 1, "maxLength": 200},
                        "workspaceId": {"type": "string", "minLength": 1, "maxLength": 200},
                        "sourceAuthority": {"type": "string", "minLength": 1, "maxLength": 300},
                        "botNamespace": {"type": "string", "minLength": 1, "maxLength": 300},
                        "accountId": {"type": "string", "minLength": 1, "maxLength": 300},
                        "conversationId": {"type": "string", "minLength": 1, "maxLength": 292},
                        "conversationKind": {"type": "string", "enum": ["private", "group"]},
                        "sourceEventId": {"type": "string", "minLength": 1, "maxLength": 300},
                        "senderId": {"type": "string", "minLength": 1, "maxLength": 200},
                        "fromSelf": {"type": "boolean"},
                        "sourceTransportRequestId": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 300,
                        },
                        "messageProtoB64": {
                            "type": "string",
                            "contentEncoding": "base64",
                            "contentMediaType": "application/x-protobuf",
                        },
                    },
                }
            }
        },
    },
    "parameters": [
        {
            "name": "X-Cyrene-WeCom-Timestamp",
            "in": "header",
            "required": True,
            "description": (
                "Unix seconds, no more than 300 seconds old or 30 seconds in the future."
            ),
            "schema": {"type": "string", "pattern": "^(0|[1-9][0-9]{0,12})$"},
        },
        {
            "name": "X-Cyrene-WeCom-Request-Id",
            "in": "header",
            "required": True,
            "schema": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,200}$"},
        },
        {
            "name": "X-Cyrene-WeCom-Body-SHA256",
            "in": "header",
            "required": True,
            "description": "Lowercase SHA-256 of the exact raw JSON request body.",
            "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        {
            "name": "X-Cyrene-WeCom-Source-Binding-Id",
            "in": "header",
            "required": True,
            "schema": {"type": "string", "format": "uuid"},
        },
        {
            "name": "X-Cyrene-WeCom-Signature",
            "in": "header",
            "required": True,
            "description": (
                "HMAC-SHA256 over v1, POST, exact request path, timestamp, "
                "request ID, source binding ID, and body SHA-256, joined by LF."
            ),
            "schema": {"type": "string", "pattern": "^sha256=[0-9a-f]{64}$"},
        },
    ],
    "responses": {
        "202": {
            "description": (
                "The source event and any fixed command/challenge work are durably recorded."
            ),
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["accepted", "persisted", "eventId"],
                        "properties": {
                            "accepted": {"type": "boolean", "const": True},
                            "persisted": {"type": "boolean", "const": True},
                            "eventId": {"type": "string", "format": "uuid"},
                        },
                    }
                }
            },
        }
    },
}


@dataclass(frozen=True, slots=True)
class WeComInboundSource:
    """One host-resolved Exchange group binding accepted at the public hook.

    The request key is resolved from a configured host secret reference. The
    remaining values are fixed at startup and must match the signed envelope.
    中文：只包含主机解析的绑定事实，不从 HTTP 请求读取授权范围。
    """

    binding_id: UUID
    organization_id: str
    workspace_id: str
    source_authority: str
    bot_namespace: str
    account_id: str
    group_conversation_id: str
    request_hmac_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name in (
            "organization_id",
            "workspace_id",
            "source_authority",
            "bot_namespace",
            "account_id",
            "group_conversation_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty text")
        limits = {
            "organization_id": 200,
            "workspace_id": 200,
            "source_authority": 300,
            "bot_namespace": 300,
            "account_id": 300,
            "group_conversation_id": 292,
        }
        if any(len(getattr(self, name)) > limit for name, limit in limits.items()):
            raise ValueError("configured WeCom source fact exceeds its size limit")
        if not self.account_id.startswith("bot:"):
            raise ValueError("account_id must identify the configured WeCom bot")
        if not isinstance(self.request_hmac_key, bytes) or len(self.request_hmac_key) < 32:
            raise ValueError("request_hmac_key must contain at least 32 bytes")


class WeComInboundEnvelope(BaseModel):
    """Strict signed body projection emitted by the configured connector."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    _raw_body_sha256: str = PrivateAttr(default="")

    schema_version: StrictInt = Field(alias="schemaVersion", ge=1, le=1)
    binding_id: StrictStr = Field(alias="bindingId", min_length=1, max_length=128)
    organization_id: StrictStr = Field(alias="organizationId", min_length=1, max_length=200)
    workspace_id: StrictStr = Field(alias="workspaceId", min_length=1, max_length=200)
    source_authority: StrictStr = Field(alias="sourceAuthority", min_length=1, max_length=300)
    bot_namespace: StrictStr = Field(alias="botNamespace", min_length=1, max_length=300)
    account_id: StrictStr = Field(alias="accountId", min_length=1, max_length=300)
    conversation_id: StrictStr = Field(alias="conversationId", min_length=1, max_length=292)
    conversation_kind: Literal["private", "group"] = Field(alias="conversationKind")
    source_event_id: StrictStr = Field(alias="sourceEventId", min_length=1, max_length=300)
    sender_id: StrictStr = Field(alias="senderId", min_length=1, max_length=200)
    from_self: StrictBool = Field(alias="fromSelf")
    source_transport_request_id: StrictStr = Field(
        alias="sourceTransportRequestId", min_length=1, max_length=300
    )
    message_proto_b64: StrictStr = Field(
        alias="messageProtoB64", min_length=1, max_length=1_500_000
    )


def register_wecom_routes(router: APIRouter, services: Any) -> None:
    """Register the fixed signed WeCom admission endpoint on the API router."""

    @router.post(
        "/api/v1/integrations/hooks/wecom/{bindingId}",
        status_code=202,
        operation_id="integrationAdmitWeComInbound",
        openapi_extra=_WE_COM_INBOUND_OPENAPI_EXTRA,
    )
    async def admit_wecom_inbound(bindingId: str, request: Request) -> dict[str, Any]:
        source = _configured_source(services.wecom_sources, bindingId)
        raw_body = await _read_bounded_request_body(request)
        envelope = verify_and_decode_wecom_request(
            source=source,
            binding_id=bindingId,
            request_path=request.url.path,
            headers=request.headers,
            raw_body=raw_body,
        )
        return admit_wecom_event(services=services, source=source, envelope=envelope)


def verify_and_decode_wecom_request(
    *,
    source: WeComInboundSource,
    binding_id: str,
    request_path: str,
    headers: Mapping[str, str],
    raw_body: bytes,
    now_epoch_seconds: int | None = None,
) -> WeComInboundEnvelope:
    """Verify raw request authentication, fixed source scope, and canonical proto."""

    expected_binding_id = str(source.binding_id)
    expected_path = f"{_HOOK_PREFIX}{expected_binding_id}"
    if binding_id != expected_binding_id or request_path != expected_path:
        raise _hook_error(404, "EXCHANGE_WECOM_BINDING_NOT_FOUND", "WeCom binding not found")
    if not 1 <= len(raw_body) <= _MAX_RAW_BODY_BYTES:
        raise _hook_error(
            413, "EXCHANGE_WECOM_BODY_TOO_LARGE", "WeCom event body is outside the size limit"
        )
    timestamp_text = _header(headers, "x-cyrene-wecom-timestamp")
    request_id = _header(headers, "x-cyrene-wecom-request-id")
    body_hash = _header(headers, "x-cyrene-wecom-body-sha256")
    signed_binding = _header(headers, "x-cyrene-wecom-source-binding-id")
    signature = _header(headers, "x-cyrene-wecom-signature")
    if _header(headers, "content-type").split(";", 1)[0].lower() != "application/json":
        raise _hook_error(
            415, "EXCHANGE_WECOM_CONTENT_TYPE_INVALID", "WeCom event must use application/json"
        )
    if (
        _TIMESTAMP.fullmatch(timestamp_text) is None
        or _REQUEST_ID.fullmatch(request_id) is None
        or signed_binding != expected_binding_id
        or re.fullmatch(r"[0-9a-f]{64}", body_hash) is None
    ):
        raise _hook_error(
            401, "EXCHANGE_WECOM_SIGNATURE_INVALID", "WeCom source authentication failed"
        )
    now = int(datetime.now(UTC).timestamp()) if now_epoch_seconds is None else now_epoch_seconds
    timestamp = int(timestamp_text)
    if timestamp > now + 30 or timestamp < now - 300:
        raise _hook_error(
            401, "EXCHANGE_WECOM_SIGNATURE_EXPIRED", "WeCom source authentication expired"
        )
    actual_hash = hashlib.sha256(raw_body).hexdigest()
    if not hmac.compare_digest(actual_hash, body_hash):
        raise _hook_error(
            401, "EXCHANGE_WECOM_BODY_HASH_MISMATCH", "WeCom source authentication failed"
        )
    signature_match = _SIGNATURE.fullmatch(signature)
    if signature_match is None:
        raise _hook_error(
            401, "EXCHANGE_WECOM_SIGNATURE_INVALID", "WeCom source authentication failed"
        )
    signing_input = (
        f"v1\nPOST\n{request_path}\n{timestamp_text}\n{request_id}\n"
        f"{expected_binding_id}\n{actual_hash}"
    ).encode()
    expected_signature = hmac.new(
        source.request_hmac_key, signing_input, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature_match.group(1), expected_signature):
        raise _hook_error(
            401, "EXCHANGE_WECOM_SIGNATURE_INVALID", "WeCom source authentication failed"
        )

    try:
        decoded = json.loads(raw_body.decode("utf-8"))
        envelope = WeComInboundEnvelope.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise _hook_error(
            400, "EXCHANGE_WECOM_ENVELOPE_INVALID", "WeCom event envelope is invalid"
        ) from exc
    if any(
        ord(character) < 32 or ord(character) == 127
        for character in envelope.source_transport_request_id
    ):
        raise _hook_error(
            400,
            "EXCHANGE_WECOM_ENVELOPE_INVALID",
            "WeCom callback correlation is invalid",
        )
    _validate_fixed_source_facts(envelope, source)
    _decode_and_validate_canonical_message(envelope, source)
    envelope._raw_body_sha256 = actual_hash
    return envelope


def admit_wecom_event(
    *, services: Any, source: WeComInboundSource, envelope: WeComInboundEnvelope
) -> dict[str, Any]:
    """Persist an authenticated event, then run only the two fixed command paths."""

    message = _decode_canonical_message(envelope.message_proto_b64)
    text = _single_text_content(message)
    self_authored = envelope.from_self or envelope.sender_id == source.account_id.removeprefix(
        "bot:"
    )
    event, _created = services.store.persist_wecom_inbound(
        source.binding_id,
        envelope.source_event_id,
        sender_id=envelope.sender_id,
        conversation_ref=f"{envelope.conversation_kind}:{envelope.conversation_id}",
        reply_message_id=message.message_id,
        reply_context_ref=envelope.source_transport_request_id,
        message_text=text,
        payload_fingerprint=_payload_fingerprint(envelope),
        verified=True,
        expected_organization_id=source.organization_id,
        expected_workspace_id=source.workspace_id,
        self_authored=self_authored,
        observed_at=utc_now(),
    )

    state = _state_name(getattr(event, "state", "RECEIVED"))
    event_id = getattr(event, "id", None)
    if event_id is None:
        raise RuntimeError("WeCom inbox store returned no durable event ID")
    if self_authored or state == "IGNORED_SELF":
        return _durable_ack(event_id)
    if state == "CHALLENGE_OBSERVING" and envelope.conversation_kind == "private":
        link_match = _LINK_COMMAND.fullmatch(text)
        if link_match is not None:
            _observe_private_link_challenge(
                services,
                source,
                envelope,
                event_id,
                challenge_value=link_match.group(1),
            )
        return _durable_ack(event_id)
    if state != "RECEIVED":
        return _durable_ack(event_id)

    if envelope.conversation_kind == "group":
        if envelope.conversation_id != source.group_conversation_id:
            _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_SCOPE")
            return _durable_ack(event_id)
        if not text.startswith("/issue"):
            _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_NON_COMMAND")
            return _durable_ack(event_id)
        try:
            parse_issue_command(text)
        except IntegrationValidationError:
            _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_INVALID_COMMAND")
            return _durable_ack(event_id)
        _admit_issue_command(services, source, envelope, event_id, text)
        return _durable_ack(event_id)

    link_match = _LINK_COMMAND.fullmatch(text)
    if link_match is not None:
        _observe_private_link_challenge(
            services,
            source,
            envelope,
            event_id,
            challenge_value=link_match.group(1),
        )
    elif text.startswith("/issue"):
        _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_SCOPE")
    else:
        _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_NON_COMMAND")
    return _durable_ack(event_id)


def _admit_issue_command(
    services: Any,
    source: WeComInboundSource,
    envelope: WeComInboundEnvelope,
    event_id: Any,
    command_text: str,
) -> None:
    """Resolve the exact external sender and admit against only its ActorBinding."""

    source_principal = services.wecom_source_principal(str(source.binding_id))
    linked = services.account_center.resolve_linked_sender(
        source_principal,
        source_authority=source.source_authority,
        bot_namespace=source.bot_namespace,
        stable_subject=envelope.sender_id,
    )
    if linked is None:
        _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_UNLINKED")
        return
    if linked.organization_id != source.organization_id or linked.workspace_id not in (
        None,
        source.workspace_id,
    ):
        _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_SCOPE")
        return
    try:
        operation = services.store.enqueue_issue_command_for_actor(
            binding_id=source.binding_id,
            actor_issuer=linked.issuer,
            actor_subject=linked.subject,
            organization_id=source.organization_id,
            workspace_id=source.workspace_id,
            source_event_ref=str(event_id),
            source_sender_id=envelope.sender_id,
            idempotency_key=f"wecom:{source.binding_id}:{event_id}",
            command_text=command_text,
        )
    except (IntegrationAuthorizationError, IntegrationNotFound):
        _mark_inbound(services.store, event_id, source.binding_id, "IGNORED_UNBOUND")
        return
    _mark_inbound(
        services.store,
        event_id,
        source.binding_id,
        "COMMAND_QUEUED",
        operation_id=operation.id,
    )


def _observe_private_link_challenge(
    services: Any,
    source: WeComInboundSource,
    envelope: WeComInboundEnvelope,
    event_id: Any,
    *,
    challenge_value: str,
) -> None:
    """Observe one private challenge and durably queue its canonical reply."""

    challenge_id = str(event_id)
    _observing_event, claimed = services.store.begin_wecom_challenge_observation(
        source.binding_id,
        source_event_ref=str(event_id),
    )
    if not claimed:
        return
    source_principal = services.wecom_source_principal(str(source.binding_id))
    try:
        observed = services.accounts.observe_wecom_challenge(
            source_principal,
            bot_namespace=source.bot_namespace,
            source_authority=source.source_authority,
            stable_subject=envelope.sender_id,
            challenge_id=challenge_id,
            challenge_value=challenge_value,
            expires_at=int(datetime.now(UTC).timestamp()) + 300,
        )
    except Exception:
        services.store.mark_wecom_challenge_unknown(
            source.binding_id,
            source_event_ref=str(event_id),
        )
        return
    if (
        not isinstance(observed, Mapping)
        or observed.get("accepted") is not True
        or observed.get("challenge_id") != challenge_id
    ):
        services.store.mark_wecom_challenge_unknown(
            source.binding_id,
            source_event_ref=str(event_id),
        )
        return
    try:
        services.store.enqueue_wecom_challenge_reply(
            source.binding_id,
            source_event_ref=str(event_id),
            challenge_id=challenge_id,
        )
    except Exception:
        services.store.mark_wecom_challenge_unknown(
            source.binding_id,
            source_event_ref=str(event_id),
        )


def _validate_fixed_source_facts(
    envelope: WeComInboundEnvelope, source: WeComInboundSource
) -> None:
    expected = {
        "binding_id": str(source.binding_id),
        "organization_id": source.organization_id,
        "workspace_id": source.workspace_id,
        "source_authority": source.source_authority,
        "bot_namespace": source.bot_namespace,
        "account_id": source.account_id,
    }
    if any(getattr(envelope, field) != value for field, value in expected.items()):
        raise _hook_error(
            403,
            "EXCHANGE_WECOM_SOURCE_SCOPE_MISMATCH",
            "WeCom source scope does not match its configured binding",
        )


def _decode_and_validate_canonical_message(
    envelope: WeComInboundEnvelope, source: WeComInboundSource
) -> None:
    """Require canonical message fields to agree with the signed source facts."""

    message = _decode_canonical_message(envelope.message_proto_b64)
    kind = {1: "private", 2: "group"}.get(int(message.conversation.kind))
    if (
        message.message_id != envelope.source_event_id
        or message.sender_id != envelope.sender_id
        or message.conversation.vendor != "wecom.bot"
        or message.conversation.account_id != source.account_id
        or message.conversation.conversation_id != envelope.conversation_id
        or kind != envelope.conversation_kind
        or message.vendor_extension.vendor != "wecom.bot"
        or [
            fact.value
            for fact in message.vendor_extension.facts
            if fact.name == "transport_request_id"
        ]
        != [envelope.source_transport_request_id]
    ):
        raise _hook_error(
            400,
            "EXCHANGE_WECOM_CANONICAL_MESSAGE_MISMATCH",
            "Canonical message facts do not match the signed envelope",
        )


def _decode_canonical_message(encoded: str) -> Any:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _hook_error(
            400, "EXCHANGE_WECOM_PROTO_INVALID", "Canonical message encoding is invalid"
        ) from exc
    if not 1 <= len(raw) <= _MAX_PROTO_BYTES:
        raise _hook_error(
            413, "EXCHANGE_WECOM_PROTO_TOO_LARGE", "Canonical message is outside the size limit"
        )
    message = _inbound_message_class()()
    try:
        message.ParseFromString(raw)
    except DecodeError as exc:
        raise _hook_error(
            400, "EXCHANGE_WECOM_PROTO_INVALID", "Canonical message is invalid"
        ) from exc
    if not all(
        (
            message.message_id,
            message.sender_id,
            message.conversation.vendor,
            message.conversation.account_id,
            message.conversation.conversation_id,
        )
    ):
        raise _hook_error(400, "EXCHANGE_WECOM_PROTO_INVALID", "Canonical message is incomplete")
    return message


def _single_text_content(message: Any) -> str:
    if len(message.content) != 1 or message.content[0].WhichOneof("kind") != "text":
        return ""
    value = message.content[0].text.text
    return value if isinstance(value, str) and len(value) <= _MAX_SOURCE_TEXT else ""


def _configured_source(sources: Mapping[Any, Any], binding_id: str) -> WeComInboundSource:
    try:
        parsed = UUID(binding_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise _hook_error(
            404, "EXCHANGE_WECOM_BINDING_NOT_FOUND", "WeCom binding not found"
        ) from exc
    source = sources.get(str(parsed), sources.get(parsed))
    if source is None or not isinstance(source, WeComInboundSource):
        raise _hook_error(404, "EXCHANGE_WECOM_BINDING_NOT_FOUND", "WeCom binding not found")
    return source


def _durable_ack(event_id: Any) -> dict[str, Any]:
    return {"accepted": True, "persisted": True, "eventId": str(event_id)}


def _payload_fingerprint(envelope: WeComInboundEnvelope) -> str:
    """Use the exact signed body hash, with canonical fallback for direct tests."""

    if envelope._raw_body_sha256:
        return envelope._raw_body_sha256
    encoded = json.dumps(
        envelope.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mark_inbound(
    store: Any,
    event_id: UUID,
    binding_id: UUID,
    state: str,
    *,
    operation_id: UUID | None = None,
) -> Any:
    """Persist one exact inbox disposition without changing actor identity."""

    values: dict[str, Any] = {"state": WeComEventState(state)}
    if operation_id is not None:
        values["operation_id"] = operation_id
    return store.mark_wecom_inbound_processed(event_id, binding_id, **values)


def _header(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    return value.strip() if isinstance(value, str) else ""


async def _read_bounded_request_body(request: Request) -> bytes:
    """Read the signed raw body without buffering beyond the configured bound."""

    raw_length = request.headers.get("content-length")
    if raw_length is not None:
        if not raw_length.isdecimal():
            raise _hook_error(
                400, "EXCHANGE_WECOM_CONTENT_LENGTH_INVALID", "WeCom event size is invalid"
            )
        if int(raw_length) > _MAX_RAW_BODY_BYTES:
            raise _hook_error(
                413, "EXCHANGE_WECOM_BODY_TOO_LARGE", "WeCom event body is outside the size limit"
            )
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_RAW_BODY_BYTES:
            raise _hook_error(
                413, "EXCHANGE_WECOM_BODY_TOO_LARGE", "WeCom event body is outside the size limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _state_name(value: Any) -> str:
    return str(getattr(value, "value", value))


def _hook_error(status: int, code: str, detail: str) -> ExchangeProductError:
    return ExchangeProductError(
        code=code,
        title="WeCom integration request rejected",
        detail=detail,
        status=status,
    )


@lru_cache(maxsize=1)
def _inbound_message_class() -> Any:
    """Create a wire-compatible projection of canonical fields read by intake.

    The contract owner remains Plugins `message_connector.proto`; all unrelated
    fields are preserved by protobuf as unknown fields and are not interpreted.
    中文：仅解码入站所需字段，规范源文件仍由 Plugins 合约目录维护。
    """

    file = descriptor_pb2.FileDescriptorProto()
    file.name = "cyrene_exchange_wecom_inbound_projection.proto"
    file.package = "cyrene.message.connector.v1"
    file.syntax = "proto3"
    enum = file.enum_type.add()
    enum.name = "ConversationKind"
    for name, number in (
        ("CONVERSATION_KIND_UNSPECIFIED", 0),
        ("CONVERSATION_KIND_PRIVATE", 1),
        ("CONVERSATION_KIND_GROUP", 2),
        ("CONVERSATION_KIND_CHANNEL", 3),
    ):
        value = enum.value.add()
        value.name = name
        value.number = number

    conversation = file.message_type.add()
    conversation.name = "ConversationScope"
    _add_field(conversation, "vendor", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(conversation, "account_id", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(conversation, "conversation_id", 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    kind = _add_field(conversation, "kind", 4, descriptor_pb2.FieldDescriptorProto.TYPE_ENUM)
    kind.type_name = ".cyrene.message.connector.v1.ConversationKind"

    text = file.message_type.add()
    text.name = "TextContent"
    _add_field(text, "text", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    fact = file.message_type.add()
    fact.name = "VendorFact"
    _add_field(fact, "name", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(fact, "value", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    extension = file.message_type.add()
    extension.name = "VendorExtension"
    _add_field(extension, "vendor", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(
        extension,
        "facts",
        2,
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
        type_name=".cyrene.message.connector.v1.VendorFact",
    )

    part = file.message_type.add()
    part.name = "MessageContentPart"
    part.oneof_decl.add().name = "kind"
    text_field = _add_field(
        part,
        "text",
        1,
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        type_name=".cyrene.message.connector.v1.TextContent",
    )
    text_field.oneof_index = 0

    payload = file.message_type.add()
    payload.name = "InboundMessagePayload"
    _add_field(payload, "message_id", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(
        payload,
        "conversation",
        2,
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        type_name=".cyrene.message.connector.v1.ConversationScope",
    )
    _add_field(payload, "sender_id", 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(payload, "sender_display_name", 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _add_field(
        payload,
        "content",
        5,
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
        type_name=".cyrene.message.connector.v1.MessageContentPart",
    )
    _add_field(
        payload,
        "vendor_extension",
        7,
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        type_name=".cyrene.message.connector.v1.VendorExtension",
    )
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)
    descriptor = pool.FindMessageTypeByName("cyrene.message.connector.v1.InboundMessagePayload")
    return message_factory.GetMessageClass(descriptor)


def _add_field(
    message: Any,
    name: str,
    number: int,
    field_type: int,
    *,
    label: int = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    type_name: str | None = None,
) -> Any:
    field = message.field.add()
    field.name = name
    field.number = number
    field.label = label
    field.type = field_type
    if type_name is not None:
        field.type_name = type_name
    return field
