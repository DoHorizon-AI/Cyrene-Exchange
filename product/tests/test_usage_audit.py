"""
Product request usage and audit acceptance tests. | Product 请求 usage 与审计验收测试。
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

import pytest
from cyrene_exchange.billing import TokenUsageEvent
from cyrene_exchange.capabilities import (
    MODEL_PROVIDER_CAPABILITY,
    MODEL_ROUTING_CAPABILITY,
    ProviderChunk,
    ProviderUsage,
    RouteTarget,
)
from cyrene_exchange.gateway import (
    AuthenticationError,
    ExchangeGateway,
    GatewayLifecycleError,
    QuotaExceededError,
    QuotaUnavailableError,
    RequestMetadata,
    RequestPrincipal,
)
from fastapi.testclient import TestClient

from cyrene_exchange_product import (
    ProductPrincipal,
    ProductQuotaGuard,
    TenantQuota,
    create_audit_app,
)
from cyrene_exchange_product.audit import RequestAuditRecorder
from cyrene_exchange_product.domain import RequestAuditStatus, UsageState
from cyrene_exchange_product.store import ExchangeStore


class Router:
    """Return one opaque Product route for the core gateway.

    中文:为核心 Gateway 返回一条不透明的 Product 路由。"""

    def plan(self, _request):
        return [RouteTarget(provider_ref="binding:unit", route_id="route:unit")]


class Provider:
    """Yield exact provider usage facts for unary or streamed requests.

    中文:为一元或流式请求产出提供方报告的精确用量事实。"""

    def __init__(self, chunks: Iterable[ProviderChunk]) -> None:
        self.chunks = list(chunks)
        self.calls = 0

    def complete(self, _request, *, cancel_event: Event):
        self.calls += 1
        if cancel_event.is_set():
            return
        yield from self.chunks


class Resolver:
    """Expose the fake router and provider through canonical capability ids.

    中文:通过规范能力 ID 暴露模拟路由器和提供方。"""

    def __init__(self, provider: Provider) -> None:
        self.provider = provider

    def resolve(self, capability_id: str, implementation_ref: str | None = None) -> object:
        if capability_id == MODEL_ROUTING_CAPABILITY:
            return Router()
        assert capability_id == MODEL_PROVIDER_CAPABILITY
        assert implementation_ref == "binding:unit"
        return self.provider


class RecordingBillingClient:
    """Capture Product-to-plugin usage events without duplicating ledger logic.

    中文:捕获 Product 到 Plugin 的用量事件,不重复实现台账逻辑。"""

    def __init__(self) -> None:
        self.events: list[TokenUsageEvent] = []
        self.totals: dict[str, int] = {}

    def record_token_usage(self, event: TokenUsageEvent) -> None:
        self.events.append(event)

    def total_tokens(self, tenant_id: str) -> int:
        return self.totals.get(tenant_id, 0)


def _gateway(
    store: ExchangeStore,
    provider: Provider,
    billing: RecordingBillingClient | None = None,
) -> ExchangeGateway:
    store.configure_credentials(
        {"unit-secret": ProductPrincipal("actor-unit", "workspace-unit", "credential-unit")}
    )
    return ExchangeGateway(
        Resolver(provider),
        principal_resolver=store.resolve_credential,
        lifecycle_observer=RequestAuditRecorder(store, billing),
        max_route_attempts=1,
    )


def _payload(*, stream: bool = False) -> dict[str, object]:
    return {
        "model": "unit-model",
        "messages": [{"role": "user", "content": "private prompt"}],
        "stream": stream,
    }


def test_unary_audit_uses_trusted_credential_and_survives_restart(tmp_path: Path) -> None:
    database = tmp_path / "exchange.sqlite3"
    store = ExchangeStore(database)
    provider = Provider(
        [
            ProviderChunk(
                delta="answer",
                finish_reason="stop",
                usage=ProviderUsage(
                    prompt_tokens=4,
                    completion_tokens=3,
                    total_tokens=7,
                    source="fixture",
                ),
            )
        ]
    )
    billing = RecordingBillingClient()
    gateway = _gateway(store, provider, billing)
    response = gateway.handle_openai_chat(
        {"Authorization": "Bearer unit-secret"},
        {
            **_payload(),
            "actorId": "spoofed-actor",
            "workspaceId": "spoofed-workspace",
        },
        request_id="chatcmpl-audit-unary",
    )

    assert response.body["choices"][0]["message"]["content"] == "answer"  # type: ignore[index]
    record = store.get_request_audit("chatcmpl-audit-unary")
    assert record is not None
    assert record.status == RequestAuditStatus.COMPLETED
    assert record.actor_id == "actor-unit"
    assert record.workspace_id == "workspace-unit"
    assert record.credential_ref == "credential-unit"
    assert record.route_id == "route:unit"
    assert record.binding_id == "binding:unit"
    assert record.usage_state == UsageState.FINAL
    assert record.prompt_tokens == 4
    assert record.completion_tokens == 3
    assert record.total_tokens == 7
    assert billing.events == [
        TokenUsageEvent(
            request_id="chatcmpl-audit-unary",
            tenant_id="actor-unit",
            workspace_id="workspace-unit",
            model="unit-model",
            request_status="completed",
            prompt_tokens=4,
            completion_tokens=3,
            total_tokens=7,
            usage_source="fixture",
        )
    ]
    store.close()

    reopened = ExchangeStore(database)
    try:
        assert reopened.get_request_audit("chatcmpl-audit-unary") == record
        assert reopened.resolve_credential("unit-secret") is not None
        database_bytes = database.read_bytes()
        assert b"unit-secret" not in database_bytes
        assert b"private prompt" not in database_bytes
    finally:
        reopened.close()


def test_stream_audit_records_observed_usage_once_and_unknown_is_not_zero(tmp_path: Path) -> None:
    store = ExchangeStore(tmp_path / "exchange.sqlite3")
    provider = Provider(
        [
            ProviderChunk(delta="part "),
            ProviderChunk(
                delta="answer",
                finish_reason="stop",
                usage=ProviderUsage(prompt_tokens=8, completion_tokens=2, source="stream-fixture"),
            ),
        ]
    )
    gateway = _gateway(store, provider)
    response = gateway.handle_openai_chat(
        {"Authorization": "Bearer unit-secret"},
        _payload(stream=True),
        request_id="chatcmpl-audit-stream",
    )
    assert list(response.body)[-1] == "[DONE]"  # type: ignore[arg-type]
    record = store.get_request_audit("chatcmpl-audit-stream")
    assert record is not None
    assert record.status == RequestAuditStatus.COMPLETED
    assert record.usage_state == UsageState.FINAL
    assert (record.prompt_tokens, record.completion_tokens, record.total_tokens) == (8, 2, None)

    metadata = RequestMetadata(
        request_id="chatcmpl-audit-stream",
        model="unit-model",
        stream=True,
        route_id="route:unit",
        provider_ref="binding:unit",
        principal=RequestPrincipal("actor-unit", "workspace-unit", "credential-unit"),
    )
    # A duplicate terminal callback is a no-op and cannot overwrite usage.
    # 中文:重复的最终回调不执行操作,也不能覆盖用量。
    store.finish_request(
        metadata,
        status="completed",
        usage=ProviderUsage(prompt_tokens=99, completion_tokens=99, total_tokens=198),
        error_type=None,
    )
    assert store.get_request_audit("chatcmpl-audit-stream") == record
    store.close()


def test_rejection_is_audited_without_provider_or_request_content(tmp_path: Path) -> None:
    database = tmp_path / "exchange.sqlite3"
    store = ExchangeStore(database)
    provider = Provider([ProviderChunk(delta="must not run")])
    gateway = _gateway(store, provider)

    with pytest.raises(AuthenticationError):
        gateway.handle_openai_chat(
            {"Authorization": "Bearer wrong-secret"},
            _payload(),
            request_id="chatcmpl-audit-rejected",
        )
    record = store.get_request_audit("chatcmpl-audit-rejected")
    assert record is not None
    assert record.status == RequestAuditStatus.REJECTED
    assert record.actor_id is None
    assert record.workspace_id is None
    assert provider.calls == 0
    store.close()


def test_read_only_audit_api_enforces_credential_scope(tmp_path: Path) -> None:
    database = tmp_path / "exchange.sqlite3"
    store = ExchangeStore(database)
    provider = Provider([ProviderChunk(delta="answer", finish_reason="stop")])
    _gateway(store, provider).handle_openai_chat(
        {"Authorization": "Bearer unit-secret"},
        _payload(),
        request_id="chatcmpl-audit-api",
    )
    store.configure_credentials(
        {"other-secret": ProductPrincipal("actor-other", "workspace-other", "credential-other")}
    )
    store.close()

    app = create_audit_app(database_path=database)
    try:
        with TestClient(app) as client:
            own = client.get(
                "/api/v1/usage-audit/requests/chatcmpl-audit-api",
                headers={"Authorization": "Bearer unit-secret"},
            )
            assert own.status_code == 200
            assert own.json()["actorId"] == "actor-unit"
            assert client.get("/api/v1/usage-audit/requests").status_code == 401
            foreign = client.get(
                "/api/v1/usage-audit/requests/chatcmpl-audit-api",
                headers={"Authorization": "Bearer other-secret"},
            )
            assert foreign.status_code == 404
    finally:
        app.state.exchange_store.close()


def test_stream_completion_is_durable_before_done_reaches_the_consumer(tmp_path: Path) -> None:
    """A client may stop reading at DONE without losing the terminal audit.

    中文:客户端可以在 DONE 处停止读取,但最终审计记录仍会保留。"""

    store = ExchangeStore(tmp_path / "exchange.sqlite3")
    provider = Provider([ProviderChunk(delta="answer", finish_reason="stop")])
    response = _gateway(store, provider).handle_openai_chat(
        {"Authorization": "Bearer unit-secret"},
        _payload(stream=True),
        request_id="chatcmpl-audit-barrier",
    )
    try:
        for event in response.body:
            if event == "[DONE]":
                record = store.get_request_audit("chatcmpl-audit-barrier")
                assert record is not None
                assert record.status == RequestAuditStatus.COMPLETED
                break
        else:
            pytest.fail("stream did not complete")
    finally:
        response.body.close()
        store.close()


def test_failed_terminal_commit_never_emits_done(tmp_path: Path, monkeypatch) -> None:
    """A storage failure after model output must not claim durable completion.

    中文:模型输出后若发生存储故障,不得声称请求已持久完成。"""

    store = ExchangeStore(tmp_path / "exchange.sqlite3")
    provider = Provider([ProviderChunk(delta="answer", finish_reason="stop")])
    attempts = []

    def fail_commit(*args, **kwargs):
        attempts.append(kwargs["status"])
        raise OSError("controlled terminal write failure")

    monkeypatch.setattr(store, "finish_request", fail_commit)
    response = _gateway(store, provider).handle_openai_chat(
        {"Authorization": "Bearer unit-secret"},
        _payload(stream=True),
        request_id="chatcmpl-audit-write-failure",
    )
    observed = []
    try:
        with pytest.raises(GatewayLifecycleError):
            for event in response.body:
                observed.append(event)
        assert observed
        assert "[DONE]" not in observed
        assert attempts == ["completed"]
        assert provider.calls == 1
    finally:
        store.close()


def test_audit_requires_trusted_identity_and_one_provider_attempt(tmp_path: Path) -> None:
    """The V1 ledger cannot invent identity or hide a second provider request.

    中文:V1 台账不能虚构身份,也不能隐藏第二次提供方请求。"""

    store = ExchangeStore(tmp_path / "exchange.sqlite3")
    provider = Provider([ProviderChunk(delta="must not run")])
    try:
        with pytest.raises(ValueError, match="principal_resolver"):
            ExchangeGateway(
                Resolver(provider),
                lifecycle_observer=RequestAuditRecorder(store),
                max_route_attempts=1,
            )
        with pytest.raises(ValueError, match="one provider attempt"):
            ExchangeGateway(
                Resolver(provider),
                principal_resolver=store.resolve_credential,
                lifecycle_observer=RequestAuditRecorder(store),
                max_route_attempts=2,
            )
        assert provider.calls == 0
    finally:
        store.close()


def test_product_quota_is_persisted_and_uses_plugin_owned_total(tmp_path: Path) -> None:
    """Product owns the limit while the billing capability owns usage aggregation.

    中文:Product 负责限额,计费能力负责用量汇总。"""

    database = tmp_path / "exchange.sqlite3"
    store = ExchangeStore(database)
    quota = TenantQuota(
        tenant_id="actor-unit",
        workspace_id="workspace-unit",
        monthly_token_quota=100,
        updated_at=datetime.now(UTC),
    )
    store.save_tenant_quota(quota)
    store.close()

    reopened = ExchangeStore(database)
    billing = RecordingBillingClient()
    billing.totals["actor-unit"] = 100
    provider = Provider([ProviderChunk(delta="must not run")])
    reopened.configure_credentials(
        {"unit-secret": ProductPrincipal("actor-unit", "workspace-unit", "credential-unit")}
    )
    gateway = ExchangeGateway(
        Resolver(provider),
        principal_resolver=reopened.resolve_credential,
        quota_checker=ProductQuotaGuard(reopened, billing),
    )
    try:
        assert reopened.get_tenant_quota("actor-unit") == quota
        with pytest.raises(QuotaExceededError):
            gateway.handle_openai_chat(
                {"Authorization": "Bearer unit-secret"},
                _payload(),
            )
        assert provider.calls == 0

        unavailable_gateway = ExchangeGateway(
            Resolver(provider),
            principal_resolver=reopened.resolve_credential,
            quota_checker=ProductQuotaGuard(reopened, None),
        )
        with pytest.raises(QuotaUnavailableError):
            unavailable_gateway.handle_openai_chat(
                {"Authorization": "Bearer unit-secret"},
                _payload(),
            )
        assert provider.calls == 0
    finally:
        reopened.close()
