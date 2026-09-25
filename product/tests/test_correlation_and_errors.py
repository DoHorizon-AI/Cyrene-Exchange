"""Unit tests for Cyrene correlation hierarchy, header sanitization, and error mapping.

中文：Cyrene 关联层级、标头清理和错误映射的单元测试。"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.domain import ProductPrincipal
from cyrene_exchange_product.errors import (
    map_exchange_error,
)
from cyrene_exchange_product.logging import (
    format_cyrene_log,
    is_sensitive_key,
    parse_w3c_traceparent,
    redact_attributes,
    sanitize_operation_id,
    sanitize_request_id,
    sanitize_resource_id,
)


def test_w3c_traceparent_parsing() -> None:
    valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parsed = parse_w3c_traceparent(valid)
    assert parsed is not None
    trace_id, span_id = parsed
    assert trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert span_id == "00f067aa0ba902b7"

    # Reject invalid version
    # 中文：拒绝无效版本。
    assert parse_w3c_traceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") is None
    # Reject all-zero trace_id
    # 中文：拒绝全零 trace_id。
    assert parse_w3c_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01") is None
    # Reject all-zero span_id
    # 中文：拒绝全零 span_id。
    assert parse_w3c_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01") is None
    # Reject invalid length / hex
    # 中文：拒绝无效长度或十六进制值。
    assert parse_w3c_traceparent("00-short-00f067aa0ba902b7-01") is None
    assert parse_w3c_traceparent("") is None
    assert parse_w3c_traceparent(None) is None


def test_correlation_id_sanitization() -> None:
    # Control chars and newlines stripped
    # 中文：剔除控制字符和换行符。
    malicious = "req-123\r\nInjected-Header: evil\x00"
    sanitized = sanitize_request_id(malicious)
    assert sanitized == "req-123Injected-Header:evil"

    # Length bounding
    # 中文：限制长度。
    long_str = "x" * 300
    assert len(sanitize_request_id(long_str) or "") == 128
    assert len(sanitize_operation_id(long_str) or "") == 128
    assert len(sanitize_resource_id(long_str) or "") == 256


def test_sensitive_data_redaction() -> None:
    assert is_sensitive_key("authorization")
    assert is_sensitive_key("x-api-key")
    assert is_sensitive_key("token")
    assert is_sensitive_key("client_secret")
    assert not is_sensitive_key("request_id")
    assert not is_sensitive_key("status")

    attrs = {
        "request_id": "req-1",
        "api_key": "sk-secret-12345",
        "authorization": "Bearer token",
        "nested": {
            "password": "supersecret",
            "model": "qwen2.5",
        },
    }
    redacted = redact_attributes(attrs)
    assert redacted["request_id"] == "req-1"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["model"] == "qwen2.5"


def test_structured_log_formatting() -> None:
    log_line = format_cyrene_log(
        level="info",
        event_name="exchange.request.completed",
        message="Request processed successfully",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        attributes={
            "request_id": "req-123",
            "api_key": "secret-key",
            "tokens": 42,
        },
    )
    parsed = json.loads(log_line)
    assert parsed["schema_version"] == 1
    assert parsed["level"] == "INFO"
    assert parsed["event.name"] == "exchange.request.completed"
    assert parsed["service.name"] == "cyrene-exchange"
    assert parsed["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parsed["message"] == "Request processed successfully"
    assert parsed["attributes"]["request_id"] == "req-123"
    assert parsed["attributes"]["api_key"] == "[REDACTED]"
    assert parsed["attributes"]["tokens"] == 42


def test_error_mapping_catalog() -> None:
    m1 = map_exchange_error("EXCHANGE_CONTROL_PERMISSION_DENIED")
    assert m1.canonical_code == "PRODUCT.EXCHANGE.PERMISSION_DENIED"
    assert m1.cause_kind == "authorization"
    assert m1.status == 403

    m2 = map_exchange_error("EXCHANGE_TARGET_UNREACHABLE")
    assert m2.canonical_code == "PRODUCT.EXCHANGE.TARGET_UNREACHABLE"
    assert m2.cause_kind == "upstream_unreachable"
    assert m2.status == 502

    # Unknown code falls back safely
    # 中文：未知代码安全回退。
    m3 = map_exchange_error("CUSTOM_FAILURE")
    assert m3.canonical_code == "PRODUCT.EXCHANGE.CUSTOM_FAILURE"
    assert m3.cause_kind == "unknown"


def test_api_correlation_headers_and_error_response(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "exchange.db",
        control_credentials={
            "ctrl-key": ProductPrincipal(
                "actor-1", "ws-1", "api-key://11111111-1111-1111-1111-111111111111"
            )
        },
    )
    client = TestClient(app)

    # Valid W3C traceparent and request-id propagation
    # 中文：传播有效的 W3C traceparent 和 request-id。
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    response = client.get(
        "/api/v1/gateway-endpoints",
        headers={
            "traceparent": traceparent,
            "x-request-id": "client-req-001\r\nInjected: True",
            "Authorization": "Bearer ctrl-key",
        },
    )
    assert response.status_code == 200
    assert (
        response.headers["traceparent"] == "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000001-01"
    )
    # Malicious newlines stripped from x-request-id
    # 中文：剔除 x-request-id 中的恶意换行符。
    assert response.headers["x-request-id"] == "client-req-001Injected:True"

    # Error scenario: unauthenticated control call
    # 中文：错误场景：未认证的控制调用。
    err_response = client.get(
        "/api/v1/gateway-endpoints",
        headers={"traceparent": traceparent},
    )
    assert err_response.status_code == 403
    problem = err_response.json()
    assert problem["code"] == "EXCHANGE_CONTROL_PERMISSION_DENIED"
    assert problem["traceId"] == "4bf92f3577b34da6a3ce929d0e0e4736"
