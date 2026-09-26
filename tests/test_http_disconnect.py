"""Cover cancellation when the reference HTTP peer socket fails.

中文:覆盖参考 HTTP 对端套接字故障时的取消处理。"""

from __future__ import annotations

import socket
from threading import Event

import pytest

from cyrene_exchange import http as exchange_http


def test_select_failure_cancels_inflight_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_select(*_args: object) -> None:
        raise OSError("peer socket failed")

    monkeypatch.setattr(exchange_http.select, "select", fail_select)
    cancelled = Event()
    with socket.socket() as connection:
        exchange_http._watch_client_disconnect(connection, cancelled, Event())
    assert cancelled.is_set()
