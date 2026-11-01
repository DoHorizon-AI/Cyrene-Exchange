"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 test_media_artifacts.py                                         │
│  Module: tests.test_media_artifacts                                 │
│  Role: Verify scoped Work attachment resolution and Product identity. │
│                                                                     │
│  模块职责：验证 Work 附件授权解析与 Product 身份传递。                    │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from cyrene_exchange.gateway import RequestCancelled, RequestPrincipal

from cyrene_exchange_product.domain import ProductPrincipal
from cyrene_exchange_product.media_artifacts import (
    MAX_WORK_ATTACHMENT_BYTES,
    WorkAttachmentCredential,
    WorkAttachmentHttpResolver,
)
from cyrene_exchange_product.routing import data_plane_principal_resolver
from cyrene_exchange_product.server import (
    HealthCheckedDirectPluginModelProvider,
    ProviderUnavailableError,
)
from cyrene_exchange_product.store import ExchangeStore


class _WorkAttachmentPeer(BaseHTTPRequestHandler):
    content = b"authorized-work-attachment"
    content_type = "image/png"
    status = 200
    declared_length: int | None = None
    requests: ClassVar[list[tuple[str, str, str]]] = []

    def do_GET(self) -> None:
        type(self).requests.append(
            (
                self.path,
                self.headers.get("Authorization", ""),
                self.headers.get("Accept", ""),
            )
        )
        if type(self).status == 302:
            self.send_response(302)
            self.send_header("Location", "/redirect-target")
            self.end_headers()
            return
        self.send_response(type(self).status)
        self.send_header("Content-Type", type(self).content_type)
        content_length = type(self).declared_length
        if content_length is None:
            content_length = len(type(self).content)
        self.send_header("Content-Length", str(content_length))
        self.end_headers()
        if type(self).status == 200:
            self.wfile.write(type(self).content)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def _work_peer() -> Iterator[ThreadingHTTPServer]:
    _WorkAttachmentPeer.content = b"authorized-work-attachment"
    _WorkAttachmentPeer.content_type = "image/png"
    _WorkAttachmentPeer.status = 200
    _WorkAttachmentPeer.declared_length = None
    _WorkAttachmentPeer.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WorkAttachmentPeer)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _resolver(server: ThreadingHTTPServer) -> WorkAttachmentHttpResolver:
    return WorkAttachmentHttpResolver(
        f"http://127.0.0.1:{server.server_port}",
        {
            "cred://exchange/data": WorkAttachmentCredential(
                actor_id="actor-a",
                workspace_id="workspace/a",
                credential_ref="cred://exchange/data",
                organization_id="org-a",
                token="separate-work-token",
            )
        },
    )


def _principal() -> RequestPrincipal:
    return RequestPrincipal(
        actor_id="actor-a",
        workspace_id="workspace/a",
        credential_ref="cred://exchange/data",
        organization_id="org-a",
    )


def test_work_attachment_read_is_principal_bound_and_digest_checked() -> None:
    with _work_peer() as server:
        resolver = _resolver(server)
        try:
            data = _WorkAttachmentPeer.content
            digest = hashlib.sha256(data).hexdigest()
            artifact = resolver.read(digest, principal=_principal(), cancel_event=Event())
            assert artifact.data == data
            assert artifact.sha256 == digest
            assert artifact.size == len(data)
            assert artifact.mime_type == "image/png"
            assert _WorkAttachmentPeer.requests == [
                (
                    f"/api/v1/workspaces/workspace%2Fa/work/attachments/{digest}",
                    "Bearer separate-work-token",
                    "image/*, audio/*, application/pdf, text/plain",
                )
            ]
        finally:
            resolver.close()


def test_work_attachment_denies_scope_mismatch_before_http_request() -> None:
    with _work_peer() as server:
        resolver = _resolver(server)
        try:
            other = RequestPrincipal(
                actor_id="actor-b",
                workspace_id="workspace/a",
                credential_ref="cred://exchange/data",
                organization_id="org-a",
            )
            digest = hashlib.sha256(_WorkAttachmentPeer.content).hexdigest()
            with pytest.raises(PermissionError):
                resolver.read(digest, principal=other, cancel_event=Event())
            assert _WorkAttachmentPeer.requests == []
        finally:
            resolver.close()


def test_work_attachment_does_not_follow_redirects_or_accept_bad_digest() -> None:
    with _work_peer() as server:
        resolver = _resolver(server)
        try:
            digest = hashlib.sha256(_WorkAttachmentPeer.content).hexdigest()
            _WorkAttachmentPeer.status = 302
            with pytest.raises(PermissionError):
                resolver.read(digest, principal=_principal(), cancel_event=Event())
            assert len(_WorkAttachmentPeer.requests) == 1

            _WorkAttachmentPeer.status = 200
            wrong_digest = hashlib.sha256(b"different-attachment").hexdigest()
            with pytest.raises(ValueError, match="do not match"):
                resolver.read(wrong_digest, principal=_principal(), cancel_event=Event())
        finally:
            resolver.close()


def test_work_attachment_rejects_oversize_and_cancelled_reads() -> None:
    with _work_peer() as server:
        resolver = _resolver(server)
        try:
            digest = hashlib.sha256(_WorkAttachmentPeer.content).hexdigest()
            _WorkAttachmentPeer.declared_length = MAX_WORK_ATTACHMENT_BYTES + 1
            with pytest.raises(ValueError, match="size limit"):
                resolver.read(digest, principal=_principal(), cancel_event=Event())

            cancel_event = Event()
            cancel_event.set()
            with pytest.raises(RequestCancelled):
                resolver.read(digest, principal=_principal(), cancel_event=cancel_event)
        finally:
            resolver.close()


def test_product_data_principal_preserves_organization_scope(tmp_path) -> None:
    store = ExchangeStore(tmp_path / "exchange.sqlite3")
    token = "gateway-data-secret"
    principal = ProductPrincipal(
        actor_id="actor-a",
        workspace_id="workspace/a",
        credential_ref="cred://exchange/data",
        organization_id="org-a",
    )
    try:
        store.configure_credentials({token: principal})
        resolved = data_plane_principal_resolver(store, {token: principal})(token)
        assert resolved is not None
        assert (resolved.actor_id, resolved.workspace_id, resolved.organization_id) == (
            "actor-a",
            "workspace/a",
            "org-a",
        )
    finally:
        store.close()


class _FakePluginClient:
    def close(self) -> None:
        return


class _FakePluginHealth:
    def __init__(self, **values: Any) -> None:
        self._values = values

    def observe(self) -> SimpleNamespace:
        return SimpleNamespace(**self._values)

    def close(self) -> None:
        return


def test_direct_plugin_binding_health_validates_connector_before_route_publish() -> None:
    route = SimpleNamespace(target_binding_id="binding:aether-model")
    valid = HealthCheckedDirectPluginModelProvider(
        "binding:aether-model",
        _FakePluginClient(),
        _FakePluginHealth(
            status="SERVING",
            plugin_id="cyrene.providers.model-api-connector",
            capabilities=("model.provider.v1",),
        ),
    )
    valid.validate_route(route)

    unavailable = HealthCheckedDirectPluginModelProvider(
        "binding:aether-model",
        _FakePluginClient(),
        _FakePluginHealth(
            status="SERVING",
            plugin_id="wrong-plugin",
            capabilities=("model.provider.v1",),
        ),
    )
    with pytest.raises(ProviderUnavailableError, match="not serving"):
        unavailable.validate_route(route)
