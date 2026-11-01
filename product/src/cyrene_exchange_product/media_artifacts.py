"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 media_artifacts.py                                              │
│  Module: cyrene_exchange_product.media_artifacts                    │
│  Role: Resolve authorized Work attachments for model requests.       │
│                                                                     │
│  模块职责：按可信主体读取 Work 附件，并校验内容身份。                     │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import Event
from urllib.parse import quote, urlsplit

import httpx
from cyrene_exchange.gateway import (
    RequestCancelled,
    RequestPrincipal,
    ResolvedMediaArtifact,
)

_ARTIFACT_ID = re.compile(r"^[0-9a-f]{64}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
MAX_WORK_ATTACHMENT_BYTES = 10_000_000


@dataclass(frozen=True, slots=True)
class WorkAttachmentCredential:
    """A separate Work bearer bound to one exact Exchange principal scope.

    中文：独立 Work Bearer 凭据，固定绑定到一个 Exchange principal 范围。
    """

    actor_id: str
    workspace_id: str
    credential_ref: str
    token: str = field(repr=False)
    organization_id: str | None = None


class WorkAttachmentHttpResolver:
    """Read a digest only through the matching Workspace-authorized Work API.

    Work credentials are configured out of band and selected by the trusted
    Exchange credential reference. The caller cannot supply a Work token,
    workspace, URL, or filesystem path.

    中文：只通过匹配的 Workspace 授权 Work API 读取 digest。Work 凭据由服务端
    独立配置，并按 Exchange 可信凭据引用选择；调用方无法传入令牌、workspace、URL 或本地路径。
    """

    def __init__(
        self,
        origin: str,
        credentials: Mapping[str, WorkAttachmentCredential],
        *,
        timeout_seconds: float = 10.0,
        max_bytes: int = MAX_WORK_ATTACHMENT_BYTES,
    ) -> None:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Work attachment origin must be an http(s) origin")
        if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
            raise ValueError("remote Work attachment origins require HTTPS")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("Work attachment timeout must be between 0 and 60 seconds")
        if max_bytes <= 0 or max_bytes > MAX_WORK_ATTACHMENT_BYTES:
            raise ValueError("Work attachment size limit exceeds the Work API limit")
        if not credentials:
            raise ValueError("at least one scoped Work attachment credential is required")
        if any(key != profile.credential_ref for key, profile in credentials.items()):
            raise ValueError("Work attachment credentials must be keyed by credential_ref")
        self._origin = origin.rstrip("/")
        self._credentials = dict(credentials)
        self._max_bytes = max_bytes
        self._timeout = httpx.Timeout(timeout_seconds)
        self._client = httpx.Client(
            timeout=self._timeout,
            trust_env=False,
            follow_redirects=False,
        )

    def read(
        self,
        artifact_id: str,
        *,
        principal: RequestPrincipal,
        cancel_event: Event,
    ) -> ResolvedMediaArtifact:
        """Fetch one authorized attachment, with bounded bytes and digest check.

        Raises on unknown principals, denied or missing attachments, redirects,
        malformed metadata, oversize content, and cancellation.

        中文：读取一份已授权附件，并限制字节数及校验摘要；主体不匹配、无权访问、重定向、元数据异常、超限或取消时失败。
        """

        if cancel_event.is_set():
            raise RequestCancelled("request was cancelled while resolving media")
        if not isinstance(artifact_id, str) or _ARTIFACT_ID.fullmatch(artifact_id) is None:
            raise ValueError("Work attachment id must be a lowercase SHA-256 digest")
        profile = self._credentials.get(principal.credential_ref)
        if profile is None or (
            profile.actor_id != principal.actor_id
            or profile.workspace_id != principal.workspace_id
            or profile.organization_id != principal.organization_id
        ):
            raise PermissionError("no Work attachment profile matches this Exchange principal")
        if not profile.token.strip():
            raise PermissionError("the configured Work attachment credential is empty")

        workspace_path = quote(profile.workspace_id, safe="")
        url = f"{self._origin}/api/v1/workspaces/{workspace_path}/work/attachments/{artifact_id}"
        headers = {
            "Authorization": f"Bearer {profile.token}",
            "Accept": "image/*, audio/*, application/pdf, text/plain",
        }
        if cancel_event.is_set():
            raise RequestCancelled("request was cancelled while resolving media")
        with self._client.stream(
            "GET",
            url,
            headers=headers,
            timeout=self._timeout,
            follow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise PermissionError("Work did not authorize or find this attachment")
            raw_length = response.headers.get("content-length")
            if raw_length is not None:
                try:
                    declared_length = int(raw_length)
                except ValueError as exc:
                    raise ValueError("Work attachment length is invalid") from exc
                if declared_length < 0 or declared_length > self._max_bytes:
                    raise ValueError("Work attachment exceeds the configured size limit")
            mime_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if _MEDIA_TYPE.fullmatch(mime_type) is None:
                raise ValueError("Work attachment MIME type is invalid")
            content = bytearray()
            for chunk in response.iter_bytes():
                if cancel_event.is_set():
                    raise RequestCancelled("request was cancelled while resolving media")
                content.extend(chunk)
                if len(content) > self._max_bytes:
                    raise ValueError("Work attachment exceeds the configured size limit")
        if cancel_event.is_set():
            raise RequestCancelled("request was cancelled while resolving media")
        data = bytes(content)
        if not data:
            raise ValueError("Work returned an empty attachment")
        digest = hashlib.sha256(data).hexdigest()
        if digest != artifact_id:
            raise ValueError("Work attachment bytes do not match the requested digest")
        return ResolvedMediaArtifact(mime_type, data, digest, len(data))

    def close(self) -> None:
        """Close the internally owned HTTP connection pool."""

        self._client.close()


def _is_loopback(hostname: str) -> bool:
    """Recognize loopback hostnames without accepting remote cleartext HTTP."""

    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


__all__ = [
    "MAX_WORK_ATTACHMENT_BYTES",
    "WorkAttachmentCredential",
    "WorkAttachmentHttpResolver",
]
