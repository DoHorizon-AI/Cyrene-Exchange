"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 route_admission.py                                              │
│  Module: cyrene_exchange_product.route_admission                    │
│  Role: Verify source version and canonical provider before publish.│
│  模块职责：回读来源资源并验证既有 provider 通路后才允许启用草稿。            │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
from threading import Event
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from cyrene_exchange.capabilities import (
    MODEL_PROVIDER_CAPABILITY,
    CapabilityResolver,
    ModelProviderCapability,
)
from cyrene_exchange.protocol import NormalizedInferenceRequest

from cyrene_exchange_product.domain import GatewayRoute
from cyrene_exchange_product.errors import ExchangeProductError


class ReactorRouteAdmission:
    """Validate operator source access and the selected direct Plugin. | 发布校验。"""

    def __init__(
        self, *, reactor_base_url: str, reactor_token: str, resolver: CapabilityResolver
    ) -> None:
        self.base_url = reactor_base_url.rstrip("/")
        self.token = reactor_token
        self.resolver = resolver
        parsed = urlsplit(self.base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
            raise ValueError("Reactor source must be an origin without credentials or path")
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("remote Reactor source verification requires TLS")

    def __call__(self, route: GatewayRoute) -> None:
        """Verify source freshness and direct Plugin inference. | 校验来源及推理。"""
        source = route.source
        if source is None:
            self._reject("SOURCE_REFERENCE_REQUIRED", "A versioned Reactor Endpoint is required.")
        assert source is not None
        parsed = urlsplit(source.resource_uri)
        admitted = urlsplit(self.base_url)
        if (
            (parsed.scheme, parsed.netloc) != (admitted.scheme, admitted.netloc)
            or parsed.query
            or parsed.fragment
            or not re.fullmatch(r"/api/v1/endpoints/[0-9a-f-]{36}", parsed.path)
        ):
            self._reject(
                "SOURCE_PERMISSION_DENIED",
                "The source URI is outside the configured Reactor scope.",
                403,
            )
        try:
            with httpx.Client(
                timeout=45, trust_env=False, headers={"Authorization": "Bearer " + self.token}
            ) as client:
                response = client.get(source.resource_uri)
                response.raise_for_status()
                endpoint = response.json()
                if (
                    not isinstance(endpoint, dict)
                    or str(UUID(str(endpoint.get("id")))) != (parsed.path.rsplit("/", 1)[1])
                ):
                    self._reject("SOURCE_RESPONSE_INVALID", "The source identity is invalid.")
                if endpoint.get("resourceVersion") != source.resource_version:
                    self._reject(
                        "SOURCE_VERSION_CONFLICT",
                        "Refresh the source Endpoint and create a new draft.",
                    )
                if endpoint.get("protocol") != "openai.chat.v1":
                    self._reject(
                        "SOURCE_PROTOCOL_INCOMPATIBLE", "The source protocol is unsupported."
                    )
                if endpoint.get("state") != "READY":
                    self._reject("SOURCE_NOT_READY", "The source Endpoint is unavailable.")
                if endpoint.get("model") != route.target_model:
                    self._reject(
                        "SOURCE_MODEL_MISMATCH",
                        "The route model does not match the source Endpoint.",
                    )
                deployment_id = str(endpoint["deploymentId"])
                if not re.fullmatch(r"[0-9a-f-]{36}", deployment_id):
                    self._reject(
                        "SOURCE_RESPONSE_INVALID",
                        "The source returned an invalid resource identity.",
                    )
                deployment = client.get(self.base_url + "/api/v1/deployments/" + deployment_id)
                deployment.raise_for_status()
                deployment_body = deployment.json()
                if str(UUID(str(deployment_body["id"]))) != deployment_id:
                    self._reject("SOURCE_RESPONSE_INVALID", "The Deployment identity is invalid.")
                if deployment_body["modelArtifact"]["digest"] != source.artifact_digest:
                    self._reject(
                        "SOURCE_ARTIFACT_MISMATCH",
                        "The model Artifact differs from the inspected source.",
                    )
                version = deployment_body.get("modelVersion")
                version_id = version.get("id") if isinstance(version, dict) else None
                if source.model_version_id != version_id or (
                    deployment_body.get("composition") == "BASE_PLUS_LORA"
                    and source.model_version_id is None
                ):
                    self._reject(
                        "SOURCE_MODEL_VERSION_MISMATCH",
                        "The immutable ModelVersion differs from the inspected source.",
                    )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {401, 403}:
                self._reject(
                    "SOURCE_PERMISSION_DENIED", "Reactor denied source read permission.", 403
                )
            if exc.response.status_code == 404:
                self._reject(
                    "SOURCE_NOT_FOUND", "The referenced Reactor resource no longer exists.", 404
                )
            raise ExchangeProductError(
                code="EXCHANGE_SOURCE_UNREACHABLE",
                title="Source unavailable",
                detail="Reactor could not verify the source resource.",
                status=503,
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise ExchangeProductError(
                code="EXCHANGE_SOURCE_UNREACHABLE",
                title="Source verification failed",
                detail="Reactor is unreachable. Restore the source control path and retry.",
                status=503,
                retryable=True,
            ) from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise ExchangeProductError(
                code="EXCHANGE_SOURCE_RESPONSE_INVALID",
                title="Source response incompatible",
                detail="The source response does not match the Endpoint contract.",
                status=409,
            ) from exc
        cancel = Event()
        try:
            provider = cast(
                ModelProviderCapability,
                self.resolver.resolve(MODEL_PROVIDER_CAPABILITY, route.target_binding_id),
            )
            request = NormalizedInferenceRequest.from_openai(
                {
                    "model": route.target_model,
                    "messages": [{"role": "user", "content": "Reply with one word: ready"}],
                    "max_tokens": 8,
                    "temperature": 0,
                }
            )
            content = "".join(
                chunk.delta for chunk in provider.complete(request, cancel_event=cancel)
            )
            if not content.strip():
                self._reject(
                    "PROVIDER_PROBE_EMPTY", "The selected provider returned no model text.", 503
                )
        except ExchangeProductError:
            raise
        except Exception as exc:
            raise ExchangeProductError(
                code="EXCHANGE_PROVIDER_UNREACHABLE",
                title="Provider verification failed",
                detail="The canonical provider binding did not complete an inference probe.",
                status=503,
                retryable=True,
            ) from exc
        finally:
            cancel.set()

    @staticmethod
    def _reject(code: str, detail: str, status: int = 409) -> None:
        raise ExchangeProductError(
            code="EXCHANGE_" + code, title="Route target rejected", detail=detail, status=status
        )
