"""Canonical binding between a verified Exchange actor and an Entra identity."""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

_TENANT_ISSUER = re.compile(
    r"https://login\.microsoftonline\.com/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/v2\.0\Z"
)


class MicrosoftActorMismatch(ValueError):
    """A valid Microsoft profile belongs to a different verified actor or tenant."""


def microsoft_identity_for_principal(principal: Any) -> tuple[str, str, str]:
    """Require a trusted original actor with a canonical tenant issuer and Entra OID.

    Exchange deliberately has no alias or client-side identity mapping for Microsoft
    profiles. The principal is created from Platform's verified signed context; its
    issuer and subject must already be the immutable Entra tenant/object identity.
    """

    issuer = getattr(principal, "issuer", None)
    subject = getattr(principal, "subject", None)
    if not isinstance(issuer, str) or not isinstance(subject, str):
        raise ValueError("Microsoft profiles require a verified Entra actor")
    match = _TENANT_ISSUER.fullmatch(issuer)
    if match is None:
        raise ValueError("Microsoft profiles require the canonical Entra tenant issuer")
    tenant_id = match.group(1)
    try:
        object_id = str(UUID(subject))
    except ValueError as exc:
        raise ValueError("Microsoft profiles require a canonical Entra object ID subject") from exc
    if subject != object_id:
        raise ValueError("Microsoft profiles require a lowercase canonical Entra object ID")
    return tenant_id, object_id, f"{tenant_id}:{object_id}"


def require_microsoft_profile_actor(
    principal: Any,
    *,
    external_subject: object,
    tenant_id: object | None = None,
) -> tuple[str, str, str]:
    """Require the current signed actor to own the exact delegated Microsoft identity."""

    actor_tenant, _object_id, actor_subject = microsoft_identity_for_principal(principal)
    if external_subject != actor_subject:
        raise MicrosoftActorMismatch("Microsoft profile belongs to a different Entra actor")
    if tenant_id is not None and tenant_id != actor_tenant:
        raise MicrosoftActorMismatch("Microsoft profile belongs to a different Entra tenant")
    return actor_tenant, _object_id, actor_subject
