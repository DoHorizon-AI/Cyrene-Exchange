"""Privileged, one-shot connector profile provisioning for a trusted host operator.

This command is a local configuration-plane operation. It does not add an HTTP
route or accept a bearer token from the bootstrap file. Platform Authority
issues one fresh, signed connector grant solely to verify the configured actor's
current Directory membership and connector-operator role before provisioning.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.api import _provider_profile_ref
from cyrene_exchange_product.integrations.connector_operations import _resource_ref
from cyrene_exchange_product.integrations.connector_security import digest_arguments
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationPrincipal,
)

_MAX_BOOTSTRAP_BYTES = 64 * 1024


def provision_connector_profiles(
    services: Any,
    bootstrap_file: Path | str,
    *,
    plan_only: bool = False,
) -> dict[str, Any]:
    """Link GitHub/HF profiles and persist exact actor or shared connections."""

    specification = _read_bootstrap_file(Path(bootstrap_file))
    authority = services.connector_grant_authority
    verifier = services.connector_grant_verifier
    registry = services.authorization_profile_registry
    if authority is None or verifier is None:
        raise _bootstrap_error("connector_bootstrap_not_configured")

    actor = _object(
        specification["actor"],
        required={"issuer", "subject", "organizationId", "workspaceId"},
        label="bootstrap actor",
    )
    issuer = _text(actor["issuer"], "actor issuer")
    subject = _text(actor["subject"], "actor subject")
    organization_id = _text(actor["organizationId"], "actor organizationId")
    workspace_id = _text(actor["workspaceId"], "actor workspaceId")
    hf_spec: dict[str, Any] | None = None
    hf_alias = ""
    hf_target_alias = ""
    hf_idempotency_key = ""
    hf_expected_access_mode = "actor_owned"
    hf_profile_config = None
    if "huggingface" in specification:
        if registry is None:
            raise _bootstrap_error("huggingface_host_profile_not_configured")
        hf_spec = _object(
            specification["huggingface"],
            required={
                "profileAlias",
                "targetAlias",
                "profileIdempotencyKey",
                "credentialSecretRef",
            },
            optional={"expectedAccessMode"},
            label="bootstrap Hugging Face settings",
        )
        hf_alias = _text(hf_spec["profileAlias"], "HF profileAlias")
        hf_target_alias = _text(hf_spec["targetAlias"], "HF targetAlias")
        hf_idempotency_key = _text(hf_spec["profileIdempotencyKey"], "HF profileIdempotencyKey")
        hf_expected_access_mode = _expected_access_mode(hf_spec.get("expectedAccessMode"))
        hf_profile_config = registry.settings.profiles.get(hf_alias)
        if (
            hf_profile_config is None
            or hf_profile_config.provider != "hf"
            or hf_profile_config.credential_secret_ref != hf_spec["credentialSecretRef"]
            or hf_profile_config.account_scopes is None
            or hf_target_alias not in hf_profile_config.targets
            or hf_profile_config.organization_id != organization_id
            or hf_profile_config.workspace_id != workspace_id
            or hf_profile_config.expected_issuer != issuer
            or hf_profile_config.access_mode != hf_expected_access_mode
            or (
                hf_profile_config.access_mode == "actor_owned"
                and (issuer, subject) not in hf_profile_config.allowed_actors
            )
        ):
            raise _bootstrap_error("huggingface_host_profile_scope_mismatch")

    github_spec = _object(
        specification["github"],
        required={"installationId", "profileIdempotencyKey", "repositories"},
        optional={"expectedAccessMode"},
        label="bootstrap GitHub settings",
    )
    installation_id = _text(github_spec["installationId"], "GitHub installationId")
    github_idempotency_key = _text(
        github_spec["profileIdempotencyKey"], "GitHub profileIdempotencyKey"
    )
    repositories = _repositories(github_spec["repositories"])
    github_access_mode = _expected_access_mode(github_spec.get("expectedAccessMode"))
    github_profile_ref = _provider_profile_ref(
        _unverified_actor(issuer, subject, organization_id, workspace_id),
        github_idempotency_key,
    )
    github_connection_ids = {
        repository["repository_id"]: _stable_connection_id(
            issuer=issuer,
            subject=subject,
            workspace_id=workspace_id,
            provider="github",
            profile_ref=github_profile_ref,
            target=repository["repository_id"],
        )
        for repository in repositories
    }

    # This exact supported connector grant is only a fresh Directory role proof
    # for the privileged local bootstrap. It is not reused for profile-link calls.
    proof_connection_id = next(iter(github_connection_ids.values()))
    grant_arguments: dict[str, object] = {}
    grant_operation = "github.repository.list"
    grant_request_id = str(uuid4())
    grant_resource_ref = _resource_ref(
        provider_id="github",
        profile_ref=github_profile_ref,
        operation_id=grant_operation,
        target={"profile_ref": github_profile_ref},
    )
    arguments_digest = bytes.fromhex(digest_arguments(grant_arguments))
    grant_bytes = authority.authorize_connector_operation(
        workspace_id=workspace_id,
        principal_issuer=issuer,
        principal_subject=subject,
        connection_ref=str(proof_connection_id),
        provider_id="github",
        profile_ref=github_profile_ref,
        operation_id=grant_operation,
        resource_ref=grant_resource_ref,
        arguments_digest_sha256=arguments_digest,
        request_id=grant_request_id,
    )
    expected = {
        "request_id": grant_request_id,
        "organization_id": organization_id,
        "workspace_id": workspace_id,
        "principal_issuer": issuer,
        "principal_subject": subject,
        "connection_ref": str(proof_connection_id),
        "provider_id": "github",
        "profile_ref": github_profile_ref,
        "operation_id": grant_operation,
        "resource_ref": grant_resource_ref,
        "arguments_digest_sha256": arguments_digest,
    }
    verifier.validate_authority_response(grant_bytes, expected=expected)
    claims = verifier.consume(grant_bytes, expected=expected)
    principal = IntegrationPrincipal(
        issuer=claims.principal_issuer,
        subject=claims.principal_subject,
        organization_id=claims.organization_id,
        workspace_id=claims.workspace_id,
        allowed_operation_ids=frozenset(
            {"navigator.connector.operator.v1", "integrationCreateConnection"}
        ),
    )

    _validate_host_actor_scope(
        principal,
        services=services,
        specification=specification,
    )
    if plan_only:
        plan: dict[str, Any] = {
            "schemaVersion": 1,
            "directoryRoleVerified": True,
            "profiles": {
                "github": {
                    "profileRef": github_profile_ref,
                    "expectedAccessMode": github_access_mode,
                    "connections": [
                        {
                            "connectionRef": str(github_connection_ids[item["repository_id"]]),
                            "repositoryId": item["repository_id"],
                        }
                        for item in repositories
                    ],
                }
            },
        }
        if hf_spec is not None:
            hf_profile_ref = _provider_profile_ref(principal, hf_idempotency_key)
            plan["profiles"]["huggingface"] = {
                "profileRef": hf_profile_ref,
                "connectionRef": str(
                    _stable_connection_id(
                        issuer=issuer,
                        subject=subject,
                        workspace_id=workspace_id,
                        provider="hf",
                        profile_ref=hf_profile_ref,
                        target=hf_target_alias,
                    )
                ),
                "targetAlias": hf_target_alias,
                "expectedAccessMode": hf_expected_access_mode,
            }
        return plan

    github_profile = services.accounts.link_github_app_installation(
        principal,
        profile_ref=github_profile_ref,
        installation_id=installation_id,
        repositories=repositories,
        idempotency_key=github_idempotency_key,
    )
    _verify_linked_profile(
        github_profile,
        profile_ref=github_profile_ref,
        provider="github",
    )
    github_access_mode = _verify_profile_readback(
        services.accounts.list_provider_profiles(principal),
        profile_ref=github_profile_ref,
        provider="github",
        expected_access_mode=github_access_mode,
    )

    github_connection_rows: list[dict[str, str]] = []
    for repository in repositories:
        request = CreateIntegrationConnection(
            provider="github",
            account_link_ref=github_profile_ref,
            repository_id=repository["repository_id"],
            repository_name=repository["owner"] + "/" + repository["name"],
            display_name=repository["owner"] + "/" + repository["name"],
        )
        connection = services.store.create_connection(
            principal,
            request,
            idempotency_key=(
                f"connector-bootstrap/github/{github_profile_ref}/{repository['repository_id']}"
            ),
            connection_id=github_connection_ids[repository["repository_id"]],
            access_mode=github_access_mode,
        )
        github_connection_rows.append(
            {
                "connectionRef": str(connection.id),
                "repositoryId": repository["repository_id"],
                "repository": connection.repository_name,
                "profileRef": github_profile_ref,
            }
        )

    result: dict[str, Any] = {
        "schemaVersion": 1,
        "directoryRoleVerified": True,
        "github": {
            "profileRef": github_profile_ref,
            "accessMode": github_access_mode,
            "connections": github_connection_rows,
        },
    }
    if hf_spec is not None and hf_profile_config is not None:
        hf_profile_ref = _provider_profile_ref(principal, hf_idempotency_key)
        hf_profile = services.accounts.link_huggingface_profile(
            principal,
            profile_ref=hf_profile_ref,
            credential_secret_ref=hf_profile_config.credential_secret_ref,
            scopes=hf_profile_config.account_scopes,
            idempotency_key=hf_idempotency_key,
            auth_mode=hf_profile_config.auth_mode,
        )
        _verify_linked_profile(hf_profile, profile_ref=hf_profile_ref, provider="huggingface")
        hf_access_mode = _verify_profile_readback(
            services.accounts.list_provider_profiles(principal),
            profile_ref=hf_profile_ref,
            provider="huggingface",
            expected_auth_mode=hf_profile_config.auth_mode or "fine_grained_token",
            expected_access_mode=hf_expected_access_mode,
        )

        hf_connection_id = _stable_connection_id(
            issuer=issuer,
            subject=subject,
            workspace_id=workspace_id,
            provider="hf",
            profile_ref=hf_profile_ref,
            target=hf_target_alias,
        )
        hf_connection = services.store.create_connection(
            principal,
            CreateIntegrationConnection(
                provider="hf",
                binding_ref=hf_alias,
                target_ref=hf_target_alias,
                account_link_ref=hf_profile_ref,
                display_name=hf_profile_config.targets[hf_target_alias].display_name,
            ),
            idempotency_key=(f"connector-bootstrap/huggingface/{hf_profile_ref}/{hf_target_alias}"),
            connection_id=hf_connection_id,
            access_mode=hf_access_mode,
        )
        result["huggingface"] = {
            "profileRef": hf_profile_ref,
            "connectionRef": str(hf_connection.id),
            "targetAlias": hf_target_alias,
            "accessMode": hf_access_mode,
            "authMode": hf_profile_config.auth_mode or "fine_grained_token",
        }
    return result


def _read_bootstrap_file(path: Path) -> dict[str, Any]:
    """Read a private, bounded operator file without exposing its contents."""

    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_size <= 0
            or info.st_size > _MAX_BOOTSTRAP_BYTES
        ):
            raise ValueError("bootstrap file must be a bounded private regular file")
        value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_pairs)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise _bootstrap_error("private_bootstrap_file_invalid") from exc
    return _object(
        value,
        required={"schemaVersion", "actor", "github"},
        optional={"huggingface"},
        label="private connector bootstrap file",
        expected_version=1,
    )


def _validate_host_actor_scope(
    principal: IntegrationPrincipal,
    *,
    services: Any,
    specification: Mapping[str, Any],
) -> None:
    """Ensure the verified Directory identity matches both fixed host bindings."""

    teams_profile = services.teams_message_profile
    if (
        teams_profile is None
        or teams_profile.expected_issuer != principal.issuer
        or teams_profile.organization_id != principal.organization_id
        or teams_profile.workspace_id != principal.workspace_id
    ):
        raise _bootstrap_error("bootstrap_actor_host_scope_mismatch")
    actor = specification["actor"]
    if (
        actor["issuer"] != principal.issuer
        or actor["subject"] != principal.subject
        or actor["organizationId"] != principal.organization_id
        or actor["workspaceId"] != principal.workspace_id
    ):
        raise _bootstrap_error("bootstrap_actor_directory_scope_mismatch")


def _repositories(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 200:
        raise _bootstrap_error("github_repository_scope_invalid")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in value:
        repository = _object(
            raw,
            required={"repositoryId", "owner", "name"},
            label="GitHub repository scope",
        )
        repository_id = _text(repository["repositoryId"], "repositoryId")
        owner = _text(repository["owner"], "repository owner")
        name = _text(repository["name"], "repository name")
        if repository_id in seen:
            raise _bootstrap_error("github_repository_scope_duplicate")
        seen.add(repository_id)
        result.append({"repository_id": repository_id, "owner": owner, "name": name})
    return result


def _verify_linked_profile(
    response: object,
    *,
    profile_ref: str,
    provider: str,
) -> None:
    if not isinstance(response, Mapping) or (
        response.get("profile_ref") != profile_ref
        or response.get("provider") != provider
        or response.get("auth_status") != "healthy"
    ):
        raise _bootstrap_error(f"{provider}_profile_link_not_healthy")


def _verify_profile_readback(
    response: object,
    *,
    profile_ref: str,
    provider: str,
    expected_auth_mode: str | None = None,
    expected_access_mode: str = "actor_owned",
) -> str:
    profiles = response.get("profiles") if isinstance(response, Mapping) else None
    matches = (
        [
            item
            for item in profiles
            if isinstance(item, Mapping)
            and item.get("profile_ref") == profile_ref
            and item.get("provider") == provider
            and item.get("auth_status") == "healthy"
            and (
                expected_auth_mode is None
                or item.get("auth_mode") == expected_auth_mode
                or (expected_auth_mode == "fine_grained_token" and item.get("auth_mode") is None)
            )
        ]
        if isinstance(profiles, list)
        else []
    )
    if len(matches) != 1:
        raise _bootstrap_error(f"{provider}_profile_readback_not_healthy")
    access_mode = matches[0].get("access_mode", "actor_owned")
    if not isinstance(access_mode, str) or access_mode not in {
        "actor_owned",
        "workspace_operator",
    }:
        raise _bootstrap_error(f"{provider}_profile_access_mode_invalid")
    if access_mode != expected_access_mode:
        raise _bootstrap_error(f"{provider}_profile_access_mode_mismatch")
    return str(access_mode)


def _expected_access_mode(value: object) -> str:
    if value is None:
        return "actor_owned"
    if not isinstance(value, str) or value not in {"actor_owned", "workspace_operator"}:
        raise _bootstrap_error("connector_bootstrap_access_mode_invalid")
    return str(value)


def _stable_connection_id(
    *,
    issuer: str,
    subject: str,
    workspace_id: str,
    provider: str,
    profile_ref: str,
    target: str,
) -> UUID:
    seed = ":".join((issuer, subject, workspace_id, provider, profile_ref, target))
    return uuid5(NAMESPACE_URL, f"cyrene-connector-bootstrap:{seed}")


def _unverified_actor(
    issuer: str,
    subject: str,
    organization_id: str,
    workspace_id: str,
) -> IntegrationPrincipal:
    """Build a data-only selector; it is never used for authorization or a side effect."""

    return IntegrationPrincipal(
        issuer=issuer,
        subject=subject,
        organization_id=organization_id,
        workspace_id=workspace_id,
        allowed_operation_ids=frozenset(),
    )


def _object(
    value: object,
    *,
    required: set[str],
    optional: set[str] | frozenset[str] = frozenset(),
    label: str,
    expected_version: int | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or set(value) - required - optional
    ):
        raise _bootstrap_error(f"{label.replace(' ', '_')}_invalid")
    result = dict(value)
    if expected_version is not None:
        version = result.get("schemaVersion")
        if isinstance(version, bool) or version != expected_version:
            raise _bootstrap_error("private_bootstrap_version_unsupported")
    return result


def _text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 1024
    ):
        raise _bootstrap_error(f"{label.replace(' ', '_')}_invalid")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bootstrap_error(reason_code: str) -> ExchangeProductError:
    return ExchangeProductError(
        code="EXCHANGE_CONNECTOR_BOOTSTRAP_INVALID",
        title="Connector bootstrap failed",
        detail=(
            "Private connector provisioning did not complete. Check host configuration "
            "and authorization."
        ),
        status=403 if "scope" in reason_code or "directory" in reason_code else 503,
        retryable=reason_code.endswith("unavailable"),
        context={"reasonCode": reason_code},
    )
