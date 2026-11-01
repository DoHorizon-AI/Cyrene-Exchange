"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 azure_devops.py                                                 │
│  Module: cyrene_exchange_product.integrations.azure_devops          │
│  Role: Validate fixed ADO source scopes and read operation targets.   │
│                                                                      │
│  模块职责：校验 ADO 授权来源及固定只读操作目标。                         │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.microsoft_identity import require_microsoft_profile_actor

SOURCE_KINDS = frozenset({"project_pipelines", "pipeline_runs", "release_deployments"})
ADO_OBSERVATION_OPERATIONS = frozenset(
    {
        "azure_devops.observations.poll",
        "azure_devops.pipelines.list",
        "azure_devops.pipeline_runs.list",
        "azure_devops.pipeline_run.get",
        "azure_devops.deployments.list",
        "azure_devops.release_environment.get",
    }
)
_OPAQUE_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,299}\Z")
_ORGANIZATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}\Z")
_BINDING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~:-]{1,2048}\Z")


def validate_profile_scope(value: object) -> dict[str, Any]:
    """Validate the exact single-source scope committed by Account Center."""

    required = {"tenant_id", "organization", "project_id", "source_id", "source_kind"}
    optional = {"pipeline_id", "definition_id", "definition_environment_id"}
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or set(value) - required - optional
    ):
        raise ValueError("Account Center returned an invalid Azure DevOps source scope")
    tenant_id = _uuid(value.get("tenant_id"), "tenant_id")
    project_id = _uuid(value.get("project_id"), "project_id")
    organization = value.get("organization")
    source_id = _source_id(value.get("source_id"), "source_id")
    source_kind = value.get("source_kind")
    if not isinstance(organization, str) or _ORGANIZATION.fullmatch(organization) is None:
        raise ValueError("Account Center returned an invalid Azure DevOps organization")
    if not isinstance(source_kind, str) or source_kind not in SOURCE_KINDS:
        raise ValueError("Account Center returned an unsupported Azure DevOps source kind")

    pipeline_id = value.get("pipeline_id")
    definition_id = value.get("definition_id")
    environment_id = value.get("definition_environment_id")
    if source_kind == "pipeline_runs":
        if set(value) != required | {"pipeline_id"}:
            raise ValueError("Azure DevOps pipeline source scope requires only pipeline_id")
        pipeline_id = _positive_id(pipeline_id, "pipeline_id")
    elif source_kind == "release_deployments":
        if set(value) not in (
            required | {"definition_id"},
            required | {"definition_id", "definition_environment_id"},
        ):
            raise ValueError("Azure DevOps release source scope is incomplete")
        definition_id = _positive_id(definition_id, "definition_id")
        if environment_id is not None:
            environment_id = _positive_id(environment_id, "definition_environment_id")
    elif set(value) != required:
        raise ValueError("Azure DevOps project pipeline scope cannot include run filters")

    return {
        "tenant_id": tenant_id,
        "organization": organization,
        "project_id": project_id,
        "source_id": source_id,
        "source_kind": source_kind,
        **({"pipeline_id": pipeline_id} if pipeline_id is not None else {}),
        **({"definition_id": definition_id} if definition_id is not None else {}),
        **({"definition_environment_id": environment_id} if environment_id is not None else {}),
    }


def validate_authorized_source(
    value: object,
    *,
    tenant_id: str,
    organization: str,
) -> dict[str, Any]:
    """Validate one provider-canonical host `authorized_sources` row."""

    if not isinstance(value, Mapping):
        raise ValueError("authorized_sources contains a non-object row")
    required = {"source_id", "kind", "project_id", "project_name", "profile_ref"}
    optional = {"pipeline_id", "definition_id", "definition_environment_id"}
    if not required <= set(value) or set(value) - required - optional:
        raise ValueError("authorized_sources row does not match the provider schema")
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in SOURCE_KINDS:
        raise ValueError("authorized_sources has an unsupported source kind")
    profile_ref = value.get("profile_ref")
    try:
        profile_ref = str(UUID(str(profile_ref)))
    except ValueError as exc:
        raise ValueError("authorized_sources profile_ref must be a UUID") from exc
    project_name = value.get("project_name")
    if (
        not isinstance(project_name, str)
        or not project_name
        or len(project_name) > 300
        or project_name.strip() != project_name
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in project_name)
    ):
        raise ValueError("authorized_sources project_name is invalid")
    scope = {
        "tenant_id": tenant_id,
        "organization": organization,
        "project_id": value.get("project_id"),
        "source_id": value.get("source_id"),
        "source_kind": kind,
        **({"pipeline_id": value["pipeline_id"]} if "pipeline_id" in value else {}),
        **({"definition_id": value["definition_id"]} if "definition_id" in value else {}),
        **(
            {"definition_environment_id": value["definition_environment_id"]}
            if "definition_environment_id" in value
            else {}
        ),
    }
    normalized_scope = validate_profile_scope(scope)
    normalized = {
        "source_id": normalized_scope["source_id"],
        "kind": normalized_scope["source_kind"],
        "project_id": normalized_scope["project_id"],
        "project_name": project_name,
        "profile_ref": profile_ref,
        **(
            {"pipeline_id": normalized_scope["pipeline_id"]}
            if "pipeline_id" in normalized_scope
            else {}
        ),
        **(
            {"definition_id": normalized_scope["definition_id"]}
            if "definition_id" in normalized_scope
            else {}
        ),
        **(
            {"definition_environment_id": normalized_scope["definition_environment_id"]}
            if "definition_environment_id" in normalized_scope
            else {}
        ),
    }
    return normalized


def scope_for_authorized_source(
    *,
    tenant_id: str,
    organization: str,
    source: Mapping[str, object],
) -> dict[str, Any]:
    """Build the exact Account Center tuple for one canonical host source row."""

    normalized_source = validate_authorized_source(
        source,
        tenant_id=tenant_id,
        organization=organization,
    )
    return validate_profile_scope(
        {
            "tenant_id": tenant_id,
            "organization": organization,
            "project_id": normalized_source["project_id"],
            "source_id": normalized_source["source_id"],
            "source_kind": normalized_source["kind"],
            **(
                {"pipeline_id": normalized_source["pipeline_id"]}
                if "pipeline_id" in normalized_source
                else {}
            ),
            **(
                {"definition_id": normalized_source["definition_id"]}
                if "definition_id" in normalized_source
                else {}
            ),
            **(
                {"definition_environment_id": normalized_source["definition_environment_id"]}
                if "definition_environment_id" in normalized_source
                else {}
            ),
        }
    )


def validate_profile_identity(
    row: Mapping[str, Any],
    *,
    profile_ref: str,
    principal: Any | None = None,
) -> dict[str, Any]:
    """Require the immutable Entra subject and actor-owned ADO profile to match."""

    subject = row.get("external_subject")
    identity_ref = row.get("identity_ref")
    if (
        row.get("profile_ref") != profile_ref
        or row.get("provider") != "azure_devops"
        or row.get("auth_mode") != "delegated_oauth"
        or row.get("access_mode", "actor_owned") != "actor_owned"
        or not isinstance(subject, str)
        or subject != identity_ref
    ):
        raise ValueError("Account Center returned a mismatched Azure DevOps identity")
    parts = subject.split(":", maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Account Center returned an invalid Azure DevOps subject")
    scope = validate_profile_scope(row.get("target_scope"))
    if parts[0] != scope["tenant_id"]:
        raise ValueError("Account Center Azure DevOps subject tenant does not match its scope")
    object_id = _uuid(parts[1], "external_subject object ID")
    if parts[1] != object_id:
        raise ValueError("Account Center Azure DevOps object ID is not canonical")
    if principal is not None:
        require_microsoft_profile_actor(
            principal,
            external_subject=subject,
            tenant_id=scope["tenant_id"],
        )
    expires_at = row.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
        raise ValueError("Account Center returned an invalid Azure DevOps token expiry")
    oauth_scopes = row.get("oauth_scopes")
    if oauth_scopes != ["https://app.vssps.visualstudio.com/.default"]:
        raise ValueError("Account Center returned an unsupported Azure DevOps OAuth scope")
    return scope


def targets_for_operation(
    operation_id: str,
    arguments: Mapping[str, object],
    profile_scope: Mapping[str, Any],
    *,
    binding_id: str,
    selected_source_id: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate one closed ADO payload and derive Directory and lease targets."""

    if operation_id not in ADO_OBSERVATION_OPERATIONS:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_OPERATION_INVALID",
            title="Azure DevOps operation is not enabled",
            detail="The operation is outside Exchange's fixed observation allowlist.",
            status=422,
            context={"reasonCode": "azure_devops_operation_not_allowlisted"},
        )
    scope = validate_profile_scope(profile_scope)
    _source_id(selected_source_id, "selected source")
    if selected_source_id != scope["source_id"]:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps source is outside the linked profile scope",
            detail="The selected source does not match the actor-owned Account Center profile.",
            status=403,
            context={"reasonCode": "azure_devops_source_scope_mismatch"},
        )
    if not isinstance(binding_id, str) or _BINDING_ID.fullmatch(binding_id) is None:
        raise ValueError("Azure DevOps provider binding ID is invalid")
    _exact_fields(arguments, required={"target"}, optional=_optional_fields(operation_id))
    target = arguments.get("target")
    if not isinstance(target, Mapping) or set(target) != {"id", "kind", "bindingId"}:
        raise ValueError("Azure DevOps target must contain exactly id, kind, and bindingId")
    target_id = _source_id(target.get("id"), "target.id")
    target_kind = target.get("kind")
    target_binding = target.get("bindingId")
    if target_id != scope["source_id"] or target_kind != scope["source_kind"]:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps target does not match the linked source",
            detail="The target ID and kind must match the selected host-authorized source.",
            status=403,
            context={"reasonCode": "azure_devops_source_scope_mismatch"},
        )
    if target_binding != binding_id:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps target binding is invalid",
            detail="The target must use the fixed host provider binding ID.",
            status=403,
            context={"reasonCode": "azure_devops_binding_scope_mismatch"},
        )
    expected_kind = _expected_source_kind(operation_id)
    if expected_kind is not None and scope["source_kind"] != expected_kind:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps operation does not match this source kind",
            detail="The operation is not valid for the selected host-authorized source kind.",
            status=403,
            context={"reasonCode": "azure_devops_source_kind_mismatch"},
        )
    if operation_id == "azure_devops.observations.poll" and scope["source_kind"] not in {
        "pipeline_runs",
        "release_deployments",
    }:
        raise ExchangeProductError(
            code="EXCHANGE_CONNECTOR_PROVIDER_SCOPE_FORBIDDEN",
            title="Azure DevOps observation source is invalid",
            detail="Polling is available only for pipeline runs or release deployments.",
            status=403,
            context={"reasonCode": "azure_devops_source_kind_mismatch"},
        )
    _validate_arguments(operation_id, arguments)
    lease_target: dict[str, object] = {
        key: scope[key]
        for key in (
            "tenant_id",
            "organization",
            "project_id",
            "source_id",
            "source_kind",
            "pipeline_id",
            "definition_id",
            "definition_environment_id",
        )
        if key in scope
    }
    if operation_id == "azure_devops.pipeline_run.get":
        lease_target["run_id"] = _positive_id(arguments.get("runId"), "runId")
    elif operation_id == "azure_devops.release_environment.get":
        lease_target["release_id"] = _positive_id(arguments.get("releaseId"), "releaseId")
        lease_target["environment_id"] = _positive_id(
            arguments.get("environmentId"),
            "environmentId",
        )
    target_projection: dict[str, object] = {
        "id": target_id,
        "kind": str(target_kind),
        "bindingId": binding_id,
    }
    return target_projection, lease_target


def public_profile_scope(value: object) -> dict[str, Any]:
    """Return the stable camelCase projection of an exact ADO source scope."""

    scope = validate_profile_scope(value)
    return {
        "tenantId": scope["tenant_id"],
        "organization": scope["organization"],
        "projectId": scope["project_id"],
        "sourceId": scope["source_id"],
        "sourceKind": scope["source_kind"],
        **({"pipelineId": scope["pipeline_id"]} if "pipeline_id" in scope else {}),
        **({"definitionId": scope["definition_id"]} if "definition_id" in scope else {}),
        **(
            {"definitionEnvironmentId": scope["definition_environment_id"]}
            if "definition_environment_id" in scope
            else {}
        ),
    }


def _optional_fields(operation_id: str) -> set[str]:
    if operation_id in {
        "azure_devops.observations.poll",
        "azure_devops.pipeline_runs.list",
        "azure_devops.deployments.list",
    }:
        return {"pageSize", "pageCursor", "windowStart", "windowEnd"}
    if operation_id in {"azure_devops.pipelines.list"}:
        return {"pageSize", "pageCursor"}
    if operation_id == "azure_devops.pipeline_run.get":
        return {"runId"}
    if operation_id == "azure_devops.release_environment.get":
        return {"releaseId", "environmentId"}
    return set()


def _expected_source_kind(operation_id: str) -> str | None:
    return {
        "azure_devops.pipelines.list": "project_pipelines",
        "azure_devops.pipeline_runs.list": "pipeline_runs",
        "azure_devops.pipeline_run.get": "pipeline_runs",
        "azure_devops.deployments.list": "release_deployments",
        "azure_devops.release_environment.get": "release_deployments",
    }.get(operation_id)


def _validate_arguments(operation_id: str, arguments: Mapping[str, object]) -> None:
    required = {"target"}
    if operation_id in {
        "azure_devops.observations.poll",
        "azure_devops.pipeline_runs.list",
        "azure_devops.deployments.list",
    }:
        required |= {"pageSize", "pageCursor", "windowStart", "windowEnd"}
    elif operation_id in {"azure_devops.pipelines.list"}:
        required |= {"pageSize", "pageCursor"}
    elif operation_id == "azure_devops.pipeline_run.get":
        required.add("runId")
    elif operation_id == "azure_devops.release_environment.get":
        required |= {"releaseId", "environmentId"}
    _exact_fields(arguments, required=required)
    if "pageSize" in arguments:
        page_size = arguments["pageSize"]
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= 100
        ):
            raise ValueError("pageSize must be between 1 and 100")
    if "pageCursor" in arguments:
        cursor = arguments["pageCursor"]
        if cursor is not None and (
            not isinstance(cursor, str) or _CURSOR.fullmatch(cursor) is None
        ):
            raise ValueError("pageCursor is invalid")
    if "windowStart" in arguments:
        start = arguments["windowStart"]
        if start is not None:
            _utc_timestamp(start, "windowStart")
    if "windowEnd" in arguments:
        _utc_timestamp(arguments["windowEnd"], "windowEnd")
    for field in ("runId", "releaseId", "environmentId"):
        if field in arguments:
            _positive_id(arguments[field], field)


def _exact_fields(
    value: Mapping[str, object], *, required: set[str], optional: set[str] | None = None
) -> None:
    allowed_optional = optional or set()
    if not required <= set(value) or set(value) - required - allowed_optional:
        raise ValueError("Azure DevOps arguments do not match the fixed operation schema")


def _uuid(value: object, label: str) -> str:
    try:
        return str(UUID(str(value))).lower()
    except ValueError as exc:
        raise ValueError(f"{label} must be a UUID") from exc


def _source_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE_SOURCE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} is not a valid Azure DevOps source ID")
    return value


def _positive_id(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} must be a UTC timestamp")
    return parsed
