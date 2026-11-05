"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 connector_manifest.py                                           │
│  Module: cyrene_exchange_product.integrations.connector_manifest    │
│  Role: The connector operations a deployment has approved.          │
│                                                                     │
│  模块职责：读取部署按摘要批准的 Connector 操作清单。                   │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MANIFEST_FILE_ENV = "CYRENE_CONNECTOR_OPERATIONS_MANIFEST_FILE"
MANIFEST_SHA256_ENV = "CYRENE_CONNECTOR_OPERATIONS_MANIFEST_SHA256"
MANIFEST_MAX_BYTES = 1024 * 1024

_SCHEMA_VERSION = "cyrene.connector-operations.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ConnectorManifestError(ValueError):
    """The approved manifest is missing, invalid, or disagrees with this Exchange."""


@dataclass(frozen=True, slots=True)
class DeclaredOperation:
    """What the manifest says about one operation, limited to the facts Exchange uses."""

    provider_ids: frozenset[str]
    mutating: bool | None
    exchange_tool_ids: Mapping[str, str]
    exchange_resource_projections: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class DeclaredOperations:
    """The operations this Exchange may prepare and export, fixed when it starts.

    Without an approved manifest, every operation in Exchange's own tables is allowed, as before.
    With one, only the operations it lists for Platform to grant are allowed. Its
    `exchangeOnlyOperations` are not, since Platform can't grant them.
    """

    digest: str | None = None
    operations: Mapping[str, DeclaredOperation] | None = None

    @classmethod
    def builtin(cls) -> DeclaredOperations:
        """Allow everything in Exchange's own tables."""

        return cls()

    def allows(self, provider_id: str, operation_id: str) -> bool:
        """Return whether this canonical provider may run this operation."""

        if self.operations is None:
            return True
        operation = self.operations.get(operation_id)
        return operation is not None and provider_id in operation.provider_ids


def load_declared_operations(environ: Mapping[str, str]) -> DeclaredOperations:
    """Read the approved manifest named by the environment, or allow everything without one.

    Both settings or neither: a deployment that set only one meant to pin a manifest.
    """

    manifest_file = environ.get(MANIFEST_FILE_ENV)
    approved_digest = environ.get(MANIFEST_SHA256_ENV)
    if manifest_file is None and approved_digest is None:
        return DeclaredOperations.builtin()
    if manifest_file is None or approved_digest is None:
        raise ConnectorManifestError(
            f"set both {MANIFEST_FILE_ENV} and {MANIFEST_SHA256_ENV}, or neither"
        )
    return declared_operations_from_bytes(_read_manifest(manifest_file), approved_digest)


def declared_operations_from_bytes(data: bytes, approved_digest: str) -> DeclaredOperations:
    """Accept manifest bytes only if they are the approved version and well formed."""

    if _DIGEST.fullmatch(approved_digest) is None:
        raise ConnectorManifestError(
            "the approved digest is not sha256:<64 lowercase hex characters>"
        )
    if len(data) > MANIFEST_MAX_BYTES:
        raise ConnectorManifestError("the manifest is too large")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if digest != approved_digest:
        raise ConnectorManifestError("the manifest digest differs from the approved digest")
    try:
        document = json.loads(data, object_pairs_hook=_refuse_duplicate_keys)
    except ConnectorManifestError:
        raise
    except ValueError as exc:  # Includes JSONDecodeError and UnicodeDecodeError.
        raise ConnectorManifestError("the manifest is not valid JSON") from exc
    if not isinstance(document, dict) or document.get("schemaVersion") != _SCHEMA_VERSION:
        raise ConnectorManifestError("the manifest schema version is not supported")
    rows = document.get("operations")
    if not isinstance(rows, list) or not rows:
        raise ConnectorManifestError("the manifest lists no operations")
    operations: dict[str, DeclaredOperation] = {}
    for row in rows:
        operation_id, operation = _declared_operation(row)
        if operation_id in operations:
            raise ConnectorManifestError(f"the manifest lists {operation_id!r} twice")
        operations[operation_id] = operation
    return DeclaredOperations(digest=digest, operations=operations)


@dataclass(frozen=True, slots=True)
class ExchangeOperationFacts:
    """What this Exchange's own tables say about one operation."""

    tool_ids: Mapping[str, str]
    resource_projections: Mapping[str, str]
    mutating: bool


def verify_declared_operations(
    declared: DeclaredOperations,
    exchange_facts: Mapping[str, ExchangeOperationFacts],
) -> None:
    """Refuse a manifest generated from a different Exchange.

    Every operation it declares must have the same tool IDs and resource projections as this
    Exchange, and the same mutating flag where both state one. An operation this Exchange maps
    but the manifest leaves out is simply not allowed.
    """

    if declared.operations is None:
        return
    for operation_id, operation in sorted(declared.operations.items()):
        facts = exchange_facts.get(operation_id)
        tool_ids = dict(facts.tool_ids) if facts is not None else {}
        projections = dict(facts.resource_projections) if facts is not None else {}
        if dict(operation.exchange_tool_ids) != tool_ids:
            raise ConnectorManifestError(
                f"the manifest's tool IDs for {operation_id!r} differ from this Exchange"
            )
        if dict(operation.exchange_resource_projections) != projections:
            raise ConnectorManifestError(
                f"the manifest's resource projections for {operation_id!r} differ "
                "from this Exchange"
            )
        if (
            facts is not None
            and tool_ids
            and operation.mutating is not None
            and operation.mutating != facts.mutating
        ):
            raise ConnectorManifestError(
                f"the manifest and this Exchange disagree on whether {operation_id!r} mutates"
            )


def _read_manifest(path: str) -> bytes:
    """Read a regular file without blocking on a FIFO. The digest protects its content."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise ConnectorManifestError("the manifest could not be read") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ConnectorManifestError("the manifest could not be read")
        with os.fdopen(descriptor, "rb", closefd=False) as manifest:
            return manifest.read(MANIFEST_MAX_BYTES + 1)
    except OSError as exc:
        raise ConnectorManifestError("the manifest could not be read") from exc
    finally:
        os.close(descriptor)


def _refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConnectorManifestError(f"the manifest repeats the key {key!r}")
        result[key] = value
    return result


def _declared_operation(row: object) -> tuple[str, DeclaredOperation]:
    if not isinstance(row, dict):
        raise ConnectorManifestError("a manifest operation is not an object")
    operation_id = row.get("operationId")
    if not isinstance(operation_id, str) or not operation_id:
        raise ConnectorManifestError("a manifest operation has no operation ID")
    provider_ids = row.get("providerIds")
    if (
        not isinstance(provider_ids, list)
        or not provider_ids
        or not all(isinstance(provider_id, str) and provider_id for provider_id in provider_ids)
        or len(set(provider_ids)) != len(provider_ids)
    ):
        raise ConnectorManifestError(f"the providers of {operation_id!r} are invalid")
    mutating = row.get("mutating")
    if "mutating" not in row or (mutating is not None and not isinstance(mutating, bool)):
        raise ConnectorManifestError(f"the mutating flag of {operation_id!r} is invalid")
    return operation_id, DeclaredOperation(
        provider_ids=frozenset(provider_ids),
        mutating=mutating,
        exchange_tool_ids=_string_map(row, "exchangeToolIds", operation_id),
        exchange_resource_projections=_string_map(row, "exchangeResourceProjections", operation_id),
    )


def _string_map(row: Mapping[str, object], field: str, operation_id: str) -> dict[str, str]:
    value = row.get(field)
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ConnectorManifestError(f"the {field} of {operation_id!r} are invalid")
    return dict(value)
