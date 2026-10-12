"""Catalog pointers stay anchored to real OpenAPI operations. | 目录指针锚定真实 OpenAPI 操作。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openapi_spec_validator.readers import read_from_filename


def _resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve one local JSON Pointer against the parsed owner OpenAPI document."""

    if not pointer.startswith("#/"):
        raise AssertionError(f"expected a local JSON Pointer, got {pointer!r}")
    value = document
    for raw_segment in pointer[2:].split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        value = value[int(segment)] if isinstance(value, list) else value[segment]
    return value


def test_product_catalog_request_pointers_select_the_route_body_schema() -> None:
    repository_root = Path(__file__).parents[2]
    openapi_path = repository_root / "contracts/product/v1/openapi.yaml"
    catalog_path = repository_root / "contracts/product/v2/catalog.json"
    openapi, _ = read_from_filename(str(openapi_path))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

    operations: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for path, path_item in openapi["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if isinstance(operation, dict) and isinstance(operation.get("operationId"), str):
                operations[operation["operationId"]] = (path, method, operation)

    for catalog_operation in catalog["operations"]:
        operation_id = catalog_operation["operationId"]
        path, method, source_operation = operations[operation_id]
        request_body = source_operation.get("requestBody")
        pointer = catalog_operation["requestSchemaPointer"]
        if request_body is None:
            assert pointer is None, operation_id
            continue

        escaped_path = path.replace("~", "~0").replace("/", "~1")
        source_body_schema_pointer = (
            f"#/paths/{escaped_path}/{method}/requestBody/content/application~1json/schema"
        )
        assert pointer == source_body_schema_pointer, operation_id
        assert (
            _resolve_pointer(openapi, pointer)
            == request_body["content"]["application/json"]["schema"]
        ), operation_id
