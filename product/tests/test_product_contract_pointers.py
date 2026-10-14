"""Catalog pointers stay anchored to real OpenAPI operations. | 目录指针锚定真实 OpenAPI 操作。"""

from __future__ import annotations

import hashlib
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


def test_new_uuid_resource_operations_match_openapi_path_constraints() -> None:
    """Keep the catalog's single resource identifier equal to its UUID path schema."""

    repository_root = Path(__file__).parents[2]
    openapi_path = repository_root / "contracts/product/v1/openapi.yaml"
    catalog_path = repository_root / "contracts/product/v2/catalog.json"
    openapi, _ = read_from_filename(str(openapi_path))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    expected = {
        "accountGetRenewalSession",
        "integrationAcknowledgeNotification",
        "integrationDeliverNotification",
        "integrationGetAuthorizationHealth",
        "integrationListConnectionResources",
        "integrationRefreshConnectionResources",
    }
    definitions = {
        operation["operationId"]: operation
        for path_item in openapi["paths"].values()
        for method in ("get", "post", "put", "patch", "delete")
        if isinstance(operation := path_item.get(method), dict)
        and isinstance(operation.get("operationId"), str)
    }
    catalog_operations = {item["operationId"]: item for item in catalog["operations"]}
    uuid_pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    for operation_id in expected:
        definition = definitions[operation_id]
        resource = catalog_operations[operation_id]["resourceId"]
        parameter_name = resource["pathParameter"]
        parameter = next(
            item
            for item in definition["parameters"]
            if item["in"] == "path" and item["name"] == parameter_name
        )
        assert parameter["schema"]["format"] == "uuid", operation_id
        assert resource["minLength"] == resource["maxLength"] == 36, operation_id
        assert resource["pattern"] == uuid_pattern, operation_id


def test_notification_sse_stays_direct_http_and_outside_generic_catalog() -> None:
    """Keep text/event-stream on Exchange HTTP while sharing the feed-read grant."""

    repository_root = Path(__file__).parents[2]
    openapi_path = repository_root / "contracts/product/v1/openapi.yaml"
    catalog_path = repository_root / "contracts/product/v2/catalog.json"
    openapi, _ = read_from_filename(str(openapi_path))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

    operation = openapi["paths"]["/api/v1/integrations/notifications/events"]["get"]
    operation_ids = {item["operationId"] for item in catalog["operations"]}
    assert operation["operationId"] == "integrationStreamNotifications"
    assert "integrationStreamNotifications" not in operation_ids
    assert "integrationListNotifications" in operation_ids
    assert operation["security"] == [{"IntegrationBearer": []}]
    assert "text/event-stream" in operation["responses"]["200"]["content"]


def test_navigator_consumer_fixture_is_pinned_to_owner_operations() -> None:
    repository_root = Path(__file__).parents[2]
    openapi_path = repository_root / "contracts/product/v1/openapi.yaml"
    catalog_path = repository_root / "contracts/product/v2/catalog.json"
    fixture_path = repository_root / "contracts/product/v1/exchange-integration-consumer.json"
    openapi, _ = read_from_filename(str(openapi_path))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert fixture["sourceOpenapiSha256"] == hashlib.sha256(openapi_path.read_bytes()).hexdigest()
    assert fixture["sourceCatalogSha256"] == hashlib.sha256(catalog_path.read_bytes()).hexdigest()

    operations: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for path, path_item in openapi["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            definition = path_item.get(method)
            if isinstance(definition, dict) and isinstance(definition.get("operationId"), str):
                operations[definition["operationId"]] = (path, method.upper(), definition)
    catalog_operations = {item["operationId"]: item for item in catalog["operations"]}

    expected = {
        "integrationCreateIssueComment",
        "integrationGetIssue",
        "integrationGetOperation",
        "integrationQueryIssue",
        "integrationUpdateIssueState",
        "integrationListConnections",
        "integrationGetAuthorizationHealth",
        "accountBeginRenewalSession",
        "accountGetRenewalSession",
        "integrationListConnectionResources",
    }
    assert set(fixture["operations"]) == expected
    for operation_id, entry in fixture["operations"].items():
        path, method, definition = operations[operation_id]
        assert entry["path"] == path
        assert entry["method"] == method
        assert entry["definition"] == definition
        assert entry["catalog"] == catalog_operations[operation_id]

    list_connections = fixture["operations"]["integrationListConnections"]
    assert (
        list_connections["definition"]["responses"]["200"]["content"]["application/json"]["schema"][
            "type"
        ]
        == "array"
    )
    connection_properties = fixture["schemas"]["IntegrationConnectionResponse"]["properties"]
    assert set(connection_properties) == {
        "id",
        "provider",
        "displayName",
        "repositoryId",
        "repositoryName",
        "enabled",
        "createdAt",
        "updatedAt",
    }
    resource_responses = fixture["operations"]["integrationListConnectionResources"]["definition"][
        "responses"
    ]
    assert resource_responses["409"] == {"$ref": "#/components/responses/Problem"}
    problem_context = fixture["schemas"]["ProblemDetails"]["properties"]["context"]
    assert set(problem_context["properties"]) == {"connectionId", "authorizationRef"}
