"""People directory exposure: client payloads, error mapping, and operator-gated routes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cyrene_plugin_runtime import DirectPayload
from fastapi.testclient import TestClient

from cyrene_exchange_product.api import create_app
from cyrene_exchange_product.errors import ExchangeProductError
from cyrene_exchange_product.integrations.api import IntegrationServices
from cyrene_exchange_product.integrations.auth import (
    AccountCenterRequestSigner,
    IntegrationPrincipal,
)
from cyrene_exchange_product.integrations.clients import AccountCenterClient

OPERATOR = "navigator.connector.operator.v1"
PERSON_REF = "6b7fd0a1-9d5a-4bdf-8c3b-0d3f6d8e1a10"
HANDLE_REF = "0c4f1c9e-7f2b-4a1d-9b38-5e2a7c6d4b21"
RESPONSE_PREFIX = "type.googleapis.com/cyrene.account.center.v1."


def _principal(*operations: str) -> IntegrationPrincipal:
    return IntegrationPrincipal(
        issuer="https://issuer.example",
        subject="admin-1",
        organization_id="org-1",
        workspace_id="workspace-1",
        allowed_operation_ids=frozenset(operations),
    )


class _Transport:
    """A direct transport that returns canned payloads or raises a canned failure."""

    def __init__(self, *responses: DirectPayload | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> DirectPayload:
        self.calls.append(kwargs)
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def payload(self, index: int = -1) -> dict[str, Any]:
        return json.loads(self.calls[index]["request"].value)["payload"]


class _Failure(Exception):
    def __init__(self, domain_code: str, message: str) -> None:
        super().__init__(message)
        self.domain_code = domain_code
        self.message = message


def _client(transport: _Transport) -> AccountCenterClient:
    return AccountCenterClient(
        transport,
        exchange_signer=AccountCenterRequestSigner(caller_id="exchange-service", key=b"a" * 32),
        binding_id="account-center-binding",
    )


def _reply(method: str, body: dict[str, Any]) -> DirectPayload:
    return DirectPayload(RESPONSE_PREFIX + method + "Response", json.dumps(body).encode())


def test_client_payloads_omit_absent_optionals_and_keep_the_workspace_null() -> None:
    transport = _Transport(
        _reply("DeclareAccountHandle", {"created": True}),
        _reply("RetractAccountHandle", {"retracted": True}),
        _reply("FindPeople", {"people": [], "truncated": False}),
        _reply("FindPeople", {"people": [], "truncated": False}),
    )
    client = _client(transport)

    client.declare_account_handle(
        _principal(OPERATOR),
        provider="github",
        handle="Octocat",
        subject="user-43",
        mail=None,
        display_name=None,
        idempotency_key="declare-1",
    )
    client.retract_account_handle(
        _principal(OPERATOR), provider="github", handle="Octocat", idempotency_key="retract-1"
    )
    client.find_people(_principal(OPERATOR), workspace_id=None, mail="ada@example.com")
    client.find_people(
        _principal(OPERATOR), workspace_id="workspace-1", provider="github", handle="x", limit=5
    )

    assert transport.payload(0) == {
        "provider": "github",
        "handle": "Octocat",
        "subject": "user-43",
        "idempotency_key": "declare-1",
    }
    assert transport.payload(1) == {
        "provider": "github",
        "handle": "Octocat",
        "idempotency_key": "retract-1",
    }
    # Absent filters are omitted; only the workspace selector may be null.
    assert transport.payload(2) == {"workspace_id": None, "mail": "ada@example.com"}
    assert transport.payload(3) == {
        "workspace_id": "workspace-1",
        "provider": "github",
        "handle": "x",
        "limit": 5,
    }
    assert [call["method"] for call in transport.calls] == [
        "declare_account_handle",
        "retract_account_handle",
        "find_people",
        "find_people",
    ]


@pytest.mark.parametrize(
    ("reason", "status", "code"),
    [
        ("handle_owned", 409, "EXCHANGE_ACCOUNT_HANDLE_CONFLICT"),
        ("person_conflict", 409, "EXCHANGE_ACCOUNT_HANDLE_CONFLICT"),
        ("handle_not_found", 404, "EXCHANGE_ACCOUNT_HANDLE_NOT_FOUND"),
        ("invalid_request", 422, "EXCHANGE_ACCOUNT_CENTER_REQUEST_INVALID"),
        ("result_too_large", 422, "EXCHANGE_ACCOUNT_CENTER_REQUEST_INVALID"),
        ("scope_mismatch", 403, "EXCHANGE_ACCOUNT_CENTER_AUTHORIZATION_DENIED"),
    ],
)
def test_people_domain_refusals_map_to_precise_statuses(
    reason: str, status: int, code: str
) -> None:
    client = _client(_Transport(_Failure("PERMISSION_DENIED", reason)))

    with pytest.raises(ExchangeProductError) as raised:
        client.retract_account_handle(
            _principal(OPERATOR), provider="github", handle="octocat", idempotency_key="k"
        )

    assert (raised.value.status, raised.value.code) == (status, code)


def test_other_account_methods_keep_the_generic_authorization_mapping() -> None:
    """The precise statuses apply to people methods only."""

    client = _client(_Transport(_Failure("PERMISSION_DENIED", "handle_owned")))

    with pytest.raises(ExchangeProductError) as raised:
        client.list_links(_principal(), workspace_id="workspace-1")

    assert raised.value.status == 403


class _Authorizer:
    def __init__(self, principal: IntegrationPrincipal) -> None:
        self.principal = principal

    def principal_for(self, *, bearer_token: str, workspace_id: str) -> IntegrationPrincipal:
        if bearer_token != "first-party-token" or workspace_id != self.principal.workspace_id:
            raise RuntimeError("Platform rejected current identity")
        return self.principal


class _People:
    """An Account Center stand-in that records calls and returns canned results."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.find_result: Any = {
            "people": [
                {
                    "person_ref": PERSON_REF,
                    "issuer": "https://issuer.example",
                    "subject": "user-43",
                    "mail": "ada@example.com",
                    "display_name": "Ada Lovelace",
                    "accounts": [
                        {
                            "source": "declared",
                            "kind": "handle",
                            "provider": "github",
                            "handle": "Octocat",
                            "external_subject": None,
                            "status": "active",
                            "updated_at": 1_800_000_000,
                        }
                    ],
                }
            ],
            "truncated": False,
        }
        self.declare_error: Exception | None = None
        self.revoke_result: Any = {
            "subject": "user-43",
            "provider": "github",
            "unlinked": 2,
            "skipped_shared": 1,
            "results": [
                {"kind": "account", "status": "revocation_unknown"},
                {"kind": "profile", "status": "unlinked"},
            ],
        }

    def find_people(self, principal: IntegrationPrincipal, **kwargs: Any) -> Any:
        self.calls.append(("find_people", kwargs))
        return self.find_result

    def declare_account_handle(self, principal: IntegrationPrincipal, **kwargs: Any) -> Any:
        self.calls.append(("declare_account_handle", kwargs))
        if self.declare_error is not None:
            raise self.declare_error
        return {
            "person_ref": PERSON_REF,
            "handle_ref": HANDLE_REF,
            "provider": kwargs["provider"],
            "handle": kwargs["handle"],
            "source": "declared",
            "created": True,
        }

    def retract_account_handle(self, principal: IntegrationPrincipal, **kwargs: Any) -> Any:
        self.calls.append(("retract_account_handle", kwargs))
        return {
            "retracted": True,
            "person_ref": PERSON_REF,
            "provider": kwargs["provider"],
            "handle": kwargs["handle"],
        }

    def revoke_person_links(self, principal: IntegrationPrincipal, **kwargs: Any) -> Any:
        self.calls.append(("revoke_person_links", kwargs))
        return self.revoke_result


class _Nothing:
    pass


def _app(tmp_path: Path, principal: IntegrationPrincipal) -> tuple[Any, _People]:
    people = _People()
    callback = IntegrationPrincipal(
        issuer="urn:cyrene:service",
        subject="exchange-oauth-callback",
        organization_id=principal.organization_id,
        workspace_id=principal.workspace_id,
        allowed_operation_ids=frozenset(),
    )
    services = IntegrationServices(
        store=_Nothing(),  # type: ignore[arg-type]
        authorizer=_Authorizer(principal),
        accounts=people,  # type: ignore[arg-type]
        github=_Nothing(),  # type: ignore[arg-type]
        webhook_verifier=_Nothing(),  # type: ignore[arg-type]
        delegation_authorizer=_Nothing(),  # type: ignore[arg-type]
        callback_principal=callback,
    )
    app = create_app(database_path=tmp_path / "exchange.sqlite3", integrations=services)
    return app, people


_AUTH = {"Authorization": "Bearer first-party-token"}


def test_find_people_route_is_operator_gated_and_projects_the_closed_shape(tmp_path: Path) -> None:
    app, people = _app(tmp_path, _principal(OPERATOR))
    with TestClient(app) as client:
        anonymous = client.get("/api/v1/accounts/people?workspaceId=workspace-1")
        response = client.get(
            "/api/v1/accounts/people?workspaceId=workspace-1&provider=github&handle=octocat&limit=5",
            headers=_AUTH,
        )
        bad_provider = client.get(
            "/api/v1/accounts/people?workspaceId=workspace-1&provider=gitlab", headers=_AUTH
        )
        bad_limit = client.get(
            "/api/v1/accounts/people?workspaceId=workspace-1&limit=0", headers=_AUTH
        )

    assert anonymous.status_code == 401
    assert (bad_provider.status_code, bad_limit.status_code) == (422, 422)
    assert response.status_code == 200
    assert response.json() == {
        "people": [
            {
                "personRef": PERSON_REF,
                "issuer": "https://issuer.example",
                "subject": "user-43",
                "mail": "ada@example.com",
                "displayName": "Ada Lovelace",
                "accounts": [
                    {
                        "source": "declared",
                        "kind": "handle",
                        "provider": "github",
                        "handle": "Octocat",
                        "externalSubject": None,
                        "status": "active",
                        "updatedAt": 1_800_000_000,
                    }
                ],
            }
        ],
        "truncated": False,
    }
    # The workspace comes from the verified identity, never from the caller's body.
    assert people.calls == [
        (
            "find_people",
            {
                "workspace_id": "workspace-1",
                "subject": None,
                "mail": None,
                "provider": "github",
                "handle": "octocat",
                "name": None,
                "limit": 5,
            },
        )
    ]


def test_people_routes_reject_a_caller_without_the_operator_role(tmp_path: Path) -> None:
    app, people = _app(tmp_path, _principal("accountListLinks"))
    with TestClient(app) as client:
        found = client.get("/api/v1/accounts/people?workspaceId=workspace-1", headers=_AUTH)
        declared = client.post(
            "/api/v1/accounts/people/handles?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "d1"},
            json={"provider": "github", "handle": "octocat", "mail": "ada@example.com"},
        )
        retracted = client.post(
            "/api/v1/accounts/people/handles/actions/retract?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "r1"},
            json={"provider": "github", "handle": "octocat"},
        )

    assert (found.status_code, declared.status_code, retracted.status_code) == (403, 403, 403)
    assert people.calls == []


def test_declare_and_retract_routes_use_camel_case_and_forward_the_idempotency_key(
    tmp_path: Path,
) -> None:
    app, people = _app(tmp_path, _principal(OPERATOR))
    with TestClient(app) as client:
        declared = client.post(
            "/api/v1/accounts/people/handles?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "declare-1"},
            json={
                "provider": "github",
                "handle": "Octocat",
                "subject": "user-43",
                "mail": "ada@example.com",
                "displayName": "Ada Lovelace",
            },
        )
        retracted = client.post(
            "/api/v1/accounts/people/handles/actions/retract?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "retract-1"},
            json={"provider": "github", "handle": "Octocat"},
        )
        missing_key = client.post(
            "/api/v1/accounts/people/handles?workspaceId=workspace-1",
            headers=_AUTH,
            json={"provider": "github", "handle": "octocat", "mail": "ada@example.com"},
        )
        injected = client.post(
            "/api/v1/accounts/people/handles?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "declare-2"},
            json={"provider": "github", "handle": "octocat", "mail": "a@b.co", "roles": ["admin"]},
        )
        bad_provider = client.post(
            "/api/v1/accounts/people/handles?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "declare-3"},
            json={"provider": "azure", "handle": "octocat", "mail": "ada@example.com"},
        )

    assert declared.status_code == 200
    assert declared.json() == {
        "personRef": PERSON_REF,
        "handleRef": HANDLE_REF,
        "provider": "github",
        "handle": "Octocat",
        "source": "declared",
        "created": True,
    }
    assert retracted.status_code == 200
    assert retracted.json() == {
        "retracted": True,
        "personRef": PERSON_REF,
        "provider": "github",
        "handle": "Octocat",
    }
    assert (missing_key.status_code, injected.status_code, bad_provider.status_code) == (
        422,
        422,
        422,
    )
    assert people.calls == [
        (
            "declare_account_handle",
            {
                "provider": "github",
                "handle": "Octocat",
                "subject": "user-43",
                "mail": "ada@example.com",
                "display_name": "Ada Lovelace",
                "idempotency_key": "declare-1",
            },
        ),
        (
            "retract_account_handle",
            {"provider": "github", "handle": "Octocat", "idempotency_key": "retract-1"},
        ),
    ]


def test_routes_surface_account_center_refusals_and_reject_malformed_responses(
    tmp_path: Path,
) -> None:
    app, people = _app(tmp_path, _principal(OPERATOR))
    people.declare_error = ExchangeProductError(
        code="EXCHANGE_ACCOUNT_HANDLE_CONFLICT",
        title="Account handle conflict",
        detail="conflict",
        status=409,
    )
    with TestClient(app) as client:
        conflict = client.post(
            "/api/v1/accounts/people/handles?workspaceId=workspace-1",
            headers={**_AUTH, "Idempotency-Key": "declare-1"},
            json={"provider": "github", "handle": "octocat", "mail": "ada@example.com"},
        )
        people.find_result = {"people": "not-a-list", "truncated": False}
        malformed = client.get("/api/v1/accounts/people?workspaceId=workspace-1", headers=_AUTH)
        people.find_result = {"people": [{"person_ref": PERSON_REF}], "truncated": False}
        incomplete = client.get("/api/v1/accounts/people?workspaceId=workspace-1", headers=_AUTH)

    assert conflict.status_code == 409
    assert (malformed.status_code, incomplete.status_code) == (502, 502)


def test_revoke_person_links_client_payload_is_exact() -> None:
    transport = _Transport(_reply("RevokePersonLinks", {"unlinked": 0}))

    _client(transport).revoke_person_links(
        _principal(OPERATOR), subject="user-43", provider="github", idempotency_key="revoke-1"
    )

    assert transport.calls[0]["method"] == "revoke_person_links"
    assert transport.payload(0) == {
        "subject": "user-43",
        "provider": "github",
        "idempotency_key": "revoke-1",
    }


def test_revoke_person_links_route_is_operator_gated_and_projects_per_link_outcomes(
    tmp_path: Path,
) -> None:
    app, people = _app(tmp_path, _principal(OPERATOR))
    url = "/api/v1/accounts/people/links/actions/revoke?workspaceId=workspace-1"
    with TestClient(app) as client:
        revoked = client.post(
            url,
            headers={**_AUTH, "Idempotency-Key": "revoke-1"},
            json={"subject": "user-43", "provider": "github"},
        )
        missing_key = client.post(url, headers=_AUTH, json={"subject": "u", "provider": "github"})
        injected = client.post(
            url,
            headers={**_AUTH, "Idempotency-Key": "revoke-2"},
            json={"subject": "u", "provider": "github", "roles": ["admin"]},
        )
        bad_provider = client.post(
            url,
            headers={**_AUTH, "Idempotency-Key": "revoke-3"},
            json={"subject": "u", "provider": "gitlab"},
        )

    assert revoked.status_code == 200
    assert revoked.json() == {
        "subject": "user-43",
        "provider": "github",
        "unlinked": 2,
        "skippedShared": 1,
        "results": [
            {"kind": "account", "status": "revocation_unknown"},
            {"kind": "profile", "status": "unlinked"},
        ],
    }
    assert (missing_key.status_code, injected.status_code, bad_provider.status_code) == (
        422,
        422,
        422,
    )
    assert people.calls == [
        (
            "revoke_person_links",
            {"subject": "user-43", "provider": "github", "idempotency_key": "revoke-1"},
        )
    ]


def test_revoke_person_links_rejects_a_non_operator_and_a_malformed_response(
    tmp_path: Path,
) -> None:
    url = "/api/v1/accounts/people/links/actions/revoke?workspaceId=workspace-1"
    body = {"subject": "user-43", "provider": "github"}
    headers = {**_AUTH, "Idempotency-Key": "revoke-1"}

    app, people = _app(tmp_path, _principal("accountListLinks"))
    with TestClient(app) as client:
        denied = client.post(url, headers=headers, json=body)
    assert denied.status_code == 403
    assert people.calls == []

    (tmp_path / "second").mkdir()
    app, people = _app(tmp_path / "second", _principal(OPERATOR))
    people.revoke_result = {"subject": "user-43", "provider": "github"}
    with TestClient(app) as client:
        malformed = client.post(url, headers=headers, json=body)
    assert malformed.status_code == 502
