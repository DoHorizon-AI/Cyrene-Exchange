"""Local cross-repository Account Center → Exchange → provider lease gate.

The test uses the current Plugins checkout through ``CYRENE_PLUGINS_ROOT`` and
synthetic OAuth/HTTP clients only. 中文：只通过本地合成传输验证授权租约链路。
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import pytest

TENANT_ID = "11111111-2222-4333-8444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
ORGANIZATION_ID = "auth-spine-org"
WORKSPACE_ID = "auth-spine-workspace"
AC_BINDING_ID = "auth-spine-account-center"
GRAPH_BINDING_ID = "auth-spine-graph-provider"
ADO_BINDING_ID = "auth-spine-ado-provider"
EXCHANGE_CALLER = "exchange-service"
CALLBACK_CALLER = "microsoft-entra-callback"
GRAPH_CALLER = "microsoft-graph-provider"
ADO_CALLER = "azure-devops-observation-provider"
EXCHANGE_KEY = b"x" * 32
CALLBACK_KEY = b"c" * 32
GRAPH_KEY = b"g" * 32
ADO_KEY = b"a" * 32
GRAPH_PROFILE_REF = "66666666-7777-4888-8999-aaaaaaaaaaaa"
GRAPH_V2_WORKSPACE_ID = "33333333-4444-4555-8666-777777777777"
GRAPH_V2_LIST_ID = "dddddddd-eeee-4fff-8000-111111111111"
GRAPH_V2_TASK_LIST_ID = "AAMkList-opaque=="
GRAPH_V2_CALENDAR_ID = "AAMkCalendar-opaque=="
GRAPH_V2_DRIVE_ID = "b!drive-opaque=="
GRAPH_V2_FREEBUSY_SUBJECT = "li.1@dohorizon.com"
ADO_PROFILE_REF = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
CONNECTION_ID = UUID("99999999-aaaa-4bbb-8ccc-dddddddddddd")
GRAPH_PLAN_ID = "plan_A2b_935s-FIFm2QAFkHM"
GRAPH_TASK_ID = "task_yQk3-opaque_ID"
GRAPH_BUCKET_ID = "bucket_936w-A2b"
GRAPH_SITE_ID = (
    "contoso.sharepoint.com,22222222-3333-4444-8555-666666666666,"
    "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
)
GRAPH_V2_SITE_ID = GRAPH_SITE_ID
GRAPH_LIST_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
ADO_ORGANIZATION = "contoso"
ADO_PROJECT_ID = "22222222-3333-4444-8555-666666666666"
ADO_SOURCE_ID = "pipeline-source-a"
ADO_PIPELINE_ID = 31
CALLBACK_URI = "http://localhost:52191/oauth/callback"
AZURE_DEVOPS_RESOURCE_SCOPE = "https://app.vssps.visualstudio.com/.default"


@pytest.fixture(scope="session")
def plugin_modules() -> SimpleNamespace:
    """Load the sibling Plugins source and SDK packages for the local gate."""

    plugins_root_text = os.environ.get("CYRENE_PLUGINS_ROOT") or os.environ.get(
        "CYRENE_PLUGINS_WORKTREE"
    )
    if not plugins_root_text:
        if os.environ.get("CI", "").lower() in {"true", "1", "yes"} or (
            os.environ.get("CYRENE_AUTH_SPINE_REQUIRED") == "1"
        ):
            pytest.fail("CI requires CYRENE_PLUGINS_ROOT for the auth-spine gate")
        pytest.skip("set CYRENE_PLUGINS_ROOT or CYRENE_PLUGINS_WORKTREE to run the auth gate")
    plugins_root = Path(plugins_root_text).resolve()
    expected_plugins_sha = os.environ.get("CYRENE_PLUGINS_SHA")
    if (
        os.environ.get("CI", "").lower() in {"true", "1", "yes"}
        or os.environ.get("CYRENE_AUTH_SPINE_REQUIRED") == "1"
    ) and not expected_plugins_sha:
        pytest.fail("CI requires an exact CYRENE_PLUGINS_SHA for the auth-spine gate")
    if expected_plugins_sha:
        actual_plugins_sha = subprocess.run(
            ["git", "-C", str(plugins_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual_plugins_sha != expected_plugins_sha:
            pytest.fail(
                "Plugins checkout HEAD does not match CYRENE_PLUGINS_SHA "
                f"({actual_plugins_sha} != {expected_plugins_sha})"
            )
    relative_paths = (
        "sdk/python/cyrene_account_center_contracts/src",
        "sdk/python/cyrene_plugin_runtime/src",
        "plugins/accounts/account-center/src",
        "plugins/providers/microsoft-graph/src",
        "plugins/providers/azure-devops-observation/src",
    )
    paths = [plugins_root / relative for relative in relative_paths]
    missing = [path for path in paths if not path.is_dir()]
    if missing:
        pytest.fail(f"Plugins checkout is missing required source paths: {missing}")
    for path in reversed(paths):
        sys.path.insert(0, str(path))

    # Other tests may have imported the installed SDK during pytest collection.
    # Remove only those cached modules that did not come from this exact
    # checkout so this gate cannot accidentally mix installed and source code.
    source_roots = tuple(path.resolve() for path in paths)
    source_packages = (
        "cyrene_account_center_contracts",
        "cyrene_plugin_runtime",
        "account_center",
        "microsoft_graph_provider",
        "azure_devops_observation_provider",
    )
    for module_name, module in tuple(sys.modules.items()):
        if not any(
            module_name == package or module_name.startswith(f"{package}.")
            for package in source_packages
        ):
            continue
        module_file = getattr(module, "__file__", None)
        if module_file is None:
            continue
        resolved_module_path = Path(module_file).resolve()
        if not any(resolved_module_path.is_relative_to(root) for root in source_roots):
            del sys.modules[module_name]

    contracts = importlib.import_module("cyrene_account_center_contracts")
    contracts_path = Path(contracts.__file__).resolve()
    if not contracts_path.is_relative_to(paths[0].resolve()):
        pytest.fail("cross-repository gate did not load the selected Account Center SDK source")

    return SimpleNamespace(
        account_center=importlib.import_module("account_center.plugin"),
        microsoft_graph_oauth=importlib.import_module("account_center.microsoft_graph_oauth"),
        graph_plugin=importlib.import_module("microsoft_graph_provider.plugin"),
        graph_settings=importlib.import_module("microsoft_graph_provider.settings"),
        graph_account_center=importlib.import_module("microsoft_graph_provider.account_center"),
        graph_api=importlib.import_module("microsoft_graph_provider.microsoft_graph_api"),
        ado_plugin=importlib.import_module("azure_devops_observation_provider.plugin"),
        ado_settings=importlib.import_module("azure_devops_observation_provider.settings"),
        ado_account_center=importlib.import_module(
            "azure_devops_observation_provider.account_center"
        ),
        ado_api=importlib.import_module("azure_devops_observation_provider.azure_devops_api"),
        contracts=contracts,
        plugin_runtime=importlib.import_module("cyrene_plugin_runtime"),
    )


class _SyntheticEntraOAuth:
    """Return fixed signed-flow identities without contacting Microsoft."""

    client_id = "synthetic-account-center-client"

    def __init__(self, modules: SimpleNamespace) -> None:
        self.modules = modules
        self.authorizations: list[dict[str, str]] = []
        self.access_tokens: dict[str, Any] = {}
        self.identity = modules.microsoft_graph_oauth.MicrosoftGraphIdentity(TENANT_ID, OBJECT_ID)

    def authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        scopes: tuple[str, ...],
        prompt: str | None = None,
    ) -> str:
        from urllib.parse import urlencode

        values = {
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "scope": " ".join(scopes),
        }
        if prompt is not None:
            values["prompt"] = prompt
        self.authorizations.append(values)
        return "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?" + urlencode(
            values
        )

    def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        nonce_digest: str,
        requested_scopes: tuple[str, ...],
    ) -> tuple[Any, Any]:
        del redirect_uri, code_verifier, nonce_digest
        if not code or not self.authorizations:
            raise self.modules.microsoft_graph_oauth.MicrosoftGraphOAuthError(
                "identity_verification_failed"
            )
        access_token = f"synthetic-access-{len(self.access_tokens) + 1}"
        resource_scopes = tuple(
            sorted(set(requested_scopes) & self.modules.microsoft_graph_oauth.ALLOWED_GRAPH_SCOPES)
        )
        token = self.modules.microsoft_graph_oauth.MicrosoftGraphToken(
            access_token=access_token,
            refresh_token=f"synthetic-refresh-{len(self.access_tokens) + 1}",
            expires_at=int(datetime.now(UTC).timestamp()) + 3600,
            refresh_expires_at=None,
            scopes=resource_scopes,
        )
        self.access_tokens[access_token] = self.identity
        if AZURE_DEVOPS_RESOURCE_SCOPE in requested_scopes:
            token = self.modules.microsoft_graph_oauth.MicrosoftGraphToken(
                access_token=access_token,
                refresh_token=token.refresh_token,
                expires_at=token.expires_at,
                refresh_expires_at=None,
                scopes=(AZURE_DEVOPS_RESOURCE_SCOPE,),
            )
        else:
            self.verify_identity(access_token, TENANT_ID)
        return token, self.identity

    def refresh(
        self,
        *,
        tenant_id: str,
        refresh_token: str,
        requested_scopes: tuple[str, ...],
    ) -> Any:
        del refresh_token
        access_token = f"synthetic-refreshed-{len(self.access_tokens) + 1}"
        self.access_tokens[access_token] = self.identity
        return self.modules.microsoft_graph_oauth.MicrosoftGraphToken(
            access_token=access_token,
            refresh_token="synthetic-rotated-refresh",
            expires_at=int(datetime.now(UTC).timestamp()) + 3600,
            refresh_expires_at=None,
            scopes=tuple(sorted(requested_scopes)),
            identity=self.identity,
        )

    def verify_identity(self, access_token: str, tenant_id: str) -> Any:
        identity = self.access_tokens.get(access_token)
        if identity is None or identity.tenant_id != tenant_id:
            raise self.modules.microsoft_graph_oauth.MicrosoftGraphOAuthError(
                "external_identity_mismatch"
            )
        return identity


class _SyntheticGraphHttp:
    """Serve only fixed Graph routes and record every resource request."""

    def __init__(self, response_type: Any) -> None:
        self.response_type = response_type
        self.calls: list[tuple[str, str, str]] = []
        self.task_percent_complete = 0
        self.task_etag = 'W/"synthetic-etag-1"'

    def request(
        self,
        method: str,
        host: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> Any:
        del timeout_seconds
        assert host == "graph.microsoft.com"
        assert headers.get("Authorization") == "Bearer synthetic-access-3"
        self.calls.append((method, host, path))
        route = path.split("?", 1)[0]
        if route == "/v1.0/me":
            return self._json(200, {"id": OBJECT_ID})
        if route == f"/v1.0/planner/plans/{GRAPH_PLAN_ID}":
            return self._json(200, {"id": GRAPH_PLAN_ID, "title": "Synthetic plan"})
        if route == f"/v1.0/planner/plans/{GRAPH_PLAN_ID}/tasks":
            return self._json(200, {"value": []})
        if route == f"/v1.0/planner/tasks/{GRAPH_TASK_ID}" and method == "GET":
            return self._json(200, self._task(GRAPH_TASK_ID, GRAPH_BUCKET_ID))
        if route == f"/v1.0/planner/tasks/{GRAPH_TASK_ID}" and method == "PATCH":
            assert body is not None
            patch = json.loads(body)
            self.task_percent_complete = patch.get("percentComplete", self.task_percent_complete)
            self.task_etag = 'W/"synthetic-etag-2"'
            return self._json(204, {})
        if route == f"/v1.0/planner/buckets/{GRAPH_BUCKET_ID}":
            return self._json(200, {"id": GRAPH_BUCKET_ID, "planId": GRAPH_PLAN_ID})
        if route == "/v1.0/planner/tasks" and method == "POST":
            assert body is not None
            request_body = json.loads(body)
            return self._json(
                201,
                {
                    "id": "task_created-synthetic",
                    "planId": GRAPH_PLAN_ID,
                    "bucketId": request_body["bucketId"],
                    "title": request_body["title"],
                    "percentComplete": 0,
                    "priority": 5,
                },
            )
        if route.startswith("/v1.0/sites/") and "/lists/" not in route:
            return self._json(200, {"id": GRAPH_SITE_ID, "displayName": "Synthetic site"})
        if route == f"/v1.0/sites/{GRAPH_SITE_ID}/lists/{GRAPH_LIST_ID}":
            return self._json(
                200,
                {
                    "id": GRAPH_LIST_ID,
                    "name": "Synthetic list",
                    "displayName": "Synthetic list",
                    "list": {"template": "genericList"},
                },
            )
        if route == f"/v1.0/sites/{GRAPH_SITE_ID}/lists/{GRAPH_LIST_ID}/items/delta":
            query = path.split("?", 1)[1]
            return self._json(
                200,
                {
                    "value": [],
                    "@odata.deltaLink": (
                        f"https://graph.microsoft.com{route}?{query}&token=synthetic-delta-token"
                    ),
                },
            )
        raise AssertionError(f"unexpected synthetic Graph route: {method} {path}")

    def _json(self, status: int, value: Mapping[str, Any]) -> Any:
        return self.response_type(
            status=status,
            headers={"content-type": "application/json"},
            body=json.dumps(dict(value)).encode("utf-8"),
        )

    def _task(self, task_id: str, bucket_id: str) -> dict[str, Any]:
        return {
            "id": task_id,
            "planId": GRAPH_PLAN_ID,
            "bucketId": bucket_id,
            "title": "Synthetic task",
            "percentComplete": self.task_percent_complete,
            "priority": 5,
            "@odata.etag": self.task_etag,
        }


class _LocalProviderTransport:
    """Connect Exchange dispatch to the real provider plugin entrypoints."""

    def __init__(self, modules: SimpleNamespace, exchange_key: bytes) -> None:
        self.modules = modules
        self.exchange_key = exchange_key
        self.graph_provider: Any = None
        self.ado_provider: Any = None
        self.actor_override: Any = None
        self.invocations: list[dict[str, Any]] = []

    def invoke_connector_tool(
        self,
        principal: Any,
        connection: Any,
        *,
        operation_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        del connection
        self.invocations.append(dict(arguments))
        actor = self.actor_override or principal
        if operation_id.startswith("microsoft_graph."):
            return self._invoke_graph(actor, operation_id, tool_id, arguments, request_id)
        if operation_id.startswith("azure_devops."):
            return self._invoke_ado(actor, operation_id, tool_id, arguments, request_id)
        raise AssertionError(f"unexpected provider operation: {operation_id}")

    def _invoke_graph(
        self,
        actor: Any,
        operation_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        signed_payload = {
            "payload": dict(arguments["payload"]),
            "profile_ref": arguments["profile_ref"],
            "lease_ref": arguments["lease_ref"],
            "target": dict(arguments["target"]),
            "arguments_sha256": arguments["arguments_sha256"],
            "profile_scope_sha256": arguments["profile_scope_sha256"],
        }
        context = self._exchange_context(
            actor, signed_payload, GRAPH_BINDING_ID, operation_id, request_id
        )
        envelope = {**signed_payload, "trusted_context": context}
        wire = self.modules.graph_plugin.wire
        request = wire.CallToolRequest(
            binding_id=GRAPH_BINDING_ID,
            provider_tool_id=tool_id,
            arguments_json=json.dumps(envelope, separators=(",", ":")),
        )
        ok, response = self.graph_provider.on_invoke(
            self.modules.graph_plugin.CAPABILITY_ID,
            self.modules.graph_plugin.CALL_TOOL_METHOD,
            request.SerializeToString(deterministic=True),
            request_type_url=self.modules.graph_plugin.CALL_TOOL_REQUEST_TYPE_URL,
        )
        if not ok:
            raise RuntimeError(str(response))
        return self._decode_response(wire, response)

    def _invoke_ado(
        self,
        actor: Any,
        operation_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        signed_payload = {
            "payload": dict(arguments["payload"]),
            "profile_ref": arguments["profile_ref"],
            "lease_ref": arguments["lease_ref"],
            "target": dict(arguments["target"]),
            "arguments_sha256": arguments["arguments_sha256"],
            "profile_scope_sha256": arguments["profile_scope_sha256"],
        }
        context = self._exchange_context(
            actor, signed_payload, ADO_BINDING_ID, operation_id, request_id
        )
        envelope = {**signed_payload, "trusted_context": context}
        wire = self.modules.ado_plugin.wire
        request = wire.CallToolRequest(
            binding_id=ADO_BINDING_ID,
            provider_tool_id=tool_id,
            arguments_json=json.dumps(envelope, separators=(",", ":")),
        )
        ok, response = self.ado_provider.on_invoke(
            self.modules.ado_plugin.CAPABILITY_ID,
            self.modules.ado_plugin.CALL_TOOL_METHOD,
            request.SerializeToString(deterministic=True),
            request_type_url=self.modules.ado_plugin.CALL_TOOL_REQUEST_TYPE_URL,
        )
        if not ok:
            raise RuntimeError(str(response))
        return self._decode_response(wire, response)

    def _exchange_context(
        self,
        actor: Any,
        payload: Mapping[str, Any],
        binding_id: str,
        operation_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        signed = self.modules.contracts.sign_context(
            method="call_tool",
            payload=dict(payload),
            caller_id=EXCHANGE_CALLER,
            issuer=actor.issuer,
            subject=actor.subject,
            organization_id=actor.organization_id,
            workspace_id=actor.workspace_id,
            binding_id=binding_id,
            request_id=request_id,
            operation_id=operation_id,
            key=self.exchange_key,
            issued_at=int(datetime.now(UTC).timestamp()),
        )
        return signed.as_dict()

    @staticmethod
    def _decode_response(wire: Any, response: Any) -> dict[str, Any]:
        typed = wire.CallToolResponse.FromString(response.value)
        if typed.WhichOneof("result") != "outcome":
            raise RuntimeError("provider returned an invalid typed result")
        values = [
            json.loads(part.json.json)
            for part in typed.outcome.content
            if part.WhichOneof("content") == "json"
        ]
        if typed.outcome.is_error:
            code = (
                values[0].get("error", {}).get("code", "provider_error")
                if values
                else "provider_error"
            )
            raise RuntimeError(f"provider rejected operation: {code}")
        if len(values) != 1 or not isinstance(values[0], dict):
            raise RuntimeError("provider returned an invalid JSON result")
        return values[0]


class _SyntheticAdoHttp:
    """Return one empty pipeline-run page and record delegated REST calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def __call__(self, request: Any) -> Any:
        import httpx

        self.calls.append(
            (
                request.method,
                str(request.url),
                request.headers.get("Authorization"),
            )
        )
        assert request.method == "GET"
        assert str(request.url).startswith(
            f"https://dev.azure.com/{ADO_ORGANIZATION}/{ADO_PROJECT_ID}/"
        )
        assert request.headers.get("Authorization") == "Bearer synthetic-access-1"
        return httpx.Response(200, json={"count": 0, "value": []})


class _ConnectionStore:
    """Return one immutable actor-owned test connection to Exchange dispatch."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def current_connection_for_provider_call(self, connection_id: UUID) -> Any:
        return self.connection if connection_id == self.connection.id else None


class _RecordingAccountPort:
    """Keep the real Exchange account port and record only returned lease metadata."""

    def __init__(self, port: Any) -> None:
        self.port = port
        self.leases: list[Any] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.port, name)

    def create_provider_credential_lease(self, *args: Any, **kwargs: Any) -> Any:
        lease = self.port.create_provider_credential_lease(*args, **kwargs)
        self.leases.append(lease)
        return lease


def _make_spine(tmp_path: Path, modules: SimpleNamespace) -> SimpleNamespace:
    """Construct real Exchange, provider, and Account Center components locally."""

    from cyrene_exchange_product.integrations.auth import AccountCenterRequestSigner
    from cyrene_exchange_product.integrations.clients import (
        AccountCenterClient,
        IntegrationAccountCenterPort,
    )
    from cyrene_exchange_product.integrations.connector_operations import (
        ConnectorOperationDispatcher,
    )

    graph_oauth = _SyntheticEntraOAuth(modules)
    ado_oauth = _SyntheticEntraOAuth(modules)
    caller_keys = {
        EXCHANGE_CALLER: EXCHANGE_KEY,
        CALLBACK_CALLER: CALLBACK_KEY,
        GRAPH_CALLER: GRAPH_KEY,
        ADO_CALLER: ADO_KEY,
        "github-provider": b"h" * 32,
    }
    plugin = modules.account_center.AccountCenterPlugin(
        {
            "binding_id": AC_BINDING_ID,
            "storage_path": str(tmp_path / "account-center.sqlite3"),
            "encryption_key": b"e" * 32,
            "exchange_caller_id": EXCHANGE_CALLER,
            "github_provider_caller_id": "github-provider",
            "microsoft_graph_callback_uri": CALLBACK_URI,
            "microsoft_graph_callback_caller_id": CALLBACK_CALLER,
            "microsoft_graph_client_id": graph_oauth.client_id,
            "microsoft_graph_client_secret": "synthetic-only-client-secret",
            "microsoft_graph_provider_caller_id": GRAPH_CALLER,
            "azure_devops_provider_caller_id": ADO_CALLER,
            "caller_keys": caller_keys,
            "wecom_sources": {},
        },
        microsoft_graph_oauth_client=graph_oauth,
        azure_devops_oauth_client=ado_oauth,
    )
    direct = _AccountCenterDirectInvoker(plugin, modules.plugin_runtime.DirectPayload)
    account_client = AccountCenterClient(
        direct,
        exchange_signer=AccountCenterRequestSigner(
            caller_id=EXCHANGE_CALLER,
            key=EXCHANGE_KEY,
        ),
        callback_signer=AccountCenterRequestSigner(
            caller_id=CALLBACK_CALLER,
            key=CALLBACK_KEY,
        ),
        binding_id=AC_BINDING_ID,
    )
    account_port = _RecordingAccountPort(IntegrationAccountCenterPort(account_client))
    provider_transport = _LocalProviderTransport(modules, EXCHANGE_KEY)

    graph_settings = modules.graph_settings.ProviderSettings(
        binding_id=GRAPH_BINDING_ID,
        exchange_caller_id=EXCHANGE_CALLER,
        exchange_verification_key=EXCHANGE_KEY,
        account_center_binding_id=AC_BINDING_ID,
        account_center_connection_ref="grpc://synthetic-account-center",
        account_center_transport="local",
        provider_caller_id=GRAPH_CALLER,
        provider_signing_key=GRAPH_KEY,
        account_center_root_cert_ref=None,
        account_center_client_cert_ref=None,
        account_center_client_key_ref=None,
        host_secret_names={},
        read_only=False,
        timeout_seconds=1,
        max_page_size=100,
        sharepoint_site_id=GRAPH_SITE_ID,
        sharepoint_list_ids=(GRAPH_LIST_ID,),
    )
    graph_http = _SyntheticGraphHttp(modules.graph_api.HttpResponse)
    graph_account_center = modules.graph_account_center.AccountCenterDirectClient(
        graph_settings,
        client=direct,
    )
    graph_api = modules.graph_api.MicrosoftGraphApi(
        cursor_key=b"k" * 32,
        timeout_seconds=1,
        transport=graph_http,
    )
    graph_provider = modules.graph_plugin.MicrosoftGraphProvider(
        settings=graph_settings,
        account_center=graph_account_center,
        graph_api=graph_api,
    )
    provider_transport.graph_provider = graph_provider

    graph_host_profile = SimpleNamespace(
        provider="microsoft_graph",
        access_mode="actor_owned",
        microsoft_graph_plan_ids=(GRAPH_PLAN_ID,),
        microsoft_graph_sharepoint_site_id=GRAPH_SITE_ID,
        microsoft_graph_sharepoint_list_ids=(GRAPH_LIST_ID,),
        targets={},
    )
    graph_dispatcher = ConnectorOperationDispatcher(
        store=None,
        accounts=account_port,
        github=None,
        authorization_cloud=provider_transport,
        registry=SimpleNamespace(
            settings=SimpleNamespace(profiles={GRAPH_BINDING_ID: graph_host_profile})
        ),
    )

    ado_source = modules.ado_settings.AuthorizedSource(
        source_id=ADO_SOURCE_ID,
        kind="pipeline_runs",
        project_id=ADO_PROJECT_ID,
        project_name="Synthetic pipeline",
        profile_ref=ADO_PROFILE_REF,
        pipeline_id=ADO_PIPELINE_ID,
    )
    ado_settings = modules.ado_settings.ProviderSettings(
        binding_id=ADO_BINDING_ID,
        account_center_binding_id=AC_BINDING_ID,
        account_center_connection_ref="grpc://synthetic-account-center",
        account_center_transport="local",
        account_center_root_cert_ref=None,
        account_center_client_cert_ref=None,
        account_center_client_key_ref=None,
        host_secret_names={},
        organization=ADO_ORGANIZATION,
        tenant_id=TENANT_ID,
        sources=(ado_source,),
        provider_caller_id=ADO_CALLER,
        exchange_caller_id=EXCHANGE_CALLER,
        exchange_verification_key=EXCHANGE_KEY,
        provider_signing_key=ADO_KEY,
        timeout_seconds=1,
    )
    ado_account_center = modules.ado_account_center.AccountCenterDirectLeaseClient(
        ado_settings,
        client=direct,
    )
    ado_http = _SyntheticAdoHttp()
    import httpx

    ado_api = modules.ado_api.AzureDevOpsApi(
        ado_settings,
        client=httpx.Client(
            transport=httpx.MockTransport(ado_http),
            follow_redirects=False,
            trust_env=False,
        ),
    )
    ado_provider = modules.ado_plugin.AzureDevOpsObservationProvider(
        settings=ado_settings,
        account_center_client=ado_account_center,
        api=ado_api,
    )
    provider_transport.ado_provider = ado_provider
    ado_host_profile = SimpleNamespace(
        provider="azure_devops",
        access_mode="actor_owned",
        azure_devops_tenant_id=TENANT_ID,
        azure_devops_organization=ADO_ORGANIZATION,
        authorized_sources={
            ADO_SOURCE_ID: SimpleNamespace(
                source_id=ADO_SOURCE_ID,
                kind="pipeline_runs",
                project_id=ADO_PROJECT_ID,
                project_name="Synthetic pipeline",
                profile_ref=ADO_PROFILE_REF,
                pipeline_id=ADO_PIPELINE_ID,
                definition_id=None,
                definition_environment_id=None,
            )
        },
        endpoint=SimpleNamespace(binding_id=ADO_BINDING_ID),
    )
    ado_dispatcher = ConnectorOperationDispatcher(
        store=None,
        accounts=account_port,
        github=None,
        authorization_cloud=provider_transport,
        registry=SimpleNamespace(settings=SimpleNamespace(profiles={"ado-host": ado_host_profile})),
    )
    return SimpleNamespace(
        plugin=plugin,
        account_client=account_client,
        account_port=account_port,
        direct=direct,
        provider_transport=provider_transport,
        graph_provider=graph_provider,
        graph_dispatcher=graph_dispatcher,
        graph_http=graph_http,
        graph_oauth=graph_oauth,
        ado_provider=ado_provider,
        ado_dispatcher=ado_dispatcher,
        ado_http=ado_http,
        ado_oauth=ado_oauth,
        _lease_row=lambda lease_ref: _lease_row(plugin, lease_ref),
    )


class _AccountCenterDirectInvoker:
    """Bridge DirectPlugin request envelopes into the real Account Center plugin."""

    def __init__(self, plugin: Any, payload_type: Any) -> None:
        self.plugin = plugin
        self.payload_type = payload_type

    def invoke(
        self,
        *,
        capability: str,
        interface_version: str,
        method: str,
        request: Any,
        deadline_seconds: float | None = None,
        request_id: str | None = None,
        **_: Any,
    ) -> Any:
        del interface_version, deadline_seconds
        ok, result = self.plugin.on_invoke(
            capability,
            method,
            request.value,
            request_type_url=request.type_url,
            request_id=request_id,
        )
        if not ok:
            raise RuntimeError(str(result))
        return self.payload_type(type_url=result.type_url, value=result.value)


def _principal(
    *,
    subject: str = OBJECT_ID,
    workspace_id: str = WORKSPACE_ID,
    operations: set[str],
) -> Any:
    principal_type = importlib.import_module(
        "cyrene_exchange_product.integrations.models"
    ).IntegrationPrincipal
    return principal_type(
        issuer=ISSUER,
        subject=subject,
        organization_id=ORGANIZATION_ID,
        workspace_id=workspace_id,
        allowed_operation_ids=frozenset(operations),
    )


def _lease_row(plugin: Any, lease_ref: str) -> dict[str, Any]:
    """Read one synthetic lease row to verify exact binding and one-use status."""

    with plugin._store._connect() as db:
        row = db.execute(
            "SELECT lease_ref,operation_id,target_json,arguments_sha256,redeemed_at "
            "FROM provider_credential_leases WHERE lease_ref=?",
            (lease_ref,),
        ).fetchone()
    assert row is not None
    return dict(row)


def _complete_graph_link(spine: SimpleNamespace, principal: Any) -> None:
    session = spine.account_client.begin_microsoft_graph_link(
        principal,
        profile_ref=GRAPH_PROFILE_REF,
        planner_plan_ids=[GRAPH_PLAN_ID],
        idempotency_key="synthetic-graph-link",
    )
    state = parse_qs(urlparse(session["authorization_url"]).query)["state"][0]
    spine.account_client.complete_microsoft_graph_link(
        principal,
        state=state,
        code="synthetic-graph-code",
    )
    for permission, suffix, site_id, list_ids in (
        ("planner_tasks_write", "write", None, None),
        ("sharepoint_selected", "sharepoint", GRAPH_SITE_ID, [GRAPH_LIST_ID]),
    ):
        upgrade = spine.account_client.begin_microsoft_graph_scope_upgrade(
            principal,
            profile_ref=GRAPH_PROFILE_REF,
            permission=permission,
            idempotency_key=f"synthetic-graph-{suffix}",
            site_id=site_id,
            list_ids=list_ids,
        )
        upgrade_state = parse_qs(urlparse(upgrade["authorization_url"]).query)["state"][0]
        spine.account_client.complete_microsoft_graph_scope_upgrade(
            principal,
            state=upgrade_state,
            code=f"synthetic-graph-{suffix}-code",
        )


def _complete_ado_link(spine: SimpleNamespace, principal: Any) -> None:
    session = spine.account_client.begin_azure_devops_link(
        principal,
        profile_ref=ADO_PROFILE_REF,
        tenant_id=TENANT_ID,
        organization=ADO_ORGANIZATION,
        project_id=ADO_PROJECT_ID,
        source_id=ADO_SOURCE_ID,
        source_kind="pipeline_runs",
        pipeline_id=ADO_PIPELINE_ID,
        idempotency_key="synthetic-ado-link",
    )
    state = parse_qs(urlparse(session["authorization_url"]).query)["state"][0]
    spine.account_client.complete_azure_devops_link(
        principal,
        state=state,
        code="synthetic-ado-code",
    )


def _claims(prepared: Any) -> Any:
    from cyrene_exchange_product.integrations.connector_security import digest_arguments

    return SimpleNamespace(
        grant_ref=f"synthetic-grant-{prepared.request_id}",
        request_id=prepared.request_id,
        organization_id=prepared.principal.organization_id,
        workspace_id=prepared.principal.workspace_id,
        principal_issuer=prepared.principal.issuer,
        principal_subject=prepared.principal.subject,
        connection_ref=prepared.connection_ref,
        provider_id=prepared.provider_id,
        profile_ref=prepared.profile_ref,
        operation_id=prepared.operation_id,
        resource_ref=prepared.resource_ref,
        arguments_digest_sha256=bytes.fromhex(digest_arguments(prepared.arguments)),
    )


def _prepare_graph(
    spine: SimpleNamespace,
    principal: Any,
    operation_id: str,
    arguments: Mapping[str, Any],
    request_id: str,
) -> Any:
    from cyrene_exchange_product.integrations.connector_operations import _resource_ref

    resource_target = importlib.import_module(
        "cyrene_exchange_product.integrations.microsoft_graph"
    ).target_for_operation
    profile = spine.account_client.list_provider_profiles(principal)["profiles"]
    graph_profile = next(row for row in profile if row["profile_ref"] == GRAPH_PROFILE_REF)
    account_target = resource_target(operation_id, arguments, graph_profile["target_scope"])
    resource_ref = _resource_ref(
        provider_id="microsoft_graph",
        profile_ref=GRAPH_PROFILE_REF,
        operation_id=operation_id,
        target=account_target,
    )
    connection = spine.graph_dispatcher._store.connection
    return spine.graph_dispatcher.prepare_connection_operation(
        principal=principal,
        connection=connection,
        provider_id="microsoft_graph",
        profile_ref=GRAPH_PROFILE_REF,
        operation_id=operation_id,
        resource_ref=resource_ref,
        arguments=arguments,
        request_id=request_id,
    )


def _graph_connection() -> Any:
    from cyrene_exchange_product.integrations.models import IntegrationConnection

    return IntegrationConnection(
        id=CONNECTION_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        actor_issuer=ISSUER,
        actor_subject=OBJECT_ID,
        account_link_ref=GRAPH_PROFILE_REF,
        provider="microsoft_graph",
        binding_ref=GRAPH_BINDING_ID,
        target_ref=None,
        display_name="Synthetic Graph profile",
        access_mode="actor_owned",
    )


def test_exchange_graph_dispatch_reaches_provider_and_consumes_exact_account_leases(
    tmp_path: Path,
    plugin_modules: SimpleNamespace,
) -> None:
    """Run all eight Graph operations through Exchange, Provider, and Account Center."""

    from cyrene_exchange_product.integrations.connector_security import digest_arguments
    from cyrene_exchange_product.integrations.microsoft_graph import (
        lease_arguments_for_operation,
    )
    from cyrene_exchange_product.integrations.models import IntegrationConnection

    spine = _make_spine(tmp_path, plugin_modules)
    operations = {
        "microsoft_graph.planner.plan.get": {"plan_id": GRAPH_PLAN_ID},
        "microsoft_graph.planner.tasks.list": {
            "plan_id": GRAPH_PLAN_ID,
            "page_size": 20,
        },
        "microsoft_graph.planner.task.get": {
            "plan_id": GRAPH_PLAN_ID,
            "task_id": GRAPH_TASK_ID,
        },
        "microsoft_graph.planner.task.create": {
            "plan_id": GRAPH_PLAN_ID,
            "bucket_id": GRAPH_BUCKET_ID,
            "title": "Synthetic create",
        },
        "microsoft_graph.planner.task.update": {
            "plan_id": GRAPH_PLAN_ID,
            "task_id": GRAPH_TASK_ID,
            "if_match": 'W/"synthetic-etag-1"',
            "changes": {"percent_complete": 50},
        },
        "microsoft_graph.sharepoint.site.get": {"site_id": GRAPH_SITE_ID},
        "microsoft_graph.sharepoint.list.get": {
            "site_id": GRAPH_SITE_ID,
            "list_id": GRAPH_LIST_ID,
        },
        "microsoft_graph.sharepoint.list.items.delta": {
            "site_id": GRAPH_SITE_ID,
            "list_id": GRAPH_LIST_ID,
            "page_size": 20,
        },
    }
    principal = _principal(operations=set(operations))
    _complete_graph_link(spine, principal)
    connection = IntegrationConnection(
        id=CONNECTION_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        actor_issuer=ISSUER,
        actor_subject=OBJECT_ID,
        account_link_ref=GRAPH_PROFILE_REF,
        provider="microsoft_graph",
        binding_ref=GRAPH_BINDING_ID,
        target_ref=None,
        display_name="Synthetic Graph profile",
        access_mode="actor_owned",
    )
    spine.graph_dispatcher._store = _ConnectionStore(connection)

    other_actor = _principal(
        subject=OTHER_OBJECT_ID,
        operations=set(operations),
    )
    with pytest.raises(PermissionError):
        spine.graph_dispatcher.prepare_connection_operation(
            principal=other_actor,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=GRAPH_PROFILE_REF,
            operation_id="microsoft_graph.planner.tasks.list",
            resource_ref="sha256:" + "0" * 64,
            arguments=operations["microsoft_graph.planner.tasks.list"],
            request_id="graph-other-actor",
        )

    first_operation = "microsoft_graph.planner.plan.get"
    first_prepared = _prepare_graph(
        spine,
        principal,
        first_operation,
        operations[first_operation],
        "graph-owner-check",
    )
    before_http = len(spine.graph_http.calls)
    spine.provider_transport.actor_override = other_actor
    with pytest.raises(RuntimeError, match="provider rejected operation"):
        spine.graph_dispatcher.invoke(
            first_prepared,
            principal=principal,
            claims=_claims(first_prepared),
        )
    spine.provider_transport.actor_override = None
    assert len(spine.graph_http.calls) == before_http
    rejected_lease = spine.account_port.leases[-1]
    assert spine._lease_row(rejected_lease.lease_ref)["redeemed_at"] is None

    for index, (operation_id, arguments) in enumerate(operations.items(), start=1):
        prepared = _prepare_graph(
            spine,
            principal,
            operation_id,
            arguments,
            f"graph-operation-{index}",
        )
        result = spine.graph_dispatcher.invoke(
            prepared,
            principal=principal,
            claims=_claims(prepared),
        )
        assert isinstance(result, Mapping)
        assert spine.provider_transport.invocations[-1]["profile_ref"] == GRAPH_PROFILE_REF
        assert "access_token" not in spine.provider_transport.invocations[-1]

        lease = spine.account_port.leases[-1]
        projected = lease_arguments_for_operation(operation_id, arguments)
        assert lease.operation_id == operation_id
        assert lease.target == prepared.account_lease_target
        assert lease.arguments_sha256 == digest_arguments(projected)
        row = spine._lease_row(lease.lease_ref)
        assert json.loads(row["target_json"]) == dict(prepared.account_lease_target)
        assert row["arguments_sha256"] == digest_arguments(projected)
        assert row["redeemed_at"] is not None

    expected_resource_paths = {
        f"/v1.0/planner/plans/{GRAPH_PLAN_ID}",
        f"/v1.0/planner/plans/{GRAPH_PLAN_ID}/tasks",
        f"/v1.0/planner/tasks/{GRAPH_TASK_ID}",
        "/v1.0/planner/tasks",
        "/v1.0/planner/buckets/" + GRAPH_BUCKET_ID,
        "/v1.0/sites/" + GRAPH_SITE_ID,
        f"/v1.0/sites/{GRAPH_SITE_ID}/lists/{GRAPH_LIST_ID}",
        f"/v1.0/sites/{GRAPH_SITE_ID}/lists/{GRAPH_LIST_ID}/items/delta",
    }
    observed_paths = {path.split("?", 1)[0] for _method, _host, path in spine.graph_http.calls}
    assert expected_resource_paths <= observed_paths

    last_lease = spine.account_port.leases[-1]
    profile = spine.account_client.list_provider_profiles(principal)["profiles"]
    scope = next(row["target_scope"] for row in profile if row["profile_ref"] == GRAPH_PROFILE_REF)
    replay_payload = {
        "lease_ref": last_lease.lease_ref,
        "profile_ref": GRAPH_PROFILE_REF,
        "operation_id": last_lease.operation_id,
        "target": dict(last_lease.target),
        "arguments_sha256": last_lease.arguments_sha256,
    }
    before_replay_http = len(spine.graph_http.calls)
    with pytest.raises(plugin_modules.graph_account_center.AccountCenterUnavailable):
        spine.graph_provider._require_account_center().redeem_provider_credential_lease(
            replay_payload,
            {
                "issuer": principal.issuer,
                "subject": principal.subject,
                "organization_id": principal.organization_id,
                "workspace_id": principal.workspace_id,
            },
        )
    assert plugin_modules.contracts.payload_sha256(scope) == last_lease.profile_scope_sha256
    assert len(spine.graph_http.calls) == before_replay_http


def _office_v2_operation_arguments() -> dict[str, dict[str, Any]]:
    """Build a valid payload for every fixed Graph operation."""

    event_window = {
        "start_date_time": "2026-11-02T10:00:00-05:00",
        "end_date_time": "2026-11-02T10:30:00-05:00",
    }
    from cyrene_exchange_product.integrations.microsoft_graph import GRAPH_OPERATIONS

    values: dict[str, dict[str, Any]] = {}
    for operation_id in sorted(GRAPH_OPERATIONS):
        if operation_id == "microsoft_graph.planner.plan.get":
            arguments = {"plan_id": GRAPH_PLAN_ID}
        elif operation_id == "microsoft_graph.planner.plans.list":
            arguments = {"page_size": 10}
        elif operation_id == "microsoft_graph.planner.tasks.list":
            arguments = {"plan_id": GRAPH_PLAN_ID, "page_size": 10}
        elif operation_id == "microsoft_graph.planner.task.get":
            arguments = {"plan_id": GRAPH_PLAN_ID, "task_id": GRAPH_TASK_ID}
        elif operation_id == "microsoft_graph.planner.task.create":
            arguments = {
                "plan_id": GRAPH_PLAN_ID,
                "bucket_id": GRAPH_BUCKET_ID,
                "title": "Office v2 task",
            }
        elif operation_id == "microsoft_graph.planner.task.update":
            arguments = {
                "plan_id": GRAPH_PLAN_ID,
                "task_id": GRAPH_TASK_ID,
                "if_match": 'W/"synthetic-etag-1"',
                "changes": {"title": "Updated office v2 task"},
            }
        elif operation_id == "microsoft_graph.sharepoint.site.get":
            arguments = {"site_id": GRAPH_V2_SITE_ID}
        elif operation_id in {
            "microsoft_graph.sharepoint.list.get",
            "microsoft_graph.sharepoint.list.items.delta",
        }:
            arguments = {"site_id": GRAPH_V2_SITE_ID, "list_id": GRAPH_V2_LIST_ID}
            if operation_id.endswith("items.delta"):
                arguments["page_size"] = 10
        elif operation_id == "microsoft_graph.todo.lists.list":
            arguments = {"page_size": 10}
        elif operation_id == "microsoft_graph.todo.tasks.list":
            arguments = {"task_list_id": GRAPH_V2_TASK_LIST_ID, "page_size": 10}
        elif operation_id == "microsoft_graph.todo.task.get":
            arguments = {
                "task_list_id": GRAPH_V2_TASK_LIST_ID,
                "task_id": "AAMkTask-opaque==",
            }
        elif operation_id == "microsoft_graph.todo.task.create":
            arguments = {"task_list_id": GRAPH_V2_TASK_LIST_ID, "title": "To Do v2 task"}
        elif operation_id == "microsoft_graph.todo.task.update":
            arguments = {
                "task_list_id": GRAPH_V2_TASK_LIST_ID,
                "task_id": "AAMkTask-opaque==",
                "if_match": 'W/"synthetic-etag-1"',
                "changes": {"title": "Updated To Do task"},
            }
        elif operation_id == "microsoft_graph.todo.task.delete":
            arguments = {
                "task_list_id": GRAPH_V2_TASK_LIST_ID,
                "task_id": "AAMkTask-opaque==",
                "if_match": 'W/"synthetic-etag-1"',
            }
        elif operation_id == "microsoft_graph.calendar.calendars.list":
            arguments = {"page_size": 10}
        elif operation_id == "microsoft_graph.calendar.events.list":
            arguments = {"calendar_id": GRAPH_V2_CALENDAR_ID, **event_window, "page_size": 10}
        elif operation_id == "microsoft_graph.calendar.event.get":
            arguments = {
                "calendar_id": GRAPH_V2_CALENDAR_ID,
                "event_id": "AAMkEvent-opaque==",
            }
        elif operation_id == "microsoft_graph.calendar.event.create":
            arguments = {
                "calendar_id": GRAPH_V2_CALENDAR_ID,
                "subject": "Office v2 event",
                **event_window,
                "transaction_id": "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa",
            }
        elif operation_id == "microsoft_graph.calendar.event.update":
            arguments = {
                "calendar_id": GRAPH_V2_CALENDAR_ID,
                "event_id": "AAMkEvent-opaque==",
                "if_match": 'W/"synthetic-etag-1"',
                "changes": {"subject": "Updated office v2 event"},
            }
        elif operation_id == "microsoft_graph.calendar.event.delete":
            arguments = {
                "calendar_id": GRAPH_V2_CALENDAR_ID,
                "event_id": "AAMkEvent-opaque==",
                "if_match": 'W/"synthetic-etag-1"',
            }
        elif operation_id == "microsoft_graph.calendar.freebusy.get":
            arguments = {
                "schedules": [GRAPH_V2_FREEBUSY_SUBJECT.upper()],
                "start_date_time": "2026-11-02T10:00:00-05:00",
                "end_date_time": "2026-11-02T10:30:00-05:00",
                "interval_minutes": 15,
            }
        elif operation_id == "microsoft_graph.sharepoint.drives.list":
            arguments = {"site_id": GRAPH_V2_SITE_ID, "page_size": 10}
        elif operation_id == "microsoft_graph.sharepoint.drive.items.list":
            arguments = {
                "site_id": GRAPH_V2_SITE_ID,
                "drive_id": GRAPH_V2_DRIVE_ID,
                "parent_item_id": "folder!opaque==",
                "page_size": 10,
            }
        else:
            raise AssertionError(f"No Graph fixture arguments for {operation_id}")
        values[operation_id] = arguments
    return values


def test_exchange_account_center_and_provider_agree_on_all_office_v2_targets(
    tmp_path: Path,
    plugin_modules: SimpleNamespace,
) -> None:
    """Use the installed SDK, real Account Center leases, and Provider target projection."""

    from cyrene_exchange_product.integrations.connector_operations import (
        _resource_ref,
    )
    from cyrene_exchange_product.integrations.connector_security import digest_arguments
    from cyrene_exchange_product.integrations.microsoft_graph import (
        GRAPH_OPERATIONS,
        lease_arguments_for_operation,
        target_for_operation,
    )

    features = {
        "plannerEnabled": True,
        "todoEnabled": True,
        "calendarEnabled": True,
        "mailMetadataEnabled": False,
        "mailDraftsEnabled": False,
        "mailSendEnabled": False,
        "sharePointDriveMetadataEnabled": True,
    }
    office_scope_host = SimpleNamespace(
        tenant_id=TENANT_ID,
        workspace_id=GRAPH_V2_WORKSPACE_ID,
        enabled_features=features,
        targets={
            "plannerPlanIds": (),
            "sharePointSiteIds": (GRAPH_V2_SITE_ID,),
            "sharePointListIds": (),
            "sharePointDriveIds": (),
            "toDoTaskListIds": (),
            "calendarIds": (),
            "mailFolderIds": (),
            "freebusySubjects": (GRAPH_V2_FREEBUSY_SUBJECT,),
        },
    )
    host_profile = SimpleNamespace(
        profile_ref=GRAPH_BINDING_ID,
        provider="microsoft_graph",
        access_mode="actor_owned",
        expected_issuer=ISSUER,
        organization_id=ORGANIZATION_ID,
        workspace_id=GRAPH_V2_WORKSPACE_ID,
        microsoft_graph_plan_ids=(),
        microsoft_graph_sharepoint_site_id=GRAPH_V2_SITE_ID,
        microsoft_graph_sharepoint_list_ids=(),
        microsoft_graph_office_v2=office_scope_host,
    )
    spine = _make_spine(tmp_path, plugin_modules)
    principal = _principal(
        workspace_id=GRAPH_V2_WORKSPACE_ID,
        operations=set(GRAPH_OPERATIONS),
    )
    initial_scope = importlib.import_module(
        "cyrene_exchange_product.integrations.authorization_cloud_profiles"
    ).microsoft_graph_office_v2_scope(host_profile, principal)
    session = spine.account_client.begin_microsoft_graph_link(
        principal,
        profile_ref=GRAPH_PROFILE_REF,
        planner_plan_ids=[],
        idempotency_key="office-v2-initial-link",
        office_v2_scope=initial_scope,
    )
    state = parse_qs(urlparse(session["authorization_url"]).query)["state"][0]
    spine.account_client.complete_microsoft_graph_link(
        principal,
        state=state,
        code="synthetic-office-v2-code",
    )
    profile_rows = spine.account_client.list_provider_profiles(principal)["profiles"]
    profile = next(row for row in profile_rows if row["profile_ref"] == GRAPH_PROFILE_REF)
    assert profile["credential_revision"] == 0
    assert profile["target_scope"] == initial_scope
    assert "Mail.Send" not in profile["oauth_scopes"]

    connection = importlib.import_module(
        "cyrene_exchange_product.integrations.models"
    ).IntegrationConnection(
        id=CONNECTION_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=GRAPH_V2_WORKSPACE_ID,
        actor_issuer=ISSUER,
        actor_subject=OBJECT_ID,
        account_link_ref=GRAPH_PROFILE_REF,
        provider="microsoft_graph",
        binding_ref=GRAPH_BINDING_ID,
        target_ref=None,
        display_name="Office v2 profile",
        access_mode="actor_owned",
    )
    spine.graph_dispatcher._store = _ConnectionStore(connection)
    spine.graph_dispatcher._registry.settings.profiles[GRAPH_BINDING_ID] = host_profile

    def create_and_compare_lease(
        operation_id: str,
        arguments: Mapping[str, Any],
        index: int,
    ) -> None:
        """Exercise Exchange projection, Account Center exact targets, and Provider target."""

        current_profile = next(
            row
            for row in spine.account_client.list_provider_profiles(principal)["profiles"]
            if row["profile_ref"] == GRAPH_PROFILE_REF
        )
        scope = current_profile["target_scope"]
        projection = target_for_operation(operation_id, arguments, scope)
        resource_ref = _resource_ref(
            provider_id="microsoft_graph",
            profile_ref=GRAPH_PROFILE_REF,
            operation_id=operation_id,
            target=projection,
        )
        prepared = spine.graph_dispatcher.prepare_connection_operation(
            principal=principal,
            connection=connection,
            provider_id="microsoft_graph",
            profile_ref=GRAPH_PROFILE_REF,
            operation_id=operation_id,
            resource_ref=resource_ref,
            arguments=arguments,
            request_id=f"office-v2-target-{index}",
        )
        exchange_arguments = lease_arguments_for_operation(operation_id, arguments)
        provider_arguments = plugin_modules.graph_plugin._arguments_for_lease(
            operation_id,
            arguments,
        )
        assert provider_arguments == exchange_arguments, operation_id
        provider_target = plugin_modules.graph_plugin._target(scope, operation_id, arguments)
        assert provider_target == prepared.account_lease_target, operation_id
        provider_profile = plugin_modules.contracts.ProviderProfile(
            profile_ref=GRAPH_PROFILE_REF,
            provider="microsoft_graph",
            identity_ref=current_profile["identity_ref"],
            target_scope=scope,
            auth_status=current_profile["auth_status"],
            auth_mode=current_profile["auth_mode"],
            oauth_scopes=current_profile["oauth_scopes"],
            access_mode=current_profile["access_mode"],
            external_subject=current_profile["external_subject"],
            expires_at=current_profile["expires_at"],
            refresh_expires_at=current_profile["refresh_expires_at"],
            credential_revision=current_profile["credential_revision"],
            scope_schema_version=current_profile["scope_schema_version"],
            reauth_required=current_profile["reauth_required"],
        )
        plugin_modules.graph_plugin._authorize_profile(
            scope,
            operation_id,
            arguments,
            provider_profile,
            settings=spine.graph_provider._require_settings(),
            expected_external_subject=f"{TENANT_ID}:{OBJECT_ID}",
            expected_workspace_id=GRAPH_V2_WORKSPACE_ID,
        )
        lease = spine.account_port.create_provider_credential_lease(
            principal,
            profile_ref=GRAPH_PROFILE_REF,
            operation_id=operation_id,
            target=prepared.account_lease_target,
            arguments_sha256=digest_arguments(exchange_arguments),
        )
        assert lease.target == provider_target
        assert lease.arguments_sha256 == digest_arguments(provider_arguments)
        row = spine._lease_row(lease.lease_ref)
        assert json.loads(row["target_json"]) == provider_target
        assert row["arguments_sha256"] == digest_arguments(provider_arguments)
        assert row["redeemed_at"] is None

    operation_arguments = _office_v2_operation_arguments()
    assert set(operation_arguments) == GRAPH_OPERATIONS
    for index, operation_id in enumerate(
        (
            "microsoft_graph.planner.plans.list",
            "microsoft_graph.todo.lists.list",
            "microsoft_graph.calendar.calendars.list",
            "microsoft_graph.sharepoint.drives.list",
        )
    ):
        create_and_compare_lease(operation_id, operation_arguments[operation_id], index)

    selected_scope = json.loads(json.dumps(initial_scope))
    selected_scope["planner"]["plan_ids"] = [GRAPH_PLAN_ID]
    selected_scope["sharepoint"]["list_ids"] = [GRAPH_V2_LIST_ID]
    selected_scope["sharepoint"]["drive_ids"] = [GRAPH_V2_DRIVE_ID]
    selected_scope["todo"]["task_list_ids"] = [GRAPH_V2_TASK_LIST_ID]
    selected_scope["calendar"]["calendar_ids"] = [GRAPH_V2_CALENDAR_ID]
    selected_scope = plugin_modules.account_center._safe_microsoft_graph_profile_scope(
        selected_scope
    )
    updated = spine.account_client.update_microsoft_graph_v2_scope(
        principal,
        profile_ref=GRAPH_PROFILE_REF,
        workspace_id=GRAPH_V2_WORKSPACE_ID,
        expected_credential_revision=0,
        target_scope=selected_scope,
        idempotency_key="office-v2-target-cas",
    )
    assert updated["credential_revision"] == 1
    assert updated["target_scope"] == selected_scope
    for index, (operation_id, arguments) in enumerate(operation_arguments.items(), start=10):
        create_and_compare_lease(operation_id, arguments, index)


def test_exchange_ado_poll_binds_scope_digest_and_unlink_revokes_pending_lease(
    tmp_path: Path,
    plugin_modules: SimpleNamespace,
) -> None:
    """Run one ADO poll through Exchange and prove Account Center revocation."""

    from cyrene_exchange_product.integrations.connector_operations import _resource_ref
    from cyrene_exchange_product.integrations.connector_security import digest_arguments
    from cyrene_exchange_product.integrations.models import IntegrationConnection
    from cyrene_exchange_product.integrations.ports import ProviderCredentialLeaseEvidence

    spine = _make_spine(tmp_path, plugin_modules)
    operation_id = "azure_devops.observations.poll"
    principal = _principal(operations={operation_id})
    _complete_ado_link(spine, principal)
    connection = IntegrationConnection(
        id=CONNECTION_ID,
        organization_id=ORGANIZATION_ID,
        workspace_id=WORKSPACE_ID,
        actor_issuer=ISSUER,
        actor_subject=OBJECT_ID,
        account_link_ref=ADO_PROFILE_REF,
        provider="azure_devops",
        binding_ref="ado-host",
        target_ref=ADO_SOURCE_ID,
        display_name="Synthetic Azure DevOps source",
        access_mode="actor_owned",
    )
    spine.ado_dispatcher._store = _ConnectionStore(connection)
    arguments = {
        "target": {
            "id": ADO_SOURCE_ID,
            "kind": "pipeline_runs",
            "bindingId": ADO_BINDING_ID,
        },
        "pageSize": 10,
        "pageCursor": None,
        "windowStart": None,
        "windowEnd": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    target_projection = {key: value for key, value in arguments["target"].items()}
    resource_ref = _resource_ref(
        provider_id="azure_devops",
        profile_ref=ADO_PROFILE_REF,
        operation_id=operation_id,
        target=target_projection,
    )
    prepared = spine.ado_dispatcher.prepare_connection_operation(
        principal=principal,
        connection=connection,
        provider_id="azure_devops",
        profile_ref=ADO_PROFILE_REF,
        operation_id=operation_id,
        resource_ref=resource_ref,
        arguments=arguments,
        request_id="ado-poll-owner",
    )
    result = spine.ado_dispatcher.invoke(
        prepared,
        principal=principal,
        claims=_claims(prepared),
    )
    assert isinstance(result, Mapping)
    assert len(spine.ado_http.calls) == 1
    lease = spine.account_port.leases[-1]
    assert lease.operation_id == operation_id
    assert lease.arguments_sha256 == digest_arguments(arguments)
    profile = spine.account_client.list_provider_profiles(principal)["profiles"]
    scope = next(row["target_scope"] for row in profile if row["profile_ref"] == ADO_PROFILE_REF)
    assert lease.profile_scope_sha256 == plugin_modules.contracts.payload_sha256(scope)
    lease_row = spine._lease_row(lease.lease_ref)
    assert json.loads(lease_row["target_json"]) == dict(lease.target)
    assert lease_row["redeemed_at"] is not None

    # Keep one second lease pending, then unlink and prove stale redemption cannot reach ADO.
    pending = spine.account_port.create_provider_credential_lease(
        principal,
        profile_ref=ADO_PROFILE_REF,
        operation_id=operation_id,
        target=dict(lease.target),
        arguments_sha256=digest_arguments(arguments),
    )
    assert isinstance(pending, ProviderCredentialLeaseEvidence)
    spine.account_client.unlink_provider_profile(
        principal,
        profile_ref=ADO_PROFILE_REF,
        idempotency_key="synthetic-ado-unlink",
    )
    before_revoked_replay = len(spine.ado_http.calls)
    with pytest.raises(RuntimeError, match="provider rejected operation"):
        spine.provider_transport.invoke_connector_tool(
            principal=principal,
            connection=connection,
            operation_id=operation_id,
            tool_id=prepared.tool_id,
            request_id="ado-revoked-lease-replay",
            arguments={
                "profile_ref": ADO_PROFILE_REF,
                "lease_ref": pending.lease_ref,
                "target": dict(pending.target),
                "arguments_sha256": pending.arguments_sha256,
                "profile_scope_sha256": pending.profile_scope_sha256,
                "payload": dict(prepared.arguments),
            },
        )
    assert len(spine.ado_http.calls) == before_revoked_replay
    with spine.plugin._store._connect() as db:
        profile_row = db.execute(
            "SELECT status,auth_status,credential_blob,credential_refresh_blob "
            "FROM provider_profiles WHERE profile_ref=?",
            (ADO_PROFILE_REF,),
        ).fetchone()
        stale_lease = db.execute(
            "SELECT COUNT(*) FROM provider_credential_leases WHERE lease_ref=?",
            (pending.lease_ref,),
        ).fetchone()[0]
    assert profile_row is not None
    assert profile_row["status"] == "unlinked"
    assert profile_row["auth_status"] == "revoked"
    assert profile_row["credential_blob"] is None
    assert profile_row["credential_refresh_blob"] is None
    assert stale_lease == 0
