"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 connector_profiles.py                                           │
│  Module: cyrene_exchange_product.integrations.connector_profiles    │
│  Role: Parse Navigator, Teams, and isolated computer host bindings.  │
│                                                                      │
│  模块职责：解析 Navigator HMAC、Teams 与 computer runner Host 绑定。  │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cyrene_exchange_product.integrations.authorization_cloud_profiles import (
    DirectPluginEndpointConfig,
    _endpoint,
    _object,
)

_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,299}$")
_SHORT_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_SECRET_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,1023}$")
_AAD_ISSUER = re.compile(r"^https://login\.microsoftonline\.com/([0-9a-fA-F-]{36})/v2\.0$")
_TEAMS_SERVICE_REGIONS = frozenset({"amer", "in", "emea", "apac"})
_UUID_PATH = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ConnectorHostConfigurationError(ValueError):
    """Navigator or host connector settings are incomplete or ambiguous."""


@dataclass(frozen=True, slots=True)
class NavigatorConnectorSettings:
    """Navigator service key file reference for internal grant mint requests."""

    key_id: str
    key_file_ref: str


@dataclass(frozen=True, slots=True)
class TeamsMessageProfile:
    """One fixed Teams bot and conversation allowlist for Exchange message egress."""

    profile_ref: str
    connection_ref: str
    organization_id: str
    workspace_id: str
    tenant_id: str
    allowed_team_ids: frozenset[str]
    allowed_channel_ids: frozenset[str]
    bot_app_id: str
    endpoint: DirectPluginEndpointConfig
    expected_issuer: str

    def authorize_conversation(
        self,
        *,
        tenant_id: str,
        team_id: str,
        channel_id: str,
    ) -> None:
        """Require one grant-bound channel inside this bot's configured tenant."""

        if tenant_id != self.tenant_id:
            raise PermissionError("Teams tenant is outside the configured bot binding")
        if team_id not in self.allowed_team_ids:
            raise PermissionError("Teams team is outside the configured bot binding")
        if self.allowed_channel_ids and channel_id not in self.allowed_channel_ids:
            raise PermissionError("Teams channel is outside the configured bot binding")


@dataclass(frozen=True, slots=True)
class ComputerRunnerProfile:
    """Host-owned logical workspace bound to one isolated computer provider."""

    profile_ref: str
    connection_ref: str
    organization_id: str
    workspace_id: str
    expected_issuer: str
    endpoint: DirectPluginEndpointConfig
    max_command_timeout_ms: int
    max_file_bytes: int
    max_read_bytes: int
    max_directory_depth: int

    def authorize_principal(self, principal: Any) -> None:
        """Bind a verified Directory principal to this exact host workspace."""

        if (
            principal.issuer != self.expected_issuer
            or principal.organization_id != self.organization_id
            or principal.workspace_id != self.workspace_id
        ):
            raise PermissionError("computer runner is outside the configured actor scope")


@dataclass(frozen=True, slots=True)
class ConnectorHostSettings:
    """Validated optional connector settings; absence leaves all paths closed."""

    navigator: NavigatorConnectorSettings | None
    teams_messages: TeamsMessageProfile | None
    computer_runner: ComputerRunnerProfile | None


def validate_teams_service_url(service_url: str, *, tenant_id: str) -> str:
    """Accept only the bounded Bot Framework service URL for the admitted tenant."""

    if (
        not isinstance(service_url, str)
        or not service_url
        or len(service_url) > 512
        or service_url.strip() != service_url
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in service_url)
        or any(char in service_url for char in ("%", "\\", "?", "#"))
    ):
        raise ValueError("Teams serviceUrl is malformed")
    try:
        parsed = urlsplit(service_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Teams serviceUrl has an invalid authority") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Teams serviceUrl must use the fixed HTTPS endpoint form")
    host = parsed.hostname
    authority = parsed.netloc
    if host not in {"smba.trafficmanager.net", "smba.infra.teams.microsoft.com"}:
        raise ValueError("Teams serviceUrl host is not an official Bot Framework endpoint")
    if authority not in {host, f"{host}:443"}:
        raise ValueError("Teams serviceUrl authority is not canonical")
    if not parsed.path.startswith("/") or parsed.path == "/" or "//" in parsed.path:
        raise ValueError("Teams serviceUrl path is invalid")
    parts = parsed.path[1:].split("/")
    if parts[-1] == "":
        parts.pop()
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ValueError("Teams serviceUrl path has an invalid segment")
    if host == "smba.infra.teams.microsoft.com":
        if parts != ["teams"]:
            raise ValueError("Teams infrastructure serviceUrl must use the /teams route")
        return service_url
    if parts == ["teams"]:
        return service_url
    if parts[0] not in _TEAMS_SERVICE_REGIONS or len(parts) not in {1, 2}:
        raise ValueError("Teams regional serviceUrl path is invalid")
    if len(parts) == 2 and (
        not _UUID_PATH.fullmatch(parts[1]) or parts[1].lower() != tenant_id.lower()
    ):
        raise ValueError("Teams serviceUrl tenant path does not match the admitted tenant")
    return service_url


def validate_teams_root_thread_id(root_thread_id: str) -> str:
    """Require the numeric, non-zero Bot Framework channel message id form."""

    if (
        not isinstance(root_thread_id, str)
        or not root_thread_id
        or len(root_thread_id) > 512
        or not root_thread_id.isascii()
        or not root_thread_id.isdecimal()
        or int(root_thread_id) == 0
    ):
        raise ValueError("Teams root thread id must be a non-zero numeric channel message id")
    return root_thread_id


def parse_connector_host_settings(value: object) -> ConnectorHostSettings:
    """Parse the exact host-owned Navigator, Teams, and computer profiles."""

    root = _object(
        value,
        required=set(),
        optional={"navigatorConnector", "teamsMessages", "computerRunner"},
        label="connectorHost",
    )
    navigator = _parse_navigator(root.get("navigatorConnector"))
    teams = _parse_teams(root.get("teamsMessages"))
    computer = _parse_computer_runner(root.get("computerRunner"))
    return ConnectorHostSettings(
        navigator=navigator,
        teams_messages=teams,
        computer_runner=computer,
    )


def _parse_navigator(value: object) -> NavigatorConnectorSettings | None:
    if value is None:
        return None
    item = _object(
        value,
        required={"keyId", "keyFileRef"},
        optional=set(),
        label="connectorHost.navigatorConnector",
    )
    key_id = _text(item["keyId"], "navigatorConnector.keyId")
    key_file_ref = _text(item["keyFileRef"], "navigatorConnector.keyFileRef")
    if (
        not _SHORT_ALIAS.fullmatch(key_id)
        or not _SECRET_REF.fullmatch(key_file_ref)
        or any(part in {"", ".", ".."} for part in key_file_ref.split("/"))
    ):
        raise ConnectorHostConfigurationError("Navigator connector key alias is invalid")
    return NavigatorConnectorSettings(key_id=key_id, key_file_ref=key_file_ref)


def _parse_teams(value: object) -> TeamsMessageProfile | None:
    if value is None:
        return None
    item = _object(
        value,
        required={
            "profileRef",
            "connectionRef",
            "organizationId",
            "workspaceId",
            "tenantId",
            "allowedTeamIds",
            "botAppId",
            "directPlugin",
            "expectedIssuer",
        },
        optional={"allowedChannelIds"},
        label="connectorHost.teamsMessages",
    )
    profile_ref = _alias(item["profileRef"], "teamsMessages.profileRef")
    connection_ref = _alias(item["connectionRef"], "teamsMessages.connectionRef")
    tenant_id = _text(item["tenantId"], "teamsMessages.tenantId").lower()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", tenant_id):
        raise ConnectorHostConfigurationError("Teams tenantId must be a canonical UUID")
    issuer = _text(item["expectedIssuer"], "teamsMessages.expectedIssuer")
    issuer_match = _AAD_ISSUER.fullmatch(issuer)
    if issuer_match is None or issuer_match.group(1).lower() != tenant_id:
        raise ConnectorHostConfigurationError("Teams issuer must match the configured tenant")
    return TeamsMessageProfile(
        profile_ref=profile_ref,
        connection_ref=connection_ref,
        organization_id=_text(item["organizationId"], "teamsMessages.organizationId"),
        workspace_id=_text(item["workspaceId"], "teamsMessages.workspaceId"),
        tenant_id=tenant_id,
        allowed_team_ids=_string_set(item["allowedTeamIds"], "teamsMessages.allowedTeamIds"),
        allowed_channel_ids=_string_set(
            item.get("allowedChannelIds", []), "teamsMessages.allowedChannelIds", allow_empty=True
        ),
        bot_app_id=_text(item["botAppId"], "teamsMessages.botAppId"),
        endpoint=_endpoint(item["directPlugin"], "teamsMessages.directPlugin"),
        expected_issuer=issuer,
    )


def _parse_computer_runner(value: object) -> ComputerRunnerProfile | None:
    """Parse one host-fixed isolated computer binding and its narrow limits."""

    if value is None:
        return None
    item = _object(
        value,
        required={
            "profileRef",
            "connectionRef",
            "organizationId",
            "workspaceId",
            "expectedIssuer",
            "directPlugin",
        },
        optional={
            "maxCommandTimeoutMs",
            "maxFileBytes",
            "maxReadBytes",
            "maxDirectoryDepth",
        },
        label="connectorHost.computerRunner",
    )
    profile_ref = _alias(item["profileRef"], "computerRunner.profileRef")
    connection_ref = _text(item["connectionRef"], "computerRunner.connectionRef").lower()
    if not _UUID_PATH.fullmatch(connection_ref):
        raise ConnectorHostConfigurationError("computerRunner.connectionRef must be a UUID")
    try:
        endpoint = _endpoint(item["directPlugin"], "computerRunner.directPlugin")
    except ValueError as exc:
        raise ConnectorHostConfigurationError(
            "computerRunner DirectPlugin endpoint is invalid"
        ) from exc
    if endpoint.binding_id != "computer-runtime":
        raise ConnectorHostConfigurationError(
            "computerRunner DirectPlugin bindingId must be computer-runtime"
        )
    if endpoint.transport != "mtls" or not endpoint.connection_ref.startswith("grpcs://"):
        raise ConnectorHostConfigurationError(
            "computerRunner DirectPlugin endpoint must use the private mTLS transport"
        )
    expected_issuer = _text(item["expectedIssuer"], "computerRunner.expectedIssuer")
    if _AAD_ISSUER.fullmatch(expected_issuer) is None:
        raise ConnectorHostConfigurationError(
            "computerRunner expectedIssuer must be a Microsoft Entra issuer"
        )
    return ComputerRunnerProfile(
        profile_ref=profile_ref,
        connection_ref=connection_ref,
        organization_id=_text(item["organizationId"], "computerRunner.organizationId"),
        workspace_id=_text(item["workspaceId"], "computerRunner.workspaceId"),
        expected_issuer=expected_issuer,
        endpoint=endpoint,
        max_command_timeout_ms=_bounded_integer(
            item.get("maxCommandTimeoutMs", 600_000),
            "computerRunner.maxCommandTimeoutMs",
            minimum=1,
            maximum=600_000,
        ),
        max_file_bytes=_bounded_integer(
            item.get("maxFileBytes", 1_048_576),
            "computerRunner.maxFileBytes",
            minimum=1,
            maximum=1_048_576,
        ),
        max_read_bytes=_bounded_integer(
            item.get("maxReadBytes", 65_536),
            "computerRunner.maxReadBytes",
            minimum=0,
            maximum=65_536,
        ),
        max_directory_depth=_bounded_integer(
            item.get("maxDirectoryDepth", 32),
            "computerRunner.maxDirectoryDepth",
            minimum=1,
            maximum=32,
        ),
    )


def _bounded_integer(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConnectorHostConfigurationError(f"{label} is outside its fixed range")
    return value


def _string_set(
    value: object,
    label: str,
    *,
    allow_empty: bool = False,
) -> frozenset[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ConnectorHostConfigurationError(f"{label} must be a string array")
    result: set[str] = set()
    for item in value:
        selected = _text(item, label)
        if len(selected) > 300 or selected in result:
            raise ConnectorHostConfigurationError(f"{label} contains an invalid or duplicate id")
        result.add(selected)
    return frozenset(result)


def _alias(value: object, label: str) -> str:
    selected = _text(value, label)
    if not _ALIAS.fullmatch(selected):
        raise ConnectorHostConfigurationError(f"{label} must be an opaque alias")
    return selected


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ConnectorHostConfigurationError(f"{label} must be bounded non-empty text")
    return value
