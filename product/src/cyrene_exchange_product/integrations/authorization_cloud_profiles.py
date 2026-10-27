"""Authorization/cloud host profiles and live caller configuration.

Module: cyrene_exchange_product.integrations.authorization_cloud_profiles
Role: Parse closed host-owned bindings and resolve actor/resource allowlists.
模块职责：解析受限 Host 配置，并按当前身份解析 Actor 与资源允许列表。
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from cyrene_exchange_product.integrations.azure_devops import validate_authorized_source
from cyrene_exchange_product.integrations.microsoft_graph import (
    is_valid_sharepoint_site_id,
    validate_resource_id,
    validate_sharepoint_list_id,
)
from cyrene_exchange_product.integrations.models import (
    CreateIntegrationConnection,
    IntegrationConnection,
    IntegrationPrincipal,
)

_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,299}$")
_HUGGINGFACE_REPOSITORY_REF = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_RECIPIENT_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_PROVIDER_IDS = frozenset(
    {
        "wecom",
        "azure",
        "azure_devops",
        "gcp",
        "hf",
        "microsoft_graph",
        "runpod",
        "tailscale",
    }
)
_LOGGER = logging.getLogger(__name__)


class AuthorizationCloudConfigurationError(ValueError):
    """Closed authorization/cloud host settings are incomplete or ambiguous."""


@dataclass(frozen=True, slots=True)
class AuthorityActorContext:
    """Host-owned identity pins and a live first-party bearer secret reference."""

    context_ref: str
    issuer: str
    subject: str
    organization_id: str
    workspace_id: str
    bearer_token_env_ref: str


@dataclass(frozen=True, slots=True)
class DirectPluginEndpointConfig:
    """One host-resolved DirectPluginRuntime address and optional mTLS profile."""

    binding_id: str
    connection_ref: str
    transport: str
    mtls: Mapping[str, str] | None


@dataclass(frozen=True, slots=True)
class CloudTargetAlias:
    """A caller-visible selector mapped to one binding-owned provider target."""

    target_ref: str
    display_name: str
    allowed_context_refs: frozenset[str]


@dataclass(frozen=True, slots=True)
class AzureDevOpsAuthorizedSource:
    """One provider-canonical ADO source row and its actor-owned AC profile ref."""

    source_id: str
    kind: str
    project_id: str
    project_name: str
    profile_ref: str
    pipeline_id: int | None = None
    definition_id: int | None = None
    definition_environment_id: int | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationProviderProfile:
    """One fixed Plugin binding scoped to configured actors and resource aliases."""

    profile_ref: str
    provider: str
    endpoint: DirectPluginEndpointConfig
    caller_workload: str
    audience: str
    expected_issuer: str
    context_key_ref: str
    organization_id: str
    workspace_id: str
    allowed_context_refs: frozenset[str]
    allowed_actors: frozenset[tuple[str, str]]
    display_name: str | None
    authorization_ref: str | None
    targets: Mapping[str, CloudTargetAlias]
    identity_ref: str | None = None
    credential_secret_ref: str | None = None
    account_scopes: Mapping[str, object] | None = None
    auth_mode: str | None = None
    access_mode: str = "actor_owned"
    azure_devops_tenant_id: str | None = None
    azure_devops_organization: str | None = None
    authorized_sources: Mapping[str, AzureDevOpsAuthorizedSource] | None = None
    microsoft_graph_plan_ids: tuple[str, ...] = ()
    microsoft_graph_sharepoint_site_id: str | None = None
    microsoft_graph_sharepoint_list_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EmailNotificationProfile:
    """An explicitly enabled mail binding and fixed recipient allowlist alias."""

    enabled: bool
    endpoint: DirectPluginEndpointConfig | None
    caller_workload: str | None
    audience: str | None
    expected_issuer: str | None
    context_key_ref: str | None
    organization_id: str | None
    workspace_id: str | None
    recipient_ref: str | None
    allowed_context_refs: frozenset[str]


@dataclass(frozen=True, slots=True)
class AuthorizationCloudSettings:
    """Validated immutable inputs used by the Product adapter and live resolver."""

    monitor_interval_seconds: int
    contexts: Mapping[str, AuthorityActorContext]
    profiles: Mapping[str, AuthorizationProviderProfile]
    email: EmailNotificationProfile


class AuthorizationCloudProfileRegistry:
    """Resolve only configured connection aliases and current verified actor scopes."""

    def __init__(self, settings: AuthorizationCloudSettings) -> None:
        self.settings = settings
        identities: dict[tuple[str, str, str, str], AuthorityActorContext] = {}
        for context in settings.contexts.values():
            identity = (
                context.issuer,
                context.subject,
                context.organization_id,
                context.workspace_id,
            )
            if identity in identities:
                raise AuthorizationCloudConfigurationError(
                    "current authority actor pins must resolve to one bearer reference"
                )
            identities[identity] = context
        self._contexts_by_identity = identities

    def display_name_for_connection(
        self,
        principal: IntegrationPrincipal,
        request: CreateIntegrationConnection,
    ) -> str:
        """Authorize a provider/binding/target alias against the live request principal."""

        principal.require("integrationCreateConnection")
        profile = self._profile(request.provider, request.binding_ref)
        if profile.access_mode == "workspace_operator":
            principal.require("navigator.connector.operator.v1")
        context = self._profile_actor_for_principal(
            principal,
            allowed_context_refs=profile.allowed_context_refs,
            allowed_actors=profile.allowed_actors,
            access_mode=profile.access_mode,
            organization_id=profile.organization_id,
            workspace_id=profile.workspace_id,
            expected_issuer=profile.expected_issuer,
        )
        if request.provider == "wecom":
            if request.target_ref is not None or profile.display_name is None:
                raise AuthorizationCloudConfigurationError(
                    "WeCom authorization profile does not match the connection selector"
                )
            return profile.display_name
        if request.provider == "microsoft_graph":
            if (
                request.target_ref is not None
                or profile.targets
                or not profile.microsoft_graph_plan_ids
                or not request.account_link_ref
            ):
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph bindings require host-selected Planner plan IDs"
                )
            return "Microsoft Graph"
        if request.provider == "azure_devops":
            sources = profile.authorized_sources or {}
            source = sources.get(request.target_ref or "")
            if (
                source is None
                or request.account_link_ref != source.profile_ref
                or profile.azure_devops_tenant_id is None
                or profile.azure_devops_organization is None
            ):
                raise PermissionError("Azure DevOps source is outside host authorized_sources")
            return source.project_name
        target = profile.targets.get(request.target_ref or "")
        if target is None:
            raise AuthorizationCloudConfigurationError(
                "cloud target alias is not configured for this provider binding"
            )
        if target.allowed_context_refs and (
            context is None or context.context_ref not in target.allowed_context_refs
        ):
            raise PermissionError("cloud target is not allowed for the current actor")
        return target.display_name

    @staticmethod
    def account_center_profile_ref(
        principal: IntegrationPrincipal,
        profile: AuthorizationProviderProfile,
        *,
        target_alias: str,
    ) -> str:
        """Derive one stable Account Center UUID for one exact cloud target.

        Workspace-operator profiles share one UUID across verified operators;
        actor-owned profiles include the exact owner subject in the derivation.
        Target alias and provider target are included because Account Center stores
        one resource scope per identity profile. 中文：UUID 与单个 provider target 精确绑定。
        """

        target = profile.targets.get(target_alias)
        if target is None:
            raise AuthorizationCloudConfigurationError(
                "Account Center identity reference requires a configured target alias"
            )
        owner_scope: tuple[str, ...] = (
            principal.issuer,
            principal.organization_id,
            principal.workspace_id,
            profile.provider,
            profile.profile_ref,
            target_alias,
            target.target_ref,
        )
        if profile.access_mode == "actor_owned":
            owner_scope = (*owner_scope, principal.subject)
        value = "\x00".join(owner_scope)
        return str(uuid5(NAMESPACE_URL, f"cyrene-account-center-host-profile:{value}"))

    def principal_allowed_for_profile(
        self,
        principal: IntegrationPrincipal,
        profile: AuthorizationProviderProfile,
    ) -> bool:
        """Check a verified actor against either context-backed or static host pins."""

        try:
            self._profile_actor_for_principal(
                principal,
                allowed_context_refs=profile.allowed_context_refs,
                allowed_actors=profile.allowed_actors,
                access_mode=profile.access_mode,
                organization_id=profile.organization_id,
                workspace_id=profile.workspace_id,
                expected_issuer=profile.expected_issuer,
            )
        except PermissionError:
            return False
        return True

    def profile_for_connection(
        self,
        principal: IntegrationPrincipal,
        connection: IntegrationConnection,
        *,
        operation_id: str,
    ) -> tuple[AuthorizationProviderProfile, str | None]:
        """Recheck exact operation, owner, binding and target allowlists before signing."""

        principal.require(operation_id)
        if (
            principal.issuer != connection.actor_issuer
            or (
                principal.subject != connection.actor_subject
                and connection.access_mode != "workspace_operator"
            )
            or principal.organization_id != connection.organization_id
            or principal.workspace_id != connection.workspace_id
        ):
            raise PermissionError("connection owner or access mode does not match this principal")
        profile = self._profile(connection.provider, connection.binding_ref)
        if connection.access_mode != profile.access_mode:
            raise PermissionError("connection access mode differs from the host profile")
        selected_context = self._profile_actor_for_principal(
            principal,
            allowed_context_refs=profile.allowed_context_refs,
            allowed_actors=profile.allowed_actors,
            access_mode=profile.access_mode,
            organization_id=connection.organization_id,
            workspace_id=connection.workspace_id,
            expected_issuer=profile.expected_issuer,
        )
        if connection.organization_id != profile.organization_id:
            raise PermissionError("connection organization is outside the provider binding")
        target_ref: str | None = None
        if connection.provider in {"wecom", "microsoft_graph"}:
            if connection.target_ref is not None:
                raise PermissionError("provider connection cannot select a cloud target")
            if connection.provider == "microsoft_graph" and profile.targets:
                raise PermissionError(
                    "Microsoft Graph binding cannot contain host resource targets"
                )
            if connection.provider == "microsoft_graph" and not profile.microsoft_graph_plan_ids:
                raise PermissionError("Microsoft Graph binding has no selected host Planner plans")
        elif connection.provider == "azure_devops":
            sources = profile.authorized_sources or {}
            source = sources.get(connection.target_ref or "")
            if source is None or connection.account_link_ref != source.profile_ref:
                raise PermissionError("Azure DevOps source/profile is outside authorized_sources")
            target_ref = source.source_id
        else:
            target = profile.targets.get(connection.target_ref or "")
            if target is None:
                raise PermissionError("cloud target alias is not configured")
            if target.allowed_context_refs and (
                selected_context is None
                or selected_context.context_ref not in target.allowed_context_refs
            ):
                raise PermissionError("cloud target is not allowed for the current actor")
            target_ref = target.target_ref
        return profile, target_ref

    def context_for_profile(
        self,
        principal: IntegrationPrincipal,
        profile: AuthorizationProviderProfile,
    ) -> AuthorityActorContext:
        """Return one exact host-pinned actor context or reject ambiguity."""

        return self._context_for_principal(
            principal,
            allowed_context_refs=profile.allowed_context_refs,
            organization_id=profile.organization_id,
            workspace_id=profile.workspace_id,
            expected_issuer=profile.expected_issuer,
        )

    def context_for_connection(
        self,
        connection: IntegrationConnection,
    ) -> tuple[AuthorityActorContext, AuthorizationProviderProfile]:
        """Map persisted ownership to one configured credential and resource profile."""

        profile = self._profile(connection.provider, connection.binding_ref)
        if (
            connection.organization_id != profile.organization_id
            or connection.workspace_id != profile.workspace_id
        ):
            raise PermissionError("connection tenant is outside its provider binding")
        context = self._contexts_by_identity.get(
            (
                connection.actor_issuer,
                connection.actor_subject,
                connection.organization_id,
                connection.workspace_id,
            )
        )
        if context is None or context.context_ref not in profile.allowed_context_refs:
            raise PermissionError("connection owner has no configured live bearer context")
        if connection.provider in {"wecom", "microsoft_graph"}:
            if connection.target_ref is not None:
                raise PermissionError("provider connection cannot select a cloud target")
            if connection.provider == "microsoft_graph" and profile.targets:
                raise PermissionError(
                    "Microsoft Graph binding cannot contain host resource targets"
                )
        elif connection.provider == "azure_devops":
            sources = profile.authorized_sources or {}
            source = sources.get(connection.target_ref or "")
            if source is None or connection.account_link_ref != source.profile_ref:
                raise PermissionError("Azure DevOps source/profile is outside authorized_sources")
        else:
            target = profile.targets.get(connection.target_ref or "")
            if target is None or (
                target.allowed_context_refs
                and context.context_ref not in target.allowed_context_refs
            ):
                raise PermissionError("connection target is outside the actor resource allowlist")
        return context, profile

    def profile_for_static_workspace_operator_connection(
        self,
        connection: IntegrationConnection,
    ) -> tuple[AuthorizationProviderProfile, str]:
        """Resolve a context-free cloud profile pinned to exactly its stored owner.

        A fresh Platform connector grant is still required before any provider call;
        this method only validates closed cloud/HF host pins without a user bearer.
        中文：仅解析静态 owner pin，不代替后续逐次 Directory grant。
        """

        profile = self._profile(connection.provider, connection.binding_ref)
        owner = (connection.actor_issuer, connection.actor_subject)
        if (
            connection.provider not in {"azure", "gcp", "hf", "runpod"}
            or profile.access_mode != "workspace_operator"
            or connection.access_mode != "workspace_operator"
            or profile.expected_issuer != connection.actor_issuer
            or profile.organization_id != connection.organization_id
            or profile.workspace_id != connection.workspace_id
            or profile.allowed_context_refs
            or profile.allowed_actors != frozenset({owner})
        ):
            raise PermissionError("static cloud owner is outside its workspace profile")
        target = profile.targets.get(connection.target_ref or "")
        if target is None or target.allowed_context_refs:
            raise PermissionError("static cloud target is outside its workspace profile")
        return profile, target.target_ref

    def email_context_for_principal(self, principal: IntegrationPrincipal) -> AuthorityActorContext:
        """Require both a dedicated current deliver grant and the mail actor allowlist."""

        principal.require("integrationDeliverNotification")
        email = self.settings.email
        if not email.enabled or email.endpoint is None:
            raise PermissionError("email delivery is disabled")
        if (
            principal.organization_id != email.organization_id
            or principal.workspace_id != email.workspace_id
            or principal.issuer != email.expected_issuer
        ):
            raise PermissionError("email delivery caller is outside the configured tenant")
        return self._context_for_principal(
            principal,
            allowed_context_refs=email.allowed_context_refs,
            organization_id=str(email.organization_id),
            workspace_id=str(email.workspace_id),
            expected_issuer=str(email.expected_issuer),
        )

    def email_recipient_for_principal(self, principal: IntegrationPrincipal) -> str | None:
        """Return the one configured recipient only for an explicitly allowed actor."""

        try:
            self.email_context_for_principal(principal)
        except Exception as exc:
            _LOGGER.info(
                "Email recipient is unavailable for the current actor (%s)",
                type(exc).__name__,
            )
            return None
        return self.settings.email.recipient_ref

    def email_recipient_for_connection(self, connection: IntegrationConnection) -> str | None:
        """Resolve configured email consent without reconstructing an identity claim."""

        email = self.settings.email
        if not email.enabled or email.endpoint is None:
            return None
        context = self._contexts_by_identity.get(
            (
                connection.actor_issuer,
                connection.actor_subject,
                connection.organization_id,
                connection.workspace_id,
            )
        )
        if (
            context is None
            or context.context_ref not in email.allowed_context_refs
            or connection.organization_id != email.organization_id
            or connection.workspace_id != email.workspace_id
            or connection.actor_issuer != email.expected_issuer
        ):
            return None
        return email.recipient_ref

    def email_context_for_job(self, job: Any) -> AuthorityActorContext:
        """Resolve the same configured identity pins for an outbox actor."""

        email = self.settings.email
        context = self._contexts_by_identity.get(
            (job.actor_issuer, job.actor_subject, job.organization_id, job.workspace_id)
        )
        if (
            not email.enabled
            or email.endpoint is None
            or email.expected_issuer != job.actor_issuer
            or email.organization_id != job.organization_id
            or email.workspace_id != job.workspace_id
            or context is None
            or context.context_ref not in email.allowed_context_refs
        ):
            raise PermissionError("notification owner is not allowlisted for email delivery")
        return context

    def _context_for_principal(
        self,
        principal: IntegrationPrincipal,
        *,
        allowed_context_refs: frozenset[str],
        organization_id: str,
        workspace_id: str,
        expected_issuer: str,
    ) -> AuthorityActorContext:
        identity = (
            principal.issuer,
            principal.subject,
            principal.organization_id,
            principal.workspace_id,
        )
        context = self._contexts_by_identity.get(identity)
        if (
            context is None
            or context.context_ref not in allowed_context_refs
            or principal.issuer != expected_issuer
            or principal.organization_id != organization_id
            or principal.workspace_id != workspace_id
        ):
            raise PermissionError("current Platform identity is not allowed by this profile")
        return context

    def _profile_actor_for_principal(
        self,
        principal: IntegrationPrincipal,
        *,
        allowed_context_refs: frozenset[str],
        allowed_actors: frozenset[tuple[str, str]],
        access_mode: str = "actor_owned",
        organization_id: str,
        workspace_id: str,
        expected_issuer: str,
    ) -> AuthorityActorContext | None:
        """Authorize a signed caller by current context or explicit host identity pin."""

        if (
            principal.issuer != expected_issuer
            or principal.organization_id != organization_id
            or principal.workspace_id != workspace_id
        ):
            raise PermissionError("current Platform identity is outside this profile scope")
        context = self._contexts_by_identity.get(
            (principal.issuer, principal.subject, principal.organization_id, principal.workspace_id)
        )
        if context is not None and context.context_ref in allowed_context_refs:
            return context
        if (principal.issuer, principal.subject) in allowed_actors:
            return None
        if access_mode == "workspace_operator":
            return None
        raise PermissionError("current Platform identity is not allowed by this profile")

    def _profile(
        self,
        provider: str,
        profile_ref: str | None,
    ) -> AuthorizationProviderProfile:
        if profile_ref is None:
            raise AuthorizationCloudConfigurationError("provider binding alias is required")
        profile = self.settings.profiles.get(profile_ref)
        if profile is None or profile.provider != provider:
            raise AuthorizationCloudConfigurationError("provider binding alias is unavailable")
        return profile


def parse_authorization_cloud_settings(
    value: object,
    *,
    email_value: object,
) -> AuthorizationCloudSettings:
    """Parse exact host fields; no Product request field becomes a URL or credential."""

    cloud = _object(
        value,
        required={"currentAuthority", "profiles"},
        optional={"monitorIntervalSeconds"},
        label="authorizationCloud",
    )
    interval = cloud.get("monitorIntervalSeconds", 900)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 60 <= interval <= 86_400:
        raise AuthorizationCloudConfigurationError("authorizationCloud monitor interval is invalid")

    authority = _object(
        cloud["currentAuthority"],
        required={"contexts"},
        optional=set(),
        label="authorizationCloud.currentAuthority",
    )
    raw_contexts = authority["contexts"]
    if not isinstance(raw_contexts, list):
        raise AuthorizationCloudConfigurationError("currentAuthority.contexts must be an array")
    contexts: dict[str, AuthorityActorContext] = {}
    for index, raw_context in enumerate(raw_contexts):
        label = f"currentAuthority.contexts[{index}]"
        item = _object(
            raw_context,
            required={
                "contextRef",
                "issuer",
                "subject",
                "organizationId",
                "workspaceId",
                "bearerTokenEnvRef",
            },
            optional=set(),
            label=label,
        )
        context_ref = _alias(item["contextRef"], f"{label}.contextRef")
        if context_ref in contexts:
            raise AuthorizationCloudConfigurationError("current authority contextRef is duplicated")
        contexts[context_ref] = AuthorityActorContext(
            context_ref=context_ref,
            issuer=_text(item["issuer"], f"{label}.issuer"),
            subject=_text(item["subject"], f"{label}.subject"),
            organization_id=_text(item["organizationId"], f"{label}.organizationId"),
            workspace_id=_text(item["workspaceId"], f"{label}.workspaceId"),
            bearer_token_env_ref=_text(item["bearerTokenEnvRef"], f"{label}.bearerTokenEnvRef"),
        )

    raw_profiles = cloud["profiles"]
    if not isinstance(raw_profiles, Mapping) or not raw_profiles:
        raise AuthorizationCloudConfigurationError("authorizationCloud.profiles is required")
    profiles: dict[str, AuthorizationProviderProfile] = {}
    for raw_profile_ref, raw_profile in raw_profiles.items():
        profile_ref = _alias(raw_profile_ref, "authorizationCloud profile key")
        item = _object(
            raw_profile,
            required={
                "provider",
                "directPlugin",
                "callerWorkload",
                "audience",
                "expectedIssuer",
                "contextKeyRef",
                "organizationId",
                "workspaceId",
            },
            optional={
                "allowedContextRefs",
                "allowedActors",
                "accessMode",
                "displayName",
                "authorizationRef",
                "targets",
                "identityRef",
                "credentialSecretRef",
                "accountScopes",
                "authMode",
                "plannerPlanIds",
                "sharepointTargets",
                "tenantId",
                "organization",
                "authorizedSources",
            },
            label=f"authorizationCloud.profiles.{profile_ref}",
        )
        provider = _text(item["provider"], "provider")
        if provider not in _PROVIDER_IDS:
            raise AuthorizationCloudConfigurationError("authorizationCloud provider is unsupported")
        endpoint = _endpoint(item["directPlugin"], f"profile {profile_ref}.directPlugin")
        access_mode = _text(item.get("accessMode", "actor_owned"), "accessMode")
        if access_mode not in {"actor_owned", "workspace_operator"}:
            raise AuthorizationCloudConfigurationError("provider profile accessMode is unsupported")
        if access_mode == "workspace_operator" and provider not in {"azure", "gcp", "hf", "runpod"}:
            raise AuthorizationCloudConfigurationError(
                "workspace_operator is supported only for cloud connector profiles"
            )
        allowed_refs = (
            _aliases(item["allowedContextRefs"], "allowedContextRefs")
            if "allowedContextRefs" in item
            else frozenset()
        )
        raw_actors = item.get("allowedActors", [])
        if not isinstance(raw_actors, list):
            raise AuthorizationCloudConfigurationError("allowedActors must be an array")
        allowed_actors: set[tuple[str, str]] = set()
        for actor_index, raw_actor in enumerate(raw_actors):
            actor = _object(
                raw_actor,
                required={"issuer", "subject"},
                optional=set(),
                label=f"profile {profile_ref}.allowedActors[{actor_index}]",
            )
            actor_issuer = _text(actor["issuer"], "allowed actor issuer")
            actor_subject = _text(actor["subject"], "allowed actor subject")
            if actor_issuer != _text(item["expectedIssuer"], "expectedIssuer"):
                raise AuthorizationCloudConfigurationError(
                    "allowed actor issuer must match expectedIssuer"
                )
            identity = (actor_issuer, actor_subject)
            if identity in allowed_actors:
                raise AuthorizationCloudConfigurationError("allowedActors contains a duplicate")
            allowed_actors.add(identity)
        if not allowed_refs and not allowed_actors and access_mode != "workspace_operator":
            raise AuthorizationCloudConfigurationError(
                "provider profile requires at least one allowedContextRef or allowedActor"
            )
        if not allowed_refs <= set(contexts):
            raise AuthorizationCloudConfigurationError(
                "provider profile has an unknown actor context"
            )
        organization_id = _text(item["organizationId"], "organizationId")
        workspace_id = _text(item["workspaceId"], "workspaceId")
        expected_issuer = _text(item["expectedIssuer"], "expectedIssuer")
        for context_ref in allowed_refs:
            context = contexts[context_ref]
            if (
                context.organization_id != organization_id
                or context.workspace_id != workspace_id
                or context.issuer != expected_issuer
            ):
                raise AuthorizationCloudConfigurationError(
                    "provider profile actor pins do not match the binding scope"
                )
        display_name = _text(item["displayName"], "displayName") if "displayName" in item else None
        authorization_ref = (
            _alias(item["authorizationRef"], "authorizationRef")
            if "authorizationRef" in item
            else None
        )
        raw_targets = item.get("targets", {})
        if not isinstance(raw_targets, Mapping):
            raise AuthorizationCloudConfigurationError("provider targets must be an object")
        targets: dict[str, CloudTargetAlias] = {}
        for raw_alias, raw_target in raw_targets.items():
            alias = _alias(raw_alias, "target alias")
            target = _object(
                raw_target,
                required={"targetRef", "displayName"},
                optional={"allowedContextRefs"},
                label=f"profile {profile_ref}.targets.{alias}",
            )
            target_contexts = (
                _aliases(target["allowedContextRefs"], "target allowedContextRefs")
                if "allowedContextRefs" in target
                else frozenset()
            )
            if not target_contexts <= allowed_refs:
                raise AuthorizationCloudConfigurationError(
                    "target actor allowlist exceeds its provider profile"
                )
            targets[alias] = CloudTargetAlias(
                target_ref=_provider_target_ref(
                    provider,
                    target["targetRef"],
                    "provider targetRef",
                ),
                display_name=_text(target["displayName"], "target displayName"),
                allowed_context_refs=target_contexts,
            )
        if provider == "wecom":
            if authorization_ref is None or display_name is None or targets:
                raise AuthorizationCloudConfigurationError(
                    "WeCom profiles require displayName and authorizationRef only"
                )
        elif provider == "microsoft_graph":
            if (
                targets
                or display_name is not None
                or authorization_ref is not None
                or access_mode != "actor_owned"
                or _text(item["callerWorkload"], "callerWorkload") != "microsoft-graph-provider"
            ):
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph requires one actor-owned provider binding "
                    "without resource targets"
                )
        elif provider == "azure_devops":
            if (
                targets
                or display_name is not None
                or authorization_ref is not None
                or access_mode != "actor_owned"
                or _text(item["callerWorkload"], "callerWorkload")
                != "azure-devops-observation-provider"
            ):
                raise AuthorizationCloudConfigurationError(
                    "Azure DevOps requires an actor-owned fixed provider binding"
                )
        elif not targets or display_name is not None or authorization_ref is not None:
            raise AuthorizationCloudConfigurationError(
                "cloud profiles require target aliases and cannot select authorization refs"
            )
        identity_ref = _alias(item["identityRef"], "identityRef") if "identityRef" in item else None
        credential_secret_ref = (
            _secret_reference(item["credentialSecretRef"], "credentialSecretRef")
            if "credentialSecretRef" in item
            else None
        )
        account_scopes = (
            _parse_huggingface_scopes(item["accountScopes"]) if "accountScopes" in item else None
        )
        auth_mode = _text(item["authMode"], "authMode") if "authMode" in item else None
        azure_devops_tenant_id: str | None = None
        azure_devops_organization: str | None = None
        authorized_sources: dict[str, AzureDevOpsAuthorizedSource] | None = None
        microsoft_graph_plan_ids: tuple[str, ...] = ()
        microsoft_graph_sharepoint_site_id: str | None = None
        microsoft_graph_sharepoint_list_ids: tuple[str, ...] = ()
        if provider == "hf":
            if "plannerPlanIds" in item or "sharepointTargets" in item:
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph targets are valid only for Graph profiles"
                )
            if credential_secret_ref is None or account_scopes is None:
                raise AuthorizationCloudConfigurationError(
                    "HF profiles require a host secret reference and explicit Account Center scopes"
                )
            if auth_mode not in {None, "fine_grained_token", "device_oauth"}:
                raise AuthorizationCloudConfigurationError("HF authMode is unsupported")
        elif provider == "azure_devops":
            if "plannerPlanIds" in item or "sharepointTargets" in item:
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph targets are valid only for Graph profiles"
                )
            if (
                credential_secret_ref is not None
                or account_scopes is not None
                or auth_mode is not None
            ):
                raise AuthorizationCloudConfigurationError(
                    "Azure DevOps delegated profiles cannot contain credentials or auth modes"
                )
            try:
                azure_devops_tenant_id = str(UUID(_text(item["tenantId"], "tenantId"))).lower()
            except (KeyError, ValueError) as exc:
                raise AuthorizationCloudConfigurationError(
                    "Azure DevOps tenantId must be a UUID"
                ) from exc
            azure_devops_organization = _text(item.get("organization"), "organization")
            raw_sources = item.get("authorizedSources", [])
            if not isinstance(raw_sources, list):
                raise AuthorizationCloudConfigurationError(
                    "Azure DevOps authorizedSources must be an array"
                )
            authorized_sources = {}
            source_profile_refs: set[str] = set()
            for raw_source in raw_sources:
                try:
                    source = validate_authorized_source(
                        raw_source,
                        tenant_id=azure_devops_tenant_id,
                        organization=azure_devops_organization,
                    )
                except ValueError as exc:
                    raise AuthorizationCloudConfigurationError(
                        "Azure DevOps authorizedSources contains an invalid source"
                    ) from exc
                source_id = str(source["source_id"])
                source_profile_ref = str(source["profile_ref"])
                if source_id in authorized_sources or source_profile_ref in source_profile_refs:
                    raise AuthorizationCloudConfigurationError(
                        "Azure DevOps authorizedSources contains a duplicate source or profile"
                    )
                source_profile_refs.add(source_profile_ref)
                authorized_sources[source_id] = AzureDevOpsAuthorizedSource(
                    source_id=source_id,
                    kind=str(source["kind"]),
                    project_id=str(source["project_id"]),
                    project_name=str(source["project_name"]),
                    profile_ref=source_profile_ref,
                    pipeline_id=source.get("pipeline_id"),
                    definition_id=source.get("definition_id"),
                    definition_environment_id=source.get("definition_environment_id"),
                )
        elif provider == "microsoft_graph":
            if (
                credential_secret_ref is not None
                or account_scopes is not None
                or auth_mode is not None
            ):
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph delegated profiles cannot contain host credentials "
                    "or auth modes"
                )
            raw_plan_ids = item.get("plannerPlanIds", [])
            if not isinstance(raw_plan_ids, list) or len(raw_plan_ids) > 100:
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph plannerPlanIds must be an array of at most 100 IDs"
                )
            try:
                microsoft_graph_plan_ids = tuple(
                    validate_resource_id(value, "plannerPlanIds") for value in raw_plan_ids
                )
            except ValueError as exc:
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph plannerPlanIds contains an invalid plan ID"
                ) from exc
            if len(microsoft_graph_plan_ids) != len(set(microsoft_graph_plan_ids)):
                raise AuthorizationCloudConfigurationError(
                    "Microsoft Graph plannerPlanIds contains duplicates"
                )
            raw_sharepoint_targets = item.get("sharepointTargets")
            if raw_sharepoint_targets is not None:
                sharepoint_targets = _object(
                    raw_sharepoint_targets,
                    required={"siteId", "listIds"},
                    optional=set(),
                    label=f"profile {profile_ref}.sharepointTargets",
                )
                list_ids = sharepoint_targets["listIds"]
                if not isinstance(list_ids, list) or not 1 <= len(list_ids) <= 100:
                    raise AuthorizationCloudConfigurationError(
                        "Microsoft Graph SharePoint listIds must contain 1..100 IDs"
                    )
                try:
                    raw_site_id = sharepoint_targets["siteId"]
                    if not isinstance(raw_site_id, str) or not is_valid_sharepoint_site_id(
                        raw_site_id
                    ):
                        raise ValueError("sharepointTargets.siteId is invalid")
                    microsoft_graph_sharepoint_site_id = raw_site_id
                    microsoft_graph_sharepoint_list_ids = tuple(
                        validate_sharepoint_list_id(value) for value in list_ids
                    )
                except ValueError as exc:
                    raise AuthorizationCloudConfigurationError(
                        "Microsoft Graph SharePoint target contains an invalid ID"
                    ) from exc
                if len(microsoft_graph_sharepoint_list_ids) != len(
                    set(microsoft_graph_sharepoint_list_ids)
                ):
                    raise AuthorizationCloudConfigurationError(
                        "Microsoft Graph SharePoint listIds contains duplicates"
                    )
        elif (
            credential_secret_ref is not None
            or account_scopes is not None
            or auth_mode is not None
            or "plannerPlanIds" in item
            or "sharepointTargets" in item
        ):
            raise AuthorizationCloudConfigurationError(
                "HF credential references, auth mode, and scopes are valid only for HF profiles"
            )
        profiles[profile_ref] = AuthorizationProviderProfile(
            profile_ref=profile_ref,
            provider=provider,
            endpoint=endpoint,
            caller_workload=_text(item["callerWorkload"], "callerWorkload"),
            audience=_text(item["audience"], "audience"),
            expected_issuer=expected_issuer,
            context_key_ref=_text(item["contextKeyRef"], "contextKeyRef"),
            organization_id=organization_id,
            workspace_id=workspace_id,
            allowed_context_refs=allowed_refs,
            allowed_actors=frozenset(allowed_actors),
            display_name=display_name,
            authorization_ref=authorization_ref,
            targets=targets,
            identity_ref=identity_ref,
            credential_secret_ref=credential_secret_ref,
            account_scopes=account_scopes,
            auth_mode=auth_mode,
            access_mode=access_mode,
            azure_devops_tenant_id=azure_devops_tenant_id,
            azure_devops_organization=azure_devops_organization,
            authorized_sources=authorized_sources,
            microsoft_graph_plan_ids=microsoft_graph_plan_ids,
            microsoft_graph_sharepoint_site_id=microsoft_graph_sharepoint_site_id,
            microsoft_graph_sharepoint_list_ids=microsoft_graph_sharepoint_list_ids,
        )

    email = _parse_email_profile(email_value, contexts)
    return AuthorizationCloudSettings(
        monitor_interval_seconds=interval,
        contexts=contexts,
        profiles=profiles,
        email=email,
    )


def _parse_huggingface_scopes(value: object) -> Mapping[str, object]:
    """Validate explicit HF repo permissions before linking a host token reference."""

    scope = _object(
        value,
        required={"repositories"},
        optional=set(),
        label="HF accountScopes",
    )
    repositories = scope["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise AuthorizationCloudConfigurationError("HF accountScopes.repositories is required")
    output: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw_repository in enumerate(repositories):
        label = f"HF accountScopes.repositories[{index}]"
        repository = _object(
            raw_repository,
            required={"repoType", "repoId", "permissions"},
            optional=set(),
            label=label,
        )
        repo_type = _text(repository["repoType"], f"{label}.repoType")
        repo_id = _text(repository["repoId"], f"{label}.repoId")
        permissions = repository["permissions"]
        if repo_type not in {"model", "dataset", "space"}:
            raise AuthorizationCloudConfigurationError("HF repoType is unsupported")
        if not isinstance(permissions, list) or not permissions:
            raise AuthorizationCloudConfigurationError("HF repo permissions are required")
        selected: set[str] = set()
        for permission in permissions:
            value_text = _text(permission, f"{label}.permissions")
            if value_text not in {"read", "write"} or value_text in selected:
                raise AuthorizationCloudConfigurationError("HF repo permission is invalid")
            selected.add(value_text)
        identity = (repo_type, repo_id)
        if identity in seen:
            raise AuthorizationCloudConfigurationError("HF repo scope is duplicated")
        seen.add(identity)
        output.append(
            {
                "repo_type": repo_type,
                "repo_id": repo_id,
                "permissions": sorted(selected),
            }
        )
    return {"repositories": output}


def _provider_target_ref(provider: str, value: object, label: str) -> str:
    """Validate provider targets without confusing HF resource IDs and aliases."""

    if provider == "hf":
        if isinstance(value, str) and _HUGGINGFACE_REPOSITORY_REF.fullmatch(value):
            return value
        raise AuthorizationCloudConfigurationError(
            "HF targetRef must be one owner/repository identifier"
        )
    return _alias(value, label)


def _parse_email_profile(
    value: object,
    contexts: Mapping[str, AuthorityActorContext],
) -> EmailNotificationProfile:
    if value is None:
        return EmailNotificationProfile(
            False, None, None, None, None, None, None, None, None, frozenset()
        )
    item = _object(
        value,
        required={"enabled"},
        optional={
            "directPlugin",
            "callerWorkload",
            "audience",
            "expectedIssuer",
            "contextKeyRef",
            "organizationId",
            "workspaceId",
            "recipientRef",
            "allowedContextRefs",
        },
        label="emailNotifications",
    )
    if item["enabled"] is not True:
        if set(item) != {"enabled"}:
            raise AuthorizationCloudConfigurationError(
                "disabled emailNotifications must not retain bindings or recipients"
            )
        return EmailNotificationProfile(
            False, None, None, None, None, None, None, None, None, frozenset()
        )
    required = {
        "directPlugin",
        "callerWorkload",
        "audience",
        "expectedIssuer",
        "contextKeyRef",
        "organizationId",
        "workspaceId",
        "recipientRef",
        "allowedContextRefs",
    }
    if not required <= set(item):
        raise AuthorizationCloudConfigurationError("enabled emailNotifications is incomplete")
    endpoint = _endpoint(item["directPlugin"], "emailNotifications.directPlugin")
    allowed_refs = _aliases(item["allowedContextRefs"], "email allowedContextRefs")
    if not allowed_refs or not allowed_refs <= set(contexts):
        raise AuthorizationCloudConfigurationError("email actor allowlist is empty or unknown")
    org = _text(item["organizationId"], "email organizationId")
    workspace = _text(item["workspaceId"], "email workspaceId")
    issuer = _text(item["expectedIssuer"], "email expectedIssuer")
    recipient_ref = _text(item["recipientRef"], "email recipientRef")
    if not _RECIPIENT_ALIAS.fullmatch(recipient_ref):
        raise AuthorizationCloudConfigurationError("email recipientRef must be a configured alias")
    for context_ref in allowed_refs:
        context = contexts[context_ref]
        if (
            context.organization_id != org
            or context.workspace_id != workspace
            or context.issuer != issuer
        ):
            raise AuthorizationCloudConfigurationError("email actor pins do not match the binding")
    return EmailNotificationProfile(
        True,
        endpoint,
        _text(item["callerWorkload"], "email callerWorkload"),
        _text(item["audience"], "email audience"),
        issuer,
        _text(item["contextKeyRef"], "email contextKeyRef"),
        org,
        workspace,
        recipient_ref,
        allowed_refs,
    )


def _endpoint(value: object, label: str) -> DirectPluginEndpointConfig:
    item = _object(
        value,
        required={"bindingId", "connectionRef", "transport"},
        optional={"mtls"},
        label=label,
    )
    transport = _text(item["transport"], f"{label}.transport")
    if transport not in {"local", "mtls"}:
        raise AuthorizationCloudConfigurationError("DirectPlugin transport is unsupported")
    raw_mtls = item.get("mtls")
    mtls = None
    if transport == "mtls":
        raw_mtls = _object(
            raw_mtls,
            required={"rootCertificateRef", "clientCertificateRef", "clientKeyRef"},
            optional=set(),
            label=f"{label}.mtls",
        )
        mtls = {key: _text(value, f"{label}.mtls.{key}") for key, value in raw_mtls.items()}
    elif raw_mtls is not None:
        raise AuthorizationCloudConfigurationError("local DirectPlugin cannot use mTLS")
    return DirectPluginEndpointConfig(
        binding_id=_alias(item["bindingId"], f"{label}.bindingId"),
        connection_ref=_text(item["connectionRef"], f"{label}.connectionRef"),
        transport=transport,
        mtls=mtls,
    )


def _object(
    value: object,
    *,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or set(value) - required - optional
    ):
        raise AuthorizationCloudConfigurationError(f"{label} has missing or unknown fields")
    return dict(value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise AuthorizationCloudConfigurationError(f"{label} must be bounded non-empty text")
    return value.strip()


def _alias(value: object, label: str) -> str:
    text = _text(value, label)
    if not _ALIAS.fullmatch(text):
        raise AuthorizationCloudConfigurationError(f"{label} must be an opaque alias")
    return text


def _secret_reference(value: object, label: str) -> str:
    """Validate a stable host secret reference without resolving its value."""

    text = _text(value, label)
    if (
        len(text) > 1024
        or "=" in text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", text)
    ):
        raise AuthorizationCloudConfigurationError(f"{label} must be a stable host reference")
    return text


def _aliases(value: object, label: str) -> frozenset[str]:
    if not isinstance(value, list):
        raise AuthorizationCloudConfigurationError(f"{label} must be an array")
    items = [_alias(item, label) for item in value]
    if len(items) != len(set(items)):
        raise AuthorizationCloudConfigurationError(f"{label} contains a duplicate")
    return frozenset(items)
