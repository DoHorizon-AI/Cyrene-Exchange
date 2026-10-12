"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 dispatcher.py                                                   │
│  Module: cyrene_exchange_product.integrations.dispatcher             │
│  Role: Execute durable jobs through typed, freshly authorized ports.  │
│                                                                      │
│  模块职责：通过类型化端口执行持久任务，并在每次调用前刷新授权。            │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Event
from typing import Any
from uuid import UUID

from cyrene_exchange_product.integrations.models import (
    DeliveryReceipt,
    IntegrationAuthorizationError,
    IntegrationConflict,
    IntegrationConnection,
    IntegrationPrincipal,
    JobState,
    Operation,
    OutboxJob,
    utc_now,
)
from cyrene_exchange_product.integrations.ports import (
    AccountAuthorization,
    AccountCenterPort,
    AuthorityInvocationState,
    DelegationPort,
    GitHubPort,
    IssueSnapshot,
    MessageEvidence,
    MessagePort,
    ProviderRejectedError,
    RetryableReadError,
    ValidatedExecutionProof,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """One durable worker outcome, including no-work and sanitized failure."""

    job_id: str | None
    state: str
    reason_code: str | None = None


class IntegrationDispatcher:
    """Run one outbox job using only fixed typed integration ports.

    No agent, model, prompt, or free-form execution API is reachable here.
    中文：只调用固定业务端口，不连接 Agent、模型或自由执行接口。
    """

    def __init__(
        self,
        *,
        store: IntegrationStore,
        account_center: AccountCenterPort,
        github: GitHubPort,
        message: MessagePort,
        delegation: DelegationPort,
        lease_seconds: int = 60,
    ) -> None:
        if not 1 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 1 and 300")
        self._store = store
        self._account_center = account_center
        self._github = github
        self._message = message
        self._delegation = delegation
        self._lease_seconds = lease_seconds

    def run_once(self, worker_id: str, *, now: datetime | None = None) -> DispatchResult:
        """Claim and process at most one durable job."""

        moment = now or utc_now()
        claim = self._store.claim_job(worker_id, now=moment, lease_seconds=self._lease_seconds)
        if claim is None:
            return DispatchResult(job_id=None, state="IDLE")
        job = claim.job
        try:
            if job.kind == "NOTIFY":
                return self._dispatch_notification(job, claim.claim_fence, moment)
            if job.kind == "COMMAND_REPLY":
                return self._dispatch_command_reply(job, claim.claim_fence, moment)
            if job.kind == "CHALLENGE_REPLY":
                return self._dispatch_challenge_reply(job, claim.claim_fence, moment)
            if job.kind == "ISSUE_ACTION":
                operation = self._store.get_operation_for_job(job)
                if job.authority_invocation_id is None:
                    return self._enqueue_authority(job, claim.claim_fence, operation, moment)
                return self._poll_authority(job, claim.claim_fence, moment)
            self._store.fail_claimed_job(
                job.id,
                claim_fence=claim.claim_fence,
                reason_code="unsupported_job_kind",
                now=moment,
            )
            return DispatchResult(str(job.id), JobState.FAILED.value, "unsupported_job_kind")
        except IntegrationAuthorizationError:
            self._store.fail_claimed_job(
                job.id,
                claim_fence=claim.claim_fence,
                reason_code="authorization_denied",
                now=moment,
            )
            return DispatchResult(str(job.id), JobState.FAILED.value, "authorization_denied")
        except IntegrationConflict:
            # A registered Connector may have claimed execution while polling raced it.
            return DispatchResult(str(job.id), "SUPERSEDED", "concurrent_authority_dispatch")

    def _dispatch_notification(
        self,
        job: OutboxJob,
        fence: int,
        now: datetime,
    ) -> DispatchResult:
        binding = self._store.get_binding_for_job(job)
        if not binding.enabled:
            raise IntegrationAuthorizationError("notification binding is disabled")
        event_id = str(job.payload.get("eventId", ""))
        text = (
            f"GitHub {job.payload.get('repositoryName', '')} issue "
            f"#{job.payload.get('issueNumber', '')}: {job.payload.get('action', '')} "
            f"— {job.payload.get('title', '')}"[:2000]
        )
        self._store.mark_sending(job.id, claim_fence=fence, now=now)
        try:
            evidence = self._message.send_notification(
                target_ref=binding.notification_target_ref,
                text=text,
                idempotency_key=f"incoming:{event_id}:{binding.id}",
            )
        except Exception:
            self._store.finish_job(
                job.id,
                claim_fence=fence,
                status=JobState.UNKNOWN,
                evidence={"reasonCode": "transport_result_unknown"},
            )
            return DispatchResult(str(job.id), JobState.UNKNOWN.value, "transport_result_unknown")
        return self._finish_message(job, fence, evidence)

    def _dispatch_command_reply(self, job: OutboxJob, fence: int, now: datetime) -> DispatchResult:
        """Reply to the source WeCom conversation using durable signed-source refs."""

        required = (
            "sourceBindingId",
            "senderId",
            "conversationRef",
            "replyMessageId",
            "replyContextRef",
            "text",
        )
        if any(not isinstance(job.payload.get(field), str) for field in required):
            raise IntegrationAuthorizationError("command reply context is incomplete")
        self._store.mark_sending(job.id, claim_fence=fence, now=now)
        try:
            evidence = self._message.send_command_reply(
                source_binding_id=str(job.payload["sourceBindingId"]),
                sender_id=str(job.payload["senderId"]),
                conversation_ref=str(job.payload["conversationRef"]),
                reply_message_id=str(job.payload["replyMessageId"]),
                reply_context_ref=str(job.payload["replyContextRef"]),
                text=str(job.payload["text"]),
                idempotency_key=job.idempotency_key or str(job.id),
            )
        except Exception:
            self._store.finish_job(
                job.id,
                claim_fence=fence,
                status=JobState.UNKNOWN,
                evidence={"reasonCode": "command_reply_result_unknown"},
            )
            return DispatchResult(str(job.id), JobState.UNKNOWN.value, "command_reply_unknown")
        return self._finish_message(job, fence, evidence)

    def _dispatch_challenge_reply(
        self, job: OutboxJob, fence: int, now: datetime
    ) -> DispatchResult:
        """Send one fixed private link acknowledgment through the configured WeCom bot."""

        required = (
            "sourceBindingId",
            "senderId",
            "conversationRef",
            "replyMessageId",
            "replyContextRef",
            "text",
        )
        if any(not isinstance(job.payload.get(field), str) for field in required):
            raise IntegrationAuthorizationError("challenge reply context is incomplete")
        self._store.mark_sending(job.id, claim_fence=fence, now=now)
        try:
            evidence = self._message.send_wecom_challenge_reply(
                source_binding_id=str(job.payload["sourceBindingId"]),
                sender_id=str(job.payload["senderId"]),
                conversation_ref=str(job.payload["conversationRef"]),
                reply_message_id=str(job.payload["replyMessageId"]),
                reply_context_ref=str(job.payload["replyContextRef"]),
                text=str(job.payload["text"]),
                idempotency_key=job.idempotency_key or str(job.id),
            )
        except Exception:
            self._store.finish_job(
                job.id,
                claim_fence=fence,
                status=JobState.UNKNOWN,
                evidence={"reasonCode": "challenge_reply_result_unknown"},
            )
            return DispatchResult(str(job.id), JobState.UNKNOWN.value, "challenge_reply_unknown")
        return self._finish_message(job, fence, evidence)

    def _enqueue_authority(
        self, job: OutboxJob, fence: int, operation: Operation, now: datetime
    ) -> DispatchResult:
        """Submit one immutable intent; Authority owns the execution queue."""

        if operation.delegation_ref is None:
            raise IntegrationAuthorizationError("operation has no delegation reference")
        candidate_key = (
            f"{operation.id}:read:{job.attempts}"
            if operation.operation_id == "integration.issue.query"
            else str(operation.id)
        )
        operation, job, idempotency_key = self._store.prepare_authority_enqueue(
            job.id,
            claim_fence=fence,
            candidate_idempotency_key=candidate_key,
            now=now,
        )
        if operation.delegation_ref is None:
            raise IntegrationAuthorizationError("operation delegation reference was removed")
        evidence = self._delegation.enqueue_authorized_action(
            delegation_ref=operation.delegation_ref,
            workspace_id=operation.workspace_id,
            binding_id=str(operation.binding_id),
            execution_operation_id=operation.execution_operation_id,
            operation_id=str(operation.id),
            argument_digest=operation.argument_digest,
            idempotency_key=idempotency_key,
        )
        updated = self._store.mark_awaiting_authority(
            job.id,
            claim_fence=fence,
            invocation_id=evidence.invocation_id,
            authority_state=evidence.state.value,
            now=now,
        )
        return DispatchResult(str(job.id), updated.state.value)

    def _poll_authority(self, job: OutboxJob, fence: int, now: datetime) -> DispatchResult:
        """Poll invocation evidence without treating an ID as execution authority."""

        invocation_id = job.authority_invocation_id
        if invocation_id is None:
            raise IntegrationAuthorizationError("Authority invocation is missing")
        evidence = self._delegation.poll_invocation(invocation_id)
        if evidence.invocation_id != invocation_id:
            raise IntegrationAuthorizationError("Authority poll returned a different invocation")
        if evidence.state in {
            AuthorityInvocationState.DENIED,
            AuthorityInvocationState.EXPIRED,
            AuthorityInvocationState.REVOKED,
            AuthorityInvocationState.FAILED,
        }:
            failed = self._store.fail_claimed_job(
                job.id,
                claim_fence=fence,
                reason_code=f"authority_{evidence.state.value.lower()}",
                now=now,
            )
            return DispatchResult(str(job.id), failed.state.value, "authority_denied")
        if evidence.state == AuthorityInvocationState.UNKNOWN_RESULT:
            unknown = self._store.mark_authority_result_unknown(
                job.id,
                claim_fence=fence,
                invocation_id=invocation_id,
                now=now,
            )
            return DispatchResult(str(job.id), unknown.state.value, "authority_unknown_result")
        updated = self._store.update_authority_evidence(
            job.id,
            claim_fence=fence,
            invocation_id=invocation_id,
            authority_state=evidence.state.value,
            now=now,
        )
        return DispatchResult(str(job.id), updated.state.value)

    def execute_authorized_action(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        binding_id: UUID,
        execution_operation_id: str,
        argument_digest: str,
        authority_invocation_id: str,
        authority_evidence: Any,
    ) -> Operation:
        """Execute only a matching signed Authority dispatch over the fixed provider ports."""

        principal.require(execution_operation_id)
        operation = self._store.get_operation_for_principal(
            principal,
            operation_id,
            authorization_operation_id=execution_operation_id,
        )
        if (
            operation.binding_id != binding_id
            or operation.execution_operation_id != execution_operation_id
            or operation.argument_digest != argument_digest
            or operation.authority_invocation_id not in (None, authority_invocation_id)
        ):
            raise IntegrationAuthorizationError("approved invocation does not match stored intent")
        _validate_execution_proof(
            authority_evidence,
            principal=principal,
            operation=operation,
            binding_id=binding_id,
            execution_operation_id=execution_operation_id,
            authority_invocation_id=authority_invocation_id,
            argument_digest=argument_digest,
        )
        connection = self._store.get_connection_for_binding(
            principal,
            operation.connection_id,
            binding_id,
            authorization_operation_id=execution_operation_id,
        )
        binding = self._store.get_binding(
            principal,
            binding_id,
            authorization_operation_id=execution_operation_id,
        )
        if not binding.enabled or binding.connection_id != connection.id:
            raise IntegrationAuthorizationError("execution binding no longer matches the intent")
        actor_binding = self._store.get_actor_binding_for_operation(
            principal, binding_id, operation_id=execution_operation_id
        )
        if (
            actor_binding.id != operation.actor_binding_id
            or actor_binding.account_link_ref != operation.account_link_ref
            or actor_binding.delegation_ref != operation.delegation_ref
        ):
            raise IntegrationAuthorizationError("member account authorization no longer matches")
        github_operation_id, arguments = _github_arguments(connection, operation)
        if _digest(arguments) != operation.argument_digest:
            raise IntegrationAuthorizationError("stored operation payload digest is invalid")
        authorization = self._account_center.get_authorization(
            principal,
            account_link_ref=operation.account_link_ref,
            operation_id=github_operation_id,
            repository_id=connection.repository_id,
            repository_name=connection.repository_name,
            issue_number=operation.issue_number,
            arguments=arguments,
            arguments_sha256=operation.argument_digest,
        )
        _validate_account_authorization(
            authorization,
            connection,
            principal,
            github_operation_id,
            operation.argument_digest,
            account_link_ref=operation.account_link_ref,
        )
        operation, job, fence = self._store.begin_authorized_execution(
            principal,
            operation_id,
            binding_id=binding_id,
            execution_operation_id=execution_operation_id,
            argument_digest=argument_digest,
            authority_invocation_id=authority_invocation_id,
            lease_seconds=self._lease_seconds,
        )
        try:
            if operation.operation_id == "integration.issue.query":
                snapshot = self._github.get_issue(
                    authorization,
                    repository_id=connection.repository_id,
                    issue_number=operation.issue_number,
                )
                self._store.save_snapshot(
                    snapshot.as_resource_snapshot(
                        organization_id=connection.organization_id,
                        workspace_id=connection.workspace_id,
                        actor_issuer=principal.issuer,
                        actor_subject=principal.subject,
                        connection_id=connection.id,
                    )
                )
                self._finish_issue_snapshot(job, fence, snapshot)
                if operation.reconciles_operation_id is not None:
                    original = self._store.get_operation_for_principal(
                        principal,
                        operation.reconciles_operation_id,
                        authorization_operation_id=execution_operation_id,
                    )
                    expected_state = (
                        "CLOSED" if original.operation_id == "integration.issue.close" else "OPEN"
                    )
                    matched = snapshot.state.upper() == expected_state
                    self._store.resolve_unknown_operation(
                        principal,
                        original.id,
                        succeeded=matched,
                        result={
                            "reconciledReadOnly": True,
                            "observedState": snapshot.state,
                            "version": snapshot.version,
                            "observedAt": snapshot.observed_at.isoformat(),
                            "reasonCode": "provider_state_confirms_operation"
                            if matched
                            else "provider_state_does_not_confirm_operation",
                        },
                        authorization_operation_id=execution_operation_id,
                    )
            elif operation.operation_id == "integration.issue.comment":
                if operation.body is None:
                    raise IntegrationAuthorizationError("comment body is missing")
                evidence = self._github.create_comment(
                    authorization,
                    repository_id=connection.repository_id,
                    issue_number=operation.issue_number,
                    body=operation.body,
                )
                self._finish_provider_write(job, fence, evidence)
            else:
                target_state = (
                    "CLOSED" if operation.operation_id == "integration.issue.close" else "OPEN"
                )
                evidence = self._github.update_state(
                    authorization,
                    repository_id=connection.repository_id,
                    issue_number=operation.issue_number,
                    state=target_state,
                )
                self._finish_provider_write(job, fence, evidence)
        except RetryableReadError as exc:
            if operation.operation_id == "integration.issue.query":
                self._store.retry_readonly_job(
                    job.id,
                    claim_fence=fence,
                    now=utc_now(),
                    retry_after_seconds=exc.retry_after_seconds,
                )
                return self._store.get_operation_for_principal(
                    principal,
                    operation_id,
                    authorization_operation_id=execution_operation_id,
                )
            self._store.finish_job(
                job.id,
                claim_fence=fence,
                status=JobState.UNKNOWN,
                evidence={"reasonCode": "provider_write_result_unknown"},
            )
            raise
        except ProviderRejectedError as exc:
            self._store.finish_job(
                job.id,
                claim_fence=fence,
                status=JobState.FAILED,
                evidence={"reasonCode": exc.reason_code},
            )
            return self._store.get_operation_for_principal(
                principal,
                operation_id,
                authorization_operation_id=execution_operation_id,
            )
        except Exception:
            self._store.finish_job(
                job.id,
                claim_fence=fence,
                status=JobState.UNKNOWN,
                evidence={"reasonCode": "provider_result_unknown"},
            )
            raise
        return self._store.get_operation_for_principal(
            principal,
            operation_id,
            authorization_operation_id=execution_operation_id,
        )

    def _finish_provider_write(self, job: OutboxJob, fence: int, evidence: Any) -> None:
        """Persist an explicit fixed-provider response under the execution fence."""

        status = (
            JobState.SUCCEEDED
            if evidence.accepted and evidence.succeeded
            else JobState.ACCEPTED
            if evidence.accepted
            else JobState.FAILED
        )
        self._store.finish_job(
            job.id,
            claim_fence=fence,
            status=status,
            evidence={
                "accepted": evidence.accepted,
                "succeeded": evidence.succeeded,
                "vendorResourceId": evidence.vendor_resource_id,
                **evidence.evidence,
            },
        )

    def reconcile_operation(
        self,
        principal: IntegrationPrincipal,
        operation_id: UUID,
        *,
        idempotency_key: str,
    ) -> Operation:
        """Queue a new Authority-approved read-only query for reconciliation.

        The current UNKNOWN write is never replayed. Query work returns through the
        registered Connector execution route before provider access.
        中文：UNKNOWN 写操作不会重发；只读核对也必须经 Authority 授权执行。
        """

        return self._store.enqueue_reconciliation_query(
            principal, operation_id, idempotency_key=idempotency_key
        )

    def _finish_issue_snapshot(
        self, job: OutboxJob, fence: int, snapshot: IssueSnapshot
    ) -> DispatchResult:
        """Persist a read result as success with source observation metadata."""

        status = JobState.SUCCEEDED
        self._store.finish_job(
            job.id,
            claim_fence=fence,
            status=status,
            evidence={
                "state": snapshot.state,
                "title": snapshot.title,
                "version": snapshot.version,
                "observedAt": snapshot.observed_at.isoformat(),
            },
        )
        return DispatchResult(str(job.id), status.value)

    def _finish_message(
        self, job: OutboxJob, fence: int, evidence: MessageEvidence
    ) -> DispatchResult:
        """Persist transport ACK as acceptance only, with no fabricated delivery."""

        status = JobState.ACCEPTED if evidence.accepted else JobState.FAILED
        receipt = DeliveryReceipt(
            status=status.value,
            accepted=evidence.accepted,
            vendor_message_id=evidence.vendor_message_id,
            transport_request_id=evidence.transport_request_id,
            observed_at=evidence.observed_at,
            evidence=evidence.evidence,
        )
        self._store.finish_job(
            job.id,
            claim_fence=fence,
            status=status,
            evidence={"accepted": evidence.accepted},
            receipt=receipt,
        )
        return DispatchResult(str(job.id), status.value)


class DispatcherRunner:
    """Long-running worker seam for an explicitly configured dispatcher."""

    def __init__(
        self,
        dispatcher: IntegrationDispatcher,
        *,
        worker_id: str,
        idle_delay_seconds: float = 0.5,
    ) -> None:
        if not worker_id.strip() or not 0.05 <= idle_delay_seconds <= 30:
            raise ValueError("worker id or idle delay is invalid")
        self._dispatcher = dispatcher
        self._worker_id = worker_id
        self._idle_delay_seconds = idle_delay_seconds

    def run_once(self, *, now: datetime | None = None) -> DispatchResult:
        """Execute one durable job through the configured typed ports."""

        return self._dispatcher.run_once(self._worker_id, now=now)

    def run_forever(self, stop_event: Event) -> None:
        """Poll until the host signals shutdown; no in-memory job queue is used."""

        while not stop_event.is_set():
            result = self.run_once()
            if result.state == "IDLE":
                stop_event.wait(self._idle_delay_seconds)


def _digest(value: dict[str, Any]) -> str:
    """Return a stable digest for delegation binding; no raw body enters grant IDs."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_execution_proof(
    proof: Any,
    *,
    principal: IntegrationPrincipal,
    operation: Operation,
    binding_id: UUID,
    execution_operation_id: str,
    authority_invocation_id: str,
    argument_digest: str,
) -> None:
    """Recheck Authority's validated envelope against immutable local intent."""

    if not isinstance(proof, ValidatedExecutionProof):
        proof = _project_authority_evidence(proof)

    try:
        body = json.loads(proof.raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrationAuthorizationError("Authority execution body is invalid") from exc
    expected_body = {
        "operationId": str(operation.id),
        "argumentDigest": operation.argument_digest,
    }
    expected_paths = {
        "integrationExecuteIssueComment": (
            f"/api/v1/integrations/sync-bindings/{binding_id}/execute-issue-comment"
        ),
        "integrationExecuteIssueState": (
            f"/api/v1/integrations/sync-bindings/{binding_id}/execute-issue-state"
        ),
        "integrationExecuteIssueQuery": (
            f"/api/v1/integrations/sync-bindings/{binding_id}/execute-issue-query"
        ),
    }
    if (
        proof.invocation_id != authority_invocation_id
        or proof.owner != "exchange"
        or proof.issuer != principal.issuer
        or proof.subject != principal.subject
        or proof.organization_id != principal.organization_id
        or proof.workspace_id != principal.workspace_id
        or proof.http_method != "POST"
        or proof.content_type != "application/json"
        or proof.path != expected_paths.get(execution_operation_id)
        or proof.idempotency_key != operation.authority_idempotency_key
        or proof.execution_operation_id != execution_operation_id
        or proof.operation_id != str(operation.id)
        or proof.binding_id != str(binding_id)
        or proof.argument_digest != argument_digest
        or proof.raw_body_sha256 != hashlib.sha256(proof.raw_body).hexdigest()
        or body != expected_body
    ):
        raise IntegrationAuthorizationError("Authority execution proof does not match intent")


def _project_authority_evidence(value: Any) -> ValidatedExecutionProof:
    """Project a verified ApprovedInvocation protobuf into the narrow proof model."""

    try:
        envelope = value.canonical_envelope
        invocation = envelope.invocation
        target = envelope.target
        raw_body = bytes(invocation.json_body)
        body = json.loads(raw_body)
        return ValidatedExecutionProof(
            invocation_id=str(value.invocation_id),
            owner=str(invocation.owner_id),
            issuer=str(envelope.principal_issuer),
            subject=str(envelope.principal_subject),
            organization_id=str(envelope.organization_id),
            workspace_id=str(envelope.workspace_id),
            http_method=str(target.http_method),
            path=str(target.endpoint),
            content_type=str(getattr(target, "content_type", "")),
            idempotency_key=str(target.idempotency_key),
            execution_operation_id=str(invocation.operation_id),
            operation_id=str(body["operationId"]),
            binding_id=str(invocation.resource_id),
            argument_digest=str(body["argumentDigest"]),
            raw_body=raw_body,
            raw_body_sha256=hashlib.sha256(raw_body).hexdigest(),
        )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise IntegrationAuthorizationError("Authority ApprovedInvocation is malformed") from exc


def _github_arguments(
    connection: IntegrationConnection, operation: Operation
) -> tuple[str, dict[str, object]]:
    """Build exact canonical public-provider arguments and operation ID."""

    arguments: dict[str, object] = {
        "repository_id": connection.repository_id,
        "repository": connection.repository_name,
        "issue_number": operation.issue_number,
    }
    if operation.operation_id == "integration.issue.comment":
        if operation.body is None:
            raise IntegrationAuthorizationError("comment body is missing")
        arguments["body"] = operation.body
        return "github.issue.comment.create", arguments
    if operation.operation_id == "integration.issue.close":
        arguments["state"] = "CLOSED"
        return "github.issue.state.update", arguments
    if operation.operation_id == "integration.issue.reopen":
        arguments["state"] = "OPEN"
        return "github.issue.state.update", arguments
    return "github.issue.get", arguments


def _validate_account_authorization(
    authorization: AccountAuthorization,
    connection: IntegrationConnection,
    principal: IntegrationPrincipal,
    operation_id: str,
    arguments_sha256: str,
    *,
    account_link_ref: str,
) -> None:
    """Fail closed if Account Center returns a lease for a different actor/scope."""

    if (
        authorization.actor_issuer != principal.issuer
        or authorization.actor_subject != principal.subject
        or authorization.organization_id != principal.organization_id
        or authorization.workspace_id != principal.workspace_id
        or authorization.account_link_ref != account_link_ref
        or authorization.provider != "github"
        or authorization.repository_id != connection.repository_id
        or authorization.repository_name != connection.repository_name
        or authorization.operation_id != operation_id
        or authorization.arguments_sha256 != arguments_sha256
        or authorization.expires_at <= utc_now()
        or authorization.expires_at > utc_now() + timedelta(seconds=60)
    ):
        raise IntegrationAuthorizationError("Account Center lease scope does not match")
