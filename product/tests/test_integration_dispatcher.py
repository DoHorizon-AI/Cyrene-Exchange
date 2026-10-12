"""Durable dispatcher boundary tests with test-only typed port substitutes."""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cyrene_exchange_product.integrations.dispatcher import IntegrationDispatcher
from cyrene_exchange_product.integrations.models import (
    CreateActorBinding,
    CreateIntegrationConnection,
    CreateSyncBinding,
    EnqueueIssueAction,
    IntegrationAuthorizationError,
    IntegrationPrincipal,
    JobState,
    NormalizedGitHubEvent,
    OperationState,
    WeComEventState,
)
from cyrene_exchange_product.integrations.ports import (
    AccountAuthorization,
    AuthorityEnqueueEvidence,
    AuthorityInvocationEvidence,
    AuthorityInvocationState,
    IssueSnapshot,
    MessageEvidence,
    ProviderRejectedError,
    RetryableReadError,
    ValidatedExecutionProof,
    WriteEvidence,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


class FakeDelegation:
    """Test-only Authority port returning invocation evidence, never credentials."""

    def __init__(self, *, actor: IntegrationPrincipal) -> None:
        self.actor = actor
        self.calls: list[dict[str, object]] = []

    def enqueue_authorized_action(self, **kwargs) -> AuthorityEnqueueEvidence:
        self.calls.append(kwargs)
        return AuthorityEnqueueEvidence(
            invocation_id=f"authority:{kwargs['idempotency_key']}",
            state=AuthorityInvocationState.PENDING,
        )

    def poll_invocation(self, invocation_id: str) -> AuthorityInvocationEvidence:
        return AuthorityInvocationEvidence(
            invocation_id=invocation_id,
            state=AuthorityInvocationState.DISPATCHED,
            observed_at=datetime.now(UTC),
        )


class FakeAccountCenter:
    """Test-only Account Center port returning actor-scoped synthetic metadata."""

    def __init__(self) -> None:
        self.calls = 0

    def get_authorization(
        self,
        principal,
        *,
        account_link_ref,
        operation_id,
        repository_id,
        repository_name,
        issue_number,
        arguments,
        arguments_sha256,
    ):
        self.calls += 1
        return AccountAuthorization(
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            organization_id=principal.organization_id,
            workspace_id=principal.workspace_id,
            account_link_ref=account_link_ref,
            provider="github",
            repository_id=repository_id,
            repository_name=repository_name,
            operation_id=operation_id,
            arguments_sha256=arguments_sha256,
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
            lease_ref="lease:synthetic-only",
        )


class FakeGitHub:
    """Test-only GitHub port that checks the send boundary before mutations."""

    def __init__(self, store: IntegrationStore) -> None:
        self.store = store
        self.sending_seen = False
        self.issue_state = "OPEN"
        self.comment_error = None
        self.issue_error = None

    def get_issue(self, authorization, *, repository_id, issue_number):
        if self.issue_error is not None:
            raise self.issue_error
        return IssueSnapshot(
            repository_id=repository_id,
            issue_number=issue_number,
            state=self.issue_state,
            title="Synthetic issue",
            body="No external content",
            version="version-7",
            observed_at=datetime.now(UTC),
        )

    def create_comment(self, authorization, *, repository_id, issue_number, body):
        if self.comment_error is not None:
            raise self.comment_error
        jobs = self.store.list_jobs(
            TEST_ACTOR,
            state=JobState.SENDING,
        )
        self.sending_seen = bool(jobs)
        return WriteEvidence(
            accepted=True,
            succeeded=True,
            vendor_resource_id="comment-99",
            observed_at=datetime.now(UTC),
            evidence={"httpStatus": 201},
        )

    def update_state(self, authorization, *, repository_id, issue_number, state):
        return WriteEvidence(
            accepted=True,
            succeeded=True,
            vendor_resource_id=f"issue-{issue_number}",
            observed_at=datetime.now(UTC),
            evidence={"state": state},
        )


class FakeMessage:
    """Test-only transport proving that acceptance may have no vendor message ID."""

    def __init__(
        self,
        store: IntegrationStore,
        actor: IntegrationPrincipal,
        *,
        raise_on_send: bool = False,
    ) -> None:
        self.store = store
        self.actor = actor
        self.sending_seen = False
        self.raise_on_send = raise_on_send
        self.command_reply_arguments: dict[str, str] | None = None
        self.challenge_reply_arguments: dict[str, str] | None = None

    def send_notification(self, *, target_ref, text, idempotency_key):
        self.sending_seen = bool(self.store.list_jobs(self.actor, state=JobState.SENDING))
        if self.raise_on_send:
            raise RuntimeError("synthetic transport outcome unknown")
        return MessageEvidence(
            accepted=True,
            vendor_message_id=None,
            transport_request_id="request-77",
            observed_at=datetime.now(UTC),
            evidence={"ackCode": 0},
        )

    def send_command_reply(
        self,
        *,
        source_binding_id,
        sender_id,
        conversation_ref,
        reply_message_id,
        reply_context_ref,
        text,
        idempotency_key,
    ):
        self.sending_seen = bool(self.store.list_jobs(self.actor, state=JobState.SENDING))
        self.command_reply_arguments = {
            "source_binding_id": source_binding_id,
            "sender_id": sender_id,
            "conversation_ref": conversation_ref,
            "reply_message_id": reply_message_id,
            "reply_context_ref": reply_context_ref,
            "text": text,
            "idempotency_key": idempotency_key,
        }
        return MessageEvidence(
            accepted=True,
            vendor_message_id=None,
            transport_request_id="reply-request-1",
            observed_at=datetime.now(UTC),
            evidence={"ackCode": 0},
        )

    def send_wecom_challenge_reply(
        self,
        *,
        source_binding_id,
        sender_id,
        conversation_ref,
        reply_message_id,
        reply_context_ref,
        text,
        idempotency_key,
    ):
        self.challenge_reply_arguments = {
            "source_binding_id": source_binding_id,
            "sender_id": sender_id,
            "conversation_ref": conversation_ref,
            "reply_message_id": reply_message_id,
            "reply_context_ref": reply_context_ref,
            "text": text,
            "idempotency_key": idempotency_key,
        }
        return MessageEvidence(
            accepted=True,
            vendor_message_id=None,
            transport_request_id="challenge-reply-request-1",
            observed_at=datetime.now(UTC),
            evidence={"ackCode": 0},
        )


TEST_ACTOR = IntegrationPrincipal(
    issuer="https://identity.example.test",
    subject="actor-1",
    organization_id="org-1",
    workspace_id="workspace-a",
    allowed_operation_ids=frozenset(
        {
            "integration.issue.comment",
            "integration.issue.close",
            "integration.issue.query",
            "integration.notification.send",
            "integrationListJobs",
            "integrationReconcile",
            "integrationGetOperation",
            "integrationExecuteIssueComment",
            "integrationExecuteIssueState",
            "integrationExecuteIssueQuery",
        }
    ),
    delegation_id="delegation-3",
    delegation_generation=3,
    expires_at=datetime.now(UTC) + timedelta(hours=1),
)


def setup_store(
    path,
    *,
    with_event: bool = False,
    wecom_command: bool = False,
    operation_id: str = "integration.issue.comment",
) -> IntegrationStore:
    """Create an isolated synthetic store and a fixed test binding."""

    store = IntegrationStore(path)
    creator = IntegrationPrincipal(
        issuer=TEST_ACTOR.issuer,
        subject=TEST_ACTOR.subject,
        organization_id=TEST_ACTOR.organization_id,
        workspace_id=TEST_ACTOR.workspace_id,
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationCreateBinding",
                "integrationAttachActorBinding",
                "integration.issue.comment",
                "integration.issue.close",
                "integration.issue.query",
                "integration.issue.reopen",
            }
        ),
    )
    connection = store.create_connection(
        creator,
        CreateIntegrationConnection(
            repository_id="repo-42",
            repository_name="acme/example",
        ),
        idempotency_key="connection:dispatcher",
    )
    binding = store.create_binding(
        creator,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="target:synthetic",
        ),
        idempotency_key=f"binding:{connection.id}",
    )
    store.create_actor_binding(
        creator,
        CreateActorBinding(
            binding_id=binding.id,
            account_link_ref="account-link:synthetic",
            delegation_ref="delegation:synthetic",
        ),
        idempotency_key="actor-binding:dispatcher",
    )
    if wecom_command:
        event, _ = store.persist_wecom_inbound(
            binding.id,
            "wecom-source-1",
            expected_organization_id=creator.organization_id,
            expected_workspace_id=creator.workspace_id,
            sender_id="wecom-user-1",
            conversation_ref="private-chat-1",
            reply_message_id="canonical-message-1",
            reply_context_ref="original-req-1",
            message_text="/issue comment 3 Please investigate",
            verified=True,
        )
        operation = store.enqueue_issue_command_for_actor(
            binding_id=binding.id,
            actor_issuer=creator.issuer,
            actor_subject=creator.subject,
            organization_id=creator.organization_id,
            workspace_id=creator.workspace_id,
            source_event_ref=str(event.id),
            source_sender_id=event.sender_id,
            idempotency_key=f"wecom:{event.id}",
            command_text=event.message_text,
        )
        store.mark_wecom_inbound_processed(
            event.id,
            binding.id,
            state=WeComEventState.COMMAND_QUEUED,
            operation_id=operation.id,
        )
    elif with_event:
        store.ingest_github_event(
            connection.id,
            "delivery-1",
            NormalizedGitHubEvent(
                event_type="issues",
                action="opened",
                repository_id="repo-42",
                issue_number=3,
                sender_id="sender-2",
                sender_login="reporter",
                title="Synthetic title",
            ),
            verified=True,
        )
    else:
        store.enqueue_issue_action(
            creator,
            EnqueueIssueAction(
                connection_id=connection.id,
                binding_id=binding.id,
                operation_id=operation_id,
                idempotency_key="comment-1",
                issue_number=3,
                body="Synthetic comment" if operation_id.endswith("comment") else None,
            ),
        )
    return store


def test_issue_write_persists_sending_before_typed_provider_call(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3")
    github = FakeGitHub(store)
    delegation = FakeDelegation(actor=TEST_ACTOR)
    accounts = FakeAccountCenter()
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=accounts,
        github=github,
        message=FakeMessage(store, TEST_ACTOR),
        delegation=delegation,
    )

    queued = dispatcher.run_once("worker-test")
    assert queued.state == JobState.AWAITING_AUTHORITY.value
    assert not github.sending_seen
    assert accounts.calls == 0
    job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    operation = store.get_operation(TEST_ACTOR, job.operation_id)
    result = dispatcher.execute_authorized_action(
        TEST_ACTOR,
        operation.id,
        binding_id=operation.binding_id,
        execution_operation_id=operation.execution_operation_id,
        argument_digest=operation.argument_digest,
        authority_invocation_id=operation.authority_invocation_id,
        authority_evidence=_proof(operation),
    )

    assert result.state == OperationState.SUCCEEDED
    assert github.sending_seen
    assert len(delegation.calls) == 1
    assert store.list_jobs(creator_for_store(), state=JobState.SUCCEEDED)
    store.close()


def test_mismatched_authority_proof_fails_before_account_or_provider_calls(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3")
    github = FakeGitHub(store)
    accounts = FakeAccountCenter()
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=accounts,
        github=github,
        message=FakeMessage(store, TEST_ACTOR),
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )
    dispatcher.run_once("worker-test")
    job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    operation = store.get_operation(TEST_ACTOR, job.operation_id)

    with pytest.raises(IntegrationAuthorizationError):
        dispatcher.execute_authorized_action(
            TEST_ACTOR,
            operation.id,
            binding_id=operation.binding_id,
            execution_operation_id=operation.execution_operation_id,
            argument_digest=operation.argument_digest,
            authority_invocation_id=operation.authority_invocation_id,
            authority_evidence=replace(_proof(operation), argument_digest="f" * 64),
        )

    assert accounts.calls == 0
    assert not github.sending_seen
    assert store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)
    store.close()


def test_explicit_provider_rejection_is_failed_not_unknown(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3")
    github = FakeGitHub(store)
    github.comment_error = ProviderRejectedError("AUTHORIZATION_DENIED")
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=github,
        message=FakeMessage(store, TEST_ACTOR),
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )
    dispatcher.run_once("worker-test")
    job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    operation = store.get_operation(TEST_ACTOR, job.operation_id)

    result = dispatcher.execute_authorized_action(
        TEST_ACTOR,
        operation.id,
        binding_id=operation.binding_id,
        execution_operation_id=operation.execution_operation_id,
        argument_digest=operation.argument_digest,
        authority_invocation_id=operation.authority_invocation_id,
        authority_evidence=_proof(operation),
    )

    assert result.state == OperationState.FAILED
    assert store.list_jobs(TEST_ACTOR, state=JobState.FAILED)
    assert not store.list_jobs(TEST_ACTOR, state=JobState.UNKNOWN)
    store.close()


def test_uncertain_provider_write_becomes_unknown_and_is_not_resent(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3")
    github = FakeGitHub(store)
    github.comment_error = RuntimeError("synthetic write timeout")
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=github,
        message=FakeMessage(store, TEST_ACTOR),
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )
    dispatcher.run_once("worker-test")
    job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    operation = store.get_operation(TEST_ACTOR, job.operation_id)

    with pytest.raises(RuntimeError):
        dispatcher.execute_authorized_action(
            TEST_ACTOR,
            operation.id,
            binding_id=operation.binding_id,
            execution_operation_id=operation.execution_operation_id,
            argument_digest=operation.argument_digest,
            authority_invocation_id=operation.authority_invocation_id,
            authority_evidence=_proof(operation),
        )
    assert store.get_operation(TEST_ACTOR, operation.id).state == OperationState.UNKNOWN
    assert store.list_jobs(TEST_ACTOR, state=JobState.UNKNOWN)
    assert dispatcher.run_once("worker-test").state == "IDLE"
    store.close()


def test_retryable_read_failure_uses_bounded_retry_after_and_new_authority_key(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3", operation_id="integration.issue.query")
    github = FakeGitHub(store)
    github.issue_error = RetryableReadError("temporary read failure", retry_after_seconds=5)
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=github,
        message=FakeMessage(store, TEST_ACTOR),
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )
    now = datetime.now(UTC)
    dispatcher.run_once("worker-test", now=now)
    job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    operation = store.get_operation(TEST_ACTOR, job.operation_id)
    first_key = operation.authority_idempotency_key

    result = dispatcher.execute_authorized_action(
        TEST_ACTOR,
        operation.id,
        binding_id=operation.binding_id,
        execution_operation_id=operation.execution_operation_id,
        argument_digest=operation.argument_digest,
        authority_invocation_id=operation.authority_invocation_id,
        authority_evidence=_proof(operation),
    )

    assert result.state == OperationState.QUEUED
    retried = store.list_jobs(TEST_ACTOR, state=JobState.READY)[0]
    queued = store.get_operation(TEST_ACTOR, operation.id)
    assert retried.available_at >= now + timedelta(seconds=5)
    assert queued.authority_invocation_id is None
    assert queued.authority_idempotency_key is None
    assert first_key is not None
    store.close()


def test_notification_ack_is_accepted_without_invented_vendor_delivery_id(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3", with_event=True)
    message = FakeMessage(store, TEST_ACTOR)
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=FakeGitHub(store),
        message=message,
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )

    result = dispatcher.run_once("worker-test")

    assert result.state == JobState.ACCEPTED.value
    assert message.sending_seen
    completed = store.list_jobs(creator_for_store(), state=JobState.ACCEPTED)
    assert len(completed) == 1
    receipts = store.list_delivery_receipts(creator_for_store())
    assert len(receipts) == 1
    assert receipts[0].accepted is True
    assert receipts[0].vendor_message_id is None
    assert receipts[0].transport_request_id == "request-77"
    store.close()


def test_wecom_command_result_is_replied_from_durable_original_context(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3", wecom_command=True)
    github = FakeGitHub(store)
    message = FakeMessage(store, TEST_ACTOR)
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=github,
        message=message,
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )

    assert dispatcher.run_once("worker-test").state == JobState.AWAITING_AUTHORITY.value
    issue_job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    operation = store.get_operation(TEST_ACTOR, issue_job.operation_id)
    completed = dispatcher.execute_authorized_action(
        TEST_ACTOR,
        operation.id,
        binding_id=operation.binding_id,
        execution_operation_id=operation.execution_operation_id,
        argument_digest=operation.argument_digest,
        authority_invocation_id=operation.authority_invocation_id,
        authority_evidence=_proof(operation),
    )

    assert completed.state == OperationState.SUCCEEDED
    reply = dispatcher.run_once("worker-test")

    assert reply.state == JobState.ACCEPTED.value
    assert message.command_reply_arguments == {
        "source_binding_id": str(operation.binding_id),
        "sender_id": "wecom-user-1",
        "conversation_ref": "private-chat-1",
        "reply_message_id": "canonical-message-1",
        "reply_context_ref": "original-req-1",
        "text": "Comment on acme/example#3 was confirmed.",
        "idempotency_key": f"command-reply:{operation.source_event_ref}:{operation.id}",
    }
    assert store.get_operation(TEST_ACTOR, operation.id).state == OperationState.SUCCEEDED
    assert store.list_delivery_receipts(TEST_ACTOR)[0].accepted
    store.close()


def test_unknown_notification_send_is_durable_and_never_resent(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3", with_event=True)
    message = FakeMessage(store, TEST_ACTOR, raise_on_send=True)
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=FakeGitHub(store),
        message=message,
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )

    result = dispatcher.run_once("worker-test")
    second = dispatcher.run_once("worker-test")

    assert result.state == JobState.UNKNOWN.value
    assert second.state == "IDLE"
    assert message.sending_seen
    assert [job.state for job in store.list_jobs(creator_for_store())] == [JobState.UNKNOWN]
    store.close()


def test_wecom_link_challenge_reply_is_durable_and_does_not_echo_nonce(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    creator = IntegrationPrincipal(
        issuer=TEST_ACTOR.issuer,
        subject=TEST_ACTOR.subject,
        organization_id=TEST_ACTOR.organization_id,
        workspace_id=TEST_ACTOR.workspace_id,
        allowed_operation_ids=frozenset(
            {"integrationCreateConnection", "integrationCreateBinding"}
        ),
    )
    connection = store.create_connection(
        creator,
        CreateIntegrationConnection(repository_id="repo-42", repository_name="acme/example"),
        idempotency_key="challenge-connection",
    )
    binding = store.create_binding(
        creator,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="wecom-bot:source-1",
        ),
        idempotency_key="challenge-binding",
    )
    event, _ = store.persist_wecom_inbound(
        binding.id,
        "wecom-link-event",
        expected_organization_id=creator.organization_id,
        expected_workspace_id=creator.workspace_id,
        sender_id="wecom-user-1",
        conversation_ref="private-chat-1",
        reply_message_id="canonical-message-11",
        reply_context_ref="original-req-11",
        message_text="/link private-nonce",
        verified=True,
    )
    store.begin_wecom_challenge_observation(binding.id, str(event.id))
    store.enqueue_wecom_challenge_reply(binding.id, str(event.id), "challenge-id-11")
    message = FakeMessage(store, TEST_ACTOR)
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=FakeGitHub(store),
        message=message,
        delegation=FakeDelegation(actor=TEST_ACTOR),
    )

    result = dispatcher.run_once("worker-test")

    assert result.state == JobState.ACCEPTED.value
    assert message.challenge_reply_arguments is not None
    assert message.challenge_reply_arguments["source_binding_id"] == str(binding.id)
    assert message.challenge_reply_arguments["reply_message_id"] == "canonical-message-11"
    assert message.challenge_reply_arguments["reply_context_ref"] == "original-req-11"
    assert "challenge-id-11" in message.challenge_reply_arguments["text"]
    assert "private-nonce" not in message.challenge_reply_arguments["text"]
    store.close()


def test_reconcile_confirms_close_with_read_only_github_snapshot(tmp_path) -> None:
    store = setup_store(tmp_path / "integrations.sqlite3", operation_id="integration.issue.close")
    github = FakeGitHub(store)
    github.issue_state = "CLOSED"
    delegation = FakeDelegation(actor=TEST_ACTOR)
    dispatcher = IntegrationDispatcher(
        store=store,
        account_center=FakeAccountCenter(),
        github=github,
        message=FakeMessage(store, TEST_ACTOR),
        delegation=delegation,
    )
    claim_time = datetime.now(UTC)
    assert (
        dispatcher.run_once("worker-test", now=claim_time).state
        == JobState.AWAITING_AUTHORITY.value
    )
    pending_job = store.list_jobs(TEST_ACTOR, state=JobState.AWAITING_AUTHORITY)[0]
    original = store.get_operation(TEST_ACTOR, pending_job.operation_id)
    store.begin_authorized_execution(
        TEST_ACTOR,
        original.id,
        binding_id=original.binding_id,
        execution_operation_id=original.execution_operation_id,
        argument_digest=original.argument_digest,
        authority_invocation_id=original.authority_invocation_id,
        lease_seconds=2,
        now=claim_time,
    )
    store.recover_expired_claims(now=claim_time + timedelta(seconds=3))
    original = store.get_operation(TEST_ACTOR, original.id)
    assert original.state == OperationState.UNKNOWN

    query_operation = dispatcher.reconcile_operation(
        TEST_ACTOR, original.id, idempotency_key="reconcile-close-1"
    )
    assert query_operation.operation_id == "integration.issue.query"
    assert query_operation.state == OperationState.QUEUED
    assert dispatcher.run_once("worker-test", now=claim_time + timedelta(seconds=4)).state == (
        JobState.AWAITING_AUTHORITY.value
    )
    query_operation = store.get_operation(TEST_ACTOR, query_operation.id)
    result = dispatcher.execute_authorized_action(
        TEST_ACTOR,
        query_operation.id,
        binding_id=query_operation.binding_id,
        execution_operation_id=query_operation.execution_operation_id,
        argument_digest=query_operation.argument_digest,
        authority_invocation_id=query_operation.authority_invocation_id,
        authority_evidence=_proof(query_operation),
    )

    assert result.state == OperationState.SUCCEEDED
    assert store.get_operation(TEST_ACTOR, original.id).state == OperationState.SUCCEEDED
    assert store.list_jobs(creator_for_store(), state=JobState.SUCCEEDED)
    store.close()


def creator_for_store() -> IntegrationPrincipal:
    """Return the synthetic owner with read permission for assertions."""

    return IntegrationPrincipal(
        issuer=TEST_ACTOR.issuer,
        subject=TEST_ACTOR.subject,
        organization_id=TEST_ACTOR.organization_id,
        workspace_id=TEST_ACTOR.workspace_id,
        allowed_operation_ids=frozenset({"integrationListJobs"}),
    )


def _proof(operation) -> ValidatedExecutionProof:
    """Build a test-only projection of the already validated Authority envelope."""

    paths = {
        "integrationExecuteIssueComment": "execute-issue-comment",
        "integrationExecuteIssueState": "execute-issue-state",
        "integrationExecuteIssueQuery": "execute-issue-query",
    }
    raw_body = json.dumps(
        {
            "operationId": str(operation.id),
            "argumentDigest": operation.argument_digest,
        },
        separators=(",", ":"),
    ).encode()
    return ValidatedExecutionProof(
        invocation_id=operation.authority_invocation_id,
        owner="exchange",
        issuer=operation.actor_issuer,
        subject=operation.actor_subject,
        organization_id=operation.organization_id,
        workspace_id=operation.workspace_id,
        http_method="POST",
        path=(
            f"/api/v1/integrations/sync-bindings/{operation.binding_id}/"
            f"{paths[operation.execution_operation_id]}"
        ),
        content_type="application/json",
        idempotency_key=operation.authority_idempotency_key,
        execution_operation_id=operation.execution_operation_id,
        operation_id=str(operation.id),
        binding_id=str(operation.binding_id),
        argument_digest=operation.argument_digest,
        raw_body=raw_body,
        raw_body_sha256=hashlib.sha256(raw_body).hexdigest(),
    )
