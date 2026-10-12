"""Persistence invariants for the Product integration store. | 集成存储持久化约束测试。"""

from datetime import UTC, datetime, timedelta

import pytest

from cyrene_exchange_product.integrations.models import (
    CreateActorBinding,
    CreateIntegrationConnection,
    CreateSyncBinding,
    EnqueueIssueAction,
    IntegrationAuthorizationError,
    IntegrationConflict,
    IntegrationConnection,
    IntegrationNotFound,
    IntegrationPrincipal,
    JobState,
    NormalizedGitHubEvent,
    OperationAudit,
    OutboxJob,
    WeComEventState,
)
from cyrene_exchange_product.integrations.store import IntegrationStore


def principal(
    *, workspace_id: str = "workspace-a", subject: str = "actor-1"
) -> IntegrationPrincipal:
    """Return trusted synthetic authorizer output for tests only."""

    return IntegrationPrincipal(
        issuer="https://identity.example.test",
        subject=subject,
        organization_id="org-1",
        workspace_id=workspace_id,
        allowed_operation_ids=frozenset(
            {
                "integrationCreateConnection",
                "integrationListConnections",
                "integrationCreateBinding",
                "integrationListBindings",
                "integrationAttachActorBinding",
                "integrationListActorBindings",
                "integration.issue.close",
                "integration.issue.reopen",
                "integration.issue.query",
                "integration.issue.comment",
                "integrationGetOperation",
                "integrationListJobs",
            }
        ),
    )


def make_connection(
    store: IntegrationStore,
) -> tuple[IntegrationPrincipal, IntegrationConnection]:
    """Create a synthetic GitHub connection used by persistence cases."""

    actor = principal()
    connection = store.create_connection(
        actor,
        CreateIntegrationConnection(
            repository_id="repo-42",
            repository_name="acme/example",
        ),
        idempotency_key="connection:1",
    )
    return actor, connection


def make_binding(
    store: IntegrationStore,
    actor: IntegrationPrincipal,
    connection: IntegrationConnection,
):
    """Create a shared notification binding and this actor's explicit own refs."""

    binding = store.create_binding(
        actor,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="target:opaque-1",
        ),
        idempotency_key=f"binding:{connection.id}",
    )
    store.create_actor_binding(
        actor,
        CreateActorBinding(
            binding_id=binding.id,
            account_link_ref="account-link:actor-1",
            delegation_ref="delegation:actor-1",
        ),
        idempotency_key=f"actor-binding:{actor.subject}",
    )
    return binding


def test_inbox_deduplicates_atomically_and_persists_across_restart(tmp_path) -> None:
    database = tmp_path / "integrations.sqlite3"
    store = IntegrationStore(database)
    actor, connection = make_connection(store)
    store.create_binding(
        actor,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="target:opaque-1",
        ),
        idempotency_key=f"binding:{connection.id}",
    )
    event = NormalizedGitHubEvent(
        event_type="issues",
        action="opened",
        repository_id="repo-42",
        issue_number=17,
        sender_id="user-5",
        sender_login="reporter",
        title="Example defect",
        body="Synthetic event body",
    )

    first = store.ingest_github_event(connection.id, "delivery-1", event, verified=True)
    redelivery = event.model_copy(update={"observed_at": event.observed_at + timedelta(seconds=30)})
    duplicate = store.ingest_github_event(connection.id, "delivery-1", redelivery, verified=True)
    assert duplicate.id == first.id
    jobs = store.list_jobs(actor, state=JobState.READY)
    assert len(jobs) == 1
    store.close()

    restarted = IntegrationStore(database)
    reloaded = restarted.ingest_github_event(connection.id, "delivery-1", event, verified=True)
    assert reloaded.id == first.id
    assert len(restarted.list_jobs(actor, state=JobState.READY)) == 1
    restarted.close()


def test_delivery_id_reuse_with_different_event_is_conflict(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    _, connection = make_connection(store)
    event = NormalizedGitHubEvent(
        event_type="issues",
        action="opened",
        repository_id="repo-42",
        issue_number=17,
        sender_id="user-5",
        sender_login="reporter",
    )
    store.ingest_github_event(connection.id, "delivery-1", event, verified=True)
    changed = event.model_copy(update={"title": "different fingerprint"})
    with pytest.raises(IntegrationConflict):
        store.ingest_github_event(connection.id, "delivery-1", changed, verified=True)
    store.close()


def test_self_authored_event_is_persisted_without_notification_loop(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    actor, connection = make_connection(store)
    store.create_binding(
        actor,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="target:opaque-1",
        ),
        idempotency_key=f"binding:{connection.id}",
    )
    event = NormalizedGitHubEvent(
        event_type="issue_comment",
        action="created",
        repository_id="repo-42",
        issue_number=17,
        sender_id="exchange-app-id",
        sender_login="cyrene-bot",
        self_authored=True,
    )

    stored = store.ingest_github_event(connection.id, "delivery-self", event, verified=True)

    assert stored.self_authored is True
    assert store.list_jobs(actor) == []
    store.close()


def test_wecom_inbox_deduplicates_before_command_admission(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    member = principal(subject="wecom-member")
    connection = store.create_connection(
        principal(),
        CreateIntegrationConnection(
            repository_id="repo-42",
            repository_name="acme/example",
        ),
        idempotency_key="connection:1",
    )
    group = store.create_binding(
        principal(),
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="target:group-1",
        ),
        idempotency_key=f"binding:{connection.id}",
    )
    store.create_actor_binding(
        member,
        CreateActorBinding(
            binding_id=group.id,
            account_link_ref="account-link:wecom-member",
            delegation_ref="delegation:wecom-member",
        ),
        idempotency_key="actor-binding:wecom-member",
    )
    event, created = store.persist_wecom_inbound(
        group.id,
        "vendor-message-9",
        expected_organization_id="org-1",
        expected_workspace_id="workspace-a",
        sender_id="wecom-user-openid-9",
        conversation_ref="wecom-chat-3",
        reply_message_id="canonical-message-9",
        reply_context_ref="original-req-9",
        message_text="/issue comment 17 Please investigate",
        verified=True,
    )
    duplicate, duplicate_created = store.persist_wecom_inbound(
        group.id,
        "vendor-message-9",
        expected_organization_id="org-1",
        expected_workspace_id="workspace-a",
        sender_id="wecom-user-openid-9",
        conversation_ref="wecom-chat-3",
        reply_message_id="canonical-message-9",
        reply_context_ref="original-req-9",
        message_text="/issue comment 17 Please investigate",
        verified=True,
    )
    assert created is True
    assert duplicate_created is False
    assert duplicate.id == event.id

    operation = store.enqueue_issue_command_for_actor(
        binding_id=group.id,
        actor_issuer=member.issuer,
        actor_subject=member.subject,
        organization_id=member.organization_id,
        workspace_id=member.workspace_id,
        source_event_ref=str(event.id),
        source_sender_id=event.sender_id,
        idempotency_key=f"wecom:{event.id}",
        command_text=event.message_text,
    )
    assert operation.operation_id == "integration.issue.comment"
    assert operation.body == "Please investigate"
    assert operation.source_kind == "WECOM_COMMAND"
    assert operation.account_link_ref == "account-link:wecom-member"
    assert operation.reply_binding_ref == str(group.id)
    assert operation.reply_conversation_ref == "wecom-chat-3"
    assert operation.reply_message_id == "canonical-message-9"
    assert operation.reply_context_ref == "original-req-9"
    updated = store.mark_wecom_inbound_processed(
        event.id,
        group.id,
        state=WeComEventState.COMMAND_QUEUED,
        operation_id=operation.id,
    )
    assert updated.state == WeComEventState.COMMAND_QUEUED
    claim = store.claim_job("command-worker", now=datetime.now(UTC), lease_seconds=60)
    assert claim is not None
    store.mark_sending(claim.job.id, claim_fence=claim.claim_fence, now=datetime.now(UTC))
    store.finish_job(
        claim.job.id,
        claim_fence=claim.claim_fence,
        status=JobState.SUCCEEDED,
        evidence={"status": "CONFIRMED", "commentId": "comment-7"},
    )
    with store._lock:
        reply_row = store._connection.execute(
            "SELECT document FROM outbox_jobs WHERE kind='COMMAND_REPLY'"
        ).fetchone()
    assert reply_row is not None
    reply_job = OutboxJob.model_validate_json(str(reply_row["document"]))
    assert reply_job.available_at == reply_job.created_at
    assert '"replyMessageId":"canonical-message-9"' in reply_row["document"]
    assert '"replyContextRef":"original-req-9"' in reply_row["document"]
    assert '"text":"Comment on acme/example#17 was confirmed."' in reply_row["document"]
    store.close()


def test_wecom_link_challenge_is_claimed_once_and_replied_from_outbox(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = store.create_connection(
        principal(),
        CreateIntegrationConnection(repository_id="repo-42", repository_name="acme/example"),
        idempotency_key="connection-link",
    )
    binding = store.create_binding(
        principal(),
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="wecom-bot:source-1",
        ),
        idempotency_key="binding-link",
    )
    event, _ = store.persist_wecom_inbound(
        binding.id,
        "link-event-1",
        expected_organization_id="org-1",
        expected_workspace_id="workspace-a",
        sender_id="wecom-user-1",
        conversation_ref="private-chat-1",
        reply_message_id="canonical-message-1",
        reply_context_ref="callback-req-1",
        message_text="/link private-nonce-never-echoed",
        verified=True,
    )
    assert event.message_text == "/link [redacted]"
    claimed, acquired = store.begin_wecom_challenge_observation(binding.id, str(event.id))
    assert acquired is True
    assert claimed.state == WeComEventState.CHALLENGE_OBSERVING
    queued = store.enqueue_wecom_challenge_reply(binding.id, str(event.id), "challenge-id-7")
    duplicate = store.enqueue_wecom_challenge_reply(binding.id, str(event.id), "challenge-id-7")
    challenge_jobs = [
        job
        for job in store._connection.execute(
            "SELECT document FROM outbox_jobs WHERE kind='CHALLENGE_REPLY'"
        ).fetchall()
    ]
    assert queued.state == WeComEventState.CHALLENGE_REPLY_PENDING
    assert duplicate.id == queued.id
    assert len(challenge_jobs) == 1
    assert "challenge-id-7" in challenge_jobs[0]["document"]
    assert "private-nonce-never-echoed" not in challenge_jobs[0]["document"]
    store.close()


def test_ambiguous_wecom_challenge_observation_is_never_retried_automatically(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    connection = store.create_connection(
        principal(),
        CreateIntegrationConnection(repository_id="repo-42", repository_name="acme/example"),
        idempotency_key="connection-link",
    )
    binding = store.create_binding(
        principal(),
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="wecom-bot:source-1",
        ),
        idempotency_key="binding-link",
    )
    event, _ = store.persist_wecom_inbound(
        binding.id,
        "link-event-2",
        expected_organization_id="org-1",
        expected_workspace_id="workspace-a",
        sender_id="wecom-user-1",
        conversation_ref="private-chat-1",
        reply_message_id="canonical-message-2",
        reply_context_ref="callback-req-2",
        message_text="/link another-nonce",
        verified=True,
    )
    _, acquired = store.begin_wecom_challenge_observation(binding.id, str(event.id))
    assert acquired
    unknown = store.mark_wecom_challenge_unknown(binding.id, str(event.id))
    replay, acquired_again = store.begin_wecom_challenge_observation(binding.id, str(event.id))
    assert replay.state == WeComEventState.CHALLENGE_UNKNOWN
    assert not acquired_again
    assert unknown.state == WeComEventState.CHALLENGE_UNKNOWN
    store.close()


def test_idempotency_key_reuses_same_operation_and_rejects_changed_body(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    actor, connection = make_connection(store)
    binding = make_binding(store, actor, connection)
    request = EnqueueIssueAction(
        connection_id=connection.id,
        binding_id=binding.id,
        operation_id="integration.issue.comment",
        idempotency_key="client-key-1",
        issue_number=17,
        body="Please investigate",
    )
    first = store.enqueue_issue_action(actor, request)
    repeated = store.enqueue_issue_action(actor, request)
    assert repeated.id == first.id
    assert len(store.list_jobs(actor, state=JobState.READY)) == 1
    with pytest.raises(IntegrationConflict):
        store.enqueue_issue_action(actor, request.model_copy(update={"body": "Changed"}))
    store.close()


def test_public_resource_creates_use_persistent_body_scoped_idempotency(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    actor = principal()
    connection_request = CreateIntegrationConnection(
        repository_id="repo-42",
        repository_name="acme/example",
    )
    connection = store.create_connection(
        actor, connection_request, idempotency_key="connection-key-1"
    )
    replayed_connection = store.create_connection(
        actor, connection_request, idempotency_key="connection-key-1"
    )
    assert replayed_connection.id == connection.id
    with pytest.raises(IntegrationConflict):
        store.create_connection(
            actor,
            connection_request.model_copy(update={"repository_name": "acme/other"}),
            idempotency_key="connection-key-1",
        )

    binding_request = CreateSyncBinding(
        connection_id=connection.id,
        notification_target_ref="target:group-a",
    )
    binding = store.create_binding(actor, binding_request, idempotency_key="binding-key-1")
    assert (
        store.create_binding(actor, binding_request, idempotency_key="binding-key-1").id
        == binding.id
    )
    with pytest.raises(IntegrationConflict):
        store.create_binding(
            actor,
            binding_request.model_copy(update={"notification_target_ref": "target:group-b"}),
            idempotency_key="binding-key-1",
        )

    actor_binding_request = CreateActorBinding(
        binding_id=binding.id,
        account_link_ref="account-link:actor-1",
        delegation_ref="delegation:actor-1",
    )
    actor_binding = store.create_actor_binding(
        actor, actor_binding_request, idempotency_key="actor-binding-key-1"
    )
    assert (
        store.create_actor_binding(
            actor, actor_binding_request, idempotency_key="actor-binding-key-1"
        ).id
        == actor_binding.id
    )
    with pytest.raises(IntegrationConflict):
        store.create_actor_binding(
            actor,
            actor_binding_request.model_copy(update={"account_link_ref": "account-link-other"}),
            idempotency_key="actor-binding-key-1",
        )
    store.close()


def test_member_issue_action_uses_only_that_members_actor_binding(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    creator, connection = make_connection(store)
    binding = store.create_binding(
        creator,
        CreateSyncBinding(
            connection_id=connection.id,
            notification_target_ref="target:group-1",
        ),
        idempotency_key=f"binding:{connection.id}",
    )
    member = principal(subject="member-2")
    store.create_actor_binding(
        member,
        CreateActorBinding(
            binding_id=binding.id,
            account_link_ref="account-link:member-2",
            delegation_ref="delegation:member-2",
        ),
        idempotency_key="actor-binding:member-2",
    )
    request = EnqueueIssueAction(
        connection_id=connection.id,
        binding_id=binding.id,
        operation_id="integration.issue.close",
        idempotency_key="close-member-2",
        issue_number=17,
    )

    operation = store.enqueue_issue_action(member, request)

    assert operation.actor_subject == "member-2"
    assert operation.account_link_ref == "account-link:member-2"
    assert operation.delegation_ref == "delegation:member-2"
    assert store.list_actor_bindings(member, binding.id)[0].account_link_ref == (
        "account-link:member-2"
    )
    assert store.list_actor_bindings(creator, binding.id) == []
    outsider = principal(subject="outsider-3")
    with pytest.raises(IntegrationNotFound):
        store.enqueue_issue_action(
            outsider,
            request.model_copy(update={"idempotency_key": "close-outsider"}),
        )
    store.close()


def test_sending_crash_becomes_unknown_and_is_never_claimed_again(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    actor, connection = make_connection(store)
    binding = make_binding(store, actor, connection)
    operation = store.enqueue_issue_action(
        actor,
        EnqueueIssueAction(
            connection_id=connection.id,
            binding_id=binding.id,
            operation_id="integration.issue.comment",
            idempotency_key="comment-1",
            issue_number=9,
            body="Synthetic write",
        ),
    )
    now = datetime.now(UTC)
    claim = store.claim_job("worker-a", now=now, lease_seconds=2)
    assert claim is not None
    sending = store.mark_sending(claim.job.id, claim_fence=claim.claim_fence, now=now)
    assert sending.state == JobState.SENDING
    assert store.recover_expired_claims(now=now + timedelta(seconds=3)) == 1
    assert store.claim_job("worker-b", now=now + timedelta(seconds=4), lease_seconds=2) is None
    with pytest.raises(IntegrationConflict):
        store.mark_sending(claim.job.id, claim_fence=claim.claim_fence, now=now)
    assert store.get_operation(actor, operation.id).state.value == "UNKNOWN"
    assert [job.state for job in store.list_jobs(actor)] == [JobState.UNKNOWN]
    store.close()


def test_expired_readonly_query_claim_is_retried_with_backoff(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    actor, connection = make_connection(store)
    binding = make_binding(store, actor, connection)
    store.enqueue_issue_action(
        actor,
        EnqueueIssueAction(
            connection_id=connection.id,
            binding_id=binding.id,
            operation_id="integration.issue.query",
            idempotency_key="query-retry-1",
            issue_number=9,
        ),
    )
    now = datetime.now(UTC)
    claim = store.claim_job("worker-a", now=now, lease_seconds=2)
    assert claim is not None
    store.mark_sending(claim.job.id, claim_fence=claim.claim_fence, now=now)
    assert store.recover_expired_claims(now=now + timedelta(seconds=3)) == 1
    retried = store.list_jobs(actor, state=JobState.READY)
    assert len(retried) == 1
    assert retried[0].attempts == 1
    assert retried[0].available_at == now + timedelta(seconds=4)
    store.close()


def test_verified_event_from_another_repository_is_rejected(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    _, connection = make_connection(store)
    event = NormalizedGitHubEvent(
        event_type="issues",
        action="opened",
        repository_id="different-repo",
        issue_number=1,
        sender_id="sender-1",
        sender_login="sender",
    )
    with pytest.raises(IntegrationAuthorizationError):
        store.ingest_github_event(connection.id, "delivery-2", event, verified=True)
    store.close()


def test_audit_rows_are_persisted_without_external_identity_or_token_fields(tmp_path) -> None:
    store = IntegrationStore(tmp_path / "integrations.sqlite3")
    record = OperationAudit(
        organization_id="org-1",
        workspace_id="workspace-a",
        actor_issuer="https://identity.example.test",
        actor_subject="actor-1",
        resource_type="integration.operation",
        resource_id="operation-1",
        action="create",
        outcome="SUCCEEDED",
        metadata={"operationId": "integration.issue.query"},
    )
    store.add_audit(record)
    with store._lock:
        row = store._connection.execute(
            "SELECT document FROM operation_audits WHERE id=?", (str(record.id),)
        ).fetchone()
    assert row is not None
    assert "access_token" not in row["document"]
    assert "authorization" not in row["document"].lower()
    store.close()
