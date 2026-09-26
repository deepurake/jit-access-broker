"""
Evals for duplicate-request rejection: a second request for the same
(requester, resource, access_level) while an earlier one is still live --
an ACTIVE grant or a PENDING human review -- is refused and points at the
existing one. The duplicate is still recorded (every request must appear in
the audit log) but never reaches the policy engine, which a counting fake
PolicyEngine proves.
"""
import pytest

from broker.broker import Broker
from broker.clock import FakeClock
from broker.connector import MockConnector
from broker.db import Database
from broker.models import (
    AuditEventType,
    DuplicateRequestError,
    PendingHumanReviewError,
    PolicyDecision,
    PolicyDecisionType,
    RequestStatus,
)
from broker.policy import PolicyEngine


class CountingPolicyEngine(PolicyEngine):
    """Returns a fixed decision and counts how often it was asked -- the
    assertion that matters here is that duplicates never reach it."""

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        self.calls = 0

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        self.calls += 1
        return self.decision


APPROVE = PolicyDecision(PolicyDecisionType.AUTO_APPROVE, "fine")
ROUTE_HUMAN = PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")


def make_broker(db_path, decision):
    clock = FakeClock()
    connector = MockConnector()
    db = Database(str(db_path))
    policy = CountingPolicyEngine(decision)
    broker = Broker(db=db, clock=clock, policy=policy, connector=connector)
    return broker, clock, connector, db, policy


def request(broker, requester="alice", resource="prod-db", access_level="read", duration_seconds=3600):
    return broker.request_access(
        requester=requester,
        resource=resource,
        access_level=access_level,
        duration_seconds=duration_seconds,
        reason="debugging incident 123",
    )


def test_second_identical_request_while_grant_active_is_rejected_and_never_reaches_policy(tmp_path):
    broker, clock, connector, db, policy = make_broker(tmp_path / "broker.db", APPROVE)
    first = request(broker)

    with pytest.raises(DuplicateRequestError) as exc_info:
        request(broker)

    assert exc_info.value.existing_grant.id == first.id
    assert exc_info.value.existing_pending is None
    assert "active grant exists" in str(exc_info.value)
    assert len(connector.issued) == 1
    assert policy.calls == 1

    # the duplicate is still a recorded request with its own audit trail
    duplicate_request_id = first.request_id + 1
    assert db.get_request(duplicate_request_id).status == RequestStatus.DUPLICATE
    events = db.get_audit_log(request_id=duplicate_request_id)
    assert [e.event_type for e in events] == [AuditEventType.REQUESTED, AuditEventType.DUPLICATE_REJECTED]
    assert f"duplicate of grant {first.id}" in events[1].detail


def test_identical_request_is_allowed_again_once_the_grant_has_expired_without_a_sweep(tmp_path):
    broker, clock, connector, db, policy = make_broker(tmp_path / "broker.db", APPROVE)
    first = request(broker, duration_seconds=60)
    clock.advance(61)

    second = request(broker, duration_seconds=60)

    assert second.id != first.id
    assert policy.calls == 2


def test_identical_request_is_allowed_again_once_the_grant_is_revoked(tmp_path):
    broker, clock, connector, db, policy = make_broker(tmp_path / "broker.db", APPROVE)
    first = request(broker)
    broker.revoke(first.id, revoked_by="security-team")

    second = request(broker)

    assert second.id != first.id
    assert policy.calls == 2


def test_different_access_level_on_the_same_resource_is_not_a_duplicate(tmp_path):
    broker, clock, connector, db, policy = make_broker(tmp_path / "broker.db", APPROVE)
    request(broker, access_level="read")

    write_grant = request(broker, access_level="write")

    assert write_grant.access_level == "write"
    assert policy.calls == 2


def test_different_requester_for_the_same_access_is_not_a_duplicate(tmp_path):
    broker, clock, connector, db, policy = make_broker(tmp_path / "broker.db", APPROVE)
    request(broker, requester="alice")

    bob_grant = request(broker, requester="bob")

    assert bob_grant.requester == "bob"
    assert policy.calls == 2


def test_second_identical_request_while_human_review_pending_points_at_the_pending_approval(tmp_path):
    broker, clock, connector, db, policy = make_broker(tmp_path / "broker.db", ROUTE_HUMAN)
    with pytest.raises(PendingHumanReviewError) as first:
        request(broker, access_level="admin")
    pending = first.value.pending_approval

    with pytest.raises(DuplicateRequestError) as exc_info:
        request(broker, access_level="admin")

    assert exc_info.value.existing_grant is None
    assert exc_info.value.existing_pending.approval_token == pending.approval_token
    assert "pending approval exists" in str(exc_info.value)
    assert policy.calls == 1
    duplicate_events = db.get_audit_log(request_id=pending.request_id + 1)
    assert duplicate_events[-1].event_type == AuditEventType.DUPLICATE_REJECTED
    assert f"duplicate of pending approval for request {pending.request_id}" in duplicate_events[-1].detail

    # once the reviewer denies it, the same access can be asked for again
    broker.resolve_approval(pending.approval_token, approve=False, decided_by="bob")
    with pytest.raises(PendingHumanReviewError):
        request(broker, access_level="admin")
    assert policy.calls == 2
