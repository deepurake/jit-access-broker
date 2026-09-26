"""
Evals for the human-in-the-loop review path: Broker.request_access routing
to a pending approval instead of auto-granting, Broker.resolve_approval
deciding it, and Broker.sweep_pending_timeouts auto-denying stale ones.

DecisionRouter (the real PolicyEngine that produces ROUTE_HUMAN) is a
separate parallel task, so these tests drive the policy seam with a tiny
hand-written fake instead of depending on it.
"""
import pytest

from broker.broker import Broker
from broker.clock import FakeClock
from broker.connector import MockConnector
from broker.db import Database
from broker.models import (
    AccessDeniedError,
    ApprovalResolution,
    AuditEventType,
    PendingApprovalStatus,
    PendingHumanReviewError,
    PolicyDecision,
    PolicyDecisionType,
)
from broker.policy import PolicyEngine


class FixedPolicyEngine(PolicyEngine):
    def __init__(self, decision: PolicyDecision):
        self.decision = decision

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        return self.decision


def make_broker(db_path, decision, clock=None, connector=None):
    clock = clock or FakeClock()
    connector = connector or MockConnector()
    db = Database(str(db_path))
    broker = Broker(db=db, clock=clock, policy=FixedPolicyEngine(decision), connector=connector)
    return broker, clock, connector, db


def test_request_access_routes_to_human_raises_pending_review_error(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )

    with pytest.raises(PendingHumanReviewError) as exc_info:
        broker.request_access(
            requester="alice",
            resource="prod-db",
            access_level="admin",
            duration_seconds=3600,
            reason="need it",
        )

    pending = exc_info.value.pending_approval
    assert isinstance(pending.approval_token, str) and len(pending.approval_token) > 0

    fetched = db.get_pending_approval_by_token(pending.approval_token)
    assert fetched.status == PendingApprovalStatus.PENDING
    assert fetched.request_id == pending.request_id
    assert fetched.deadline_at == fetched.created_at + 14400


def test_request_access_still_raises_access_denied_for_deny_decision(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.DENY, "not allowed")
    )

    with pytest.raises(AccessDeniedError):
        broker.request_access(
            requester="bob",
            resource="prod-db",
            access_level="admin",
            duration_seconds=3600,
            reason="need it",
        )


def _route_to_human_and_get_token(broker):
    with pytest.raises(PendingHumanReviewError) as exc_info:
        broker.request_access(
            requester="alice",
            resource="prod-db",
            access_level="admin",
            duration_seconds=3600,
            reason="need it",
        )
    return exc_info.value.pending_approval


def test_resolve_approval_approve_issues_active_grant(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)

    resolution = broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    assert resolution.resolved is True
    assert resolution.grant is not None
    assert broker.is_active(resolution.grant.id) is True
    assert len(connector.issued) == 1

    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert AuditEventType.HUMAN_APPROVED in events


def test_resolve_approval_deny_creates_no_grant(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)

    resolution = broker.resolve_approval(pending.approval_token, approve=False, decided_by="bob")

    assert resolution == ApprovalResolution(resolved=True, grant=None)
    assert connector.issued == []

    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert AuditEventType.HUMAN_DENIED in events


def test_resolving_the_same_token_twice_is_a_noop_the_second_time(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)

    first = broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")
    assert first.resolved is True

    second = broker.resolve_approval(pending.approval_token, approve=True, decided_by="carol")

    assert second == ApprovalResolution(resolved=False, grant=None)
    # only one grant was ever issued, not two
    assert len(connector.issued) == 1
    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert events.count(AuditEventType.HUMAN_APPROVED) == 1


def test_resolve_approval_unknown_token_is_not_resolved(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )

    resolution = broker.resolve_approval("never-issued", approve=True, decided_by="bob")

    assert resolution == ApprovalResolution(resolved=False, grant=None)


def test_sweep_pending_timeouts_auto_denies_stale_approvals(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)

    clock.advance(14400 + 1)

    count = broker.sweep_pending_timeouts()

    assert count == 1
    fetched = db.get_pending_approval_by_token(pending.approval_token)
    assert fetched.status == PendingApprovalStatus.TIMED_OUT
    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert AuditEventType.APPROVAL_TIMEOUT in events


def test_sweep_pending_timeouts_does_not_touch_already_resolved_approvals(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)
    broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    clock.advance(14400 + 1)
    count = broker.sweep_pending_timeouts()

    assert count == 0
    fetched = db.get_pending_approval_by_token(pending.approval_token)
    assert fetched.status == PendingApprovalStatus.APPROVED
    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert AuditEventType.APPROVAL_TIMEOUT not in events
