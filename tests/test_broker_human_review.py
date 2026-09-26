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
    RequestStatus,
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

    assert second.resolved is False
    assert second.grant is None
    # only one grant was ever issued, not two
    assert len(connector.issued) == 1
    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert events.count(AuditEventType.HUMAN_APPROVED) == 1


def test_resolve_approval_unknown_token_is_not_resolved(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )

    resolution = broker.resolve_approval("never-issued", approve=True, decided_by="bob")

    assert resolution == ApprovalResolution(resolved=False, grant=None, reason="unknown approval token")


def test_second_resolve_reports_the_approval_is_already_decided(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)
    broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    second = broker.resolve_approval(pending.approval_token, approve=True, decided_by="carol")

    assert second.resolved is False
    assert "already approved" in second.reason


# -- T9b hardening: deadline enforced at click time, self-approval rejected -- #


def test_approving_after_the_deadline_times_out_instead_of_granting(tmp_path):
    """Closes the fail-open window between deadline_at passing and the next
    sweep: a stale link clicked before any sweeper has run must NOT approve.
    No sweep is called here on purpose -- resolve_approval enforces it."""
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)
    clock.advance(14400 + 1)

    resolution = broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    assert resolution.resolved is False
    assert resolution.grant is None
    assert "timed_out" in resolution.reason
    assert db.get_pending_approval_by_token(pending.approval_token).status == PendingApprovalStatus.TIMED_OUT
    assert connector.issued == []
    events = [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]
    assert AuditEventType.APPROVAL_TIMEOUT in events
    assert AuditEventType.HUMAN_APPROVED not in events


def test_requester_cannot_approve_their_own_request_but_someone_else_still_can(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)  # requester is "alice"

    self_attempt = broker.resolve_approval(pending.approval_token, approve=True, decided_by="alice")

    assert self_attempt.resolved is False
    assert self_attempt.grant is None
    assert "own request" in self_attempt.reason
    assert connector.issued == []
    # the approval is NOT consumed: it stays PENDING for a different reviewer
    assert db.get_pending_approval_by_token(pending.approval_token).status == PendingApprovalStatus.PENDING
    events = db.get_audit_log(request_id=pending.request_id)
    rejected = [e for e in events if e.event_type == AuditEventType.APPROVAL_REJECTED]
    assert len(rejected) == 1
    assert "self-approval attempt by alice" in rejected[0].detail

    by_bob = broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    assert by_bob.resolved is True
    assert by_bob.grant is not None
    assert by_bob.reason == ""
    assert len(connector.issued) == 1


# -- request.status follows every transition (T9b item D) -- #


def _request_kwargs():
    return dict(requester="alice", resource="prod-db", access_level="admin", duration_seconds=3600, reason="need it")


def test_auto_approved_request_status(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.AUTO_APPROVE, "fine"))

    grant = broker.request_access(**_request_kwargs())

    assert db.get_request(grant.request_id).status == RequestStatus.AUTO_APPROVED


def test_denied_request_status(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.DENY, "not allowed"))

    with pytest.raises(AccessDeniedError):
        broker.request_access(**_request_kwargs())

    assert db.get_request(1).status == RequestStatus.DENIED


def test_routed_request_status_is_pending_human(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))

    pending = _route_to_human_and_get_token(broker)

    assert db.get_request(pending.request_id).status == RequestStatus.PENDING_HUMAN


def test_human_approved_request_status(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    pending = _route_to_human_and_get_token(broker)

    broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    assert db.get_request(pending.request_id).status == RequestStatus.HUMAN_APPROVED


def test_human_denied_request_status(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    pending = _route_to_human_and_get_token(broker)

    broker.resolve_approval(pending.approval_token, approve=False, decided_by="bob")

    assert db.get_request(pending.request_id).status == RequestStatus.HUMAN_DENIED


def test_timed_out_request_status(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    pending = _route_to_human_and_get_token(broker)
    clock.advance(14400 + 1)

    broker.sweep_pending_timeouts()

    assert db.get_request(pending.request_id).status == RequestStatus.TIMED_OUT


def test_self_approval_attempt_leaves_request_status_pending_human(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    pending = _route_to_human_and_get_token(broker)

    broker.resolve_approval(pending.approval_token, approve=True, decided_by="alice")

    assert db.get_request(pending.request_id).status == RequestStatus.PENDING_HUMAN


# -- reconcile: one call that runs both sweeps (boot + periodic) -- #


def test_reconcile_reports_expired_grants_and_timed_out_approvals(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    # two distinct pending reviews (different access levels, so not duplicates)
    with pytest.raises(PendingHumanReviewError) as first:
        broker.request_access(requester="alice", resource="prod-db", access_level="read", duration_seconds=60, reason="need it")
    with pytest.raises(PendingHumanReviewError) as second:
        broker.request_access(requester="alice", resource="prod-db", access_level="admin", duration_seconds=60, reason="need it")
    # one becomes a 60s grant, the other stays pending
    approved = broker.resolve_approval(first.value.pending_approval.approval_token, approve=True, decided_by="bob")
    assert approved.resolved is True

    clock.advance(14400 + 1)
    result = broker.reconcile()

    assert result == (1, 1)
    assert connector.revoked == [(approved.grant.resource, approved.grant.access_level, approved.grant.token)]
    assert db.get_pending_approval_by_token(second.value.pending_approval.approval_token).status == PendingApprovalStatus.TIMED_OUT
    # nothing left to do on the next pass
    assert broker.reconcile() == (0, 0)


def test_self_approval_check_ignores_surrounding_whitespace(tmp_path):
    broker, clock, connector, db = make_broker(
        tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")
    )
    pending = _route_to_human_and_get_token(broker)

    resolution = broker.resolve_approval(pending.approval_token, approve=True, decided_by=" alice ")

    assert resolution.resolved is False
    assert "own request" in resolution.reason
    assert connector.issued == []
    assert db.get_pending_approval_by_token(pending.approval_token).status == PendingApprovalStatus.PENDING


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
