"""
Evals for the human-in-the-loop review path: Broker.request_access routing
to a pending approval instead of auto-granting, Broker.resolve_approval
deciding it, and Broker.sweep_pending_timeouts auto-denying stale ones.

PolicyEngine (the real PolicyEngine that produces ROUTE_HUMAN) is a
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
    ReturnedToRequesterError,
)
from broker.policy import Policy


class FixedPolicy(Policy):
    def __init__(self, decision: PolicyDecision):
        self.decision = decision

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        return self.decision


def make_broker(db_path, decision, clock=None, connector=None):
    clock = clock or FakeClock()
    connector = connector or MockConnector()
    db = Database(str(db_path))
    broker = Broker(db=db, clock=clock, policy=FixedPolicy(decision), connector=connector)
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
    rejected = [e for e in events if e.event_type == AuditEventType.SELF_APPROVAL_BLOCKED]
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


# -- T9f: return-to-requester and escalation -- #
#
# An insufficient reason goes back to the requester, not to an approver. The
# request is RETURNED (terminal for the policy) and the requester may either
# resubmit with a better reason or escalate the same request to a human.


RETURNED_DECISION = PolicyDecision(PolicyDecisionType.RETURN_TO_REQUESTER, "reason is missing or a placeholder -- say what you need to do and why")


class SequencePolicyEngine(Policy):
    """Returns the next decision on each call, so one test can drive a
    RETURNED request followed by a resubmission that is decided differently."""

    def __init__(self, *decisions: PolicyDecision):
        self.decisions = list(decisions)
        self.calls = 0

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        self.calls += 1
        return self.decisions.pop(0)


def _return_to_requester(broker, reason="idk"):
    with pytest.raises(ReturnedToRequesterError) as exc_info:
        broker.request_access(requester="alice", resource="prod-db", access_level="admin", duration_seconds=3600, reason=reason)
    return exc_info.value


def test_return_to_requester_sets_returned_status_and_audits_with_hint(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", RETURNED_DECISION)

    err = _return_to_requester(broker)

    assert err.request_id == 1
    assert err.decision is RETURNED_DECISION
    assert str(err) == RETURNED_DECISION.reason
    assert "resubmit" in err.hint and "escalate" in err.hint
    assert db.get_request(1).status == RequestStatus.RETURNED
    # nothing was granted and no approver was involved
    assert connector.issued == []
    assert db.find_pending_approval("alice", "prod-db", "admin") is None

    events = db.get_audit_log(request_id=1)
    assert [e.event_type for e in events] == [AuditEventType.REQUESTED, AuditEventType.POLICY_DECIDED, AuditEventType.RETURNED_TO_REQUESTER]
    assert events[-1].detail == f"{RETURNED_DECISION.reason}; hint: {err.hint}"


def test_return_to_requester_keeps_the_triaged_audit_when_triage_ran(tmp_path):
    decision = PolicyDecision(
        PolicyDecisionType.RETURN_TO_REQUESTER,
        "reason does not justify admin access: it describes no change to make",
        triage_recommendation="DENY",
        triage_confidence="LOW",
        triage_risk_flag=True,
        triage_justification="reason does not justify admin access: it describes no change to make",
    )
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", decision)

    _return_to_requester(broker, reason="I want to look at the dashboards for a while")

    events = [e.event_type for e in db.get_audit_log(request_id=1)]
    assert events == [
        AuditEventType.REQUESTED,
        AuditEventType.TRIAGED,
        AuditEventType.POLICY_DECIDED,
        AuditEventType.RETURNED_TO_REQUESTER,
    ]


def test_resubmitting_after_a_return_is_not_a_duplicate(tmp_path):
    policy = SequencePolicyEngine(RETURNED_DECISION, PolicyDecision(PolicyDecisionType.AUTO_APPROVE, "fine"))
    db = Database(str(tmp_path / "broker.db"))
    broker = Broker(db=db, clock=FakeClock(), policy=policy, connector=MockConnector())
    _return_to_requester(broker)

    grant = broker.request_access(requester="alice", resource="prod-db", access_level="admin", duration_seconds=3600, reason="rotating leaked credentials after incident 4711")

    assert grant.request_id == 2
    assert policy.calls == 2  # the resubmission reached the policy: RETURNED is neither ACTIVE nor PENDING
    assert db.get_request(1).status == RequestStatus.RETURNED
    assert db.get_request(2).status == RequestStatus.AUTO_APPROVED


def test_escalate_returned_request_creates_pending_approval_and_audits(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", RETURNED_DECISION)
    _return_to_requester(broker)

    pending = broker.escalate(1, note="on-call, checking replication lag, ticket OPS-77", requested_by="alice")

    assert pending is not None
    assert pending.request_id == 1
    assert pending.status == PendingApprovalStatus.PENDING
    assert pending.deadline_at == pending.created_at + 14400
    assert db.get_pending_approval_by_token(pending.approval_token).status == PendingApprovalStatus.PENDING
    assert db.get_request(1).status == RequestStatus.PENDING_HUMAN

    events = db.get_audit_log(request_id=1)
    assert [e.event_type for e in events] == [
        AuditEventType.REQUESTED,
        AuditEventType.POLICY_DECIDED,
        AuditEventType.RETURNED_TO_REQUESTER,
        AuditEventType.ESCALATED,
        AuditEventType.ROUTED_TO_HUMAN,
    ]
    assert events[3].detail == "escalated by alice: on-call, checking replication lag, ticket OPS-77"
    assert events[4].detail == f"escalated by requester; AI returned it because: {RETURNED_DECISION.reason}"


def test_escalate_by_someone_other_than_the_requester_returns_none(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", RETURNED_DECISION)
    _return_to_requester(broker)

    assert broker.escalate(1, note="please", requested_by="mallory") is None
    assert db.get_request(1).status == RequestStatus.RETURNED
    assert db.find_pending_approval("alice", "prod-db", "admin") is None
    assert AuditEventType.ESCALATED not in [e.event_type for e in db.get_audit_log(request_id=1)]


def test_escalate_twice_returns_none_the_second_time(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", RETURNED_DECISION)
    _return_to_requester(broker)
    first = broker.escalate(1, note="first", requested_by="alice")
    assert first is not None

    second = broker.escalate(1, note="second", requested_by="alice")

    assert second is None
    events = [e.event_type for e in db.get_audit_log(request_id=1)]
    assert events.count(AuditEventType.ESCALATED) == 1
    assert events.count(AuditEventType.ROUTED_TO_HUMAN) == 1


def test_escalate_unknown_request_returns_none(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", RETURNED_DECISION)

    assert broker.escalate(42, note="?", requested_by="alice") is None


def test_escalate_a_request_already_pending_human_returns_none(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    pending = _route_to_human_and_get_token(broker)

    assert broker.escalate(pending.request_id, note="hurry", requested_by="alice") is None
    assert db.get_request(pending.request_id).status == RequestStatus.PENDING_HUMAN
    assert AuditEventType.ESCALATED not in [e.event_type for e in db.get_audit_log(request_id=pending.request_id)]


def test_escalate_an_auto_approved_request_returns_none(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.AUTO_APPROVE, "fine"))
    grant = broker.request_access(**_request_kwargs())

    assert broker.escalate(grant.request_id, note="?", requested_by="alice") is None
    assert db.get_request(grant.request_id).status == RequestStatus.AUTO_APPROVED


# -- T9d/T9e: triage step details, least-privilege suggestion and requester
# history in the audit trail. The TRIAGED line keeps its existing prefix
# (`REC confidence=X risk_flag=Y: justification`) and gains optional
# ` | steps: ...` and ` | history: ...` segments; ROUTED_TO_HUMAN gains an
# optional ` | suggested minimum: level/durations` suffix the approval page
# renders as the least-privilege alternative.


def _triaged_detail(db, request_id=1):
    events = [e for e in db.get_audit_log(request_id=request_id) if e.event_type == AuditEventType.TRIAGED]
    assert len(events) == 1
    return events[0].detail


def _routed_detail(db, request_id=1):
    events = [e for e in db.get_audit_log(request_id=request_id) if e.event_type == AuditEventType.ROUTED_TO_HUMAN]
    assert len(events) == 1
    return events[0].detail


def test_triaged_detail_appends_steps_and_history_segments_when_present(tmp_path):
    decision = PolicyDecision(
        PolicyDecisionType.ROUTE_HUMAN,
        "needs review",
        triage_recommendation="APPROVE",
        triage_confidence="MEDIUM",
        triage_risk_flag=True,
        triage_justification="reason is present but over-scoped",
        triage_steps_summary="reason_validation=pass; scope_proportionality=fail (too long)",
        history_summary="requester=alice total_requests=1 approved_grants=0",
    )
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", decision)
    _route_to_human_and_get_token(broker)

    assert _triaged_detail(db) == (
        "APPROVE confidence=MEDIUM risk_flag=True: reason is present but over-scoped"
        " | steps: reason_validation=pass; scope_proportionality=fail (too long)"
        " | history: requester=alice total_requests=1 approved_grants=0"
    )


def test_triaged_detail_omits_segments_that_are_not_set(tmp_path):
    decision = PolicyDecision(
        PolicyDecisionType.AUTO_APPROVE,
        "fine",
        triage_recommendation="APPROVE",
        triage_confidence="HIGH",
        triage_risk_flag=False,
        triage_justification="fine",
    )
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", decision)
    broker.request_access(**_request_kwargs())

    assert _triaged_detail(db) == "APPROVE confidence=HIGH risk_flag=False: fine"


def test_routed_to_human_detail_appends_suggested_minimum_when_triage_suggested_one(tmp_path):
    decision = PolicyDecision(
        PolicyDecisionType.ROUTE_HUMAN,
        "needs review",
        triage_recommendation="APPROVE",
        triage_confidence="MEDIUM",
        triage_risk_flag=True,
        triage_justification="over-scoped",
        suggested_access_level="write",
        suggested_duration_seconds=3600,
    )
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", decision)
    _route_to_human_and_get_token(broker)

    assert _routed_detail(db) == "needs review | suggested minimum: write/3600s"


def test_routed_to_human_detail_fills_the_missing_half_of_a_partial_suggestion_from_the_request(tmp_path):
    # Only a shorter duration was suggested: the level stays what was asked for.
    decision = PolicyDecision(
        PolicyDecisionType.ROUTE_HUMAN,
        "needs review",
        triage_recommendation="APPROVE",
        triage_confidence="MEDIUM",
        triage_risk_flag=True,
        triage_justification="too long",
        suggested_duration_seconds=28800,
    )
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", decision)
    _route_to_human_and_get_token(broker)  # asks for admin

    assert _routed_detail(db) == "needs review | suggested minimum: admin/28800s"


def test_routed_to_human_detail_has_no_suffix_without_a_suggestion(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review"))
    _route_to_human_and_get_token(broker)

    assert _routed_detail(db) == "needs review"


def test_real_engine_over_scoped_admin_request_audits_step_details_and_suggested_minimum(tmp_path):
    """The real pipeline (ACL -> MockTriageProvider -> PolicyEngine) for the
    oncall admin/7200 case: step 2 fails, so the TRIAGED line shows which
    step objected and ROUTED_TO_HUMAN carries the least-privilege alternative."""
    from broker.acl_policy import AclPolicyEngine
    from broker.llm_decision_agent import MockTriageProvider
    from broker.policy_engine import PolicyEngine
    from broker.user_directory import DatabaseUserDirectory

    db = Database(str(tmp_path / "broker.db"))
    db.load_acl_rules([{"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200}])
    db.set_user_role("alice", "oncall")
    policy = PolicyEngine(DatabaseUserDirectory(db), AclPolicyEngine(db), MockTriageProvider())
    broker = Broker(db=db, clock=FakeClock(), policy=policy, connector=MockConnector())

    with pytest.raises(PendingHumanReviewError):
        broker.request_access(
            requester="alice", resource="prod-db", access_level="admin", duration_seconds=7200,
            reason="rotating leaked credentials after incident 4711",
        )

    triaged = _triaged_detail(db)
    assert triaged.startswith("APPROVE confidence=MEDIUM risk_flag=True: reason is present but admin access for an extended duration carries elevated risk")
    assert (
        " | steps: reason_validation=pass; scope_proportionality=fail (admin access for an extended duration carries elevated risk); "
        "risk_assessment=fail (APPROVE with MEDIUM confidence; over-scoped request flagged for human review)"
    ) in triaged
    assert " | history:" not in triaged  # no history reader on this engine
    assert _routed_detail(db).endswith(" | suggested minimum: write/3600s")


def test_approving_an_escalated_request_issues_a_grant(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db", RETURNED_DECISION)
    _return_to_requester(broker)
    pending = broker.escalate(1, note="on-call, ticket OPS-77", requested_by="alice")

    resolution = broker.resolve_approval(pending.approval_token, approve=True, decided_by="bob")

    assert resolution.resolved is True
    assert resolution.grant is not None
    assert resolution.grant.request_id == 1
    assert broker.is_active(resolution.grant.id) is True
    assert len(connector.issued) == 1
    assert db.get_request(1).status == RequestStatus.HUMAN_APPROVED
