"""Orchestrates the request -> decision -> grant state machine. This is the
one place that knows the full lifecycle; Database, PolicyEngine, and
ResourceConnector are all interchangeable behind their own seams."""
import secrets
from typing import Optional

from broker.clock import SystemClock
from broker.connector import ResourceConnector
from broker.db import Database
from broker.models import (
    AccessDeniedError,
    ApprovalResolution,
    AuditEventType,
    DuplicateRequestError,
    Grant,
    PendingApproval,
    PendingApprovalStatus,
    PendingHumanReviewError,
    PolicyDecisionType,
    RequestStatus,
    ReturnedToRequesterError,
)
from broker.policy import Policy

# What the requester is told they can do with a RETURNED request. Goes into
# the exception (for the CLI) and into the audit detail (so the log shows
# the requester was told their options, not just refused).
RETURN_HINT = "fix the reason and resubmit, or escalate this request to a human reviewer"


class Broker:
    def __init__(self, db: Database, policy: Policy, connector: ResourceConnector, clock=None, approval_deadline_seconds: int = 14400):
        self.db = db
        self.policy = policy
        self.connector = connector
        self.clock = clock or SystemClock()
        self.approval_deadline_seconds = approval_deadline_seconds

    def request_access(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> Grant:
        now = self.clock.now()
        request_id = self.db.create_request(requester, resource, access_level, duration_seconds, reason, now)
        self.db.append_audit(request_id, None, AuditEventType.REQUESTED, f"{requester} requested {access_level} on {resource} for {duration_seconds}s: {reason}", now)

        # Duplicate check before the policy runs: the same access already
        # granted or already awaiting a reviewer must not be re-decided (or
        # re-triaged, which costs an LLM call and could reach a different
        # answer). The duplicate is still a recorded request -- the audit
        # log captures every ask -- it just goes nowhere.
        existing_grant = self.db.find_active_grant(requester, resource, access_level, now)
        existing_pending = None if existing_grant else self.db.find_pending_approval(requester, resource, access_level)
        if existing_grant or existing_pending:
            self.db.set_request_status(request_id, RequestStatus.DUPLICATE)
            detail = (
                f"duplicate of grant {existing_grant.id}"
                if existing_grant
                else f"duplicate of pending approval for request {existing_pending.request_id}"
            )
            self.db.append_audit(request_id, None, AuditEventType.DUPLICATE_REJECTED, detail, now)
            raise DuplicateRequestError(existing_grant=existing_grant, existing_pending=existing_pending)

        decision = self.policy.decide(requester, resource, access_level, duration_seconds, reason)
        if decision.triage_recommendation is not None:
            # Logged before POLICY_DECIDED: the AI's recommendation existed
            # before the router turned it into a decision.
            self.db.append_audit(
                request_id,
                None,
                AuditEventType.TRIAGED,
                f"{decision.triage_recommendation} confidence={decision.triage_confidence} "
                f"risk_flag={decision.triage_risk_flag}: {decision.triage_justification}",
                now,
            )
        self.db.append_audit(request_id, None, AuditEventType.POLICY_DECIDED, f"{decision.decision.value}: {decision.reason}", now)

        if decision.decision == PolicyDecisionType.DENY:
            self.db.set_request_status(request_id, RequestStatus.DENIED)
            self.db.append_audit(request_id, None, AuditEventType.DENIED, decision.reason, now)
            raise AccessDeniedError(decision)

        if decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER:
            # Not a denial and not a review: the reason is insufficient and
            # only the requester can fix that. No approver is involved unless
            # the requester escalates (see escalate()).
            self.db.set_request_status(request_id, RequestStatus.RETURNED)
            self.db.append_audit(
                request_id, None, AuditEventType.RETURNED_TO_REQUESTER, f"{decision.reason}; hint: {RETURN_HINT}", now
            )
            raise ReturnedToRequesterError(request_id, decision, RETURN_HINT)

        if decision.decision == PolicyDecisionType.ROUTE_HUMAN:
            pending = self._route_to_human(request_id, decision.reason, now)
            raise PendingHumanReviewError(pending)

        self.db.set_request_status(request_id, RequestStatus.AUTO_APPROVED)
        token = self.connector.issue(resource, access_level)
        grant = self.db.create_grant(
            request_id=request_id,
            requester=requester,
            resource=resource,
            access_level=access_level,
            token=token,
            granted_at=now,
            expires_at=now + duration_seconds,
        )
        self.db.append_audit(request_id, grant.id, AuditEventType.GRANTED, f"granted until {grant.expires_at}", now)
        return grant

    def _route_to_human(self, request_id: int, why: str, now: int) -> PendingApproval:
        """The one place a pending approval is created: mints the single-use
        token, sets the deadline, moves the request to PENDING_HUMAN and
        audits ROUTED_TO_HUMAN with `why` (what the reviewer will be shown as
        the justification). Used by the policy's ROUTE_HUMAN path and by a
        requester's escalation so both produce an identical approval."""
        approval_token = secrets.token_urlsafe(32)
        deadline_at = now + self.approval_deadline_seconds
        pending = self.db.create_pending_approval(request_id, approval_token, created_at=now, deadline_at=deadline_at)
        self.db.set_request_status(request_id, RequestStatus.PENDING_HUMAN)
        self.db.append_audit(request_id, None, AuditEventType.ROUTED_TO_HUMAN, why, now)
        return pending

    def escalate(self, request_id: int, note: str, requested_by: str) -> Optional[PendingApproval]:
        """Pushes a RETURNED request in front of a human reviewer anyway, at
        the requester's own choice. Returns the new PendingApproval, or None
        when there is nothing to escalate: unknown request, a request in any
        status other than RETURNED (already pending, already decided, a
        duplicate), or a caller who is not the requester -- only the person
        the AI returned it to gets to say "a human should look at this".
        Escalating twice therefore fails the second time: the first call
        moved the request to PENDING_HUMAN."""
        request = self.db.get_request(request_id)
        if request is None or request.status != RequestStatus.RETURNED:
            return None
        if requested_by.strip() != request.requester:
            return None

        now = self.clock.now()
        # The reviewer should see what the AI objected to, not just that the
        # requester insisted. The original reason is the RETURNED_TO_REQUESTER
        # audit detail, minus the hint appended for the requester's benefit.
        original_reason = "(no reason recorded)"
        for event in self.db.get_audit_log(request_id=request_id):
            if event.event_type == AuditEventType.RETURNED_TO_REQUESTER:
                original_reason = event.detail.split(f"; hint: {RETURN_HINT}", 1)[0]
        self.db.append_audit(request_id, None, AuditEventType.ESCALATED, f"escalated by {requested_by}: {note}", now)
        return self._route_to_human(
            request_id, f"escalated by requester; AI returned it because: {original_reason}", now
        )

    def resolve_approval(self, approval_token: str, approve: bool, decided_by: str) -> ApprovalResolution:
        # Enforce deadlines at click time, not just when a sweeper happens to
        # run: a link whose deadline_at has passed is timed out (and audited)
        # right here, so a stale link can never approve access in the gap
        # before the next sweep.
        self.sweep_pending_timeouts()

        now = self.clock.now()
        pending = self.db.get_pending_approval_by_token(approval_token)
        if pending is None:
            return ApprovalResolution(resolved=False, grant=None, reason="unknown approval token")
        if pending.status != PendingApprovalStatus.PENDING:
            return ApprovalResolution(resolved=False, grant=None, reason=f"approval already {pending.status.value.lower()}")

        request = self.db.get_request(pending.request_id)

        # Self-approval is refused WITHOUT consuming the approval: the link
        # stays PENDING so a different reviewer can still decide it.
        if decided_by.strip() == request.requester:
            self.db.append_audit(request.id, None, AuditEventType.SELF_APPROVAL_BLOCKED, f"self-approval attempt by {request.requester}", now)
            return ApprovalResolution(resolved=False, grant=None, reason="requesters cannot approve their own request")

        new_status = PendingApprovalStatus.APPROVED if approve else PendingApprovalStatus.DENIED
        transitioned = self.db.resolve_pending_approval(approval_token, new_status, decided_by, now)
        if not transitioned:
            # Lost a race with another reviewer or the sweeper between our
            # read above and this guarded UPDATE; report what won.
            current = self.db.get_pending_approval_by_token(approval_token)
            return ApprovalResolution(resolved=False, grant=None, reason=f"approval already {current.status.value.lower()}")

        if not approve:
            self.db.set_request_status(request.id, RequestStatus.HUMAN_DENIED)
            self.db.append_audit(pending.request_id, None, AuditEventType.HUMAN_DENIED, f"denied by {decided_by}", now)
            return ApprovalResolution(resolved=True, grant=None)

        self.db.set_request_status(request.id, RequestStatus.HUMAN_APPROVED)
        token = self.connector.issue(request.resource, request.access_level)
        grant = self.db.create_grant(
            request_id=request.id,
            requester=request.requester,
            resource=request.resource,
            access_level=request.access_level,
            token=token,
            granted_at=now,
            expires_at=now + request.duration_seconds,
        )
        self.db.append_audit(pending.request_id, grant.id, AuditEventType.HUMAN_APPROVED, f"approved by {decided_by}", now)
        return ApprovalResolution(resolved=True, grant=grant)

    def sweep_pending_timeouts(self) -> int:
        now = self.clock.now()
        timed_out = self.db.sweep_pending_timeouts(now)
        for pending in timed_out:
            self.db.set_request_status(pending.request_id, RequestStatus.TIMED_OUT)
            self.db.append_audit(pending.request_id, None, AuditEventType.APPROVAL_TIMEOUT, "approval window expired, auto-denied", now)
        return len(timed_out)

    def is_active(self, grant_id: int) -> bool:
        return self.db.is_grant_active(grant_id, self.clock.now())

    def revoke(self, grant_id: int, revoked_by: str) -> bool:
        """Returns True if this call actually transitioned the grant to
        REVOKED, False if it didn't exist or was already terminal."""
        grant = self.db.get_grant(grant_id)
        if grant is None:
            return False
        transitioned = self.db.revoke_grant(grant_id)
        if not transitioned:
            return False
        self.connector.revoke(grant.resource, grant.access_level, grant.token)
        self.db.append_audit(grant.request_id, grant.id, AuditEventType.REVOKED, f"revoked by {revoked_by}", self.clock.now())
        return True

    def sweep_expired(self) -> int:
        now = self.clock.now()
        expired_grants = self.db.expire_due_grants(now)
        for grant in expired_grants:
            self.connector.revoke(grant.resource, grant.access_level, grant.token)
            self.db.append_audit(grant.request_id, grant.id, AuditEventType.EXPIRED, "expired", now)
        return len(expired_grants)

    def reconcile(self) -> tuple[int, int]:
        """Runs both sweeps; returns (expired_count, timed_out_count). Call
        at process start and then periodically. Grant expiry is already
        derived at read time (is_active), but connector-side teardown of an
        expired grant and the auto-deny of a stale pending approval only
        happen here -- so a long gap between sweeps is a fail-open window on
        the external system, not just a stale status in our DB."""
        return self.sweep_expired(), self.sweep_pending_timeouts()
