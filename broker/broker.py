"""Orchestrates the request -> decision -> grant state machine. This is the
one place that knows the full lifecycle; Database, PolicyEngine, and
ResourceConnector are all interchangeable behind their own seams."""
import secrets

from broker.clock import SystemClock
from broker.connector import ResourceConnector
from broker.db import Database
from broker.models import (
    AccessDeniedError,
    ApprovalResolution,
    AuditEventType,
    Grant,
    PendingApprovalStatus,
    PendingHumanReviewError,
    PolicyDecisionType,
)
from broker.policy import PolicyEngine


class Broker:
    def __init__(self, db: Database, policy: PolicyEngine, connector: ResourceConnector, clock=None, approval_deadline_seconds: int = 14400):
        self.db = db
        self.policy = policy
        self.connector = connector
        self.clock = clock or SystemClock()
        self.approval_deadline_seconds = approval_deadline_seconds

    def request_access(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> Grant:
        now = self.clock.now()
        request_id = self.db.create_request(requester, resource, access_level, duration_seconds, reason, now)
        self.db.append_audit(request_id, None, AuditEventType.REQUESTED, f"{requester} requested {access_level} on {resource} for {duration_seconds}s: {reason}", now)

        decision = self.policy.decide(requester, resource, access_level, duration_seconds, reason)
        self.db.append_audit(request_id, None, AuditEventType.POLICY_DECIDED, f"{decision.decision.value}: {decision.reason}", now)

        if decision.decision == PolicyDecisionType.DENY:
            self.db.append_audit(request_id, None, AuditEventType.DENIED, decision.reason, now)
            raise AccessDeniedError(decision)

        if decision.decision == PolicyDecisionType.ROUTE_HUMAN:
            approval_token = secrets.token_urlsafe(32)
            deadline_at = now + self.approval_deadline_seconds
            pending = self.db.create_pending_approval(request_id, approval_token, created_at=now, deadline_at=deadline_at)
            self.db.append_audit(request_id, None, AuditEventType.ROUTED_TO_HUMAN, decision.reason, now)
            raise PendingHumanReviewError(pending)

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

    def resolve_approval(self, approval_token: str, approve: bool, decided_by: str) -> ApprovalResolution:
        now = self.clock.now()
        pending = self.db.get_pending_approval_by_token(approval_token)
        if pending is None:
            return ApprovalResolution(resolved=False, grant=None)

        new_status = PendingApprovalStatus.APPROVED if approve else PendingApprovalStatus.DENIED
        transitioned = self.db.resolve_pending_approval(approval_token, new_status, decided_by, now)
        if not transitioned:
            return ApprovalResolution(resolved=False, grant=None)

        request = self.db.get_request(pending.request_id)

        if not approve:
            self.db.append_audit(pending.request_id, None, AuditEventType.HUMAN_DENIED, f"denied by {decided_by}", now)
            return ApprovalResolution(resolved=True, grant=None)

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
