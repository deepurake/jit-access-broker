"""Orchestrates the request -> decision -> grant state machine. This is the
one place that knows the full lifecycle; Database, PolicyEngine, and
ResourceConnector are all interchangeable behind their own seams."""
from broker.clock import SystemClock
from broker.connector import ResourceConnector
from broker.db import Database
from broker.models import AuditEventType, Grant, PolicyDecisionType
from broker.policy import PolicyEngine


class Broker:
    def __init__(self, db: Database, policy: PolicyEngine, connector: ResourceConnector, clock=None):
        self.db = db
        self.policy = policy
        self.connector = connector
        self.clock = clock or SystemClock()

    def request_access(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> Grant:
        now = self.clock.now()
        request_id = self.db.create_request(requester, resource, access_level, duration_seconds, reason, now)
        self.db.append_audit(request_id, None, AuditEventType.REQUESTED, f"{requester} requested {access_level} on {resource} for {duration_seconds}s: {reason}", now)

        decision = self.policy.decide(resource, access_level, duration_seconds, reason)
        self.db.append_audit(request_id, None, AuditEventType.POLICY_DECIDED, f"{decision.decision.value}: {decision.reason}", now)

        if decision.decision != PolicyDecisionType.AUTO_APPROVE:
            self.db.append_audit(request_id, None, AuditEventType.DENIED, decision.reason, now)
            raise NotImplementedError("only AUTO_APPROVE is implemented in stage 1")

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

    def is_active(self, grant_id: int) -> bool:
        return self.db.is_grant_active(grant_id, self.clock.now())

    def revoke(self, grant_id: int, revoked_by: str) -> None:
        grant = self.db.get_grant(grant_id)
        if grant is None:
            return
        transitioned = self.db.revoke_grant(grant_id)
        if not transitioned:
            return
        self.connector.revoke(grant.resource, grant.access_level, grant.token)
        self.db.append_audit(grant.request_id, grant.id, AuditEventType.REVOKED, f"revoked by {revoked_by}", self.clock.now())

    def sweep_expired(self) -> int:
        now = self.clock.now()
        expired_ids = self.db.expire_due_grants(now)
        for grant_id in expired_ids:
            grant = self.db.get_grant(grant_id)
            self.db.append_audit(grant.request_id, grant.id, AuditEventType.EXPIRED, "expired", now)
        return len(expired_ids)
