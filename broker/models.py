from dataclasses import dataclass
from enum import Enum
from typing import Optional


class GrantStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class PolicyDecisionType(str, Enum):
    AUTO_APPROVE = "AUTO_APPROVE"
    ROUTE_HUMAN = "ROUTE_HUMAN"
    DENY = "DENY"


class AuditEventType(str, Enum):
    REQUESTED = "REQUESTED"
    POLICY_DECIDED = "POLICY_DECIDED"
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    ROUTED_TO_HUMAN = "ROUTED_TO_HUMAN"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_DENIED = "HUMAN_DENIED"
    APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"


class PendingApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str


class AccessDeniedError(Exception):
    """Raised by Broker.request_access when the policy engine does not
    auto-approve. Carries the real PolicyDecision so callers (e.g. the CLI)
    report the actual reason instead of inventing their own text."""

    def __init__(self, decision: PolicyDecision):
        super().__init__(decision.reason)
        self.decision = decision


@dataclass
class Grant:
    id: int
    request_id: int
    requester: str
    resource: str
    access_level: str
    token: str
    status: GrantStatus
    granted_at: int
    expires_at: int


@dataclass
class AuditEvent:
    id: int
    request_id: int
    grant_id: Optional[int]
    event_type: AuditEventType
    detail: str
    at: int


@dataclass
class PendingApproval:
    id: int
    request_id: int
    approval_token: str
    status: PendingApprovalStatus
    created_at: int
    deadline_at: int
    decided_at: Optional[int]
    decided_by: Optional[str]
