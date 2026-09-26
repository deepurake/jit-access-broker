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


@dataclass
class Request:
    id: int
    requester: str
    resource: str
    access_level: str
    duration_seconds: int
    reason: str
    created_at: int


class PendingHumanReviewError(Exception):
    """Raised by Broker.request_access when the policy engine routes the
    request to a human instead of deciding it outright. Carries the
    PendingApproval (with its single-use approval_token) so callers (e.g.
    the CLI) can surface the review link instead of a grant."""

    def __init__(self, pending_approval: "PendingApproval"):
        super().__init__(f"routed to human review, token={pending_approval.approval_token}")
        self.pending_approval = pending_approval


@dataclass
class ApprovalResolution:
    """Result of resolving a pending approval. `resolved` distinguishes
    'this call actually changed something' from 'no-op, already decided or
    unknown token' -- callers need that distinction even for a deny (which
    has no Grant to return either way)."""
    resolved: bool
    grant: "Optional[Grant]"
