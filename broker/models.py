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
    # A resolve attempt that was refused without changing the approval's
    # state (e.g. a requester trying to approve their own request).
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    # A request that never reached the policy engine because the same
    # requester already holds an ACTIVE grant / PENDING approval for the
    # same resource + access level.
    DUPLICATE_REJECTED = "DUPLICATE_REJECTED"
    # What the AI triage step recommended and how sure it was, recorded so
    # the log shows WHY the router decided what it did, not just what.
    TRIAGED = "TRIAGED"


class PendingApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"


class RequestStatus(str, Enum):
    """Where a request ended up. Grants and pending approvals each have their
    own status; this is the one on the request row itself, so a request that
    never produced either (DENIED, DUPLICATE) still has a visible outcome."""
    PENDING_POLICY = "PENDING_POLICY"
    AUTO_APPROVED = "AUTO_APPROVED"
    DENIED = "DENIED"
    DUPLICATE = "DUPLICATE"
    PENDING_HUMAN = "PENDING_HUMAN"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_DENIED = "HUMAN_DENIED"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str
    # Populated by DecisionRouter only when the triage step actually ran.
    # Plain strings/bools (the enums' .value), not a TriageResult, so this
    # module stays free of a dependency on broker.triage.
    triage_recommendation: Optional[str] = None
    triage_confidence: Optional[str] = None
    triage_risk_flag: Optional[bool] = None
    triage_justification: Optional[str] = None


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
    status: RequestStatus


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
    has no Grant to return either way). `reason` says WHY when not resolved
    (unknown token, already decided, timed out, self-approval) so the CLI and
    web UI can tell the reviewer instead of guessing."""
    resolved: bool
    grant: "Optional[Grant]"
    reason: str = ""


class DuplicateRequestError(Exception):
    """Raised by Broker.request_access when the same requester already has
    an ACTIVE grant or a PENDING approval for the same resource + access
    level. Carries whichever one exists so callers can point at it."""

    def __init__(self, existing_grant: "Optional[Grant]" = None, existing_pending: "Optional[PendingApproval]" = None):
        self.existing_grant = existing_grant
        self.existing_pending = existing_pending
        super().__init__("duplicate request: " + ("active grant exists" if existing_grant else "pending approval exists"))
