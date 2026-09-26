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
    # The stated reason is missing, a placeholder, or does not justify the
    # requested permission. Only the requester can fix that, so it goes back
    # to them (resubmit, or escalate to a human) instead of to an approver.
    RETURN_TO_REQUESTER = "RETURN_TO_REQUESTER"


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
    SELF_APPROVAL_BLOCKED = "SELF_APPROVAL_BLOCKED"
    # A request that never reached the policy engine because the same
    # requester already holds an ACTIVE grant / PENDING approval for the
    # same resource + access level.
    DUPLICATE_REJECTED = "DUPLICATE_REJECTED"
    # What the AI triage step recommended and how sure it was, recorded so
    # the log shows WHY the router decided what it did, not just what.
    TRIAGED = "TRIAGED"
    # The policy handed the request back to its requester (insufficient
    # reason) instead of to an approver.
    RETURNED_TO_REQUESTER = "RETURNED_TO_REQUESTER"
    # The requester chose to push a RETURNED request to a human reviewer
    # anyway. Always followed by ROUTED_TO_HUMAN.
    ESCALATED = "ESCALATED"


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
    # Terminal for the policy, but not for the requester: they may resubmit
    # with a better reason (a RETURNED request is neither an active grant nor
    # a pending approval, so it never counts as a duplicate) or escalate it
    # to a human reviewer, which moves it to PENDING_HUMAN.
    RETURNED = "RETURNED"


@dataclass
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str
    # Populated by PolicyEngine only when the triage step actually ran.
    # Plain strings/bools (the enums' .value), not a TriageResult, so this
    # module stays free of a dependency on broker.llm_decision_agent.
    triage_recommendation: Optional[str] = None
    triage_confidence: Optional[str] = None
    triage_risk_flag: Optional[bool] = None
    triage_justification: Optional[str] = None
    # TriageResult.steps_summary() -- which step passed/failed and why. None
    # when triage produced no steps (a stepless fake, or never ran).
    triage_steps_summary: Optional[str] = None
    # Least-privilege alternative from triage step 2 when the request was
    # over-scoped. Broker appends it to the ROUTED_TO_HUMAN detail so the
    # approval page can show the reviewer what would have sufficed.
    suggested_access_level: Optional[str] = None
    suggested_duration_seconds: Optional[int] = None
    # RequesterHistory.summary() when the engine consulted history (only with
    # a history reader configured, and only past the ACL and junk gate).
    history_summary: Optional[str] = None


class AccessDeniedError(Exception):
    """Raised by Broker.request_access when the policy engine does not
    auto-approve. Carries the real PolicyDecision so callers (e.g. the CLI)
    report the actual reason instead of inventing their own text."""

    def __init__(self, decision: PolicyDecision):
        super().__init__(decision.reason)
        self.decision = decision


class ReturnedToRequesterError(Exception):
    """Raised by Broker.request_access when the policy engine hands the
    request back to the requester because the stated reason is insufficient.
    Not a denial: `hint` tells the requester what they can do next (resubmit
    with a real reason, or escalate to a human), and `request_id` is what
    they need to escalate."""

    def __init__(self, request_id: int, decision: PolicyDecision, hint: str):
        super().__init__(decision.reason)
        self.request_id = request_id
        self.decision = decision
        self.hint = hint


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
