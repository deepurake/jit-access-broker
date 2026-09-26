"""Requester history: a read-only projection over the broker's SQLite tables.

Why this exists
---------------
A request's scope alone is a weak signal. The same "admin on prod-db for
two hours" is routine from someone who has held and cleanly returned that
access a dozen times, and alarming from someone the broker has never seen
-- or who was denied or revoked an hour ago. The user asked for exactly
this: use the existing SQL data to gain confidence when the requested scope
is large, and send brand-new requesters to a human instead of trusting the
AI's read of a reason string.

Nothing new has to be recorded to answer that. Every fact the policy layer
wants is already in `requests`, `grants`, `audit_log` and
`pending_approvals`; this module just aggregates them per requester into a
`RequesterHistory` the policy engine and the LLM prompt can consume, and a
one-line `summary()` that goes into the TRIAGED audit detail so the log
shows what the decision was based on.

Conventions
-----------
* READ-ONLY. This module never INSERTs or UPDATEs. It borrows the
  Database's connection (row_factory is sqlite3.Row) and only ever SELECTs.
* It owns its own SQL. The project convention is "all SQL lives in db.py";
  this is a deliberate exception. A history read model is a natural seam
  of its own (it aggregates across four tables and has no CRUD), and
  keeping its queries here means changing what "history" means never
  touches the persistence layer's write paths -- which several other
  workstreams are editing at the same time.
* Denials, human approvals and revocations are attributed to a requester
  by joining audit_log.request_id back to requests.requester -- audit_log
  itself does not carry the requester.
* `exclude_request_id`: the broker records the current request row BEFORE
  it consults history, so the caller passes that id to keep the request
  being decided from counting as its own precedent.

TODO (richer behavioral rules, deliberately out of scope here): per-
requester baselines (usual resources/levels/durations), anomaly relative
to the requester's own history rather than absolute thresholds, agent-vs-
human requester distinctions, and a cool-down period after a denial.
"""
import sqlite3
from dataclasses import dataclass
from typing import Optional, Sequence

from broker.models import AuditEventType, GrantStatus, PendingApprovalStatus

_NEGATIVE_AUDIT_EVENTS = (AuditEventType.DENIED.value, AuditEventType.HUMAN_DENIED.value)


@dataclass
class RequesterHistory:
    requester: str
    total_requests: int
    approved_grants: int
    active_grants: int
    revocations: int
    denials: int
    human_approvals: int
    pending_reviews: int
    same_resource_grants: int
    same_scope_grants: int
    last_denial_at: Optional[int]
    last_revocation_at: Optional[int]

    @property
    def is_new(self) -> bool:
        """No grant has ever been issued to this requester, by any path."""
        return self.approved_grants == 0

    def had_recent_negative_event(self, now: int, window_seconds: int) -> bool:
        """True if a denial or a revocation landed within the last
        `window_seconds` (inclusive of the window's start, exclusive of the
        future -- an event stamped after `now` is not "recent", it is a
        clock problem)."""
        cutoff = now - window_seconds
        for at in (self.last_denial_at, self.last_revocation_at):
            if at is not None and cutoff <= at <= now:
                return True
        return False

    def summary(self) -> str:
        """One deterministic line for prompts and audit detail."""
        return (
            f"requester={self.requester} "
            f"total_requests={self.total_requests} "
            f"approved_grants={self.approved_grants} "
            f"active={self.active_grants} "
            f"revocations={self.revocations} "
            f"denials={self.denials} "
            f"human_approvals={self.human_approvals} "
            f"pending={self.pending_reviews} "
            f"same_resource={self.same_resource_grants} "
            f"same_scope={self.same_scope_grants} "
            f"last_denial_at={_fmt_ts(self.last_denial_at)} "
            f"last_revocation_at={_fmt_ts(self.last_revocation_at)}"
        )


def _fmt_ts(value: Optional[int]) -> str:
    return "none" if value is None else str(value)


class RequesterHistoryReader:
    """Read-only projection over the broker's SQLite tables.

    Holds a reference to the Database's own sqlite3 connection (documented
    read-only use; row_factory is sqlite3.Row) so it sees the same committed
    state the broker does, with no second file handle to keep in sync."""

    def __init__(self, db) -> None:
        self._conn: sqlite3.Connection = db._conn

    def for_request(
        self,
        requester: str,
        resource: str,
        access_level: str,
        now: int,
        exclude_request_id: Optional[int] = None,
    ) -> RequesterHistory:
        return RequesterHistory(
            requester=requester,
            total_requests=self._count_requests(requester, exclude_request_id),
            approved_grants=self._scalar(
                "SELECT COUNT(*) FROM grants WHERE requester = ?", (requester,)
            ),
            active_grants=self._scalar(
                "SELECT COUNT(*) FROM grants WHERE requester = ? AND status = ? AND expires_at > ?",
                (requester, GrantStatus.ACTIVE.value, now),
            ),
            revocations=self._scalar(
                "SELECT COUNT(*) FROM grants WHERE requester = ? AND status = ?",
                (requester, GrantStatus.REVOKED.value),
            ),
            denials=self._count_audit(requester, _NEGATIVE_AUDIT_EVENTS),
            human_approvals=self._count_audit(requester, (AuditEventType.HUMAN_APPROVED.value,)),
            pending_reviews=self._scalar(
                "SELECT COUNT(*) FROM pending_approvals pa JOIN requests r ON r.id = pa.request_id "
                "WHERE r.requester = ? AND pa.status = ?",
                (requester, PendingApprovalStatus.PENDING.value),
            ),
            same_resource_grants=self._scalar(
                "SELECT COUNT(*) FROM grants WHERE requester = ? AND resource = ?",
                (requester, resource),
            ),
            same_scope_grants=self._scalar(
                "SELECT COUNT(*) FROM grants WHERE requester = ? AND resource = ? AND access_level = ?",
                (requester, resource, access_level),
            ),
            last_denial_at=self._latest_audit_at(requester, _NEGATIVE_AUDIT_EVENTS),
            last_revocation_at=self._latest_audit_at(requester, (AuditEventType.REVOKED.value,)),
        )

    # -- query helpers ---------------------------------------------------- #

    def _count_requests(self, requester: str, exclude_request_id: Optional[int]) -> int:
        if exclude_request_id is None:
            return self._scalar("SELECT COUNT(*) FROM requests WHERE requester = ?", (requester,))
        return self._scalar(
            "SELECT COUNT(*) FROM requests WHERE requester = ? AND id != ?",
            (requester, exclude_request_id),
        )

    def _count_audit(self, requester: str, event_types: Sequence[str]) -> int:
        placeholders = ", ".join("?" for _ in event_types)
        return self._scalar(
            "SELECT COUNT(*) FROM audit_log a JOIN requests r ON r.id = a.request_id "
            f"WHERE r.requester = ? AND a.event_type IN ({placeholders})",
            (requester, *event_types),
        )

    def _latest_audit_at(self, requester: str, event_types: Sequence[str]) -> Optional[int]:
        placeholders = ", ".join("?" for _ in event_types)
        row = self._conn.execute(
            "SELECT MAX(a.at) AS latest FROM audit_log a JOIN requests r ON r.id = a.request_id "
            f"WHERE r.requester = ? AND a.event_type IN ({placeholders})",
            (requester, *event_types),
        ).fetchone()
        return row["latest"] if row is not None and row["latest"] is not None else None

    def _scalar(self, sql: str, params: tuple) -> int:
        row = self._conn.execute(sql, params).fetchone()
        return int(row[0]) if row is not None and row[0] is not None else 0
