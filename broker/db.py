"""SQLite-backed persistence. File-based (never :memory:) so state survives
a process restart -- the broker re-derives everything from these tables on
every call, it keeps nothing important in memory."""
import sqlite3
from typing import List, Optional

from broker.models import (
    AuditEvent,
    AuditEventType,
    Grant,
    GrantStatus,
    PendingApproval,
    PendingApprovalStatus,
    Request,
    RequestStatus,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    resource TEXT NOT NULL,
    access_level TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING_POLICY'
);

CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL REFERENCES requests(id),
    requester TEXT NOT NULL,
    resource TEXT NOT NULL,
    access_level TEXT NOT NULL,
    token TEXT NOT NULL,
    status TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    grant_id INTEGER,
    event_type TEXT NOT NULL,
    detail TEXT NOT NULL,
    at INTEGER NOT NULL
);

-- Dynamic, frequently-changing operational data (who has what role) --
-- in a real deployment this would be synced from the IdP (e.g. Okta
-- group membership), not hand-edited. A table, not a YAML file.
CREATE TABLE IF NOT EXISTS user_roles (
    requester TEXT PRIMARY KEY,
    role TEXT NOT NULL
);

-- ACL rules: authored in acl.yaml (git-reviewed, human-readable source of
-- truth) and loaded into this table via Database.load_acl_rules(), so the
-- runtime query path is indexed SQL, not a file read, and audit entries can
-- reference which rule fired. Same "YAML authors it, a table serves it"
-- split real systems use (Teleport roles, OPA bundles, etc.).
CREATE TABLE IF NOT EXISTS acl_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    resource_pattern TEXT NOT NULL,
    max_access_level TEXT NOT NULL,
    max_duration_seconds INTEGER NOT NULL
);

-- Which roles may decide a pending human review. Authored as the
-- `approver_roles:` list in acl.yaml and synced here by the same load-acl
-- step as acl_rules. Broker.resolve_approval joins this against user_roles:
-- a decider must be a known user AND hold one of these roles. An empty
-- table means nobody can approve (fail closed).
CREATE TABLE IF NOT EXISTS approver_roles (
    role TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL REFERENCES requests(id),
    approval_token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    deadline_at INTEGER NOT NULL,
    decided_at INTEGER,
    decided_by TEXT
);
"""


class Database:
    def __init__(self, path: str):
        # check_same_thread=False: the Flask services hand each request to a
        # worker thread while the Database was opened on the main thread. One
        # connection, commit after every write, and the services run their
        # dev server single-threaded, so there is no concurrent use of it.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate_requests_status_column()
        self._conn.commit()

    def _migrate_requests_status_column(self) -> None:
        """CREATE TABLE IF NOT EXISTS leaves an existing table alone, so a
        SQLite file created before requests.status existed (e.g. one already
        sitting in a docker volume) needs the column added on open."""
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(requests)")}
        if "status" not in columns:
            self._conn.execute(
                f"ALTER TABLE requests ADD COLUMN status TEXT NOT NULL DEFAULT '{RequestStatus.PENDING_POLICY.value}'"
            )

    def create_request(self, requester, resource, access_level, duration_seconds, reason, at) -> int:
        cur = self._conn.execute(
            "INSERT INTO requests (requester, resource, access_level, duration_seconds, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (requester, resource, access_level, duration_seconds, reason, at),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_request(self, request_id: int) -> Optional[Request]:
        row = self._conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
        if row is None:
            return None
        return Request(
            id=row["id"],
            requester=row["requester"],
            resource=row["resource"],
            access_level=row["access_level"],
            duration_seconds=row["duration_seconds"],
            reason=row["reason"],
            created_at=row["created_at"],
            status=RequestStatus(row["status"]),
        )

    def set_request_status(self, request_id: int, status: RequestStatus) -> None:
        self._conn.execute("UPDATE requests SET status = ? WHERE id = ?", (status.value, request_id))
        self._conn.commit()

    def create_grant(self, request_id, requester, resource, access_level, token, granted_at, expires_at) -> Grant:
        cur = self._conn.execute(
            "INSERT INTO grants (request_id, requester, resource, access_level, token, status, granted_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (request_id, requester, resource, access_level, token, GrantStatus.ACTIVE.value, granted_at, expires_at),
        )
        self._conn.commit()
        return Grant(
            id=cur.lastrowid,
            request_id=request_id,
            requester=requester,
            resource=resource,
            access_level=access_level,
            token=token,
            status=GrantStatus.ACTIVE,
            granted_at=granted_at,
            expires_at=expires_at,
        )

    def get_grant(self, grant_id: int) -> Optional[Grant]:
        row = self._conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone()
        return self._row_to_grant(row) if row is not None else None

    def is_grant_active(self, grant_id: int, now: int) -> bool:
        grant = self.get_grant(grant_id)
        if grant is None:
            return False
        return grant.status == GrantStatus.ACTIVE and grant.expires_at > now

    def find_active_grant(self, requester: str, resource: str, access_level: str, now: int) -> Optional[Grant]:
        """Newest grant for this exact (requester, resource, access_level)
        that is still live -- same expires_at > now rule as is_grant_active,
        so a grant the sweeper hasn't reached yet still counts as expired."""
        row = self._conn.execute(
            "SELECT * FROM grants WHERE requester = ? AND resource = ? AND access_level = ? "
            "AND status = ? AND expires_at > ? ORDER BY id DESC LIMIT 1",
            (requester, resource, access_level, GrantStatus.ACTIVE.value, now),
        ).fetchone()
        return self._row_to_grant(row) if row is not None else None

    def _transition_grant(self, grant_id: int, to_status: GrantStatus, from_status: GrantStatus = GrantStatus.ACTIVE) -> bool:
        """Guarded state transition: only affects a row still in `from_status`.
        If a concurrent revoke/expiry already moved it, this is a no-op
        instead of clobbering the winning status. Caller commits."""
        cur = self._conn.execute(
            "UPDATE grants SET status = ? WHERE id = ? AND status = ?",
            (to_status.value, grant_id, from_status.value),
        )
        return cur.rowcount == 1

    def expire_due_grants(self, now: int) -> List[Grant]:
        due_rows = self._conn.execute(
            "SELECT * FROM grants WHERE status = ? AND expires_at <= ?",
            (GrantStatus.ACTIVE.value, now),
        ).fetchall()
        expired = []
        for row in due_rows:
            if self._transition_grant(row["id"], GrantStatus.EXPIRED):
                grant = self._row_to_grant(row)
                grant.status = GrantStatus.EXPIRED
                expired.append(grant)
        self._conn.commit()
        return expired

    def revoke_grant(self, grant_id: int) -> bool:
        transitioned = self._transition_grant(grant_id, GrantStatus.REVOKED)
        self._conn.commit()
        return transitioned

    def append_audit(self, request_id, grant_id, event_type: AuditEventType, detail: str, at: int) -> None:
        self._conn.execute(
            "INSERT INTO audit_log (request_id, grant_id, event_type, detail, at) VALUES (?, ?, ?, ?, ?)",
            (request_id, grant_id, event_type.value, detail, at),
        )
        self._conn.commit()

    def get_audit_log(self, request_id: int = None, grant_id: int = None) -> List[AuditEvent]:
        if grant_id is not None:
            where, params = "WHERE grant_id = ?", (grant_id,)
        elif request_id is not None:
            where, params = "WHERE request_id = ?", (request_id,)
        else:
            where, params = "", ()
        rows = self._conn.execute(f"SELECT * FROM audit_log {where} ORDER BY id", params).fetchall()
        return [
            AuditEvent(
                id=row["id"],
                request_id=row["request_id"],
                grant_id=row["grant_id"],
                event_type=AuditEventType(row["event_type"]),
                detail=row["detail"],
                at=row["at"],
            )
            for row in rows
        ]

    def _row_to_grant(self, row: sqlite3.Row) -> Grant:
        return Grant(
            id=row["id"],
            request_id=row["request_id"],
            requester=row["requester"],
            resource=row["resource"],
            access_level=row["access_level"],
            token=row["token"],
            status=GrantStatus(row["status"]),
            granted_at=row["granted_at"],
            expires_at=row["expires_at"],
        )

    # -- user_roles: dynamic directory data, would sync from a real IdP -- #

    def set_user_role(self, requester: str, role: str) -> None:
        self._conn.execute(
            "INSERT INTO user_roles (requester, role) VALUES (?, ?) "
            "ON CONFLICT(requester) DO UPDATE SET role = excluded.role",
            (requester, role),
        )
        self._conn.commit()

    def get_role_for_requester(self, requester: str) -> Optional[str]:
        row = self._conn.execute("SELECT role FROM user_roles WHERE requester = ?", (requester,)).fetchone()
        return row["role"] if row is not None else None

    # -- acl_rules: authored in acl.yaml, served from this table -- #

    def load_acl_rules(self, rules: List[dict]) -> None:
        """Replaces all ACL rules with the given list of
        {role, resource_pattern, max_access_level, max_duration_seconds}
        dicts -- the runtime sync step for acl.yaml."""
        self._conn.execute("DELETE FROM acl_rules")
        self._conn.executemany(
            "INSERT INTO acl_rules (role, resource_pattern, max_access_level, max_duration_seconds) "
            "VALUES (?, ?, ?, ?)",
            [
                (r["role"], r["resource_pattern"], r["max_access_level"], r["max_duration_seconds"])
                for r in rules
            ],
        )
        self._conn.commit()

    def get_acl_rules_for_role(self, role: str) -> List[dict]:
        rows = self._conn.execute(
            "SELECT role, resource_pattern, max_access_level, max_duration_seconds "
            "FROM acl_rules WHERE role = ?",
            (role,),
        ).fetchall()
        return [dict(row) for row in rows]

    # -- approver_roles: authored in acl.yaml, served from this table -- #

    def load_approver_roles(self, roles: List[str]) -> None:
        """Replaces the whole set of approver roles -- the runtime sync step
        for acl.yaml's `approver_roles:` list, same replace-all semantics as
        load_acl_rules. Loading [] leaves nobody able to approve."""
        self._conn.execute("DELETE FROM approver_roles")
        self._conn.executemany(
            "INSERT OR IGNORE INTO approver_roles (role) VALUES (?)",
            [(role,) for role in roles],
        )
        self._conn.commit()

    def is_approver(self, name: str) -> bool:
        """True iff `name` is a known user (present in user_roles) whose role
        is one of the approver roles. This authorizes a CLAIMED name -- it is
        not authentication; nothing here proves the caller is that user. It
        does make "who may approve" policy-as-data instead of "anyone who
        types a name". Unknown names, known users in non-approver roles and
        an empty approver_roles table all answer False."""
        row = self._conn.execute(
            "SELECT 1 FROM user_roles u JOIN approver_roles a ON a.role = u.role WHERE u.requester = ? LIMIT 1",
            (name,),
        ).fetchone()
        return row is not None

    # -- pending_approvals: the human-review magic-link flow -- #

    def create_pending_approval(self, request_id: int, approval_token: str, created_at: int, deadline_at: int) -> PendingApproval:
        cur = self._conn.execute(
            "INSERT INTO pending_approvals (request_id, approval_token, status, created_at, deadline_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (request_id, approval_token, PendingApprovalStatus.PENDING.value, created_at, deadline_at),
        )
        self._conn.commit()
        return PendingApproval(
            id=cur.lastrowid,
            request_id=request_id,
            approval_token=approval_token,
            status=PendingApprovalStatus.PENDING,
            created_at=created_at,
            deadline_at=deadline_at,
            decided_at=None,
            decided_by=None,
        )

    def get_pending_approval_by_token(self, approval_token: str) -> Optional[PendingApproval]:
        row = self._conn.execute(
            "SELECT * FROM pending_approvals WHERE approval_token = ?", (approval_token,)
        ).fetchone()
        return self._row_to_pending_approval(row) if row is not None else None

    def find_pending_approval(self, requester: str, resource: str, access_level: str) -> Optional[PendingApproval]:
        """Newest still-PENDING approval whose underlying request matches this
        exact (requester, resource, access_level). pending_approvals doesn't
        denormalise those fields, so join back to requests."""
        row = self._conn.execute(
            "SELECT pa.* FROM pending_approvals pa JOIN requests r ON r.id = pa.request_id "
            "WHERE pa.status = ? AND r.requester = ? AND r.resource = ? AND r.access_level = ? "
            "ORDER BY pa.id DESC LIMIT 1",
            (PendingApprovalStatus.PENDING.value, requester, resource, access_level),
        ).fetchone()
        return self._row_to_pending_approval(row) if row is not None else None

    def resolve_pending_approval(self, approval_token: str, new_status: PendingApprovalStatus, decided_by: str, now: int) -> bool:
        """Guarded transition, same pattern as _transition_grant: only a
        still-PENDING row can be resolved, so two people racing the same
        link (or a timeout sweep racing a click) can't both win."""
        cur = self._conn.execute(
            "UPDATE pending_approvals SET status = ?, decided_at = ?, decided_by = ? "
            "WHERE approval_token = ? AND status = ?",
            (new_status.value, now, decided_by, approval_token, PendingApprovalStatus.PENDING.value),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def sweep_pending_timeouts(self, now: int) -> List[PendingApproval]:
        due_rows = self._conn.execute(
            "SELECT * FROM pending_approvals WHERE status = ? AND deadline_at <= ?",
            (PendingApprovalStatus.PENDING.value, now),
        ).fetchall()
        timed_out = []
        for row in due_rows:
            cur = self._conn.execute(
                "UPDATE pending_approvals SET status = ?, decided_at = ? WHERE id = ? AND status = ?",
                (PendingApprovalStatus.TIMED_OUT.value, now, row["id"], PendingApprovalStatus.PENDING.value),
            )
            if cur.rowcount == 1:
                pending = self._row_to_pending_approval(row)
                pending.status = PendingApprovalStatus.TIMED_OUT
                pending.decided_at = now
                timed_out.append(pending)
        self._conn.commit()
        return timed_out

    def _row_to_pending_approval(self, row: sqlite3.Row) -> PendingApproval:
        return PendingApproval(
            id=row["id"],
            request_id=row["request_id"],
            approval_token=row["approval_token"],
            status=PendingApprovalStatus(row["status"]),
            created_at=row["created_at"],
            deadline_at=row["deadline_at"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
        )
