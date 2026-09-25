"""SQLite-backed persistence. File-based (never :memory:) so state survives
a process restart -- the broker re-derives everything from these tables on
every call, it keeps nothing important in memory."""
import sqlite3
from typing import List, Optional

from broker.models import AuditEvent, AuditEventType, Grant, GrantStatus

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    resource TEXT NOT NULL,
    access_level TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL
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
"""


class Database:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def create_request(self, requester, resource, access_level, duration_seconds, reason, at) -> int:
        cur = self._conn.execute(
            "INSERT INTO requests (requester, resource, access_level, duration_seconds, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (requester, resource, access_level, duration_seconds, reason, at),
        )
        self._conn.commit()
        return cur.lastrowid

    def create_grant(self, request_id, requester, resource, access_level, token, granted_at, expires_at) -> Grant:
        cur = self._conn.execute(
            "INSERT INTO grants (request_id, requester, resource, access_level, token, status, granted_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (request_id, requester, resource, access_level, token, GrantStatus.ACTIVE.value, granted_at, expires_at),
        )
        self._conn.commit()
        return self.get_grant(cur.lastrowid)

    def get_grant(self, grant_id: int) -> Optional[Grant]:
        row = self._conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone()
        if row is None:
            return None
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

    def is_grant_active(self, grant_id: int, now: int) -> bool:
        grant = self.get_grant(grant_id)
        if grant is None:
            return False
        return grant.status == GrantStatus.ACTIVE and grant.expires_at > now

    def expire_due_grants(self, now: int) -> List[int]:
        """Conditional UPDATE guarded by status='ACTIVE': if a concurrent
        revoke already transitioned the row, this affects zero rows for it
        instead of clobbering the REVOKED status."""
        due = self._conn.execute(
            "SELECT id FROM grants WHERE status = ? AND expires_at <= ?",
            (GrantStatus.ACTIVE.value, now),
        ).fetchall()
        expired_ids = []
        for row in due:
            cur = self._conn.execute(
                "UPDATE grants SET status = ? WHERE id = ? AND status = ?",
                (GrantStatus.EXPIRED.value, row["id"], GrantStatus.ACTIVE.value),
            )
            if cur.rowcount == 1:
                expired_ids.append(row["id"])
        self._conn.commit()
        return expired_ids

    def revoke_grant(self, grant_id: int) -> bool:
        """Same guarded-transition pattern as expiry: only an ACTIVE grant
        can become REVOKED. Returns False if it was already terminal."""
        cur = self._conn.execute(
            "UPDATE grants SET status = ? WHERE id = ? AND status = ?",
            (GrantStatus.REVOKED.value, grant_id, GrantStatus.ACTIVE.value),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def append_audit(self, request_id, grant_id, event_type: AuditEventType, detail: str, at: int) -> None:
        self._conn.execute(
            "INSERT INTO audit_log (request_id, grant_id, event_type, detail, at) VALUES (?, ?, ?, ?, ?)",
            (request_id, grant_id, event_type.value, detail, at),
        )
        self._conn.commit()

    def get_audit_log(self, request_id: int = None, grant_id: int = None) -> List[AuditEvent]:
        if grant_id is not None:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE grant_id = ? ORDER BY id", (grant_id,)
            ).fetchall()
        elif request_id is not None:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE request_id = ? ORDER BY id", (request_id,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
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
