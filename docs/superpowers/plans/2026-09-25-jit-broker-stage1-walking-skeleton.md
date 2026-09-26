# JIT Access Broker — Stage 1: Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and test an end-to-end JIT token disbursement flow — request → policy decision → mocked grant issuance → automatic expiry / revocation → audit trail — as a walking skeleton, before layering on the real policy engine, human approval routing, and AI triage in later stages.

**Architecture:** A `Broker` orchestrator sits between four seams: `Clock` (time), `PolicyEngine` (decision), `ResourceConnector` (the mocked external grant), and `Database` (SQLite persistence with guarded state transitions). Stage 1 implements trivial versions of the policy engine (`AlwaysApprovePolicy`) and connector (`MockConnector`) to prove the pipeline end to end; later stages replace those two without touching `Broker`, `Database`, or the schema.

**Tech Stack:** Python 3 (stdlib `sqlite3`, `dataclasses`, `enum`), `pytest`.

---

> **Retroactive record.** This plan documents Stage 1 as it was actually built (per user direction: keep the working code, formalize the plan after the fact). One honest deviation from the skill's ideal task-by-task RED/GREEN cadence: because stage 1 is small and each module is a thin, mechanical seam, all six modules were written together and verified with a single RED run (import error) followed by a single GREEN run (which surfaced one test bug, fixed and re-verified). Task-by-task RED/GREEN is used strictly from Stage 2 onward — see the "Deviation note" at the end.

## Task 1: Data model contracts

**Files:**
- Create: `broker/models.py`

- [x] **Step 1: Define the contract — dataclasses and enums, no behavior**

```python
from dataclasses import dataclass
from enum import Enum


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


@dataclass
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str


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
    grant_id: "int | None"
    event_type: AuditEventType
    detail: str
    at: int
```

- [x] **Step 2: Verify by import — no syntax/type errors**

Run: `python3 -c "import broker.models"`
Expected: no output, exit code 0.

## Task 2: Clock seam

**Files:**
- Create: `broker/clock.py`

**Why this seam exists:** production code must never call `time.time()` directly — every place that needs "now" asks a `Clock`, so tests can move time forward deterministically instead of sleeping.

- [x] **Step 1: Define the contract + both implementations**

```python
"""Time seam: production code always asks a Clock for `now()` instead of
calling time.time() directly, so tests can control the passage of time
without sleeping."""
import time


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class FakeClock:
    def __init__(self, start: int = 1_700_000_000):
        self._now = start

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += seconds
```

- [x] **Step 2: Verify by import**

Run: `python3 -c "from broker.clock import SystemClock, FakeClock; c = FakeClock(); c.advance(5); assert c.now() == 1_700_000_005"`
Expected: no output, exit code 0.

## Task 3: ResourceConnector seam (the mocked grant backend)

**Files:**
- Create: `broker/connector.py`

**Why this seam exists:** this is where a real Okta/AWS/Workspace SDK call goes later. The `Broker` only ever talks to `ResourceConnector`, never to a concrete system — swapping the mock for a real integration means writing one new class that implements `issue`/`revoke` and changing nothing else.

- [x] **Step 1: Define the interface and the mock implementation**

```python
"""ResourceConnector is the seam where a real Okta / AWS / Workspace SDK call
would go. The broker only ever talks to this interface, never to a concrete
system, so swapping the mock for a real integration later means writing one
new class and changing nothing else."""
import secrets
from abc import ABC, abstractmethod


class ResourceConnector(ABC):
    @abstractmethod
    def issue(self, resource: str, access_level: str) -> str:
        """Provision access on the real system and return an opaque token."""

    @abstractmethod
    def revoke(self, resource: str, access_level: str, token: str) -> None:
        """Tear down access on the real system for a previously issued token."""


class MockConnector(ResourceConnector):
    """Stands in for a real identity/resource provider. Records every call
    it receives so tests can assert on what the broker asked it to do."""

    def __init__(self):
        self.issued = []
        self.revoked = []

    def issue(self, resource: str, access_level: str) -> str:
        token = f"mock-token-{secrets.token_hex(8)}"
        self.issued.append((resource, access_level, token))
        return token

    def revoke(self, resource: str, access_level: str, token: str) -> None:
        self.revoked.append((resource, access_level, token))
```

- [x] **Step 2: Verify by import**

Run: `python3 -c "from broker.connector import MockConnector; c = MockConnector(); t = c.issue('r','read'); c.revoke('r','read', t); assert c.issued and c.revoked"`
Expected: no output, exit code 0.

## Task 4: PolicyEngine seam (stage-1 placeholder)

**Files:**
- Create: `broker/policy.py`

**Why this seam exists:** stage 2 replaces `AlwaysApprovePolicy` with a YAML-driven rules engine (auto-approve / route-to-human / deny). Stage 1 only needs the interface and a trivial implementation so the request → decision → grant pipeline can be proven before real rules exist.

- [x] **Step 1: Define the interface and the stage-1 implementation**

```python
"""PolicyEngine is the seam for stage 2's real rule evaluation. Stage 1 uses
a trivial always-approve implementation so the request -> decision -> grant
pipeline can be built and tested end to end before any real policy logic
exists."""
from abc import ABC, abstractmethod

from broker.models import PolicyDecision, PolicyDecisionType


class PolicyEngine(ABC):
    @abstractmethod
    def decide(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        ...


class AlwaysApprovePolicy(PolicyEngine):
    def decide(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        return PolicyDecision(
            decision=PolicyDecisionType.AUTO_APPROVE,
            reason="stage-1 placeholder policy: all requests auto-approved",
        )
```

- [x] **Step 2: Verify by import**

Run: `python3 -c "from broker.policy import AlwaysApprovePolicy; d = AlwaysApprovePolicy().decide('r','read',60,'x'); assert d.decision.value == 'AUTO_APPROVE'"`
Expected: no output, exit code 0.

## Task 5: Database layer

**Files:**
- Create: `broker/db.py`

**Why this design:** file-based SQLite (never `:memory:`) so state survives a process restart. The race-condition requirement (grant/expire/revoke landing at the same time) is answered here, not in `Broker`: `expire_due_grants` and `revoke_grant` are both conditional `UPDATE ... WHERE status = 'ACTIVE'` — whichever transaction commits first wins atomically (SQLite serializes writers), and the loser's `UPDATE` affects zero rows instead of clobbering the winning status.

- [x] **Step 1: Define the schema and full data-access contract**

```python
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
```

- [x] **Step 2: Verify by import**

Run: `python3 -c "from broker.db import Database; import tempfile, os; p = tempfile.mktemp(); Database(p); os.remove(p)"`
Expected: no output, exit code 0.

## Task 6: Broker orchestrator

**Files:**
- Create: `broker/broker.py`

**Contract:**

```python
class Broker:
    def __init__(self, db: Database, policy: PolicyEngine, connector: ResourceConnector, clock=None): ...
    def request_access(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> Grant: ...
    def is_active(self, grant_id: int) -> bool: ...
    def revoke(self, grant_id: int, revoked_by: str) -> None: ...
    def sweep_expired(self) -> int: ...
```

- [x] **Step 1: Implement against the contract**

```python
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
```

## Task 7: End-to-end evals

**Files:**
- Create: `tests/test_broker_e2e.py`
- Create: `pytest.ini` (so `broker` is importable without installing the package: `[pytest]\npythonpath = .`)
- Create: `requirements.txt` (`pytest>=7.0`)

Each test opens a fresh `Broker` against a real (file-based, `tmp_path`-scoped) SQLite database — not `:memory:` — so persistence and the restart scenario are exercised for real, and a `FakeClock` replaces sleeping.

- [x] **Step 1: Write the six eval tests**

```python
"""
End-to-end evals for stage 1: JIT token disbursement.

Each test opens the Broker against a real (file-based) SQLite database so we
exercise actual persistence, not an in-memory stand-in. A FakeClock lets us
control time deterministically instead of sleeping in tests.
"""
import pytest

from broker.broker import Broker
from broker.clock import FakeClock
from broker.connector import MockConnector
from broker.db import Database
from broker.models import AuditEventType, GrantStatus
from broker.policy import AlwaysApprovePolicy


def make_broker(db_path, clock=None, connector=None):
    clock = clock or FakeClock()
    connector = connector or MockConnector()
    db = Database(str(db_path))
    broker = Broker(db=db, clock=clock, policy=AlwaysApprovePolicy(), connector=connector)
    return broker, clock, connector, db


def test_request_access_issues_active_grant_immediately(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db")

    grant = broker.request_access(
        requester="alice",
        resource="prod-db",
        access_level="read",
        duration_seconds=3600,
        reason="debugging incident 123",
    )

    assert grant.status == GrantStatus.ACTIVE
    assert broker.is_active(grant.id) is True
    assert grant.expires_at == clock.now() + 3600
    assert connector.issued == [(grant.resource, grant.access_level, grant.token)]


def test_grant_expires_after_duration_elapses(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db")

    grant = broker.request_access(
        requester="bob",
        resource="prod-db",
        access_level="write",
        duration_seconds=60,
        reason="hotfix",
    )
    assert broker.is_active(grant.id) is True

    clock.advance(61)

    # is_active must reflect expiry even before any sweep has run
    assert broker.is_active(grant.id) is False

    expired_count = broker.sweep_expired()
    assert expired_count == 1
    assert db.get_grant(grant.id).status == GrantStatus.EXPIRED


def test_revoke_active_grant_makes_it_inactive_immediately(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db")

    grant = broker.request_access(
        requester="carol",
        resource="prod-queue",
        access_level="admin",
        duration_seconds=3600,
        reason="on-call",
    )

    broker.revoke(grant.id, revoked_by="security-team")

    assert broker.is_active(grant.id) is False
    assert db.get_grant(grant.id).status == GrantStatus.REVOKED
    assert connector.revoked == [(grant.resource, grant.access_level, grant.token)]


def test_audit_log_records_full_lifecycle(tmp_path):
    broker, clock, connector, db = make_broker(tmp_path / "broker.db")

    grant = broker.request_access(
        requester="dave",
        resource="prod-db",
        access_level="read",
        duration_seconds=60,
        reason="report generation",
    )
    clock.advance(61)
    broker.sweep_expired()

    events = [e.event_type for e in db.get_audit_log(request_id=grant.request_id)]
    assert events == [
        AuditEventType.REQUESTED,
        AuditEventType.POLICY_DECIDED,
        AuditEventType.GRANTED,
        AuditEventType.EXPIRED,
    ]


def test_expired_grant_cannot_be_revoked(tmp_path):
    """Guards the state-machine transition used to resolve the
    grant/expire/revoke race: a terminal grant stays terminal."""
    broker, clock, connector, db = make_broker(tmp_path / "broker.db")

    grant = broker.request_access(
        requester="erin",
        resource="prod-db",
        access_level="read",
        duration_seconds=60,
        reason="audit",
    )
    clock.advance(61)
    broker.sweep_expired()
    assert db.get_grant(grant.id).status == GrantStatus.EXPIRED

    broker.revoke(grant.id, revoked_by="security-team")

    # still EXPIRED, not flipped to REVOKED, and the connector was never
    # asked to revoke a token that's already dead
    assert db.get_grant(grant.id).status == GrantStatus.EXPIRED
    assert connector.revoked == []


def test_service_restart_recovers_state_from_db(tmp_path):
    db_path = tmp_path / "broker.db"
    clock = FakeClock()
    connector = MockConnector()

    broker1, _, _, _ = make_broker(db_path, clock=clock, connector=connector)
    grant = broker1.request_access(
        requester="frank",
        resource="prod-db",
        access_level="read",
        duration_seconds=3600,
        reason="migration",
    )

    # Simulate a process restart: brand new Broker/Database pointed at the
    # same file, sharing nothing in memory with broker1.
    broker2, clock2, _, db2 = make_broker(db_path, clock=clock, connector=connector)

    assert broker2.is_active(grant.id) is True
    assert db2.get_grant(grant.id).resource == "prod-db"
```

- [x] **Step 2: Verify RED**

Run: `pytest tests/test_broker_e2e.py -v`
Actual result (before `broker/` existed): `ModuleNotFoundError: No module named 'broker'` — fails for the right reason (feature missing, not a typo).

- [x] **Step 3: Implement Tasks 1–6, then verify GREEN**

Run: `pytest tests/test_broker_e2e.py -v`
First actual result: 5 passed, 1 failed — `test_audit_log_records_full_lifecycle` failed because the test queried `get_audit_log(grant_id=...)`, which correctly excludes `REQUESTED`/`POLICY_DECIDED` (no grant exists yet at that point). This was a test bug, not a broker bug; fixed by querying `get_audit_log(request_id=grant.request_id)` instead.

Final result: `6 passed in 0.03s`.

- [x] **Step 4: Commit**

```bash
git init
git add broker/ tests/ pytest.ini requirements.txt README.md
git commit -m "feat: JIT broker stage 1 walking skeleton (request -> mock grant -> expiry/revoke, 6 evals green)"
```

(Not yet run — this repo has no `.git` yet. Run this before starting Stage 2, so Stage 1 is a clean checkpoint to diff against.)

## Task 8: README documentation

**Files:**
- Modify: `README.md`

- [x] **Step 1: Document what stage 1 covers, how to run it, and what's deferred**

Done — see the "Stage 1 — Walking Skeleton" section of `README.md`, which lists the six eval scenarios and an explicit "not yet built" list (real policy rules, human approval + timeout, AI triage, duplicate-request rejection, CLI/API layer).

---

## Self-Review

**1. Spec coverage (stage-1 scope only — full spec is intentionally deferred):**
- ✅ "A user can request time-boxed access: resource, access level, duration, reason" — `Broker.request_access`.
- ✅ "Policy engine decides ... and records why" — `PolicyEngine.decide` + `POLICY_DECIDED` audit row (decision is hardcoded to auto-approve in stage 1; real rules are Stage 2).
- ✅ "Grants are time-boxed and expire automatically; an expired or revoked grant is no longer active" — `is_active`, `sweep_expired`, guarded transitions.
- ✅ "The grant is mocked behind an interface" — `ResourceConnector`/`MockConnector`.
- ✅ "Append-only audit log captures every request, decision, grant, expiry, revocation" — `audit_log` table, insert-only, no update/delete method exists on `Database`.
- ✅ "Service restarts with grants still outstanding" edge case — `test_service_restart_recovers_state_from_db`.
- ✅ "A grant expires mid-revoke" race — `test_expired_grant_cannot_be_revoked` + guarded `UPDATE ... WHERE status='ACTIVE'`.
- ⛔ Deferred to Stage 2+ (explicitly, by design): real policy rules, human approval routing, AI triage, duplicate-request rejection, CLI/API surface.

**2. Placeholder scan:** none — every step above has real code, real commands, and real (or explicitly marked "not yet run") output.

**3. Type consistency:** `Grant`, `GrantStatus`, `PolicyDecision`, `PolicyDecisionType`, `AuditEvent`, `AuditEventType` are defined once in `broker/models.py` (Task 1) and used identically by name in every later task — no renames.

## Deviation Note (read before Stage 2)

Stage 1 was built by writing all six modules together and verifying with one whole-suite RED run and one whole-suite GREEN run, rather than the stricter contract → boundary-test → TDD cadence per task that this skill prescribes. That was acceptable here because every stage-1 module is a small, mechanical seam (an interface plus one trivial implementation) with no real business logic to get wrong. **Stage 2 (real policy rules, human approval, AI triage) has actual business logic and should follow the per-task RED/GREEN cadence strictly** — each new decision rule, each approval-state transition, and the AI-triage defer-on-low-confidence logic each need their own failing test written and watched-red before implementation.
