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
