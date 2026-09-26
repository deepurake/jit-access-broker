"""
Evals for the read-only RequesterHistory projection: counts derived from the
requests / grants / audit_log / pending_approvals tables for one requester.
Seeded through the public Database methods only -- the reader owns its own
SELECTs, so the tests pin down what those SELECTs must agree with.
"""
from broker.db import Database
from broker.models import AuditEventType, PendingApprovalStatus
from broker.requester_history import RequesterHistory, RequesterHistoryReader

NOW = 1_700_000_000
HOUR = 3600


def make_db(tmp_path):
    return Database(str(tmp_path / "history.db"))


def grant_for(db, requester, resource, access_level, granted_at, ttl=HOUR, token="tok"):
    """Request + grant pair, the way the broker creates them."""
    request_id = db.create_request(requester, resource, access_level, ttl, "reason", at=granted_at)
    return db.create_grant(request_id, requester, resource, access_level, token, granted_at, granted_at + ttl)


# -- brand-new requester -------------------------------------------------- #


def test_new_requester_has_all_zero_counts(tmp_path):
    db = make_db(tmp_path)

    history = RequesterHistoryReader(db).for_request("newbie", "prod-db", "read", now=NOW)

    assert history.requester == "newbie"
    assert history.total_requests == 0
    assert history.approved_grants == 0
    assert history.active_grants == 0
    assert history.revocations == 0
    assert history.denials == 0
    assert history.human_approvals == 0
    assert history.pending_reviews == 0
    assert history.same_resource_grants == 0
    assert history.same_scope_grants == 0
    assert history.last_denial_at is None
    assert history.last_revocation_at is None
    assert history.is_new is True
    assert "approved_grants=0" in history.summary()


def test_other_requesters_history_does_not_leak(tmp_path):
    db = make_db(tmp_path)
    grant_for(db, "bob", "prod-db", "read", granted_at=NOW - HOUR)

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "read", now=NOW)

    assert history.total_requests == 0
    assert history.approved_grants == 0
    assert history.is_new is True


# -- grants --------------------------------------------------------------- #


def test_grant_counts_distinguish_active_expired_and_revoked(tmp_path):
    db = make_db(tmp_path)
    # Still live at NOW: granted 10 minutes ago, one-hour TTL.
    grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 600, token="live")
    # Expired by the clock (row still says ACTIVE -- the sweeper hasn't run).
    grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 2 * HOUR, token="stale")
    # Revoked.
    revoked = grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 3 * HOUR, token="gone")
    db.revoke_grant(revoked.id)
    db.append_audit(revoked.request_id, revoked.id, AuditEventType.REVOKED, "manual revoke", at=NOW - 2 * HOUR - 1800)

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "read", now=NOW)

    assert history.approved_grants == 3
    assert history.active_grants == 1
    assert history.revocations == 1
    assert history.last_revocation_at == NOW - 2 * HOUR - 1800
    assert history.total_requests == 3
    assert history.is_new is False


def test_same_resource_and_same_scope_counts(tmp_path):
    db = make_db(tmp_path)
    grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 5 * HOUR, token="a")
    grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 4 * HOUR, token="b")
    grant_for(db, "alice", "prod-db", "admin", granted_at=NOW - 3 * HOUR, token="c")
    grant_for(db, "alice", "staging-db", "admin", granted_at=NOW - 2 * HOUR, token="d")

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "read", now=NOW)

    assert history.approved_grants == 4
    assert history.same_resource_grants == 3
    assert history.same_scope_grants == 2


# -- denials -------------------------------------------------------------- #


def test_denials_count_both_policy_and_human_denials(tmp_path):
    db = make_db(tmp_path)
    r1 = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - 3 * HOUR)
    db.append_audit(r1, None, AuditEventType.DENIED, "acl ceiling", at=NOW - 3 * HOUR)
    r2 = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - HOUR)
    db.append_audit(r2, None, AuditEventType.HUMAN_DENIED, "reviewer said no", at=NOW - HOUR)
    # A denial for someone else must not be attributed to alice.
    r3 = db.create_request("bob", "prod-db", "admin", HOUR, "reason", at=NOW - 600)
    db.append_audit(r3, None, AuditEventType.DENIED, "acl ceiling", at=NOW - 600)

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "admin", now=NOW)

    assert history.denials == 2
    assert history.last_denial_at == NOW - HOUR
    assert history.had_recent_negative_event(now=NOW, window_seconds=2 * HOUR) is True
    assert history.had_recent_negative_event(now=NOW, window_seconds=1800) is False


def test_recent_negative_event_sees_revocations_too(tmp_path):
    db = make_db(tmp_path)
    revoked = grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 2 * HOUR)
    db.revoke_grant(revoked.id)
    db.append_audit(revoked.request_id, revoked.id, AuditEventType.REVOKED, "revoked", at=NOW - HOUR)

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "read", now=NOW)

    assert history.denials == 0
    assert history.last_revocation_at == NOW - HOUR
    assert history.had_recent_negative_event(now=NOW, window_seconds=2 * HOUR) is True
    assert history.had_recent_negative_event(now=NOW, window_seconds=1800) is False


def test_human_approvals_counted_from_audit_log(tmp_path):
    db = make_db(tmp_path)
    r1 = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - HOUR)
    db.append_audit(r1, None, AuditEventType.HUMAN_APPROVED, "reviewer=carol", at=NOW - HOUR + 60)
    r2 = db.create_request("alice", "prod-db", "read", HOUR, "reason", at=NOW - 600)
    db.append_audit(r2, None, AuditEventType.GRANTED, "auto", at=NOW - 600)

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "admin", now=NOW)

    assert history.human_approvals == 1


# -- pending approvals ---------------------------------------------------- #


def test_pending_reviews_counts_only_pending_rows(tmp_path):
    db = make_db(tmp_path)
    r1 = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - HOUR)
    db.create_pending_approval(r1, "tok-pending", created_at=NOW - HOUR, deadline_at=NOW + HOUR)
    r2 = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - 2 * HOUR)
    db.create_pending_approval(r2, "tok-approved", created_at=NOW - 2 * HOUR, deadline_at=NOW + HOUR)
    db.resolve_pending_approval("tok-approved", PendingApprovalStatus.APPROVED, "carol", now=NOW - HOUR)
    r3 = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - 3 * HOUR)
    db.create_pending_approval(r3, "tok-timedout", created_at=NOW - 3 * HOUR, deadline_at=NOW - HOUR)
    db.sweep_pending_timeouts(now=NOW)
    r4 = db.create_request("bob", "prod-db", "admin", HOUR, "reason", at=NOW - HOUR)
    db.create_pending_approval(r4, "tok-bob", created_at=NOW - HOUR, deadline_at=NOW + HOUR)

    history = RequesterHistoryReader(db).for_request("alice", "prod-db", "admin", now=NOW)

    assert history.pending_reviews == 1
    assert history.total_requests == 3


# -- exclude_request_id --------------------------------------------------- #


def test_exclude_request_id_removes_current_request_from_totals(tmp_path):
    db = make_db(tmp_path)
    grant_for(db, "alice", "prod-db", "read", granted_at=NOW - HOUR)
    current = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW)

    reader = RequesterHistoryReader(db)
    without_exclusion = reader.for_request("alice", "prod-db", "admin", now=NOW)
    with_exclusion = reader.for_request("alice", "prod-db", "admin", now=NOW, exclude_request_id=current)

    assert without_exclusion.total_requests == 2
    assert with_exclusion.total_requests == 1
    # Everything else is unaffected -- the current request has no grant/audit rows yet.
    assert with_exclusion.approved_grants == without_exclusion.approved_grants == 1


# -- summary -------------------------------------------------------------- #


def test_summary_is_single_line_and_deterministic(tmp_path):
    db = make_db(tmp_path)
    grant_for(db, "alice", "prod-db", "read", granted_at=NOW - 600)
    r = db.create_request("alice", "prod-db", "admin", HOUR, "reason", at=NOW - HOUR)
    db.append_audit(r, None, AuditEventType.DENIED, "acl ceiling", at=NOW - HOUR)

    reader = RequesterHistoryReader(db)
    first = reader.for_request("alice", "prod-db", "read", now=NOW).summary()
    second = reader.for_request("alice", "prod-db", "read", now=NOW).summary()

    assert first == second
    assert "\n" not in first
    assert first.startswith("requester=alice ")
    assert "total_requests=2" in first
    assert "approved_grants=1" in first
    assert "active=1" in first
    assert "denials=1" in first
    assert f"last_denial_at={NOW - HOUR}" in first
    assert "last_revocation_at=none" in first


def test_summary_from_plain_dataclass_matches_documented_format():
    history = RequesterHistory(
        requester="alice",
        total_requests=5,
        approved_grants=4,
        active_grants=1,
        revocations=0,
        denials=1,
        human_approvals=1,
        pending_reviews=0,
        same_resource_grants=3,
        same_scope_grants=2,
        last_denial_at=1700000000,
        last_revocation_at=None,
    )

    assert history.summary() == (
        "requester=alice total_requests=5 approved_grants=4 active=1 revocations=0 "
        "denials=1 human_approvals=1 pending=0 same_resource=3 same_scope=2 "
        "last_denial_at=1700000000 last_revocation_at=none"
    )
