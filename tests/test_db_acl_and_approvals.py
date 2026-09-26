"""
Evals for the three schema additions that back the ACL policy engine,
user-role directory, and human-approval flow: user_roles, acl_rules, and
pending_approvals. Same guarded-transition pattern as grants (db.py) --
resolve_pending_approval and sweep_pending_timeouts are both conditional
UPDATE ... WHERE status='PENDING', for the same race-safety reason.
"""
from broker.db import Database
from broker.models import PendingApprovalStatus


def make_db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def test_user_role_round_trips(tmp_path):
    db = make_db(tmp_path)

    db.set_user_role("alice", "engineer")

    assert db.get_role_for_requester("alice") == "engineer"


def test_unknown_requester_has_no_role(tmp_path):
    db = make_db(tmp_path)

    assert db.get_role_for_requester("nobody") is None


def test_setting_a_role_twice_updates_it(tmp_path):
    db = make_db(tmp_path)
    db.set_user_role("alice", "engineer")

    db.set_user_role("alice", "oncall")

    assert db.get_role_for_requester("alice") == "oncall"


def test_load_acl_rules_and_query_by_role(tmp_path):
    db = make_db(tmp_path)

    db.load_acl_rules([
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600},
        {"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200},
    ])

    engineer_rules = db.get_acl_rules_for_role("engineer")
    assert len(engineer_rules) == 1
    assert engineer_rules[0]["resource_pattern"] == "prod-db"
    assert db.get_acl_rules_for_role("intern") == []


def test_load_acl_rules_replaces_previous_rules(tmp_path):
    db = make_db(tmp_path)
    db.load_acl_rules([
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600},
    ])

    db.load_acl_rules([
        {"role": "engineer", "resource_pattern": "staging-db", "max_access_level": "admin", "max_duration_seconds": 7200},
    ])

    rules = db.get_acl_rules_for_role("engineer")
    assert len(rules) == 1
    assert rules[0]["resource_pattern"] == "staging-db"


def test_create_and_fetch_pending_approval(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)

    pending = db.create_pending_approval(request_id, "tok-abc123", created_at=1000, deadline_at=1000 + 14400)

    assert pending.status == PendingApprovalStatus.PENDING
    fetched = db.get_pending_approval_by_token("tok-abc123")
    assert fetched.request_id == request_id
    assert fetched.deadline_at == 1000 + 14400


def test_get_pending_approval_by_unknown_token_is_none(tmp_path):
    db = make_db(tmp_path)

    assert db.get_pending_approval_by_token("never-issued") is None


def test_resolve_pending_approval_transitions_to_approved(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)
    db.create_pending_approval(request_id, "tok-abc123", created_at=1000, deadline_at=5000)

    resolved = db.resolve_pending_approval("tok-abc123", PendingApprovalStatus.APPROVED, decided_by="bob", now=2000)

    assert resolved is True
    pending = db.get_pending_approval_by_token("tok-abc123")
    assert pending.status == PendingApprovalStatus.APPROVED
    assert pending.decided_by == "bob"
    assert pending.decided_at == 2000


def test_resolving_an_already_resolved_approval_is_a_noop(tmp_path):
    """Guards the same race the grant state machine guards: a terminal
    pending_approval stays terminal, and a second resolve attempt (e.g. two
    people clicking the same link) does not flip it or overwrite who decided."""
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)
    db.create_pending_approval(request_id, "tok-abc123", created_at=1000, deadline_at=5000)
    db.resolve_pending_approval("tok-abc123", PendingApprovalStatus.APPROVED, decided_by="bob", now=2000)

    second_attempt = db.resolve_pending_approval("tok-abc123", PendingApprovalStatus.DENIED, decided_by="carol", now=3000)

    assert second_attempt is False
    pending = db.get_pending_approval_by_token("tok-abc123")
    assert pending.status == PendingApprovalStatus.APPROVED
    assert pending.decided_by == "bob"


def test_sweep_pending_timeouts_times_out_due_approvals(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)
    db.create_pending_approval(request_id, "tok-abc123", created_at=1000, deadline_at=5000)

    timed_out = db.sweep_pending_timeouts(now=5001)

    assert len(timed_out) == 1
    assert timed_out[0].status == PendingApprovalStatus.TIMED_OUT
    assert db.get_pending_approval_by_token("tok-abc123").status == PendingApprovalStatus.TIMED_OUT


def test_sweep_pending_timeouts_ignores_approvals_not_yet_due(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)
    db.create_pending_approval(request_id, "tok-abc123", created_at=1000, deadline_at=5000)

    timed_out = db.sweep_pending_timeouts(now=2000)

    assert timed_out == []
    assert db.get_pending_approval_by_token("tok-abc123").status == PendingApprovalStatus.PENDING


def test_sweep_does_not_time_out_an_already_decided_approval(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)
    db.create_pending_approval(request_id, "tok-abc123", created_at=1000, deadline_at=5000)
    db.resolve_pending_approval("tok-abc123", PendingApprovalStatus.APPROVED, decided_by="bob", now=2000)

    timed_out = db.sweep_pending_timeouts(now=6000)

    assert timed_out == []
    assert db.get_pending_approval_by_token("tok-abc123").status == PendingApprovalStatus.APPROVED
