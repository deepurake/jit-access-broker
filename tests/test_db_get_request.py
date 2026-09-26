"""Evals for Database.get_request -- fetches a previously-created request row
back out, the same pattern as get_grant. Needed by Broker.resolve_approval to
look up the original request's resource/access_level/duration when a human
approves a pending review."""
from broker.db import Database


def make_db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def test_get_request_returns_the_right_fields(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)

    request = db.get_request(request_id)

    assert request.id == request_id
    assert request.requester == "alice"
    assert request.resource == "prod-db"
    assert request.access_level == "admin"
    assert request.duration_seconds == 3600
    assert request.reason == "reason"
    assert request.created_at == 1000


def test_get_request_for_unknown_id_is_none(tmp_path):
    db = make_db(tmp_path)

    assert db.get_request(999) is None
