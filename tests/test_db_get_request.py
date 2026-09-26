"""Evals for Database.get_request -- fetches a previously-created request row
back out, the same pattern as get_grant. Needed by Broker.resolve_approval to
look up the original request's resource/access_level/duration when a human
approves a pending review."""
import sqlite3

from broker.db import Database
from broker.models import RequestStatus


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


# -- request status column (T9b item D) -- #


def test_new_request_starts_in_pending_policy_status(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)

    assert db.get_request(request_id).status == RequestStatus.PENDING_POLICY


def test_set_request_status_round_trips(tmp_path):
    db = make_db(tmp_path)
    request_id = db.create_request("alice", "prod-db", "admin", 3600, "reason", at=1000)

    db.set_request_status(request_id, RequestStatus.AUTO_APPROVED)

    assert db.get_request(request_id).status == RequestStatus.AUTO_APPROVED


OLD_REQUESTS_TABLE = """
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    resource TEXT NOT NULL,
    access_level TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def test_opening_a_pre_status_column_database_migrates_it(tmp_path):
    """SQLite files already sitting in docker volumes were created before the
    requests.status column existed. Opening them must add the column (with
    the PENDING_POLICY default) rather than blowing up on the first SELECT."""
    path = str(tmp_path / "old.db")
    raw = sqlite3.connect(path)
    raw.executescript(OLD_REQUESTS_TABLE)
    raw.execute(
        "INSERT INTO requests (requester, resource, access_level, duration_seconds, reason, created_at) "
        "VALUES ('alice', 'prod-db', 'read', 600, 'legacy row', 1000)"
    )
    raw.commit()
    raw.close()

    db = Database(path)

    request = db.get_request(1)
    assert request.requester == "alice"
    assert request.status == RequestStatus.PENDING_POLICY
    # and the migration is idempotent: reopening does not try to add it twice
    Database(path)
