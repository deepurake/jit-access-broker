"""
Evals for the UserDirectory seam -- an ABC over "who has what role" so the
rest of the broker depends on an interface, not raw DB calls. In production,
DatabaseUserDirectory's user_roles table would be kept in sync with a real
IdP (e.g. Okta group membership) by a separate sync job; this class only
reads it.
"""
from broker.db import Database
from broker.user_directory import DatabaseUserDirectory, UserDirectory


def make_db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def test_returns_role_for_a_requester_with_an_assigned_role(tmp_path):
    db = make_db(tmp_path)
    db.set_user_role("alice", "engineer")
    directory = DatabaseUserDirectory(db)

    assert directory.get_role("alice") == "engineer"


def test_returns_none_for_a_requester_with_no_assigned_role(tmp_path):
    db = make_db(tmp_path)
    directory = DatabaseUserDirectory(db)

    assert directory.get_role("nobody") is None


def test_database_user_directory_is_a_real_user_directory_subclass(tmp_path):
    db = make_db(tmp_path)
    directory = DatabaseUserDirectory(db)

    assert isinstance(directory, UserDirectory)
