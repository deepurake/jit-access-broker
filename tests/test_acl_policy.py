"""
Evals for AclPolicyEngine.evaluate -- the ACL ceiling check: does this role's
acl_rules entry (loaded from acl.yaml into the acl_rules table) permit this
resource/access_level/duration combination. Seeded via the already-tested
Database.load_acl_rules(), not reinvented here.
"""
from broker.acl_policy import AclDecision, AclPolicyEngine
from broker.db import Database


def make_engine(tmp_path, rules):
    db = Database(str(tmp_path / "test.db"))
    db.load_acl_rules(rules)
    return AclPolicyEngine(db)


def test_no_role_is_denied(tmp_path):
    engine = make_engine(tmp_path, [])

    decision = engine.evaluate(role=None, resource="prod-db", access_level="read", duration_seconds=600)

    assert decision.allowed is False
    assert "no assigned role" in decision.reason


def test_role_with_no_rules_at_all_is_denied(tmp_path):
    engine = make_engine(tmp_path, [])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="read", duration_seconds=600)

    assert decision.allowed is False
    assert "no ACL rule permits role 'engineer'" in decision.reason


def test_role_with_a_rule_but_non_matching_resource_is_denied(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "engineer", "resource_pattern": "staging-db", "max_access_level": "admin", "max_duration_seconds": 7200},
    ])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="read", duration_seconds=600)

    assert decision.allowed is False
    assert "no ACL rule permits role 'engineer'" in decision.reason
    assert "prod-db" in decision.reason


def test_wildcard_pattern_matches_and_allows_within_ceiling(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200},
    ])

    decision = engine.evaluate(role="oncall", resource="prod-db", access_level="admin", duration_seconds=3600)

    assert decision.allowed is True
    assert "oncall" in decision.reason


def test_access_level_exceeding_rule_ceiling_is_denied(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600},
    ])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="admin", duration_seconds=600)

    assert decision.allowed is False
    assert "capped at 'read'" in decision.reason
    assert "requested 'admin'" in decision.reason


def test_duration_exceeding_rule_ceiling_is_denied(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600},
    ])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="read", duration_seconds=7200)

    assert decision.allowed is False
    assert "7200" in decision.reason
    assert "3600" in decision.reason


def test_request_fully_within_ceiling_is_allowed(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "write", "max_duration_seconds": 3600},
    ])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="read", duration_seconds=1800)

    assert decision.allowed is True
    assert "engineer" in decision.reason
    assert "prod-db" in decision.reason


def test_unrecognized_access_level_is_denied(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600},
    ])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="superuser", duration_seconds=600)

    assert decision.allowed is False
    assert "unrecognized access level 'superuser'" in decision.reason


def test_decision_is_a_dataclass_with_allowed_and_reason(tmp_path):
    engine = make_engine(tmp_path, [
        {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600},
    ])

    decision = engine.evaluate(role="engineer", resource="prod-db", access_level="read", duration_seconds=600)

    assert isinstance(decision, AclDecision)
    assert decision.allowed is True
