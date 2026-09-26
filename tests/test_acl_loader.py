"""
Evals for broker.acl_loader -- parses the human-authored, git-reviewed
acl.yaml. load_acl_yaml turns the nested role -> list-of-rules shape into the
flat list-of-dicts shape Database.load_acl_rules() expects, so the call site
is just `db.load_acl_rules(load_acl_yaml("acl.yaml"))`; load_approver_roles
reads the top-level `approver_roles:` list (who may decide a human review).
"""
from broker.acl_loader import load_acl_yaml, load_approver_roles

YAML_TEXT = """\
approver_roles: [security, oncall]
roles:
  engineer:
    - resource_pattern: "prod-db"
      max_access_level: read
      max_duration_seconds: 3600
  oncall:
    - resource_pattern: "prod-*"
      max_access_level: admin
      max_duration_seconds: 7200
    - resource_pattern: "staging-*"
      max_access_level: admin
      max_duration_seconds: 3600
  intern:
    - resource_pattern: "staging-*"
      max_access_level: read
      max_duration_seconds: 1800
"""


def write_yaml(tmp_path, text=YAML_TEXT):
    path = tmp_path / "acl.yaml"
    path.write_text(text)
    return str(path)


def test_flattens_nested_roles_into_flat_list_of_dicts(tmp_path):
    path = write_yaml(tmp_path)

    rules = load_acl_yaml(path)

    assert isinstance(rules, list)
    assert len(rules) == 4


def test_each_rule_carries_its_role_and_the_four_expected_keys(tmp_path):
    path = write_yaml(tmp_path)

    rules = load_acl_yaml(path)

    engineer_rules = [r for r in rules if r["role"] == "engineer"]
    assert len(engineer_rules) == 1
    rule = engineer_rules[0]
    assert set(rule.keys()) == {"role", "resource_pattern", "max_access_level", "max_duration_seconds"}
    assert rule["resource_pattern"] == "prod-db"
    assert rule["max_access_level"] == "read"
    assert rule["max_duration_seconds"] == 3600


def test_a_role_with_multiple_rules_produces_multiple_flat_entries(tmp_path):
    path = write_yaml(tmp_path)

    rules = load_acl_yaml(path)

    oncall_rules = [r for r in rules if r["role"] == "oncall"]
    assert len(oncall_rules) == 2
    patterns = {r["resource_pattern"] for r in oncall_rules}
    assert patterns == {"prod-*", "staging-*"}


def test_output_is_ready_to_pass_directly_to_database_load_acl_rules(tmp_path):
    path = write_yaml(tmp_path)

    from broker.db import Database
    db = Database(str(tmp_path / "test.db"))
    rules = load_acl_yaml(path)

    db.load_acl_rules(rules)

    assert len(db.get_acl_rules_for_role("intern")) == 1
    assert db.get_acl_rules_for_role("intern")[0]["resource_pattern"] == "staging-*"


def test_empty_roles_section_yields_empty_list(tmp_path):
    path = write_yaml(tmp_path, text="roles: {}\n")

    rules = load_acl_yaml(path)

    assert rules == []


# -- approver_roles: which roles may decide a pending human review -- #


def test_load_approver_roles_returns_the_listed_roles_in_order(tmp_path):
    path = write_yaml(tmp_path)

    assert load_approver_roles(path) == ["security", "oncall"]


def test_load_approver_roles_is_empty_when_the_key_is_absent(tmp_path):
    """No `approver_roles:` means nobody is an approver (fail closed), not a
    crash and not some implicit default."""
    path = write_yaml(tmp_path, text="roles: {}\n")

    assert load_approver_roles(path) == []


def test_load_approver_roles_accepts_a_block_list_too(tmp_path):
    path = write_yaml(tmp_path, text="approver_roles:\n  - security\nroles: {}\n")

    assert load_approver_roles(path) == ["security"]


def test_load_approver_roles_does_not_change_load_acl_yaml(tmp_path):
    """The two keys are independent: approver_roles is not a role with rules,
    and a role can appear in both (oncall people request AND approve)."""
    path = write_yaml(tmp_path)

    rules = load_acl_yaml(path)

    assert len(rules) == 4
    assert "security" not in {r["role"] for r in rules}
