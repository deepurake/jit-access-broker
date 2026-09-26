"""
Evals for broker.acl_loader.load_acl_yaml -- parses the human-authored,
git-reviewed acl.yaml (nested role -> list-of-rules shape) into the flat
list-of-dicts shape Database.load_acl_rules() expects, so the call site is
just `db.load_acl_rules(load_acl_yaml("acl.yaml"))`.
"""
from broker.acl_loader import load_acl_yaml

YAML_TEXT = """\
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
