"""Parses the human-authored, git-reviewed acl.yaml (nested role -> list of
rules) into the flat list-of-dicts shape Database.load_acl_rules() expects.
This is the only place that understands the YAML's nested shape -- the
runtime (AclPolicyEngine, the acl_rules table) never reads the file
directly, only the synced table. Call site: db.load_acl_rules(load_acl_yaml(path))."""
from typing import List

import yaml


def load_acl_yaml(path: str) -> List[dict]:
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    roles = data.get("roles") or {}
    flat_rules = []
    for role, rules in roles.items():
        for rule in rules:
            flat_rules.append({
                "role": role,
                "resource_pattern": rule["resource_pattern"],
                "max_access_level": rule["max_access_level"],
                "max_duration_seconds": rule["max_duration_seconds"],
            })
    return flat_rules
