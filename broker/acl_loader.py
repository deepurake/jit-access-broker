"""Parses the human-authored, git-reviewed acl.yaml. This is the only place
that understands the YAML's shape -- the runtime (AclPolicyEngine, the
acl_rules and approver_roles tables) never reads the file directly, only the
synced tables.

Two independent top-level keys:
  roles:           role -> list of rules; load_acl_yaml flattens it into the
                   list-of-dicts shape Database.load_acl_rules() expects.
  approver_roles:  list of role names that may decide a pending human review;
                   load_approver_roles reads it for Database.load_approver_roles().

Call site (broker.cli load-acl):
    db.load_acl_rules(load_acl_yaml(path))
    db.load_approver_roles(load_approver_roles(path))"""
from typing import List

import yaml


def _read(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_acl_yaml(path: str) -> List[dict]:
    roles = _read(path).get("roles") or {}
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


def load_approver_roles(path: str) -> List[str]:
    """The `approver_roles:` list, in file order. An absent or empty key
    yields [] -- which, once loaded, means nobody can approve. That is the
    intended fail-closed default, not an error."""
    return [str(role) for role in (_read(path).get("approver_roles") or [])]
