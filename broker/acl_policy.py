"""The ACL ceiling check: given a requester's role, does any acl_rules entry
for that role (synced from acl.yaml via Database.load_acl_rules) permit the
requested resource / access_level / duration combination."""
import fnmatch
from dataclasses import dataclass

from broker.db import Database

ACCESS_LEVEL_RANK = {"read": 0, "write": 1, "admin": 2}


@dataclass
class AclDecision:
    allowed: bool
    reason: str


class AclPolicyEngine:
    def __init__(self, db: Database):
        self.db = db

    def evaluate(self, role, resource: str, access_level: str, duration_seconds: int) -> AclDecision:
        if role is None:
            return AclDecision(allowed=False, reason="requester has no assigned role")

        rules = self.db.get_acl_rules_for_role(role)
        # Known limitation: if multiple rules for this role match the same
        # resource, the first match (DB row order) wins -- overlapping rules
        # for a role aren't specially resolved (no "most specific pattern"
        # or "most permissive" tie-breaking).
        matched_rule = None
        for rule in rules:
            if fnmatch.fnmatch(resource, rule["resource_pattern"]):
                matched_rule = rule
                break

        if matched_rule is None:
            return AclDecision(
                allowed=False,
                reason=f"no ACL rule permits role '{role}' to request '{resource}'",
            )

        if access_level not in ACCESS_LEVEL_RANK:
            return AclDecision(allowed=False, reason=f"unrecognized access level '{access_level}'")

        if ACCESS_LEVEL_RANK[access_level] > ACCESS_LEVEL_RANK[matched_rule["max_access_level"]]:
            return AclDecision(
                allowed=False,
                reason=(
                    f"role '{role}' is capped at '{matched_rule['max_access_level']}' for '{resource}', "
                    f"requested '{access_level}'"
                ),
            )

        if duration_seconds > matched_rule["max_duration_seconds"]:
            return AclDecision(
                allowed=False,
                reason=(
                    f"requested duration {duration_seconds}s exceeds role '{role}''s ceiling of "
                    f"{matched_rule['max_duration_seconds']}s for '{resource}'"
                ),
            )

        return AclDecision(
            allowed=True,
            reason=(
                f"role '{role}' is permitted up to '{matched_rule['max_access_level']}' / "
                f"{matched_rule['max_duration_seconds']}s for '{resource}'"
            ),
        )
