"""
End-to-end scenarios for the decision pipeline (T10a), one test per named
path, driven the way an operator drives it: through `broker.cli.main()`
against a real SQLite file, with the SHIPPED acl.yaml loaded via `load-acl`.

Each scenario asserts three things: what the `request` command printed
(`status:`), what `show-request` says the request's final status is, and the
exact audit event sequence -- so a regression in any layer (CLI output,
request state machine, audit trail) is caught here, not just in the unit
tests of that layer.

The CLI runs on the real SystemClock, so the one path that needs time to
pass (approval timeout) is exercised with a pre-expired pending approval
rather than a sleep; the FakeClock-driven version lives in
tests/test_broker_human_review.py::test_approving_after_the_deadline_times_out_instead_of_granting.
"""
import re
import shutil
import time
from pathlib import Path

from broker.cli import main
from broker.db import Database
from tests.test_cli import parse_field, request_grant

REPO_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_ACL = REPO_ROOT / "acl.yaml"

SUBSTANTIVE_MUTATING_REASON = "rotating leaked credentials after incident 4711"
LOOK_ONLY_REASON = "I want to look at the dashboards for a while"


def seed(db_path, tmp_path, capsys, roles):
    """Loads the shipped acl.yaml and assigns `roles` ({requester: role})
    through the CLI's own admin subcommands, then drains capsys."""
    acl_copy = tmp_path / "acl.yaml"
    shutil.copy(SHIPPED_ACL, acl_copy)
    assert main(["--db", str(db_path), "load-acl", str(acl_copy)]) == 0
    assert parse_field(capsys.readouterr().out, "rules_loaded") == "3"
    for requester, role in roles.items():
        assert main(["--db", str(db_path), "set-role", requester, role]) == 0
    capsys.readouterr()


def request(db_path, capsys, **overrides):
    """Runs `request`, returning (exit_code, stdout)."""
    code = main(request_grant(db_path, **overrides))
    return code, capsys.readouterr().out


def request_status(db_path, capsys, request_id):
    assert main(["--db", str(db_path), "show-request", str(request_id)]) == 0
    return parse_field(capsys.readouterr().out, "status")


def audit(db_path, capsys, request_id):
    """Returns (event_types, {event_type: detail}) for one request. The dict
    keeps the LAST detail per type, which is what the approval page shows."""
    assert main(["--db", str(db_path), "audit", "--request-id", str(request_id)]) == 0
    lines = capsys.readouterr().out.splitlines()
    event_types = re.findall(r"event=(\w+)", "\n".join(lines))
    details = {}
    for line in lines:
        match = re.search(r"event=(\w+) request=\d+ grant=\S+ detail=(.*)$", line)
        details[match.group(1)] = match.group(2)
    return event_types, details


def approve(db_path, capsys, token, by, decision="approve"):
    code = main(["--db", str(db_path), "approve", token, "--by", by, "--decision", decision])
    return code, capsys.readouterr().out


# 1 -------------------------------------------------------------------------


def test_auto_approve_path(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "engineer"})

    code, out = request(db_path, capsys)  # alice, prod-db, read, 3600, substantive

    assert code == 0
    assert parse_field(out, "status") == "ACTIVE"
    assert parse_field(out, "token").startswith("mock-token-")
    assert request_status(db_path, capsys, 1) == "AUTO_APPROVED"

    events, details = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "GRANTED"]
    assert details["TRIAGED"].startswith("APPROVE confidence=HIGH risk_flag=False: ")
    assert "| steps: reason_validation=pass; scope_proportionality=pass; risk_assessment=pass" in details["TRIAGED"]
    assert "| history: requester=alice " in details["TRIAGED"]
    assert details["POLICY_DECIDED"].startswith("AUTO_APPROVE: ")

    main(["--db", str(db_path), "status", parse_field(out, "grant_id")])
    assert parse_field(capsys.readouterr().out, "active") == "true"


# 2 / 3 ---------------------------------------------------------------------


def test_deny_path_for_a_requester_with_no_role(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, roles={})  # ACL loaded, nobody assigned

    code, out = request(db_path, capsys)

    assert code == 1
    assert parse_field(out, "status") == "DENY"
    assert "no assigned role" in parse_field(out, "detail")
    assert request_status(db_path, capsys, 1) == "DENIED"

    events, details = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "POLICY_DECIDED", "DENIED"]  # no TRIAGED: the model was never consulted
    assert details["POLICY_DECIDED"].startswith("DENY: ")


def test_deny_path_for_a_request_over_the_acl_ceiling(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "engineer"})  # engineer: prod-db read/3600 at most

    code, out = request(db_path, capsys, **{"access-level": "admin"}, reason=SUBSTANTIVE_MUTATING_REASON)

    assert code == 1
    assert parse_field(out, "status") == "DENY"
    assert "capped at 'read'" in parse_field(out, "detail")
    assert request_status(db_path, capsys, 1) == "DENIED"
    events, _ = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "POLICY_DECIDED", "DENIED"]


# 4 -------------------------------------------------------------------------


def test_returned_junk_reason_then_escalate_then_human_approve(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "engineer"})

    code, out = request(db_path, capsys, reason="idk")

    assert code == 1
    assert parse_field(out, "status") == "RETURNED"
    assert "placeholder" in parse_field(out, "detail")
    assert parse_field(out, "request_id") == "1"
    assert request_status(db_path, capsys, 1) == "RETURNED"
    events, _ = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "POLICY_DECIDED", "RETURNED_TO_REQUESTER"]  # no TRIAGED

    assert main(["--db", str(db_path), "escalate", "1", "--by", "alice", "--note", "on-call, ticket OPS-77"]) == 0
    out = capsys.readouterr().out
    assert parse_field(out, "status") == "PENDING_HUMAN"
    token = parse_field(out, "approval_token")
    assert request_status(db_path, capsys, 1) == "PENDING_HUMAN"

    code, out = approve(db_path, capsys, token, by="dana")
    assert code == 0
    assert parse_field(out, "resolved") == "true"
    assert parse_field(out, "grant_id").isdigit()
    assert request_status(db_path, capsys, 1) == "HUMAN_APPROVED"

    events, details = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "POLICY_DECIDED", "RETURNED_TO_REQUESTER", "ESCALATED", "ROUTED_TO_HUMAN", "HUMAN_APPROVED"]
    assert details["ESCALATED"] == "escalated by alice: on-call, ticket OPS-77"
    assert details["ROUTED_TO_HUMAN"].startswith("escalated by requester; AI returned it because: ")
    assert details["HUMAN_APPROVED"] == "approved by dana"


# 5 -------------------------------------------------------------------------


def test_returned_after_triage_when_the_reason_does_not_justify_admin(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "oncall"})

    code, out = request(db_path, capsys, **{"access-level": "admin"}, duration="600", reason=LOOK_ONLY_REASON)

    assert code == 1
    assert parse_field(out, "status") == "RETURNED"
    assert "does not justify admin" in parse_field(out, "detail")
    assert request_status(db_path, capsys, 1) == "RETURNED"

    events, details = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "RETURNED_TO_REQUESTER"]
    assert details["TRIAGED"].startswith("DENY confidence=LOW risk_flag=True: ")
    assert "| steps: reason_validation=fail (reason does not justify admin access" in details["TRIAGED"]
    assert "scope_proportionality" not in details["TRIAGED"]  # step 1 gated the rest


# 6 -------------------------------------------------------------------------


def test_human_review_path_for_an_over_scoped_admin_request(tmp_path, capsys):
    """Routed by the triage risk flag alone: alice first earns a small grant so
    the newcomer rule (scenario 7) is NOT what sends this one to a human."""
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "oncall"})
    code, out = request(db_path, capsys, duration="600")  # read/600: small scope, auto-approves
    assert parse_field(out, "status") == "ACTIVE"

    code, out = request(db_path, capsys, **{"access-level": "admin"}, duration="7200", reason=SUBSTANTIVE_MUTATING_REASON)

    assert code == 0
    assert parse_field(out, "status") == "PENDING_HUMAN"
    token = parse_field(out, "approval_token")
    assert parse_field(out, "approval_url") == f"http://localhost:8083/approve/{token}"
    assert request_status(db_path, capsys, 2) == "PENDING_HUMAN"

    events, details = audit(db_path, capsys, 2)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "ROUTED_TO_HUMAN"]
    assert details["TRIAGED"].startswith("APPROVE confidence=MEDIUM risk_flag=True: ")
    assert "| steps: reason_validation=pass; scope_proportionality=fail (admin access for an extended duration" in details["TRIAGED"]
    assert "| history: requester=alice " in details["TRIAGED"] and "approved_grants=1" in details["TRIAGED"]
    assert details["ROUTED_TO_HUMAN"].endswith(" | suggested minimum: write/3600s")
    assert "no prior approved grants" not in details["ROUTED_TO_HUMAN"]

    # self-approval is refused without consuming the link
    code, out = approve(db_path, capsys, token, by="alice")
    assert code == 1
    assert parse_field(out, "resolved") == "false"
    assert "own request" in parse_field(out, "detail")
    assert request_status(db_path, capsys, 2) == "PENDING_HUMAN"
    events, _ = audit(db_path, capsys, 2)
    assert events[-1] == "SELF_APPROVAL_BLOCKED"

    # a different reviewer can
    code, out = approve(db_path, capsys, token, by="bob")
    assert code == 0
    assert parse_field(out, "resolved") == "true"
    grant_id = parse_field(out, "grant_id")
    assert request_status(db_path, capsys, 2) == "HUMAN_APPROVED"

    main(["--db", str(db_path), "status", grant_id])
    out = capsys.readouterr().out
    assert parse_field(out, "status") == "ACTIVE"
    assert parse_field(out, "active") == "true"

    events, details = audit(db_path, capsys, 2)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "ROUTED_TO_HUMAN", "SELF_APPROVAL_BLOCKED", "HUMAN_APPROVED"]
    assert details["HUMAN_APPROVED"] == "approved by bob"


# 7 -------------------------------------------------------------------------


def test_new_requester_earns_trust_through_one_human_approval(tmp_path, capsys):
    """Triage is perfectly happy with admin/1800 and a mutating reason (HIGH,
    no risk flag) -- only the requester's empty history routes it to a human.
    Once a human has approved one grant, the same kind of request on another
    resource auto-approves: trust is earned, not blocked forever."""
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"newbie": "oncall"})

    code, out = request(
        db_path, capsys, requester="newbie", **{"access-level": "admin"}, duration="1800", reason=SUBSTANTIVE_MUTATING_REASON
    )

    assert code == 0
    assert parse_field(out, "status") == "PENDING_HUMAN"
    token = parse_field(out, "approval_token")
    assert request_status(db_path, capsys, 1) == "PENDING_HUMAN"

    events, details = audit(db_path, capsys, 1)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "ROUTED_TO_HUMAN"]
    assert details["TRIAGED"].startswith("APPROVE confidence=HIGH risk_flag=False: ")  # the AI would have approved
    assert "| steps: reason_validation=pass; scope_proportionality=pass; risk_assessment=pass" in details["TRIAGED"]
    assert "| history: requester=newbie " in details["TRIAGED"] and "approved_grants=0" in details["TRIAGED"]
    assert details["ROUTED_TO_HUMAN"].startswith("first large-scope request from a requester with no prior approved grants; ")
    assert "suggested minimum" not in details["ROUTED_TO_HUMAN"]  # it was proportionate

    code, out = approve(db_path, capsys, token, by="bob")
    assert parse_field(out, "resolved") == "true"
    assert request_status(db_path, capsys, 1) == "HUMAN_APPROVED"

    # Second admin/1800 request, different resource: proportionate, and the
    # requester now has one approved grant -> no longer "new".
    code, out = request(
        db_path, capsys, requester="newbie", resource="prod-queue", **{"access-level": "admin"}, duration="1800",
        reason="rotating the queue's leaked credentials, same incident 4711",
    )

    assert code == 0
    assert parse_field(out, "status") == "ACTIVE"
    assert request_status(db_path, capsys, 2) == "AUTO_APPROVED"
    events, details = audit(db_path, capsys, 2)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "GRANTED"]
    assert "approved_grants=1" in details["TRIAGED"]
    assert "human_approvals=1" in details["TRIAGED"]


def test_recently_denied_requester_is_routed_to_a_human_even_for_a_small_request(tmp_path, capsys):
    """Companion to the newcomer rule: a human denial in the last 30 days
    sends even a read/600 that triage rates HIGH back to a reviewer."""
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "oncall"})
    code, out = request(db_path, capsys, duration="600")  # small, auto-approves -> alice is not new
    assert parse_field(out, "status") == "ACTIVE"
    code, out = request(db_path, capsys, **{"access-level": "admin"}, duration="7200", reason=SUBSTANTIVE_MUTATING_REASON)
    token = parse_field(out, "approval_token")
    code, out = approve(db_path, capsys, token, by="bob", decision="deny")
    assert parse_field(out, "resolved") == "true"
    assert request_status(db_path, capsys, 2) == "HUMAN_DENIED"

    code, out = request(db_path, capsys, resource="prod-cache", duration="600")

    assert code == 0
    assert parse_field(out, "status") == "PENDING_HUMAN"
    events, details = audit(db_path, capsys, 3)
    assert events == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "ROUTED_TO_HUMAN"]
    assert details["TRIAGED"].startswith("APPROVE confidence=HIGH risk_flag=False: ")
    assert details["ROUTED_TO_HUMAN"].startswith("requester had a denial or revocation in the last 30 days; ")
    assert "denials=1" in details["ROUTED_TO_HUMAN"]


# 8 -------------------------------------------------------------------------


def test_duplicate_path_while_the_first_grant_is_active(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "engineer"})
    code, out = request(db_path, capsys)
    grant_id = parse_field(out, "grant_id")

    code, out = request(db_path, capsys)

    assert code == 1
    assert parse_field(out, "status") == "DUPLICATE"
    assert parse_field(out, "existing_grant_id") == grant_id
    assert "active grant exists" in parse_field(out, "detail")
    assert request_status(db_path, capsys, 2) == "DUPLICATE"
    events, details = audit(db_path, capsys, 2)
    assert events == ["REQUESTED", "DUPLICATE_REJECTED"]  # never reached the policy, never triaged
    assert details["DUPLICATE_REJECTED"] == f"duplicate of grant {grant_id}"


# 9 -------------------------------------------------------------------------


def test_approve_after_the_deadline_is_refused_and_times_the_request_out(tmp_path, capsys):
    """The CLI is on the real clock, so the pending approval is created
    directly with a deadline already in the past; the click-time enforcement
    is what's under test. The FakeClock-driven variant (route through the
    policy, advance time, click) is
    tests/test_broker_human_review.py::test_approving_after_the_deadline_times_out_instead_of_granting."""
    db_path = tmp_path / "pipeline.db"
    seed(db_path, tmp_path, capsys, {"alice": "oncall"})
    now = int(time.time())
    db = Database(str(db_path))
    request_id = db.create_request("alice", "prod-db", "admin", 7200, SUBSTANTIVE_MUTATING_REASON, at=now - 20000)
    db.create_pending_approval(request_id, "tok-stale", created_at=now - 20000, deadline_at=now - 1)

    code, out = approve(db_path, capsys, "tok-stale", by="bob")

    assert code == 1
    assert parse_field(out, "resolved") == "false"
    assert "timed_out" in parse_field(out, "detail")
    assert request_status(db_path, capsys, request_id) == "TIMED_OUT"
    events, details = audit(db_path, capsys, request_id)
    assert events == ["APPROVAL_TIMEOUT"]
    assert details["APPROVAL_TIMEOUT"] == "approval window expired, auto-denied"
