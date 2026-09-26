"""
Evals for the CLI layer (part of Stage 1 -- the "service with a CLI"
requirement). The CLI is a thin argparse wrapper over broker.broker.Broker;
these tests drive it exactly as a user would, in-process, capturing stdout.
"""
import re
import time

from broker.broker import Broker
from broker.cli import build_parser, cmd_request, main
from broker.connector import MockConnector
from broker.db import Database
from broker.models import PolicyDecision, PolicyDecisionType
from broker.policy import PolicyEngine


class FixedPolicyEngine(PolicyEngine):
    def __init__(self, decision: PolicyDecision):
        self.decision = decision

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        return self.decision


def request_grant(db_path, **overrides):
    args = {
        "requester": "alice",
        "resource": "prod-db",
        "access-level": "read",
        "duration": "3600",
        "reason": "debugging incident 123",
    }
    args.update(overrides)
    argv = ["--db", str(db_path), "request"]
    for key, value in args.items():
        argv += [f"--{key}", value]
    return argv


def parse_field(output, field):
    match = re.search(rf"^{field}: (.+)$", output, re.MULTILINE)
    assert match, f"field {field!r} not found in output:\n{output}"
    return match.group(1)


ACL_FIXTURE_YAML = """\
roles:
  engineer:
    - resource_pattern: "prod-db"
      max_access_level: read
      max_duration_seconds: 3600
  oncall:
    - resource_pattern: "prod-*"
      max_access_level: admin
      max_duration_seconds: 7200
  intern:
    - resource_pattern: "staging-*"
      max_access_level: read
      max_duration_seconds: 1800
"""


def write_acl_fixture(tmp_path):
    acl_path = tmp_path / "acl.yaml"
    acl_path.write_text(ACL_FIXTURE_YAML)
    return acl_path


def seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="engineer"):
    """Seeds state the way a real operator would -- through the CLI's own
    admin subcommands -- so request tests flow through the real
    ACL -> triage -> router pipeline rather than a permissive stub.
    Drains capsys so callers only see their own command's output."""
    acl_path = write_acl_fixture(tmp_path)
    assert main(["--db", str(db_path), "load-acl", str(acl_path)]) == 0
    assert main(["--db", str(db_path), "set-role", requester, role]) == 0
    capsys.readouterr()


def test_request_command_prints_active_grant(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)

    exit_code = main(request_grant(db_path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "ACTIVE"
    assert parse_field(output, "token").startswith("mock-token-")
    grant_id = parse_field(output, "grant_id")
    assert grant_id.isdigit()


def test_second_identical_request_is_reported_as_duplicate(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    grant_id = parse_field(capsys.readouterr().out, "grant_id")

    exit_code = main(request_grant(db_path))

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "DUPLICATE"
    assert "active grant exists" in parse_field(output, "detail")
    assert parse_field(output, "existing_grant_id") == grant_id


def test_status_command_reflects_revoke(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    grant_id = parse_field(capsys.readouterr().out, "grant_id")

    main(["--db", str(db_path), "status", grant_id])
    assert parse_field(capsys.readouterr().out, "active") == "true"

    main(["--db", str(db_path), "revoke", grant_id, "--by", "security-team"])
    capsys.readouterr()

    main(["--db", str(db_path), "status", grant_id])
    output = capsys.readouterr().out
    assert parse_field(output, "active") == "false"
    assert parse_field(output, "status") == "REVOKED"


def test_revoke_command_is_idempotent_once_terminal(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    grant_id = parse_field(capsys.readouterr().out, "grant_id")

    main(["--db", str(db_path), "revoke", grant_id, "--by", "security-team"])
    assert parse_field(capsys.readouterr().out, "revoked") == "true"

    main(["--db", str(db_path), "revoke", grant_id, "--by", "security-team"])
    assert parse_field(capsys.readouterr().out, "revoked") == "false"


def test_sweep_command_expires_due_grants(tmp_path, capsys):
    """Deliberate real-time wait: this exercises the CLI's real SystemClock,
    not the fake one the domain tests use, so it's a genuine (if slow)
    wall-clock integration check rather than a unit test."""
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path, duration="1"))
    grant_id = parse_field(capsys.readouterr().out, "grant_id")

    time.sleep(1.2)

    main(["--db", str(db_path), "sweep"])
    assert parse_field(capsys.readouterr().out, "expired_count") == "1"

    main(["--db", str(db_path), "status", grant_id])
    output = capsys.readouterr().out
    assert parse_field(output, "active") == "false"
    assert parse_field(output, "status") == "EXPIRED"


def test_audit_command_lists_full_lifecycle_in_order(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    grant_id = parse_field(capsys.readouterr().out, "grant_id")

    main(["--db", str(db_path), "revoke", grant_id, "--by", "security-team"])
    capsys.readouterr()

    main(["--db", str(db_path), "audit", "--grant-id", grant_id])
    output = capsys.readouterr().out
    event_types = re.findall(r"event=(\w+)", output)
    assert event_types == ["GRANTED", "REVOKED"]

    main(["--db", str(db_path), "audit"])
    output = capsys.readouterr().out
    event_types = re.findall(r"event=(\w+)", output)
    # TRIAGED sits between REQUESTED and POLICY_DECIDED: chronologically the
    # AI recommendation exists before the router turns it into a decision.
    assert event_types == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "GRANTED", "REVOKED"]


def test_audit_triaged_event_records_confidence_and_risk_flag(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    capsys.readouterr()

    main(["--db", str(db_path), "audit", "--request-id", "1"])
    output = capsys.readouterr().out

    triaged = [line for line in output.splitlines() if "event=TRIAGED" in line]
    assert len(triaged) == 1
    assert "APPROVE confidence=HIGH risk_flag=False" in triaged[0]
    assert "proportionate" in triaged[0]


def test_audit_triaged_event_shows_risk_flag_for_extended_admin_access(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="oncall")
    main(
        request_grant(
            db_path,
            **{"access-level": "admin"},
            duration="7200",
            reason="rotating leaked credentials after incident 4711",
        )
    )
    capsys.readouterr()

    main(["--db", str(db_path), "audit", "--request-id", "1"])
    output = capsys.readouterr().out

    event_types = re.findall(r"event=(\w+)", output)
    assert event_types == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "ROUTED_TO_HUMAN"]
    triaged = [line for line in output.splitlines() if "event=TRIAGED" in line][0]
    assert "APPROVE confidence=MEDIUM risk_flag=True" in triaged


def test_audit_has_no_triaged_event_when_acl_denies_before_triage(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path, **{"access-level": "admin"}))
    capsys.readouterr()

    main(["--db", str(db_path), "audit", "--request-id", "1"])
    output = capsys.readouterr().out

    event_types = re.findall(r"event=(\w+)", output)
    assert event_types == ["REQUESTED", "POLICY_DECIDED", "DENIED"]


def test_request_command_reports_pending_human_review(tmp_path, capsys):
    """Drives cmd_request directly against a hand-built Broker with a fixed
    ROUTE_HUMAN policy, isolating the command's PENDING_HUMAN output format
    from the real pipeline (which test_risk_flag_routes_otherwise_permitted_request_to_human
    covers end to end through main())."""
    db_path = tmp_path / "cli.db"
    broker = Broker(
        db=Database(str(db_path)),
        policy=FixedPolicyEngine(PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs review")),
        connector=MockConnector(),
    )
    args = build_parser().parse_args(
        [
            "--db", str(db_path),
            "--approval-base-url", "http://localhost:8083",
            "request",
            "--requester", "alice",
            "--resource", "prod-db",
            "--access-level", "admin",
            "--duration", "3600",
            "--reason", "need it",
        ]
    )

    exit_code = cmd_request(args, broker)

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "PENDING_HUMAN"
    token = parse_field(output, "approval_token")
    assert parse_field(output, "approval_url") == f"http://localhost:8083/approve/{token}"
    assert parse_field(output, "deadline_at")


def test_approve_command_approves_a_pending_request(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    output = capsys.readouterr().out
    request_id = int(parse_field(output, "request_id"))

    # The CLI runs on the real SystemClock and resolve_approval enforces the
    # deadline at click time, so the hand-built approval must not be stale.
    now = int(time.time())
    db = Database(str(db_path))
    pending = db.create_pending_approval(request_id, "tok-cli-test", created_at=now, deadline_at=now + 14400)

    exit_code = main(["--db", str(db_path), "approve", pending.approval_token, "--by", "bob", "--decision", "approve"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "resolved") == "true"
    assert parse_field(output, "grant_id").isdigit()


def test_approve_command_with_unknown_token_fails(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    capsys.readouterr()

    exit_code = main(["--db", str(db_path), "approve", "never-issued", "--by", "bob", "--decision", "approve"])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "resolved") == "false"
    assert parse_field(output, "detail") == "unknown approval token"


def test_sweep_command_reports_expired_and_timed_out_counts(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path, duration="1"))
    capsys.readouterr()

    time.sleep(1.2)

    main(["--db", str(db_path), "sweep"])
    output = capsys.readouterr().out
    assert parse_field(output, "expired_count") == "1"
    assert parse_field(output, "timed_out_count") == "0"


# --- T9: real ACL -> triage -> router pipeline wired into the CLI ---------


def test_load_acl_command_reports_rule_count(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    acl_path = write_acl_fixture(tmp_path)

    exit_code = main(["--db", str(db_path), "load-acl", str(acl_path)])

    assert exit_code == 0
    assert parse_field(capsys.readouterr().out, "rules_loaded") == "3"


def test_load_acl_command_with_missing_file_fails_cleanly(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    missing = tmp_path / "does-not-exist.yaml"

    exit_code = main(["--db", str(db_path), "load-acl", str(missing)])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert output.startswith("error:")
    assert str(missing) in output


def test_set_role_command_echoes_assignment(tmp_path, capsys):
    db_path = tmp_path / "cli.db"

    exit_code = main(["--db", str(db_path), "set-role", "alice", "engineer"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "requester") == "alice"
    assert parse_field(output, "role") == "engineer"


def test_request_by_requester_with_no_role_is_denied(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    acl_path = write_acl_fixture(tmp_path)
    main(["--db", str(db_path), "load-acl", str(acl_path)])
    capsys.readouterr()

    exit_code = main(request_grant(db_path))

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "DENY"
    assert "no assigned role" in parse_field(output, "detail")


def test_request_exceeding_acl_ceiling_is_denied(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="engineer")

    exit_code = main(request_grant(db_path, **{"access-level": "admin"}))

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "DENY"
    assert "capped" in parse_field(output, "detail")


def test_request_with_placeholder_reason_is_returned_to_requester_via_main(tmp_path, capsys):
    """A junk reason never reaches an approver: it goes back to the requester
    with a hint and the exact escalate command, and no model ran."""
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)

    exit_code = main(request_grant(db_path, reason="idk"))

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "RETURNED"
    assert parse_field(output, "request_id") == "1"
    assert "placeholder" in parse_field(output, "detail")
    assert "resubmit" in parse_field(output, "hint")
    assert parse_field(output, "escalate_with") == f'python -m broker.cli --db {db_path} escalate 1 --by alice --note "..."'
    assert "approval_token" not in output

    main(["--db", str(db_path), "audit", "--request-id", "1"])
    event_types = re.findall(r"event=(\w+)", capsys.readouterr().out)
    assert event_types == ["REQUESTED", "POLICY_DECIDED", "RETURNED_TO_REQUESTER"]


def test_request_with_irrelevant_reason_for_admin_is_returned_after_triage(tmp_path, capsys):
    """Substantive wording clears the junk gate, so triage runs (TRIAGED is
    audited) -- but step 1 says it doesn't justify admin, so it is returned."""
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="oncall")

    exit_code = main(
        request_grant(db_path, **{"access-level": "admin"}, duration="600", reason="I want to look at the dashboards for a while")
    )

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "RETURNED"
    assert "does not justify admin" in parse_field(output, "detail")

    main(["--db", str(db_path), "audit", "--request-id", "1"])
    event_types = re.findall(r"event=(\w+)", capsys.readouterr().out)
    assert event_types == ["REQUESTED", "TRIAGED", "POLICY_DECIDED", "RETURNED_TO_REQUESTER"]


def test_escalate_command_turns_a_returned_request_into_a_pending_review(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path, reason="idk"))
    capsys.readouterr()

    exit_code = main(["--db", str(db_path), "escalate", "1", "--by", "alice", "--note", "on-call, checking replication lag, ticket OPS-77"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "PENDING_HUMAN"
    token = parse_field(output, "approval_token")
    assert parse_field(output, "approval_url") == f"http://localhost:8083/approve/{token}"
    assert parse_field(output, "deadline_at").isdigit()

    main(["--db", str(db_path), "show-request", "1"])
    assert parse_field(capsys.readouterr().out, "status") == "PENDING_HUMAN"


def test_escalate_command_by_someone_else_fails(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path, reason="idk"))
    capsys.readouterr()

    exit_code = main(["--db", str(db_path), "escalate", "1", "--by", "mallory", "--note", "let me in"])

    assert exit_code == 1
    assert capsys.readouterr().out.strip() == "error: request 1 cannot be escalated (not found, not returned, or not yours)"
    main(["--db", str(db_path), "show-request", "1"])
    assert parse_field(capsys.readouterr().out, "status") == "RETURNED"


def test_escalate_command_on_unknown_request_fails(tmp_path, capsys):
    db_path = tmp_path / "cli.db"

    exit_code = main(["--db", str(db_path), "escalate", "42", "--by", "alice", "--note", "?"])

    assert exit_code == 1
    assert capsys.readouterr().out.startswith("error: request 42 cannot be escalated")


def test_full_return_escalate_approve_loop_via_cli(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)

    assert main(request_grant(db_path, reason="idk")) == 1
    assert parse_field(capsys.readouterr().out, "status") == "RETURNED"

    assert main(["--db", str(db_path), "escalate", "1", "--by", "alice", "--note", "ticket OPS-77"]) == 0
    token = parse_field(capsys.readouterr().out, "approval_token")

    assert main(["--db", str(db_path), "approve", token, "--by", "bob", "--decision", "approve"]) == 0
    output = capsys.readouterr().out
    assert parse_field(output, "resolved") == "true"
    grant_id = parse_field(output, "grant_id")

    main(["--db", str(db_path), "status", grant_id])
    output = capsys.readouterr().out
    assert parse_field(output, "active") == "true"
    assert parse_field(output, "status") == "ACTIVE"

    main(["--db", str(db_path), "show-request", "1"])
    assert parse_field(capsys.readouterr().out, "status") == "HUMAN_APPROVED"

    main(["--db", str(db_path), "audit", "--request-id", "1"])
    event_types = re.findall(r"event=(\w+)", capsys.readouterr().out)
    # no TRIAGED: the junk gate returned it before any model ran
    assert event_types == ["REQUESTED", "POLICY_DECIDED", "RETURNED_TO_REQUESTER", "ESCALATED", "ROUTED_TO_HUMAN", "HUMAN_APPROVED"]


def test_risk_flag_routes_otherwise_permitted_request_to_human(tmp_path, capsys):
    """oncall is permitted admin/7200 on prod-* by the ACL and the reason is
    substantive, so the only thing routing this to a human is the triage
    risk_flag -- proving risk_flag overrides an otherwise-fine request."""
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="oncall")

    exit_code = main(
        request_grant(
            db_path,
            **{"access-level": "admin"},
            duration="7200",
            reason="rotating leaked credentials after incident 4711",
        )
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "PENDING_HUMAN"


def test_full_human_review_loop_via_cli(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="oncall")

    main(
        request_grant(
            db_path,
            **{"access-level": "admin"},
            duration="7200",
            reason="rotating leaked credentials after incident 4711",
        )
    )
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "PENDING_HUMAN"
    token = parse_field(output, "approval_token")

    exit_code = main(["--db", str(db_path), "approve", token, "--by", "bob", "--decision", "approve"])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "resolved") == "true"
    grant_id = parse_field(output, "grant_id")
    assert grant_id.isdigit()

    main(["--db", str(db_path), "status", grant_id])
    output = capsys.readouterr().out
    assert parse_field(output, "active") == "true"
    assert parse_field(output, "status") == "ACTIVE"


def test_sweep_loop_runs_the_requested_number_of_passes(tmp_path, capsys):
    db_path = tmp_path / "cli.db"

    exit_code = main(["--db", str(db_path), "sweep", "--loop", "--interval", "0", "--iterations", "2"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert re.findall(r"^expired_count: (\d+)$", output, re.MULTILINE) == ["0", "0"]
    assert re.findall(r"^timed_out_count: (\d+)$", output, re.MULTILINE) == ["0", "0"]


def test_sweep_without_loop_flag_runs_exactly_once(tmp_path, capsys):
    db_path = tmp_path / "cli.db"

    exit_code = main(["--db", str(db_path), "sweep"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert len(re.findall(r"^expired_count:", output, re.MULTILINE)) == 1


def test_show_request_command_prints_the_request_and_its_status(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys)
    main(request_grant(db_path))
    request_id = parse_field(capsys.readouterr().out, "request_id")

    exit_code = main(["--db", str(db_path), "show-request", request_id])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "request_id") == request_id
    assert parse_field(output, "requester") == "alice"
    assert parse_field(output, "resource") == "prod-db"
    assert parse_field(output, "access_level") == "read"
    assert parse_field(output, "duration_seconds") == "3600"
    assert parse_field(output, "reason") == "debugging incident 123"
    assert parse_field(output, "status") == "AUTO_APPROVED"
    assert parse_field(output, "created_at").isdigit()


def test_show_request_command_reflects_human_approval(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    seed_acl_and_role(db_path, tmp_path, capsys, requester="alice", role="oncall")
    main(request_grant(db_path, **{"access-level": "admin"}, duration="7200", reason="rotating leaked credentials after incident 4711"))
    token = parse_field(capsys.readouterr().out, "approval_token")

    main(["--db", str(db_path), "show-request", "1"])
    assert parse_field(capsys.readouterr().out, "status") == "PENDING_HUMAN"

    main(["--db", str(db_path), "approve", token, "--by", "bob", "--decision", "approve"])
    capsys.readouterr()

    main(["--db", str(db_path), "show-request", "1"])
    assert parse_field(capsys.readouterr().out, "status") == "HUMAN_APPROVED"


def test_show_request_command_with_unknown_id_fails(tmp_path, capsys):
    db_path = tmp_path / "cli.db"

    exit_code = main(["--db", str(db_path), "show-request", "42"])

    assert exit_code == 1
    assert capsys.readouterr().out.strip() == "error: no such request 42"


def test_triage_claude_flag_is_accepted_by_parser():
    """Parser-level only: constructing the real provider is safe, but a
    request through it would hit the Anthropic API, so we never run one."""
    args = build_parser().parse_args(["--triage", "claude", "sweep"])
    assert args.triage == "claude"

    default_args = build_parser().parse_args(["sweep"])
    assert default_args.triage == "mock"
    assert default_args.sidecar_url is None
