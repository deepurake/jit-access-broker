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


def test_request_command_prints_active_grant(tmp_path, capsys):
    db_path = tmp_path / "cli.db"

    exit_code = main(request_grant(db_path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "status") == "ACTIVE"
    assert parse_field(output, "token").startswith("mock-token-")
    grant_id = parse_field(output, "grant_id")
    assert grant_id.isdigit()


def test_status_command_reflects_revoke(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
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
    assert event_types == ["REQUESTED", "POLICY_DECIDED", "GRANTED", "REVOKED"]


def test_request_command_reports_pending_human_review(tmp_path, capsys):
    """build_broker() hardcodes AlwaysApprovePolicy, which never routes to a
    human, so this drives cmd_request directly against a hand-built Broker
    with a policy that does -- the CLI wiring for a real ACL/triage policy is
    a separate task."""
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
    main(request_grant(db_path))
    output = capsys.readouterr().out
    request_id = int(parse_field(output, "request_id"))

    db = Database(str(db_path))
    pending = db.create_pending_approval(request_id, "tok-cli-test", created_at=1000, deadline_at=1000 + 14400)

    exit_code = main(["--db", str(db_path), "approve", pending.approval_token, "--by", "bob", "--decision", "approve"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert parse_field(output, "resolved") == "true"
    assert parse_field(output, "grant_id").isdigit()


def test_approve_command_with_unknown_token_fails(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    main(request_grant(db_path))
    capsys.readouterr()

    exit_code = main(["--db", str(db_path), "approve", "never-issued", "--by", "bob", "--decision", "approve"])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert parse_field(output, "resolved") == "false"


def test_sweep_command_reports_expired_and_timed_out_counts(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    main(request_grant(db_path, duration="1"))
    capsys.readouterr()

    time.sleep(1.2)

    main(["--db", str(db_path), "sweep"])
    output = capsys.readouterr().out
    assert parse_field(output, "expired_count") == "1"
    assert parse_field(output, "timed_out_count") == "0"
