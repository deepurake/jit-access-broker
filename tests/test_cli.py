"""
Evals for the CLI layer (part of Stage 1 -- the "service with a CLI"
requirement). The CLI is a thin argparse wrapper over broker.broker.Broker;
these tests drive it exactly as a user would, in-process, capturing stdout.
"""
import re
import time

from broker.cli import main


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
