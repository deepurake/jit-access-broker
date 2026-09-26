"""Thin CLI over Broker. Every subcommand opens the same SQLite file passed
via --db, so state is shared across separate process invocations exactly
the way a real CLI is used -- this is not an in-memory demo harness."""
import argparse
import sys

from broker.broker import Broker
from broker.connector import MockConnector
from broker.db import Database
from broker.models import AccessDeniedError
from broker.policy import AlwaysApprovePolicy


def build_broker(db_path: str) -> Broker:
    return Broker(db=Database(db_path), policy=AlwaysApprovePolicy(), connector=MockConnector())


def _require_grant(broker: Broker, grant_id: int):
    """Looks up a grant, printing the standard not-found error if missing.
    Shared by every subcommand that operates on an existing grant."""
    grant = broker.db.get_grant(grant_id)
    if grant is None:
        print(f"error: no such grant {grant_id}")
    return grant


def cmd_request(args, broker: Broker) -> int:
    try:
        grant = broker.request_access(
            requester=args.requester,
            resource=args.resource,
            access_level=args.access_level,
            duration_seconds=args.duration,
            reason=args.reason,
        )
    except AccessDeniedError as e:
        print(f"status: {e.decision.decision.value}")
        print(f"detail: {e.decision.reason}")
        return 1

    print(f"status: {grant.status.value}")
    print(f"grant_id: {grant.id}")
    print(f"request_id: {grant.request_id}")
    print(f"token: {grant.token}")
    print(f"granted_at: {grant.granted_at}")
    print(f"expires_at: {grant.expires_at}")
    return 0


def cmd_status(args, broker: Broker) -> int:
    grant = _require_grant(broker, args.grant_id)
    if grant is None:
        return 1
    print(f"grant_id: {grant.id}")
    print(f"status: {grant.status.value}")
    print(f"active: {'true' if broker.is_active(grant.id) else 'false'}")
    print(f"expires_at: {grant.expires_at}")
    return 0


def cmd_revoke(args, broker: Broker) -> int:
    grant = _require_grant(broker, args.grant_id)
    if grant is None:
        return 1
    revoked = broker.revoke(args.grant_id, revoked_by=args.by)
    print(f"grant_id: {grant.id}")
    print(f"revoked: {'true' if revoked else 'false'}")
    return 0


def cmd_sweep(args, broker: Broker) -> int:
    count = broker.sweep_expired()
    print(f"expired_count: {count}")
    return 0


def cmd_audit(args, broker: Broker) -> int:
    events = broker.db.get_audit_log(request_id=args.request_id, grant_id=args.grant_id)
    for event in events:
        grant_field = event.grant_id if event.grant_id is not None else "-"
        print(f"at={event.at} event={event.event_type.value} request={event.request_id} grant={grant_field} detail={event.detail}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="broker")
    parser.add_argument("--db", default="broker.db", help="path to the SQLite database file")
    sub = parser.add_subparsers(dest="command", required=True)

    p_request = sub.add_parser("request", help="request time-boxed access")
    p_request.add_argument("--requester", required=True)
    p_request.add_argument("--resource", required=True)
    p_request.add_argument("--access-level", required=True)
    p_request.add_argument("--duration", type=int, required=True, help="duration in seconds")
    p_request.add_argument("--reason", required=True)
    p_request.set_defaults(func=cmd_request)

    p_status = sub.add_parser("status", help="show whether a grant is active")
    p_status.add_argument("grant_id", type=int)
    p_status.set_defaults(func=cmd_status)

    p_revoke = sub.add_parser("revoke", help="revoke a grant")
    p_revoke.add_argument("grant_id", type=int)
    p_revoke.add_argument("--by", required=True, help="who is revoking it")
    p_revoke.set_defaults(func=cmd_revoke)

    p_sweep = sub.add_parser("sweep", help="expire any due grants")
    p_sweep.set_defaults(func=cmd_sweep)

    p_audit = sub.add_parser("audit", help="show audit log entries")
    p_audit.add_argument("--request-id", type=int, default=None)
    p_audit.add_argument("--grant-id", type=int, default=None)
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    broker = build_broker(args.db)
    return args.func(args, broker)


if __name__ == "__main__":
    sys.exit(main())
