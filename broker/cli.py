"""Thin CLI over Broker. Every subcommand opens the same SQLite file passed
via --db, so state is shared across separate process invocations exactly
the way a real CLI is used -- this is not an in-memory demo harness."""
import argparse
import os
import sys
import time
from typing import Optional

from broker.acl_loader import load_acl_yaml
from broker.acl_policy import AclPolicyEngine
from broker.broker import Broker
from broker.connector import MockConnector
from broker.db import Database
from broker.decision_router import DecisionRouter
from broker.http_connector import HttpResourceConnector
from broker.models import AccessDeniedError, DuplicateRequestError, PendingApproval, PendingHumanReviewError, ReturnedToRequesterError
from broker.triage import ClaudeTriageProvider, MockTriageProvider
from broker.user_directory import DatabaseUserDirectory


def build_broker(db_path: str, triage: str = "mock", sidecar_url: Optional[str] = None) -> Broker:
    """Wires the real decision pipeline: user_roles -> ACL ceiling -> triage
    -> DecisionRouter. Only the triage backend and the resource connector are
    swappable from the command line; the routing logic itself is fixed."""
    db = Database(db_path)
    triage_provider = ClaudeTriageProvider() if triage == "claude" else MockTriageProvider()
    policy = DecisionRouter(
        user_directory=DatabaseUserDirectory(db),
        acl_engine=AclPolicyEngine(db),
        triage_provider=triage_provider,
    )
    connector = HttpResourceConnector(sidecar_url) if sidecar_url else MockConnector()
    return Broker(db=db, policy=policy, connector=connector)


def _require_grant(broker: Broker, grant_id: int):
    """Looks up a grant, printing the standard not-found error if missing.
    Shared by every subcommand that operates on an existing grant."""
    grant = broker.db.get_grant(grant_id)
    if grant is None:
        print(f"error: no such grant {grant_id}")
    return grant


def _print_pending(args, pending: PendingApproval) -> None:
    """The PENDING_HUMAN block, identical whether the router or an
    escalation put the request in front of a reviewer."""
    print("status: PENDING_HUMAN")
    print(f"approval_token: {pending.approval_token}")
    print(f"approval_url: {args.approval_base_url}/approve/{pending.approval_token}")
    print(f"deadline_at: {pending.deadline_at}")


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
    except ReturnedToRequesterError as e:
        # Exit 1 like a deny (no access was granted), but the output says
        # what the requester can do about it -- including the exact command
        # to escalate this very request if they think a human should see it.
        print("status: RETURNED")
        print(f"request_id: {e.request_id}")
        print(f"detail: {e.decision.reason}")
        print(f"hint: {e.hint}")
        print(f'escalate_with: python -m broker.cli --db {args.db} escalate {e.request_id} --by {args.requester} --note "..."')
        return 1
    except DuplicateRequestError as e:
        print("status: DUPLICATE")
        print(f"detail: {e}")
        if e.existing_grant is not None:
            print(f"existing_grant_id: {e.existing_grant.id}")
        else:
            print(f"existing_approval_token: {e.existing_pending.approval_token}")
        return 1
    except PendingHumanReviewError as e:
        _print_pending(args, e.pending_approval)
        return 0

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
    """One reconcile pass by default. --loop keeps going every --interval
    seconds (the docker-compose `sweeper` service runs this way) so expired
    grants get torn down on the connector and stale approvals get auto-denied
    without waiting for someone to run `sweep` by hand. --iterations bounds
    the loop, mainly so tests can drive it."""
    passes = 0
    while True:
        expired_count, timed_out_count = broker.reconcile()
        print(f"expired_count: {expired_count}")
        print(f"timed_out_count: {timed_out_count}")
        passes += 1
        if not args.loop or (args.iterations is not None and passes >= args.iterations):
            return 0
        sys.stdout.flush()
        time.sleep(args.interval)


def cmd_approve(args, broker: Broker) -> int:
    resolution = broker.resolve_approval(args.token, approve=(args.decision == "approve"), decided_by=args.by)
    print(f"resolved: {'true' if resolution.resolved else 'false'}")
    if not resolution.resolved:
        print(f"detail: {resolution.reason}")
        return 1
    if resolution.grant is not None:
        print(f"grant_id: {resolution.grant.id}")
        print(f"token: {resolution.grant.token}")
    return 0


def cmd_escalate(args, broker: Broker) -> int:
    """The requester's answer to a RETURNED request when they believe a
    human should see it anyway. Only the requester can escalate, and only a
    RETURNED request -- everything else is one generic error so the command
    can't be used to probe which request ids exist or whose they are."""
    pending = broker.escalate(args.request_id, note=args.note, requested_by=args.by)
    if pending is None:
        print(f"error: request {args.request_id} cannot be escalated (not found, not returned, or not yours)")
        return 1
    _print_pending(args, pending)
    return 0


def cmd_show_request(args, broker: Broker) -> int:
    """Shows a request row and where it ended up. Requests that never
    produced a grant or a pending approval (DENIED, DUPLICATE) have no other
    object to inspect, so this is the only way to see their outcome."""
    request = broker.db.get_request(args.request_id)
    if request is None:
        print(f"error: no such request {args.request_id}")
        return 1
    print(f"request_id: {request.id}")
    print(f"requester: {request.requester}")
    print(f"resource: {request.resource}")
    print(f"access_level: {request.access_level}")
    print(f"duration_seconds: {request.duration_seconds}")
    print(f"reason: {request.reason}")
    print(f"status: {request.status.value}")
    print(f"created_at: {request.created_at}")
    return 0


def cmd_audit(args, broker: Broker) -> int:
    events = broker.db.get_audit_log(request_id=args.request_id, grant_id=args.grant_id)
    for event in events:
        grant_field = event.grant_id if event.grant_id is not None else "-"
        print(f"at={event.at} event={event.event_type.value} request={event.request_id} grant={grant_field} detail={event.detail}")
    return 0


def cmd_load_acl(args, broker: Broker) -> int:
    """Syncs the human-authored acl.yaml into the acl_rules table. Admin
    operation, not a requester action, so it deliberately writes no audit
    events -- the audit log records access decisions, not config syncs."""
    if not os.path.exists(args.path):
        print(f"error: no such file {args.path}")
        return 1
    rules = load_acl_yaml(args.path)
    broker.db.load_acl_rules(rules)
    print(f"rules_loaded: {len(rules)}")
    return 0


def cmd_set_role(args, broker: Broker) -> int:
    """Assigns a requester's role. Stands in for the IdP group sync a real
    deployment would run; like load-acl it is config, not an access event."""
    broker.db.set_user_role(args.requester, args.role)
    print(f"requester: {args.requester}")
    print(f"role: {args.role}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="broker")
    parser.add_argument("--db", default="broker.db", help="path to the SQLite database file")
    parser.add_argument("--approval-base-url", default="http://localhost:8083", help="base URL where the approval web service is reachable")
    parser.add_argument(
        "--triage",
        choices=["mock", "claude"],
        default="mock",
        help="AI triage backend: mock (deterministic heuristic, default) or claude (real Anthropic API, needs ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--sidecar-url",
        default=None,
        help="if set, issue/revoke grants against the fake Okta sidecar at this URL instead of the in-process mock",
    )
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

    p_sweep = sub.add_parser("sweep", help="expire due grants and time out stale pending approvals")
    p_sweep.add_argument("--loop", action="store_true", help="keep sweeping every --interval seconds instead of once")
    p_sweep.add_argument("--interval", type=int, default=30, help="seconds between passes in --loop mode (default 30)")
    p_sweep.add_argument("--iterations", type=int, default=None, help="stop --loop after this many passes (default: forever)")
    p_sweep.set_defaults(func=cmd_sweep)

    p_show_request = sub.add_parser("show-request", help="show a request and its current status")
    p_show_request.add_argument("request_id", type=int)
    p_show_request.set_defaults(func=cmd_show_request)

    p_audit = sub.add_parser("audit", help="show audit log entries")
    p_audit.add_argument("--request-id", type=int, default=None)
    p_audit.add_argument("--grant-id", type=int, default=None)
    p_audit.set_defaults(func=cmd_audit)

    p_approve = sub.add_parser("approve", help="resolve a pending human-review approval")
    p_approve.add_argument("token")
    p_approve.add_argument("--by", required=True, help="who is deciding")
    p_approve.add_argument("--decision", choices=["approve", "deny"], required=True)
    p_approve.set_defaults(func=cmd_approve)

    p_escalate = sub.add_parser("escalate", help="send a request the AI returned to you to a human reviewer instead")
    p_escalate.add_argument("request_id", type=int)
    p_escalate.add_argument("--by", required=True, help="who is escalating (must be the requester)")
    p_escalate.add_argument("--note", required=True, help="what the reviewer should know that the original reason didn't say")
    p_escalate.set_defaults(func=cmd_escalate)

    p_load_acl = sub.add_parser("load-acl", help="sync an acl.yaml file into the ACL rules table")
    p_load_acl.add_argument("path", help="path to the acl.yaml file")
    p_load_acl.set_defaults(func=cmd_load_acl)

    p_set_role = sub.add_parser("set-role", help="assign a role to a requester")
    p_set_role.add_argument("requester")
    p_set_role.add_argument("role")
    p_set_role.set_defaults(func=cmd_set_role)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    broker = build_broker(args.db, triage=args.triage, sidecar_url=args.sidecar_url)
    return args.func(args, broker)


if __name__ == "__main__":
    sys.exit(main())
