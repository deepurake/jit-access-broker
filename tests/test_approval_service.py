"""
Evals for the approval service: the magic-link web app a human reviewer
lands on when the DecisionRouter routes a request to human review.

GET /approve/<token> renders the request (read-only) so the reviewer sees
what they're deciding on, including the AI triage justification.
POST /approve/<token>/decide records the decision -- it is a POST, never a
GET, so a link scanner or prefetcher following the URL can't approve access.
Broker.resolve_approval enforces single-use with a guarded DB transition.
"""
import pytest

from approval_service.app import create_app
from broker.broker import Broker
from broker.clock import FakeClock
from broker.connector import MockConnector
from broker.db import Database
from broker.models import (
    PendingApprovalStatus,
    PendingHumanReviewError,
    PolicyDecision,
    PolicyDecisionType,
)
from broker.policy import PolicyEngine

JUSTIFICATION = "reason is present but admin access for an extended duration carries elevated risk"
REASON = "rotating leaked credentials after incident 4711"


class FixedPolicyEngine(PolicyEngine):
    def __init__(self, decision: PolicyDecision):
        self.decision = decision

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        return self.decision


@pytest.fixture
def env(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    clock = FakeClock()
    connector = MockConnector()
    policy = FixedPolicyEngine(PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, JUSTIFICATION))
    broker = Broker(db=db, policy=policy, connector=connector, clock=clock)
    client = create_app(broker).test_client()
    return broker, db, connector, client


def _route_to_human(broker, reason=REASON) -> str:
    with pytest.raises(PendingHumanReviewError) as exc_info:
        broker.request_access(
            requester="alice",
            resource="prod-db",
            access_level="admin",
            duration_seconds=7200,
            reason=reason,
        )
    return exc_info.value.pending_approval.approval_token


# -- GET /approve/<token> -- #


def test_get_pending_token_renders_request_justification_and_form(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)

    resp = client.get(f"/approve/{token}")

    assert resp.status_code == 200
    assert b"alice" in resp.data
    assert b"prod-db" in resp.data
    assert b"admin" in resp.data
    assert REASON.encode() in resp.data
    assert JUSTIFICATION.encode() in resp.data
    assert b"<form" in resp.data
    assert f'action="/approve/{token}/decide"'.encode() in resp.data
    assert b'method="post"' in resp.data
    assert b'value="approve"' in resp.data
    assert b'value="deny"' in resp.data
    assert b'name="decided_by"' in resp.data


def test_get_unknown_token_is_404(env):
    broker, db, connector, client = env

    resp = client.get("/approve/never-issued")

    assert resp.status_code == 404


def test_get_after_decision_shows_status_and_no_form(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)
    client.post(f"/approve/{token}/decide", data={"decision": "approve", "decided_by": "bob"})

    resp = client.get(f"/approve/{token}")

    assert resp.status_code == 200
    assert b"APPROVED" in resp.data
    assert b"bob" in resp.data
    assert b"<form" not in resp.data


def test_requester_reason_is_html_escaped(env):
    broker, db, connector, client = env
    token = _route_to_human(broker, reason="<script>alert(1)</script>")

    resp = client.get(f"/approve/{token}")

    assert resp.status_code == 200
    assert b"<script>" not in resp.data
    assert b"&lt;script&gt;" in resp.data


# -- POST /approve/<token>/decide -- #


def test_post_approve_issues_grant(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)

    resp = client.post(f"/approve/{token}/decide", data={"decision": "approve", "decided_by": "bob"})

    assert resp.status_code == 200
    assert b"Approved" in resp.data
    assert len(connector.issued) == 1

    pending = db.get_pending_approval_by_token(token)
    assert pending.status == PendingApprovalStatus.APPROVED
    assert pending.decided_by == "bob"

    # the confirmation names the grant that was actually issued
    grants = db.get_audit_log(request_id=pending.request_id)
    grant_ids = {e.grant_id for e in grants if e.grant_id is not None}
    assert len(grant_ids) == 1
    grant_id = grant_ids.pop()
    assert f"#{grant_id}".encode() in resp.data
    assert broker.is_active(grant_id) is True


def test_post_deny_issues_no_grant(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)

    resp = client.post(f"/approve/{token}/decide", data={"decision": "deny", "decided_by": "bob"})

    assert resp.status_code == 200
    assert b"Denied" in resp.data
    assert connector.issued == []
    pending = db.get_pending_approval_by_token(token)
    assert pending.status == PendingApprovalStatus.DENIED
    assert pending.decided_by == "bob"


def test_post_approve_twice_second_is_409_and_no_double_grant(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)

    first = client.post(f"/approve/{token}/decide", data={"decision": "approve", "decided_by": "bob"})
    second = client.post(f"/approve/{token}/decide", data={"decision": "approve", "decided_by": "carol"})

    assert first.status_code == 200
    assert second.status_code == 409
    assert b"no longer valid" in second.data
    assert len(connector.issued) == 1
    assert db.get_pending_approval_by_token(token).decided_by == "bob"


def test_post_unknown_token_is_409(env):
    broker, db, connector, client = env

    resp = client.post("/approve/never-issued/decide", data={"decision": "approve", "decided_by": "bob"})

    assert resp.status_code == 409
    assert connector.issued == []


def test_post_invalid_decision_is_400_and_leaves_pending(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)

    resp = client.post(f"/approve/{token}/decide", data={"decision": "maybe", "decided_by": "bob"})

    assert resp.status_code == 400
    assert connector.issued == []
    assert db.get_pending_approval_by_token(token).status == PendingApprovalStatus.PENDING


def test_post_blank_decided_by_is_400_and_leaves_pending(env):
    broker, db, connector, client = env
    token = _route_to_human(broker)

    blank = client.post(f"/approve/{token}/decide", data={"decision": "approve", "decided_by": "   "})
    missing = client.post(f"/approve/{token}/decide", data={"decision": "approve"})

    assert blank.status_code == 400
    assert missing.status_code == 400
    assert connector.issued == []
    assert db.get_pending_approval_by_token(token).status == PendingApprovalStatus.PENDING


def test_get_on_decide_url_does_not_decide(env):
    """A bare link must never approve access: the decide endpoint is POST-only."""
    broker, db, connector, client = env
    token = _route_to_human(broker)

    resp = client.get(f"/approve/{token}/decide?decision=approve&decided_by=bob")

    assert resp.status_code == 405
    assert connector.issued == []
    assert db.get_pending_approval_by_token(token).status == PendingApprovalStatus.PENDING
