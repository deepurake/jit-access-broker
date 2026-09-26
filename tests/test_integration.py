"""
Full-chain integration: Broker -> HttpResourceConnector -> fake Okta sidecar
-> protected test service. This is the proof that the broker is actually
integrated with something over the network, not just its own mocks.

Runs against real (in-thread) instances of both services via the
sidecar_url/protected_service_url fixtures, so it works under plain pytest.
The same services also run as real containers under docker-compose (see
docker-compose.yml + tests/test_integration.py invoked from the test-runner
service), which additionally proves the wiring survives process boundaries.
"""
from uuid import uuid4

import pytest
import requests

from broker.broker import Broker
from broker.clock import FakeClock
from broker.db import Database
from broker.http_connector import HttpResourceConnector
from broker.models import PendingApprovalStatus, PendingHumanReviewError, RequestStatus
from broker.policy import AlwaysApprovePolicy


def make_broker(db_path, sidecar_url):
    return Broker(
        db=Database(str(db_path)),
        policy=AlwaysApprovePolicy(),
        connector=HttpResourceConnector(sidecar_url),
        clock=FakeClock(),
    )


def get_data(protected_service_url, token):
    return requests.get(f"{protected_service_url}/data", headers={"Authorization": f"Bearer {token}"})


def test_broker_issued_grant_gives_real_access_to_the_protected_service(tmp_path, sidecar_url, protected_service_url):
    broker = make_broker(tmp_path / "integration.db", sidecar_url)

    grant = broker.request_access(
        requester="alice",
        resource="prod-db",
        access_level="read",
        duration_seconds=3600,
        reason="integration test",
    )

    resp = get_data(protected_service_url, grant.token)
    assert resp.status_code == 200


def test_unrevoked_unissued_token_is_rejected_by_the_protected_service(protected_service_url):
    resp = get_data(protected_service_url, "some-token-nobody-ever-issued")
    assert resp.status_code == 401


def test_broker_revocation_immediately_blocks_the_protected_service(tmp_path, sidecar_url, protected_service_url):
    broker = make_broker(tmp_path / "integration.db", sidecar_url)
    grant = broker.request_access(
        requester="bob",
        resource="prod-db",
        access_level="admin",
        duration_seconds=3600,
        reason="integration test",
    )
    assert get_data(protected_service_url, grant.token).status_code == 200

    broker.revoke(grant.id, revoked_by="security-team")

    assert get_data(protected_service_url, grant.token).status_code == 401


def test_broker_expiry_immediately_blocks_the_protected_service(tmp_path, sidecar_url, protected_service_url):
    """The broker's own DB marking a grant EXPIRED is not enough -- the
    external system (sidecar-issued token) must actually be torn down too,
    or an expired-in-the-broker's-eyes grant keeps working everywhere else."""
    broker = make_broker(tmp_path / "integration.db", sidecar_url)
    grant = broker.request_access(
        requester="carol",
        resource="prod-db",
        access_level="read",
        duration_seconds=60,
        reason="integration test",
    )
    assert get_data(protected_service_url, grant.token).status_code == 200

    broker.clock.advance(61)
    broker.sweep_expired()

    assert get_data(protected_service_url, grant.token).status_code == 401


# -- Human-review leg over real HTTP: Broker -> approval web app -> Broker
# -> HttpResourceConnector -> sidecar -> protected service. The
# approval_service_url fixture hands back an ApprovalHarness whose broker
# shares the SAME Database the web app reads (in-thread: literally the same
# Broker object; under docker-compose: the same SQLite file on a shared
# volume), so a pending approval the test creates is the one the reviewer's
# link resolves. Requesters are unique per test because in env mode the DB
# is shared across the whole run and Broker.request_access rejects a
# duplicate (requester, resource, access_level) while one is ACTIVE/PENDING.


def _unique(name):
    return f"{name}-{uuid4().hex[:6]}"


def _route_to_human(broker, requester, resource="prod-db", access_level="admin", duration_seconds=3600):
    with pytest.raises(PendingHumanReviewError) as exc_info:
        broker.request_access(
            requester=requester,
            resource=resource,
            access_level=access_level,
            duration_seconds=duration_seconds,
            reason="integration test: needs a human",
        )
    return exc_info.value.pending_approval.approval_token


def _grant_for(broker, requester, resource, access_level):
    return broker.db.find_active_grant(requester, resource, access_level, broker.clock.now())


def test_human_routed_request_renders_on_the_approval_service(approval_service_url):
    harness = approval_service_url
    requester = _unique("dave")
    token = _route_to_human(harness.broker, requester, resource="billing-db", access_level="read")

    resp = requests.get(f"{harness.url}/approve/{token}")

    assert resp.status_code == 200
    assert requester in resp.text
    assert "billing-db" in resp.text


def test_human_approval_over_http_gives_real_access_to_the_protected_service(approval_service_url, protected_service_url):
    harness = approval_service_url
    requester = _unique("erin")
    token = _route_to_human(harness.broker, requester, resource="prod-db", access_level="admin")
    assert _grant_for(harness.broker, requester, "prod-db", "admin") is None

    resp = requests.post(f"{harness.url}/approve/{token}/decide", data={"decision": "approve", "decided_by": "bob"})

    assert resp.status_code == 200
    pending = harness.broker.db.get_pending_approval_by_token(token)
    assert pending.status == PendingApprovalStatus.APPROVED
    assert pending.decided_by == "bob"
    assert harness.broker.db.get_request(pending.request_id).status == RequestStatus.HUMAN_APPROVED

    grant = _grant_for(harness.broker, requester, "prod-db", "admin")
    assert grant is not None
    assert grant.request_id == pending.request_id
    # The click on the web app produced a token the real protected resource honours.
    assert get_data(protected_service_url, grant.token).status_code == 200


def test_human_denial_over_http_issues_nothing(approval_service_url):
    harness = approval_service_url
    requester = _unique("frank")
    token = _route_to_human(harness.broker, requester, resource="prod-db", access_level="write")

    resp = requests.post(f"{harness.url}/approve/{token}/decide", data={"decision": "deny", "decided_by": "bob"})

    assert resp.status_code == 200
    pending = harness.broker.db.get_pending_approval_by_token(token)
    assert pending.status == PendingApprovalStatus.DENIED
    assert pending.decided_by == "bob"
    assert harness.broker.db.get_request(pending.request_id).status == RequestStatus.HUMAN_DENIED
    # No grant row at all for this request: nothing was issued anywhere.
    assert _grant_for(harness.broker, requester, "prod-db", "write") is None
    grant_ids = {e.grant_id for e in harness.broker.db.get_audit_log(request_id=pending.request_id) if e.grant_id is not None}
    assert grant_ids == set()


def test_second_decision_on_the_same_link_is_409(approval_service_url):
    harness = approval_service_url
    requester = _unique("grace")
    token = _route_to_human(harness.broker, requester, resource="staging-db", access_level="read")

    first = requests.post(f"{harness.url}/approve/{token}/decide", data={"decision": "approve", "decided_by": "bob"})
    second = requests.post(f"{harness.url}/approve/{token}/decide", data={"decision": "approve", "decided_by": "carol"})

    assert first.status_code == 200
    assert second.status_code == 409
    # The first reviewer's decision stands; the second one changed nothing.
    assert harness.broker.db.get_pending_approval_by_token(token).decided_by == "bob"


def test_invalid_decision_is_400_and_leaves_the_link_pending(approval_service_url):
    harness = approval_service_url
    requester = _unique("heidi")
    token = _route_to_human(harness.broker, requester, resource="prod-db", access_level="read")

    resp = requests.post(f"{harness.url}/approve/{token}/decide", data={"decision": "maybe", "decided_by": "bob"})

    assert resp.status_code == 400
    assert harness.broker.db.get_pending_approval_by_token(token).status == PendingApprovalStatus.PENDING
    assert _grant_for(harness.broker, requester, "prod-db", "read") is None
