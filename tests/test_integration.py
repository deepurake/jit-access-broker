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
from broker.broker import Broker
from broker.clock import FakeClock
from broker.db import Database
from broker.http_connector import HttpResourceConnector
from broker.policy import AlwaysApprovePolicy


def make_broker(db_path, sidecar_url):
    return Broker(
        db=Database(str(db_path)),
        policy=AlwaysApprovePolicy(),
        connector=HttpResourceConnector(sidecar_url),
        clock=FakeClock(),
    )


def get_data(protected_service_url, token):
    import requests

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
