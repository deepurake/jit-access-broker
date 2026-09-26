"""
Unit tests for the fake Okta sidecar (sidecar/app.py), via Flask's test
client -- no network, no docker needed. This is the seam a real Okta
integration would sit behind; HttpResourceConnector talks to exactly these
three routes.
"""
from sidecar.app import create_app


def make_client():
    return create_app().test_client()


def test_issue_returns_a_token():
    client = make_client()

    resp = client.post("/grants", json={"resource": "prod-db", "access_level": "read"})

    assert resp.status_code == 201
    token = resp.get_json()["token"]
    assert isinstance(token, str) and token


def test_introspect_reports_active_for_an_issued_token():
    client = make_client()
    token = client.post("/grants", json={"resource": "prod-db", "access_level": "read"}).get_json()["token"]

    resp = client.get(f"/introspect/{token}")

    assert resp.status_code == 200
    assert resp.get_json() == {"active": True, "resource": "prod-db", "access_level": "read"}


def test_introspect_reports_inactive_for_an_unknown_token():
    client = make_client()

    resp = client.get("/introspect/does-not-exist")

    assert resp.status_code == 200
    assert resp.get_json()["active"] is False


def test_revoke_deactivates_the_token():
    client = make_client()
    token = client.post("/grants", json={"resource": "prod-db", "access_level": "write"}).get_json()["token"]

    revoke_resp = client.post(f"/grants/{token}/revoke")

    assert revoke_resp.status_code == 200
    assert revoke_resp.get_json()["revoked"] is True
    assert client.get(f"/introspect/{token}").get_json()["active"] is False


def test_revoking_an_unknown_token_reports_false_not_an_error():
    client = make_client()

    resp = client.post("/grants/does-not-exist/revoke")

    assert resp.status_code == 200
    assert resp.get_json()["revoked"] is False


def test_two_apps_have_isolated_token_stores():
    """create_app() must not share module-level state across instances --
    otherwise tests (and separate real deployments) would leak into each
    other."""
    client_a = make_client()
    client_b = make_client()
    token = client_a.post("/grants", json={"resource": "r", "access_level": "read"}).get_json()["token"]

    assert client_b.get(f"/introspect/{token}").get_json()["active"] is False
