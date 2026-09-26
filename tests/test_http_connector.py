"""
Tests HttpResourceConnector against a *real* instance of the sidecar Flask
app, running in a background thread on an ephemeral port -- not a mocked
HTTP client. This proves the connector's request/response handling actually
works over a real socket, without needing docker for this particular check
(docker-compose is what additionally proves the protected-service leg; see
tests/test_integration.py).
"""
from broker.http_connector import HttpResourceConnector


def test_issue_returns_a_token_from_the_real_sidecar(sidecar_url):
    connector = HttpResourceConnector(sidecar_url)

    token = connector.issue("prod-db", "read")

    assert isinstance(token, str) and token


def test_issued_token_introspects_as_active_on_the_sidecar(sidecar_url):
    import requests

    connector = HttpResourceConnector(sidecar_url)
    token = connector.issue("prod-db", "read")

    resp = requests.get(f"{sidecar_url}/introspect/{token}")

    assert resp.json() == {"active": True, "resource": "prod-db", "access_level": "read"}


def test_revoke_deactivates_the_token_on_the_real_sidecar(sidecar_url):
    import requests

    connector = HttpResourceConnector(sidecar_url)
    token = connector.issue("prod-db", "write")

    connector.revoke("prod-db", "write", token)

    resp = requests.get(f"{sidecar_url}/introspect/{token}")
    assert resp.json()["active"] is False
