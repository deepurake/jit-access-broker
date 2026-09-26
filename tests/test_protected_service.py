"""
Unit tests for the protected test resource (protected_service/app.py), using
a FakeTokenIntrospector test double -- same pattern as broker's FakeClock /
MockConnector. No network involved here; the real HTTP path to the sidecar
is exercised separately in test_http_introspector.py and test_integration.py.
"""
from protected_service.app import create_app
from protected_service.introspector import TokenIntrospector


class FakeTokenIntrospector(TokenIntrospector):
    def __init__(self, active_tokens):
        self.active_tokens = set(active_tokens)

    def is_active(self, token: str) -> bool:
        return token in self.active_tokens


def make_client(active_tokens=()):
    return create_app(FakeTokenIntrospector(active_tokens)).test_client()


def test_active_token_grants_access_to_data():
    client = make_client(active_tokens={"good-token"})

    resp = client.get("/data", headers={"Authorization": "Bearer good-token"})

    assert resp.status_code == 200
    assert "data" in resp.get_json()


def test_missing_authorization_header_is_rejected():
    client = make_client(active_tokens={"good-token"})

    resp = client.get("/data")

    assert resp.status_code == 401


def test_inactive_token_is_rejected():
    client = make_client(active_tokens=set())

    resp = client.get("/data", headers={"Authorization": "Bearer revoked-token"})

    assert resp.status_code == 401


def test_malformed_authorization_header_is_rejected():
    client = make_client(active_tokens={"good-token"})

    resp = client.get("/data", headers={"Authorization": "Basic good-token"})

    assert resp.status_code == 401
