"""HttpIntrospector against a real (in-thread) sidecar instance -- the other
half of the real-HTTP proof, mirroring test_http_connector.py."""
from protected_service.introspector import HttpIntrospector


def test_reports_active_for_a_token_issued_by_the_sidecar(sidecar_url):
    import requests

    issue_resp = requests.post(f"{sidecar_url}/grants", json={"resource": "prod-db", "access_level": "read"})
    token = issue_resp.json()["token"]
    introspector = HttpIntrospector(sidecar_url)

    assert introspector.is_active(token) is True


def test_reports_inactive_for_an_unknown_token(sidecar_url):
    introspector = HttpIntrospector(sidecar_url)

    assert introspector.is_active("never-issued") is False


def test_reports_inactive_after_revocation(sidecar_url):
    import requests

    token = requests.post(f"{sidecar_url}/grants", json={"resource": "prod-db", "access_level": "read"}).json()["token"]
    requests.post(f"{sidecar_url}/grants/{token}/revoke")
    introspector = HttpIntrospector(sidecar_url)

    assert introspector.is_active(token) is False
