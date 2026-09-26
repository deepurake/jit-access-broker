"""Real (if mocked-identity-provider-shaped) ResourceConnector implementation:
talks to the fake Okta sidecar over HTTP instead of keeping state in-process.
This is the shape a genuine Okta/AWS/Workspace connector would take -- same
interface, same call sites in Broker, just pointed at a real base_url with
real auth headers instead of the sidecar."""
import requests

from broker.connector import ResourceConnector


class HttpResourceConnector(ResourceConnector):
    def __init__(self, base_url: str, timeout_seconds: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def issue(self, resource: str, access_level: str) -> str:
        resp = requests.post(
            f"{self.base_url}/grants",
            json={"resource": resource, "access_level": access_level},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()["token"]

    def revoke(self, resource: str, access_level: str, token: str) -> None:
        resp = requests.post(f"{self.base_url}/grants/{token}/revoke", timeout=self.timeout_seconds)
        resp.raise_for_status()
