"""ResourceConnector is the seam where a real Okta / AWS / Workspace SDK call
would go. The broker only ever talks to this interface, never to a concrete
system, so swapping the mock for a real integration later means writing one
new class and changing nothing else."""
import secrets
from abc import ABC, abstractmethod


class ResourceConnector(ABC):
    @abstractmethod
    def issue(self, resource: str, access_level: str) -> str:
        """Provision access on the real system and return an opaque token."""

    @abstractmethod
    def revoke(self, resource: str, access_level: str, token: str) -> None:
        """Tear down access on the real system for a previously issued token."""


class MockConnector(ResourceConnector):
    """Stands in for a real identity/resource provider. Records every call
    it receives so tests can assert on what the broker asked it to do."""

    def __init__(self):
        self.issued = []
        self.revoked = []

    def issue(self, resource: str, access_level: str) -> str:
        token = f"mock-token-{secrets.token_hex(8)}"
        self.issued.append((resource, access_level, token))
        return token

    def revoke(self, resource: str, access_level: str, token: str) -> None:
        self.revoked.append((resource, access_level, token))
