"""TokenIntrospector is the seam between the protected resource and whatever
identity provider issued the token. HttpIntrospector talks to the fake Okta
sidecar; a real deployment would point this at a real IdP's introspection
endpoint (or verify a signed JWT locally -- see the README for that
tradeoff)."""
from abc import ABC, abstractmethod

import requests


class TokenIntrospector(ABC):
    @abstractmethod
    def is_active(self, token: str) -> bool:
        ...


class HttpIntrospector(TokenIntrospector):
    def __init__(self, sidecar_url: str, timeout_seconds: float = 5.0):
        self.sidecar_url = sidecar_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def is_active(self, token: str) -> bool:
        resp = requests.get(f"{self.sidecar_url}/introspect/{token}", timeout=self.timeout_seconds)
        resp.raise_for_status()
        return resp.json()["active"]
