"""UserDirectory seam: "who has what role" as an interface, not a raw DB
call scattered everywhere. In a real deployment this would sync from a real
IdP (e.g. Okta group membership)."""
from abc import ABC, abstractmethod
from typing import Optional

from broker.db import Database


class UserDirectory(ABC):
    @abstractmethod
    def get_role(self, requester: str) -> Optional[str]:
        """Returns the requester's role, or None if they have no assigned role."""


class DatabaseUserDirectory(UserDirectory):
    """Reads from the user_roles table. In production this table would be
    kept in sync with a real IdP (e.g. Okta group membership) by a separate
    sync job -- this class only reads, it doesn't own the sync."""

    def __init__(self, db: Database):
        self.db = db

    def get_role(self, requester: str) -> Optional[str]:
        return self.db.get_role_for_requester(requester)
