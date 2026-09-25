"""PolicyEngine is the seam for stage 2's real rule evaluation. Stage 1 uses
a trivial always-approve implementation so the request -> decision -> grant
pipeline can be built and tested end to end before any real policy logic
exists."""
from abc import ABC, abstractmethod

from broker.models import PolicyDecision, PolicyDecisionType


class PolicyEngine(ABC):
    @abstractmethod
    def decide(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        ...


class AlwaysApprovePolicy(PolicyEngine):
    def decide(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        return PolicyDecision(
            decision=PolicyDecisionType.AUTO_APPROVE,
            reason="stage-1 placeholder policy: all requests auto-approved",
        )
