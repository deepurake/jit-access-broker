"""PolicyEngine is the seam for real rule evaluation. AlwaysApprovePolicy is
the stage-1 placeholder that let the request -> decision -> grant pipeline
be built and tested before any real policy logic existed. DecisionRouter
(broker/decision_router.py) is the real implementation, composing an
AclPolicyEngine and a TriageProvider behind this same interface."""
from abc import ABC, abstractmethod

from broker.models import PolicyDecision, PolicyDecisionType


class PolicyEngine(ABC):
    @abstractmethod
    def decide(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        ...


class AlwaysApprovePolicy(PolicyEngine):
    def decide(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        return PolicyDecision(
            decision=PolicyDecisionType.AUTO_APPROVE,
            reason="stage-1 placeholder policy: all requests auto-approved",
        )
