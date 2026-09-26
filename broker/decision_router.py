"""DecisionRouter is the real PolicyEngine implementation, composing a
UserDirectory, AclPolicyEngine, and TriageProvider. This is the ONLY place
that combines their outputs into a final decision -- deterministic glue
code, not another model call (the routing threshold logic itself must never
be delegated to an LLM).

Routing rules, in order:
1. ACL deny is a hard stop -- triage is never called (saves cost, and more
   importantly means AI can never override a hard access-control boundary).
2. ACL allow + triage HIGH confidence + APPROVE + no risk flag -> the only
   case where AI gets unilateral approve authority.
3. Everything else (including a confident DENY -- AI never gets unilateral
   deny authority -- and any risk_flag=True, even on a confident APPROVE)
   routes to a human.
"""
from broker.acl_policy import AclPolicyEngine
from broker.models import PolicyDecision, PolicyDecisionType
from broker.policy import PolicyEngine
from broker.triage import TriageConfidence, TriageProvider, TriageRecommendation
from broker.user_directory import UserDirectory


class DecisionRouter(PolicyEngine):
    def __init__(self, user_directory: UserDirectory, acl_engine: AclPolicyEngine, triage_provider: TriageProvider):
        self.user_directory = user_directory
        self.acl_engine = acl_engine
        self.triage_provider = triage_provider

    def decide(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        role = self.user_directory.get_role(requester)
        acl_decision = self.acl_engine.evaluate(role, resource, access_level, duration_seconds)

        if not acl_decision.allowed:
            return PolicyDecision(decision=PolicyDecisionType.DENY, reason=acl_decision.reason)

        triage_result = self.triage_provider.triage(resource, access_level, duration_seconds, reason)

        is_confidently_fine = (
            triage_result.confidence == TriageConfidence.HIGH
            and triage_result.recommendation == TriageRecommendation.APPROVE
            and not triage_result.risk_flag
        )
        if is_confidently_fine:
            return PolicyDecision(decision=PolicyDecisionType.AUTO_APPROVE, reason=triage_result.justification)

        return PolicyDecision(decision=PolicyDecisionType.ROUTE_HUMAN, reason=triage_result.justification)
