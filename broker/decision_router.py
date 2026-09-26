"""DecisionRouter is the real PolicyEngine implementation, composing a
UserDirectory, AclPolicyEngine, and TriageProvider. This is the ONLY place
that combines their outputs into a final decision -- deterministic glue
code, not another model call (the routing threshold logic itself must never
be delegated to an LLM).

Routing rules, in order:
1. ACL deny is a hard stop -- triage is never called (saves cost, and more
   importantly means AI can never override a hard access-control boundary).
2. Junk-reason gate: an empty/placeholder/too-short reason is returned to
   the requester, and triage is never called. Deterministic and readable by
   a security reviewer: no model cost, no approver time, and prompt
   injection in the reason field can only move the requester's OWN request
   back to themselves.
3. Triage step 1 failed ("this reason does not justify this permission")
   -> returned to the requester. The requester can fix the wording; the
   approver cannot, so the approver never sees it unless the requester
   escalates.
4. ACL allow + triage HIGH confidence + APPROVE + no risk flag -> the only
   case where AI gets unilateral approve authority.
5. Everything else (over-scope, risk_flag=True even on a confident APPROVE,
   low confidence, a stepless DENY -- AI never gets unilateral deny
   authority) routes to a human: least privilege and risk are a reviewer's
   judgment call, not a wording fix.

Failure policy: a component *denying* is a decision; a component *throwing*
is a system failure. A failure anywhere in this pipeline never crashes the
request, never auto-denies, and never auto-approves -- it routes to manual
review with the failure text in the reason, so the reviewer and the audit
log both see what broke. If the ACL boundary itself can't be evaluated,
triage is skipped too: an AI APPROVE that nothing has gated must not exist.
"""
from broker.acl_policy import AclPolicyEngine
from broker.models import PolicyDecision, PolicyDecisionType
from broker.policy import PolicyEngine
from broker.triage import (
    _MIN_REASON_LENGTH,
    _NON_SUBSTANTIVE_REASONS,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageStepName,
)
from broker.user_directory import UserDirectory

JUNK_REASON_MESSAGE = "reason is missing or a placeholder -- say what you need to do and why"


class DecisionRouter(PolicyEngine):
    def __init__(self, user_directory: UserDirectory, acl_engine: AclPolicyEngine, triage_provider: TriageProvider):
        self.user_directory = user_directory
        self.acl_engine = acl_engine
        self.triage_provider = triage_provider

    def decide(self, requester: str, resource: str, access_level: str, duration_seconds: int, reason: str) -> PolicyDecision:
        try:
            role = self.user_directory.get_role(requester)
            acl_decision = self.acl_engine.evaluate(role, resource, access_level, duration_seconds)
        except Exception as exc:  # deliberate: any failure here -> manual review, see module docstring
            return self._defer_to_human("access-control evaluation failed", exc)

        if not acl_decision.allowed:
            return PolicyDecision(decision=PolicyDecisionType.DENY, reason=acl_decision.reason)

        if self._is_junk_reason(reason):
            return PolicyDecision(decision=PolicyDecisionType.RETURN_TO_REQUESTER, reason=JUNK_REASON_MESSAGE)

        try:
            triage_result = self.triage_provider.triage(resource, access_level, duration_seconds, reason)
        except Exception as exc:  # deliberate: any failure here -> manual review, see module docstring
            return self._defer_to_human("triage failed", exc)

        # Step 1 failing means "this reason does not justify this permission".
        # That is the requester's to fix, not the approver's, so it goes back
        # to them. A provider whose result carries no steps (a hand-written
        # fake, or one that stopped somewhere else) keeps the plain rules.
        steps = triage_result.steps
        if steps and steps[0].name == TriageStepName.REASON_VALIDATION and not steps[0].passed:
            decision = PolicyDecisionType.RETURN_TO_REQUESTER
            reason_text = steps[0].detail
        else:
            is_confidently_fine = (
                triage_result.confidence == TriageConfidence.HIGH
                and triage_result.recommendation == TriageRecommendation.APPROVE
                and not triage_result.risk_flag
            )
            decision = PolicyDecisionType.AUTO_APPROVE if is_confidently_fine else PolicyDecisionType.ROUTE_HUMAN
            reason_text = triage_result.justification

        # Carry the full triage signal, not just the flattened justification,
        # so the audit log can show why the AI recommended what it did.
        return PolicyDecision(
            decision=decision,
            reason=reason_text,
            triage_recommendation=triage_result.recommendation.value,
            triage_confidence=triage_result.confidence.value,
            triage_risk_flag=triage_result.risk_flag,
            triage_justification=triage_result.justification,
        )

    @staticmethod
    def _is_junk_reason(reason: str) -> bool:
        """The deterministic junk gate. Shares its placeholder list and
        length floor with MockTriageProvider's step 1 (imported, not copied)
        so the two can never drift apart. A rule this simple belongs in code
        a security reviewer can read, not in a model call."""
        stripped = reason.strip()
        return stripped.lower() in _NON_SUBSTANTIVE_REASONS or len(stripped) < _MIN_REASON_LENGTH

    @staticmethod
    def _defer_to_human(what_failed: str, exc: Exception) -> PolicyDecision:
        return PolicyDecision(
            decision=PolicyDecisionType.ROUTE_HUMAN,
            reason=f"{what_failed} ({type(exc).__name__}: {exc}); deferring to human review",
        )
