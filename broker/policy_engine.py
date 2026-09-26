"""PolicyEngine is the real Policy implementation, composing a
UserDirectory, AclPolicyEngine, and TriageProvider (and, optionally, a
RequesterHistoryReader). This is the ONLY place that combines their outputs
into a final decision -- deterministic glue code, not another model call
(the routing threshold logic itself must never be delegated to an LLM).

Routing rules, in order:
1. ACL deny is a hard stop -- triage is never called (saves cost, and more
   importantly means AI can never override a hard access-control boundary).
2. Junk-reason gate: an empty/placeholder/too-short reason is returned to
   the requester, and triage is never called. Deterministic and readable by
   a security reviewer: no model cost, no approver time, and prompt
   injection in the reason field can only move the requester's OWN request
   back to themselves.
3. Requester history (only with a history reader configured): the
   requester's own record in the broker's tables is read once, fed to the
   triage provider as context, and applied as deterministic rules AFTER
   triage has run -- see "History rules" below.
4. Triage step 1 failed ("this reason does not justify this permission")
   -> returned to the requester. The requester can fix the wording; the
   approver cannot, so the approver never sees it unless the requester
   escalates. History does not change this: a bad reason is a bad reason.
5. ACL allow + triage HIGH confidence + APPROVE + no risk flag -> the only
   case where AI gets unilateral approve authority.
6. Everything else (over-scope, risk_flag=True even on a confident APPROVE,
   low confidence, a stepless DENY -- AI never gets unilateral deny
   authority) routes to a human: least privilege and risk are a reviewer's
   judgment call, not a wording fix.

History rules (user-stated: use the SQL data we already have to gain
confidence on large scopes, and make newcomers earn trust rather than
trusting the AI's read of a reason string):
* A denial or revocation within the last `negative_event_window_seconds`
  (30 days) forces ROUTE_HUMAN, whatever triage recommended.
* A first LARGE-scope request from a requester who has never held a grant
  forces ROUTE_HUMAN, never AUTO_APPROVE. Large scope = an access level in
  `large_scope_levels` (write/admin) or a duration over
  `large_scope_duration_seconds` (1h). A newcomer's SMALL request (read,
  <= 1h) may still auto-approve on HIGH confidence: the point is "earn
  trust", not "block newcomers".
Triage still runs in both forced-human cases: TRIAGED is audited and the
reviewer sees the AI's step analysis on the approval page; the history
note is prefixed to the reason so they also see why it landed with them.

Failure policy: a component *denying* is a decision; a component *throwing*
is a system failure. A failure anywhere in this pipeline never crashes the
request, never auto-denies, and never auto-approves -- it routes to manual
review with the failure text in the reason, so the reviewer and the audit
log both see what broke. If the ACL boundary (or the history gate) can't be
evaluated, triage is skipped too: an AI APPROVE that nothing has gated must
not exist.
"""
from typing import Optional, Sequence

from broker.acl_policy import AclPolicyEngine
from broker.clock import SystemClock
from broker.models import PolicyDecision, PolicyDecisionType
from broker.policy import Policy
from broker.llm_decision_agent import (
    _MIN_REASON_LENGTH,
    _NON_SUBSTANTIVE_REASONS,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageResult,
    TriageStepName,
)
from broker.requester_history import RequesterHistory, RequesterHistoryReader
from broker.user_directory import UserDirectory

JUNK_REASON_MESSAGE = "reason is missing or a placeholder -- say what you need to do and why"

# TODO (richer behavioural rules -- deliberately not in this change, each
# needs its own design and its own evals):
#   * behavioural baselines per requester: usual resources, usual hours of
#     day, usual durations -- so "admin on prod-db at 03:00 for 8h" is judged
#     against what THIS person normally asks for, not a global threshold;
#   * anomaly vs. own history rather than absolute thresholds (a first-ever
#     resource, a first-ever access level on a familiar resource, a duration
#     several times the requester's median);
#   * agent-vs-human requesters: automated agents/service accounts get
#     stricter defaults (smaller large-scope thresholds, no auto-approve on
#     admin at all) since they cannot be asked follow-up questions;
#   * cool-down after a denial: a resubmission within N minutes of a denial
#     for the same scope goes straight to the same reviewer, not to triage;
#   * escalation counts as a signal: repeated escalations of RETURNED
#     requests lower confidence in the requester's stated reasons.


class PolicyEngine(Policy):
    def __init__(
        self,
        user_directory: UserDirectory,
        acl_engine: AclPolicyEngine,
        triage_provider: TriageProvider,
        history_reader: Optional[RequesterHistoryReader] = None,
        clock=None,
        large_scope_levels: Sequence[str] = ("write", "admin"),
        large_scope_duration_seconds: int = 3600,
        negative_event_window_seconds: int = 30 * 24 * 3600,
    ):
        self.user_directory = user_directory
        self.acl_engine = acl_engine
        self.triage_provider = triage_provider
        # Optional: with no reader the engine behaves exactly as before and
        # calls the triage provider with the plain four arguments.
        self.history_reader = history_reader
        self.clock = clock or SystemClock()  # only used for `now` in history lookups
        self.large_scope_levels = tuple(large_scope_levels)
        self.large_scope_duration_seconds = large_scope_duration_seconds
        self.negative_event_window_seconds = negative_event_window_seconds

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

        history: Optional[RequesterHistory] = None
        if self.history_reader is not None:
            try:
                history = self._load_history(requester, resource, access_level)
            except Exception as exc:  # deliberate: the history gate broke -> manual review, no ungated AI APPROVE
                return self._defer_to_human("requester history lookup failed", exc)
        history_summary = history.summary() if history is not None else None

        try:
            if history is not None:
                triage_result = self.triage_provider.triage(
                    resource, access_level, duration_seconds, reason, context=history_summary
                )
            else:
                # No history -> the pre-existing four-argument call, so a
                # provider written against the old signature still works.
                triage_result = self.triage_provider.triage(resource, access_level, duration_seconds, reason)
        except Exception as exc:  # deliberate: any failure here -> manual review, see module docstring
            return self._defer_to_human("triage failed", exc, history_summary)

        # Step 1 failing means "this reason does not justify this permission".
        # That is the requester's to fix, not the approver's, so it goes back
        # to them -- history does not change that. A provider whose result
        # carries no steps (a hand-written fake, or one that stopped somewhere
        # else) keeps the plain rules.
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
            if history is not None:
                decision, reason_text = self._apply_history_rules(
                    history, access_level, duration_seconds, decision, reason_text
                )

        # Carry the full triage signal, not just the flattened justification,
        # so the audit log can show why the AI recommended what it did.
        return PolicyDecision(
            decision=decision,
            reason=reason_text,
            triage_recommendation=triage_result.recommendation.value,
            triage_confidence=triage_result.confidence.value,
            triage_risk_flag=triage_result.risk_flag,
            triage_justification=triage_result.justification,
            triage_steps_summary=triage_result.steps_summary() or None,
            suggested_access_level=triage_result.suggested_access_level,
            suggested_duration_seconds=triage_result.suggested_duration_seconds,
            history_summary=history_summary,
        )

    def _load_history(self, requester: str, resource: str, access_level: str) -> RequesterHistory:
        """One read of the requester's record. Broker.request_access has
        already inserted the current request row when it calls decide(), and
        Policy.decide() does not receive the request id, so the lookup runs
        WITHOUT exclude_request_id. Consequences, deliberately accepted:
        `total_requests` in the summary counts the request being decided
        (off by one, cosmetic -- it only appears in the prompt/audit line).
        Nothing the rules below depend on is affected: `is_new` is based on
        approved grants, `had_recent_negative_event` on DENIED/HUMAN_DENIED/
        REVOKED audit rows, and the current request can have neither yet."""
        return self.history_reader.for_request(requester, resource, access_level, self.clock.now())

    def _apply_history_rules(
        self,
        history: RequesterHistory,
        access_level: str,
        duration_seconds: int,
        decision: PolicyDecisionType,
        reason_text: str,
    ) -> tuple:
        """Deterministic, no model: may only tighten (-> ROUTE_HUMAN), never
        loosen, a decision. Only reached for AUTO_APPROVE/ROUTE_HUMAN
        candidates -- RETURN_TO_REQUESTER is decided before this."""
        now = self.clock.now()
        if history.had_recent_negative_event(now, self.negative_event_window_seconds):
            days = self.negative_event_window_seconds // (24 * 3600)
            return (
                PolicyDecisionType.ROUTE_HUMAN,
                f"requester had a denial or revocation in the last {days} days; {history.summary()}; {reason_text}",
            )

        is_large_scope = access_level in self.large_scope_levels or duration_seconds > self.large_scope_duration_seconds
        if history.is_new and is_large_scope:
            return (
                PolicyDecisionType.ROUTE_HUMAN,
                f"first large-scope request from a requester with no prior approved grants; {reason_text}",
            )

        return decision, reason_text

    @staticmethod
    def _is_junk_reason(reason: str) -> bool:
        """The deterministic junk gate. Shares its placeholder list and
        length floor with MockTriageProvider's step 1 (imported, not copied)
        so the two can never drift apart. A rule this simple belongs in code
        a security reviewer can read, not in a model call."""
        stripped = reason.strip()
        return stripped.lower() in _NON_SUBSTANTIVE_REASONS or len(stripped) < _MIN_REASON_LENGTH

    @staticmethod
    def _defer_to_human(what_failed: str, exc: Exception, history_summary: Optional[str] = None) -> PolicyDecision:
        return PolicyDecision(
            decision=PolicyDecisionType.ROUTE_HUMAN,
            reason=f"{what_failed} ({type(exc).__name__}: {exc}); deferring to human review",
            history_summary=history_summary,
        )
