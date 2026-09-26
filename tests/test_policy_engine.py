"""
Evals for PolicyEngine -- the real PolicyEngine implementation that
composes UserDirectory, AclPolicyEngine, and TriageProvider into a final
decision. Uses a REAL Database + DatabaseUserDirectory + AclPolicyEngine
(seeded via the already-tested db.set_user_role / db.load_acl_rules), and
either a hand-written FakeTriageProvider (for exact, controlled triage
output the real MockTriageProvider heuristic can't produce -- e.g. a
confident DENY) or the real MockTriageProvider (for realistic end-to-end
cases).
"""
from broker.acl_policy import AclPolicyEngine
from broker.clock import FakeClock
from broker.db import Database
from broker.policy_engine import PolicyEngine
from broker.models import AuditEventType, PolicyDecisionType
from broker.requester_history import RequesterHistoryReader
from broker.llm_decision_agent import (
    MockTriageProvider,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageResult,
    TriageStep,
    TriageStepName,
)
from broker.user_directory import DatabaseUserDirectory


class FakeTriageProvider(TriageProvider):
    """Hand-written test double that returns an exact, pre-configured
    TriageResult -- used where the real MockTriageProvider's heuristic
    cannot produce the combination under test (e.g. a HIGH-confidence
    DENY, which MockTriageProvider's DENY branches never produce)."""

    def __init__(self, result: TriageResult):
        self.result = result
        self.calls = []

    def triage(self, resource, access_level, duration_seconds, reason):
        self.calls.append((resource, access_level, duration_seconds, reason))
        return self.result


def make_router(tmp_path, rules, triage_provider):
    db = Database(str(tmp_path / "test.db"))
    db.load_acl_rules(rules)
    user_directory = DatabaseUserDirectory(db)
    acl_engine = AclPolicyEngine(db)
    return PolicyEngine(user_directory, acl_engine, triage_provider), db


def test_acl_deny_short_circuits_before_triage_is_ever_called(tmp_path):
    # Requester has no assigned role at all -> ACL denies immediately.
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="should never be seen",
            risk_flag=False,
        )
    )
    router, _db = make_router(tmp_path, rules=[], triage_provider=fake_triage)

    decision = router.decide(
        requester="alice", resource="prod-db", access_level="read", duration_seconds=600, reason="doing my job"
    )

    assert decision.decision == PolicyDecisionType.DENY
    assert "no assigned role" in decision.reason
    assert fake_triage.calls == []
    # triage never ran, so there is no triage signal to report
    assert decision.triage_recommendation is None
    assert decision.triage_confidence is None
    assert decision.triage_risk_flag is None
    assert decision.triage_justification is None


def test_acl_denies_on_ceiling_violation_before_triage_is_ever_called(tmp_path):
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="should never be seen",
            risk_flag=False,
        )
    )
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=fake_triage,
    )
    db.set_user_role("bob", "engineer")

    decision = router.decide(
        requester="bob", resource="prod-db", access_level="admin", duration_seconds=600, reason="need admin access now"
    )

    assert decision.decision == PolicyDecisionType.DENY
    assert "capped at 'read'" in decision.reason
    assert fake_triage.calls == []


def test_acl_allow_plus_high_confidence_approve_no_risk_is_auto_approved(tmp_path):
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="reason is clearly legitimate",
            risk_flag=False,
        )
    )
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=fake_triage,
    )
    db.set_user_role("carol", "engineer")

    decision = router.decide(
        requester="carol", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE
    assert decision.reason == "reason is clearly legitimate"
    assert fake_triage.calls == [("prod-db", "read", 600, "debugging an incident")]
    # the triage signal survives into the decision so the broker can audit
    # WHY the AI recommended what it did, not just the flattened reason
    assert decision.triage_recommendation == "APPROVE"
    assert decision.triage_confidence == "HIGH"
    assert decision.triage_risk_flag is False
    assert decision.triage_justification == "reason is clearly legitimate"


def test_confident_deny_still_routes_to_human_not_denied_outright(tmp_path):
    # AI never gets unilateral deny authority -- only unilateral approve.
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.DENY,
            confidence=TriageConfidence.HIGH,
            justification="this looks suspicious",
            risk_flag=False,
        )
    )
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=fake_triage,
    )
    db.set_user_role("dave", "engineer")

    decision = router.decide(
        requester="dave", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert decision.decision != PolicyDecisionType.DENY
    assert decision.reason == "this looks suspicious"


def test_risk_flag_forces_human_review_even_on_confident_approve(tmp_path):
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="approved but flagged as risky",
            risk_flag=True,
        )
    )
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "admin", "max_duration_seconds": 7200}],
        triage_provider=fake_triage,
    )
    db.set_user_role("erin", "engineer")

    decision = router.decide(
        requester="erin", resource="prod-db", access_level="admin", duration_seconds=7200, reason="urgent production fix"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert decision.reason == "approved but flagged as risky"
    assert decision.triage_recommendation == "APPROVE"
    assert decision.triage_confidence == "HIGH"
    assert decision.triage_risk_flag is True
    assert decision.triage_justification == "approved but flagged as risky"


def test_medium_confidence_approve_is_not_high_enough_to_auto_approve(tmp_path):
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.MEDIUM,
            justification="probably fine but not certain",
            risk_flag=False,
        )
    )
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=fake_triage,
    )
    db.set_user_role("frank", "engineer")

    decision = router.decide(
        requester="frank", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert decision.reason == "probably fine but not certain"


def test_end_to_end_with_real_mock_triage_provider_placeholder_reason_is_returned_to_requester(tmp_path):
    # "testing" is in the placeholder set, so the deterministic junk gate
    # returns it to the requester before any triage runs.
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=MockTriageProvider(),
    )
    db.set_user_role("gina", "engineer")

    decision = router.decide(
        requester="gina", resource="prod-db", access_level="read", duration_seconds=600, reason="testing"
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert "placeholder" in decision.reason
    assert decision.triage_recommendation is None


def test_end_to_end_with_real_mock_triage_provider_irrelevant_reason_for_admin_is_returned_to_requester(tmp_path):
    # Substantive wording, so it clears the junk gate and triage runs -- but
    # step 1 finds it describes no change to make, which cannot justify admin.
    router, db = make_router(
        tmp_path,
        rules=[{"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200}],
        triage_provider=MockTriageProvider(),
    )
    db.set_user_role("gina", "oncall")

    decision = router.decide(
        requester="gina",
        resource="prod-db",
        access_level="admin",
        duration_seconds=600,
        reason="I want to look at the dashboards for a while",
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert "does not justify admin" in decision.reason
    # triage DID run here, so its signal must survive for the TRIAGED audit
    assert decision.triage_recommendation == "DENY"
    assert decision.triage_confidence == "LOW"
    assert decision.triage_risk_flag is True
    assert decision.triage_justification == decision.reason


# --- Return-to-requester: an insufficient reason is the requester's problem
# to fix, not the approver's. Two rules produce it: a deterministic junk gate
# that runs BEFORE triage (no model cost, no approver time), and a failed
# triage step 1 ("this reason does not justify this permission"). Over-scope,
# risk flags, low confidence, and system failures still go to a human.


def _fake_high_approve():
    return FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="should never be seen",
            risk_flag=False,
        )
    )


ENGINEER_READ_RULES = [
    {"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}
]


def test_placeholder_reason_is_returned_to_requester_without_calling_triage(tmp_path):
    fake_triage = _fake_high_approve()
    router, db = make_router(tmp_path, rules=ENGINEER_READ_RULES, triage_provider=fake_triage)
    db.set_user_role("jane", "engineer")

    decision = router.decide(
        requester="jane", resource="prod-db", access_level="read", duration_seconds=600, reason="  IDK "
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert "placeholder" in decision.reason
    assert fake_triage.calls == []
    assert decision.triage_recommendation is None
    assert decision.triage_confidence is None
    assert decision.triage_risk_flag is None
    assert decision.triage_justification is None


def test_too_short_reason_is_returned_to_requester_without_calling_triage(tmp_path):
    fake_triage = _fake_high_approve()
    router, db = make_router(tmp_path, rules=ENGINEER_READ_RULES, triage_provider=fake_triage)
    db.set_user_role("jane", "engineer")

    decision = router.decide(
        requester="jane", resource="prod-db", access_level="read", duration_seconds=600, reason="ops stuff"
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert fake_triage.calls == []
    assert decision.triage_recommendation is None


def test_junk_gate_runs_after_acl_so_a_denied_requester_still_sees_deny(tmp_path):
    # ACL deny is a hard stop and comes first: a requester with no role gets
    # DENY, not "fix your reason", even when the reason is junk.
    fake_triage = _fake_high_approve()
    router, _db = make_router(tmp_path, rules=[], triage_provider=fake_triage)

    decision = router.decide(
        requester="nobody", resource="prod-db", access_level="read", duration_seconds=600, reason="idk"
    )

    assert decision.decision == PolicyDecisionType.DENY
    assert fake_triage.calls == []


def test_failed_reason_validation_step_is_returned_to_requester_with_triage_fields(tmp_path):
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.DENY,
            confidence=TriageConfidence.LOW,
            justification="reason does not justify write access: it describes no change to make",
            risk_flag=True,
            steps=[
                TriageStep(
                    TriageStepName.REASON_VALIDATION,
                    False,
                    "reason does not justify write access: it describes no change to make",
                )
            ],
        )
    )
    router, db = make_router(
        tmp_path,
        rules=[{"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200}],
        triage_provider=fake_triage,
    )
    db.set_user_role("kim", "oncall")

    decision = router.decide(
        requester="kim", resource="prod-db", access_level="write", duration_seconds=600, reason="checking the replication lag graphs"
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert decision.reason == "reason does not justify write access: it describes no change to make"
    assert len(fake_triage.calls) == 1
    assert decision.triage_recommendation == "DENY"
    assert decision.triage_confidence == "LOW"
    assert decision.triage_risk_flag is True


def test_stepless_deny_from_a_provider_without_steps_still_routes_to_human(tmp_path):
    # A TriageResult with no steps carries no "step 1 failed" signal, so the
    # pre-existing rule applies: AI never gets unilateral deny authority.
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.DENY,
            confidence=TriageConfidence.LOW,
            justification="reason does not appear substantive",
            risk_flag=True,
        )
    )
    router, db = make_router(tmp_path, rules=ENGINEER_READ_RULES, triage_provider=fake_triage)
    db.set_user_role("lee", "engineer")

    decision = router.decide(
        requester="lee", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert decision.reason == "reason does not appear substantive"


def test_passed_step_one_but_failed_scope_step_still_routes_to_human(tmp_path):
    # oncall may hold admin/7200 and the reason is substantive and mutating,
    # so step 1 passes; step 2 flags the extended admin scope. Least privilege
    # is the approver's call, not a wording fix -> human, not returned.
    router, db = make_router(
        tmp_path,
        rules=[{"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200}],
        triage_provider=MockTriageProvider(),
    )
    db.set_user_role("mia", "oncall")

    decision = router.decide(
        requester="mia",
        resource="prod-db",
        access_level="admin",
        duration_seconds=7200,
        reason="rotating leaked credentials after incident 4711",
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert decision.triage_recommendation == "APPROVE"
    assert decision.triage_risk_flag is True


def test_end_to_end_with_real_mock_triage_provider_substantive_reason_is_auto_approved(tmp_path):
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=MockTriageProvider(),
    )
    db.set_user_role("henry", "engineer")

    decision = router.decide(
        requester="henry",
        resource="prod-db",
        access_level="read",
        duration_seconds=600,
        reason="need to investigate a customer-reported data discrepancy",
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE
    assert "proportionate" in decision.reason


# --- Failure policy: if the decision machinery itself fails, fall back to a
# human. A component *denying* is a decision; a component *throwing* is a
# system failure, and a system failure must never crash the request, never
# auto-deny, and never auto-approve -- it routes to manual review with the
# failure recorded in the reason so the reviewer (and the audit log) see it.


class ExplodingTriageProvider(TriageProvider):
    def triage(self, resource, access_level, duration_seconds, reason):
        raise RuntimeError("triage backend exploded")


class ExplodingUserDirectory:
    def get_role(self, requester):
        raise ConnectionError("directory unreachable")


class ExplodingAclEngine:
    def evaluate(self, role, resource, access_level, duration_seconds):
        raise RuntimeError("acl table unreadable")


def test_triage_failure_routes_to_human_instead_of_crashing(tmp_path):
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=ExplodingTriageProvider(),
    )
    db.set_user_role("ivan", "engineer")

    decision = router.decide(
        requester="ivan", resource="prod-db", access_level="read", duration_seconds=600, reason="investigating an alert"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "triage" in decision.reason.lower()
    assert "triage backend exploded" in decision.reason
    # a failed triage call produced no recommendation to record
    assert decision.triage_recommendation is None
    assert decision.triage_confidence is None


def test_user_directory_failure_routes_to_human_instead_of_denying(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    router = PolicyEngine(ExplodingUserDirectory(), AclPolicyEngine(db), MockTriageProvider())

    decision = router.decide(
        requester="ivan", resource="prod-db", access_level="read", duration_seconds=600, reason="investigating an alert"
    )

    # Not DENY: an unreachable directory is a failure, not a policy outcome.
    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "directory unreachable" in decision.reason


def test_acl_engine_failure_routes_to_human_and_skips_triage(tmp_path):
    fake_triage = FakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="should never be seen",
        )
    )
    db = Database(str(tmp_path / "test.db"))
    db.set_user_role("ivan", "engineer")
    router = PolicyEngine(DatabaseUserDirectory(db), ExplodingAclEngine(), fake_triage)

    decision = router.decide(
        requester="ivan", resource="prod-db", access_level="read", duration_seconds=600, reason="investigating an alert"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "acl table unreadable" in decision.reason
    # With the ACL boundary unverifiable, the AI step must not run -- it
    # could otherwise produce a confident APPROVE that nothing has gated.
    assert fake_triage.calls == []


# --- Triage step details survive into the decision (T9d) -------------------
# The Broker writes PolicyDecision.triage_steps_summary and the least-privilege
# suggestion into the audit log, so the engine must carry them across.


def test_decision_carries_step_summary_and_least_privilege_suggestion(tmp_path):
    router, db = make_router(
        tmp_path,
        rules=[{"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200}],
        triage_provider=MockTriageProvider(),
    )
    db.set_user_role("mia", "oncall")

    decision = router.decide(
        requester="mia",
        resource="prod-db",
        access_level="admin",
        duration_seconds=7200,
        reason="rotating leaked credentials after incident 4711",
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert decision.triage_steps_summary == (
        "reason_validation=pass; "
        "scope_proportionality=fail (admin access for an extended duration carries elevated risk); "
        "risk_assessment=fail (APPROVE with MEDIUM confidence; over-scoped request flagged for human review)"
    )
    assert decision.suggested_access_level == "write"
    assert decision.suggested_duration_seconds == 3600
    # no history reader configured -> no history lookup happened
    assert decision.history_summary is None


def test_stepless_triage_result_leaves_steps_summary_unset(tmp_path):
    router, db = make_router(tmp_path, rules=ENGINEER_READ_RULES, triage_provider=_fake_high_approve())
    db.set_user_role("jane", "engineer")

    decision = router.decide(
        requester="jane", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE
    assert decision.triage_steps_summary is None
    assert decision.suggested_access_level is None
    assert decision.suggested_duration_seconds is None


# --- Requester history as a confidence input (T9e) -------------------------
# Deterministic rules over the requester's own record in the broker's tables,
# applied AFTER the ACL and the junk gate and around the triage call:
#   * a denial or revocation in the last 30 days -> human, whatever triage says
#   * a first large-scope request (write/admin, or > 1h) from someone who has
#     never held a grant -> human, even on a confident APPROVE ("earn trust")
#   * a new requester's SMALL request may still auto-approve
#   * return-to-requester outcomes are unaffected: a bad reason is a bad reason
# Triage still runs in the forced-human cases so the reviewer sees its analysis.

NOW = 1_700_000_000
DAY = 24 * 3600
ONCALL_RULES = [{"role": "oncall", "resource_pattern": "prod-*", "max_access_level": "admin", "max_duration_seconds": 7200}]
KEYWORD_REASON = "rotating leaked credentials after incident 4711"


class ContextAwareFakeTriageProvider(FakeTriageProvider):
    """Same fixed result, but records the `context` keyword the engine passes
    once a history reader is configured (the plain fake keeps the old
    4-argument signature to prove the no-history call site is unchanged)."""

    def triage(self, resource, access_level, duration_seconds, reason, context=None):
        self.calls.append((resource, access_level, duration_seconds, reason, context))
        return self.result


def _high_approve_with_steps():
    return ContextAwareFakeTriageProvider(
        TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="reason is clearly legitimate",
            risk_flag=False,
            steps=[
                TriageStep(TriageStepName.REASON_VALIDATION, True, "ok"),
                TriageStep(TriageStepName.SCOPE_PROPORTIONALITY, True, "ok"),
                TriageStep(TriageStepName.RISK_ASSESSMENT, True, "APPROVE with HIGH confidence"),
            ],
        )
    )


def make_history_router(tmp_path, rules, triage_provider, clock=None, **engine_kwargs):
    db = Database(str(tmp_path / "test.db"))
    db.load_acl_rules(rules)
    engine = PolicyEngine(
        DatabaseUserDirectory(db),
        AclPolicyEngine(db),
        triage_provider,
        history_reader=RequesterHistoryReader(db),
        clock=clock or FakeClock(NOW),
        **engine_kwargs,
    )
    return engine, db


def _seed_approved_grant(db, requester, resource="prod-db", access_level="read", at=NOW - 5 * DAY):
    request_id = db.create_request(requester, resource, access_level, 600, "earlier, approved", at=at)
    db.create_grant(request_id, requester, resource, access_level, "tok-old", at, at + 600)


def test_new_requester_large_scope_is_forced_to_human_after_triage_ran(tmp_path):
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="admin", duration_seconds=1800, reason=KEYWORD_REASON
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "no prior approved grants" in decision.reason
    assert decision.reason.endswith("reason is clearly legitimate")  # the AI's justification is kept for the reviewer
    # triage WAS called, and its signal is on the decision for the TRIAGED audit
    assert len(fake_triage.calls) == 1
    assert decision.triage_recommendation == "APPROVE"
    assert decision.triage_confidence == "HIGH"
    assert decision.triage_steps_summary == "reason_validation=pass; scope_proportionality=pass; risk_assessment=pass"


def test_same_requester_with_one_prior_grant_auto_approves_the_same_request(tmp_path):
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("newbie", "oncall")
    _seed_approved_grant(db, "newbie")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="admin", duration_seconds=1800, reason=KEYWORD_REASON
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE
    assert decision.reason == "reason is clearly legitimate"


def test_new_requester_small_scope_still_auto_approves(tmp_path):
    # "earn trust", not "block newcomers": read for 10 minutes is small scope.
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE


def test_new_requester_long_read_counts_as_large_scope(tmp_path):
    # Duration alone makes it large scope: read for 2h is > the 1h threshold.
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="read", duration_seconds=7200, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "no prior approved grants" in decision.reason


def _seed_human_denial(db, requester, at):
    request_id = db.create_request(requester, "prod-db", "admin", 1800, "earlier request", at=at)
    db.append_audit(request_id, None, AuditEventType.HUMAN_DENIED, "denied by dana", at=at)


def test_recent_denial_forces_human_even_on_confident_approve(tmp_path):
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("vic", "oncall")
    _seed_approved_grant(db, "vic")  # not new, so only the denial can route this
    _seed_human_denial(db, "vic", at=NOW - 2 * DAY)

    decision = router.decide(
        requester="vic", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "denial or revocation" in decision.reason
    assert "last 30 days" in decision.reason
    assert len(fake_triage.calls) == 1  # triage still ran so the reviewer sees its analysis
    assert decision.triage_recommendation == "APPROVE"


def test_old_denial_outside_the_window_does_not_force_human(tmp_path):
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("vic", "oncall")
    _seed_approved_grant(db, "vic")
    _seed_human_denial(db, "vic", at=NOW - 60 * DAY)

    decision = router.decide(
        requester="vic", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE


def test_junk_reason_from_new_requester_is_still_returned_not_routed(tmp_path):
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="admin", duration_seconds=1800, reason="idk"
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert fake_triage.calls == []
    assert decision.history_summary is None  # the junk gate runs before any history lookup


def test_failed_step_one_from_new_requester_is_still_returned_not_routed(tmp_path):
    # Real mock: "look at the dashboards" describes no change -> step 1 fails.
    router, db = make_history_router(tmp_path, ONCALL_RULES, MockTriageProvider())
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="admin", duration_seconds=1800,
        reason="I want to look at the dashboards for a while",
    )

    assert decision.decision == PolicyDecisionType.RETURN_TO_REQUESTER
    assert "does not justify admin" in decision.reason


def test_history_summary_is_on_the_decision_and_passed_to_triage_as_context(tmp_path):
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(tmp_path, ONCALL_RULES, fake_triage)
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.history_summary is not None
    assert decision.history_summary.startswith("requester=newbie ")
    assert "approved_grants=0" in decision.history_summary
    # the same line the LLM prompt saw
    assert fake_triage.calls[0][4] == decision.history_summary


def test_without_a_history_reader_triage_is_called_with_the_plain_four_arguments(tmp_path):
    fake_triage = _fake_high_approve()  # the 4-argument fake: a `context` kwarg would TypeError
    router, db = make_router(tmp_path, rules=ENGINEER_READ_RULES, triage_provider=fake_triage)
    db.set_user_role("jane", "engineer")

    decision = router.decide(
        requester="jane", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE
    assert fake_triage.calls == [("prod-db", "read", 600, "debugging an incident")]


def test_large_scope_thresholds_are_configurable(tmp_path):
    # With write no longer large-scope and the duration bar at 2h, a new
    # requester's write/7200 is small scope and may auto-approve.
    fake_triage = _high_approve_with_steps()
    router, db = make_history_router(
        tmp_path, ONCALL_RULES, fake_triage, large_scope_levels=("admin",), large_scope_duration_seconds=7200
    )
    db.set_user_role("newbie", "oncall")

    decision = router.decide(
        requester="newbie", resource="prod-db", access_level="write", duration_seconds=7200, reason=KEYWORD_REASON
    )

    assert decision.decision == PolicyDecisionType.AUTO_APPROVE


class ExplodingHistoryReader:
    def for_request(self, requester, resource, access_level, now, exclude_request_id=None):
        raise RuntimeError("history table unreadable")


def test_history_lookup_failure_routes_to_human_instead_of_crashing(tmp_path):
    # Same failure policy as every other component: throwing is not deciding.
    db = Database(str(tmp_path / "test.db"))
    db.load_acl_rules(ONCALL_RULES)
    db.set_user_role("vic", "oncall")
    fake_triage = _high_approve_with_steps()
    router = PolicyEngine(
        DatabaseUserDirectory(db), AclPolicyEngine(db), fake_triage, history_reader=ExplodingHistoryReader(), clock=FakeClock(NOW)
    )

    decision = router.decide(
        requester="vic", resource="prod-db", access_level="read", duration_seconds=600, reason="debugging an incident"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "history table unreadable" in decision.reason
    assert fake_triage.calls == []  # an ungated AI APPROVE must not exist when the gate itself broke
