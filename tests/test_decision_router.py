"""
Evals for DecisionRouter -- the real PolicyEngine implementation that
composes UserDirectory, AclPolicyEngine, and TriageProvider into a final
decision. Uses a REAL Database + DatabaseUserDirectory + AclPolicyEngine
(seeded via the already-tested db.set_user_role / db.load_acl_rules), and
either a hand-written FakeTriageProvider (for exact, controlled triage
output the real MockTriageProvider heuristic can't produce -- e.g. a
confident DENY) or the real MockTriageProvider (for realistic end-to-end
cases).
"""
from broker.acl_policy import AclPolicyEngine
from broker.db import Database
from broker.decision_router import DecisionRouter
from broker.models import PolicyDecisionType
from broker.triage import (
    MockTriageProvider,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageResult,
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
    return DecisionRouter(user_directory, acl_engine, triage_provider), db


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


def test_end_to_end_with_real_mock_triage_provider_vague_reason_routes_to_human(tmp_path):
    router, db = make_router(
        tmp_path,
        rules=[{"role": "engineer", "resource_pattern": "prod-db", "max_access_level": "read", "max_duration_seconds": 3600}],
        triage_provider=MockTriageProvider(),
    )
    db.set_user_role("gina", "engineer")

    decision = router.decide(
        requester="gina", resource="prod-db", access_level="read", duration_seconds=600, reason="testing"
    )

    assert decision.decision == PolicyDecisionType.ROUTE_HUMAN
    assert "not appear substantive" in decision.reason


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
