"""
Evals for MockTriageProvider.triage -- the deterministic heuristic standing
in for a real LLM call. Each branch is asserted on recommendation,
confidence, AND risk_flag together, since a test that only checks one field
could pass even if the others are wrong.
"""
from broker.triage import (
    MockTriageProvider,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageResult,
)


def test_short_reason_is_denied_with_low_confidence_and_risk_flag():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db", access_level="read", duration_seconds=600, reason="oops"
    )

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert "too short" in result.justification


def test_placeholder_reason_is_denied_with_low_confidence_and_risk_flag():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db", access_level="read", duration_seconds=600, reason="  Testing  "
    )

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert "substantive" in result.justification


def test_admin_access_for_extended_duration_is_approved_but_flagged_as_risky():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db",
        access_level="admin",
        duration_seconds=7200,
        reason="need to patch a critical CVE in the prod database tonight",
    )

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.MEDIUM
    assert result.risk_flag is True
    assert "elevated risk" in result.justification


def test_substantive_reason_with_unremarkable_request_is_approved_confidently():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="staging-db",
        access_level="read",
        duration_seconds=600,
        reason="debugging a failing integration test in staging",
    )

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.HIGH
    assert result.risk_flag is False
    assert "proportionate" in result.justification


def test_mock_triage_provider_is_a_real_triage_provider():
    provider = MockTriageProvider()

    assert isinstance(provider, TriageProvider)

    result = provider.triage(
        resource="prod-db",
        access_level="read",
        duration_seconds=600,
        reason="on-call incident response for a customer-facing outage",
    )
    assert isinstance(result, TriageResult)
