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
    TriageStep,
    TriageStepName,
)


# --- Data model: TriageResult stays backwards compatible, gains steps ------


def test_triage_result_new_fields_default_to_empty():
    result = TriageResult(
        recommendation=TriageRecommendation.APPROVE,
        confidence=TriageConfidence.HIGH,
        justification="fine",
    )

    assert result.risk_flag is False
    assert result.steps == []
    assert result.suggested_access_level is None
    assert result.suggested_duration_seconds is None


def test_steps_summary_is_single_line_with_detail_only_for_failed_steps():
    result = TriageResult(
        recommendation=TriageRecommendation.APPROVE,
        confidence=TriageConfidence.MEDIUM,
        justification="x",
        risk_flag=True,
        steps=[
            TriageStep(TriageStepName.REASON_VALIDATION, True, "reason is substantive"),
            TriageStep(
                TriageStepName.SCOPE_PROPORTIONALITY,
                False,
                "admin for 7200s exceeds what the reason needs; suggest read/3600s",
            ),
            TriageStep(TriageStepName.RISK_ASSESSMENT, True, "APPROVE with MEDIUM confidence"),
        ],
    )

    summary = result.steps_summary()

    assert summary == (
        "reason_validation=pass; "
        "scope_proportionality=fail (admin for 7200s exceeds what the reason needs; suggest read/3600s); "
        "risk_assessment=pass"
    )
    assert "\n" not in summary


def test_steps_summary_with_no_steps_is_empty_string():
    result = TriageResult(
        recommendation=TriageRecommendation.DENY,
        confidence=TriageConfidence.LOW,
        justification="x",
    )

    assert result.steps_summary() == ""


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


# --- Multi-step pipeline: step 1 validates the reason AGAINST the requested
# permission and gates steps 2/3; step 2 applies least privilege; step 3 is
# the final recommendation. -------------------------------------------------


def _step_names(result: TriageResult):
    return [step.name for step in result.steps]


def test_read_only_reason_does_not_justify_admin_and_stops_at_step_one():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="grafana",
        access_level="admin",
        duration_seconds=3600,
        reason="I want to look at the dashboards for a while",
    )

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert len(result.steps) == 1
    assert result.steps[0].name == TriageStepName.REASON_VALIDATION
    assert result.steps[0].passed is False
    assert "does not justify admin" in result.steps[0].detail
    assert result.justification == result.steps[0].detail
    assert result.suggested_access_level is None
    assert result.suggested_duration_seconds is None


def test_same_read_only_reason_is_consistent_with_read_access_and_passes_all_steps():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="grafana",
        access_level="read",
        duration_seconds=3600,
        reason="I want to look at the dashboards for a while",
    )

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.HIGH
    assert result.risk_flag is False
    assert _step_names(result) == [
        TriageStepName.REASON_VALIDATION,
        TriageStepName.SCOPE_PROPORTIONALITY,
        TriageStepName.RISK_ASSESSMENT,
    ]
    assert all(step.passed for step in result.steps)
    assert "consistent with read access" in result.steps[0].detail


def test_read_only_reason_does_not_justify_write_either():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db",
        access_level="write",
        duration_seconds=600,
        reason="I want to look at the dashboards for a while",
    )

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert len(result.steps) == 1
    assert "does not justify write" in result.steps[0].detail


def test_over_scoped_admin_request_passes_step_one_fails_step_two_and_suggests_least_privilege():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db",
        access_level="admin",
        duration_seconds=7200,
        reason="rotating leaked credentials after incident 4711",
    )

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.MEDIUM
    assert result.risk_flag is True
    assert result.justification == (
        "reason is present but admin access for an extended duration carries elevated risk"
    )
    assert _step_names(result) == [
        TriageStepName.REASON_VALIDATION,
        TriageStepName.SCOPE_PROPORTIONALITY,
        TriageStepName.RISK_ASSESSMENT,
    ]
    assert result.steps[0].passed is True
    assert result.steps[1].passed is False
    assert result.steps[2].passed is False  # risk was flagged
    assert result.suggested_access_level == "write"
    assert result.suggested_duration_seconds == 3600
    assert "scope_proportionality=fail" in result.steps_summary()
    assert result.steps_summary().startswith("reason_validation=pass; ")


def test_long_read_request_fails_step_two_on_the_eight_hour_rule():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db",
        access_level="read",
        duration_seconds=36000,
        reason="investigating a customer-reported data discrepancy",
    )

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.MEDIUM
    assert result.risk_flag is True
    assert result.steps[0].passed is True
    assert result.steps[1].passed is False
    assert "8 hours" in result.steps[1].detail
    assert result.suggested_access_level is None
    assert result.suggested_duration_seconds == 28800
    assert "reason is present but" in result.justification


def test_step_one_failure_records_exact_placeholder_phrase_and_nothing_else_runs():
    provider = MockTriageProvider()

    result = provider.triage(resource="prod-db", access_level="read", duration_seconds=600, reason="idk")

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert result.justification == "reason does not appear substantive"
    assert len(result.steps) == 1
    assert result.steps[0].name == TriageStepName.REASON_VALIDATION
    assert result.steps[0].passed is False
    assert result.steps_summary() == "reason_validation=fail (reason does not appear substantive)"


def test_step_one_failure_records_exact_too_short_phrase():
    provider = MockTriageProvider()

    result = provider.triage(resource="prod-db", access_level="admin", duration_seconds=600, reason="need it")

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert result.justification == "reason is too short to evaluate for validity"
    assert len(result.steps) == 1


def test_fully_proportionate_request_has_three_passed_steps_and_no_suggestions():
    provider = MockTriageProvider()

    result = provider.triage(
        resource="prod-db",
        access_level="admin",
        duration_seconds=1800,
        reason="deploy the hotfix for incident 4711 to production",
    )

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.HIGH
    assert result.risk_flag is False
    assert result.justification == (
        "reason appears substantive and the requested level/duration are proportionate to it"
    )
    assert [step.passed for step in result.steps] == [True, True, True]
    assert result.suggested_access_level is None
    assert result.suggested_duration_seconds is None
    assert result.steps_summary() == (
        "reason_validation=pass; scope_proportionality=pass; risk_assessment=pass"
    )


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
