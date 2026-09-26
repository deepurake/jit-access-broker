"""
Evals for ClaudeTriageProvider -- the real LLM-backed TriageProvider.

Split into two groups, matching the split in broker/triage.py:

1. Tests of `_parse_triage_response`, the pure text-in/TriageResult-out
   parser. These need no network access and no API key, so they always run
   and are what makes the "a malformed model response must never crash the
   broker or silently grant access" guarantee real and verified in every
   environment.
2. A couple of tests that make a real call to the Anthropic API to verify
   the end-to-end wiring. These are skipped whenever ANTHROPIC_API_KEY is
   not set, so the suite stays green without a key.
"""
import os

import anthropic
import pytest

from broker.triage import (
    ClaudeTriageProvider,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageResult,
    TriageStepName,
    _parse_reason_validation,
    _parse_triage_response,
)

_FALLBACK_JUSTIFICATION = "model response could not be parsed; deferring to human review"
_REASON_VALIDATION_FALLBACK_DETAIL = (
    "model response for reason validation could not be parsed; deferring to human review"
)


def _assert_is_fallback(result: TriageResult) -> None:
    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.justification == _FALLBACK_JUSTIFICATION
    assert result.risk_flag is True


# --- Scripted stand-in for anthropic.Anthropic() so the two-call flow can be
# verified without a network. Each entry in `replies` is either the text the
# model "returns" for that call or an exception to raise instead. ------------


class _FakeTextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, replies) -> None:
        self._replies = list(replies)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        reply = self._replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return _FakeResponse(reply)


class _FakeClient:
    def __init__(self, *replies) -> None:
        self.messages = _FakeMessages(replies)


def _connection_error() -> anthropic.APIConnectionError:
    # The SDK stores `request` for diagnostics only; None is enough to build
    # a raisable instance without importing the SDK's HTTP client library.
    return anthropic.APIConnectionError(message="simulated network failure", request=None)


_VALID_REASON = '{"valid": true, "explanation": "rotating credentials needs admin"}'
_INVALID_REASON = '{"valid": false, "explanation": "looking at dashboards does not need admin"}'
_PROPORTIONATE_APPROVE = (
    '{"recommendation": "APPROVE", "confidence": "HIGH", "justification": "fits the reason", '
    '"risk_flag": false, "proportionate": true}'
)
_OVER_SCOPED_APPROVE = (
    '{"recommendation": "APPROVE", "confidence": "MEDIUM", "justification": "write would suffice", '
    '"risk_flag": false, "proportionate": false, '
    '"suggested_access_level": "write", "suggested_duration_seconds": 1800}'
)


def test_parse_valid_json_with_all_four_fields():
    raw = (
        '{"recommendation": "APPROVE", "confidence": "HIGH", '
        '"justification": "reason is substantive and proportionate", '
        '"risk_flag": true}'
    )

    result = _parse_triage_response(raw)

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.HIGH
    assert result.justification == "reason is substantive and proportionate"
    assert result.risk_flag is True


def test_parse_valid_json_missing_risk_flag_defaults_to_false():
    raw = (
        '{"recommendation": "DENY", "confidence": "MEDIUM", '
        '"justification": "reason is vague"}'
    )

    result = _parse_triage_response(raw)

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.MEDIUM
    assert result.justification == "reason is vague"
    assert result.risk_flag is False


def test_parse_completely_invalid_json_falls_back():
    result = _parse_triage_response("this is not json")

    _assert_is_fallback(result)


def test_parse_invalid_recommendation_value_falls_back():
    raw = (
        '{"recommendation": "MAYBE", "confidence": "HIGH", '
        '"justification": "unclear"}'
    )

    result = _parse_triage_response(raw)

    _assert_is_fallback(result)


def test_parse_missing_required_key_falls_back():
    raw = '{"recommendation": "APPROVE", "justification": "looks fine"}'

    result = _parse_triage_response(raw)

    _assert_is_fallback(result)


def test_parse_empty_string_falls_back():
    result = _parse_triage_response("")

    _assert_is_fallback(result)


def test_parse_reads_optional_least_privilege_keys():
    result = _parse_triage_response(_OVER_SCOPED_APPROVE)

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.MEDIUM
    assert result.justification == "write would suffice"
    assert result.suggested_access_level == "write"
    assert result.suggested_duration_seconds == 1800
    # Over-scoped always goes to a human, even if the model didn't flag risk.
    assert result.risk_flag is True


def test_parse_without_optional_keys_leaves_suggestions_unset_and_proportionate_by_default():
    result = _parse_triage_response(_PROPORTIONATE_APPROVE)

    assert result.suggested_access_level is None
    assert result.suggested_duration_seconds is None
    assert result.risk_flag is False
    scope_steps = [s for s in result.steps if s.name == TriageStepName.SCOPE_PROPORTIONALITY]
    assert len(scope_steps) == 1 and scope_steps[0].passed is True


def test_parse_records_scope_and_risk_steps_from_the_response():
    result = _parse_triage_response(_OVER_SCOPED_APPROVE)

    assert [s.name for s in result.steps] == [
        TriageStepName.SCOPE_PROPORTIONALITY,
        TriageStepName.RISK_ASSESSMENT,
    ]
    assert result.steps[0].passed is False
    assert result.steps[0].detail == "write would suffice"
    assert result.steps[1].passed is False  # risk_flag was forced True by proportionate=false
    assert result.steps[1].detail == "APPROVE with MEDIUM confidence"


def test_parse_non_integer_suggested_duration_is_ignored_not_fatal():
    raw = (
        '{"recommendation": "APPROVE", "confidence": "HIGH", "justification": "ok", '
        '"suggested_duration_seconds": "an hour"}'
    )

    result = _parse_triage_response(raw)

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.suggested_duration_seconds is None


def test_parse_failure_records_a_failed_scope_step():
    result = _parse_triage_response("not json")

    _assert_is_fallback(result)
    assert len(result.steps) == 1
    assert result.steps[0].name == TriageStepName.SCOPE_PROPORTIONALITY
    assert result.steps[0].passed is False
    assert result.steps[0].detail == _FALLBACK_JUSTIFICATION


def test_parse_failure_returns_a_fresh_result_each_time():
    first = _parse_triage_response("garbage")
    second = _parse_triage_response("garbage")

    assert first is not second
    assert first.steps is not second.steps


# --- _parse_reason_validation: step 1's pure parser ---------------------------


def test_parse_reason_validation_valid_true():
    step = _parse_reason_validation(_VALID_REASON)

    assert step.name == TriageStepName.REASON_VALIDATION
    assert step.passed is True
    assert step.detail == "rotating credentials needs admin"


def test_parse_reason_validation_valid_false():
    step = _parse_reason_validation(_INVALID_REASON)

    assert step.name == TriageStepName.REASON_VALIDATION
    assert step.passed is False
    assert step.detail == "looking at dashboards does not need admin"


def test_parse_reason_validation_garbage_fails_closed():
    step = _parse_reason_validation("definitely not json")

    assert step.name == TriageStepName.REASON_VALIDATION
    assert step.passed is False
    assert step.detail == _REASON_VALIDATION_FALLBACK_DETAIL


def test_parse_reason_validation_missing_valid_key_fails_closed():
    step = _parse_reason_validation('{"explanation": "forgot the verdict"}')

    assert step.passed is False
    assert step.detail == _REASON_VALIDATION_FALLBACK_DETAIL


def test_parse_reason_validation_non_boolean_valid_fails_closed():
    # A truthy string like "yes" must not be coerced into a pass.
    step = _parse_reason_validation('{"valid": "yes", "explanation": "sure"}')

    assert step.passed is False
    assert step.detail == _REASON_VALIDATION_FALLBACK_DETAIL


def test_parse_reason_validation_missing_explanation_still_carries_verdict():
    step = _parse_reason_validation('{"valid": false}')

    assert step.passed is False
    assert step.detail != ""


# --- ClaudeTriageProvider.triage: two calls, step 1 gates step 2 -----------


def test_claude_triage_provider_is_a_real_triage_provider():
    provider = ClaudeTriageProvider(client=_FakeClient())

    assert isinstance(provider, TriageProvider)


def test_failed_reason_validation_denies_without_a_second_model_call():
    client = _FakeClient(_INVALID_REASON, _PROPORTIONATE_APPROVE)
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("grafana", "admin", 3600, "I want to look at the dashboards")

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert result.justification == "looking at dashboards does not need admin"
    assert len(result.steps) == 1
    assert result.steps[0].name == TriageStepName.REASON_VALIDATION
    assert len(client.messages.calls) == 1


def test_passed_reason_validation_then_proportionate_request_is_confident_approve():
    client = _FakeClient(_VALID_REASON, _PROPORTIONATE_APPROVE)
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("prod-db", "admin", 1800, "rotating leaked credentials after incident 4711")

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.HIGH
    assert result.risk_flag is False
    assert result.justification == "fits the reason"
    assert [s.name for s in result.steps] == [
        TriageStepName.REASON_VALIDATION,
        TriageStepName.SCOPE_PROPORTIONALITY,
        TriageStepName.RISK_ASSESSMENT,
    ]
    assert all(s.passed for s in result.steps)
    assert result.steps_summary() == (
        "reason_validation=pass; scope_proportionality=pass; risk_assessment=pass"
    )
    assert len(client.messages.calls) == 2


def test_second_call_carries_the_request_details_and_effort_low():
    client = _FakeClient(_VALID_REASON, _PROPORTIONATE_APPROVE)
    provider = ClaudeTriageProvider(client=client)

    provider.triage("prod-db", "admin", 1800, "rotating leaked credentials after incident 4711")

    for call in client.messages.calls:
        assert call["model"] == "claude-opus-5"
        assert call["output_config"] == {"effort": "low"}
        user_text = call["messages"][0]["content"]
        assert "resource: prod-db" in user_text
        assert "access_level: admin" in user_text
        assert "duration_seconds: 1800" in user_text
        assert "rotating leaked credentials" in user_text
    # The two calls ask different questions.
    assert client.messages.calls[0]["system"] != client.messages.calls[1]["system"]
    assert '"valid"' in client.messages.calls[0]["system"]
    assert '"proportionate"' in client.messages.calls[1]["system"]


def test_over_scoped_request_is_flagged_and_carries_least_privilege_suggestion():
    client = _FakeClient(_VALID_REASON, _OVER_SCOPED_APPROVE)
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("prod-db", "admin", 7200, "rotating leaked credentials after incident 4711")

    assert result.recommendation == TriageRecommendation.APPROVE
    assert result.confidence == TriageConfidence.MEDIUM
    assert result.risk_flag is True
    assert result.suggested_access_level == "write"
    assert result.suggested_duration_seconds == 1800
    assert result.steps[0].passed is True
    assert result.steps[1].passed is False
    assert "scope_proportionality=fail (write would suffice)" in result.steps_summary()


def test_unparseable_second_call_falls_back_with_both_steps_recorded():
    client = _FakeClient(_VALID_REASON, "the model rambled instead of returning JSON")
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("prod-db", "admin", 1800, "rotating leaked credentials after incident 4711")

    _assert_is_fallback(result)
    assert [s.name for s in result.steps] == [
        TriageStepName.REASON_VALIDATION,
        TriageStepName.SCOPE_PROPORTIONALITY,
    ]
    assert result.steps[0].passed is True
    assert result.steps[1].passed is False
    assert result.steps[1].detail == _FALLBACK_JUSTIFICATION


def test_unparseable_first_call_denies_and_makes_no_second_call():
    client = _FakeClient("nonsense", _PROPORTIONATE_APPROVE)
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("prod-db", "admin", 1800, "rotating leaked credentials after incident 4711")

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert result.justification == _REASON_VALIDATION_FALLBACK_DETAIL
    assert len(result.steps) == 1
    assert len(client.messages.calls) == 1


def test_api_failure_on_first_call_defers_without_raising():
    client = _FakeClient(_connection_error(), _PROPORTIONATE_APPROVE)
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("prod-db", "admin", 1800, "rotating leaked credentials after incident 4711")

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert len(result.steps) == 1
    assert result.steps[0].passed is False
    assert "APIConnectionError" in result.steps[0].detail
    assert len(client.messages.calls) == 1


def test_api_failure_on_second_call_defers_without_raising():
    client = _FakeClient(_VALID_REASON, _connection_error())
    provider = ClaudeTriageProvider(client=client)

    result = provider.triage("prod-db", "admin", 1800, "rotating leaked credentials after incident 4711")

    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.risk_flag is True
    assert [s.name for s in result.steps] == [
        TriageStepName.REASON_VALIDATION,
        TriageStepName.SCOPE_PROPORTIONALITY,
    ]
    assert result.steps[1].passed is False
    assert "APIConnectionError" in result.steps[1].detail


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"), reason="requires a real Anthropic API key"
)
def test_claude_triage_provider_end_to_end_with_substantive_reason():
    provider = ClaudeTriageProvider()

    result = provider.triage(
        resource="staging-db",
        access_level="read",
        duration_seconds=600,
        reason="debugging a failing integration test in staging that is blocking our release",
    )

    assert isinstance(result, TriageResult)
    assert result.recommendation in (TriageRecommendation.APPROVE, TriageRecommendation.DENY)
    assert result.confidence in (
        TriageConfidence.HIGH,
        TriageConfidence.MEDIUM,
        TriageConfidence.LOW,
    )
    assert isinstance(result.justification, str)
    assert result.justification != ""
    assert isinstance(result.risk_flag, bool)


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"), reason="requires a real Anthropic API key"
)
def test_claude_triage_provider_end_to_end_with_risky_admin_request():
    provider = ClaudeTriageProvider()

    result = provider.triage(
        resource="prod-db",
        access_level="admin",
        duration_seconds=86400,
        reason="testing",
    )

    assert isinstance(result, TriageResult)
    assert result.recommendation in (TriageRecommendation.APPROVE, TriageRecommendation.DENY)
    assert result.confidence in (
        TriageConfidence.HIGH,
        TriageConfidence.MEDIUM,
        TriageConfidence.LOW,
    )
