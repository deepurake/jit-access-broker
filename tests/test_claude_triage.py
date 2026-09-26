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

import pytest

from broker.triage import (
    ClaudeTriageProvider,
    TriageConfidence,
    TriageProvider,
    TriageRecommendation,
    TriageResult,
    _parse_triage_response,
)

_FALLBACK_JUSTIFICATION = "model response could not be parsed; deferring to human review"


def _assert_is_fallback(result: TriageResult) -> None:
    assert result.recommendation == TriageRecommendation.DENY
    assert result.confidence == TriageConfidence.LOW
    assert result.justification == _FALLBACK_JUSTIFICATION
    assert result.risk_flag is True


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


def test_claude_triage_provider_is_a_real_triage_provider():
    provider = ClaudeTriageProvider()

    assert isinstance(provider, TriageProvider)


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
