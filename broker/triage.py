"""TriageProvider is the seam for the AI triage step: given a request that
passed the deterministic ACL check, does the stated reason look valid, and
is the requested access level/duration proportionate to it? A real
implementation would call an LLM; MockTriageProvider is a deterministic
heuristic standing in for one, so the request -> triage -> decision pipeline
is real and testable before any live model call exists. This is exactly the
kind of judgment call where AI helps (reading unstructured, free-text
justifications) but confidence must be explicit and low confidence must
defer to a human -- see DecisionRouter (broker/decision_router.py, a
different task) for how the confidence signal actually gets used."""
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

import anthropic

_MIN_REASON_LENGTH = 10
_NON_SUBSTANTIVE_REASONS = {"test", "testing", "asdf", "idk", "because", "n/a", "none"}
_RISKY_ACCESS_LEVEL = "admin"
_RISKY_DURATION_SECONDS = 3600


class TriageRecommendation(str, Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"


class TriageConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class TriageResult:
    recommendation: TriageRecommendation
    confidence: TriageConfidence
    justification: str
    risk_flag: bool = False


class TriageProvider(ABC):
    @abstractmethod
    def triage(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> TriageResult:
        ...


class MockTriageProvider(TriageProvider):
    """Deterministic heuristic standing in for a real LLM call. No
    randomness, no network call -- just enough judgment to exercise the
    real recommend-and-defer behavior (short/vague reasons and risky
    combinations defer to a human via low confidence or a risk flag)."""

    def triage(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> TriageResult:
        stripped_reason = reason.strip()

        # Checked before the length check below: every word in the
        # placeholder set is itself under _MIN_REASON_LENGTH, so checking
        # length first would make this branch unreachable dead code.
        if stripped_reason.lower() in _NON_SUBSTANTIVE_REASONS:
            return TriageResult(
                recommendation=TriageRecommendation.DENY,
                confidence=TriageConfidence.LOW,
                justification="reason does not appear substantive",
                risk_flag=True,
            )

        if len(stripped_reason) < _MIN_REASON_LENGTH:
            return TriageResult(
                recommendation=TriageRecommendation.DENY,
                confidence=TriageConfidence.LOW,
                justification="reason is too short to evaluate for validity",
                risk_flag=True,
            )

        if access_level == _RISKY_ACCESS_LEVEL and duration_seconds > _RISKY_DURATION_SECONDS:
            return TriageResult(
                recommendation=TriageRecommendation.APPROVE,
                confidence=TriageConfidence.MEDIUM,
                justification="reason is present but admin access for an extended duration carries elevated risk",
                risk_flag=True,
            )

        return TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="reason appears substantive and the requested level/duration are proportionate to it",
            risk_flag=False,
        )


_MODEL = "claude-opus-5"

_FALLBACK_RESULT = TriageResult(
    recommendation=TriageRecommendation.DENY,
    confidence=TriageConfidence.LOW,
    justification="model response could not be parsed; deferring to human review",
    risk_flag=True,
)

_SYSTEM_PROMPT = """You are the triage step of a Just-in-Time access broker. \
You will be given details of an access request that has already passed a \
deterministic ACL check: a resource, an access level, a requested duration \
in seconds, and the requester's stated reason.

Assess two things:
1. Does the stated reason plausibly and substantively justify needing access \
at all? Vague, placeholder, or non-substantive reasons should not be approved.
2. Is the requested access level and duration proportionate to that reason? \
A high-risk access level (e.g. admin) or an unusually long duration relative \
to the reason should lower your confidence or be flagged as risky, even if \
you still recommend approval.

Respond with ONLY a JSON object -- no prose, no markdown code fences, no \
explanation outside the JSON -- with exactly these keys:
{
  "recommendation": "APPROVE" or "DENY",
  "confidence": "HIGH", "MEDIUM", or "LOW",
  "justification": a short string explaining your reasoning,
  "risk_flag": true or false, whether this request carries elevated risk \
even if approved
}"""


def _parse_triage_response(raw_text: str) -> TriageResult:
    """Parse the model's raw text output into a TriageResult.

    Pure text-in, TriageResult-out -- no network dependency, so this is
    fully unit-testable without an API key. Broad exception handling here
    is deliberate: a malformed model response (invalid JSON, missing keys,
    an enum value that doesn't match, wrong types) must never crash the
    broker or silently grant access. Any failure to parse defers to a
    human via the same fixed fallback result.
    """
    try:
        data = json.loads(raw_text)
        recommendation = TriageRecommendation(data["recommendation"])
        confidence = TriageConfidence(data["confidence"])
        justification = str(data["justification"])
        risk_flag = bool(data.get("risk_flag", False))
        return TriageResult(
            recommendation=recommendation,
            confidence=confidence,
            justification=justification,
            risk_flag=risk_flag,
        )
    except Exception:
        # Broad catch is deliberate -- see docstring above. json.JSONDecodeError
        # (not valid JSON), KeyError (missing required key), ValueError (bad
        # enum value), TypeError (e.g. data isn't a dict) all land here and
        # all mean the same thing: we can't trust this response, so defer.
        return _FALLBACK_RESULT


class ClaudeTriageProvider(TriageProvider):
    """Real TriageProvider backed by the Claude API. Asks the model to
    assess whether the stated reason justifies the requested access and
    whether the access level/duration are proportionate to it, then parses
    its JSON response via _parse_triage_response. Any network/API failure
    or unparseable response defers to a human via the same fallback result
    -- a triage provider must never fail open."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic()

    def triage(self, resource: str, access_level: str, duration_seconds: int, reason: str) -> TriageResult:
        user_message = (
            f"resource: {resource}\n"
            f"access_level: {access_level}\n"
            f"duration_seconds: {duration_seconds}\n"
            f"reason: {reason}"
        )

        try:
            response = self._client.messages.create(
                model=_MODEL,
                max_tokens=500,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
                output_config={"effort": "low"},
            )
        except (anthropic.APIStatusError, anthropic.APIConnectionError):
            # A network/API failure is just another form of "couldn't get a
            # usable answer" -- same defer-to-human response as a malformed
            # response, since a triage provider must never fail open.
            return _FALLBACK_RESULT

        raw_text = ""
        for block in response.content:
            if block.type == "text":
                raw_text = block.text
                break

        return _parse_triage_response(raw_text)
