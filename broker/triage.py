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
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

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
