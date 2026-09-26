"""TriageProvider is the seam for the AI triage step: given a request that
passed the deterministic ACL check, does the stated reason look valid, and
is the requested access level/duration proportionate to it?

Triage is explicitly multi-step, and step 1 gates the rest:
  1. reason_validation     -- does the reason justify THIS resource at THIS
                              access level? A reason that only describes
                              looking at something does not justify write or
                              admin. Failing here stops triage.
  2. scope_proportionality -- least privilege: is the level/duration the
                              minimum the reason needs? If not, the result
                              carries a suggested_access_level / duration.
  3. risk_assessment       -- final recommendation + confidence.
Every executed step is recorded on the TriageResult so the audit log can
show *why* the AI recommended what it did (TriageResult.steps_summary()).

Triage RECOMMENDS, never decides. ClaudeTriageProvider runs the steps as
two model calls; MockTriageProvider is a deterministic heuristic running
the same steps, so the request -> triage -> decision pipeline is real and
testable before any live model call exists. This is exactly the kind of
judgment call where AI helps (reading unstructured, free-text
justifications) but confidence must be explicit and low confidence must
defer to a human -- see PolicyEngine (broker/policy_engine.py) for how
the confidence signal actually gets used."""
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

import anthropic

_MIN_REASON_LENGTH = 10
_NON_SUBSTANTIVE_REASONS = {"test", "testing", "asdf", "idk", "because", "n/a", "none"}
_RISKY_ACCESS_LEVEL = "admin"
_RISKY_DURATION_SECONDS = 3600
_MAX_READ_DURATION_SECONDS = 8 * 3600

# Access levels that let the requester change something. A reason that only
# describes reading/looking cannot justify these -- see
# MockTriageProvider._validate_reason.
_MUTATING_ACCESS_LEVELS = {"write", "admin"}
# Words that signal the requester intends to change something. Substring,
# case-insensitive match against the reason. Deliberately small: the mock
# stands in for a model that actually reads the reason, not for a real
# classifier.
_MUTATION_KEYWORDS = {
    "rotate", "rotating", "fix", "fixing", "hotfix", "deploy", "migrate", "migration",
    "restore", "patch", "update", "incident", "outage", "credential", "credentials",
    "leak", "leaked", "repair", "remediate", "rollback",
}


class TriageRecommendation(str, Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"


class TriageConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TriageStepName(str, Enum):
    """The three steps of triage, in execution order. Step 1 gates the rest:
    if the reason doesn't justify the requested permission there is nothing
    to assess for proportionality or risk."""

    REASON_VALIDATION = "reason_validation"  # does the reason justify THIS resource at THIS access level?
    SCOPE_PROPORTIONALITY = "scope_proportionality"  # is level/duration the minimum that fits the reason?
    RISK_ASSESSMENT = "risk_assessment"  # final recommendation + confidence


@dataclass
class TriageStep:
    name: TriageStepName
    passed: bool
    detail: str


@dataclass
class TriageResult:
    recommendation: TriageRecommendation
    confidence: TriageConfidence
    justification: str
    risk_flag: bool = False
    # Every step that actually executed, in order. A result that stopped at
    # step 1 has exactly one entry; a full run has three.
    steps: List[TriageStep] = field(default_factory=list)
    # Populated by step 2 when the request is over-scoped: the least-privilege
    # alternative the triage step believes would fit the stated reason.
    suggested_access_level: Optional[str] = None
    suggested_duration_seconds: Optional[int] = None

    def steps_summary(self) -> str:
        """One deterministic line, `name=pass|fail` per executed step, with
        `(detail)` appended only for failed steps. Written into the TRIAGED
        audit event, so it must stay single-line."""
        parts = []
        for step in self.steps:
            if step.passed:
                parts.append(f"{step.name.value}=pass")
            else:
                detail = " ".join(step.detail.split())  # collapse any newlines/runs of whitespace
                parts.append(f"{step.name.value}=fail ({detail})")
        return "; ".join(parts)


class TriageProvider(ABC):
    @abstractmethod
    def triage(
        self,
        resource: str,
        access_level: str,
        duration_seconds: int,
        reason: str,
        context: Optional[str] = None,
    ) -> TriageResult:
        """`context` is optional extra background for the model -- today the
        requester's history line (RequesterHistory.summary()). Positional
        arguments are unchanged so existing providers and call sites keep
        working; a provider that has no use for it may ignore it."""
        ...


class MockTriageProvider(TriageProvider):
    """Deterministic heuristic standing in for a real LLM call. No
    randomness, no network call -- just enough judgment to exercise the
    real recommend-and-defer behavior (short/vague reasons and risky
    combinations defer to a human via low confidence or a risk flag).

    Runs the same three steps as the real provider, in the same order, and
    records a TriageStep for each one that executes:
      1. _validate_reason  -- is the reason substantive, and does it justify
                              the REQUESTED access level? Failing here stops
                              triage; steps 2/3 never run.
      2. _check_scope      -- least privilege: is level/duration the minimum
                              the reason needs? Failure lowers confidence
                              and sets risk_flag (so a human sees it) but
                              still recommends APPROVE.
      3. _assess_risk      -- final recommendation + confidence.
    """

    def triage(
        self,
        resource: str,
        access_level: str,
        duration_seconds: int,
        reason: str,
        context: Optional[str] = None,
    ) -> TriageResult:
        # `context` is ignored: the heuristic has no model to hand it to. The
        # PolicyEngine applies the deterministic history rules itself.
        step1 = self._validate_reason(resource, access_level, duration_seconds, reason)
        if not step1.passed:
            return TriageResult(
                recommendation=TriageRecommendation.DENY,
                confidence=TriageConfidence.LOW,
                justification=step1.detail,
                risk_flag=True,
                steps=[step1],
            )

        step2, suggested_level, suggested_duration = self._check_scope(
            resource, access_level, duration_seconds, reason
        )
        step3 = self._assess_risk(step1, step2)

        if not step2.passed:
            return TriageResult(
                recommendation=TriageRecommendation.APPROVE,
                confidence=TriageConfidence.MEDIUM,
                justification=f"reason is present but {step2.detail}",
                risk_flag=True,
                steps=[step1, step2, step3],
                suggested_access_level=suggested_level,
                suggested_duration_seconds=suggested_duration,
            )

        return TriageResult(
            recommendation=TriageRecommendation.APPROVE,
            confidence=TriageConfidence.HIGH,
            justification="reason appears substantive and the requested level/duration are proportionate to it",
            risk_flag=False,
            steps=[step1, step2, step3],
        )

    @staticmethod
    def _validate_reason(resource: str, access_level: str, duration_seconds: int, reason: str) -> TriageStep:
        """Step 1: does the reason justify THIS permission? Substantive-ness
        first, then consistency with the requested access level."""
        stripped_reason = reason.strip()
        lowered = stripped_reason.lower()

        # Checked before the length check below: every word in the
        # placeholder set is itself under _MIN_REASON_LENGTH, so checking
        # length first would make this branch unreachable dead code.
        if lowered in _NON_SUBSTANTIVE_REASONS:
            return TriageStep(TriageStepName.REASON_VALIDATION, False, "reason does not appear substantive")

        if len(stripped_reason) < _MIN_REASON_LENGTH:
            return TriageStep(
                TriageStepName.REASON_VALIDATION, False, "reason is too short to evaluate for validity"
            )

        # "Against the requested permission": a reason that only describes
        # looking at something cannot justify the ability to change it.
        if access_level in _MUTATING_ACCESS_LEVELS and not any(kw in lowered for kw in _MUTATION_KEYWORDS):
            return TriageStep(
                TriageStepName.REASON_VALIDATION,
                False,
                f"reason does not justify {access_level} access: it describes no change to make",
            )

        return TriageStep(
            TriageStepName.REASON_VALIDATION,
            True,
            f"reason is substantive and consistent with {access_level} access",
        )

    @staticmethod
    def _check_scope(
        resource: str, access_level: str, duration_seconds: int, reason: str
    ) -> Tuple[TriageStep, Optional[str], Optional[int]]:
        """Step 2 (least privilege). Returns the step plus the suggested
        (access_level, duration) when the request is over-scoped; both None
        when it is proportionate."""
        if access_level == _RISKY_ACCESS_LEVEL and duration_seconds > _RISKY_DURATION_SECONDS:
            # The mock has no real understanding of the reason, so it can't
            # know what the minimum actually is. It suggests one level down
            # and the 1h ceiling as a plausible least-privilege alternative;
            # the real provider asks the model for the true minimum.
            return (
                TriageStep(
                    TriageStepName.SCOPE_PROPORTIONALITY,
                    False,
                    "admin access for an extended duration carries elevated risk",
                ),
                "write",
                _RISKY_DURATION_SECONDS,
            )

        if access_level == "read" and duration_seconds > _MAX_READ_DURATION_SECONDS:
            return (
                TriageStep(
                    TriageStepName.SCOPE_PROPORTIONALITY,
                    False,
                    "read access for more than 8 hours is longer than a typical investigation needs",
                ),
                None,
                _MAX_READ_DURATION_SECONDS,
            )

        return (
            TriageStep(
                TriageStepName.SCOPE_PROPORTIONALITY,
                True,
                "requested level and duration are proportionate to the reason",
            ),
            None,
            None,
        )

    @staticmethod
    def _assess_risk(step1: TriageStep, step2: TriageStep) -> TriageStep:
        """Step 3: the final call. With a validated reason, the only risk
        signal the mock has is an over-scoped request from step 2."""
        if not step2.passed:
            return TriageStep(
                TriageStepName.RISK_ASSESSMENT,
                False,
                "APPROVE with MEDIUM confidence; over-scoped request flagged for human review",
            )
        return TriageStep(TriageStepName.RISK_ASSESSMENT, True, "APPROVE with HIGH confidence")


_MODEL = "claude-opus-5"

_FALLBACK_JUSTIFICATION = "model response could not be parsed; deferring to human review"
_REASON_VALIDATION_FALLBACK_DETAIL = (
    "model response for reason validation could not be parsed; deferring to human review"
)


def _fallback_result(steps: List[TriageStep]) -> TriageResult:
    """The defer-to-human result for an unusable call-2 response. Built fresh
    each time because `steps` is mutable and the caller prepends step 1."""
    return TriageResult(
        recommendation=TriageRecommendation.DENY,
        confidence=TriageConfidence.LOW,
        justification=_FALLBACK_JUSTIFICATION,
        risk_flag=True,
        steps=steps,
    )


# Call 1 / step 1. Deliberately narrow: the model is asked ONE question --
# does this reason justify THIS permission? -- so a "looks fine overall"
# impression can't paper over a reason/permission mismatch.
_REASON_VALIDATION_PROMPT = """You are step 1 of the triage pipeline of a \
Just-in-Time access broker. Your only job is to validate whether a stated \
business reason justifies a SPECIFIC permission.

You will be given a resource, an access level (e.g. read, write, admin), a \
requested duration in seconds, and the requester's stated reason. Decide \
whether the reason justifies THAT access level on THAT resource. Be strict:
- A vague, placeholder, or non-substantive reason justifies nothing.
- A reason that describes only reading, looking, viewing, checking, or \
investigating does NOT justify write or admin access.
- A reason unrelated to the named resource does not justify access to it.
- Do not assess whether the duration is reasonable; a later step does that.

Respond with ONLY a JSON object -- no prose, no markdown code fences, no \
explanation outside the JSON -- with exactly these keys:
{
  "valid": true or false,
  "explanation": a short string saying why the reason does or does not \
justify this permission
}"""

# Call 2 / steps 2+3. Only reached once step 1 has confirmed the reason
# justifies the requested permission, so this call focuses on least
# privilege and the final recommendation.
_SYSTEM_PROMPT = """You are steps 2 and 3 of the triage pipeline of a \
Just-in-Time access broker. A previous step has already confirmed that the \
requester's stated reason justifies the requested access level on the \
requested resource, and the request has passed a deterministic ACL check.

You will be given a resource, an access level, a requested duration in \
seconds, and the requester's stated reason.

Step 2 -- least privilege: is the requested access level and duration the \
MINIMUM that fits the reason? If a lower access level or a shorter duration \
would suffice, the request is not proportionate; say what the minimum would \
be. A high-risk access level (e.g. admin) or an unusually long duration \
relative to the reason should lower your confidence or be flagged as risky, \
even if you still recommend approval.

Step 3 -- final recommendation and confidence.

Respond with ONLY a JSON object -- no prose, no markdown code fences, no \
explanation outside the JSON -- with exactly these keys:
{
  "recommendation": "APPROVE" or "DENY",
  "confidence": "HIGH", "MEDIUM", or "LOW",
  "justification": a short string explaining your reasoning,
  "risk_flag": true or false, whether this request carries elevated risk \
even if approved,
  "proportionate": true or false, whether the requested level and duration \
are the minimum the reason needs,
  "suggested_access_level": the minimum access level that fits the reason \
(a string), or null if the requested level is already the minimum,
  "suggested_duration_seconds": the minimum duration in seconds that fits \
the reason (an integer), or null if the requested duration is already the \
minimum
}"""


def _parse_reason_validation(raw_text: str) -> TriageStep:
    """Parse call 1's raw text into the REASON_VALIDATION step.

    Pure text-in, TriageStep-out. `valid` must be an actual JSON boolean:
    a truthy string like "yes" is treated as unparseable rather than
    coerced, because a misread here would let step 2 run on a reason the
    model never actually validated. Any parse failure is a failed step
    (fail closed) with a fixed detail.
    """
    try:
        data = json.loads(raw_text)
        valid = data["valid"]
        if not isinstance(valid, bool):
            raise TypeError("valid must be a JSON boolean")
        explanation = str(data.get("explanation", "")).strip()
        if not explanation:
            explanation = (
                "model judged the reason to justify the requested access"
                if valid
                else "model judged the reason not to justify the requested access"
            )
        return TriageStep(TriageStepName.REASON_VALIDATION, valid, explanation)
    except Exception:
        # Broad catch is deliberate: JSONDecodeError, KeyError, TypeError all
        # mean "we can't trust this response", and the only safe reading of
        # an unvalidated reason is a failed validation.
        return TriageStep(TriageStepName.REASON_VALIDATION, False, _REASON_VALIDATION_FALLBACK_DETAIL)


def _parse_triage_response(raw_text: str) -> TriageResult:
    """Parse call 2's raw text output into a TriageResult carrying the
    SCOPE_PROPORTIONALITY and RISK_ASSESSMENT steps (the caller prepends
    the REASON_VALIDATION step from call 1).

    Pure text-in, TriageResult-out -- no network dependency, so this is
    fully unit-testable without an API key. Broad exception handling here
    is deliberate: a malformed model response (invalid JSON, missing keys,
    an enum value that doesn't match, wrong types) must never crash the
    broker or silently grant access. Any failure to parse defers to a
    human via the fixed fallback result.

    Optional keys: `proportionate` (default True), `suggested_access_level`,
    `suggested_duration_seconds`. An over-scoped request (proportionate is
    False) always forces risk_flag=True so it can never be auto-approved.
    A malformed optional key is dropped, not fatal -- the required verdict
    is still trustworthy without it.
    """
    try:
        data = json.loads(raw_text)
        recommendation = TriageRecommendation(data["recommendation"])
        confidence = TriageConfidence(data["confidence"])
        justification = str(data["justification"])
        risk_flag = bool(data.get("risk_flag", False))
        proportionate = data.get("proportionate", True) is not False
    except Exception:
        # Broad catch is deliberate -- see docstring above. json.JSONDecodeError
        # (not valid JSON), KeyError (missing required key), ValueError (bad
        # enum value), TypeError (e.g. data isn't a dict) all land here and
        # all mean the same thing: we can't trust this response, so defer.
        return _fallback_result(
            [TriageStep(TriageStepName.SCOPE_PROPORTIONALITY, False, _FALLBACK_JUSTIFICATION)]
        )

    suggested_level = data.get("suggested_access_level")
    suggested_level = suggested_level if isinstance(suggested_level, str) and suggested_level else None
    suggested_duration = data.get("suggested_duration_seconds")
    # bool is an int subclass; `true` is not a duration.
    if isinstance(suggested_duration, bool) or not isinstance(suggested_duration, int):
        suggested_duration = None

    if not proportionate:
        risk_flag = True  # over-scoped always goes to a human

    step2 = TriageStep(
        TriageStepName.SCOPE_PROPORTIONALITY,
        proportionate,
        justification or "requested level and duration are proportionate to the reason",
    )
    step3 = TriageStep(
        TriageStepName.RISK_ASSESSMENT,
        not risk_flag,
        f"{recommendation.value} with {confidence.value} confidence",
    )
    return TriageResult(
        recommendation=recommendation,
        confidence=confidence,
        justification=justification,
        risk_flag=risk_flag,
        steps=[step2, step3],
        suggested_access_level=suggested_level,
        suggested_duration_seconds=suggested_duration,
    )


class ClaudeTriageProvider(TriageProvider):
    """Real TriageProvider backed by the Claude API, run as two model calls:

    Call 1 (step 1) asks only whether the stated reason justifies the
    requested access level on the requested resource. If it doesn't -- or
    the answer can't be obtained -- triage stops there with a DENY/LOW
    recommendation and step 2 is never asked.

    Call 2 (steps 2+3) asks for the least-privilege assessment and the
    final recommendation, parsed via _parse_triage_response.

    Any network/API failure or unparseable response defers to a human --
    a triage provider must never fail open, and it never raises: a result
    is always returned so PolicyEngine sees a decision, not a failure.
    `client` is injectable so the flow can be tested without a network."""

    def __init__(self, client: Optional[anthropic.Anthropic] = None) -> None:
        self._client = client if client is not None else anthropic.Anthropic()

    def triage(
        self,
        resource: str,
        access_level: str,
        duration_seconds: int,
        reason: str,
        context: Optional[str] = None,
    ) -> TriageResult:
        user_message = (
            f"resource: {resource}\n"
            f"access_level: {access_level}\n"
            f"duration_seconds: {duration_seconds}\n"
            f"reason: {reason}"
        )
        if context:
            # The requester's track record, on BOTH calls: it bears on whether
            # a reason is credible (call 1) and on how much risk an admin
            # grant carries (call 2). Appended after the request fields so
            # the model sees it as background, not as part of the reason.
            user_message += f"\nRequester history: {context}"

        # Call 1 / step 1: validate the reason against the requested permission.
        try:
            step1 = _parse_reason_validation(self._ask(_REASON_VALIDATION_PROMPT, user_message))
        except (anthropic.APIStatusError, anthropic.APIConnectionError) as exc:
            step1 = TriageStep(
                TriageStepName.REASON_VALIDATION,
                False,
                f"reason validation call failed ({type(exc).__name__}: {exc}); deferring to human review",
            )

        if not step1.passed:
            return TriageResult(
                recommendation=TriageRecommendation.DENY,
                confidence=TriageConfidence.LOW,
                justification=step1.detail,
                risk_flag=True,
                steps=[step1],
            )

        # Call 2 / steps 2+3: least privilege and the final recommendation.
        try:
            result = _parse_triage_response(self._ask(_SYSTEM_PROMPT, user_message))
        except (anthropic.APIStatusError, anthropic.APIConnectionError) as exc:
            # A network/API failure is just another form of "couldn't get a
            # usable answer" -- same defer-to-human response as a malformed
            # response, since a triage provider must never fail open.
            return _fallback_result(
                [
                    step1,
                    TriageStep(
                        TriageStepName.SCOPE_PROPORTIONALITY,
                        False,
                        f"scope assessment call failed ({type(exc).__name__}: {exc}); deferring to human review",
                    ),
                ]
            )

        result.steps.insert(0, step1)
        return result

    def _ask(self, system_prompt: str, user_message: str) -> str:
        """One model call; returns the first text block (empty string if none)."""
        response = self._client.messages.create(
            model=_MODEL,
            max_tokens=400,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
            output_config={"effort": "low"},
        )
        for block in response.content:
            if block.type == "text":
                return block.text
        return ""
