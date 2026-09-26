# Design

## How a request is decided

Two stages, in a fixed order.

**Stage 1 -- ACL: may this user or agent hold this access at all?**
- Deterministic. Rules live in `acl.yaml`, loaded into the database.
- Checks the requester's role against: allowed resource pattern, highest access level, longest duration.
- Fails -> DENY. The AI is never consulted, so it can never override the rules.

**Stage 2 -- LLM: is this particular request reasonable?**
- Runs only after stage 1 passes.
- The model judges the free-text reason: does it justify this resource at this level; is the level and duration the minimum that fits; how risky is it.
- The LLM only advises: it returns a recommendation (approve or deny), a confidence (high, medium or low), and a risk flag.
- The policy engine, which is plain code, turns that advice into the outcome:
  - **Auto-approve:** high confidence, recommends approve, and no risk flag.
  - **Return to the requester:** the reason is too short or a placeholder (caught before the LLM is called), or the LLM finds it doesn't justify the requested level. The requester can fix the reason and resubmit, or escalate to a human.
  - **Human review:** everything else.
- Two deterministic history rules sit on top: a recent denial or revocation, or a newcomer asking for large scope, always goes to a human.

The full flow, step by step. The first step that reaches a verdict wins; nothing
after it runs.

```
request arrives (requester, resource, access level, duration, reason)
|
|-- 1. Duplicate?  The same requester already has an ACTIVE grant or a PENDING
|      review for the same resource and level.
|        yes -> DUPLICATE. The reply points at the existing grant or review.
|
|-- 2. ACL ceiling (deterministic, from acl.yaml).  Does the requester's role
|      allow this resource, at this level, for this long?
|        no  -> DENY.  The AI never runs; it cannot override the ACL.
|
|-- 3. Junk reason?  A placeholder ("idk", "test", "asdf") or under 10 chars.
|        yes -> RETURNED to the requester with a hint. No model call, no approver.
|
|-- 4. Requester history (read from the same database): prior grants, denials,
|      revocations, pending reviews. Used in step 6 and shown to the AI.
|
|-- 5. AI triage.  It recommends; it never decides.
|        step 1  Does the reason justify THIS resource at THIS level?
|                  ("I want to look at the dashboards" does not justify admin)
|                  no -> RETURNED to the requester with the explanation.
|        step 2  Is the level and duration the minimum that fits the reason?
|                  If not, a suggested minimum is recorded for the reviewer.
|        step 3  Recommendation (APPROVE/DENY), confidence (HIGH/MEDIUM/LOW),
|                risk flag.
|
|-- 6. Routing (plain code, not a model call).
|        AUTO_APPROVE -> grant issued, only when ALL of these hold:
|          - HIGH confidence, APPROVE, no risk flag
|          - no denial or revocation for this requester in the last 30 days
|          - not a first large-scope request (write/admin, or over 1h) from a
|            requester with no prior approved grant
|        HUMAN REVIEW -> everything else: over-scoped, risk-flagged, low or
|          medium confidence, an AI DENY that did not come from the reason
|          check, a recent negative event, a newcomer asking for large scope.
|
'-- Any step that throws (database, directory, ACL, history, model) -> HUMAN
    REVIEW, with the error as the reason. Never auto-approve, never auto-deny.

HUMAN REVIEW
|   A single-use link. The reviewer must be a known user with an approver
|   role (acl.yaml: approver_roles) and must not be the requester. Blocked
|   attempts are audited and leave the link pending for someone else.
|-- approve -> grant issued (HUMAN_APPROVED)
|-- deny    -> HUMAN_DENIED, nothing issued
'-- no decision within 4h -> TIMED_OUT (auto-deny, fail closed). The deadline
    is checked when the link is used, not only when the sweeper runs.

RETURNED
|-- resubmit with a better reason (a returned request is not a duplicate)
'-- escalate -> HUMAN REVIEW. The reviewer sees the AI's objection and the
    requester's note. Only the requester, only once.

GRANT
|-- inactive the instant expires_at passes (checked on read)
|-- sweeper tears down the external token and marks EXPIRED
'-- revoke -> REVOKED and the external token is torn down immediately
```

Who does what:

| Actor | Can |
|---|---|
| Deterministic rules (acl.yaml, junk gate, history rules) | deny, return, force human review |
| AI triage | recommend; auto-approve only the obviously fine case; return an insufficient reason |
| Approver (known user with an approver role) | approve or deny a pending review, not their own |
| Requester | request, resubmit, escalate a returned request |
| Sweeper / clock | expire grants, time out reviews |

## Request and grant states

```
Request:  PENDING_POLICY -> DUPLICATE | DENIED | RETURNED | AUTO_APPROVED | PENDING_HUMAN
          RETURNED       -> PENDING_HUMAN            (escalate)
          PENDING_HUMAN  -> HUMAN_APPROVED | HUMAN_DENIED | TIMED_OUT

Grant:    ACTIVE -> EXPIRED | REVOKED
```

Every transition is a conditional `UPDATE ... WHERE status = <expected>`; whoever
commits first wins and the other side is a no-op. That is how a revoke landing at
the same moment as an expiry, or two reviewers clicking the same link, is settled.

## Key decisions

1. **Deterministic ACL before AI.** Every request passes the ACL before triage runs, and an ACL denial is final.

	*Why:* access boundaries stay auditable and predictable, a model can never grant past them, and denied requests cost no LLM call.

2. **When in doubt, a human decides.** The AI auto-approves only with HIGH confidence, APPROVE, and no risk flag. Everything else goes to a human: low or medium confidence, a risk flag, an AI recommendation to deny, and any exception anywhere in the pipeline (logged with the error in the reason). The human gets a single-use approval link, valid for 4 hours: opening it shows the request, the reason and the AI's justification, and an approve or deny only takes effect when it comes from someone with an approver role who is not the requester.

	*Why:* a request is auto-approved only after it has passed the ACL checks and the agent is highly confident. The agent is never allowed to deny on its own, because an auto-deny would block legitimate work. A broken component must fail safe: never auto-approve, never silently block.

3. **Weak reasons go back to the requester.** A junk reason, or one that doesn't justify the requested level, is returned with the option to resubmit or escalate.

	*Why:* only the requester can fix the wording, so approvers aren't turned into an approval desk.

4. **Past behavior builds auto-approval confidence.** The requesting user's or agent's history decides how far auto-approval can be trusted. Today it can only hold a request back: a recent denial or revocation, or a newcomer asking for large scope, forces human review.

	*Why:* trust is earned from the requester's own record, not from how convincing a reason string sounds. New and untested agents carry more risk, while an agent that has been used repeatedly without problems earns more confidence for auto-approval. Today this is a simple heuristic (recent denials or revocations, and first large-scope requests). In future, the broker should analyse each agent's past traces to build a risk profile, and use that profile to strengthen its auto-approval decisions.

5. **Routing is plain code.** Thresholds and rules live in `PolicyEngine`, not in a prompt.

	*Why:* policy has to be readable, testable, and give the same answer every time.

6. **Audit trails (stored in SQL) as the single source of truth.** All requests, grants, approvals and an append-only audit log live in one database, and nothing important is kept in memory.

	*Why:* restarts lose nothing, every decision can be traced after the fact, and when actions race (e.g. expiry and revocation) only one can win.

7. **Additional protections: approval timeout, request deduplication and idempotency.**
   - **Approval timeout:** a pending approval is auto-denied after 4h, and the deadline is also checked when the link is clicked.
   - **Request deduplication:** a request matching an active grant or pending approval (same requester, resource and level) is recorded and rejected before policy runs.
   - **Idempotency:** repeating an action changes nothing. A second approval click, a revoke of an already-ended grant, or a repeated sweep never issues or tears down access twice.

	*Why:* a sleeping approver can't leave requests open forever, a stale link can't grant access, and retries or repeated clicks can't produce double grants, extra LLM calls, or a second chance at a different answer.

8. **Opaque bearer tokens, checked on every request (not JWTs).** An approved grant gives the requester a random, meaningless token issued by the identity provider (the fake Okta sidecar). The client sends it as `Authorization: Bearer <token>`, and the protected service asks the identity provider whether it is still active (`GET /introspect/<token>`) on every request.

	*Why:* the brief requires an expired or revoked grant to stop working, full stop. A JWT is checked locally and stays valid until its `exp`, so revoking it early doesn't take effect. With introspection, revocation and expiry take effect on the very next request. The cost is a network call per request and a dependency on the identity provider being up. At higher volume, the next step would be short-lived JWTs whose `exp` is no later than the grant's expiry, accepting a small revocation delay in exchange for local checks.
