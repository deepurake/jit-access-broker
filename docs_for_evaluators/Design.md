# Design

## How a request is decided

Every request goes through the same steps, in this order. The first step that
reaches a verdict wins; nothing after it runs.

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

## Moving parts

- **broker CLI** (`python -m broker.cli`): request, approve, escalate, revoke,
  sweep, audit, load-acl, set-role. Every invocation opens the same SQLite file.
- **approval-service** (:8083): the review page. GET renders, POST decides.
- **sweeper**: runs `reconcile` every few seconds -- expires grants (tearing down
  the external token) and times out stale reviews.
- **Okta sidecar** (:8081, fake IdP): issues, introspects and revokes tokens.
- **protected service** (:8082): the resource; checks the bearer token with the
  sidecar on every request.
- **SQLite**: requests, grants, pending_approvals, audit_log (append-only),
  user_roles, acl_rules, approver_roles. `acl.yaml` is the reviewed source of
  the last two; `load-acl` syncs it in.
- **Anthropic API** (optional, `--triage claude`): the real model behind the
  triage seam; the default is a deterministic mock with the same behaviour.

## Key decisions

1. The ACL is a hard stop and runs before the AI. The AI never overrides it.
2. The AI may auto-approve only with HIGH confidence, APPROVE, and no risk flag. It never denies on its own.
3. A weak reason goes back to the requester, who can resubmit or escalate. It doesn't go to an approver.
4. Requester history only tightens a decision: a recent denial or revocation, or a newcomer asking for large scope, goes to a human.
5. Any exception in the pipeline routes to a human, never to an automatic approve or deny.
6. Routing is plain code, not a model call.
7. SQLite is the single source of truth. Guarded `UPDATE ... WHERE status=...` settles races.
8. Pending approvals time out after 4h and are auto-denied. The deadline is also checked at click time.
9. Duplicate requests (same requester, resource and level while one is active or pending) are rejected before policy runs.
10. Expiry and revocation call `connector.revoke`. The protected service checks the token with the sidecar on every request.
11. Every external dependency sits behind an interface: Policy, TriageProvider, ResourceConnector, UserDirectory, RequesterHistoryReader, TokenIntrospector, Clock.
12. Who may approve is data (`approver_roles` in acl.yaml), and the check runs on every decision, CLI or web.

## Known limitations

- The approver's name is typed, not authenticated. It must match a known user with an approver role, but anyone who knows an approver's name can type it. SSO on the review page is the fix.
- The protected service doesn't check the token's resource.
- Request status is set before `connector.issue`. If issue fails, the request shows approved with no grant.
- The duplicate check isn't atomic across processes.
- `connector.revoke` failure after the status change is not retried.
- Between sweeps an expired grant's external token stays live (bounded by the sweep interval).
