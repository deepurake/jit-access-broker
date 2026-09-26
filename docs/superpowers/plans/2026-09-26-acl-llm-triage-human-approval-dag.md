# Stage 3: ACL Policy Engine + LLM Triage + Human-Approval DAG

## Design decisions (approved in chat)
1. ACL rules authored in `acl.yaml` (git-reviewed source of truth), synced into an `acl_rules`
   SQLite table (indexed runtime query path, matches how Teleport/OPA/AWS IAM actually split
   authoring vs. serving).
2. User -> role mapping lives in a `user_roles` SQLite table (dynamic operational data; in a real
   deployment this syncs from the IdP, e.g. Okta group membership -- not hand-edited YAML).
3. Confident LLM-recommended DENY still routes to a human. AI gets unilateral **approve** authority
   only for the obviously-fine cases; a wrong auto-deny costs a human's time, a wrong auto-approve
   costs a security incident.
4. Magic link: `GET /approve/<random-single-use-token>` renders the request + LLM recommendation;
   the actual decision is a `POST` (not GET, to avoid link-scanner-triggers-action footguns). No login.
5. Pending-approval timeout: 4 hours default, configurable; **auto-deny (TIMED_OUT) on timeout** --
   fail closed, answers "approver is asleep."
6. Garbage/unparseable LLM output => treated as lowest confidence => routes to human. Never crashes,
   never silently auto-approves.
7. **Failure policy (user-stated): any system failure falls back to manual review.** A component
   *denying* is a decision; a component *throwing* is a failure. DecisionRouter catches exceptions
   from the user directory, the ACL engine, and the triage provider and returns ROUTE_HUMAN with the
   failure text in the reason (visible to the reviewer and in the audit log). If the ACL boundary
   itself can't be evaluated, triage is skipped so no ungated AI APPROVE can exist.
8. **Return to requester (revises #3, user-argued):** approvers must not be an approval desk, and the
   person who can fix an insufficient *reason* is the requester, not the approver. Prompt injection in
   the reason can only move the requester's own request, so nobody gains from being denied. Hence a
   fourth outcome, RETURN_TO_REQUESTER: a deterministic junk gate (placeholder / <10 chars, before any
   model call) and a failed triage step 1 (reason doesn't justify this permission) return the request
   with a hint. The requester resubmits or escalates (`escalate <id> --by <requester> --note ...`) into
   a normal human review that shows both the AI's reason and the note. Over-scope, risk flag, low
   confidence and system failure still go to a human; AI approve authority is unchanged.

## DAG

| ID | Task | Files | depends_on | status |
|----|------|-------|------------|--------|
| T1 | Shared contracts: PendingApproval/PendingApprovalStatus + new AuditEventType values (models.py), PolicyEngine.decide(+requester) (policy.py), user_roles/acl_rules/pending_approvals tables + guarded CRUD (db.py) | broker/models.py, broker/policy.py, broker/db.py | none | **done** |
| T2 | UserDirectory seam: reads user_roles table via Database | broker/user_directory.py, tests/test_user_directory.py | T1 | **done** (46 tests green) |
| T3 | AclPolicyEngine: loads acl.yaml -> acl_rules table, evaluates role/resource-pattern/max-level/max-duration ceiling | broker/acl_policy.py, broker/acl_loader.py, acl.yaml, tests/test_acl_policy.py | T1 | **done** (14 tests green) |
| T4 | TriageProvider seam + MockTriageProvider (deterministic heuristic recommend+confidence+justification, real recommend-and-defer behavior) | broker/triage.py, tests/test_triage.py | T1 | **done** (5 tests green) |
| T5 | ClaudeTriageProvider (real Anthropic API, gated by ANTHROPIC_API_KEY, optional/non-blocking) | broker/triage.py (same file as T4, sequential after it) | T4 | **done** (7 tests + 2 gated skips) |
| T6 | DecisionRouter: composes UserDirectory + AclPolicyEngine + TriageProvider into the PolicyEngine interface per decisions #3/#6 above | broker/decision_router.py, tests/test_decision_router.py | T1, T2, T3, T4 | **done** (8 tests green) |
| T7 | Broker + CLI: branch on ROUTE_HUMAN -> create_pending_approval + issue approval_url instead of AccessDeniedError; Broker.resolve_approval(); Broker.sweep_pending_timeouts() | broker/broker.py, broker/cli.py, broker/models.py (+Request, PendingHumanReviewError, ApprovalResolution), broker/db.py (+get_request) | T1 | **done** (14 tests green) |
| T8 | approval_service/: Flask magic-link web app (GET renders, POST decides) calling Broker.resolve_approval | approval_service/app.py, approval_service/Dockerfile, docker-compose.yml (+approval-service), tests/test_approval_service.py | T7 | **done** (11 tests green) |
| T9 | CLI wiring: build_broker uses DecisionRouter; --triage/--sidecar-url; load-acl/set-role subcommands; tests seed via CLI | broker/cli.py, tests/test_cli.py | T6, T7 | **done** (18 CLI tests green) |
| T9b | Hardening from review: (a) resolve_approval rejects self-approval (decided_by == requester) and enforces deadline_at at read time (no fail-open window before the sweep runs); (b) duplicate-request rejection per (requester, resource, access_level) against ACTIVE grants / PENDING approvals, raising DuplicateRequestError that the CLI reports; (c) TRIAGED audit event carrying recommendation/confidence/risk_flag so the log shows *why* the AI recommended what it did | broker/models.py, broker/db.py, broker/broker.py, broker/decision_router.py, broker/cli.py, approval_service/app.py, docker-compose.yml, tests/* | T9 | **done** (183 passed at hand-back) |
| T9c | Multi-step LLM triage (user-stated): step 1 validates the reason against the requested permission and gates the rest; step 2 least-privilege scope/proportionality with a suggested minimum level/duration (surfaced to the reviewer, not silently applied); step 3 risk -> recommendation+confidence. Both providers; per-step results in TriageResult.steps; steps_summary() for the TRIAGED audit line | broker/triage.py, tests/test_triage.py, tests/test_claude_triage.py | T5 | **done** (16 + 27 tests) |
| T9d | Renames (user-requested): DecisionRouter -> PolicyEngine (broker/policy_engine.py), abstract PolicyEngine -> Policy; broker/triage.py -> broker/llm_decision_agent.py (class names unchanged); AuditEventType.APPROVAL_REJECTED -> SELF_APPROVAL_BLOCKED (the attempt is what was blocked, the request stays PENDING for another reviewer). Wire TriageResult.steps_summary() + suggestions into the TRIAGED audit detail and the approval page | broker/*, approval_service/app.py, tests/* | T9b, T9c | pending |
| T9e | Requester history as a confidence input (part 1 read model **done**, 11 tests; part 2 wiring pending) (user-stated): RequesterHistory seam over existing SQLite tables; deterministic rules -- new requester + large scope (write/admin or >1h) -> human; recent revocation/denial -> human; history summary fed to the LLM prompt for large-scope requests and recorded in TRIAGED; TODO block for richer behavioral rules (baselines, anomaly vs own history, agent-vs-human requesters, cool-down after denial) | broker/requester_history.py, broker/policy_engine.py, broker/llm_decision_agent.py, tests/* | T9d | pending |
| T9f | RETURN_TO_REQUESTER outcome + escalation (decision #8): junk gate in the policy engine, step-1 failure returns, RequestStatus.RETURNED, ReturnedToRequesterError, Broker.escalate, CLI `escalate`, approval page shows the escalation note | broker/models.py, broker/decision_router.py, broker/broker.py, broker/cli.py, approval_service/app.py, tests/* | T9b, T9c | in_progress |
| T10a | tests/test_decision_pipeline.py: ACL-deny (no LLM call made), auto-approve, route-human paths, failure->manual fallback, duplicate rejection | tests/test_decision_pipeline.py | T6, T7, T8, T9, T9b, T9c, T9d, T9e | pending |
| T10b | tests/test_human_approval.py: approve via URL, deny via URL, timeout sweep, deadline enforced at click time, self-approval rejected, garbage-LLM-output-defers; docker compose validation incl. approval-service | tests/test_human_approval.py, Dockerfile.test, docker-compose.yml | T6, T7, T8, T9, T9b, T9c, T9d, T9e | pending |
| T11 | README + REPORT.md: rewrite README usage in a plain human voice (how to run, example requests that auto-approve / route to a human / deny); drop the stale 'planned' section (FastAPI, click, background sweeper thread) and state the actual scope cuts honestly; REPORT.md with trade-offs incl. fail-open windows closed/remaining | README.md, REPORT.md | T10a, T10b | pending |

## Round plan
- Round 1 (done): T1 (done by coordinator, not a subagent -- foundational/mechanical).
- Round 2 (parallel, dispatching now): T2, T3, T4. Disjoint files, all depend only on T1 (done).
- Round 3: T5 (needs T4), T6 (needs T1,T2,T3,T4), T7 (needs T1) -- dispatch once T2/T3/T4 land.
- Round 4: T8, T9 -- both need T7; T9 also touches cli.py which T7 already finished, so sequential
  after T7 specifically, but parallel with T8 (different files).
- Round 5: T10a, T10b -- parallel, both need T6+T7+T8+T9.
- Round 6: T11 -- needs T10a+T10b.

Note: T5 (real Claude API) is optional/best-effort, gated behind `ANTHROPIC_API_KEY` presence like
the Okta integration was gated. It does not block T6/T10 -- MockTriageProvider is sufficient for the
real "recommend and defer" behavior the spec requires.
