# Just-in-Time Access Broker — Build Plan

# Question:
Just-in-Time Access Broker



Background



We'd want people and agents to request access to a resource when they need it, for a bounded window, and have it disappear on its own. And we don’t want approvers to have to sit around acting as an approval desk. We want to make short-lived access easy to request, safe to grant while pulling a human into the loop only as an exception.

Build a service with UI or CLI that brokers just-in-time access: a user requests time-boxed access to a resource, a policy engine decides whether to auto-approve, route to a human, or deny; approved grants expire on their own; and everything lands in an audit trail.



Requirements



A zip file that contains your code.
A README for how to run the app, plus example requests to test — including ones that auto-approve, ones that route to a human, and ones that get denied.
A short report of architecture decisions with motivations.
Core:
A user can request time-boxed access: resource, access level, duration, and a reason.
A policy engine decides each request — auto-approve / route to a human / deny — and records why.
Requests routed to a human can be approved or denied, and the requester ends up with (or without) a grant accordingly.
Grants are time-boxed and expire automatically; an expired or revoked grant is no longer active.
The actual "grant" is mocked behind an interface (e.g. a fake Okta / AWS / Workspace call) — the workflow and policy are the point, not real integrations.
An append-only audit log captures every request, decision, grant, expiry, and revocation.
An AI triage step recommends a decision with a short justification for requests that aren't trivially auto-approved or denied, and defers to a human when it isn't confident. (You may mock the model call, but the recommend-and-defer behavior should be real.)


Worth thinking about



You decide how far to take each of these. We mostly care about the choices you make and why.
How policy is expressed — could a non-engineer security person understand it?
What happens when the approver is asleep: defaults, escalation, expiry of pending requests.
Races between grant, expiry, and revocation landing at the same time.
Concurrent or duplicate requests for the same access.
Where AI genuinely helps triage vs. where trusting it is too risky.
Least privilege on the duration and level: do you grant exactly what was asked, or the minimum that fits the reason?
How you'd swap the mocked grant for a real Okta / Workspace / AWS connector later.


Notes



Total time is ~6 hours. Budget roughly 4 to build, 1 to QA, 1 to review the code. A tight, working broker beats a broad, half-built one; if you run out of time, write down what's left.
Use whatever stack and LLM provider you're most comfortable with. Raw provider SDKs (the anthropic / openai clients) are fine — but build the request → decision → grant state machine yourself; don't hand the orchestration to an agent framework.
Mock external systems (identity providers, the resources themselves) behind clean interfaces. We're evaluating the brokering logic, not integration plumbing.
Make reasonable assumptions and note them. Handle the edge cases you think matter (approver never responds, a grant expires mid-revoke, duplicate requests, the model returns garbage, the service restarts with grants still outstanding).
Spend ~15 minutes writing the reasoning behind your decisions.





Words: 1
If your submission is larger than 10 MB, feel free to compress the file and upload to a google drive. And share the link with us below.

## Stack & Interface
- **Python 3.11 + FastAPI** for the service — exposes a REST API that both a CLI and `curl` examples can hit.
- **SQLite** (stdlib `sqlite3`, no ORM) for persistence — durable across restarts; single-writer transaction model
  gives correct handling of the grant/expire/revoke race for free (conditional `UPDATE ... WHERE status='ACTIVE'`,
  whoever commits first wins, the loser is a no-op).
- **CLI (`click`)** as a thin wrapper over the same API — satisfies "UI or CLI" and gives scriptable demo commands.

## Core Design Decisions
1. **State machine**: `Request` → `PENDING_POLICY` → (`AUTO_APPROVED` / `PENDING_HUMAN` / `DENIED`) → human path
   resolves to `APPROVED`/`DENIED`. `Grant` → `ACTIVE` → `EXPIRED` | `REVOKED`. All transitions are guarded,
   conditional DB writes — no in-memory state, so a service restart just resumes from SQLite (a boot-time sweep
   reconciles anything that expired while the service was down).
2. **Policy engine as data, not code**: a YAML file of rules (resource pattern, access level, max duration,
   condition → decision) that a security person can read/edit without touching Python. Engine evaluates rules
   top-down: clear allow → auto-approve, clear deny → deny, everything else → AI triage.
3. **AI triage**: only invoked for the gray zone. `TriageProvider` interface with a `MockTriageProvider`
   (deterministic heuristic standing in for the model) and a real Claude-backed implementation behind
   `ANTHROPIC_API_KEY` — same interface, swappable. If the response doesn't parse or confidence is low, it defers
   to a human — the "recommend and defer" behavior the spec calls out.
4. **Expiry**: derived at read-time (`expires_at <= now` ⇒ inactive) *and* a background sweeper thread that flips
   status + writes the audit event, so both "is it active right now" and "when did it actually expire" stay
   correct even if the sweeper is lagging.
5. **Pending-human timeout**: each human-routed request gets a policy-configurable `response_deadline`. A sweeper
   auto-denies stale pending requests and logs "approval timeout" — the answer to "approver is asleep."
6. **Duplicate/concurrent requests**: a uniqueness check on (requester, resource, access level) against existing
   PENDING/ACTIVE rows inside the same transaction — a second request is rejected with a pointer to the existing
   one instead of creating a duplicate grant.
7. **Mocked grant backend**: `ResourceConnector` interface (`grant`/`revoke`), one `MockConnector` implementation
   that just logs the "API call" — the seam where a real Okta/AWS/Workspace SDK call would go later.
8. **Audit log**: append-only SQLite table, insert-only (no update/delete path exposed), one row per event
   (`REQUESTED`, `POLICY_DECIDED`, `TRIAGED`, `HUMAN_DECIDED`, `GRANTED`, `EXPIRED`, `REVOKED`).

## Deliverables
- `broker/` source
- `README.md` — run instructions + example requests (auto-approve / human-route / deny)
- `REPORT.md` — architecture rationale
- Zipped project at the end
- Tests for the policy engine and the race-condition logic

## Component Timeline (~6h budget)

| # | Component | Est. | Notes |
|---|-----------|------|-------|
| 1 | Skeleton | 45m | DB schema, FastAPI app, one endpoint, mock connector, end-to-end happy path |
| 2 | Policy engine | 1h | YAML rules + evaluator + tests |
| 3 | AI triage | 45m | `TriageProvider` interface + mock provider + defer-on-low-confidence logic |
| 4 | Human approval flow | 1h | Approve/deny endpoints + pending-request timeout sweeper |
| 5 | Expiry & revocation | 1h | Expiry sweeper + race handling + tests |
| 6 | CLI + README | 45m | `click` CLI, run instructions, example requests |
| 7 | QA + REPORT.md | 45m | End-to-end pass, edge cases, architecture write-up |

## Stage 1 — Walking Skeleton (JIT token disbursement, end to end)

Scope, deliberately narrowed to prove the core loop before building the full policy engine,
AI triage, and human-approval flow described above:

- `broker/clock.py` — `Clock` seam (`SystemClock` / `FakeClock`) so expiry is testable without sleeping.
- `broker/models.py` — `Grant`, `AuditEvent`, `PolicyDecision`, and their status/type enums.
- `broker/connector.py` — `ResourceConnector` seam + `MockConnector` (stands in for Okta/AWS/Workspace).
- `broker/policy.py` — `PolicyEngine` seam + `AlwaysApprovePolicy` (stage-1 placeholder; real rules come later).
- `broker/db.py` — SQLite persistence (file-based, not in-memory) with guarded state transitions:
  expiry and revocation are both conditional `UPDATE ... WHERE status='ACTIVE'`, so whichever lands
  first wins atomically and the other is a no-op — this is the race-condition answer from the spec.
- `broker/broker.py` — `Broker`, the orchestrator: `request_access`, `is_active`, `revoke`, `sweep_expired`.

Run the evals (they're real tests, not smoke checks — each one fails under a plausible bug mutation):

```bash
pip install -r requirements.txt
pytest tests/test_broker_e2e.py -v
```

`tests/test_broker_e2e.py` covers, against a real (file-based) SQLite test database per test:
1. A request auto-approves and issues an active, tokenized grant immediately.
2. A grant becomes inactive the instant its duration elapses, even before a sweep runs (expiry is
   derived at read-time), and the sweep then persists that as `EXPIRED`.
3. Revoking an active grant deactivates it immediately and calls the mock connector's `revoke`.
4. The audit log captures the full `REQUESTED → POLICY_DECIDED → GRANTED → EXPIRED` lifecycle.
5. An already-`EXPIRED` grant cannot be flipped to `REVOKED` (guards the expire/revoke race).
6. A brand-new `Broker`/`Database` pointed at the same file recovers grant state after a simulated
   process restart.

**Status: Stage 1 done, all 6 evals green.** Not yet built: real policy rules (YAML-driven), human
approval routing + pending-request timeout, AI triage, duplicate-request rejection, CLI/API layer.
Those are stage 2+, to be layered on top of these same seams.
