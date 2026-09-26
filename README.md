# JIT Access Broker

A small service that brokers just-in-time access: someone asks for time-boxed access to a resource, a policy engine decides (auto-approve, route to a human, deny, or hand it back to the requester for a better reason) and records why, approved grants expire on their own, and every step lands in an append-only audit log. The grant itself is mocked behind a connector interface; there is an in-process mock and an HTTP mock (a fake Okta sidecar plus a protected test service) so the same broker code is exercised over a real network boundary.

## The brief

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

## Run it

Python 3.11+ and nothing else. The tests are the executable spec, so run them first.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Everything below goes through `python -m broker.cli --db broker.db <command>`. Each invocation opens the same SQLite file, so state is shared across separate processes the way a real CLI is used. Start by loading the access rules and telling the broker who has which role:

```
$ python -m broker.cli --db broker.db load-acl acl.yaml
rules_loaded: 3

$ python -m broker.cli --db broker.db set-role alice engineer
requester: alice
role: engineer

$ python -m broker.cli --db broker.db set-role carol oncall
requester: carol
role: oncall
```

`acl.yaml` ships with three roles: `engineer` may hold up to `read` on `prod-db` for an hour, `oncall` up to `admin` on anything matching `prod-*` for two hours, `intern` up to `read` on `staging-*` for thirty minutes. Bob has no role.

### Path 1: auto-approve

A read request, inside the role's ceiling, with a reason that says something. The AI triage step recommends APPROVE with HIGH confidence and no risk flag, and that is the one combination the router lets through on its own.

```
$ python -m broker.cli --db broker.db request --requester alice --resource prod-db \
    --access-level read --duration 3600 --reason "debugging incident 123"
status: ACTIVE
grant_id: 1
request_id: 1
token: mock-token-18fc20650ec22ae4
granted_at: 1790405816
expires_at: 1790409416
```

### Path 2: route to a human

An over-scoped but legitimate request. Carol is oncall and allowed admin for two hours, and the reason is real, but the triage step's least-privilege check flags admin-for-two-hours and suggests `write` for one hour instead. It still recommends APPROVE, but with MEDIUM confidence and a risk flag, and whether the requester really needs the wider scope is a reviewer's call, not a wording problem. The output is a single-use approval token, the URL where a reviewer decides it, and the deadline (four hours from now by default):

```
$ python -m broker.cli --db broker.db request --requester carol --resource prod-db \
    --access-level admin --duration 7200 --reason "rotating leaked credentials after incident 4711"
status: PENDING_HUMAN
approval_token: DOtGCE6HCpE83SKJJ8CJieLqwAzOpDsfSjxkQvWZ3NA
approval_url: http://localhost:8083/approve/DOtGCE6HCpE83SKJJ8CJieLqwAzOpDsfSjxkQvWZ3NA
deadline_at: 1790420217
```

The same happens for anything the router is not sure about: low confidence, a risk flag on an otherwise confident approve, a DENY recommendation that did not come from the reason check, a brand-new requester asking for a large scope, a requester with a recent denial or revocation, or any component of the pipeline throwing an error (the error text becomes the reason the reviewer sees).

The reviewer decides from the CLI (or from the web page, see the next section). The requester cannot approve their own request, and that attempt does not consume the link:

```
$ python -m broker.cli --db broker.db approve DOtGCE6HCpE83SKJJ8CJieLqwAzOpDsfSjxkQvWZ3NA --by carol --decision approve
resolved: false
detail: requesters cannot approve their own request

$ python -m broker.cli --db broker.db approve DOtGCE6HCpE83SKJJ8CJieLqwAzOpDsfSjxkQvWZ3NA --by bob --decision approve
resolved: true
grant_id: 2
token: mock-token-510b6c0b7e11e30b

$ python -m broker.cli --db broker.db approve DOtGCE6HCpE83SKJJ8CJieLqwAzOpDsfSjxkQvWZ3NA --by bob --decision approve
resolved: false
detail: approval already approved

$ python -m broker.cli --db broker.db status 2
grant_id: 2
status: ACTIVE
active: true
expires_at: 1790413040
```

`--decision deny` works the same way and issues nothing. If nobody decides within the deadline, the request times out and is auto-denied; the deadline is checked when the link is used, not only when the sweeper runs, so a stale link can never approve.

### Path 3: deny

Denials come from the deterministic ACL check and never involve the AI. No role:

```
$ python -m broker.cli --db broker.db request --requester bob --resource prod-db \
    --access-level read --duration 600 --reason "debugging incident 123"
status: DENY
detail: requester has no assigned role
```

Over the role's ceiling (engineer is capped at read on prod-db; the same happens for a duration over the cap or a resource the role has no rule for):

```
$ python -m broker.cli --db broker.db request --requester alice --resource prod-db \
    --access-level admin --duration 600 --reason "rotating leaked credentials after incident 4711"
status: DENY
detail: role 'engineer' is capped at 'read' for 'prod-db', requested 'admin'
```

### Path 4: returned to the requester

The brief says approvers should not sit around acting as an approval desk. A reason that is junk, or that does not justify the permission being asked for, is something only the requester can fix, so the broker hands it back to them instead of to a reviewer. Nobody gains anything by getting their own request bounced, so this is safe to automate in a way that denying or approving is not.

A placeholder reason never reaches the model. `idk` (or anything under ten characters) is caught by a deterministic gate in the policy engine:

```
$ python -m broker.cli --db broker.db request --requester alice --resource prod-db \
    --access-level read --duration 600 --reason "idk"
status: RETURNED
request_id: 9
detail: reason is missing or a placeholder -- say what you need to do and why
hint: fix the reason and resubmit, or escalate this request to a human reviewer
escalate_with: python -m broker.cli --db broker.db escalate 9 --by alice --note "..."
```

A reason that does not fit the permission fails triage step 1. "I want to look at the dashboards" describes reading, so it cannot justify `admin`; the rest of triage never runs and the model's explanation comes back as the detail:

```
$ python -m broker.cli --db broker.db request --requester carol --resource prod-queue \
    --access-level admin --duration 600 --reason "I want to look at the dashboards"
status: RETURNED
request_id: 10
detail: reason does not justify admin access: it describes no change to make
hint: fix the reason and resubmit, or escalate this request to a human reviewer
escalate_with: python -m broker.cli --db broker.db escalate 10 --by carol --note "..."
```

The exit code is 1 and the request's status is `RETURNED`. From there the requester has two options. Resubmitting with a better reason is an ordinary new request (a returned request is neither an active grant nor a pending review, so it is not a duplicate). Or, if they think the broker is wrong, they escalate, which turns the returned request into a normal pending human review:

```
$ python -m broker.cli --db broker.db escalate 10 --by carol \
    --note "the dashboard service only exposes its config through the admin console"
status: PENDING_HUMAN
approval_token: 7QbXm2p9Z-2f1RkL0uYdVwq4Hs8nJgTcE6aBo3xWiKM
approval_url: http://localhost:8083/approve/7QbXm2p9Z-2f1RkL0uYdVwq4Hs8nJgTcE6aBo3xWiKM
deadline_at: 1790420839
```

Only the requester can escalate their own request, only a `RETURNED` request can be escalated, and only once. The review page shows the reviewer both the broker's reason for returning it and the requester's note, and from there approve and deny work exactly as in path 2. In the audit log this shows up as `RETURNED_TO_REQUESTER`, then `ESCALATED` followed by `ROUTED_TO_HUMAN`.

### Duplicates

Asking again for the same (requester, resource, access level) while a grant is active or a review is pending is recorded and rejected, pointing at the existing one. The reason and duration do not matter; it is the same access.

```
$ python -m broker.cli --db broker.db request --requester alice --resource prod-db \
    --access-level read --duration 3600 --reason "debugging incident 123"
status: DUPLICATE
detail: duplicate request: active grant exists
existing_grant_id: 1
```

When the original is still waiting on a reviewer the output has `existing_approval_token` instead. Once the grant expires or is revoked, or the review is decided, the same request goes through again.

### Inspecting, revoking, sweeping

```
$ python -m broker.cli --db broker.db show-request 3
request_id: 3
requester: carol
resource: prod-db
access_level: admin
duration_seconds: 7200
reason: rotating leaked credentials after incident 4711
status: HUMAN_APPROVED
created_at: 1790405817
```

Request status goes `PENDING_POLICY -> AUTO_APPROVED | DENIED | DUPLICATE | RETURNED | PENDING_HUMAN`; a returned one may move to `PENDING_HUMAN` by escalation, and a pending one ends as `HUMAN_APPROVED`, `HUMAN_DENIED`, or `TIMED_OUT`. `show-request` is the only way to see the outcome of a request that never produced a grant.

The audit log is one row per event, append-only. `TRIAGED` sits between `REQUESTED` and `POLICY_DECIDED` because the recommendation exists before the router turns it into a decision, and it carries the recommendation, confidence, risk flag, and what each triage step concluded. A request the ACL denied has no `TRIAGED` row at all.

```
$ python -m broker.cli --db broker.db audit --request-id 3
at=1790405817 event=REQUESTED request=3 grant=- detail=carol requested admin on prod-db for 7200s: rotating leaked credentials after incident 4711
at=1790405817 event=TRIAGED request=3 grant=- detail=APPROVE confidence=MEDIUM risk_flag=True: reason is present but admin access for an extended duration carries elevated risk
at=1790405817 event=POLICY_DECIDED request=3 grant=- detail=ROUTE_HUMAN: reason is present but admin access for an extended duration carries elevated risk
at=1790405817 event=ROUTED_TO_HUMAN request=3 grant=- detail=reason is present but admin access for an extended duration carries elevated risk
at=1790405839 event=SELF_APPROVAL_BLOCKED request=3 grant=- detail=self-approval attempt by carol
at=1790405840 event=HUMAN_APPROVED request=3 grant=2 detail=approved by bob
```

`audit` with no filter prints everything; `--grant-id` narrows to one grant. Event types: `REQUESTED`, `TRIAGED`, `POLICY_DECIDED`, `GRANTED`, `DENIED`, `RETURNED_TO_REQUESTER`, `ESCALATED`, `ROUTED_TO_HUMAN`, `HUMAN_APPROVED`, `HUMAN_DENIED`, `APPROVAL_TIMEOUT`, `SELF_APPROVAL_BLOCKED`, `DUPLICATE_REJECTED`, `EXPIRED`, `REVOKED`.

Revoking is immediate and idempotent; a second revoke, or a revoke of an already-expired grant, is a no-op:

```
$ python -m broker.cli --db broker.db revoke 1 --by security-team
grant_id: 1
revoked: true

$ python -m broker.cli --db broker.db status 1
grant_id: 1
status: REVOKED
active: false
expires_at: 1790409416
```

`status` reports `active: false` the instant `expires_at` passes, whether or not anything has swept yet. The sweep is what tears the external token down and auto-denies stale reviews:

```
$ python -m broker.cli --db broker.db sweep
expired_count: 0
timed_out_count: 0
```

`sweep --loop --interval 30` keeps going; that is what the `sweeper` compose service runs. Be clear about what this means: between sweeps the external token stays live even though the broker already reports the grant inactive. That is the remaining fail-open window, and it is exactly as wide as the sweep interval.

To use the real model instead of the deterministic mock, set `ANTHROPIC_API_KEY` and add `--triage claude` before the subcommand. To issue tokens against the fake Okta sidecar instead of the in-process mock, add `--sidecar-url http://localhost:8081`.

## The approval page

The `approval_url` printed above points at a small Flask app:

```bash
BROKER_DB=broker.db python -m approval_service.app     # listens on :8083
```

Set `SIDECAR_URL` too if the grants were issued through the sidecar, so an approval issues a token there. On start the app runs one reconcile pass, so anything that expired or timed out while nothing was running is dealt with before it serves a click.

`GET /approve/<token>` shows the reviewer the requester, resource, level, duration, the stated reason, the deadline, and why the AI did not auto-approve, including the suggested minimum level and duration when the least-privilege step produced one. For an escalated request it also shows why the broker returned it and the requester's escalation note. The decision is a form `POST` to `/approve/<token>/decide` with the reviewer's name and approve/deny. A `GET` on that URL is a 405: a bare link, whether clicked by a person or prefetched by a mail client, can never approve anything. The token is random, single-use, and the only credential; there is no login. A second decision on the same link, a decision by the requester, a decision after the deadline, or an unknown token all come back as 409 with the reason on the page, and none of them issue anything. After the deadline the request is marked `TIMED_OUT` right there, without waiting for a sweep.

## Docker Compose

```bash
docker compose up --build --abort-on-container-exit --exit-code-from test-runner
docker compose down
```

This brings up five containers. `okta-sidecar` is the fake identity provider: it issues tokens, introspects them, and revokes them. `protected-resource` is the thing being protected; it asks the sidecar whether the bearer token is still active on every request. `approval-service` is the review page, and `sweeper` is `broker.cli sweep --loop --interval 5`; both share the `broker-data` volume so they operate on the same SQLite file, and both point at the sidecar so an approval issues a real token and an expiry tears one down. `test-runner` runs `tests/test_integration.py` against the live containers and exits non-zero if anything fails: a broker-issued token gets a 200 from the protected service, revoking or expiring the grant turns that into a 401, and an approval clicked on the web app produces a token the protected service honours.

The same integration tests run under plain `pytest` with no Docker; `tests/conftest.py` starts the three services in background threads when the `*_URL` environment variables are not set.

## How decisions are made

A request goes through four stages, and only the first one can deny.

First the ACL ceiling. The requester's role comes from the `user_roles` table; the rules for that role come from the `acl_rules` table, which is loaded from `acl.yaml`. The first rule whose `resource_pattern` matches the resource decides the ceiling: the requested level must be at or below `max_access_level` (read < write < admin) and the duration at or below `max_duration_seconds`. No role, no matching rule, or over either cap is a DENY, and the AI never runs. This is the hard boundary; nothing downstream can widen it.

Then a junk gate, also deterministic: an empty, placeholder, or under-ten-character reason is returned to the requester before any model call. It costs nothing, no approver sees it, and a security person can read the rule.

Then triage, in three steps. Step 1 asks whether the stated reason justifies this resource at this access level; a reason that only describes looking at something does not justify write or admin. Failing step 1 stops triage and the request is returned to the requester with the model's explanation. Step 2 is least privilege: is the level and duration the minimum the reason needs, and if not, what would be; an over-scoped request gets a suggested minimum and a risk flag. Step 3 produces the final recommendation and confidence. The mock runs these as deterministic heuristics; `--triage claude` runs them as two model calls (step 1 alone, then steps 2 and 3), each returning JSON that is parsed defensively. Unparseable output is the lowest confidence and goes to a human.

Then the router, which is plain code and not another model call. HIGH confidence plus APPROVE plus no risk flag is the only auto-approve. A failed step 1 is the only return-to-requester. Everything else routes to a human: over-scope, a risk flag on an otherwise confident approve, low confidence, or a DENY recommendation the model reached for some reason other than the wording. The AI can approve the obviously fine case and bounce the obviously insufficient reason back to the person who wrote it; it cannot deny, and it cannot decide the ambiguous middle. Deterministic rules and humans deny.

The failure policy is separate from the decision policy: a component that denies has made a decision, a component that throws has failed, and any failure in the directory, the ACL engine, or the triage provider routes the request to a human with the error text in the reason, visible on the review page and in the audit log. If the ACL boundary itself could not be evaluated, triage is skipped as well, so an ungated AI approve cannot exist.

Requester history feeds into this as well: a read model over the same tables summarises what the broker already knows about the requester (grants held, denials, revocations, pending reviews). A brand-new requester asking for a large scope goes to a human regardless of what the triage step says, as does anyone with a recent denial or revocation; the summary is passed to the model for large requests and recorded in the `TRIAGED` event.

This is the whole of `acl.yaml`:

```yaml
roles:
  engineer:
    - resource_pattern: "prod-db"
      max_access_level: read
      max_duration_seconds: 3600
  oncall:
    - resource_pattern: "prod-*"
      max_access_level: admin
      max_duration_seconds: 7200
  intern:
    - resource_pattern: "staging-*"
      max_access_level: read
      max_duration_seconds: 1800
```

A security person edits this file, has it reviewed, and runs `load-acl`. They do not touch the triage heuristics or the router; those are code, and the thresholds in them (what counts as risky, what confidence auto-approves) are the part I would expect to change least often.

## Policy as data

The ACL is authored in YAML and served from a table, which is how Teleport roles, OPA bundles, and IAM policies all work: the file is the thing people read, diff, and review in git; the table is the thing the runtime queries, indexed and referenceable from an audit row. `load-acl` is the sync between them and replaces the table wholesale, so what is loaded is always exactly one reviewed version of the file.

User-to-role is a table and not YAML because it is operational data that changes with hiring, on-call rotations, and team moves. In a real deployment it is synced from the identity provider (Okta group membership, say) and nobody hand-edits it. `set-role` stands in for that sync.

## What I'd do next

A real connector: `HttpResourceConnector` already has the shape (issue and revoke over HTTP), so an Okta or AWS implementation is one class against the same two methods, plus real credentials and retries.

Authentication on the approval page: the single-use token is the only credential today. Behind SSO the reviewer's identity would come from the session rather than a text field, which also makes the self-approval check trustworthy instead of honour-based.

More requester-history rules: per-requester baselines, anomalies relative to the requester's own history rather than absolute thresholds, distinguishing agent from human requesters, a cool-down after a denial, and counting escalations (someone who escalates every returned request is a signal in itself). The read model exists; these are rules on top of it.

Notifications and escalation: the approval URL is printed to the terminal. Sending it somewhere, reminding, and escalating to a second approver before the four-hour deadline is what "the approver is asleep" really needs; today the answer is only the fail-closed timeout.

A REST API for the broker itself, so requests can come from something other than a shell.

Metrics: auto-approve rate, time-to-decision, timeout rate, and how often the reviewer's decision disagrees with the AI's recommendation, which is the number that tells you whether the confidence threshold is right.

## Layout

```
acl.yaml                        the access rules; edit, review, load-acl
broker/models.py                dataclasses, enums, and the exceptions the broker raises
broker/db.py                    SQLite schema and all writes; guarded state transitions live here
broker/broker.py                the request -> decision -> grant state machine
broker/policy.py                Policy interface and the stage-1 AlwaysApprovePolicy
broker/policy_engine.py         PolicyEngine: composes directory, ACL, triage, history into a decision
broker/acl_policy.py            the ACL ceiling check
broker/acl_loader.py            parses acl.yaml into rows for the acl_rules table
broker/user_directory.py        UserDirectory seam over the user_roles table
broker/llm_decision_agent.py    TriageProvider, MockTriageProvider, ClaudeTriageProvider
broker/requester_history.py     read-only history projection over the same tables
broker/connector.py             ResourceConnector seam and the in-process MockConnector
broker/http_connector.py        ResourceConnector that talks to the sidecar over HTTP
broker/clock.py                 Clock seam (SystemClock, FakeClock) so tests never sleep
broker/cli.py                   argparse CLI; every subcommand opens the --db file
approval_service/app.py         the magic-link review page (Flask)
sidecar/app.py                  fake Okta: issue, introspect, revoke
protected_service/              the protected resource; introspects the bearer token per request
docker-compose.yml              sidecar, protected resource, approval service, sweeper, test runner
Dockerfile.test                 image for the test-runner service
tests/                          the executable spec; tests/test_cli.py shows every command and its output
docs/superpowers/plans/         the design notes this was built from
REPORT.md                       architecture decisions and their motivations
```
