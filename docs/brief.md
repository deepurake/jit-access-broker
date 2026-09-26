# The brief (assignment text, verbatim)

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
