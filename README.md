# JIT Access Broker

A small service that brokers just-in-time access. Someone asks for time-boxed
access to a resource with a reason; a policy engine decides -- auto-approve,
return it to the requester, send it to a human, or deny -- and records why; an
AI step recommends but never decides; approved grants expire on their own; and
everything lands in an append-only audit log. The external identity provider
and the protected resource are mocked behind interfaces (an in-process mock and
a fake Okta sidecar over HTTP), so the brokering logic is what's under test.

## Reviewers: start here

Everything written for people is in [`docs_for_evaluators/`](docs_for_evaluators/):

1. [`instructions_to_tryout.md`](docs_for_evaluators/instructions_to_tryout.md) -- bring the stack up with Docker Compose and click through a request, an approval, a denial.
2. [`Design.md`](docs_for_evaluators/Design.md) -- how a request is decided, in plain language, plus the state machines and the key decisions.
3. [`REPORT.md`](docs_for_evaluators/REPORT.md) -- architecture decisions with motivations, the edge cases from the brief, and the known gaps.
4. [`cli_walkthrough.md`](docs_for_evaluators/cli_walkthrough.md) -- every path driven from the CLI with real output, including the ones that auto-approve, route to a human, and get denied.
5. [`brief.md`](docs_for_evaluators/brief.md) -- the original assignment, verbatim.

## Quick check

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest                      # unit + integration tests, no Docker needed

docker compose up --build --abort-on-container-exit --exit-code-from test-runner
docker compose down -v      # the same integration tests against real containers
```

## Layout

```
broker/                 the broker: models, SQLite store, policy engine, LLM triage,
                        requester history, connectors, CLI
approval_service/       the human-review web page (magic link)
sidecar/                fake Okta: issue / introspect / revoke tokens
protected_service/      a resource that checks tokens with the sidecar
tests/                  the executable spec
acl.yaml                who may ask for what, and who may approve
docker-compose.yml      sidecar, protected resource, approval service, sweeper, test-runner
docs_for_evaluators/    everything above, for people
docs/agent_build_plans_not_for_humans/
                        task plans written for the AI agents that built this; kept for traceability
```
