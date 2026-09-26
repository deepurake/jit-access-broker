"""The human-review half of the JIT broker: a magic-link web app. A request
the PolicyEngine couldn't confidently auto-approve lands here as a
single-use URL. GET renders what's being asked (including the AI triage
justification) so the reviewer can decide; the decision itself is a POST so
a bare link can never approve access on its own. No login -- the unguessable
single-use token is the credential, and Broker.resolve_approval enforces
single-use with a guarded DB transition."""
import os

from flask import Flask, abort, render_template_string, request

from broker.broker import SUGGESTED_MINIMUM_SEPARATOR, Broker
from broker.models import AuditEventType, PendingApprovalStatus

NO_JUSTIFICATION = "(no justification recorded)"

REVIEW_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Access review: {{ req.requester }} -> {{ req.resource }}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 40em; margin: 2em auto; padding: 0 1em; line-height: 1.4; }
    dt { font-weight: bold; margin-top: 0.75em; }
    dd { margin-left: 0; }
    blockquote { margin: 0; padding: 0.5em 1em; border-left: 3px solid #999; background: #f4f4f4; }
    form { margin-top: 1.5em; padding-top: 1em; border-top: 1px solid #ccc; }
    button { padding: 0.5em 1.5em; margin-right: 0.5em; }
  </style>
</head>
<body>
  <h1>Access request review</h1>

  <dl>
    <dt>Requester</dt><dd>{{ req.requester }}</dd>
    <dt>Resource</dt><dd>{{ req.resource }}</dd>
    <dt>Access level</dt><dd>{{ req.access_level }}</dd>
    <dt>Duration</dt><dd>{{ req.duration_seconds }} seconds</dd>
    <dt>Requester's stated reason</dt><dd><blockquote>{{ req.reason }}</blockquote></dd>
    <dt>Review deadline (unix time)</dt><dd>{{ pending.deadline_at }}</dd>
    <dt>Status</dt><dd>{{ pending.status.value }}</dd>
  </dl>

  <h2>Why this needs a human</h2>
  {% if escalation_note is not none %}
  <p><strong>Escalated by the requester: {{ escalation_note }}</strong></p>
  {% endif %}
  <p>The AI triage step did not auto-approve this request. Its justification:</p>
  <blockquote>{{ justification }}</blockquote>
  {% if suggested_minimum is not none %}
  <p><strong>Suggested minimum:</strong> {{ suggested_minimum }}</p>
  {% endif %}

  {% if pending.status == PendingApprovalStatus.PENDING %}
  <form method="post" action="/approve/{{ token }}/decide">
    <label>Your name <input type="text" name="decided_by" required></label>
    <p>
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </p>
  </form>
  {% else %}
  <p>This request has already been decided: <strong>{{ pending.status.value }}</strong>
  {% if pending.decided_by %}by {{ pending.decided_by }}{% endif %}
  {% if pending.decided_at %}at {{ pending.decided_at }} (unix time){% endif %}.</p>
  {% endif %}
</body>
</html>
"""

MESSAGE_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }}</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 40em; margin: 2em auto; padding: 0 1em;">
  <h1>{{ title }}</h1>
  <p>{{ message }}</p>
</body>
</html>
"""


def _split_suggested_minimum(detail: str):
    """A ROUTED_TO_HUMAN detail may end in ` | suggested minimum: write/3600s`
    (Broker appends it when triage found the request over-scoped). Returns
    (justification, "write for 3600s") -- or (detail, None) when there is
    no such suffix -- so the page can label the alternative on its own line
    instead of burying it in the justification. No schema change: the audit
    detail is the record, this only parses it back for display."""
    justification, separator, suggestion = detail.partition(SUGGESTED_MINIMUM_SEPARATOR)
    if not separator:
        return detail, None
    level, slash, duration = suggestion.partition("/")
    return justification, f"{level} for {duration}" if slash else suggestion


def create_app(broker: Broker) -> Flask:
    app = Flask(__name__)

    def message(title: str, text: str, status: int):
        return render_template_string(MESSAGE_PAGE, title=title, message=text), status

    @app.get("/approve/<token>")
    def review(token):
        pending = broker.db.get_pending_approval_by_token(token)
        if pending is None:
            abort(404)
        req = broker.db.get_request(pending.request_id)

        # The LAST ROUTED_TO_HUMAN event is the one this approval came from
        # (get_audit_log is ordered by id, so iterating without a break keeps
        # the latest). An escalated request has exactly one, carrying what
        # the AI originally objected to; the ESCALATED event (if any) is the
        # requester's own note explaining why a human should look anyway.
        justification = NO_JUSTIFICATION
        escalation_note = None
        for event in broker.db.get_audit_log(request_id=pending.request_id):
            if event.event_type == AuditEventType.ROUTED_TO_HUMAN:
                justification = event.detail
            elif event.event_type == AuditEventType.ESCALATED:
                escalation_note = event.detail.split(": ", 1)[-1]
        justification, suggested_minimum = _split_suggested_minimum(justification)

        return render_template_string(
            REVIEW_PAGE,
            token=token,
            pending=pending,
            req=req,
            justification=justification,
            suggested_minimum=suggested_minimum,
            escalation_note=escalation_note,
            PendingApprovalStatus=PendingApprovalStatus,
        )

    @app.post("/approve/<token>/decide")
    def decide(token):
        decision = request.form.get("decision")
        decided_by = (request.form.get("decided_by") or "").strip()
        if decision not in ("approve", "deny"):
            return message("Bad request", "decision must be 'approve' or 'deny'.", 400)
        if not decided_by:
            return message("Bad request", "Your name is required to record the decision.", 400)

        resolution = broker.resolve_approval(token, approve=(decision == "approve"), decided_by=decided_by)
        if not resolution.resolved:
            # 409 for every refusal: the client's request conflicts with the
            # approval's current state (decided, timed out, unknown) or with
            # who is allowed to decide it (the requester). The broker's reason
            # says which, so the reviewer isn't left guessing.
            return message("Link no longer valid", f"This approval link was not accepted: {resolution.reason}.", 409)
        if resolution.grant is not None:
            return message("Approved", f"Approved -- grant #{resolution.grant.id} issued.", 200)
        return message("Denied", "Denied -- no access was granted.", 200)

    return app


if __name__ == "__main__":
    from broker.connector import MockConnector
    from broker.db import Database
    from broker.http_connector import HttpResourceConnector
    from broker.policy import AlwaysApprovePolicy

    db = Database(os.environ.get("BROKER_DB", "broker.db"))
    sidecar_url = os.environ.get("SIDECAR_URL")
    connector = HttpResourceConnector(sidecar_url) if sidecar_url else MockConnector()
    # The policy is irrelevant here: this service only ever calls
    # Broker.resolve_approval, which never consults the policy -- the routing
    # decision was already made (and audited) when the request came in.
    broker = Broker(db=db, policy=AlwaysApprovePolicy(), connector=connector)
    # Boot reconciliation: anything that expired or timed out while no
    # process was running gets torn down / auto-denied before we serve a
    # single click, instead of waiting for the next sweeper pass.
    broker.reconcile()
    # The Database holds one SQLite connection; the dev server must not run
    # requests concurrently on it.
    create_app(broker).run(host="0.0.0.0", port=8083, threaded=False)
