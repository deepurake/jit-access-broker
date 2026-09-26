# Instructions

## Setup

```bash
docker compose up -d --build okta-sidecar protected-resource approval-service sweeper
docker compose cp acl.yaml approval-service:/app/acl.yaml

b() { docker compose exec -T approval-service python -m broker.cli \
        --db /data/broker.db --sidecar-url http://okta-sidecar:8081 "$@"; }

b load-acl acl.yaml            # prints rules_loaded: 4, approver_roles_loaded: 2
b set-role alice engineer
b set-role carol oncall
b set-role dave intern
b set-role bob security        # security is an approver role (acl.yaml: approver_roles)
```

## Minimum test plan

### 1. Auto-approve

```bash
b request --requester alice --resource prod-db --access-level read --duration 600 \
  --reason "investigating slow queries for INC-123"
curl -s -H "Authorization: Bearer <token>" localhost:8082/data
```

Expected: `status: ACTIVE`, then `{"data":"this is the protected payload"}`.

### 2. Route to human and approve

```bash
b request --requester carol --resource prod-db --access-level admin --duration 7200 \
  --reason "rotating leaked credentials for INC-42"
```

Expected: `status: PENDING_HUMAN` and an `approval_url`.

Open `approval_url` in a browser:
- Name `rakesh` (no role) → Approve. Expected: 409, 'rakesh' is not a known approver. Link still pending.
- Name `carol` → Approve. Expected: 409, requester cannot approve their own request.
- Name `bob` → Approve. Expected: "Approved -- grant #N issued".
- Approve again. Expected: 409, already approved.

```bash
b show-request <request_id>
```

Expected: `status: HUMAN_APPROVED`.

### 3. Deny

```bash
b request --requester alice --resource prod-db --access-level write --duration 600 --reason "fix bad row"
```

Expected: `status: DENY`.

### 4. Revoke

```bash
b revoke <grant_id> --by security-team
curl -s -H "Authorization: Bearer <token>" localhost:8082/data
```

Expected: `revoked: true`, then `{"error":"token is invalid, expired, or revoked"}`.

### 5. Expiry

```bash
b request --requester alice --resource prod-db --access-level read --duration 20 \
  --reason "quick check of replication lag"
sleep 30
curl -s -H "Authorization: Bearer <token>" localhost:8082/data
b status <grant_id>
```

Expected: error response, then `status: EXPIRED`.

## Automated tests

```bash
source .venv/bin/activate
pytest
```

## Teardown

```bash
docker compose down -v
```
