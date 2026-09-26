# Design

## System

```mermaid
flowchart LR
    Requester(["Requester"])
    Approver(["Approver"])
    Admin(["Admin"])
    Client(["Client with token"])

    subgraph Procs["Broker processes (shared SQLite file)"]
        CLI["broker CLI"]
        ApprovalSvc["approval-service :8083"]
        Sweeper["sweeper (reconcile every 5s)"]
    end

    subgraph Core["Broker core"]
        Broker["Broker"]
        subgraph PE["PolicyEngine"]
            UD["UserDirectory"]
            ACL["AclPolicyEngine"]
            Junk{"Junk-reason gate"}
            Hist["RequesterHistoryReader"]
            Triage["TriageProvider<br/>Mock or Claude"]
            Rules{"Routing + history rules"}
            UD --> ACL --> Junk --> Hist --> Triage --> Rules
        end
        Conn["ResourceConnector<br/>Mock or Http"]
    end

    DB[("SQLite<br/>requests · grants · pending_approvals<br/>audit_log · user_roles · acl_rules")]
    YAML["acl.yaml"]
    Claude["Anthropic API"]

    subgraph EP["Enforcement"]
        Sidecar["Okta sidecar :8081"]
        Protected["Protected service :8082"]
    end

    Requester --> CLI
    Admin -- "load-acl · set-role" --> CLI
    Approver --> ApprovalSvc
    CLI --> Broker
    ApprovalSvc --> Broker
    Sweeper --> Broker
    Broker --> PE
    Broker --> DB
    Broker --> Conn
    PE -.-> DB
    YAML --> DB
    Triage --> Claude
    Conn --> Sidecar
    Client --> Protected
    Protected -- "introspect" --> Sidecar
```

## Decision pipeline

```mermaid
flowchart TD
    A(["request_access"]) --> B{"Duplicate?"}
    B -- yes --> DUP["DUPLICATE"]
    B -- no --> C{"ACL allows?"}
    C -- no --> DENY["DENY"]
    C -- yes --> D{"Junk reason?"}
    D -- yes --> RET["RETURN_TO_REQUESTER"]
    D -- no --> E["Load requester history"]
    E --> F{"Triage step 1:<br/>reason justifies level?"}
    F -- no --> RET
    F -- yes --> G{"HIGH + APPROVE + no risk?"}
    G -- no --> HUM["ROUTE_HUMAN"]
    G -- yes --> H{"Recent denial/revocation,<br/>or newcomer + large scope?"}
    H -- yes --> HUM
    H -- no --> AUTO["AUTO_APPROVE → grant"]
    RET -- "requester escalates" --> HUM
    HUM --> I{"Approver decision"}
    I -- approve --> GR["HUMAN_APPROVED → grant"]
    I -- deny --> HD["HUMAN_DENIED"]
    I -- deadline passed --> TO["TIMED_OUT"]
    C -. "exception" .-> HUM
    E -. "exception" .-> HUM
    F -. "exception" .-> HUM
```

## Sequence: human approval

```mermaid
sequenceDiagram
    actor R as Requester
    participant B as Broker
    participant P as PolicyEngine
    participant DB as SQLite
    participant AS as approval-service
    actor A as Approver
    participant C as Sidecar

    R->>B: request_access
    B->>DB: INSERT request, audit REQUESTED
    B->>P: decide
    P-->>B: ROUTE_HUMAN
    B->>DB: audit TRIAGED, POLICY_DECIDED
    B->>DB: INSERT pending_approval, audit ROUTED_TO_HUMAN
    B-->>R: approval_url
    A->>AS: GET /approve/token
    AS-->>A: review page
    A->>AS: POST /approve/token/decide
    AS->>B: resolve_approval
    B->>DB: timeout sweep, self-approval check
    B->>DB: guarded UPDATE PENDING to APPROVED
    B->>C: issue
    C-->>B: token
    B->>DB: INSERT grant, audit HUMAN_APPROVED
```

## State machines

```mermaid
stateDiagram-v2
    state "Request" as Req {
        [*] --> PENDING_POLICY
        PENDING_POLICY --> DUPLICATE
        PENDING_POLICY --> DENIED
        PENDING_POLICY --> RETURNED
        PENDING_POLICY --> AUTO_APPROVED
        PENDING_POLICY --> PENDING_HUMAN
        RETURNED --> PENDING_HUMAN : escalate
        PENDING_HUMAN --> HUMAN_APPROVED
        PENDING_HUMAN --> HUMAN_DENIED
        PENDING_HUMAN --> TIMED_OUT
    }
    state "Grant" as Gr {
        [*] --> ACTIVE
        ACTIVE --> EXPIRED
        ACTIVE --> REVOKED
    }
```

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
11. Every external dependency sits behind an interface: Policy, TriageProvider, ResourceConnector, UserDirectory, TokenIntrospector, Clock.

## Known limitations

- The approver's name is free text: it's authorization of a claimed name, not authentication.
- The protected service doesn't check the token's resource.
- Request status is set before `connector.issue`. If issue fails, the request shows approved with no grant.
- The duplicate check isn't atomic across processes.
- `connector.revoke` failure after the status change is not retried.
