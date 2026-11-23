# ADR 0004 — Durable workflows and mock execution

**Status:** Accepted for Agent Workflows

LangGraph owns the Greenfield and Brownfield state transitions, including input and
approval interrupts. A supported SQLite `SqliteSaver` stores checkpoints in
`<database>.checkpoints` alongside the application database. The checkpoint contains only
typed JSON-compatible graph data, uses restricted deserialization, and carries the thread ID
and schema version. Alembic owns the application schema. Foundation's `tasks` remains the
task directory. Linked metadata carries ownership and the pending input or decision.
The audit timeline and approvals are application data. LangGraph manages its own checkpoint
tables. Back up both SQLite databases together. Deploy on a local filesystem with
advisory locking support.

Each invocation checkpoints synchronously. The runtime records an input, cancellation or
approval signal before delivering it to the graph. It clears the signal only after a
checkpoint acknowledges its ID, then projects the current graph status to `tasks`.
Deterministic audit IDs deduplicate repeated steps on recovery. The per-database advisory
lock serializes graph invocations across processes with a bounded acquisition time.
There is a 20-step graph recursion limit and a 20-second planning budget checked at
step boundaries. Post-check can finish after the planning budget if execution committed.

An approval is unique per task. Only the Admin principal has the explicit permission to
approve, and only the task owner may submit a decision. Viewer can perform private
dry-runs. The exact hash, decision time, expiry, actor and referenced audit event are
persisted together. The approval clock starts when the plan is made and defaults to
300 seconds, configured by `NETGUARD_WORKFLOW_APPROVAL_TTL_SECONDS`.

The plan hash is SHA-256 of the validated plan body without `plan_hash`, encoded as
UTF-8 JSON with sorted object keys, compact separators, unescaped Unicode, and no NaN.
Pydantic JSON mode serializes UUIDs and UTC timestamps. Array order is preserved. The
plan includes the task and network UUIDs, base revision and snapshot checksum, version
and canonical hash of the active policy, typed intent, diff, risk, and validity times.
The resulting full mock configuration is hashed by the same canonical rules.

Before a new write, execution rechecks permission, the approval, hash, expiry, policy
fingerprint, current revision and rendered diff. The SQLite compare-and-swap transaction
checks expiry after acquiring the write lock. It commits the revision, its unique plan
hash receipt, and an audit event together. After a process failure between that commit
and the next checkpoint, execution reads the existing receipt and proceeds to
post-check. It never resubmits the mutation. Post-check verifies the persisted revision
and expected configuration checksum. It marks an unverifiable receipt as requiring
recovery. These checks operate exclusively on mock state.

The offline hardware adapter reads a bounded local catalog and performs zero network
requests. Optional LiteLLM sees only a restricted set of typed candidates and has no
tools. Final selection membership, policy validation, diff and execution remain
deterministic. Live search, Containerlab image verification and Workforce integration
are later stages.
