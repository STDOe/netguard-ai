# NetGuard Integration Contract v1

`external_compatibility: unverified`. This is NetGuard's contract for external
clients. The sample client implements it independently of AI Workforce OS.

OpenAPI 3.1 is available at authenticated `GET /api/v1/integration/openapi.json`
with `integration:capabilities:read`. The repository includes the
[OpenAPI contract](contracts/integration-v1.openapi.json) and
[JSON Schema 2020-12 message catalog](contracts/integration-v1.schema.json).
Select a message in the catalog with a reference such as `#/$defs/Submission`.
Run `PYTHONPATH=. uv run --locked python ../deploy/workforce/export_contract.py`
from `backend` with local role credentials loaded.

| Method and route under `/api/v1/integration` | Required scope after `integration:` |
|---|---|
| GET `/capabilities`, `/openapi.json` | `capabilities:read` |
| POST `/tasks`, `/tasks/{id}/input` | `tasks:create` |
| GET `/tasks/{id}` | `tasks:read` |
| POST `/tasks/{id}/cancel` | `tasks:cancel` |
| GET `/tasks/{id}/events` | `events:read` |
| GET `/artifacts/{id}` | `artifacts:read` |
| GET `/approvals/{id}` | `approvals:read` |
| POST `/approvals/{id}/decision` | With `approvals:read`, returns 403 `not_supported` |

The API uses a dedicated Bearer token and returns 404 `integration_disabled`
when disabled. The disabled check and the per-process request limit run before
body intake, including for malformed JSON. Missing, expired and rotated credentials receive 401. A
missing scope or a request for a different workspace receives 403. Unknown
and foreign resource UUIDs receive 404. Read and control operations on
individual resources take the `workspace_id` query parameter.

Submit `schema_version: "1.0"`, `workspace_id` and a typed `task`. Task kinds are
`greenfield`, `brownfield` and `audit`. Unknown kinds and fields get 422
`invalid_request`. Brownfield and audit accept only the active demo network ID
reported by capabilities. Greenfield accepts the same typed requirements as the
standalone workflow and can pause for input. Audit creation persists the report,
completion and event atomically. Successful creation returns 201 with task
and correlation IDs. Matching caller, key, workspace and payload return the
same Task ID. Reusing the key with a different payload or workspace returns
409. Retry ambiguous transport errors or transient 503/409 `workflow_busy`
with the original key and payload.

Create, input and cancel return a `TaskReceipt` when the caller lacks
`integration:tasks:read`. Its only fields are `schema_version`, `request_id`,
`task_id` and `correlation_id`. This also applies to idempotent replays.
With task read permission these operations return the usual `TaskResponse`.
Artifact links and approval IDs additionally require their own read scopes.

An interrupted audit remains queued with code `audit_profile_unavailable`
while its original network profile is absent. The owner can poll the same ID
or retry the original submission. When the profile returns, either operation
can finish that audit once.

A non-dry-run Brownfield task pauses for local Admin approval. The approval
resource uses the task UUID as its stable ID and publishes the distinct plan
UUID and exact hash. The response also includes the network scope, risk, plan
TTL, policy version and decision status. The local Dashboard presents the exact
diff and records a human decision through the existing guarded endpoint. Mock
commit requires that decision and rechecks role, expiry, policy, snapshot and
diff. A recorded valid decision can resume after restart.

Clients poll events with `limit` (1–100) and the last returned `next_cursor`.
The cursor is bound to the task. Each event carries a stable ID, per-task
sequence, schema version, correlation ID, request ID and timestamp. An empty
page returns the cursor for the next poll. Persist the cursor after handling
events and deduplicate by event ID. No reasoning traces are returned.

Artifacts are allowlisted Greenfield exports. Each UUID refers to one task and
export name. The payload is UTF-8 text in JSON with MIME type, SHA-256 over
the UTF-8 bytes, size and provenance. The UUID is UUIDv5 with the task UUID
as namespace and the exact export name as input. Completion indexes exports
regardless of caller scopes. A client with artifact read permission can fetch
a known UUID directly after token rotation or restore. Unavailable and foreign
artifacts both return 404 `artifact_not_found`. Validate the hash before downstream use.
The checkpoint stores content, and SQLite stores the ownership index. The
Brownfield service projection exposes plan metadata and execution evidence.
The local Dashboard holds the full diff.

Use the [quickstart](quickstart-v0.1.md) and
[security and recovery guide](deployment-security.md).
