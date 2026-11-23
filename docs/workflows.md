# Standalone agent workflows

All routes are under `/api/v1` and require a local Bearer credential. Each installation
credential represents one principal. Viewer and Admin can create and inspect their own
Greenfield tasks and Brownfield dry-runs. Admin has the explicit approval permission and
can create Brownfield tasks that apply a change. Workflow task ownership uses the existing
installation principals. Multiple people using the same token share one identity.

| Endpoint | Purpose |
|---|---|
| `POST /tasks` | Starts Greenfield or Brownfield. Uses the same task for an identical request with the same principal and `idempotency_key`. Reusing the key for a different request returns HTTP 409. |
| `GET /tasks/{id}` | Shows progress, correlation and thread IDs, plan, approval, result and available artifacts. |
| `POST /tasks/{id}/input` | Patches the supplied interview fields while awaiting input. |
| `POST /tasks/{id}/cancel` | Cancels at an input or approval boundary before any approved execution. |
| `GET /tasks/{id}/plan` | Returns the immutable plan and deterministic diff. |
| `GET /approvals` | Returns up to 50 of the Admin principal's tasks awaiting approval. |
| `POST /tasks/{id}/plan/{plan_id}/decision` | Requires Admin, exact `plan_hash`, and `approve` or `reject`. |
| `GET /tasks/{id}/result` | Returns persisted execution and post-check evidence. |
| `GET /tasks/{id}/artifacts/{name}` | Returns a named artifact as a typed envelope containing media type and text. |
| `GET /tasks/{id}/events` | Returns the ordered task audit trail, including the corresponding HTTP request IDs. |

Use the authenticated `GET /api/v1/openapi.json` contract for exact payloads. Task and
execution outcomes are available in `status` and `code`. HTTP errors retain Foundation's
error shape. A failed or blocked workflow can still be a successfully created task.

## States

- `queued` and `running` are transient states.
- `awaiting_input` pauses the interview. Up to five input submissions can fill missing
  fields or resolve inconsistencies.
- `awaiting_approval` pauses a Brownfield plan. A matching decision resumes it. Repeated
  identical decisions return the same result. A different decision conflicts.
- `succeeded` means Greenfield artifacts were generated, a dry-run diff is ready, or a mock
  revision passed post-check. `failed` denotes a validation or tool failure.
- `blocked`, `rejected`, `expired`, and `cancelled` stop apply. `recovery_required` means
  that a committed revision or its checksum could not be verified. The operator can
  inspect the linked events and revision history.

Tasks run synchronously to an interrupt or terminal state. Approval expiration is evaluated
on access. After an interrupted process, the next authorized request for a task reconciles its
checkpoint and any decision that was already recorded. There is one writer per data directory.
Contending clients can retry HTTP 409 with code `workflow_busy`. A cancellation is accepted
at a waiting boundary. An apply already committed retains its revision and audit record.

## Greenfield

Start with `{"kind":"greenfield","idempotency_key":"design-001","requirements":{}}` and use
the `missing` list to complete the interview. The following is a complete requirements
object for a two-site example.

```json
{
  "organization": "retail",
  "sites": 2,
  "users_per_site": 40,
  "devices_per_site": 20,
  "registers_per_site": 4,
  "throughput_mbps": 250,
  "packets_per_second": 80000,
  "budget_minor": 150000000,
  "currency": "RUB",
  "vendors": [],
  "region": "RU",
  "availability": "redundant",
  "security": ["segmentation", "payment_isolation"],
  "services": ["dns", "dhcp", "point_of_sale"],
  "address_pool": "10.50.0.0/16"
}
```

Use an explicit private IPv4 or IPv6 ULA pool. Device counts include registers, and zero
registers declares that payment segregation is inapplicable. An empty vendor list explicitly
leaves vendor choice open. Sizing allocates each site segment for its declared users and
devices and assumes simultaneous site peaks at the hub. The output describes a logical
design. Validate procurement, physical capacity, compatibility and failover separately.

Exports include BOM in JSON, CSV and Markdown, a Mermaid topology, validated `inventory.yaml`,
and a Markdown assumptions file. Available Containerlab images are unverified, so this
stage omits Containerlab output.

Hardware sourcing is offline. An optional operator-provided JSON catalog at
`NETGUARD_HARDWARE_CATALOG_PATH` supplies public datasheet references with
`vendor`, `sku`, `source_url`, `retrieved_on`, and optional `throughput_mbps` and
`packets_per_second`. Vendor and minimum requirements filter candidates. The adapter
records provenance and preserves missing characteristics. Live search reports
`unavailable` and the BOM marks candidates `unverified`. Price and availability
remain unknown. URLs are validated as public HTTPS references without credentials,
query or fragment. The adapter performs zero DNS lookups and zero document fetches,
so it follows no redirects.

## Brownfield

Read network and device UUIDs from the Network Core API. Submit `kind: "brownfield"`,
an `idempotency_key`, the `network_id` and a typed `goal`. For example, a
`find_static_route` goal takes `device_id` and `destination`. The planner searches
only adjacent peers in the existing mock snapshot. It also accepts the typed
`put_static_route`, `put_firewall_rule`, and `set_routing_protocols` intents already
documented in Network Core.

Set `dry_run: true` to obtain a validated diff and leave the network unchanged.
Otherwise, Admin receives a plan awaiting approval. Pass its UUID and hash back to
the decision endpoint. A rejection, TTL expiry, policy mismatch or changed revision
blocks the write. A successful approval applies once to the virtual network and
records a post-check against the persisted revision. Direct operator changes through
the existing Network Core API can make pending plans stale.

## Optional LiteLLM configuration

The default planner works offline with an explicit typed goal or one unambiguous route
candidate. For online planning, set `NETGUARD_LLM_MODEL` and `NETGUARD_LLM_API_BASE`
together. An OpenAI-compatible setup uses `openai/<model>` and a base such as
`https://provider.example/v1`. Store `NETGUARD_LLM_API_KEY` in the runtime environment.
Ollama uses `ollama/<model>` or `ollama_chat/<model>` and a trusted Ollama base such
as `http://127.0.0.1:11434` for a locally installed server. Other providers must
accept a manually configured LiteLLM model, endpoint and JSON text response.

The provider receives only bounded typed candidates. Discovery names, inventory text,
credentials and policy documents stay out of prompts. A single request has an
eight-second timeout, a 500-token output cap and zero retries. The runtime parses a JSON
intent, requires exact membership of the allowed candidates, and runs deterministic
policy and diff validation. Unsupported responses, unavailable providers and rate
limits get fixed error codes. There is no provider fallback.
