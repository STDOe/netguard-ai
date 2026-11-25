# NetGuard AI

NetGuard AI is a network design and security application with a standalone backend and an optional Workforce Integration Contract. The stable v0.1.0 release provides a persistent mock network. The v0.1.1 installer runs NetGuard locally through Docker. The backend reports `demo_mode: true`. Workflows run offline by default and operate on mock networks.


## Install with Docker

From the source checkout, run the installer for your system:

- **Windows (Docker Desktop with Linux containers)** — `.\netguard.ps1 install`
- **Linux (Docker Engine and Compose v2)** — `./netguard.sh install`

Open the loopback Dashboard URL printed on success and sign in using the
Admin token from your private `.env`. The installer generates distinct local
credentials, starts Docker Compose and waits for API readiness.
[Installer quickstart, commands and troubleshooting](docs/easy-install.md)

[Clean install](docs/quickstart-v0.1.md) · [Integration Contract v1](docs/integration-v1.md) · [Deployment security and recovery](docs/deployment-security.md) · [Release notes and acceptance](docs/release-v0.1.0.md)

## Development team and next phases

NetGuard AI is led and maintained by **STDOe**. The project has been built with AI development assistance from **OpenAI Codex** (implementation and tests) and **OpenAI ChatGPT** (architecture discussions, independent review and planning). These are acknowledgments of AI tools, **not GitHub collaborator accounts or claims of OpenAI endorsement**. See [Contributors and acknowledgments](docs/CONTRIBUTORS.md).

**Next step: build a safe, isolated laboratory network before connecting NetGuard to real devices.** The [Development roadmap](docs/ROADMAP.md) outlines this prerequisite, proposed **v0.2 read-only discovery/audit**, **v0.3 controlled lab changes**, and a conditional **v1.0 production candidate**. No real-device compatibility or delivery dates are promised.


## Local development

Native execution requires Linux or another POSIX system with local filesystem support for `fcntl.flock`. On Windows use Docker Desktop with Linux containers or WSL 2.

Use Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/). The lockfile supplies reproducible Python dependencies.

From the repository root, generate two distinct local credentials for the current shell:

```bash
export NETGUARD_VIEWER_TOKEN="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export NETGUARD_ADMIN_TOKEN="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Then install, migrate, and start:

```bash
cd backend
uv sync --locked
uv run --locked alembic upgrade head
uv run --locked uvicorn app.main:create_app --factory --no-access-log --timeout-graceful-shutdown 10
```

By default, the service binds to `127.0.0.1:8000`. Stop it with Ctrl+C. SQLite is stored at `backend/data/netguard.sqlite3`. To choose a different file, set `NETGUARD_DATABASE_PATH` before running both Alembic and Uvicorn. `NETGUARD_DEMO_MODE` defaults to `true`, which is the sole supported setting.

## Docker Compose

Run these commands from the repository root with the two token variables exported as above. Compose can also read a local `.env` created using `.env.example` and filled with independently generated tokens. Keep `.env` out of Git. Start one instance per SQLite volume.

```bash
docker compose up --build --wait
docker compose down
```

The container runs Alembic before starting Uvicorn. It stores SQLite in a named volume that survives `down`. Set `NETGUARD_PORT` to change the published loopback port (default `8000`). Send Bearer credentials over TLS when crossing a host boundary.

For builds behind a TLS inspection proxy, pass the trusted host CA bundle to BuildKit as the
`netguard_ca` build secret. For example, add it to `services.netguard-app.build.secrets` in a
local Compose override and declare its file under the top-level `secrets.netguard_ca.file`.
The CA is used during dependency installation and stays out of the image.

## API

| Route | Access |
|---|---|
| `GET /api/v1/health/live` | Public. Reports process liveness. |
| `GET /api/v1/health/ready` | Public. Reports readiness after both SQLite tables and the expected migration revision are available. |
| `GET /api/v1/capabilities` | Viewer or admin. Reports the API version, stage and demo mode. |
| `GET /api/v1/audit/events?limit=25` | Admin. Returns recent access denials. Add `include_network=true` to include network audit events. Limits are 1–100. |
| `GET /api/v1/openapi.json` | Viewer or admin. Returns the OpenAPI contract. |

```bash
curl -fsS http://127.0.0.1:8000/api/v1/health/ready
curl -fsS -H "Authorization: Bearer ${NETGUARD_VIEWER_TOKEN}" \
  http://127.0.0.1:8000/api/v1/capabilities
```

The server assigns an `X-Request-ID` to every response and logs request completion as JSON. Errors share the shape `{"error":{"code":"…","message":"…","request_id":"…"}}`. An absent or invalid credential yields 401. An authenticated role without permission yields 403. An unavailable database or pending migration yields 503 from readiness.

## Network Core demo

At startup, the backend seeds `retail-payment-hub-spoke` from the
[bundled YAML profile](backend/config/profiles/retail-payment-hub-spoke.yaml) if the migrated
database has no network with its UUID. The profile defines the devices, zones, VLANs, subnets,
and versioned policy. Its `10.30.0.0/16` block is an allocation container with distinct DMZ and
Honeypot child subnets. The Cash and Infra segments use their own allocations.

Set `NETGUARD_PROFILE_PATH` before starting local Uvicorn to load another YAML file. For Compose,
mount the replacement read-only at `/srv/netguard/config/profiles/retail-payment-hub-spoke.yaml`
in a local override. Restart to load changes and bump the policy version when editing policy.
Use a new network UUID for a different topology. The service preserves existing networks and
snapshots. A missing policy or a mismatch between the stored topology and the active profile
blocks changes while preserving read access. If you migrate a database while the app is running,
restart the app to run profile initialization.

The following routes start with `/api/v1/networks`. Viewer and Admin can read. Only Admin can
change or restore.

| Method and suffix | Behavior |
|---|---|
| `GET /api/v1/networks` | Lists network IDs, names and current revisions. |
| `GET /{network_id}/topology` | Returns the current network and snapshot checksum. |
| `GET /{network_id}/devices/{device_id}` | Returns device facts, interfaces, routes and capabilities. |
| `GET /{network_id}/policy` | Evaluates the current revision, reporting rule IDs, decisions, severity, reasons, evidence and policy version. |
| `GET /{network_id}/revisions` | Lists revision metadata newest first. Supports `limit` (1–100) and `before_revision`. |
| `GET /{network_id}/snapshots/{revision}` | Returns a verified full snapshot. |
| `POST /{network_id}/changes` | Requires the current `expected_revision` and a typed `change` with kind `put_static_route`, `put_firewall_rule` or `set_routing_protocols`. |
| `POST /{network_id}/restore` | Requires the current `expected_revision` and a stored `snapshot_revision`. Checks the active policy and creates a new revision. |

Fetch the UUID and revision before proposing a change:

```bash
curl -fsS -H "Authorization: Bearer ${NETGUARD_VIEWER_TOKEN}" \
  http://127.0.0.1:8000/api/v1/networks
```

Each successful change creates a snapshot and audit event in the same SQLite transaction.
Stale revisions and corrupt snapshots return HTTP 409. Policy denials and unknown decisions
return HTTP 403 with typed `findings`; malformed requests and invalid topology changes return
HTTP 422. See the authenticated OpenAPI schema for payloads.

The policy defaults to deny. It checks directions, CIDR containment, protocol permissions and
device capabilities. The bundled allowlist permits only Cash-to-Infra DNS to its configured
address and port. An allowed firewall intent must use a shared, known firewall gateway.
Static routes require a modeled, directly connected next hop and a destination attached to that
peer. The model covers these simulated paths and assumes no NAT. Multi-hop reachability,
dynamic routing and real device dataplanes are outside the model. Findings with insufficient
information are `unknown` and block writes.

## Agent Workflows

Greenfield collects requirements and exports a validated logical design and BOM. Brownfield
builds a deterministic diff and supports dry-run or a hash-bound Admin approval before
a mock apply. LangGraph checkpoints allow both workflows to resume after restart.

See [workflow API, states, offline sourcing and LiteLLM configuration](docs/workflows.md)
and the [checkpoint and approval ADR](docs/architecture/0004-agent-checkpoints-and-approvals.md).
The SQLite application database and its adjacent checkpoint database share the Compose
volume. Keep both when migrating or backing up a deployment.

## Standalone web console

After local startup or `docker compose up --build --wait`, open
`http://127.0.0.1:8000/` and sign in with your Viewer or Admin installation token.
The console connects to the same mock network, workflows and role checks as the REST API.
See [dashboard access, audit scoring and the optional OpenCanary demo](docs/dashboard-security.md).

## Verification

Run from `backend/` after `uv sync --locked`:

```bash
uv run --locked ruff check app migrations ../tests
uv run --locked ruff format --check app migrations ../tests
uv run --locked mypy
uv run --locked pytest
```

The test suite covers the Foundation contracts, migration from the Foundation schema, policy
isolation, authorization, concurrent edits, atomic rollback, and corrupt snapshot rejection.
The pull request workflow runs lint, type checks, tests, Gitleaks, and a Compose smoke test
that checks readiness, the seeded demo network and an interview checkpoint after restart.

See [Foundation ADRs](docs/architecture/) and the [master specification](docs/NetGuard_AI_TZ_v2.0.md).
