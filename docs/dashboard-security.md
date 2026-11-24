# Standalone dashboard, audit and honeypot

## Dashboard

Open `http://127.0.0.1:8000/` and sign in with the installation Viewer or Admin
token. The same role permissions and task ownership apply in the dashboard and REST API.
Viewer can read the virtual network, security reports and sensor events, run Greenfield
and preview a Brownfield change. Admin can run audits, see system activity and approve
or reject its own pending changes. Each plan decision submits the immutable plan hash to
the existing workflow endpoint.

- **Overview and Network Topology** show the active mock revision, devices, zones,
  links and subnet/VLAN membership. Use the device selector for keyboard inspection.
  Physical reachability is unknown. A marker indicates a recent observation matched to
  an exact destination interface on the displayed revision.
- **AI Workspace** supports structured Brownfield requests, including typed goals.
  **Greenfield Designer** shows required fields, BOM, inventory and the generated
  Mermaid source. The diagram preview accepts only the Greenfield flowchart subset.
  Artifact text is rendered literally.
- **Change Plans & Approvals** shows pending plans, exact hash, expiry, diff, decision
  and execution evidence. **Activity / History** lists up to 100 of the current role's
  tasks and, for Admin, recent system audit events.
- **Security Audit** displays immutable reports and distinguishes current from historical
  reports. **Honeypot Events** lists the 50 most recent accepted observations.

The browser exchanges a role token for an opaque eight-hour SQLite-backed session.
Cookie authentication uses HttpOnly and SameSite=Strict. HTTPS sets Secure automatically
when the server sees the HTTPS scheme. For a trusted TLS reverse proxy, configure
trusted forwarded headers and set `NETGUARD_WEB_SECURE_COOKIES=true`. The login Origin
must match the application origin and the proxy must preserve the external Host.
Cookie-authenticated writes, including logout, require the session-bound CSRF header.
Logout deletes the session. Rotating a role token invalidates existing sessions for it.
Bearer clients can continue using the API directly. Use TLS for remote browser access.

Jinja2 escapes template values and client renderers use text nodes for API content.
CSP permits scripts and styles from the application only and disables frames and plugins.
Assets are local. The vendored directory records versions and licenses. A Node build step
is unnecessary. No real device access or free-form model chat is available.

## Security audit API and score

Use Bearer auth or a dashboard session.

| Method and path | Purpose |
|---|---|
| `POST /api/v1/networks/{network_id}/audits` | Admin captures and saves a report for the active revision |
| `GET /api/v1/networks/{network_id}/audits` | Returns the ten most recent saved reports |
| `GET /api/v1/networks/{network_id}/audits/{report_id}` | Returns the original report with its current/historical flag |

The audit validates snapshot integrity and interprets the existing Policy Engine over
the stored virtual configuration. It checks segmentation, directed DMZ → Cash isolation,
honeypot egress isolation, default deny, firewall rules, routing, device capabilities and
the active policy version. For the named zone checks, a profile without corresponding
zone names yields `not_applicable`. A persisted allow across one of these isolation
directions is a finding. The remaining catalog applies to any stored mock profile.
Report evidence includes relevant policy check IDs, rule or object IDs, or the snapshot
checksum. Reads do not generate reports. The current flag compares the active snapshot
and the complete active profile fingerprint with the saved ones.

**Score 1.0** uses severity weights of 10 for critical, 5 for high, 3 for medium and 1
for low. Let A be the sum of applicable weights, K the sum for pass and fail, and P
the sum for pass.

- Coverage is `floor(100 × K / A)`, or 0 when A is zero.
- Score is `floor(100 × P / A)` at coverage of 70% or higher. Below 70% it is unavailable.
- Unknown is included in A and earns zero credit. Not applicable contributes no weight.
- One critical pass and one medium unknown give 76% coverage and a score of 76.

NAT, asymmetric routing and physical dataplane behavior remain unknown. The score
describes simulated configuration evidence. It provides no PCI DSS attestation.

## Signed OpenCanary observations

Configure a separate random secret in the application environment, then recreate the
app if the configuration changed.

```bash
export NETGUARD_HONEYPOT_SECRET="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build --wait
python3.12 deploy/opencanary/forward.py --fixture
```

The fixture script creates a fresh UTC timestamp and UUID, signs the JSON and sends it
to the local webhook. Use `--port` for a custom host port. The event is marked as a demo
fixture. Open **Honeypot Events** to inspect it.

For the optional live lab sensor, start the `honeypot` Compose profile:

```bash
docker compose --profile honeypot up --build --wait
docker compose exec -T opencanary python -c 'from urllib.request import urlopen; print(urlopen("http://127.0.0.1:8080/", timeout=5).status)'
```

The pinned OpenCanary image runs on Linux AMD64 in an internal network with no published
sensor ports, as a non-root user with all capabilities dropped. The forwarder parses a
bounded OpenCanary JSON line and sends only the fields below. Raw logdata, URLs, headers
and attempted login fields are discarded. This profile is for isolated local demonstrations.

`POST /api/v1/webhooks/honeypot` accepts JSON with the following fields.

| Field | Value |
|---|---|
| `event_id` | Unique UUID retained across redelivery |
| `occurred_at` | ISO 8601 timestamp with timezone |
| `source_ip`, `destination_ip` | Normalized IPv4 or IPv6 |
| `destination_port` | Integer in 1–65535 |
| `service` | `http`, `ssh` or `ftp` |
| `sensor` | 1–40 ASCII letters, digits, hyphens or underscores |
| `demo` | JSON boolean |

Set `X-NetGuard-Timestamp` to UNIX seconds and `X-NetGuard-Signature` to
`sha256=<lowercase hex HMAC-SHA256>`. Sign the decimal timestamp, a dot and the
exact raw body. Signature and event timestamps must fall within five minutes of
server time. Bodies are limited to 4096 bytes and five seconds to read. At most
30 new authenticated events are stored per rolling minute per installation.
Exact replays return the original event. Conflicting reuse of a UUID returns
409 and rate-limited requests return 429. Authenticated users read events at
`GET /api/v1/honeypot/events`.

Correlation requires the exact destination IP of one interface in a honeypot
zone. Other events remain unverified. Even a matched observation is not a finding
of compromise. Event ingestion writes only event and audit records.

## Persistence

Alembic revision `0005_dashboard_security` adds session, audit report, findings and
honeypot tables. The app database and workflow checkpoints remain on the same named
Compose volume. Recreating the container with the same volume retains reports, accepted
events and workflows. Back up both SQLite files as a pair.

## Browser smoke test

Use a fresh disposable demo database. The smoke test creates tasks, applies one
approved mock route, and verifies desktop and 320 px layouts. Load an offline
fixture before running it. Install Playwright outside the repository and point it
at an available Chromium binary.

```bash
browser_tools="$(mktemp -d)"
npm install --prefix "$browser_tools" --ignore-scripts playwright-core@1.61.0
NODE_PATH="$browser_tools/node_modules" NETGUARD_CHROMIUM="$(command -v chromium)" \
  node tests/browser_dashboard.cjs
```

The test uses the configured `NETGUARD_ADMIN_TOKEN` and `NETGUARD_PORT`. Set
`NETGUARD_SCREENSHOTS` to a directory to capture both viewports.

### Audit integrity and task retries

The audit screen obtains registered UUIDs from the authenticated
`GET /api/v1/audit/networks` endpoint. A missing or damaged current snapshot has
`snapshot_integrity: failed` and no trusted display name. Its UUID still opens
historical reports and accepts an Admin integrity audit.

Score 1.0 keeps its existing weights. Unspecified forwarding or unsupported dynamic
routing makes routing, firewall reachability, DMZ-to-Cash isolation and honeypot
isolation unknown unless there is direct evidence of a violation. Static checks
retain their independent findings. On the standard profile either uncertainty alone
reduces coverage to 47%, below the numeric score threshold.

Migration 0006 stores the full profile fingerprint and the ordered findings checksum.
Both POST and GET verify the saved report against the current snapshot and profile.
Reports created before 0006 remain historical. Reads verify the required findings,
their scope and severity, and recompute Score 1.0. A damaged report has
`evidence_status: corrupt`, no score and no verified findings. Reading it preserves
both its stored evidence and other reports.

After an interrupted task creation, resubmit the same Greenfield or Brownfield
request. The tab retains its retry key and a session-bound request digest. Confirmed
creation or a changed request gets a fresh key. The browser stores no form content
or credentials in session storage.
