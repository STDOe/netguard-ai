# NetGuard AI

NetGuard AI is a network design and security application with a standalone backend and a future AI Workforce OS integration. The current stage is **Foundation (v0.1)**. The backend reports `demo_mode: true` and has no network device or LLM connectivity.

## Local development

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
| `GET /api/v1/audit/events?limit=25` | Admin. Returns recent authentication and permission denials, with a limit of 1–100. |
| `GET /api/v1/openapi.json` | Viewer or admin. Returns the OpenAPI contract. |

```bash
curl -fsS http://127.0.0.1:8000/api/v1/health/ready
curl -fsS -H "Authorization: Bearer ${NETGUARD_VIEWER_TOKEN}" \
  http://127.0.0.1:8000/api/v1/capabilities
```

The server assigns an `X-Request-ID` to every response and logs request completion as JSON. Errors share the shape `{"error":{"code":"…","message":"…","request_id":"…"}}`. An absent or invalid credential yields 401. An authenticated role without permission yields 403. An unavailable database or pending migration yields 503 from readiness.

## Foundation acceptance

Run from `backend/` after `uv sync --locked`:

```bash
uv run --locked ruff check app migrations ../tests
uv run --locked ruff format --check app migrations ../tests
uv run --locked mypy
uv run --locked pytest
```

The test suite covers role checks, health before and after migration, response contracts, migrations, and SQLite persistence. Foundation acceptance also requires local and Compose startup with HTTP readiness, a clean Git history secret scan, and the Foundation workflow on a pull request. The workflow runs lint, type checks, tests, Gitleaks and a Compose startup check.

See [Foundation ADRs](docs/architecture/) and the [master specification](docs/NetGuard_AI_TZ_v2.0.md).
