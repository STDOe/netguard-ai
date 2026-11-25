# NetGuard AI v0.1.0 quickstart

Use a fresh checkout, Docker Engine with Compose v2, and Python 3.12 for setup.
From the repository root, generate installation secrets and select a disposable
project name for a clean demonstration.

```bash
umask 077
cp .env.example .env
python3.12 - <<'PY'
from pathlib import Path
from secrets import token_urlsafe
path = Path(".env")
text = path.read_text()
for key in ("VIEWER_TOKEN", "ADMIN_TOKEN", "HONEYPOT_SECRET"):
    text = text.replace(f"NETGUARD_{key}=\n", f"NETGUARD_{key}={token_urlsafe(32)}\n")
path.write_text(text)
PY
docker compose up --build --wait
curl --fail http://127.0.0.1:8000/api/v1/health/ready
```

Open http://127.0.0.1:8000 and sign in with the Admin token from `.env`.
Open Network Topology. In Greenfield Designer, submit a design, then complete
the requested requirements. In AI Workspace, select **Infra spoke** and
**Cash / Payment** and keep **Dry-run only** selected. The plan should succeed
with the mock revision unchanged. Choose **Run audit** on Security Audit.
Review the unknown dataplane finding and the coverage shown with the score.
OpenCanary remains optional. See the
[Dashboard guide](dashboard-security.md) for the signed fixture.

To exercise integration from inside the application container, provision a
fresh client token and a short-lived server configuration.

```bash
umask 077
python3.12 - <<'PY'
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from secrets import token_urlsafe
import json

token = "ngw." + token_urlsafe(32)
with Path(".workforce-client.env").open("x") as client:
    client.write(f"NETGUARD_WORKFORCE_TOKEN={token}\n")
scopes = ["capabilities:read", "tasks:create", "tasks:read", "tasks:cancel",
          "events:read", "artifacts:read", "approvals:read"]
values = {
    "ENABLED": "true",
    "TOKEN_SHA256": sha256(token.encode()).hexdigest(),
    "EXPIRES_AT": (datetime.now(UTC) + timedelta(hours=4)).isoformat(),
    "SCOPES": json.dumps(["integration:" + scope for scope in scopes]),
}
path = Path(".env")
lines = [line for line in path.read_text().splitlines()
         if line.partition("=")[0] not in {f"NETGUARD_INTEGRATION_{key}" for key in values}]
lines.extend(f"NETGUARD_INTEGRATION_{key}={value}" for key, value in values.items())
path.write_text("\n".join(lines) + "\n")
PY
docker compose up --wait
set -a
. ./.workforce-client.env
set +a
docker compose exec -T -e NETGUARD_WORKFORCE_TOKEN netguard-app python - < deploy/workforce/client.py
unset NETGUARD_WORKFORCE_TOKEN
```

For the disabled scenario on the original standalone configuration, pass
`--disabled` to the sample client. Outside the container use
`python3.12 deploy/workforce/client.py --base https://your-netguard-origin`
with the client token in the environment. The demo device and destination
defaults match the bundled profile. Override them for a different profile.
