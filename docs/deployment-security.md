# Deployment security and recovery

NetGuard v0.1.0 is a single-instance mock application. The Compose configuration
binds the host port to loopback, drops capabilities and runs the app as a
non-root user. Keep the SQLite volume, profile, optional catalog and local
configuration private. The optional OpenCanary service has a separate
HMAC secret and an internal network.

## Workforce identity

Integration defaults to disabled. Configure a stable caller and workspace,
an independent high-entropy `ngw.` token digest, an expiry within 30 days,
and the minimum JSON array of scopes. Use the quickstart generator to produce
256 random bits. Keep the token only in the client secret store. The app stores
the SHA-256 digest in deployment configuration. Rotate by replacing the digest
and expiry and recreating the application. Revoke by clearing the credential
and disabling integration, or by replacing the digest. Preserve caller and
workspace when rotating to keep access to their existing tasks.

The application accepts credentials over HTTPS or direct socket loopback.
For remote operation, terminate TLS at a trusted reverse proxy and configure
Uvicorn to trust only that proxy's address. Have the proxy overwrite forwarded
headers and keep the upstream private. Force Secure Dashboard cookies via
`NETGUARD_WEB_SECURE_COOKIES=true`. Use target-specific proxy timeouts and
request/concurrency limits. NetGuard limits integration requests to 120 per
minute per application process, and bounds POST bodies to 16 KiB and five
seconds of intake. Workflow and SQLite lock waits remain bounded. The global
process limit also means that excess failed attempts can temporarily consume
the integration budget. Preserve the supported single-process application model.

Authentication outcomes and workspace denials are recorded with request IDs.
Keep proxy logs free of authorization headers and request bodies. Correlate API
errors and task events with the request ID. Keep local Admin access restricted
to human operators. Possession of a shared local Admin token is the MVP human
identity boundary.

## Consistent backup and disposable restore

Use an approved encrypted backup destination. Stop the app and optional sensor
before reading volume files. Keep the app database and the LangGraph checkpoint
together with the exact release, profile/catalog and a separately protected copy
of deployment configuration and the required credentials. Coordination lock
files are recreated when needed.

```bash
umask 077
backup_dir=$(mktemp -d)
mkdir "$backup_dir/data"
docker compose stop
docker compose cp netguard-app:/var/lib/netguard/. "$backup_dir/data/"
tar -C "$backup_dir/data" -cf "$backup_dir/netguard-data.tar" .
docker compose up --wait
```

For a separate restore, use a fresh Compose project name and an unused host port.
The example uses the same Compose file and restored settings loaded via `.env`.

```bash
export NETGUARD_PORT=18001
docker compose -p netguard-restore run --rm --no-deps -T --entrypoint sh netguard-app \
  -ec 'tar --no-same-owner -xf - -C /var/lib/netguard' < "$backup_dir/netguard-data.tar"
docker compose -p netguard-restore up --wait
curl --fail "http://127.0.0.1:$NETGUARD_PORT/api/v1/health/ready"
```

Verify task IDs, approval, event IDs, artifact hash, current snapshot revision
and audit report ID against the backup's source. Use the original workspace and
caller when checking integration data. Restore only validated backups from
sources you control. Record the result before retiring the restore environment.
