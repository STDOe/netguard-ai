# ADR 0002 — Local access and health probes

**Status:** Accepted for Foundation

The operator provisions distinct, random Bearer tokens for the Viewer and Administrator roles via environment variables. Startup rejects missing, malformed or duplicate credentials. Viewer can read capabilities and OpenAPI. Administrator can also read denial events. Rotation requires changing the configured values and restarting the service. These are installation-level role credentials for a single local instance. Individual accounts, workspaces and service identities are later stages.

Liveness and readiness are public for deployment probes and disclose only the status or a generic error with a correlation ID. The API schema requires authentication. Denials are stored with an outcome and known role, when available. If storage is unavailable, the request still fails authorization and the correlated request log marks the audit write failure.

Foundation uses a loopback host binding by default and expects TLS for remote transport. Credentials belong in shell environment or an ignored local `.env` for Compose. Shared tokens make revocation and attribution role-level. The local demo boundary is enforced by accepting only `NETGUARD_DEMO_MODE=true`. Real-device connectivity and network changes are outside this stage.
