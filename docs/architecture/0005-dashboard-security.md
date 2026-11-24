# ADR 0005 — Standalone dashboard and security evidence

**Status:** Accepted for Dashboard, Security Audit and Honeypot Demo

FastAPI serves Jinja2 views and local static assets. HTMX refreshes a same-origin
read-only activity fragment. Vanilla JavaScript calls the existing versioned APIs.
Cytoscape reads Network Core snapshots. The browser exchanges an existing role
credential for an opaque session whose hashed identifier and expiry live in SQLite.
The session refers to the same role and permissions as Bearer authorization. Its
binding to the current role credential allows operator rotation. Cookie-authenticated
writes require a session-bound CSRF token, including approval decisions. Untrusted
artifact text is displayed as text. Only the small flowchart grammar produced by
Greenfield gets a diagram preview.

A security audit reads a specific immutable mock revision, verifies its checksum and
evaluates the active Policy Engine. Findings and score are stored together with the
revision, policy provenance and an audit entry. Reading a report checks its freshness
against the current snapshot and policy. The original report stays unchanged.

The optional OpenCanary adapter normalizes selected observations and signs requests
with an installation-secret HMAC. SQLite serializes checks for replay, rate and
insertion. The app stores the normalized payload and records accepted events in the
existing audit log. Exact inventory matching is limited to an identified destination
interface in the virtual decoy zone. The event pipeline has no dependency on the
network mutation API. See [the dashboard and security API documentation](../dashboard-security.md).
