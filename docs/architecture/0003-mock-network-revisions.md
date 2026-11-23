# ADR 0003 — Mock network revisions and policy

**Status:** Accepted for Network Core

The FastAPI routes reuse Foundation authorization and error contracts. Domain models, the
read-only driver interface and deterministic policy evaluator are independent of FastAPI,
Workforce OS and agent orchestration. The mock driver accepts only typed change operations.
The domain enforces UUID references, subnet containment and link validation before policy
evaluation. Profile rules are local YAML deployed by an operator and loaded at process startup.

An attached subnet has a VLAN and belongs to that VLAN's zone. Allocation containers can
contain strictly nested, explicitly parented allocations. They have no gateway or VLAN and
are not accepted as firewall endpoints. The bundled profile uses this rule to carve the
Honeypot VLAN out of the DMZ allocation without overlapping attached trust zones.

The evaluator uses a deny-by-default directed rule model. An allow rule needs both CIDRs to
lie in attached subnets of the declared zones. It must match an allowlist entry and a modeled
shared gateway with firewall capability. Unknown topology, unknown platforms and unmodeled
routing prevent writes. Static routes are limited to known one-hop paths in the mock. These
findings describe the simulated configuration and provide no real dataplane evidence.

Each SQLite revision stores canonical serialized domain state and a SHA-256 checksum bound to
the network UUID and revision number. This detects corruption and misplaced snapshots.
Database files remain trusted local storage. Restore addresses a persisted revision by number,
verifies it, reevaluates the active policy and appends a new revision. The compare-and-swap
update takes the first write in the mutation transaction. Losing writers get a conflict
and can reread the current revision. State, snapshot and success audit commit together.

Deploy one application instance per SQLite volume. Policy changes take effect on restart.
Editing the configured topology requires a different network UUID. Existing state is kept
available for reading, and matching UUIDs with different topology are rejected for writes.
