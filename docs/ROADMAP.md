# NetGuard AI — development roadmap

**Status:** planning document, updated 2026-11-25. Versions and milestones below are **proposals**, not released capabilities or delivery commitments.

## Completed: v0.1.0 — Mock-only MVP

- Standalone FastAPI backend and Dashboard.
- Stateful mock network inventory, deterministic policy checks and network revisions.
- Greenfield design artifacts and Brownfield typed plans, diffs, expiry/hash-bound human approval and simulated application.
- Static security audit with evidence, coverage and `pass/fail/unknown/not_applicable`.
- Optional signed OpenCanary event ingestion.
- Optional scoped Workforce Integration Contract v1, local persistence and tested installation/recovery scenarios.

**Limits:** no connections to or writes on physical equipment; no verification of real dataplane or production HA; compatibility with an actual deployed AI Workforce OS remains unverified. A Git tag is not the same thing as a published GitHub Release.

## Stage 0 — Build an isolated laboratory network (NEXT)

**Why first:** NetGuard needs a known, controlled reference network before validating any real-device collector or discovery logic.

Proposed work:
1. Agree on a **lab topology and budget**: a management segment, a small infrastructure segment, a test user/DMZ segment and an isolated payment-like test segment; never use production payment data.
2. Choose a feasible substrate: initially **virtual network appliances and Linux network namespaces/VMs** (e.g., with Containerlab where compatible), followed by optional inexpensive physical devices. No real-device vendor support is claimed yet.
3. Keep lab access separated from the home/office/production LAN; document addressing, routing, firewall policy, snapshots and an out-of-band recovery path.
4. Seed a known-good inventory, deliberately broken test cases, and expected policy/audit outcomes.
5. Establish an operator-controlled procedure for bringing up, resetting and destroying the lab, with no privileged production credentials.

**Exit criteria:** topology reproducible from documentation, expected paths and isolation tested independently, restore procedure works, and read-only credentials exist for later integration tests.

## Proposed v0.2 — Real Read-Only Discovery & Audit

- Add **explicitly allowlisted, read-only** connectors for a **small, version-pinned set of lab platforms** selected after Stage 0.
- Collect interface, addressing, VLAN, route and ACL facts with provenance, timestamps, error/unknown states and secret redaction.
- Normalize evidence and compare detected facts to the expected lab topology; keep inferred and verified findings distinct.
- Never execute configuration-changing CLI or shell commands. No automatic scanning outside the authorized lab scope.
- Test loss of access, vendor/version mismatch, partial responses, forged output and prompt injection.

**Exit criteria:** lab inventory can be collected and audited repeatedly without changing device configuration; unsupported platforms fail closed.

## Proposed v0.3 — Controlled Lab Changes (NOT production)

- Start with only a small allowlist of tested configuration changes on explicitly supported lab devices.
- Retain a real human decision bound to plan hash, policy and expiry; verify device capability and management-channel safety.
- Add vendor-specific backup, transaction/commit-confirmed or safe-mode application, post-check and tested rollback/recovery.
- Exercise failure injection and recovery with isolated lab devices; an unverified rollback becomes `recovery_required`, never “success.”
- No autonomous write access to production networks.

**Exit criteria:** independently verified end-to-end lab change, denial and recovery tests for each supported vendor and version.

## Proposed v1.0 — Production candidate (conditional)

- Complete security review, operations documentation, maintenance/upgrade tests, supported hardware matrix, audit/event retention, observability, HA where required and disaster recovery.
- Validate integration with the **actual** AI Workforce OS deployment, including operator identity, scopes, approvals and failure modes.
- Run limited supervised pilots only after formal change-management approval and safety criteria are met.

**Not a promise of production readiness:** actual rollout requires additional evidence, platform-specific acceptance and owner approval.

## Guiding constraints

- Standalone operation remains available independently of AI Workforce OS.
- Deny by default; unknown evidence must not be treated as pass.
- Service identities never impersonate a human approver.
- Mock, observed read-only evidence and verified real outcomes must be clearly labeled.
- All implementation milestones require PR review, automated checks and updated documentation.

For project roles and acknowledgments, see [Contributors](CONTRIBUTORS.md).
