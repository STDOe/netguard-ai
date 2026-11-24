# ADR 0006 · Workforce integration and local approval

Integration v1 uses a separate REST router and a single scoped service
credential configured by the operator. The gateway validates credential
expiry, transport, workspace and scope. The application stores a namespaced
caller and workspace on each durable workflow record.

A service may submit a typed change plan through Runtime. Task ownership
remains with the service. A local Admin can inspect its Brownfield proposal
and record an independent approval tied to the exact plan. Execution uses
the recorded human decision and the existing policy, expiry and revision
checks. The approval receipt and workflow events preserve the decision
actor. Legacy local task ownership continues to use the existing principals.

Integration audit uses the existing engine and commits its report and task
outcome together. Artifact records index deterministic IDs and reference
the owning workflow. The LangGraph checkpoint remains the content store.
The client consumes versioned HTTP messages and polls for appended events.
