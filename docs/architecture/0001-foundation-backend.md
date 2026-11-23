# ADR 0001 — Standalone backend and storage boundary

**Status:** Accepted for Foundation

FastAPI exposes the standalone API at `/api/v1`. Pydantic response models define its contracts. Request middleware assigns a UUID and records the matched route and HTTP status, without capturing request bodies, query strings or credentials. Error responses use stable codes and public messages. The same request ID is available in the response, log and stored denial event.

The storage boundary uses SQLAlchemy models and short-lived sessions. Alembic owns schema transitions. SQLite contains task records and authorization denial events. The task table provides storage for later workflow stages. Foundation exposes capabilities and the audit log. Running migrations is an explicit deployment step, performed once per database by a single operator or by the one Compose replica before it starts serving. Readiness verifies the migration revision and reads both tables. The application disposes of its connection pool on shutdown.

PostgreSQL adoption can reuse the storage boundary and portable column types. It will require connection configuration, migration validation and integration tests on PostgreSQL. The namespace `/api/v1/workforce` is reserved for future integration-specific routes. The integration will reuse the backend's authorization and storage contracts and authenticate with scoped service identities. Its routes will be registered as they become functional.
