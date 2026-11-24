from hashlib import sha256
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field

from app.config import IntegrationName, Scope
from app.dashboard.audit import Report
from app.network.models import Model
from app.workflows.models import (
    Artifact,
    AuditRequest,
    BrownfieldRequest,
    ExecutionResult,
    GreenfieldRequest,
    Hash,
    Risk,
    Status,
)

Operation = Literal["greenfield", "brownfield", "audit"]


class Submission(Model):
    schema_version: Literal["1.0"]
    workspace_id: IntegrationName
    task: Annotated[
        GreenfieldRequest | BrownfieldRequest | AuditRequest,
        Field(discriminator="kind"),
    ]


class Capabilities(Model):
    api_version: Literal["v1"] = "v1"
    schema_version: Literal["1.0"] = "1.0"
    workspace_id: IntegrationName
    caller: IntegrationName
    network_id: UUID | None
    scenarios: tuple[Operation, ...] = ("greenfield", "brownfield", "audit")
    scopes: list[Scope]
    actions: list[str]
    mode: Literal["mock"] = "mock"
    integration: Literal["enabled"] = "enabled"
    external_compatibility: Literal["unverified"] = "unverified"
    limitations: tuple[str, ...] = (
        "polling",
        "local_human_approval",
        "offline_greenfield_sourcing",
    )


class ArtifactLink(Model):
    artifact_id: UUID
    href: str
    name: str
    media_type: str
    sha256: Hash
    size_bytes: int
    provenance: Literal["netguard.greenfield"] = "netguard.greenfield"


class ArtifactContent(ArtifactLink):
    workspace_id: IntegrationName
    task_id: UUID
    content: str


class PlanSummary(Model):
    plan_id: UUID
    plan_hash: Hash
    risk: Risk
    network_id: UUID
    expires_at: AwareDatetime
    policy_version: str
    base_revision: int
    expected_config_sha256: Hash


class ApprovalView(PlanSummary):
    approval_id: UUID
    workspace_id: IntegrationName
    status: Literal[
        "pending", "approve", "reject", "expired", "cancelled", "unavailable"
    ]


class TaskResponse(Model):
    schema_version: Literal["1.0"] = "1.0"
    request_id: UUID
    task_id: UUID
    correlation_id: UUID
    workspace_id: IntegrationName
    kind: Operation
    status: Status
    code: str | None = None
    missing: tuple[str, ...] = ()
    plan: PlanSummary | None = None
    approval_id: UUID | None = None
    execution: ExecutionResult | None = None
    audit: Report | None = None
    artifacts: tuple[ArtifactLink, ...] = ()


class IntegrationEvent(Model):
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    sequence: int
    event: str
    code: str | None
    timestamp: AwareDatetime
    correlation_id: UUID
    request_id: UUID


class Events(Model):
    events: list[IntegrationEvent]
    next_cursor: str | None


def artifact_link(task_id: UUID, artifact: Artifact) -> ArtifactLink:
    data = artifact.content.encode()
    artifact_id = uuid5(task_id, artifact.name)
    return ArtifactLink(
        artifact_id=artifact_id,
        href=f"/api/v1/integration/artifacts/{artifact_id}",
        name=artifact.name,
        media_type=artifact.media_type,
        size_bytes=len(data),
        sha256=sha256(data).hexdigest(),
    )
