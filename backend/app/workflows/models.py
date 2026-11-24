from datetime import datetime
from hashlib import sha256
from json import dumps
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StringConstraints

from app.network.driver import PutFirewallRule, PutStaticRoute, SetRoutingProtocols
from app.network.models import CIDR, Model, Revision
from app.network.policy import Finding

SCHEMA_VERSION: Literal[1] = 1
Status = Literal[
    "queued",
    "running",
    "awaiting_input",
    "awaiting_approval",
    "succeeded",
    "failed",
    "blocked",
    "rejected",
    "expired",
    "cancelled",
    "recovery_required",
]
Kind = Literal["greenfield", "brownfield"]
Risk = Literal["moderate", "high"]
Hash = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Key = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{8,64}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z][a-zA-Z0-9.-]{0,39}$")]
Count = Annotated[int, Field(strict=True, ge=0, le=100_000)]
Positive = Annotated[int, Field(strict=True, ge=1, le=1_000_000_000_000)]
Service = Literal["dns", "dhcp", "ntp", "monitoring", "voice", "point_of_sale"]
SecurityControl = Literal[
    "segmentation", "egress_filter", "logging", "payment_isolation"
]


def canonical(model: Model) -> bytes:
    return dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_model(model: Model) -> str:
    return sha256(canonical(model)).hexdigest()


class Requirements(Model):
    organization: (
        Literal["retail", "enterprise", "education", "healthcare", "other"] | None
    ) = None
    sites: Annotated[int, Field(strict=True, ge=1, le=32)] | None = None
    users_per_site: Count | None = None
    devices_per_site: Count | None = None
    registers_per_site: Count | None = None
    throughput_mbps: Positive | None = None
    packets_per_second: Positive | None = None
    budget_minor: Positive | None = None
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")] | None = None
    vendors: Annotated[tuple[Slug, ...], Field(max_length=12)] | None = None
    region: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")] | None = None
    availability: Literal["single", "redundant"] | None = None
    security: Annotated[tuple[SecurityControl, ...], Field(max_length=4)] | None = None
    services: Annotated[tuple[Service, ...], Field(max_length=6)] | None = None
    address_pool: CIDR | None = None


class GreenfieldRequest(Model):
    kind: Literal["greenfield"]
    idempotency_key: Key
    requirements: Requirements


class FindStaticRoute(Model):
    kind: Literal["find_static_route"]
    device_id: UUID
    destination: CIDR


Goal = Annotated[
    FindStaticRoute | PutStaticRoute | PutFirewallRule | SetRoutingProtocols,
    Field(discriminator="kind"),
]
ChangeIntent = Annotated[
    PutStaticRoute | PutFirewallRule | SetRoutingProtocols, Field(discriminator="kind")
]


class BrownfieldRequest(Model):
    kind: Literal["brownfield"]
    idempotency_key: Key
    network_id: UUID
    goal: Goal
    dry_run: Annotated[bool, Field(strict=True)] = False


TaskRequest = Annotated[
    GreenfieldRequest | BrownfieldRequest, Field(discriminator="kind")
]


class FieldDiff(Model):
    path: str
    before: object
    after: object


class Diff(Model):
    target_id: UUID
    original_revision: Revision
    risk: Risk
    fields: tuple[FieldDiff, ...]
    expected_config_sha256: Hash
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...] = ("Simulation only. No real dataplane verification.",)


class PlanBody(Model):
    plan_id: UUID
    task_id: UUID
    network_id: UUID
    base_revision: Revision
    base_snapshot_sha256: Hash
    policy_version: str
    policy_sha256: Hash
    schema_version: Literal[1] = SCHEMA_VERSION
    change_intent: ChangeIntent
    diff: Diff
    risk: Risk
    created_at: AwareDatetime
    expires_at: AwareDatetime


class Plan(PlanBody):
    plan_hash: Hash

    def exact_hash(self) -> str:
        body = PlanBody.model_validate(self.model_dump(exclude={"plan_hash"}))
        return hash_model(body)


class DecisionRequest(Model):
    plan_hash: Hash
    decision: Literal["approve", "reject"]


class Approval(Model):
    plan_id: UUID
    actor: str
    decision: Literal["approve", "reject"]
    decided_at: AwareDatetime
    plan_hash: Hash
    expires_at: AwareDatetime
    audit_event_id: UUID
    request_id: UUID


class Event(Model):
    id: UUID
    step: str
    code: str | None
    actor: str
    request_id: UUID
    at: datetime


class Artifact(Model):
    name: Literal[
        "bom.json",
        "bom.csv",
        "bom.md",
        "topology.mmd",
        "inventory.yaml",
        "assumptions.md",
    ]
    media_type: Literal[
        "application/json",
        "text/csv",
        "text/markdown",
        "text/plain",
        "application/yaml",
    ]
    content: str


class ExecutionResult(Model):
    plan_id: UUID
    approval_event_id: UUID
    snapshot_revision: Revision
    snapshot_sha256: Hash
    expected_config_sha256: Hash
    observed_config_sha256: Hash | None
    post_check: Literal["passed", "failed"]
    mock: Literal[True] = True


class TaskSummary(Model):
    id: UUID
    kind: str
    status: str


class TaskView(Model):
    id: UUID
    thread_id: UUID
    correlation_id: UUID
    schema_version: Literal[1] = SCHEMA_VERSION
    kind: Kind
    status: Status
    code: str | None = None
    missing: tuple[str, ...] = ()
    plan: Plan | None = None
    approval: Approval | None = None
    findings: tuple[Finding, ...] = ()
    result: ExecutionResult | None = None
    artifacts: tuple[Artifact, ...] = ()


class WorkflowError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code
        super().__init__(code)
