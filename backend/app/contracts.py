from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class Health(BaseModel):
    status: Literal["ok"] = "ok"


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


class Capabilities(BaseModel):
    api_version: Literal["v1"] = "v1"
    stage: Literal["foundation"] = "foundation"
    demo_mode: Literal[True] = True


class AuditEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    occurred_at: datetime
    actor: str | None
    request_id: str
    outcome: int
    event_type: str | None = None
    network_id: str | None = None
    revision: int | None = None
    policy_version: str | None = None


class AuditResponse(BaseModel):
    events: list[AuditEntry]
