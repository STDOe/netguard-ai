import asyncio
from collections.abc import Callable, Coroutine
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import TypeAdapter
from sqlalchemy import ForeignKey, String, false, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.config import IntegrationName, Scope
from app.contracts import ErrorResponse
from app.dashboard.audit import Audits
from app.integration.auth import IntegrationAuth
from app.integration.models import (
    ApprovalView,
    ArtifactContent,
    Capabilities,
    Events,
    IntegrationEvent,
    PlanSummary,
    Submission,
    TaskResponse,
    artifact_link,
)
from app.storage import Base, Task
from app.workflows.models import (
    AuditRequest,
    BrownfieldRequest,
    Plan,
    Requirements,
    Status,
    WorkflowError,
)
from app.workflows.runtime import Runtime
from app.workflows.store import WorkflowRecord

PREFIX = "/api/v1/integration"
Workspace = Annotated[IntegrationName, Query()]
BODY_LIMIT = 16_384
TASK_STATUS = TypeAdapter(Status)


class ArtifactRecord(Base):
    __tablename__ = "integration_artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("workflow_metadata.task_id"))
    name: Mapped[str] = mapped_column(String(32))


class BoundedRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handle = super().get_route_handler()

        async def bounded(request: Request) -> Response:
            if request.method != "POST":
                return await handle(request)
            body = bytearray()
            try:
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > BODY_LIMIT:
                            raise WorkflowError(413, "integration_body_too_large")
                        body.extend(chunk)
            except TimeoutError:
                raise WorkflowError(408, "integration_body_timeout") from None

            async def receive() -> dict[str, Any]:
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            return await handle(Request(request.scope, receive))

        return bounded


def summarize(plan: Plan) -> PlanSummary:
    return PlanSummary(
        plan_id=plan.plan_id,
        plan_hash=plan.plan_hash,
        risk=plan.risk,
        network_id=plan.network_id,
        expires_at=plan.expires_at,
        policy_version=plan.policy_version,
        base_revision=plan.base_revision,
        expected_config_sha256=plan.diff.expected_config_sha256,
    )


class IntegrationTasks:
    def __init__(self, auth: IntegrationAuth, runtime: Runtime, audits: Audits) -> None:
        self.auth = auth
        self.runtime = runtime
        self.audits = audits

    @property
    def network_id(self) -> UUID | None:
        profile = self.audits.driver.profile
        return profile.network.id if profile else None

    def scoped(self, task_id: UUID) -> WorkflowRecord:
        return self.runtime.store.scoped(task_id, self.auth.owner, self.auth.workspace)

    def project(self, request: Request, task_id: UUID) -> TaskResponse:
        row = self.scoped(task_id)
        request_id = UUID(request.state.request_id)
        if row.payload_kind == "audit":
            audit = AuditRequest.model_validate_json(row.payload)
            self.advance_audit(row, audit, request_id)
            reports = self.audits.read(audit.network_id, task_id)
            status = TASK_STATUS.validate_python(self.runtime.store.status(row.task_id))
            if status == "succeeded" and not reports:
                status = "recovery_required"
            return TaskResponse(
                request_id=request_id,
                task_id=task_id,
                workspace_id=self.auth.workspace,
                correlation_id=UUID(row.correlation_id),
                kind="audit",
                status=status,
                code="audit_report_missing" if status == "recovery_required" else None,
                audit=reports[0] if reports else None,
            )
        return self.workflow_view(request, row, task_id)

    def workflow_view(
        self, request: Request, row: WorkflowRecord, task_id: UUID
    ) -> TaskResponse:
        task = self.runtime.get(task_id, self.auth.owner)
        has_artifacts = Scope.ARTIFACTS in self.auth.settings.integration_scopes
        links = (
            tuple(artifact_link(task_id, item) for item in task.artifacts)
            if has_artifacts
            else ()
        )
        if links:
            with Session(self.auth.storage.engine) as session, session.begin():
                session.execute(
                    insert(ArtifactRecord).on_conflict_do_nothing(
                        index_elements=[ArtifactRecord.id]
                    ),
                    [
                        dict(
                            id=str(link.artifact_id),
                            task_id=str(task_id),
                            name=link.name,
                        )
                        for link in links
                    ],
                )
        awaiting_human = (
            task.kind == "brownfield"
            and task.plan is not None
            and not BrownfieldRequest.model_validate_json(row.payload).dry_run
        )
        return TaskResponse(
            request_id=UUID(request.state.request_id),
            task_id=task_id,
            workspace_id=self.auth.workspace,
            correlation_id=task.correlation_id,
            kind=task.kind,
            status=task.status,
            code=task.code,
            missing=task.missing,
            plan=summarize(task.plan) if task.plan else None,
            approval_id=task_id
            if awaiting_human
            and Scope.APPROVAL in self.auth.settings.integration_scopes
            else None,
            execution=task.result,
            artifacts=links,
        )

    def create(self, request: Request, body: Submission) -> TaskResponse:
        task = body.task
        if (
            isinstance(task, (AuditRequest, BrownfieldRequest))
            and task.network_id != self.network_id
        ):
            raise WorkflowError(404, "network_scope_denied")
        request_id = UUID(request.state.request_id)
        if isinstance(task, AuditRequest):
            with self.runtime.lock(self.runtime.lock_path):
                row = self.runtime.store.create(
                    self.auth.owner, request_id, task, self.auth.workspace
                )
            task_id = UUID(row.task_id)
        else:
            task_id = self.runtime.create(
                self.auth.owner, request_id, task, self.auth.workspace
            ).id
        return self.project(request, task_id)

    def advance_audit(
        self, row: WorkflowRecord, audit: AuditRequest, request_id: UUID
    ) -> None:
        if self.runtime.store.status(row.task_id) != "queued":
            return
        task_id = UUID(row.task_id)
        path = self.runtime.lock_path.with_suffix(f".{task_id}.lock")
        with (
            self.runtime.lock(path),
            Session(self.auth.storage.engine) as session,
            session.begin(),
        ):
            # Hold SQLite's writer reservation before reading the mutable status.
            session.execute(update(Task).where(false()).values(status="queued"))
            projection = session.get_one(Task, row.task_id)
            if projection.status == "queued":
                if audit.network_id != self.network_id:
                    raise WorkflowError(404, "network_scope_denied")
                self.audits.persist(
                    session, audit.network_id, row.owner, str(request_id), task_id
                )
                projection.status = "succeeded"
                self.runtime.store.append_event(
                    session,
                    task_id,
                    task_id,
                    "task.succeeded",
                    row.owner,
                    request_id,
                    None,
                )

    def artifact(self, artifact_id: UUID) -> ArtifactContent:
        with Session(self.auth.storage.engine) as session:
            row = session.get(ArtifactRecord, str(artifact_id))
        if row is None:
            raise WorkflowError(404, "artifact_not_found")
        task_id = UUID(row.task_id)
        owner = self.scoped(task_id).owner
        task = self.runtime.get(task_id, owner)
        for item in task.artifacts:
            if item.name == row.name:
                link = artifact_link(task_id, item)
                if link.artifact_id == artifact_id:
                    return ArtifactContent(
                        **link.model_dump(),
                        workspace_id=self.auth.workspace,
                        task_id=task_id,
                        content=item.content,
                    )
        raise WorkflowError(404, "artifact_not_found")


def integration_openapi(router: APIRouter) -> dict[str, Any]:
    return get_openapi(
        title="NetGuard Integration Contract", version="1.0", routes=router.routes
    )


def router_for(auth: IntegrationAuth, runtime: Runtime, audits: Audits) -> APIRouter:
    router = APIRouter(
        prefix=PREFIX,
        tags=["workforce"],
        route_class=BoundedRoute,
        responses={
            code: {"model": ErrorResponse}
            for code in (401, 403, 404, 408, 409, 413, 422, 429, 500, 503)
        },
    )
    tasks = IntegrationTasks(auth, runtime, audits)

    @router.get(
        "/capabilities", dependencies=[Depends(auth.require(Scope.CAPABILITIES))]
    )
    def capabilities() -> Capabilities:
        scopes = sorted(auth.settings.integration_scopes)
        return Capabilities(
            workspace_id=auth.workspace,
            caller=auth.settings.integration_caller,
            network_id=tasks.network_id,
            scopes=scopes,
            actions=[scope.value.removeprefix("integration:") for scope in scopes],
        )

    @router.get(
        "/openapi.json",
        dependencies=[Depends(auth.require(Scope.CAPABILITIES))],
        include_in_schema=False,
    )
    def openapi() -> JSONResponse:
        return JSONResponse(integration_openapi(router))

    @router.post(
        "/tasks", status_code=201, dependencies=[Depends(auth.require(Scope.CREATE))]
    )
    def create_task(request: Request, body: Submission) -> TaskResponse:
        auth.check_workspace(request, body.workspace_id)
        return tasks.create(request, body)

    @router.get("/tasks/{task_id}", dependencies=[Depends(auth.require(Scope.TASK))])
    def read_task(
        request: Request, task_id: UUID, workspace_id: Workspace
    ) -> TaskResponse:
        auth.check_workspace(request, workspace_id)
        return tasks.project(request, task_id)

    @router.post(
        "/tasks/{task_id}/input", dependencies=[Depends(auth.require(Scope.CREATE))]
    )
    def supply_input(
        request: Request, task_id: UUID, workspace_id: Workspace, body: Requirements
    ) -> TaskResponse:
        auth.check_workspace(request, workspace_id)
        if tasks.scoped(task_id).payload_kind != "greenfield":
            raise WorkflowError(409, "task_not_awaiting_input")
        runtime.input(task_id, auth.owner, UUID(request.state.request_id), body)
        return tasks.project(request, task_id)

    @router.post(
        "/tasks/{task_id}/cancel", dependencies=[Depends(auth.require(Scope.CANCEL))]
    )
    def cancel(
        request: Request, task_id: UUID, workspace_id: Workspace
    ) -> TaskResponse:
        auth.check_workspace(request, workspace_id)
        if tasks.scoped(task_id).payload_kind == "audit":
            raise WorkflowError(409, "task_not_cancellable")
        runtime.cancel(task_id, auth.owner, UUID(request.state.request_id))
        return tasks.project(request, task_id)

    @router.get(
        "/tasks/{task_id}/events", dependencies=[Depends(auth.require(Scope.EVENTS))]
    )
    def events(
        request: Request,
        task_id: UUID,
        workspace_id: Workspace,
        cursor: Annotated[str | None, Query(max_length=52)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> Events:
        auth.check_workspace(request, workspace_id)
        row = tasks.scoped(task_id)
        after = 0
        if cursor is not None:
            prefix, _, suffix = cursor.partition(".")
            if prefix != str(task_id) or not suffix.isascii() or not suffix.isdecimal():
                raise WorkflowError(422, "invalid_cursor")
            after = int(suffix)
        page = runtime.store.event_page(task_id, after, limit)
        return Events(
            events=[
                IntegrationEvent(
                    event_id=UUID(event.id),
                    sequence=after + i,
                    event=event.step,
                    code=event.code,
                    timestamp=datetime.fromisoformat(event.at),
                    correlation_id=UUID(row.correlation_id),
                    request_id=UUID(event.request_id),
                )
                for i, event in enumerate(page, 1)
            ],
            next_cursor=f"{task_id}.{after + len(page)}",
        )

    @router.get(
        "/artifacts/{artifact_id}",
        dependencies=[Depends(auth.require(Scope.ARTIFACTS))],
    )
    def artifact(
        request: Request, artifact_id: UUID, workspace_id: Workspace
    ) -> ArtifactContent:
        auth.check_workspace(request, workspace_id)
        return tasks.artifact(artifact_id)

    @router.get(
        "/approvals/{approval_id}", dependencies=[Depends(auth.require(Scope.APPROVAL))]
    )
    def approval(
        request: Request, approval_id: UUID, workspace_id: Workspace
    ) -> ApprovalView:
        auth.check_workspace(request, workspace_id)
        row = tasks.scoped(approval_id)
        if (
            row.payload_kind != "brownfield"
            or BrownfieldRequest.model_validate_json(row.payload).dry_run
        ):
            raise WorkflowError(404, "approval_not_found")
        task = runtime.get(approval_id, auth.owner)
        if task.plan is None:
            raise WorkflowError(404, "approval_not_found")
        state: Literal[
            "pending", "approve", "reject", "expired", "cancelled", "unavailable"
        ]
        if task.approval:
            state = task.approval.decision
        elif task.status in ("expired", "cancelled"):
            state = task.status
        else:
            state = "pending" if task.status == "awaiting_approval" else "unavailable"
        return ApprovalView(
            **summarize(task.plan).model_dump(),
            approval_id=approval_id,
            workspace_id=workspace_id,
            status=state,
        )

    @router.post(
        "/approvals/{approval_id}/decision",
        status_code=403,
        response_model=ErrorResponse,
        dependencies=[Depends(auth.require(Scope.APPROVAL))],
    )
    def unsupported_decision(
        approval_id: UUID, request: Request, workspace_id: Workspace
    ) -> None:
        auth.check_workspace(request, workspace_id)
        raise WorkflowError(403, "not_supported")

    return router
