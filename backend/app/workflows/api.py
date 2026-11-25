from uuid import UUID

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.contracts import ErrorResponse
from app.security import Permission, authorizer
from app.workflows.models import (
    Artifact,
    DecisionRequest,
    Event,
    ExecutionResult,
    Plan,
    Requirements,
    TaskRequest,
    TaskSummary,
    TaskView,
    WorkflowError,
)
from app.workflows.runtime import Runtime


def workflow_router(settings: Settings, runtime: Runtime) -> APIRouter:
    errors: dict[int | str, dict[str, object]] = {
        code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 500, 503)
    }
    router = APIRouter(prefix="/api/v1", tags=["workflows"], responses=errors)
    use = Depends(authorizer(settings, Permission.USE_WORKFLOWS))
    approve = Depends(authorizer(settings, Permission.APPROVE_WORKFLOW))

    @router.get("/tasks", dependencies=[use])
    def tasks(request: Request) -> list[TaskSummary]:
        return runtime.store.summaries(request.state.actor)

    @router.post("/tasks", dependencies=[use], status_code=201)
    def create(body: TaskRequest, request: Request) -> TaskView:
        return runtime.create(request.state.actor, UUID(request.state.request_id), body)

    @router.get("/tasks/{task_id}", dependencies=[use])
    def task(task_id: UUID, request: Request) -> TaskView:
        return runtime.inspect(task_id, request.state.actor)

    @router.post("/tasks/{task_id}/input", dependencies=[use])
    def provide_input(task_id: UUID, body: Requirements, request: Request) -> TaskView:
        return runtime.input(
            task_id, request.state.actor, UUID(request.state.request_id), body
        )

    @router.post("/tasks/{task_id}/cancel", dependencies=[use])
    def cancel(task_id: UUID, request: Request) -> TaskView:
        return runtime.cancel(
            task_id, request.state.actor, UUID(request.state.request_id)
        )

    @router.get("/tasks/{task_id}/plan", dependencies=[use])
    def plan(task_id: UUID, request: Request) -> Plan:
        result = runtime.get(task_id, request.state.actor).plan
        if result is None:
            raise WorkflowError(404, "plan_not_found")
        return result

    @router.get("/approvals", dependencies=[approve])
    def approvals(request: Request) -> list[TaskView]:
        return runtime.pending_approvals(request.state.actor)

    @router.post("/tasks/{task_id}/plan/{plan_id}/decision", dependencies=[approve])
    def decide(
        task_id: UUID, plan_id: UUID, body: DecisionRequest, request: Request
    ) -> TaskView:
        return runtime.decide(
            task_id,
            plan_id,
            request.state.actor,
            UUID(request.state.request_id),
            body,
        )

    @router.get("/tasks/{task_id}/result", dependencies=[use])
    def result(task_id: UUID, request: Request) -> ExecutionResult:
        evidence = runtime.get(task_id, request.state.actor).result
        if evidence is None:
            raise WorkflowError(404, "result_not_found")
        return evidence

    @router.get("/tasks/{task_id}/artifacts/{name}", dependencies=[use])
    def artifact(task_id: UUID, name: str, request: Request) -> Artifact:
        for artifact in runtime.get(task_id, request.state.actor).artifacts:
            if artifact.name == name:
                return artifact
        raise WorkflowError(404, "artifact_not_found")

    @router.get("/tasks/{task_id}/events", dependencies=[use])
    def events(task_id: UUID, request: Request) -> list[Event]:
        return runtime.events(
            task_id, runtime.store.approval_owner(task_id, request.state.actor)
        )

    return router
