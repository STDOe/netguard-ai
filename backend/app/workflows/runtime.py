import fcntl
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic, sleep
from typing import cast
from uuid import UUID, uuid4, uuid5

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command
from langsmith import tracing_context

from app.security import ROLE_PERMISSIONS, Permission, Role
from app.workflows.graph import REQUEST, RUN_DEADLINE, State, WorkflowNodes, build_graph
from app.workflows.models import (
    SCHEMA_VERSION,
    Approval,
    BrownfieldRequest,
    DecisionRequest,
    Event,
    Plan,
    Requirements,
    TaskRequest,
    TaskView,
    WorkflowError,
)
from app.workflows.store import Signal, WorkflowRecord

Graph = CompiledStateGraph[State, None, State, State]


class Runtime:
    def __init__(self, database_path: Path, nodes: WorkflowNodes) -> None:
        self.nodes = nodes
        self.store = nodes.store
        self.checkpoint_path = database_path.with_name(
            database_path.name + ".checkpoints"
        )
        self.lock_path = database_path.with_name(database_path.name + ".workflow.lock")

    @contextmanager
    def graph(self) -> Iterator[Graph]:
        try:
            with self.lock_path.open("a") as lock, tracing_context(enabled=False):
                deadline = monotonic() + 3
                while True:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if monotonic() >= deadline:
                            raise WorkflowError(409, "workflow_busy") from None
                        sleep(0.025)

                with closing(
                    sqlite3.connect(
                        self.checkpoint_path,
                        timeout=2,
                        check_same_thread=False,
                    )
                ) as connection:
                    saver = SqliteSaver(
                        connection,
                        serde=JsonPlusSerializer(allowed_msgpack_modules=None),
                    )
                    yield build_graph(self.nodes, saver)
        except (OSError, sqlite3.Error):
            raise WorkflowError(503, "workflow_storage_unavailable") from None

    @staticmethod
    def invoke(
        graph: Graph, command: State | Command[object] | None, config: RunnableConfig
    ) -> None:
        token = RUN_DEADLINE.set(monotonic() + 20)
        try:
            graph.invoke(command, config, durability="sync")
        finally:
            RUN_DEADLINE.reset(token)

    def drive(self, graph: Graph, row: WorkflowRecord) -> TaskView:
        config: RunnableConfig = {
            "configurable": {"thread_id": row.thread_id},
            "recursion_limit": 20,
        }
        before = graph.get_state(config)
        initial = REQUEST.validate_json(row.payload)
        if before.created_at is None:
            self.invoke(
                graph,
                {
                    "task_id": row.task_id,
                    "actor": row.owner,
                    "request_id": row.initial_request_id,
                    "schema_version": SCHEMA_VERSION,
                    "request": initial.model_dump(mode="json"),
                    "status": "queued",
                },
                config,
            )
            before = graph.get_state(config)

        signal = (
            None if row.pending is None else Signal.model_validate_json(row.pending)
        )
        state = cast(State, before.values)
        if state.get("schema_version") != SCHEMA_VERSION:
            raise WorkflowError(409, "unsupported_checkpoint_version")

        if (
            signal is not None
            and str(signal.id) != state.get("last_signal")
            and before.interrupts
        ):
            self.invoke(
                graph,
                Command(
                    resume={
                        before.interrupts[0].id: signal.model_dump(
                            mode="json", exclude_unset=True
                        )
                    }
                ),
                config,
            )
            state = cast(State, graph.get_state(config).values)
        elif before.next and not before.interrupts:
            self.invoke(graph, None, config)
            state = cast(State, graph.get_state(config).values)

        consumed = state.get("last_signal")
        self.store.synchronize(
            row.task_id, state["status"], None if consumed is None else UUID(consumed)
        )
        return TaskView.model_validate(
            {
                "id": row.task_id,
                "thread_id": row.thread_id,
                "correlation_id": row.correlation_id,
                "kind": initial.kind,
                "status": state["status"],
                "code": state.get("code"),
                "missing": state.get("missing", ()),
                "plan": state.get("plan"),
                "approval": self.store.approval(UUID(row.task_id)),
                "result": state.get("result"),
                "artifacts": state.get("artifacts", ()),
                "findings": state.get("findings", ()),
            },
        )

    def create(self, owner: str, request_id: UUID, body: TaskRequest) -> TaskView:
        if (
            isinstance(body, BrownfieldRequest)
            and not body.dry_run
            and (Permission.CHANGE_NETWORK not in ROLE_PERMISSIONS[Role(owner)])
        ):
            raise WorkflowError(403, "workflow_write_denied")
        with self.graph() as graph:
            row = self.store.create(owner, request_id, body)
            return self.expire_if_due(graph, self.drive(graph, row), owner)

    def get(self, task_id: UUID, owner: str) -> TaskView:
        with self.graph() as graph:
            result = self.drive(graph, self.store.get(task_id, owner))
            return self.expire_if_due(graph, result, owner)

    def pending_approvals(self, owner: str) -> list[TaskView]:
        results = []
        with self.graph() as graph:
            for task_id in self.store.pending_approvals(owner):
                result = self.drive(graph, self.store.get(task_id, owner))
                result = self.expire_if_due(graph, result, owner)
                if result.status == "awaiting_approval":
                    results.append(result)
        return results

    def expire_if_due(self, graph: Graph, task: TaskView, owner: str) -> TaskView:
        if (
            task.status != "awaiting_approval"
            or task.plan is None
            or task.plan.expires_at > datetime.now(UTC)
            or task.approval is not None
        ):
            return task
        signal = Signal(
            id=uuid4(),
            request_id=uuid4(),
            actor=owner,
            kind="expire",
        )
        self.store.signal(task.id, signal)
        return self.drive(graph, self.store.get(task.id, owner))

    def input(
        self,
        task_id: UUID,
        owner: str,
        request_id: UUID,
        requirements: Requirements,
    ) -> TaskView:
        with self.graph() as graph:
            result = self.drive(graph, self.store.get(task_id, owner))
            if result.status != "awaiting_input":
                raise WorkflowError(409, "task_not_awaiting_input")
            self.store.signal(
                task_id,
                Signal(
                    id=uuid4(),
                    request_id=request_id,
                    actor=owner,
                    kind="input",
                    requirements=requirements,
                ),
            )
            return self.drive(graph, self.store.get(task_id, owner))

    def decide(
        self,
        task_id: UUID,
        plan_id: UUID,
        owner: str,
        request_id: UUID,
        decision: DecisionRequest,
    ) -> TaskView:
        if Permission.APPROVE_WORKFLOW not in ROLE_PERMISSIONS[Role(owner)]:
            raise WorkflowError(403, "approval_denied")
        with self.graph() as graph:
            result = self.drive(graph, self.store.get(task_id, owner))
            plan = result.plan
            if plan is None or plan.plan_id != plan_id:
                raise WorkflowError(404, "plan_not_found")
            if (
                decision.plan_hash != plan.plan_hash
                or plan.exact_hash() != plan.plan_hash
            ):
                raise WorkflowError(409, "plan_hash_mismatch")
            if result.approval is not None:
                if result.approval.decision != decision.decision:
                    raise WorkflowError(409, "decision_exists")
                return result
            result = self.expire_if_due(graph, result, owner)
            if result.status != "awaiting_approval":
                raise WorkflowError(
                    409,
                    "approval_expired"
                    if result.status == "expired"
                    else "not_awaiting_approval",
                )
            now = datetime.now(UTC)
            if now >= plan.expires_at:
                self.expire_if_due(graph, result, owner)
                raise WorkflowError(409, "approval_expired")
            approval, signal = self.create_approval(
                plan, request_id, owner, decision, now
            )
            self.store.signal(task_id, signal, approval)
            return self.drive(graph, self.store.get(task_id, owner))

    @staticmethod
    def create_approval(
        plan: Plan,
        request_id: UUID,
        owner: str,
        decision: DecisionRequest,
        at: datetime,
    ) -> tuple[Approval, Signal]:
        signal = Signal(id=uuid4(), request_id=request_id, actor=owner, kind="decision")
        return (
            Approval(
                plan_id=plan.plan_id,
                actor=owner,
                decision=decision.decision,
                decided_at=at,
                plan_hash=plan.plan_hash,
                expires_at=plan.expires_at,
                request_id=request_id,
                audit_event_id=uuid5(signal.id, f"approval.{decision.decision}"),
            ),
            signal,
        )

    def cancel(self, task_id: UUID, owner: str, request_id: UUID) -> TaskView:
        with self.graph() as graph:
            result = self.drive(graph, self.store.get(task_id, owner))
            if result.status == "cancelled":
                return result
            if result.status not in ("awaiting_input", "awaiting_approval"):
                raise WorkflowError(409, "task_not_cancellable")
            result = self.expire_if_due(graph, result, owner)
            if result.status == "expired":
                raise WorkflowError(409, "approval_expired")
            self.store.signal(
                task_id,
                Signal(id=uuid4(), request_id=request_id, actor=owner, kind="cancel"),
            )
            return self.drive(graph, self.store.get(task_id, owner))

    def events(self, task_id: UUID, owner: str) -> list[Event]:
        self.store.get(task_id, owner)
        return self.store.events(task_id)
