import fcntl
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import monotonic, sleep
from typing import cast
from uuid import UUID, uuid4, uuid5

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, StateSnapshot
from langsmith import tracing_context

from app.network.errors import CorruptSnapshot, NotFound
from app.security import Permission, can_request_change, has_permissions
from app.workflows.graph import REQUEST, RUN_DEADLINE, State, WorkflowNodes, build_graph
from app.workflows.models import (
    SCHEMA_VERSION,
    Approval,
    BrownfieldRequest,
    DecisionRequest,
    Event,
    ExecutionResult,
    Plan,
    Requirements,
    TaskRequest,
    TaskView,
    WorkflowError,
    hash_model,
)
from app.workflows.store import Signal, WorkflowRecord

Graph = CompiledStateGraph[State, None, State, State]


class InvalidCheckpoint(Exception):
    """Checkpoint disagrees with durable application records."""


def checkpoint_digest(snapshot: StateSnapshot) -> str:
    encoded = json.dumps(
        [snapshot.values, snapshot.next], sort_keys=True, separators=(",", ":")
    )
    return sha256(encoded.encode()).hexdigest()


def validate_input_checkpoint(
    graph: Graph, before: StateSnapshot, start: State, kind: str
) -> None:
    saver = cast(SqliteSaver, graph.checkpointer)
    stored = saver.get_tuple(before.config)
    if (
        stored is None
        or (before.metadata or {}).get("step") != -1
        or stored.checkpoint["channel_values"].get("__start__") != start
    ):
        raise InvalidCheckpoint
    # A process can stop on either side of the __start__ pending writes.
    entry = "interview" if kind == "greenfield" else "discovery"
    writes = {channel: value for _, channel, value in (stored.pending_writes or ())}
    if writes:
        if (
            writes != {**start, f"branch:to:{entry}": None}
            or before.values != start
            or before.next
        ):
            raise InvalidCheckpoint
    elif before.values or before.next != ("__start__",):
        raise InvalidCheckpoint


class Runtime:
    def __init__(self, database_path: Path, nodes: WorkflowNodes) -> None:
        self.nodes = nodes
        self.store = nodes.store
        self.checkpoint_path = database_path.with_name(
            database_path.name + ".checkpoints"
        )
        self.lock_path = database_path.with_name(database_path.name + ".workflow.lock")

    @contextmanager
    def lock(self, path: Path) -> Iterator[None]:
        with path.open("a") as lock:
            deadline = monotonic() + 3
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if monotonic() >= deadline:
                        raise WorkflowError(409, "workflow_busy") from None
                    sleep(0.025)
            yield

    @contextmanager
    def saver(self) -> Iterator[SqliteSaver]:
        try:
            with closing(
                sqlite3.connect(
                    self.checkpoint_path, timeout=2, check_same_thread=False
                )
            ) as connection:
                yield SqliteSaver(
                    connection, serde=JsonPlusSerializer(allowed_msgpack_modules=None)
                )
        except (OSError, sqlite3.Error):
            raise WorkflowError(503, "workflow_storage_unavailable") from None

    def check_ready(self) -> None:
        with self.saver() as saver, saver.cursor() as cursor:
            # Exercise the same schema and write permissions without creating a thread.
            cursor.execute("UPDATE checkpoints SET metadata=metadata WHERE 0")
            cursor.execute("SELECT value FROM writes LIMIT 0")

    @contextmanager
    def graph(self, task_id: UUID, owner: str) -> Iterator[Graph]:
        self.store.get(task_id, owner)
        path = self.lock_path.with_suffix(f".{task_id}.lock")
        with self.saver() as saver, self.lock(path), tracing_context(enabled=False):
            yield build_graph(self.nodes, saver)

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
        initial = REQUEST.validate_json(row.payload)
        task_id = UUID(row.task_id)
        approval = self.store.approval(task_id)
        status = self.store.status(row.task_id)
        view = TaskView(
            id=task_id,
            thread_id=UUID(row.thread_id),
            correlation_id=UUID(row.correlation_id),
            kind=initial.kind,
            status="recovery_required",
            requested_by_service=row.workspace is not None,
            code=row.recovery_code or "checkpoint_inconsistent",
            approval=approval,
            result=ExecutionResult.model_validate_json(row.verified_result)
            if row.verified_result
            else None,
        )
        if status == "recovery_required" and row.recovery_code:
            return view

        start: State = {
            "task_id": row.task_id,
            "actor": row.owner,
            "request_id": row.initial_request_id,
            "schema_version": SCHEMA_VERSION,
            "request": initial.model_dump(mode="json"),
            "status": "queued",
        }
        signal = (
            None if row.pending is None else Signal.model_validate_json(row.pending)
        )
        try:
            before = graph.get_state(config)
            is_input = (before.metadata or {}).get("source") == "input"
            if before.created_at is None or is_input:
                if (
                    status != "queued"
                    or row.checkpoint_id
                    or approval
                    or signal
                    or self.store.has_progress(row.task_id)
                ):
                    raise InvalidCheckpoint
                if is_input:
                    validate_input_checkpoint(graph, before, start, initial.kind)
            else:
                self.validate_checkpoint(graph, before, row, initial, status, approval)
        except sqlite3.DatabaseError as error:
            if getattr(error, "sqlite_errorcode", None) not in (
                sqlite3.SQLITE_CORRUPT,
                sqlite3.SQLITE_NOTADB,
            ):
                raise
            self.store.mark_recovery(row.task_id)
            return view
        except (
            InvalidCheckpoint,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            IndexError,
            NotImplementedError,
            CorruptSnapshot,
            NotFound,
        ):
            self.store.mark_recovery(row.task_id)
            return view
        if before.created_at is None or is_input:
            self.invoke(graph, None if is_input else start, config)
            before = graph.get_state(config)

        state = cast(State, before.values)
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
            before = graph.get_state(config)
        elif before.next and not before.interrupts:
            self.invoke(graph, None, config)
            before = graph.get_state(config)

        state = cast(State, before.values)
        consumed = state.get("last_signal")
        result = TaskView.model_validate(
            {
                "id": row.task_id,
                "thread_id": row.thread_id,
                "correlation_id": row.correlation_id,
                "kind": initial.kind,
                "status": state["status"],
                "requested_by_service": row.workspace is not None,
                "code": state.get("code"),
                "missing": state.get("missing", ()),
                "plan": state.get("plan"),
                "approval": self.store.approval(UUID(row.task_id)),
                "result": state.get("result"),
                "artifacts": state.get("artifacts", ()),
                "findings": state.get("findings", ()),
            },
        )

        if (
            before.config["configurable"]["checkpoint_id"] != row.checkpoint_id
            or row.pending
        ):
            self.store.synchronize(
                row.task_id,
                result.status,
                UUID(consumed) if consumed else None,
                before.config["configurable"]["checkpoint_id"],
                checkpoint_digest(before),
                result.result.model_dump_json() if result.result else None,
                result.code if result.status == "recovery_required" else None,
            )
        return result

    def validate_checkpoint(
        self,
        graph: Graph,
        before: StateSnapshot,
        row: WorkflowRecord,
        initial: TaskRequest,
        status: str,
        approval: Approval | None,
    ) -> None:
        state = cast(State, before.values)
        if (
            state.get("schema_version") != SCHEMA_VERSION
            or state.get("task_id") != row.task_id
            or state.get("request") != initial.model_dump(mode="json")
            or state.get("actor") != row.owner
            or not state.get("status")
        ):
            raise InvalidCheckpoint
        current_id = before.config["configurable"]["checkpoint_id"]
        if row.checkpoint_id == current_id:
            if (
                row.checkpoint_digest != checkpoint_digest(before)
                or status != state["status"]
            ):
                raise InvalidCheckpoint
        elif row.checkpoint_id:
            # A newer checkpoint is legitimate only while delivering a durable signal.
            if not row.pending:
                raise InvalidCheckpoint
            parent = before.parent_config
            while (
                parent and parent["configurable"]["checkpoint_id"] != row.checkpoint_id
            ):
                ancestor = graph.get_state(parent)
                if (
                    not ancestor.parent_config
                    or ancestor.parent_config["configurable"]["checkpoint_id"]
                    >= parent["configurable"]["checkpoint_id"]
                ):
                    raise InvalidCheckpoint
                parent = ancestor.parent_config
            if not parent:
                raise InvalidCheckpoint
        elif not row.pending:
            if status != "queued" and status != state["status"]:
                raise InvalidCheckpoint
            if not self.store.legacy_signal_matches(
                row.task_id, state.get("last_signal")
            ):
                raise InvalidCheckpoint

        plan = Plan.model_validate(state["plan"]) if "plan" in state else None
        if plan and (
            not isinstance(initial, BrownfieldRequest)
            or plan.task_id != UUID(row.task_id)
            or plan.network_id != initial.network_id
            or plan.exact_hash() != plan.plan_hash
        ):
            raise InvalidCheckpoint
        if approval and (
            not plan
            or approval.plan_hash != plan.plan_hash
            or approval.plan_id != plan.plan_id
            or (row.workspace is None and approval.actor != row.owner)
        ):
            raise InvalidCheckpoint
        if not isinstance(initial, BrownfieldRequest) or initial.dry_run:
            return
        if not approval or not plan:
            if (
                "committed" in state
                or "result" in state
                or state["status"] == "succeeded"
            ):
                raise InvalidCheckpoint
            return
        receipt = self.nodes.driver.repository.execution_receipt(
            initial.network_id, approval.plan_hash
        )
        if receipt is None:
            if (
                "committed" in state
                or "result" in state
                or state["status"] == "succeeded"
            ):
                raise InvalidCheckpoint
            return
        if (
            approval.decision != "approve"
            or receipt.revision != plan.base_revision + 1
            or hash_model(receipt.network) != plan.diff.expected_config_sha256
            or self.nodes.driver.get_snapshot(initial.network_id).revision
            < receipt.revision
            or (
                "committed" in state
                and state["committed"] != receipt.model_dump(mode="json")
            )
        ):
            raise InvalidCheckpoint
        if state["status"] == "succeeded":
            evidence = ExecutionResult.model_validate(state.get("result"))
            if (
                evidence.snapshot_revision != receipt.revision
                or evidence.snapshot_sha256 != receipt.sha256
                or evidence.approval_event_id != approval.audit_event_id
                or evidence.plan_id != plan.plan_id
                or evidence.observed_config_sha256 != plan.diff.expected_config_sha256
                or evidence.expected_config_sha256 != plan.diff.expected_config_sha256
                or evidence.post_check != "passed"
            ):
                raise InvalidCheckpoint
        elif not row.pending:
            raise InvalidCheckpoint

    def create(
        self,
        owner: str,
        request_id: UUID,
        body: TaskRequest,
        workspace: str | None = None,
    ) -> TaskView:
        if (
            isinstance(body, BrownfieldRequest)
            and not body.dry_run
            and not can_request_change(owner, workspace)
        ):
            raise WorkflowError(403, "workflow_write_denied")
        with self.lock(self.lock_path):
            row = self.store.create(owner, request_id, body, workspace)
        return self.get(UUID(row.task_id), owner)

    def get(self, task_id: UUID, owner: str) -> TaskView:
        with self.graph(task_id, owner) as graph:
            result = self.drive(graph, self.store.get(task_id, owner))
            return self.expire_if_due(graph, result, owner)

    def inspect(self, task_id: UUID, actor: str) -> TaskView:
        return self.get(task_id, self.store.approval_owner(task_id, actor))

    def pending_approvals(self, actor: str) -> list[TaskView]:
        results = []
        for task_id in self.store.pending_approvals(actor):
            owner = self.store.approval_owner(task_id, actor)
            with self.graph(task_id, owner) as graph:
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
        with self.graph(task_id, owner) as graph:
            result = self.drive(graph, self.store.get(task_id, owner))
            if result.status != "awaiting_input":
                raise WorkflowError(409, "task_not_awaiting_input")
            current = graph.get_state(
                {"configurable": {"thread_id": str(result.thread_id)}}
            ).values["requirements"]
            patch = requirements.model_dump(mode="json", exclude_unset=True)
            if all(current.get(key) == value for key, value in patch.items()):
                return result
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
        actor: str,
        request_id: UUID,
        decision: DecisionRequest,
    ) -> TaskView:
        if not has_permissions(
            actor, Permission.APPROVE_WORKFLOW, Permission.CHANGE_NETWORK
        ):
            raise WorkflowError(403, "approval_denied")
        owner = self.store.approval_owner(task_id, actor)
        with self.graph(task_id, owner) as graph:
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
                if (
                    result.approval.plan_hash != decision.plan_hash
                    or result.approval.decision != decision.decision
                ):
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
                plan, request_id, actor, decision, now
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
        with self.graph(task_id, owner) as graph:
            if self.store.approval(task_id) is not None:
                raise WorkflowError(409, "task_not_cancellable")
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
