from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from time import monotonic
from typing import Any, Protocol, TypedDict
from uuid import UUID

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt
from pydantic import TypeAdapter, ValidationError

from app.config import Settings
from app.network.driver import MockNetworkDriver
from app.network.errors import (
    CorruptSnapshot,
    ExecutionExpired,
    NetworkError,
    PolicyBlocked,
)
from app.network.models import NetworkSnapshot
from app.network.repository import ExecutionGuard
from app.security import ROLE_PERMISSIONS, Permission, Role
from app.workflows.greenfield import (
    BillOfMaterials,
    Inventory,
    OfflineSources,
    architecture,
    export,
    hardware,
    validate_requirements,
)
from app.workflows.models import (
    BrownfieldRequest,
    Diff,
    ExecutionResult,
    Plan,
    Requirements,
    Status,
    TaskRequest,
    WorkflowError,
    hash_model,
)
from app.workflows.planner import (
    INTENT,
    LiteLLMPlanner,
    OfflinePlanner,
    PlannerProvider,
    build_plan,
    choose_intent,
    render,
)
from app.workflows.store import Signal, WorkflowStore

Json = dict[str, Any]
REQUEST = TypeAdapter(TaskRequest)
MAX_INPUTS = 5
RUN_DEADLINE: ContextVar[float] = ContextVar("workflow_deadline", default=float("inf"))


class State(TypedDict, total=False):
    task_id: str
    actor: str
    request_id: str
    last_signal: str
    input_count: int
    request: Json
    schema_version: int
    status: Status
    code: str | None
    requirements: Json
    missing: tuple[str, ...]
    bom: Json
    inventory: Json
    artifacts: list[Json]
    snapshot: Json
    intent: Json
    diff: Json
    plan: Json
    findings: list[Json]
    committed: Json
    result: Json


class GraphNode(Protocol):
    def __call__(self, state: State) -> State: ...


class WorkflowNodes:
    def __init__(
        self,
        settings: Settings,
        store: WorkflowStore,
        driver: MockNetworkDriver,
        provider: PlannerProvider | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.driver = driver
        self.sources = OfflineSources(settings.hardware_catalog_path)
        self.provider = provider or (
            OfflinePlanner() if settings.llm_model is None else LiteLLMPlanner(settings)
        )

    def event(self, state: State, step: str, code: str | None = None) -> None:
        self.store.event(
            UUID(state["task_id"]),
            UUID(state.get("last_signal", state["task_id"])),
            step,
            state["actor"],
            UUID(state["request_id"]),
            code,
        )

    def guarded(self, name: str, step: Callable[[State], State]) -> GraphNode:
        def run(state: State) -> State:
            self.event(state, name)
            try:
                if monotonic() >= RUN_DEADLINE.get() and name not in (
                    "simulate_apply",
                    "post_check",
                    "completed",
                ):
                    raise WorkflowError(503, "workflow_time_limit")
                return step(state)
            except PolicyBlocked as error:
                self.event(state, f"{name}.blocked", error.code)
                return {
                    "status": "blocked",
                    "code": error.code,
                    "findings": [
                        item.model_dump(mode="json") for item in error.findings
                    ],
                }
            except ExecutionExpired as error:
                self.event(state, "approval.expired", error.code)
                return {"status": "expired", "code": error.code}
            except NetworkError as error:
                self.event(state, f"{name}.blocked", error.code)
                return {"status": "blocked", "code": error.code}
            except WorkflowError as error:
                self.event(state, f"{name}.failed", error.code)
                return {
                    "status": "blocked" if error.status in (403, 409) else "failed",
                    "code": error.code,
                }
            except ValidationError:
                self.event(state, f"{name}.failed", "invalid_workflow_data")
                return {"status": "failed", "code": "invalid_workflow_data"}

        return run

    def interview(self, state: State) -> State:
        return {
            "requirements": Requirements.model_validate(
                state["request"]["requirements"]
            ).model_dump(mode="json"),
            "status": "running",
        }

    def validate(self, state: State) -> State:
        reasons = validate_requirements(
            Requirements.model_validate(state["requirements"])
        )
        if reasons:
            if state.get("input_count", 0) >= MAX_INPUTS:
                raise WorkflowError(422, "input_limit_reached")
            self.event(state, "task.awaiting_input")
            return {"status": "awaiting_input", "missing": reasons}
        return {"status": "running", "missing": ()}

    @staticmethod
    def interrupt_boundary(kind: str) -> Signal:
        return Signal.model_validate(interrupt({"kind": kind, "schema_version": 1}))

    @staticmethod
    def resumed(signal: Signal) -> State:
        return {
            "last_signal": str(signal.id),
            "actor": signal.actor,
            "request_id": str(signal.request_id),
        }

    def input_boundary(self, state: State) -> State:
        signal = self.interrupt_boundary("input")
        resumed = self.resumed(signal)
        if signal.kind == "cancel":
            return {**resumed, "status": "cancelled"}
        if signal.kind != "input" or signal.requirements is None:
            raise WorkflowError(409, "invalid_task_signal")
        current = state["requirements"]
        updated = {
            **current,
            **signal.requirements.model_dump(mode="json", exclude_unset=True),
        }
        return {
            **resumed,
            "requirements": updated,
            "status": "running",
            "input_count": state.get("input_count", 0) + int(updated != current),
        }

    def source(self, state: State) -> State:
        bom = hardware(
            UUID(state["task_id"]),
            Requirements.model_validate(state["requirements"]),
            self.sources,
        )
        self.event(state, "source_hardware.unavailable", "live_search_unavailable")
        return {"bom": bom.model_dump(mode="json")}

    def generate_architecture(self, state: State) -> State:
        result = architecture(
            UUID(state["task_id"]), Requirements.model_validate(state["requirements"])
        )
        return {"inventory": result.model_dump(mode="json")}

    def export_artifacts(self, state: State) -> State:
        artifacts = export(
            Requirements.model_validate(state["requirements"]),
            BillOfMaterials.model_validate(state["bom"]),
            Inventory.model_validate(state["inventory"]),
        )
        return {"artifacts": [item.model_dump(mode="json") for item in artifacts]}

    def discovery(self, state: State) -> State:
        body = BrownfieldRequest.model_validate(state["request"])
        snapshot = self.driver.get_snapshot(body.network_id)
        return {"snapshot": snapshot.model_dump(mode="json"), "status": "running"}

    def planner(self, state: State) -> State:
        body = BrownfieldRequest.model_validate(state["request"])
        snapshot = NetworkSnapshot.model_validate(state["snapshot"])
        intent = choose_intent(
            self.provider, self.driver, UUID(state["task_id"]), snapshot, body.goal
        )
        return {"intent": intent.model_dump(mode="json")}

    def validate_intent(self, state: State) -> State:
        body = BrownfieldRequest.model_validate(state["request"])
        if (
            not body.dry_run
            and Permission.CHANGE_NETWORK not in ROLE_PERMISSIONS[Role(state["actor"])]
        ):
            raise WorkflowError(403, "workflow_write_denied")
        snapshot = NetworkSnapshot.model_validate(state["snapshot"])
        if self.driver.get_snapshot(body.network_id).sha256 != snapshot.sha256:
            raise WorkflowError(409, "network_snapshot_changed")
        intent = INTENT.validate_python(state["intent"])
        diff = render(self.driver, snapshot, intent)
        self.event(state, "policy.allowed")
        return {"diff": diff.model_dump(mode="json")}

    def generate_diff(self, state: State) -> State:
        task_id = UUID(state["task_id"])
        body = BrownfieldRequest.model_validate(state["request"])
        diff = Diff.model_validate(state["diff"])
        plan = build_plan(
            self.driver,
            task_id,
            NetworkSnapshot.model_validate(state["snapshot"]),
            INTENT.validate_python(state["intent"]),
            diff,
            self.settings.workflow_approval_ttl_seconds,
        )
        self.event(state, "plan.created")
        status: Status = "running" if body.dry_run else "awaiting_approval"
        return {"plan": plan.model_dump(mode="json"), "status": status}

    def request_approval(self, state: State) -> State:
        signal = self.interrupt_boundary("approval")
        resumed = self.resumed(signal)
        updated: State = {**state, **resumed}
        if signal.kind == "cancel":
            return {**resumed, "status": "cancelled"}
        if signal.kind == "expire":
            self.event(updated, "approval.expired", "approval_expired")
            return {**resumed, "status": "expired", "code": "approval_expired"}
        approval = self.store.approval(UUID(state["task_id"]))
        if signal.kind != "decision" or approval is None:
            raise WorkflowError(409, "invalid_task_signal")
        if approval.decision == "reject":
            return {**resumed, "status": "rejected"}
        return {**resumed, "status": "running"}

    def simulate_apply(self, state: State) -> State:
        plan = Plan.model_validate(state["plan"])
        approval = self.store.approval(UUID(state["task_id"]))
        if (
            approval is None
            or approval.decision != "approve"
            or approval.actor != state["actor"]
            or plan.plan_id != approval.plan_id
            or plan.task_id != UUID(state["task_id"])
            or plan.exact_hash() != plan.plan_hash
            or approval.plan_hash != plan.plan_hash
            or approval.expires_at != plan.expires_at
            or not plan.created_at <= approval.decided_at < plan.expires_at
        ):
            raise WorkflowError(403, "approval_invalid")

        try:
            prior = self.driver.repository.execution_receipt(
                plan.network_id, plan.plan_hash
            )
        except CorruptSnapshot:
            self.event(state, "execution.receipt_corrupt", "corrupt_snapshot")
            return {"status": "recovery_required", "code": "corrupt_snapshot"}
        if prior is not None:
            self.event(state, "execution.committed")
            return {"committed": prior.model_dump(mode="json")}
        required = {Permission.APPROVE_WORKFLOW, Permission.CHANGE_NETWORK}
        if not required.issubset(ROLE_PERMISSIONS[Role(approval.actor)]):
            raise WorkflowError(403, "workflow_write_denied")
        if monotonic() >= RUN_DEADLINE.get():
            raise WorkflowError(409, "workflow_time_limit")
        if datetime.now(UTC) >= approval.expires_at:
            raise ExecutionExpired
        profile = self.driver.profile
        if profile is None or (
            profile.policy.version != plan.policy_version
            or hash_model(profile.policy) != plan.policy_sha256
        ):
            raise WorkflowError(409, "policy_changed")
        snapshot = self.driver.get_snapshot(plan.network_id)
        if (
            snapshot.revision != plan.base_revision
            or snapshot.sha256 != plan.base_snapshot_sha256
        ):
            raise WorkflowError(409, "network_snapshot_changed")
        if render(self.driver, snapshot, plan.change_intent) != plan.diff:
            raise WorkflowError(409, "plan_diff_changed")

        committed = self.driver.apply(
            plan.network_id,
            plan.base_revision,
            plan.change_intent,
            str(approval.request_id),
            approval.actor,
            execution=ExecutionGuard(plan.plan_hash, plan.expires_at),
        )
        self.event(state, "execution.committed")
        return {"committed": committed.model_dump(mode="json")}

    def post_check(self, state: State) -> State:
        plan = Plan.model_validate(state["plan"])
        result = NetworkSnapshot.model_validate(state["committed"])
        approval = self.store.approval(plan.task_id)
        assert approval is not None
        try:
            persisted = self.driver.repository.execution_receipt(
                plan.network_id, plan.plan_hash
            )
        except CorruptSnapshot:
            persisted = None
        observed = None if persisted is None else hash_model(persisted.network)
        valid = (
            persisted is not None
            and persisted == result
            and persisted.revision == plan.base_revision + 1
            and observed == plan.diff.expected_config_sha256
        )
        self.event(state, "post_check.result", "passed" if valid else "failed")
        evidence = ExecutionResult(
            plan_id=plan.plan_id,
            approval_event_id=approval.audit_event_id,
            snapshot_revision=result.revision,
            snapshot_sha256=result.sha256,
            expected_config_sha256=plan.diff.expected_config_sha256,
            observed_config_sha256=observed,
            post_check="passed" if valid else "failed",
        )
        return {
            "result": evidence.model_dump(mode="json"),
            "status": "running" if valid else "recovery_required",
            "code": None if valid else "post_check_failed",
        }

    def completed(self, _state: State) -> State:
        return {"status": "succeeded"}


def build_graph(
    nodes: WorkflowNodes, saver: BaseCheckpointSaver[Any]
) -> CompiledStateGraph[State, None, State, State]:
    graph = StateGraph(State)
    steps = {
        "interview": nodes.interview,
        "validate_requirements": nodes.validate,
        "await_input": nodes.input_boundary,
        "source_hardware": nodes.source,
        "generate_architecture": nodes.generate_architecture,
        "export_artifacts": nodes.export_artifacts,
        "discovery": nodes.discovery,
        "planner": nodes.planner,
        "validate_intent": nodes.validate_intent,
        "generate_diff": nodes.generate_diff,
        "request_approval": nodes.request_approval,
        "simulate_apply": nodes.simulate_apply,
        "post_check": nodes.post_check,
        "completed": nodes.completed,
    }
    for name, handler in steps.items():
        graph.add_node(name, nodes.guarded(name, handler))
    graph.add_conditional_edges(
        START,
        lambda state: state["request"]["kind"],
        {"greenfield": "interview", "brownfield": "discovery"},
    )

    def after(source: str, target: str) -> None:
        graph.add_conditional_edges(
            source,
            lambda state: state["status"] == "running",
            {True: target, False: END},
        )

    after("interview", "validate_requirements")
    graph.add_conditional_edges(
        "validate_requirements",
        lambda state: state["status"],
        {
            "awaiting_input": "await_input",
            "running": "source_hardware",
            "failed": END,
            "blocked": END,
        },
    )
    after("await_input", "validate_requirements")
    after("source_hardware", "generate_architecture")
    after("generate_architecture", "export_artifacts")
    after("export_artifacts", "completed")
    after("discovery", "planner")
    after("planner", "validate_intent")
    after("validate_intent", "generate_diff")
    graph.add_conditional_edges(
        "generate_diff",
        lambda state: state["status"],
        {
            "awaiting_approval": "request_approval",
            "running": "completed",
            "failed": END,
            "blocked": END,
        },
    )
    after("request_approval", "simulate_apply")
    after("simulate_apply", "post_check")
    after("post_check", "completed")
    graph.add_edge("completed", END)
    return graph.compile(checkpointer=saver)
