from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4, uuid5

from sqlalchemy import (
    Engine,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.network.models import Model
from app.storage import Base, Task
from app.workflows.models import (
    Approval,
    Event,
    Requirements,
    Status,
    TaskRequest,
    WorkflowError,
    hash_model,
)


class Signal(Model):
    id: UUID
    request_id: UUID
    actor: str
    kind: Literal["input", "decision", "cancel", "expire"]
    requirements: Requirements | None = None


class WorkflowRecord(Base):
    __tablename__ = "workflow_metadata"
    __table_args__ = (UniqueConstraint("owner", "idempotency_key"),)

    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)
    thread_id: Mapped[str] = mapped_column(String(36), unique=True)
    owner: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(64))
    request_hash: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str] = mapped_column(String(36))
    initial_request_id: Mapped[str] = mapped_column(String(36))
    payload: Mapped[str] = mapped_column(Text)
    pending: Mapped[str | None] = mapped_column(Text)
    checkpoint_id: Mapped[str | None] = mapped_column(String(36))
    checkpoint_digest: Mapped[str | None] = mapped_column(String(64))
    verified_result: Mapped[str | None] = mapped_column(Text)
    recovery_code: Mapped[str | None] = mapped_column(String(64))


class WorkflowEvent(Base):
    __tablename__ = "workflow_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    step: Mapped[str] = mapped_column(String(64))
    code: Mapped[str | None] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
    request_id: Mapped[str] = mapped_column(String(36))
    at: Mapped[str] = mapped_column(String(40))


class ApprovalRecord(Base):
    __tablename__ = "workflow_approvals"

    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)
    audit_event_id: Mapped[str] = mapped_column(
        ForeignKey("workflow_events.id"), unique=True
    )
    payload: Mapped[str] = mapped_column(Text)


class WorkflowStore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def create(self, owner: str, request_id: UUID, body: TaskRequest) -> WorkflowRecord:
        fingerprint = hash_model(body)
        with Session(self.engine, expire_on_commit=False) as session, session.begin():
            existing = session.scalar(
                select(WorkflowRecord).where(
                    WorkflowRecord.owner == owner,
                    WorkflowRecord.idempotency_key == body.idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_hash != fingerprint:
                    raise WorkflowError(409, "idempotency_conflict")
                return existing
            task_id = uuid4()
            session.add(Task(id=str(task_id), kind=body.kind, status="queued"))
            session.flush()
            record = WorkflowRecord(
                task_id=str(task_id),
                thread_id=str(uuid4()),
                owner=owner,
                request_hash=fingerprint,
                idempotency_key=body.idempotency_key,
                correlation_id=str(uuid4()),
                initial_request_id=str(request_id),
                payload=body.model_dump_json(),
            )
            session.add(record)
            self._event(
                session, task_id, task_id, "task.created", owner, request_id, None
            )
            return record

    def get(self, task_id: UUID, owner: str) -> WorkflowRecord:
        with Session(self.engine) as session:
            record = session.get(WorkflowRecord, str(task_id))
            if record is None:
                raise WorkflowError(404, "task_not_found")
            if record.owner != owner:
                raise WorkflowError(403, "task_scope_denied")
            return record

    def pending_approvals(self, owner: str) -> list[UUID]:
        with Session(self.engine) as session:
            statement = (
                select(WorkflowRecord.task_id)
                .join(Task, Task.id == WorkflowRecord.task_id)
                .where(
                    WorkflowRecord.owner == owner, Task.status == "awaiting_approval"
                )
                .order_by(WorkflowRecord.task_id)
                .limit(50)
            )
            return [UUID(value) for value in session.scalars(statement)]

    def approval(self, task_id: UUID) -> Approval | None:
        with Session(self.engine) as session:
            row = session.get(ApprovalRecord, str(task_id))
            return None if row is None else Approval.model_validate_json(row.payload)

    def signal(
        self,
        task_id: UUID,
        signal: Signal,
        approval: Approval | None = None,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            record = session.get_one(WorkflowRecord, str(task_id))
            if record.pending is not None:
                raise WorkflowError(409, "task_signal_pending")
            record.pending = signal.model_dump_json(exclude_unset=True)
            step = (
                f"task.{signal.kind}"
                if approval is None
                else f"approval.{approval.decision}"
            )
            event_id = self._event(
                session,
                task_id,
                signal.id,
                step,
                signal.actor,
                signal.request_id,
                None,
            )
            if approval is not None:
                if approval.audit_event_id != event_id:
                    raise ValueError("approval event mismatch")
                session.add(
                    ApprovalRecord(
                        task_id=str(task_id),
                        audit_event_id=str(event_id),
                        payload=approval.model_dump_json(),
                    )
                )

    def status(self, task_id: str) -> str:
        with Session(self.engine) as session:
            return session.get_one(Task, task_id).status

    def has_progress(self, task_id: str) -> bool:
        with Session(self.engine) as session:
            return (
                session.scalar(
                    select(WorkflowEvent.id)
                    .where(
                        WorkflowEvent.task_id == task_id,
                        WorkflowEvent.step != "task.created",
                    )
                    .limit(1)
                )
                is not None
            )

    def legacy_signal_matches(self, task_id: str, consumed: str | None) -> bool:
        # Before migration 0004 the audit trail was the only application-side
        # acknowledgement of interview inputs, cancellation and decisions.
        with Session(self.engine) as session:
            last = session.scalar(
                select(WorkflowEvent)
                .where(
                    WorkflowEvent.task_id == task_id,
                    WorkflowEvent.step.in_(
                        (
                            "task.input",
                            "task.cancel",
                            "task.expire",
                            "approval.approve",
                            "approval.reject",
                        )
                    ),
                )
                .order_by(WorkflowEvent.sequence.desc())
                .limit(1)
            )
            if last is None:
                return consumed is None
            return consumed is not None and last.id == str(
                uuid5(UUID(consumed), last.step)
            )

    def mark_recovery(self, task_id: str) -> None:
        with Session(self.engine) as session, session.begin():
            session.get_one(Task, task_id).status = "recovery_required"
            record = session.get_one(WorkflowRecord, task_id)
            record.recovery_code = "checkpoint_inconsistent"

    def synchronize(
        self,
        task_id: str,
        status: Status,
        consumed: UUID | None,
        checkpoint_id: str,
        digest: str,
        result: str | None,
        recovery_code: str | None,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            task = session.get_one(Task, task_id)
            task.status = status
            row = session.get_one(WorkflowRecord, task_id)
            row.checkpoint_id = checkpoint_id
            row.checkpoint_digest = digest
            row.verified_result = result
            row.recovery_code = recovery_code
            if consumed is not None:
                if (
                    row.pending is not None
                    and Signal.model_validate_json(row.pending).id == consumed
                ):
                    row.pending = None

    def event(
        self,
        task_id: UUID,
        action: UUID,
        step: str,
        actor: str,
        request_id: UUID,
        code: str | None = None,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            self._event(session, task_id, action, step, actor, request_id, code)

    @staticmethod
    def _event(
        session: Session,
        task_id: UUID,
        action: UUID,
        step: str,
        actor: str,
        request_id: UUID,
        code: str | None,
    ) -> UUID:
        event_id = uuid5(action, step)
        session.execute(
            insert(WorkflowEvent)
            .values(
                id=str(event_id),
                task_id=str(task_id),
                step=step,
                code=code,
                actor=actor,
                request_id=str(request_id),
                at=datetime.now(UTC).isoformat(),
            )
            .on_conflict_do_nothing(index_elements=[WorkflowEvent.id])
        )
        return event_id

    def events(self, task_id: UUID) -> list[Event]:
        with Session(self.engine) as session:
            statement = (
                select(WorkflowEvent)
                .where(WorkflowEvent.task_id == str(task_id))
                .order_by(WorkflowEvent.sequence)
            )
            return [
                Event.model_validate(entry, from_attributes=True)
                for entry in session.scalars(statement)
            ]
