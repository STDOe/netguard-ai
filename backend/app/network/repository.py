from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from typing import Literal
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, ForeignKey, Index, Integer, String, Text, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.network.errors import (
    CorruptSnapshot,
    ExecutionExpired,
    NotFound,
    RevisionConflict,
)
from app.network.models import Model, Network, NetworkSnapshot
from app.storage import Base, audit_event

Operation = Literal["seed", "change", "restore"]


@dataclass(frozen=True, slots=True)
class ExecutionGuard:
    plan_hash: str
    expires_at: datetime


class NetworkRecord(Base):
    __tablename__ = "networks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    current_revision: Mapped[int] = mapped_column(Integer)


class RevisionRecord(Base):
    __tablename__ = "network_revisions"
    __table_args__ = (Index("uq_network_execution_key", "execution_key", unique=True),)

    network_id: Mapped[str] = mapped_column(ForeignKey("networks.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    operation: Mapped[Operation] = mapped_column(String(16))
    policy_version: Mapped[str] = mapped_column(String(80))
    restored_from: Mapped[int | None] = mapped_column(Integer)
    execution_key: Mapped[str | None] = mapped_column(String(64))


class RevisionInfo(Model):
    revision: int
    sha256: str
    operation: Operation
    policy_version: str
    restored_from: int | None


class AuditTarget(Model):
    id: UUID
    name: str | None
    snapshot_integrity: Literal["verified", "failed"]


class NetworkSummary(Model):
    id: UUID
    name: str
    revision: int


def digest(network_id: str, revision: int, payload: str) -> str:
    raw = f"netguard-snapshot-v1\n{network_id}\n{revision}\n{payload}".encode()
    return sha256(raw).hexdigest()


def serialize(
    network: Network,
    revision: int,
    operation: Operation,
    policy_version: str,
    restored_from: int | None = None,
) -> RevisionRecord:
    payload = dumps(
        network.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    network_id = str(network.id)
    return RevisionRecord(
        network_id=network_id,
        revision=revision,
        payload=payload,
        sha256=digest(network_id, revision, payload),
        operation=operation,
        policy_version=policy_version,
        restored_from=restored_from,
    )


def deserialize(record: RevisionRecord) -> NetworkSnapshot:
    if digest(record.network_id, record.revision, record.payload) != record.sha256:
        raise CorruptSnapshot
    try:
        network = Network.model_validate_json(record.payload)
        if str(network.id) != record.network_id:
            raise CorruptSnapshot
        return NetworkSnapshot(
            network=network, revision=record.revision, sha256=record.sha256
        )
    except ValidationError as error:
        raise CorruptSnapshot from error


class NetworkRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def check_ready(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(select(NetworkRecord).limit(1))
            connection.execute(select(RevisionRecord).limit(1))

    def seed(self, network: Network, policy_version: str) -> None:
        record = serialize(network, 1, "seed", policy_version)
        with Session(self.engine) as session, session.begin():
            statement = (
                insert(NetworkRecord)
                .values(id=record.network_id, current_revision=1)
                .on_conflict_do_nothing(index_elements=[NetworkRecord.id])
                .returning(NetworkRecord.id)
            )
            if session.scalar(statement) is None:
                return
            session.add(record)
            session.add(
                audit_event(
                    request_id=str(uuid4()),
                    actor="system",
                    outcome=201,
                    event_type="network.seed",
                    network_id=network.id,
                    revision=1,
                    policy_version=policy_version,
                )
            )

    def audit_targets(self) -> list[AuditTarget]:
        statement = (
            select(NetworkRecord.id, RevisionRecord)
            .outerjoin(
                RevisionRecord,
                (RevisionRecord.network_id == NetworkRecord.id)
                & (RevisionRecord.revision == NetworkRecord.current_revision),
            )
            .order_by(NetworkRecord.id)
        )
        with Session(self.engine) as session:
            targets = []
            for network_id, record in session.execute(statement):
                try:
                    name = (
                        deserialize(record).network.name if record is not None else None
                    )
                except CorruptSnapshot:
                    name = None
                targets.append(
                    AuditTarget(
                        id=UUID(network_id),
                        name=name,
                        snapshot_integrity="verified" if name is not None else "failed",
                    )
                )
            return targets

    def summaries(self) -> list[NetworkSummary]:
        with Session(self.engine) as session:
            statement = (
                select(RevisionRecord)
                .join(NetworkRecord, NetworkRecord.id == RevisionRecord.network_id)
                .where(NetworkRecord.current_revision == RevisionRecord.revision)
                .order_by(NetworkRecord.id)
            )
            snapshots = [deserialize(record) for record in session.scalars(statement)]
        return [
            NetworkSummary(
                id=item.network.id, name=item.network.name, revision=item.revision
            )
            for item in snapshots
        ]

    def snapshot(
        self, network_id: UUID, revision: int | None = None
    ) -> NetworkSnapshot:
        with Session(self.engine) as session:
            statement = select(RevisionRecord).where(
                RevisionRecord.network_id == str(network_id)
            )
            if revision is None:
                statement = statement.join(
                    NetworkRecord, NetworkRecord.id == RevisionRecord.network_id
                ).where(NetworkRecord.current_revision == RevisionRecord.revision)
            else:
                statement = statement.where(RevisionRecord.revision == revision)
            record = session.scalar(statement)
            if record is None:
                raise NotFound
            return deserialize(record)

    def current_revision(self, network_id: UUID) -> int:
        with Session(self.engine) as session:
            record = session.get(NetworkRecord, str(network_id))
            if record is None:
                raise NotFound
            return record.current_revision

    def revision_info(self, network_id: UUID, revision: int) -> RevisionInfo:
        with Session(self.engine) as session:
            record = session.get(RevisionRecord, (str(network_id), revision))
            if record is None:
                raise NotFound
            return RevisionInfo.model_validate(record, from_attributes=True)

    def history(
        self, network_id: UUID, limit: int, before_revision: int | None
    ) -> list[RevisionInfo]:
        with Session(self.engine) as session:
            if session.get(NetworkRecord, str(network_id)) is None:
                raise NotFound
            statement = select(RevisionRecord).where(
                RevisionRecord.network_id == str(network_id)
            )
            if before_revision is not None:
                statement = statement.where(RevisionRecord.revision < before_revision)
            return [
                RevisionInfo(
                    revision=row.revision,
                    sha256=row.sha256,
                    operation=row.operation,
                    policy_version=row.policy_version,
                    restored_from=row.restored_from,
                )
                for row in session.scalars(
                    statement.order_by(RevisionRecord.revision.desc()).limit(limit)
                )
            ]

    def execution_receipt(
        self, network_id: UUID, plan_hash: str
    ) -> NetworkSnapshot | None:
        with Session(self.engine) as session:
            record = session.scalar(
                select(RevisionRecord).where(
                    RevisionRecord.network_id == str(network_id),
                    RevisionRecord.execution_key == plan_hash,
                )
            )
            return None if record is None else deserialize(record)

    def commit(
        self,
        network: Network,
        expected_revision: int,
        operation: Literal["change", "restore"],
        policy_version: str,
        request_id: str,
        actor: str,
        restored_from: int | None = None,
        *,
        execution: ExecutionGuard | None = None,
    ) -> NetworkSnapshot:
        revision = expected_revision + 1
        record = serialize(network, revision, operation, policy_version, restored_from)
        result = NetworkSnapshot(
            network=network, revision=revision, sha256=record.sha256
        )
        with Session(self.engine) as session, session.begin():
            statement = (
                update(NetworkRecord)
                .where(
                    NetworkRecord.id == str(network.id),
                    NetworkRecord.current_revision == expected_revision,
                )
                .values(current_revision=revision)
                .returning(NetworkRecord.id)
            )
            if session.scalar(statement) is None:
                raise RevisionConflict
            if execution is not None:
                if datetime.now(UTC) >= execution.expires_at:
                    raise ExecutionExpired
                record.execution_key = execution.plan_hash
            session.add(record)
            session.add(
                audit_event(
                    request_id=request_id,
                    actor=actor,
                    outcome=200,
                    event_type=f"network.{operation}",
                    network_id=network.id,
                    revision=revision,
                    policy_version=policy_version,
                )
            )
        return result
