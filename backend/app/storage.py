from datetime import UTC, datetime, timedelta
from pathlib import Path
from sqlite3 import Connection
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, Engine, String, create_engine, event, select, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    occurred_at_us: Mapped[int] = mapped_column(BigInteger, index=True)
    actor: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str] = mapped_column(String(36))
    outcome: Mapped[int]
    event_type: Mapped[str | None] = mapped_column(String(48))
    network_id: Mapped[str | None] = mapped_column(String(36))
    revision: Mapped[int | None]
    policy_version: Mapped[str | None] = mapped_column(String(80))

    @property
    def occurred_at(self) -> datetime:
        return EPOCH + timedelta(microseconds=self.occurred_at_us)


def sqlite_engine(path: Path) -> Engine:
    engine = create_engine(
        URL.create("sqlite", database=str(path.resolve())),
        connect_args={"autocommit": False, "timeout": 2},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: Connection, _: object) -> None:
        connection.autocommit = True
        try:
            connection.execute("PRAGMA foreign_keys=ON")
        finally:
            connection.autocommit = False

    return engine


def audit_event(
    request_id: str,
    actor: str | None,
    outcome: int,
    *,
    event_type: str | None = None,
    network_id: UUID | None = None,
    revision: int | None = None,
    policy_version: str | None = None,
) -> AuditEvent:
    elapsed = datetime.now(UTC) - EPOCH
    return AuditEvent(
        id=str(uuid4()),
        occurred_at_us=elapsed // timedelta(microseconds=1),
        actor=actor,
        request_id=request_id,
        outcome=outcome,
        event_type=event_type,
        network_id=None if network_id is None else str(network_id),
        revision=revision,
        policy_version=policy_version,
    )


class Storage:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def check_ready(self, expected_heads: set[str]) -> bool:
        with self.engine.connect() as connection:
            heads = set(
                connection.scalars(text("SELECT version_num FROM alembic_version"))
            )
            if heads != expected_heads:
                return False
            connection.execute(select(Task).limit(1))
            connection.execute(select(AuditEvent).limit(1))
            return True

    def record_denial(self, request_id: str, actor: str | None, outcome: int) -> None:
        self.record_event(audit_event(request_id, actor, outcome))

    def record_event(self, entry: AuditEvent) -> None:
        with Session(self.engine) as session, session.begin():
            session.add(entry)

    def recent_denials(self, limit: int) -> list[AuditEvent]:
        return self.recent_events(limit, denials_only=True)

    def recent_events(
        self, limit: int, *, denials_only: bool = False
    ) -> list[AuditEvent]:
        with Session(self.engine) as session:
            statement = select(AuditEvent)
            if denials_only:
                statement = statement.where(AuditEvent.event_type.is_(None))
            return list(
                session.scalars(
                    statement.order_by(
                        AuditEvent.occurred_at_us.desc(), AuditEvent.id.desc()
                    ).limit(limit)
                )
            )
