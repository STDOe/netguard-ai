from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import BigInteger, Engine, String, create_engine, select, text
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

    @property
    def occurred_at(self) -> datetime:
        return EPOCH + timedelta(microseconds=self.occurred_at_us)


def sqlite_engine(path: Path) -> Engine:
    return create_engine(
        URL.create("sqlite", database=str(path.resolve())),
        connect_args={"autocommit": False, "timeout": 2},
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
        elapsed = datetime.now(UTC) - EPOCH
        with Session(self.engine) as session, session.begin():
            session.add(
                AuditEvent(
                    id=str(uuid4()),
                    occurred_at_us=elapsed // timedelta(microseconds=1),
                    actor=actor,
                    request_id=request_id,
                    outcome=outcome,
                )
            )

    def recent_denials(self, limit: int) -> list[AuditEvent]:
        with Session(self.engine) as session:
            statement = (
                select(AuditEvent)
                .order_by(AuditEvent.occurred_at_us.desc(), AuditEvent.id.desc())
                .limit(limit)
            )
            return list(session.scalars(statement))
