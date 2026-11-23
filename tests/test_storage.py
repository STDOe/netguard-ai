from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.config import Settings
from app.storage import Storage, Task, sqlite_engine


def test_migrations_and_durability(
    settings: Settings, migration_config: Config
) -> None:
    command.upgrade(migration_config, "head")
    request_id = str(uuid4())
    task_id = str(uuid4())
    engine = sqlite_engine(settings.database_path)
    try:
        with Session(engine) as session, session.begin():
            session.add(Task(id=task_id, kind="audit", status="queued"))
        Storage(engine).record_denial(request_id, None, 401)
    finally:
        engine.dispose()

    command.upgrade(migration_config, "head")
    engine = sqlite_engine(settings.database_path)
    try:
        with Session(engine) as session:
            task = session.get(Task, task_id)
            assert task is not None
            assert (task.kind, task.status) == ("audit", "queued")
        assert Storage(engine).recent_denials(1)[0].request_id == request_id
        command.downgrade(migration_config, "base")
        assert not {"tasks", "audit_events"} & set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
